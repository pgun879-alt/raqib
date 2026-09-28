"""The HTTP client: validated, rate-limited, size-capped, retrying, and DNS-pinned.

Every safety property this tool claims is enforced here, because this is the only place that
touches the network.

**DNS pinning** deserves a note. :mod:`raqib.netguard` resolves a hostname and checks the
addresses, but if the HTTP client then resolved the name *again* independently, an attacker
controlling that DNS record could answer "public" for the check and "private" for the request --
a **DNS-rebinding** bypass, and the reason a naive SSRF guard fails. So the validated address is
pinned into the connection via a request-level ``Host`` header and a URL rewritten to the address,
which means the socket goes exactly where the guard approved.

Redirects are followed manually rather than by ``httpx``, because each hop is a fresh URL that
must go through the same validation. ``follow_redirects=True`` would let a public URL hand us off
to ``http://127.0.0.1:8080/`` with no check at all.
"""

from __future__ import annotations

import logging
import random
import threading
import time
from dataclasses import dataclass, field
from typing import Final
from urllib.parse import urlparse, urlunparse

import httpx

from .config import Settings, utcnow
from .netguard import UnsafeTargetError, validate_target
from .robots import MAX_ROBOTS_BYTES, RobotsRules, robots_url_for

logger = logging.getLogger(__name__)

#: Status codes worth retrying. Everything else is either success or a client error that will not
#: change on a second attempt.
RETRYABLE_STATUS: Final[frozenset[int]] = frozenset({429, 500, 502, 503, 504, 408})


class FetchError(RuntimeError):
    """A fetch failed. The message is safe to show an operator and to store in a report."""


class RobotsDisallowedError(FetchError):
    """``robots.txt`` forbids fetching this URL. Not retried -- it is a decision, not a failure."""


class RobotsUnavailableError(FetchError):
    """``robots.txt`` could not be read, so the fetch was refused (fail closed).

    Deliberately **not** a :class:`RobotsDisallowedError`. The two look identical from inside the
    fetcher -- both end in "do not fetch" -- but they mean opposite things to the operator:

    * *disallowed* -> the site published a rule; fix the target list, and do not retry.
    * *unavailable* -> the site did not answer; this is almost always an outage, and it **is**
      worth retrying.

    Conflating them reports a down site as a robots misconfiguration, which sends the operator to
    edit a YAML file while their server is on fire. It is also the wrong retry behaviour.
    """


@dataclass(frozen=True, slots=True)
class FetchResult:
    """The outcome of one successful fetch."""

    url: str
    final_url: str
    status_code: int
    headers: dict[str, str]
    body: str
    elapsed_ms: float
    truncated: bool
    redirects: tuple[str, ...] = ()
    resolved_address: str = ""

    @property
    def content_type(self) -> str:
        return self.headers.get("content-type", "")


@dataclass
class _HostState:
    """Per-host politeness state."""

    last_request_at: float = 0.0
    crawl_delay: float | None = None
    robots: RobotsRules | None = None
    robots_fetched_at: float = field(default=0.0)


class PolitenessGate:
    """Enforces a minimum gap between requests to the same host.

    Per-host rather than global: being slow to one site should not throttle every other target.
    The gap is the larger of the configured minimum and any ``Crawl-delay`` the site asked for --
    a site's own request always wins when it is stricter.
    """

    def __init__(self, *, min_interval: float) -> None:
        self.min_interval = min_interval
        self._hosts: dict[str, _HostState] = {}
        self._lock = threading.Lock()

    def state_for(self, host: str) -> _HostState:
        with self._lock:
            return self._hosts.setdefault(host, _HostState())

    def wait_for(self, host: str, *, sleep: bool = True, now: float | None = None) -> float:
        """Return how long to wait before requesting ``host``, sleeping unless told not to."""
        state = self.state_for(host)
        required = max(self.min_interval, state.crawl_delay or 0.0)
        current = now if now is not None else time.monotonic()
        elapsed = current - state.last_request_at
        delay = max(required - elapsed, 0.0) if state.last_request_at else 0.0
        if delay > 0 and sleep:
            logger.debug("waiting %.2fs before the next request to %s", delay, host)
            time.sleep(delay)
        return delay

    def mark_request(self, host: str, *, now: float | None = None) -> None:
        state = self.state_for(host)
        state.last_request_at = now if now is not None else time.monotonic()


class Fetcher:
    """Fetches URLs subject to every safety and politeness rule."""

    def __init__(self, settings: Settings, *, client: httpx.Client | None = None) -> None:
        self.settings = settings
        self.gate = PolitenessGate(min_interval=settings.min_seconds_between_requests_per_host)
        self._owns_client = client is None
        self._client = client or httpx.Client(
            timeout=httpx.Timeout(settings.request_timeout_seconds),
            # Redirects are followed manually so each hop is re-validated.
            follow_redirects=False,
            headers={
                "User-Agent": settings.user_agent,
                "Accept": (
                    "text/html,application/xhtml+xml,application/json,text/plain;q=0.9,*/*;q=0.8"
                ),
                "Accept-Encoding": "gzip, deflate",
            },
        )

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> Fetcher:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    # -- robots ------------------------------------------------------------------

    def _load_robots(self, url: str) -> RobotsRules:
        """Fetch and cache ``robots.txt`` for the origin of ``url``.

        Failure policy, stated explicitly because it is a judgement call:

        * **404 or 410** -> allow everything. The standard says a missing file means no rules.
        * **network error, timeout, or 5xx** -> **deny everything**. If we cannot establish that
          we are welcome, we do not proceed. Failing open here would mean an outage on the target
          silently turns compliance off.
        """
        state = self.gate.state_for(urlparse(url).hostname or "")
        if state.robots is not None:
            return state.robots

        robots_target = robots_url_for(url)
        try:
            response = self._request_once(robots_target, max_bytes=MAX_ROBOTS_BYTES)
        except FetchError as exc:
            logger.warning(
                "could not read robots.txt; treating the site as disallowed",
                extra={"url": robots_target, "error": str(exc)[:200]},
            )
            rules = RobotsRules.deny_all(user_agent=self.settings.user_agent)
        else:
            if response.status_code in {404, 410}:
                rules = RobotsRules.allow_all(user_agent=self.settings.user_agent)
            elif 200 <= response.status_code < 300:
                rules = RobotsRules.parse(response.body, user_agent=self.settings.user_agent)
            else:
                logger.warning(
                    "robots.txt returned HTTP %d; treating the site as disallowed",
                    response.status_code,
                    extra={"url": robots_target},
                )
                rules = RobotsRules.deny_all(user_agent=self.settings.user_agent)

        if rules.unavailable:
            # Deliberately not cached. A fail-closed placeholder means the host did not answer;
            # caching it would make a transient outage permanently poison every later attempt,
            # and the retry loop above would retry against the cached denial rather than against
            # the site. Real rules are cached; "we could not ask" is re-asked.
            return rules

        state.robots = rules
        state.robots_fetched_at = time.monotonic()
        if rules.crawl_delay is not None:
            state.crawl_delay = rules.crawl_delay
            logger.info(
                "honouring the site's Crawl-delay",
                extra={"host": urlparse(url).hostname, "crawl_delay": rules.crawl_delay},
            )
        return rules

    # -- single request ----------------------------------------------------------

    def _request_once(self, url: str, *, max_bytes: int | None = None) -> FetchResult:
        """Validate, pin DNS, and perform exactly one request with no redirect following."""
        target = validate_target(url, allow_private=self.settings.allow_private_targets)
        limit = max_bytes or self.settings.max_response_bytes

        # Pin the connection to the address the guard approved. Letting httpx resolve the name
        # again would reopen the DNS-rebinding window the guard exists to close.
        address = target.primary_address
        parsed = urlparse(target.url)
        literal = f"[{address}]" if ":" in address else address
        pinned_netloc = f"{literal}:{target.port}"
        pinned_url = urlunparse(
            (parsed.scheme, pinned_netloc, parsed.path, parsed.params, parsed.query, "")
        )
        headers = {
            # The Host header keeps virtual hosting working against the pinned address.
            "Host": target.host if target.port in (80, 443) else f"{target.host}:{target.port}",
            # Set per request, not only as a client default. Being identifiable is a *policy* of
            # this tool -- the config validator refuses a browser-impersonating agent -- so it
            # must hold regardless of how the client was constructed. Relying on client defaults
            # meant an injected client silently sent "python-httpx/x.y" instead.
            "User-Agent": self.settings.user_agent,
        }

        self.gate.wait_for(target.host)
        started = time.perf_counter()
        try:
            with self._client.stream(
                "GET",
                pinned_url,
                headers=headers,
                # TLS must still be verified against the *name*, not the pinned address.
                extensions={"sni_hostname": target.host} if parsed.scheme == "https" else None,
            ) as response:
                chunks: list[bytes] = []
                total = 0
                truncated = False
                for chunk in response.iter_bytes():
                    chunks.append(chunk)
                    total += len(chunk)
                    if total >= limit:
                        # Stop reading rather than letting a huge or endless response exhaust
                        # memory. A truncated body is still useful for change detection.
                        truncated = True
                        break
                raw = b"".join(chunks)[:limit]
                encoding = response.encoding or "utf-8"
                body = raw.decode(encoding, errors="replace")
                result = FetchResult(
                    url=target.url,
                    final_url=target.url,
                    status_code=response.status_code,
                    headers={key.lower(): value for key, value in response.headers.items()},
                    body=body,
                    elapsed_ms=(time.perf_counter() - started) * 1000,
                    truncated=truncated,
                    resolved_address=address,
                )
        except httpx.TimeoutException as exc:
            raise FetchError(
                f"{target.url} timed out after {self.settings.request_timeout_seconds}s"
            ) from exc
        except httpx.HTTPError as exc:
            raise FetchError(f"{target.url} could not be fetched: {exc}") from exc
        finally:
            self.gate.mark_request(target.host)

        return result

    # -- public entry point ------------------------------------------------------

    def fetch(self, url: str, *, check_robots: bool | None = None) -> FetchResult:
        """Fetch ``url``, following redirects safely and retrying transient failures.

        Raises:
            UnsafeTargetError: if the URL, or any redirect hop, fails validation.
            RobotsDisallowedError: if ``robots.txt`` forbids it.
            FetchError: if every attempt failed.
        """
        respect = self.settings.respect_robots if check_robots is None else check_robots
        attempts = self.settings.max_attempts
        last_error: Exception | None = None

        for attempt in range(1, attempts + 1):
            try:
                return self._fetch_with_redirects(url, respect_robots=respect)
            except (RobotsDisallowedError, UnsafeTargetError):
                # Both are decisions, not transient failures. Retrying would be pointless and,
                # for the SSRF case, would look like probing.
                raise
            except FetchError as exc:
                last_error = exc
                if attempt >= attempts:
                    break
                delay = self.settings.retry_backoff_base_seconds * (2 ** (attempt - 1))
                delay += random.uniform(0, delay * 0.25)  # noqa: S311 - jitter, not cryptography
                logger.info(
                    "fetch failed, retrying",
                    extra={"url": url, "attempt": attempt, "retry_in": round(delay, 2)},
                )
                time.sleep(delay)

        summary = f"{url} failed after {attempts} attempt(s): {last_error}"
        # Preserve the specific error class. Collapsing everything to FetchError here would lose
        # the distinction the exception hierarchy exists to make -- a caller could no longer tell
        # "robots.txt was unreachable" from "the page timed out", even though it matters for how
        # the failure is reported. Every FetchError subclass takes a single message argument.
        raise (
            type(last_error)(summary) if isinstance(last_error, FetchError) else FetchError(summary)
        )

    def _fetch_with_redirects(self, url: str, *, respect_robots: bool) -> FetchResult:
        current = url
        redirects: list[str] = []

        for _ in range(self.settings.max_redirects + 1):
            if respect_robots:
                rules = self._load_robots(current)
                if not rules.can_fetch(current):
                    if rules.unavailable:
                        # Not a refusal by the site -- we simply could not ask it. Raised as a
                        # retryable FetchError so the caller reports (and retries) an outage.
                        raise RobotsUnavailableError(
                            f"could not read {robots_url_for(current)}, so {current} was not "
                            "fetched; the host appears to be unreachable"
                        )
                    raise RobotsDisallowedError(
                        f"robots.txt at {robots_url_for(current)} disallows {current} for "
                        f"user-agent {self.settings.user_agent!r}"
                    )

            response = self._request_once(current)
            if response.status_code not in {301, 302, 303, 307, 308}:
                if response.status_code in RETRYABLE_STATUS:
                    raise FetchError(f"{current} returned HTTP {response.status_code}")
                return FetchResult(
                    url=url,
                    final_url=response.url,
                    status_code=response.status_code,
                    headers=response.headers,
                    body=response.body,
                    elapsed_ms=response.elapsed_ms,
                    truncated=response.truncated,
                    redirects=tuple(redirects),
                    resolved_address=response.resolved_address,
                )

            location = response.headers.get("location")
            if not location:
                raise FetchError(f"{current} returned HTTP {response.status_code} with no Location")
            current = httpx.URL(response.url).join(location).__str__()
            redirects.append(current)
            logger.debug("following redirect to %s", current)
            # The loop re-enters validate_target and the robots check for this new URL, which is
            # the whole point of not using follow_redirects=True.

        raise FetchError(f"{url} exceeded {self.settings.max_redirects} redirects")


def measure_availability(result: FetchResult | None, error: str | None) -> dict[str, object]:
    """Summarise one poll as an availability record."""
    return {
        "checked_at": utcnow().isoformat(timespec="seconds"),
        "available": result is not None and 200 <= result.status_code < 400,
        "status_code": result.status_code if result else None,
        "elapsed_ms": round(result.elapsed_ms, 1) if result else None,
        "error": error,
    }
