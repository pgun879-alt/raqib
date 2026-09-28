"""Tests for the HTTP client: politeness, redirects, size caps, retries, robots enforcement."""

from __future__ import annotations

import httpx
import pytest

from raqib.config import Settings
from raqib.fetcher import (
    Fetcher,
    FetchError,
    PolitenessGate,
    RobotsDisallowedError,
    RobotsUnavailableError,
    measure_availability,
)
from raqib.netguard import UnsafeTargetError

ROBOTS = "User-agent: *\nDisallow: /private/\n"


def _fetcher(handler, settings: Settings) -> Fetcher:
    return Fetcher(
        settings,
        client=httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False),
    )


def _simple(body: str = "<html><body>hello</body></html>", *, robots: str = ROBOTS):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/robots.txt":
            return httpx.Response(200, text=robots, headers={"content-type": "text/plain"})
        return httpx.Response(200, text=body, headers={"content-type": "text/html"})

    return handler


# --------------------------------------------------------------------- politeness gate


def test_the_first_request_to_a_host_is_not_delayed() -> None:
    gate = PolitenessGate(min_interval=5.0)
    assert gate.wait_for("example.com", sleep=False, now=100.0) == 0.0


def test_a_second_request_within_the_interval_is_delayed() -> None:
    gate = PolitenessGate(min_interval=5.0)
    gate.mark_request("example.com", now=100.0)
    assert gate.wait_for("example.com", sleep=False, now=102.0) == pytest.approx(3.0)


def test_no_delay_once_the_interval_has_passed() -> None:
    gate = PolitenessGate(min_interval=5.0)
    gate.mark_request("example.com", now=100.0)
    assert gate.wait_for("example.com", sleep=False, now=110.0) == 0.0


def test_the_gate_is_per_host() -> None:
    """Being slow to one site must not throttle every other target."""
    gate = PolitenessGate(min_interval=5.0)
    gate.mark_request("slow.example", now=100.0)
    assert gate.wait_for("other.example", sleep=False, now=100.5) == 0.0


def test_a_sites_crawl_delay_wins_when_it_is_stricter() -> None:
    gate = PolitenessGate(min_interval=1.0)
    gate.state_for("example.com").crawl_delay = 10.0
    gate.mark_request("example.com", now=100.0)
    assert gate.wait_for("example.com", sleep=False, now=101.0) == pytest.approx(9.0)


def test_our_minimum_wins_when_it_is_stricter_than_crawl_delay() -> None:
    gate = PolitenessGate(min_interval=10.0)
    gate.state_for("example.com").crawl_delay = 1.0
    gate.mark_request("example.com", now=100.0)
    assert gate.wait_for("example.com", sleep=False, now=101.0) == pytest.approx(9.0)


# --------------------------------------------------------------------- fetching


def test_a_simple_fetch_returns_the_body_and_headers(settings: Settings) -> None:
    with _fetcher(_simple(), settings) as fetcher:
        result = fetcher.fetch("http://127.0.0.1:8999/page.html")
    assert result.status_code == 200
    assert "hello" in result.body
    assert result.content_type.startswith("text/html")
    assert result.resolved_address == "127.0.0.1"
    assert not result.truncated


def test_robots_txt_is_fetched_before_the_page(settings: Settings) -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.path)
        if request.url.path == "/robots.txt":
            return httpx.Response(200, text=ROBOTS, headers={"content-type": "text/plain"})
        return httpx.Response(200, text="ok", headers={"content-type": "text/html"})

    with _fetcher(handler, settings) as fetcher:
        fetcher.fetch("http://127.0.0.1:8999/page.html")
    assert seen[0] == "/robots.txt"


def test_robots_txt_is_fetched_only_once_per_host(settings: Settings) -> None:
    """Re-reading it on every poll would double the request count against every site."""
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.path)
        if request.url.path == "/robots.txt":
            return httpx.Response(200, text=ROBOTS, headers={"content-type": "text/plain"})
        return httpx.Response(200, text="ok", headers={"content-type": "text/html"})

    with _fetcher(handler, settings) as fetcher:
        for _ in range(3):
            fetcher.fetch("http://127.0.0.1:8999/page.html")
    assert seen.count("/robots.txt") == 1


def test_a_disallowed_path_is_refused(settings: Settings) -> None:
    with _fetcher(_simple(), settings) as fetcher, pytest.raises(RobotsDisallowedError):
        fetcher.fetch("http://127.0.0.1:8999/private/secret.html")


def test_a_missing_robots_txt_means_everything_is_allowed(settings: Settings) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/robots.txt":
            return httpx.Response(404, text="not found")
        return httpx.Response(200, text="ok", headers={"content-type": "text/html"})

    with _fetcher(handler, settings) as fetcher:
        assert fetcher.fetch("http://127.0.0.1:8999/anything").status_code == 200


def test_an_unreadable_robots_txt_fails_closed_but_says_so(settings: Settings) -> None:
    """Fail closed, and report the real cause rather than pretending the site published a rule."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/robots.txt":
            return httpx.Response(503, text="unavailable")
        return httpx.Response(200, text="ok", headers={"content-type": "text/html"})

    with (
        _fetcher(handler, settings) as fetcher,
        pytest.raises(RobotsUnavailableError, match="unreachable"),
    ):
        fetcher.fetch("http://127.0.0.1:8999/page.html")


def test_robots_can_be_bypassed_explicitly_per_call(settings: Settings) -> None:
    with _fetcher(_simple(), settings) as fetcher:
        result = fetcher.fetch("http://127.0.0.1:8999/private/x.html", check_robots=False)
    assert result.status_code == 200


def test_a_sites_crawl_delay_is_adopted(settings: Settings) -> None:
    robots = "User-agent: *\nCrawl-delay: 7\n"
    with _fetcher(_simple(robots=robots), settings) as fetcher:
        fetcher.fetch("http://127.0.0.1:8999/page.html")
        assert fetcher.gate.state_for("127.0.0.1").crawl_delay == 7.0


# --------------------------------------------------------------------- redirects


def test_a_redirect_is_followed(settings: Settings) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/robots.txt":
            return httpx.Response(200, text="", headers={"content-type": "text/plain"})
        if request.url.path == "/old":
            return httpx.Response(301, headers={"location": "/new"})
        return httpx.Response(200, text="arrived", headers={"content-type": "text/html"})

    with _fetcher(handler, settings) as fetcher:
        result = fetcher.fetch("http://127.0.0.1:8999/old")
    assert "arrived" in result.body
    assert len(result.redirects) == 1


def test_a_redirect_loop_is_stopped(settings: Settings) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/robots.txt":
            return httpx.Response(200, text="", headers={"content-type": "text/plain"})
        return httpx.Response(302, headers={"location": "/loop"})

    with _fetcher(handler, settings) as fetcher, pytest.raises(FetchError, match="exceeded"):
        fetcher.fetch("http://127.0.0.1:8999/loop")


def test_a_redirect_with_no_location_is_an_error(settings: Settings) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/robots.txt":
            return httpx.Response(200, text="", headers={"content-type": "text/plain"})
        return httpx.Response(302)

    with _fetcher(handler, settings) as fetcher, pytest.raises(FetchError, match="no Location"):
        fetcher.fetch("http://127.0.0.1:8999/page")


def test_a_redirect_to_a_private_address_is_refused(settings: Settings) -> None:
    """The reason redirects are followed manually instead of by httpx.

    A public URL can hand us off to http://127.0.0.1:8080/ -- with follow_redirects=True that
    request would be made with no validation at all.
    """
    strict = settings.model_copy(update={"allow_private_targets": False})

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/robots.txt":
            return httpx.Response(200, text="", headers={"content-type": "text/plain"})
        return httpx.Response(302, headers={"location": "http://127.0.0.1:8080/internal"})

    def resolve(host: str, port: int) -> list[str]:
        return ["93.184.216.34"] if host == "example.com" else ["127.0.0.1"]

    import raqib.netguard as netguard

    original = netguard.resolve_addresses
    netguard.resolve_addresses = resolve  # type: ignore[assignment]
    try:
        with (
            _fetcher(handler, strict) as fetcher,
            pytest.raises(UnsafeTargetError, match="loopback"),
        ):
            fetcher.fetch("http://example.com/start")
    finally:
        netguard.resolve_addresses = original  # type: ignore[assignment]


# --------------------------------------------------------------------- size cap


def test_an_over_large_response_is_truncated_not_loaded_whole(settings: Settings) -> None:
    small = settings.model_copy(update={"max_response_bytes": 2048})

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/robots.txt":
            return httpx.Response(200, text="", headers={"content-type": "text/plain"})
        return httpx.Response(200, text="x" * 100_000, headers={"content-type": "text/html"})

    with _fetcher(handler, small) as fetcher:
        result = fetcher.fetch("http://127.0.0.1:8999/big")
    assert result.truncated
    assert len(result.body) <= 2048


# --------------------------------------------------------------------- retries


def test_a_retryable_status_is_retried_then_reported(settings: Settings) -> None:
    retrying = settings.model_copy(update={"max_attempts": 3, "retry_backoff_base_seconds": 0.001})
    attempts = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/robots.txt":
            return httpx.Response(200, text="", headers={"content-type": "text/plain"})
        attempts["count"] += 1
        return httpx.Response(503, text="unavailable")

    with _fetcher(handler, retrying) as fetcher, pytest.raises(FetchError, match="3 attempt"):
        fetcher.fetch("http://127.0.0.1:8999/flaky")
    assert attempts["count"] == 3


def test_a_transient_failure_then_success(settings: Settings) -> None:
    retrying = settings.model_copy(update={"max_attempts": 3, "retry_backoff_base_seconds": 0.001})
    attempts = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/robots.txt":
            return httpx.Response(200, text="", headers={"content-type": "text/plain"})
        attempts["count"] += 1
        if attempts["count"] == 1:
            return httpx.Response(502, text="bad gateway")
        return httpx.Response(200, text="recovered", headers={"content-type": "text/html"})

    with _fetcher(handler, retrying) as fetcher:
        assert "recovered" in fetcher.fetch("http://127.0.0.1:8999/flaky").body


def test_a_robots_refusal_is_never_retried(settings: Settings) -> None:
    """It is a published decision, not a transient failure.

    Retrying would also look like probing to the site being monitored.
    """
    retrying = settings.model_copy(update={"max_attempts": 5, "retry_backoff_base_seconds": 0.001})
    attempts = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/robots.txt":
            return httpx.Response(200, text=ROBOTS, headers={"content-type": "text/plain"})
        attempts["count"] += 1
        return httpx.Response(200, text="ok", headers={"content-type": "text/html"})

    with _fetcher(handler, retrying) as fetcher, pytest.raises(RobotsDisallowedError):
        fetcher.fetch("http://127.0.0.1:8999/private/x")
    assert attempts["count"] == 0, "the page must never have been requested"


def test_a_404_is_returned_rather_than_retried(settings: Settings) -> None:
    """A 404 is a real answer; the monitor decides what it means."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/robots.txt":
            return httpx.Response(200, text="", headers={"content-type": "text/plain"})
        return httpx.Response(404, text="gone", headers={"content-type": "text/html"})

    with _fetcher(handler, settings) as fetcher:
        assert fetcher.fetch("http://127.0.0.1:8999/missing").status_code == 404


def test_a_timeout_is_reported_clearly(settings: Settings) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/robots.txt":
            return httpx.Response(200, text="", headers={"content-type": "text/plain"})
        raise httpx.ReadTimeout("too slow", request=request)

    with _fetcher(handler, settings) as fetcher, pytest.raises(FetchError, match="timed out"):
        fetcher.fetch("http://127.0.0.1:8999/slow")


# --------------------------------------------------------------------- user agent


def test_the_configured_user_agent_is_sent(settings: Settings) -> None:
    captured: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["ua"] = request.headers.get("user-agent", "")
        if request.url.path == "/robots.txt":
            return httpx.Response(200, text="", headers={"content-type": "text/plain"})
        return httpx.Response(200, text="ok", headers={"content-type": "text/html"})

    with _fetcher(handler, settings) as fetcher:
        fetcher.fetch("http://127.0.0.1:8999/page")
    assert "raqib" in captured["ua"]


def test_the_host_header_is_set_for_the_pinned_connection(settings: Settings) -> None:
    """DNS pinning rewrites the URL to the IP, so Host must carry the real name or virtual
    hosting and SNI break."""
    captured: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured[request.url.path] = request.headers.get("host", "")
        if request.url.path == "/robots.txt":
            return httpx.Response(200, text="", headers={"content-type": "text/plain"})
        return httpx.Response(200, text="ok", headers={"content-type": "text/html"})

    with _fetcher(handler, settings) as fetcher:
        fetcher.fetch("http://127.0.0.1:8999/page")
    assert captured["/page"] == "127.0.0.1:8999"


# --------------------------------------------------------------------- availability


def test_measure_availability_summarises_a_result() -> None:
    from raqib.fetcher import FetchResult

    result = FetchResult(
        url="https://example.com/",
        final_url="https://example.com/",
        status_code=200,
        headers={},
        body="",
        elapsed_ms=12.34,
        truncated=False,
    )
    record = measure_availability(result, None)
    assert record["available"] is True
    assert record["status_code"] == 200
    assert record["elapsed_ms"] == 12.3


def test_measure_availability_of_a_failure() -> None:
    record = measure_availability(None, "connection refused")
    assert record["available"] is False
    assert record["error"] == "connection refused"
    assert record["status_code"] is None
