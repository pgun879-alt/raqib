"""Orchestration: check a target, detect change, decide whether to alert.

The alerting rules, stated up front because they are the product:

* **First poll of a target never alerts.** There is nothing to compare against, so an alert would
  just be noise on every newly added target.
* **A content change alerts once**, with a unified diff.
* **Availability alerts on transition only** — down alerts once, and recovery alerts once.
* **Security alerts on the finding set changing**, not on the findings existing. A site that has
  been missing a CSP for a year is not news every hour; losing one it had yesterday is.

All four are implemented through :meth:`~raqib.storage.Store.should_alert`, which compares a
fingerprint of the current state against the stored one.
"""

from __future__ import annotations

import difflib
import logging
import random
import time
from dataclasses import dataclass, field
from typing import Final

from .alerting import Alert, AlertDispatcher
from .config import Settings, WatchTarget, utcnow
from .extract import ExtractionError, extract
from .fetcher import Fetcher, FetchError, RobotsDisallowedError
from .netguard import UnsafeTargetError
from .security_scan import SecurityReport, assess
from .storage import Store, content_fingerprint

logger = logging.getLogger(__name__)

#: Lines of unified diff included in an alert. A full diff of a large page is unreadable in a
#: Telegram message and unhelpful in a log line.
MAX_DIFF_LINES: Final = 40


@dataclass(slots=True)
class CheckOutcome:
    """Everything that happened during one target check."""

    target: WatchTarget
    available: bool = False
    status_code: int | None = None
    elapsed_ms: float | None = None
    changed: bool = False
    is_first_snapshot: bool = False
    diff: str = ""
    error: str | None = None
    security: SecurityReport | None = None
    alerts: list[Alert] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.error is None


def build_diff(previous: str, current: str, *, name: str, max_lines: int = MAX_DIFF_LINES) -> str:
    """Unified diff between two snapshots, truncated to ``max_lines``."""
    lines = list(
        difflib.unified_diff(
            previous.splitlines(),
            current.splitlines(),
            fromfile=f"{name} (previous)",
            tofile=f"{name} (current)",
            lineterm="",
            n=2,
        )
    )
    if not lines:
        return ""
    if len(lines) > max_lines:
        remaining = len(lines) - max_lines
        lines = lines[:max_lines] + [f"... ({remaining} more diff line(s) omitted)"]
    return "\n".join(lines)


def summarise_change(previous: str, current: str) -> str:
    """A one-line summary of the size of a change, for an alert title."""
    added = sum(
        1
        for line in difflib.unified_diff(previous.splitlines(), current.splitlines(), lineterm="")
        if line.startswith("+") and not line.startswith("+++")
    )
    removed = sum(
        1
        for line in difflib.unified_diff(previous.splitlines(), current.splitlines(), lineterm="")
        if line.startswith("-") and not line.startswith("---")
    )
    return f"{added} line(s) added, {removed} removed"


class Monitor:
    """Checks targets and raises alerts."""

    def __init__(
        self,
        *,
        settings: Settings,
        store: Store,
        fetcher: Fetcher,
        dispatcher: AlertDispatcher,
    ) -> None:
        self.settings = settings
        self.store = store
        self.fetcher = fetcher
        self.dispatcher = dispatcher

    # -- one target --------------------------------------------------------------

    def check(self, target: WatchTarget) -> CheckOutcome:
        """Check one target: fetch, extract, compare, assess, alert."""
        outcome = CheckOutcome(target=target)
        logger.info("checking target", extra={"target": target.name, "url": target.url})

        try:
            response = self.fetcher.fetch(target.url)
        except (UnsafeTargetError, RobotsDisallowedError) as exc:
            # A refusal, not a failure. Recorded and alerted once so the operator fixes the
            # config, but never retried.
            outcome.error = str(exc)
            self._record(outcome)
            self._maybe_alert(
                outcome,
                kind="error",
                severity="critical",
                fingerprint=f"refused:{type(exc).__name__}",
                title=f"{target.name}: refused to fetch",
                body=str(exc),
            )
            return outcome
        except FetchError as exc:
            outcome.error = str(exc)
            self._record(outcome)
            self._maybe_alert(
                outcome,
                kind="availability",
                severity="critical",
                fingerprint="unavailable",
                title=f"{target.name} is unreachable",
                body=str(exc),
            )
            return outcome

        outcome.status_code = response.status_code
        outcome.elapsed_ms = response.elapsed_ms
        outcome.available = 200 <= response.status_code < 400

        if not outcome.available:
            outcome.error = f"HTTP {response.status_code}"
            self._record(outcome)
            self._maybe_alert(
                outcome,
                kind="availability",
                severity="critical",
                fingerprint=f"http:{response.status_code}",
                title=f"{target.name} returned HTTP {response.status_code}",
                body=f"{response.final_url} responded with {response.status_code}.",
            )
            return outcome

        # Available: clear any standing outage state so the next outage alerts again, and announce
        # the recovery once.
        if self.store.should_alert(target.name, "availability", "available"):
            # `_record` runs at the end of this method, so the current check is not stored yet:
            # recent_checks()[0] is the *previous* poll. Reading [1] here (as this originally did)
            # looked one poll too far back, and the recovery alert silently never fired.
            previous = self.store.recent_checks(target.name, limit=1)
            # Only a recovery if the previous poll had actually failed; otherwise this is just
            # the first successful poll and there is nothing to announce.
            if previous and not previous[0].available:
                self._emit(
                    outcome,
                    kind="availability",
                    severity="info",
                    title=f"{target.name} is reachable again",
                    body=f"HTTP {response.status_code} in {response.elapsed_ms:.0f} ms.",
                )

        try:
            extraction = extract(target, response.body, content_type=response.content_type)
        except ExtractionError as exc:
            outcome.error = f"extraction failed: {exc}"
            self._record(outcome)
            self._maybe_alert(
                outcome,
                kind="error",
                severity="warning",
                fingerprint=f"extraction:{content_fingerprint(str(exc))[:16]}",
                title=f"{target.name}: could not extract content",
                body=str(exc),
            )
            return outcome

        previous_snapshot = self.store.latest_snapshot(target.name)
        outcome.is_first_snapshot = previous_snapshot is None
        fingerprint = content_fingerprint(extraction.text)

        if previous_snapshot is None:
            self.store.add_snapshot(
                target_name=target.name,
                url=response.final_url,
                content=extraction.text,
                status_code=response.status_code,
                elapsed_ms=response.elapsed_ms,
                history_limit=self.settings.snapshot_history_limit,
            )
            logger.info(
                "captured the first snapshot; nothing to compare yet",
                extra={"target": target.name, "characters": len(extraction.text)},
            )
        elif previous_snapshot.content_hash != fingerprint:
            outcome.changed = True
            outcome.diff = build_diff(previous_snapshot.content, extraction.text, name=target.name)
            self.store.add_snapshot(
                target_name=target.name,
                url=response.final_url,
                content=extraction.text,
                status_code=response.status_code,
                elapsed_ms=response.elapsed_ms,
                history_limit=self.settings.snapshot_history_limit,
            )
            self._emit(
                outcome,
                kind="content_change",
                severity="warning",
                title=f"{target.name} changed ({summarise_change(previous_snapshot.content, extraction.text)})",
                body=outcome.diff,
                details={"previous_captured_at": previous_snapshot.captured_at},
            )
            # A change means the *next* identical content is the new normal, so reset the
            # content fingerprint rather than leaving the old one stored.
            self.store.should_alert(target.name, "content_change", fingerprint)
        else:
            logger.debug("no change", extra={"target": target.name})

        if target.security_check:
            outcome.security = self._assess_security(target, response)
            if outcome.security is not None:
                checks = ",".join(sorted(f.check for f in outcome.security.findings))
                if self.store.should_alert(
                    target.name, "security", content_fingerprint(checks)
                ) and outcome.security.findings:
                    worst = outcome.security.sorted_findings[0]
                    self._emit(
                        outcome,
                        kind="security",
                        severity="critical" if worst.severity == "high" else "warning",
                        title=(
                            f"{target.name}: security posture changed "
                            f"(grade {outcome.security.grade}, score {outcome.security.score})"
                        ),
                        body="\n".join(
                            f"- [{finding.severity}] {finding.summary}"
                            for finding in outcome.security.sorted_findings[:10]
                        ),
                        details={
                            "score": outcome.security.score,
                            "grade": outcome.security.grade,
                            "certificate_days_left": outcome.security.certificate_days_left,
                        },
                    )

        self._record(outcome)
        return outcome

    def _assess_security(self, target: WatchTarget, response: object) -> SecurityReport | None:
        from urllib.parse import urlparse

        from .fetcher import FetchResult

        assert isinstance(response, FetchResult)
        parsed = urlparse(response.final_url)
        host = parsed.hostname
        if not host:  # pragma: no cover - a fetched URL always has a host
            return None
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        try:
            return assess(
                url=response.final_url,
                headers=response.headers,
                body=response.body,
                host=host,
                port=port,
                address=response.resolved_address or None,
                timeout=self.settings.request_timeout_seconds,
            )
        except Exception as exc:
            # The security assessment is a bonus, not the core job. Never let it break a check.
            logger.warning(
                "security assessment failed",
                extra={"target": target.name, "error": str(exc)[:200]},
            )
            return None

    # -- alert plumbing ----------------------------------------------------------

    def _maybe_alert(
        self,
        outcome: CheckOutcome,
        *,
        kind: str,
        severity: str,
        fingerprint: str,
        title: str,
        body: str,
    ) -> None:
        """Emit an alert only when this is a new state for ``(target, kind)``."""
        if self.store.should_alert(outcome.target.name, kind, fingerprint):
            self._emit(outcome, kind=kind, severity=severity, title=title, body=body)
        else:
            logger.debug(
                "suppressing a repeat alert", extra={"target": outcome.target.name, "kind": kind}
            )

    def _emit(
        self,
        outcome: CheckOutcome,
        *,
        kind: str,
        severity: str,
        title: str,
        body: str = "",
        details: dict[str, object] | None = None,
    ) -> None:
        alert = Alert(
            target_name=outcome.target.name,
            url=outcome.target.url,
            kind=kind,  # type: ignore[arg-type]
            severity=severity,  # type: ignore[arg-type]
            title=title,
            body=body,
            details=details or {},
        )
        outcome.alerts.append(alert)
        self.dispatcher.dispatch(alert)

    def _record(self, outcome: CheckOutcome) -> None:
        self.store.record_check(
            target_name=outcome.target.name,
            available=outcome.available,
            status_code=outcome.status_code,
            elapsed_ms=outcome.elapsed_ms,
            changed=outcome.changed,
            error=outcome.error,
        )

    # -- many targets ------------------------------------------------------------

    def check_all(self, targets: list[WatchTarget]) -> list[CheckOutcome]:
        """Check every enabled target in order, surviving individual failures."""
        outcomes: list[CheckOutcome] = []
        for target in targets:
            if not target.enabled:
                logger.debug("skipping disabled target", extra={"target": target.name})
                continue
            try:
                outcomes.append(self.check(target))
            except Exception:
                # One target must never stop the run.
                logger.exception("unexpected error checking a target", extra={"target": target.name})
                outcomes.append(CheckOutcome(target=target, error="unexpected internal error"))
        return outcomes


class Scheduler:
    """Runs due targets on their own intervals, with jitter.

    Jitter matters: without it, twenty targets on a 60-minute schedule all fire in the same second
    every hour, which looks like a burst to every site being polled and defeats the per-host
    politeness gap.
    """

    def __init__(self, monitor: Monitor, *, jitter_fraction: float = 0.1) -> None:
        self.monitor = monitor
        self.jitter_fraction = jitter_fraction
        self._due_at: dict[str, float] = {}
        self._stopping = False

    def request_stop(self) -> None:
        self._stopping = True

    def _next_due(self, target: WatchTarget, *, now: float) -> float:
        jitter = target.interval_seconds * self.jitter_fraction
        return now + target.interval_seconds + random.uniform(0, jitter)  # noqa: S311 - not crypto

    def due_targets(self, targets: list[WatchTarget], *, now: float) -> list[WatchTarget]:
        """Targets whose next check time has arrived. Unseen targets are due immediately."""
        due = []
        for target in targets:
            if not target.enabled:
                continue
            if self._due_at.get(target.name, 0.0) <= now:
                due.append(target)
        return due

    def run_once(self, targets: list[WatchTarget], *, now: float | None = None) -> list[CheckOutcome]:
        """Check whatever is due, and schedule each one's next check."""
        moment = now if now is not None else time.monotonic()
        due = self.due_targets(targets, now=moment)
        outcomes = self.monitor.check_all(due)
        for target in due:
            self._due_at[target.name] = self._next_due(target, now=moment)
        return outcomes

    def run_forever(
        self,
        targets: list[WatchTarget],
        *,
        tick_seconds: float = 30.0,
        max_ticks: int | None = None,
    ) -> int:
        """Poll on a loop until stopped. Returns the number of checks performed."""
        performed = 0
        ticks = 0
        logger.info(
            "scheduler started",
            extra={"targets": sum(1 for target in targets if target.enabled)},
        )
        while not self._stopping:
            if max_ticks is not None and ticks >= max_ticks:
                break
            ticks += 1
            performed += len(self.run_once(targets))
            if not self._stopping:
                time.sleep(tick_seconds)
        logger.info("scheduler stopped", extra={"checks": performed})
        return performed


def summarise_run(outcomes: list[CheckOutcome]) -> dict[str, object]:
    """Aggregate a run for the CLI and for reports."""
    return {
        "generated_at": utcnow().isoformat(timespec="seconds"),
        "checked": len(outcomes),
        "available": sum(1 for outcome in outcomes if outcome.available),
        "changed": sum(1 for outcome in outcomes if outcome.changed),
        "errors": sum(1 for outcome in outcomes if outcome.error),
        "alerts": sum(len(outcome.alerts) for outcome in outcomes),
        "first_snapshots": sum(1 for outcome in outcomes if outcome.is_first_snapshot),
    }
