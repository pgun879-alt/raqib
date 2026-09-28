"""Tests for orchestration: change detection, and when an alert does and does not fire.

The alerting rules are the product, so they are tested explicitly -- including the two bugs that
only running the tool against a real server revealed.
"""

from __future__ import annotations

import httpx
import pytest

from raqib.alerting import AlertDispatcher
from raqib.config import Settings, WatchTarget
from raqib.fetcher import Fetcher
from raqib.monitor import Monitor, Scheduler, build_diff, summarise_run
from raqib.storage import Store

from .conftest import SAMPLE_HTML, RecordingSink

ROBOTS_ALLOW = "User-agent: *\nDisallow: /private/\n"


class FakeSite:
    """A mock HTTP transport standing in for a website.

    Lets a test change the page, take the site down, or serve an error, without a network.
    """

    def __init__(self, body: str = SAMPLE_HTML, *, robots: str = ROBOTS_ALLOW) -> None:
        self.body = body
        self.robots = robots
        self.status = 200
        self.down = False
        self.headers = {"content-type": "text/html; charset=utf-8"}
        self.requests: list[str] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(str(request.url))
        if self.down:
            raise httpx.ConnectError("connection refused", request=request)
        if request.url.path == "/robots.txt":
            return httpx.Response(200, text=self.robots, headers={"content-type": "text/plain"})
        if self.status >= 400:
            return httpx.Response(self.status, text="error", headers=self.headers)
        return httpx.Response(self.status, text=self.body, headers=self.headers)

    def client(self) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(self.handler), follow_redirects=False)


@pytest.fixture
def site() -> FakeSite:
    return FakeSite()


@pytest.fixture
def monitor(
    settings: Settings, store: Store, site: FakeSite, dispatcher: AlertDispatcher
) -> Monitor:
    fetcher = Fetcher(settings, client=site.client())
    return Monitor(settings=settings, store=store, fetcher=fetcher, dispatcher=dispatcher)


@pytest.fixture
def watched() -> WatchTarget:
    return WatchTarget(
        name="shop",
        url="http://127.0.0.1:8999/index.html",
        extractor="css",
        selector="#catalogue",
    )


# --------------------------------------------------------------------- diffing


def test_build_diff_shows_added_and_removed_lines() -> None:
    diff = build_diff("a\nb\nc", "a\nB\nc", name="t")
    assert "-b" in diff
    assert "+B" in diff


def test_identical_content_produces_no_diff() -> None:
    assert build_diff("same", "same", name="t") == ""


def test_a_long_diff_is_truncated() -> None:
    before = "\n".join(str(index) for index in range(200))
    after = "\n".join(str(index * 2) for index in range(200))
    diff = build_diff(before, after, name="t", max_lines=10)
    assert len(diff.splitlines()) == 11  # 10 lines plus the omission notice
    assert "omitted" in diff


# --------------------------------------------------------------------- first check


def test_the_first_check_captures_a_baseline_and_does_not_alert(
    monitor: Monitor, watched: WatchTarget, sink: RecordingSink
) -> None:
    """A newly added target must not alert just for existing."""
    outcome = monitor.check(watched)
    assert outcome.available
    assert outcome.is_first_snapshot
    assert not outcome.changed
    assert sink.alerts == []
    assert monitor.store.latest_snapshot("shop") is not None


# --------------------------------------------------------------------- no change


def test_an_unchanged_page_does_not_alert(
    monitor: Monitor, watched: WatchTarget, sink: RecordingSink
) -> None:
    monitor.check(watched)
    outcome = monitor.check(watched)
    assert not outcome.changed
    assert sink.alerts == []


def test_a_volatile_timestamp_does_not_trigger_a_change(
    monitor: Monitor, site: FakeSite, sink: RecordingSink
) -> None:
    """The headline anti-false-positive property, end to end."""
    target = WatchTarget(
        name="page",
        url="http://127.0.0.1:8999/index.html",
        extractor="text",
        ignore_patterns=(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z",),
    )
    monitor.check(target)
    site.body = SAMPLE_HTML.replace("01:00:00", "23:59:59")
    outcome = monitor.check(target)
    assert not outcome.changed
    assert sink.alerts == []


# --------------------------------------------------------------------- change


def test_a_real_change_alerts_once_with_a_diff(
    monitor: Monitor, watched: WatchTarget, site: FakeSite, sink: RecordingSink
) -> None:
    monitor.check(watched)
    site.body = SAMPLE_HTML.replace("89,900", "79,900")
    outcome = monitor.check(watched)

    assert outcome.changed
    assert "-89,900 DZD" in outcome.diff
    assert "+79,900 DZD" in outcome.diff
    assert sink.kinds() == ["content_change"]
    assert "changed" in sink.titles()[0]


def test_a_change_is_not_re_alerted_on_the_next_poll(
    monitor: Monitor, watched: WatchTarget, site: FakeSite, sink: RecordingSink
) -> None:
    monitor.check(watched)
    site.body = SAMPLE_HTML.replace("89,900", "79,900")
    monitor.check(watched)
    sink.alerts.clear()
    outcome = monitor.check(watched)
    assert not outcome.changed
    assert sink.alerts == []


def test_a_second_distinct_change_alerts_again(
    monitor: Monitor, watched: WatchTarget, site: FakeSite, sink: RecordingSink
) -> None:
    monitor.check(watched)
    site.body = SAMPLE_HTML.replace("89,900", "79,900")
    monitor.check(watched)
    site.body = SAMPLE_HTML.replace("89,900", "69,900")
    sink.alerts.clear()
    assert monitor.check(watched).changed
    assert sink.kinds() == ["content_change"]


def test_a_change_stores_a_new_snapshot(
    monitor: Monitor, watched: WatchTarget, site: FakeSite
) -> None:
    monitor.check(watched)
    site.body = SAMPLE_HTML.replace("89,900", "79,900")
    monitor.check(watched)
    assert monitor.store.count_snapshots("shop") == 2


# --------------------------------------------------------------------- availability


def test_an_http_error_alerts_once(
    monitor: Monitor, watched: WatchTarget, site: FakeSite, sink: RecordingSink
) -> None:
    monitor.check(watched)
    sink.alerts.clear()
    site.status = 404
    outcome = monitor.check(watched)
    assert not outcome.available
    assert sink.kinds() == ["availability"]

    sink.alerts.clear()
    monitor.check(watched)
    assert sink.alerts == [], "a persisting error must not re-alert"


def test_an_outage_is_reported_as_unreachable_not_as_a_robots_refusal(
    monitor: Monitor, watched: WatchTarget, site: FakeSite, sink: RecordingSink
) -> None:
    """Regression guard for a bug found by running the tool against a real server.

    robots.txt is fetched before the page. When the host is down, that fetch fails too, and the
    fail-closed policy produced a "robots.txt disallows this URL" error -- sending the operator to
    edit a YAML file while their server was down. It was also the wrong retry behaviour: a
    published rule should never be retried, an outage should.
    """
    # Host down from the very first check, so robots.txt has never been read and the fail-closed
    # placeholder is what the fetcher has to work from. This is exactly where the bug appeared.
    site.down = True
    outcome = monitor.check(watched)

    assert not outcome.available
    assert outcome.error is not None
    assert "disallows" not in outcome.error, "an outage must not be reported as a robots refusal"
    assert "unreachable" in outcome.error
    assert sink.kinds() == ["availability"]
    assert "unreachable" in sink.titles()[0]


def test_an_outage_after_robots_was_already_cached_reports_the_real_connection_error(
    monitor: Monitor, watched: WatchTarget, site: FakeSite, sink: RecordingSink
) -> None:
    """The other half of the same bug: once robots.txt is cached, the page fetch is what fails,
    and the operator should see that rather than anything about robots."""
    monitor.check(watched)
    sink.alerts.clear()
    site.down = True

    outcome = monitor.check(watched)
    assert not outcome.available
    assert outcome.error is not None
    assert "disallows" not in outcome.error
    assert "could not be fetched" in outcome.error
    assert sink.kinds() == ["availability"]


def test_a_fail_closed_robots_placeholder_is_not_cached(
    settings: Settings, store: Store, dispatcher: AlertDispatcher, watched: WatchTarget
) -> None:
    """Caching "we could not ask" would make a transient outage permanently poison the target.

    After the host recovers, the very next check must succeed rather than keep refusing from a
    cached denial.
    """
    site = FakeSite()
    site.down = True
    monitor = Monitor(
        settings=settings,
        store=store,
        fetcher=Fetcher(settings, client=site.client()),
        dispatcher=dispatcher,
    )
    assert monitor.check(watched).error is not None

    site.down = False
    outcome = monitor.check(watched)
    assert outcome.available, "a recovered host must not stay blocked by a cached denial"


def test_recovery_alerts_once(
    monitor: Monitor, watched: WatchTarget, site: FakeSite, sink: RecordingSink
) -> None:
    """Regression guard for a second bug found by running the tool.

    The recovery check read ``recent_checks()[1]``, but the current check is recorded *after* the
    comparison, so index 0 is already the previous poll. Looking at [1] was one poll too far back
    and the recovery alert silently never fired.
    """
    monitor.check(watched)
    site.status = 500
    monitor.check(watched)
    sink.alerts.clear()

    site.status = 200
    monitor.check(watched)
    assert sink.kinds() == ["availability"]
    assert "reachable again" in sink.titles()[0]

    sink.alerts.clear()
    monitor.check(watched)
    assert sink.alerts == [], "recovery must not be announced twice"


def test_the_first_successful_check_is_not_announced_as_a_recovery(
    monitor: Monitor, watched: WatchTarget, sink: RecordingSink
) -> None:
    monitor.check(watched)
    assert sink.alerts == []


def test_an_outage_then_recovery_then_outage_alerts_each_time(
    monitor: Monitor, watched: WatchTarget, site: FakeSite, sink: RecordingSink
) -> None:
    monitor.check(watched)
    site.status = 503
    monitor.check(watched)
    site.status = 200
    monitor.check(watched)
    site.status = 503
    monitor.check(watched)
    assert sink.kinds().count("availability") == 3


# --------------------------------------------------------------------- robots


def test_a_disallowed_url_is_refused_and_alerts_as_an_error(
    monitor: Monitor, sink: RecordingSink
) -> None:
    target = WatchTarget(name="private", url="http://127.0.0.1:8999/private/x.html")
    outcome = monitor.check(target)
    assert outcome.error is not None
    assert "disallows" in outcome.error
    assert sink.kinds() == ["error"]
    assert monitor.store.latest_snapshot("private") is None, "no content may be stored"


# --------------------------------------------------------------------- extraction


def test_a_selector_that_stops_matching_alerts_as_an_error(
    monitor: Monitor, watched: WatchTarget, site: FakeSite, sink: RecordingSink
) -> None:
    """A redesign that removes the watched element must be surfaced, not silently ignored."""
    monitor.check(watched)
    sink.alerts.clear()
    site.body = "<html><body><p>completely redesigned</p></body></html>"
    outcome = monitor.check(watched)
    assert outcome.error is not None
    assert "matched no elements" in outcome.error
    assert sink.kinds() == ["error"]


# --------------------------------------------------------------------- many targets


def test_check_all_skips_disabled_targets(monitor: Monitor) -> None:
    enabled = WatchTarget(name="on", url="http://127.0.0.1:8999/index.html")
    disabled = WatchTarget(name="off", url="http://127.0.0.1:8999/index.html", enabled=False)
    outcomes = monitor.check_all([enabled, disabled])
    assert [outcome.target.name for outcome in outcomes] == ["on"]


def test_check_all_survives_one_target_raising(monitor: Monitor, watched: WatchTarget) -> None:
    broken = WatchTarget(name="broken", url="http://127.0.0.1:8999/index.html")
    original = monitor.check

    def flaky(target: WatchTarget):
        if target.name == "broken":
            raise RuntimeError("unexpected internal failure")
        return original(target)

    monitor.check = flaky  # type: ignore[method-assign]
    outcomes = monitor.check_all([broken, watched])
    assert len(outcomes) == 2
    assert outcomes[0].error == "unexpected internal error"
    assert outcomes[1].available


def test_summarise_run_counts_each_category(monitor: Monitor, watched: WatchTarget) -> None:
    summary = summarise_run(monitor.check_all([watched]))
    assert summary["checked"] == 1
    assert summary["available"] == 1
    assert summary["first_snapshots"] == 1
    assert summary["errors"] == 0


# --------------------------------------------------------------------- scheduler


def test_an_unseen_target_is_due_immediately(monitor: Monitor, watched: WatchTarget) -> None:
    scheduler = Scheduler(monitor, jitter_fraction=0.0)
    assert scheduler.due_targets([watched], now=0.0) == [watched]


def test_a_checked_target_is_not_due_again_until_its_interval_elapses(
    monitor: Monitor, watched: WatchTarget
) -> None:
    scheduler = Scheduler(monitor, jitter_fraction=0.0)
    scheduler.run_once([watched], now=0.0)
    assert scheduler.due_targets([watched], now=10.0) == []
    assert scheduler.due_targets([watched], now=watched.interval_seconds + 1) == [watched]


def test_disabled_targets_are_never_due(monitor: Monitor) -> None:
    disabled = WatchTarget(name="off", url="http://127.0.0.1:8999/index.html", enabled=False)
    assert Scheduler(monitor).due_targets([disabled], now=0.0) == []


def test_jitter_keeps_the_next_due_time_within_the_expected_band(
    monitor: Monitor, watched: WatchTarget
) -> None:
    """Jitter stops twenty targets on the same schedule all firing in the same second."""
    scheduler = Scheduler(monitor, jitter_fraction=0.5)
    scheduler.run_once([watched], now=1000.0)
    due_at = scheduler._due_at["shop"]
    interval = watched.interval_seconds
    assert 1000.0 + interval <= due_at <= 1000.0 + interval * 1.5


def test_run_forever_stops_at_max_ticks(monitor: Monitor, watched: WatchTarget) -> None:
    assert Scheduler(monitor).run_forever([watched], tick_seconds=0.01, max_ticks=1) == 1


def test_request_stop_ends_the_loop(monitor: Monitor, watched: WatchTarget) -> None:
    scheduler = Scheduler(monitor)
    scheduler.request_stop()
    assert scheduler.run_forever([watched], tick_seconds=0.01) == 0
