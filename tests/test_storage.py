"""Tests for storage, history pruning, and alert de-duplication."""

from __future__ import annotations

from raqib.storage import Store, content_fingerprint


def _add(store: Store, name: str, content: str, *, limit: int = 5) -> None:
    store.add_snapshot(
        target_name=name,
        url="https://example.com/",
        content=content,
        status_code=200,
        elapsed_ms=12.5,
        history_limit=limit,
    )


# --------------------------------------------------------------------- snapshots


def test_the_first_snapshot_is_stored_and_retrievable(store: Store) -> None:
    assert store.latest_snapshot("t") is None
    _add(store, "t", "hello")
    latest = store.latest_snapshot("t")
    assert latest is not None
    assert latest.content == "hello"
    assert latest.content_hash == content_fingerprint("hello")
    assert latest.status_code == 200


def test_the_latest_snapshot_is_the_newest(store: Store) -> None:
    _add(store, "t", "first")
    _add(store, "t", "second")
    latest = store.latest_snapshot("t")
    assert latest is not None
    assert latest.content == "second"


def test_history_is_pruned_to_the_limit(store: Store) -> None:
    """Unbounded history would grow forever on a page that changes often, and stored page
    bodies are the bulkiest thing in the database."""
    for index in range(10):
        _add(store, "t", f"version {index}", limit=3)
    assert store.count_snapshots("t") == 3
    history = store.snapshot_history("t", limit=10)
    assert [snapshot.content for snapshot in history] == ["version 9", "version 8", "version 7"]


def test_pruning_is_per_target(store: Store) -> None:
    for index in range(6):
        _add(store, "a", f"a{index}", limit=2)
    _add(store, "b", "b0", limit=2)
    assert store.count_snapshots("a") == 2
    assert store.count_snapshots("b") == 1


def test_identical_content_yields_an_identical_fingerprint() -> None:
    assert content_fingerprint("same") == content_fingerprint("same")
    assert content_fingerprint("a") != content_fingerprint("b")


# --------------------------------------------------------------------- checks


def test_checks_are_recorded_and_ordered_newest_first(store: Store) -> None:
    store.record_check(
        target_name="t", available=True, status_code=200, elapsed_ms=10.0, changed=False, error=None
    )
    store.record_check(
        target_name="t",
        available=False,
        status_code=None,
        elapsed_ms=None,
        changed=False,
        error="boom",
    )
    checks = store.recent_checks("t")
    assert len(checks) == 2
    assert checks[0].error == "boom"
    assert checks[0].available is False
    assert checks[1].available is True


def test_availability_ratio_is_computed_over_recent_checks(store: Store) -> None:
    for available in [True, True, True, False]:
        store.record_check(
            target_name="t",
            available=available,
            status_code=200 if available else 500,
            elapsed_ms=1.0,
            changed=False,
            error=None,
        )
    assert store.availability_ratio("t") == 0.75


def test_availability_ratio_of_an_unknown_target_is_none(store: Store) -> None:
    assert store.availability_ratio("never-seen") is None


# --------------------------------------------------------------------- alert dedup


def test_a_new_state_alerts_and_a_repeat_does_not(store: Store) -> None:
    """The property that stops a six-hour outage producing seventy-two identical alerts."""
    assert store.should_alert("t", "availability", "down") is True
    for _ in range(10):
        assert store.should_alert("t", "availability", "down") is False


def test_a_changed_state_alerts_again_immediately(store: Store) -> None:
    assert store.should_alert("t", "availability", "down") is True
    assert store.should_alert("t", "availability", "up") is True
    assert store.should_alert("t", "availability", "up") is False
    assert store.should_alert("t", "availability", "down") is True


def test_alert_state_is_tracked_per_kind(store: Store) -> None:
    assert store.should_alert("t", "availability", "x") is True
    assert store.should_alert("t", "content_change", "x") is True, "a different kind is separate"
    assert store.should_alert("t", "availability", "x") is False


def test_alert_state_is_tracked_per_target(store: Store) -> None:
    assert store.should_alert("a", "availability", "down") is True
    assert store.should_alert("b", "availability", "down") is True


def test_occurrences_are_counted_while_a_state_persists(store: Store) -> None:
    store.should_alert("t", "availability", "down")
    for _ in range(4):
        store.should_alert("t", "availability", "down")
    state = next(row for row in store.alert_states() if row["target_name"] == "t")
    assert state["occurrences"] == 5


def test_occurrences_reset_when_the_state_changes(store: Store) -> None:
    for _ in range(3):
        store.should_alert("t", "availability", "down")
    store.should_alert("t", "availability", "up")
    state = next(row for row in store.alert_states() if row["target_name"] == "t")
    assert state["occurrences"] == 1


def test_clearing_alert_state_makes_the_next_occurrence_alert_again(store: Store) -> None:
    store.should_alert("t", "availability", "down")
    assert store.should_alert("t", "availability", "down") is False
    store.clear_alert_state("t", "availability")
    assert store.should_alert("t", "availability", "down") is True


def test_clearing_all_state_for_a_target(store: Store) -> None:
    store.should_alert("t", "availability", "x")
    store.should_alert("t", "content_change", "y")
    store.clear_alert_state("t")
    assert store.alert_states() == []


# --------------------------------------------------------------------- housekeeping


def test_forgetting_a_target_removes_every_trace(store: Store) -> None:
    _add(store, "t", "content")
    store.record_check(
        target_name="t", available=True, status_code=200, elapsed_ms=1.0, changed=False, error=None
    )
    store.should_alert("t", "availability", "up")
    assert "t" in store.known_targets()

    store.forget_target("t")

    assert store.latest_snapshot("t") is None
    assert store.recent_checks("t") == []
    assert store.alert_states() == []
    assert "t" not in store.known_targets()


def test_forgetting_one_target_leaves_others_alone(store: Store) -> None:
    _add(store, "a", "x")
    _add(store, "b", "y")
    store.forget_target("a")
    assert store.latest_snapshot("b") is not None


def test_known_targets_is_sorted_and_deduplicated(store: Store) -> None:
    _add(store, "zeta", "x")
    _add(store, "alpha", "y")
    store.record_check(
        target_name="alpha",
        available=True,
        status_code=200,
        elapsed_ms=1.0,
        changed=False,
        error=None,
    )
    assert store.known_targets() == ["alpha", "zeta"]


def test_the_schema_is_reusable_across_connections(settings) -> None:
    """Reopening the same file must not lose data or fail on re-running the schema."""
    with Store(settings.db_path) as first:
        _add(first, "t", "persisted")
    with Store(settings.db_path) as second:
        latest = second.latest_snapshot("t")
        assert latest is not None
        assert latest.content == "persisted"
