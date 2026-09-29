"""Tests for settings validation and the targets file."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from raqib.config import Settings, WatchTarget, load_targets


def _base(**overrides: object) -> Settings:
    defaults: dict[str, object] = {"db_path": Path("data/t.sqlite3")}
    defaults.update(overrides)
    return Settings(_env_file=None, **defaults)  # type: ignore[arg-type]


# --------------------------------------------------------------------- settings


def test_defaults_are_safe() -> None:
    settings = _base()
    assert settings.respect_robots is True, "robots must be honoured unless deliberately disabled"
    assert settings.allow_private_targets is False, "SSRF protection must be on by default"
    assert "raqib" in settings.user_agent


def test_a_browser_impersonating_user_agent_is_refused() -> None:
    """Pretending to be Chrome is how a monitor becomes indistinguishable from an attack, and it
    removes the site owner's ability to contact whoever is polling them."""
    for agent in [
        "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36",
        "Mozilla/5.0 Chrome/120.0",
        "Safari/605.1.15",
    ]:
        with pytest.raises(ValidationError, match="impersonating"):
            _base(user_agent=agent)


def test_an_empty_user_agent_is_refused() -> None:
    with pytest.raises(ValidationError, match="must identify this tool"):
        _base(user_agent="x")


def test_an_identifiable_user_agent_is_accepted() -> None:
    assert _base(user_agent="raqib/1.0 (+https://example.com/contact)").user_agent.startswith(
        "raqib"
    )


def test_unknown_alert_sinks_are_refused() -> None:
    with pytest.raises(ValidationError, match="unknown alert sink"):
        _base(alert_sinks="carrier-pigeon")


def test_the_webhook_sink_requires_a_url() -> None:
    with pytest.raises(ValidationError, match="requires RAQIB_WEBHOOK_URL"):
        _base(alert_sinks="webhook")


def test_the_telegram_sink_requires_a_token_and_chat_id() -> None:
    with pytest.raises(ValidationError, match="TELEGRAM"):
        _base(alert_sinks="telegram")
    with pytest.raises(ValidationError, match="TELEGRAM"):
        _base(alert_sinks="telegram", telegram_bot_token="123:ABC")


def test_sinks_with_their_requirements_met_are_accepted() -> None:
    assert _base(alert_sinks="webhook", webhook_url="https://hooks.example/x").alert_sinks == (
        "webhook",
    )


def test_alert_sinks_parse_from_a_plain_environment_string(monkeypatch: pytest.MonkeyPatch) -> None:
    """pydantic-settings JSON-decodes sequence fields before validators run; NoDecode prevents
    a bare comma-separated value from crashing startup."""
    monkeypatch.setenv("RAQIB_ALERT_SINKS", "stdout,file")
    settings = Settings(_env_file=None)  # type: ignore[call-arg]
    assert settings.alert_sinks == ("stdout", "file")


def test_the_log_level_is_normalised_and_validated() -> None:
    assert _base(log_level="debug").log_level == "DEBUG"
    with pytest.raises(ValidationError, match="log_level must be one of"):
        _base(log_level="chatty")


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("min_seconds_between_requests_per_host", -1),
        ("request_timeout_seconds", 0),
        ("max_response_bytes", 10),
        ("max_redirects", -1),
        ("max_attempts", 0),
        ("scheduler_jitter_fraction", 0.9),
        ("snapshot_history_limit", 1),
    ],
)
def test_out_of_range_values_are_refused(field: str, value: object) -> None:
    with pytest.raises(ValidationError):
        _base(**{field: value})


def test_secrets_are_absent_from_the_repr() -> None:
    settings = _base(
        webhook_url="https://hooks.example/secret-path", telegram_bot_token="123:SECRET"
    )
    text = repr(settings)
    assert "secret-path" not in text
    assert "SECRET" not in text


# --------------------------------------------------------------------- watch targets


def test_a_minimal_target_is_valid() -> None:
    target = WatchTarget(name="t", url="https://example.com/")
    assert target.extractor == "text"
    assert target.enabled is True
    assert target.interval_seconds == 3600


def test_a_css_extractor_requires_a_selector() -> None:
    with pytest.raises(ValidationError, match="requires a 'selector'"):
        WatchTarget(name="t", url="https://example.com/", extractor="css")


def test_a_json_extractor_requires_a_selector() -> None:
    with pytest.raises(ValidationError, match="requires a 'selector'"):
        WatchTarget(name="t", url="https://example.com/", extractor="json")


def test_the_text_extractor_rejects_a_selector() -> None:
    """Silently ignoring it would leave the operator thinking the selector applied."""
    with pytest.raises(ValidationError, match="takes no 'selector'"):
        WatchTarget(name="t", url="https://example.com/", extractor="text", selector="#x")


def test_a_security_check_requires_an_explicit_authorisation_attestation() -> None:
    """The authorisation boundary, enforced in code rather than only documented."""
    with pytest.raises(ValidationError, match="authorised: false"):
        WatchTarget(name="t", url="https://example.com/", security_check=True)


def test_a_security_check_with_authorisation_is_accepted() -> None:
    target = WatchTarget(name="t", url="https://example.com/", security_check=True, authorised=True)
    assert target.security_check and target.authorised


def test_authorised_alone_does_not_enable_anything() -> None:
    target = WatchTarget(name="t", url="https://example.com/", authorised=True)
    assert target.security_check is False


def test_a_name_that_is_unsafe_as_a_filename_is_refused() -> None:
    """Names become report filenames, so path characters must never reach the filesystem."""
    for name in ["../etc/passwd", "a/b", "a\\b", "a:b", "a*b", "a?b", '"x"', "<x>", "a|b", "."]:
        with pytest.raises(ValidationError):
            WatchTarget(name=name, url="https://example.com/")


def test_an_invalid_ignore_pattern_is_refused_at_load_time() -> None:
    """Better to fail on startup than halfway through a monitoring run."""
    with pytest.raises(ValidationError, match="not a valid regex"):
        WatchTarget(name="t", url="https://example.com/", ignore_patterns=("[unclosed",))


def test_unknown_fields_are_refused() -> None:
    """A typo in a YAML key must not be silently ignored."""
    with pytest.raises(ValidationError):
        WatchTarget(name="t", url="https://example.com/", intervl_minutes=5)  # type: ignore[call-arg]


# --------------------------------------------------------------------- targets file


def test_a_valid_targets_file_loads(tmp_path: Path) -> None:
    path = tmp_path / "targets.yaml"
    path.write_text(
        """
targets:
  - name: prices
    url: https://example.com/prices
    interval_minutes: 15
    extractor: css
    selector: "#price"
    ignore_patterns:
      - '\\d{2}:\\d{2}'
  - name: api
    url: https://example.com/api.json
    extractor: json
    selector: data.value
""",
        encoding="utf-8",
    )
    targets = load_targets(path)
    assert [target.name for target in targets] == ["prices", "api"]
    assert targets[0].interval_minutes == 15
    assert targets[1].selector == "data.value"


def test_a_bare_list_is_accepted(tmp_path: Path) -> None:
    path = tmp_path / "targets.yaml"
    path.write_text("- name: a\n  url: https://example.com/\n", encoding="utf-8")
    assert [target.name for target in load_targets(path)] == ["a"]


def test_an_empty_file_yields_no_targets(tmp_path: Path) -> None:
    path = tmp_path / "targets.yaml"
    path.write_text("", encoding="utf-8")
    assert load_targets(path) == []


def test_a_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        load_targets(tmp_path / "absent.yaml")


def test_malformed_yaml_is_reported_clearly(tmp_path: Path) -> None:
    path = tmp_path / "targets.yaml"
    path.write_text("targets: [unclosed", encoding="utf-8")
    with pytest.raises(ValueError, match="not valid YAML"):
        load_targets(path)


def test_duplicate_target_names_are_refused(tmp_path: Path) -> None:
    """Names key snapshots, alert state and report filenames, so they must be unique."""
    path = tmp_path / "targets.yaml"
    path.write_text(
        "targets:\n  - name: dup\n    url: https://a.example/\n"
        "  - name: dup\n    url: https://b.example/\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="duplicate target name"):
        load_targets(path)


def test_an_invalid_target_in_the_file_is_reported(tmp_path: Path) -> None:
    path = tmp_path / "targets.yaml"
    path.write_text(
        "targets:\n  - name: t\n    url: https://a.example/\n    extractor: css\n", encoding="utf-8"
    )
    with pytest.raises(ValueError, match="selector"):
        load_targets(path)


def test_the_yaml_loader_cannot_construct_arbitrary_objects(tmp_path: Path) -> None:
    """safe_load, never load: full YAML can instantiate Python objects, and a targets file is
    exactly the kind of thing that gets copied between machines."""
    path = tmp_path / "targets.yaml"
    path.write_text("targets: !!python/object/apply:os.system ['echo pwned']\n", encoding="utf-8")
    with pytest.raises(ValueError, match="not valid YAML"):
        load_targets(path)


def test_notify_accepts_known_sink_names() -> None:
    target = WatchTarget(name="t", url="https://example.com/", notify=("file", "telegram"))
    assert target.notify == ("file", "telegram")


def test_notify_rejects_an_unknown_sink_name() -> None:
    """A typo would otherwise route a target's alerts to nowhere, in silence."""
    with pytest.raises(ValidationError, match="unknown notify sink"):
        WatchTarget(name="t", url="https://example.com/", notify=("telegramm",))


def test_max_concurrent_requests_is_gone() -> None:
    """It was declared, validated and advertised in .env.example, but never read at runtime.

    A setting that silently does nothing is worse than no setting: it tells the operator they
    have a control they do not have. Real concurrency needs async fan-out and a rework of the
    politeness gate, so the honest fix was to remove the knob rather than fake it.
    """
    assert not hasattr(Settings(_env_file=None), "max_concurrent_requests")
