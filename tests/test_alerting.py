"""Tests for alert sinks and the dispatcher."""

from __future__ import annotations

import json

import httpx
import pytest

from raqib.alerting import (
    Alert,
    AlertDispatcher,
    FileSink,
    StdoutSink,
    TelegramSink,
    WebhookSink,
    build_dispatcher,
)
from raqib.config import Settings

from .conftest import RecordingSink


def _alert(**overrides: object) -> Alert:
    fields: dict[str, object] = {
        "target_name": "demo",
        "url": "https://example.com/",
        "kind": "content_change",
        "severity": "warning",
        "title": "demo changed",
        "body": "-old\n+new",
    }
    fields.update(overrides)
    return Alert(**fields)  # type: ignore[arg-type]


# --------------------------------------------------------------------- the alert


def test_an_alert_serialises_every_field() -> None:
    payload = _alert(details={"score": 70}).to_dict()
    assert payload["target"] == "demo"
    assert payload["kind"] == "content_change"
    assert payload["details"] == {"score": 70}
    assert payload["created_at"]


def test_the_text_rendering_includes_severity_target_and_body() -> None:
    text = _alert().as_text()
    assert "[WARNING]" in text
    assert "demo changed" in text
    assert "https://example.com/" in text
    assert "+new" in text


# --------------------------------------------------------------------- file sink


def test_the_file_sink_appends_one_json_object_per_line(tmp_path) -> None:
    """JSON Lines rather than a growing array: appending to an array means rewriting the file,
    and a crash mid-write corrupts the whole history."""
    path = tmp_path / "nested" / "alerts.jsonl"
    sink = FileSink(path)
    sink.send(_alert(title="first"))
    sink.send(_alert(title="second"))

    lines = path.read_text(encoding="utf-8").strip().split("\n")
    assert len(lines) == 2
    assert [json.loads(line)["title"] for line in lines] == ["first", "second"]


def test_the_file_sink_creates_its_parent_directory(tmp_path) -> None:
    path = tmp_path / "a" / "b" / "c.jsonl"
    FileSink(path).send(_alert())
    assert path.is_file()


def test_the_file_sink_keeps_arabic_readable(tmp_path) -> None:
    path = tmp_path / "alerts.jsonl"
    FileSink(path).send(_alert(title="تغيّر السعر"))
    assert "تغيّر السعر" in path.read_text(encoding="utf-8")


# --------------------------------------------------------------------- stdout sink


def test_the_stdout_sink_prints(capsys: pytest.CaptureFixture[str]) -> None:
    StdoutSink(colour=False).send(_alert(title="printed alert"))
    assert "printed alert" in capsys.readouterr().out


# --------------------------------------------------------------------- webhook sink


def test_the_webhook_sink_posts_the_alert_as_json() -> None:
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(200)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    WebhookSink("https://hooks.example/abc", client=client).send(_alert())
    body = captured["body"]
    assert isinstance(body, dict)
    assert body["target"] == "demo"
    client.close()


def test_the_webhook_sink_raises_on_an_error_status() -> None:
    client = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(500)))
    with pytest.raises(RuntimeError, match="HTTP 500"):
        WebhookSink("https://hooks.example/abc", client=client).send(_alert())
    client.close()


def test_the_webhook_sink_requires_a_url() -> None:
    with pytest.raises(ValueError, match="URL is required"):
        WebhookSink("")


# --------------------------------------------------------------------- telegram sink


def test_the_telegram_sink_sends_plain_text_without_a_parse_mode() -> None:
    """Alert bodies contain page content and diff output, so any stray Markdown character would
    break delivery or inject formatting."""
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["path"] = request.url.path
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json={"ok": True})

    client = httpx.Client(
        transport=httpx.MockTransport(handler), base_url="https://api.telegram.org/bot123:ABC"
    )
    TelegramSink(bot_token="123:ABC", chat_id="42", client=client).send(
        _alert(body="-price: *100*\n+price: _200_")
    )
    body = captured["body"]
    assert isinstance(body, dict)
    assert "parse_mode" not in body
    assert body["chat_id"] == "42"
    client.close()


def test_the_telegram_sink_truncates_to_the_api_limit() -> None:
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json={"ok": True})

    client = httpx.Client(
        transport=httpx.MockTransport(handler), base_url="https://api.telegram.org/bot123:ABC"
    )
    TelegramSink(bot_token="123:ABC", chat_id="42", client=client).send(_alert(body="x" * 9000))
    body = captured["body"]
    assert isinstance(body, dict)
    assert len(body["text"]) <= 4096
    client.close()


def test_the_telegram_sink_requires_a_token_and_chat_id() -> None:
    with pytest.raises(ValueError, match="token and chat id"):
        TelegramSink(bot_token="", chat_id="42")
    with pytest.raises(ValueError, match="token and chat id"):
        TelegramSink(bot_token="123:ABC", chat_id="")


# --------------------------------------------------------------------- dispatcher


def test_the_dispatcher_sends_to_every_sink() -> None:
    first, second = RecordingSink(), RecordingSink()
    AlertDispatcher([first, second]).dispatch(_alert())
    assert len(first.alerts) == 1
    assert len(second.alerts) == 1


def test_a_failing_sink_does_not_stop_the_others() -> None:
    """A monitoring run must survive a broken webhook. The alternative is that one misconfigured
    sink silently stops all monitoring."""
    broken, working = RecordingSink(fail=True), RecordingSink()
    dispatcher = AlertDispatcher([broken, working])
    dispatcher.dispatch(_alert())
    assert len(working.alerts) == 1
    assert dispatcher.failed == 1
    assert dispatcher.sent == 1


def test_the_dispatcher_counts_successes_and_failures() -> None:
    dispatcher = AlertDispatcher([RecordingSink(), RecordingSink(fail=True)])
    for _ in range(3):
        dispatcher.dispatch(_alert())
    assert dispatcher.sent == 3
    assert dispatcher.failed == 3


def test_closing_the_dispatcher_closes_every_sink() -> None:
    sinks = [RecordingSink(), RecordingSink()]
    AlertDispatcher(sinks).close()
    assert all(sink.closed for sink in sinks)


def test_a_sink_that_raises_on_close_does_not_propagate() -> None:
    class BadClose(RecordingSink):
        def close(self) -> None:
            raise RuntimeError("close failed")

    AlertDispatcher([BadClose()]).close()  # must not raise


# --------------------------------------------------------------------- factory


def test_the_factory_builds_the_configured_sinks(settings: Settings) -> None:
    dispatcher = build_dispatcher(
        settings.model_copy(update={"alert_sinks": ("stdout", "file")}), colour=False
    )
    assert sorted(sink.name for sink in dispatcher.sinks) == ["file", "stdout"]
    dispatcher.close()


def test_the_factory_builds_a_webhook_sink(settings: Settings) -> None:
    dispatcher = build_dispatcher(
        settings.model_copy(
            update={"alert_sinks": ("webhook",), "webhook_url": "https://hooks.example/x"}
        )
    )
    assert [sink.name for sink in dispatcher.sinks] == ["webhook"]
    dispatcher.close()


def test_the_factory_builds_a_telegram_sink(settings: Settings) -> None:
    dispatcher = build_dispatcher(
        settings.model_copy(
            update={
                "alert_sinks": ("telegram",),
                "telegram_bot_token": "123:ABC",
                "telegram_chat_id": "42",
            }
        )
    )
    assert [sink.name for sink in dispatcher.sinks] == ["telegram"]
    dispatcher.close()
