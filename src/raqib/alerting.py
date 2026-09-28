"""Alert delivery through pluggable sinks.

An alert is data (:class:`Alert`), and a sink decides where it goes. Four are implemented:

``stdout``   printed, with severity colouring -- the default, and enough for a cron job.
``file``     appended as JSON Lines, so ``jq`` and ``grep`` work and history is durable.
``webhook``  POSTed, for Slack/Discord/n8n/anything.
``telegram`` sent to a chat, because that is where small businesses actually read things.

Every sink failure is caught and logged. **An alert that cannot be delivered must never take down
the monitoring run** -- losing one notification is bad, losing the next hour of monitoring because
of it is worse.
"""

from __future__ import annotations

import json
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

import httpx

from .config import Settings, utcnow

logger = logging.getLogger(__name__)

AlertKind = Literal["content_change", "availability", "security", "error"]
AlertSeverity = Literal["info", "warning", "critical"]

_SEVERITY_COLOUR = {"info": "\033[0;36m", "warning": "\033[0;33m", "critical": "\033[0;31m"}
_RESET = "\033[0m"


@dataclass(frozen=True, slots=True)
class Alert:
    """Something the operator should know about."""

    target_name: str
    url: str
    kind: AlertKind
    severity: AlertSeverity
    title: str
    body: str = ""
    details: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: utcnow().isoformat(timespec="seconds"))

    def to_dict(self) -> dict[str, Any]:
        return {
            "created_at": self.created_at,
            "target": self.target_name,
            "url": self.url,
            "kind": self.kind,
            "severity": self.severity,
            "title": self.title,
            "body": self.body,
            "details": self.details,
        }

    def as_text(self) -> str:
        """Plain-text rendering used by the stdout and Telegram sinks."""
        lines = [f"[{self.severity.upper()}] {self.title}", f"target: {self.target_name}", f"url: {self.url}"]
        if self.body:
            lines.append("")
            lines.append(self.body)
        return "\n".join(lines)


class AlertSink(ABC):
    """Somewhere an alert can be delivered."""

    name: str = "base"

    @abstractmethod
    def send(self, alert: Alert) -> None:
        """Deliver ``alert``. May raise; the dispatcher catches and logs."""

    def close(self) -> None:
        """Release any held resources. Concrete no-op; sinks with a client override it."""
        return None


class StdoutSink(AlertSink):
    """Prints alerts. The default, and enough for a cron job that mails its output."""

    name = "stdout"

    def __init__(self, *, colour: bool = True) -> None:
        self.colour = colour

    def send(self, alert: Alert) -> None:
        text = alert.as_text()
        if self.colour:
            prefix = _SEVERITY_COLOUR.get(alert.severity, "")
            print(f"{prefix}{text}{_RESET}\n")
        else:
            print(f"{text}\n")


class FileSink(AlertSink):
    """Appends alerts as JSON Lines.

    One JSON object per line, rather than a growing JSON array: appending to an array means
    rewriting the file, and a crash mid-write corrupts the whole history. JSON Lines is
    append-only, greppable, and readable by ``jq``.
    """

    name = "file"

    def __init__(self, path: Path) -> None:
        self.path = path

    def send(self, alert: Alert) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(alert.to_dict(), ensure_ascii=False) + "\n")


class WebhookSink(AlertSink):
    """POSTs the alert as JSON to a configured URL."""

    name = "webhook"

    def __init__(self, url: str, *, timeout: float = 15.0, client: httpx.Client | None = None) -> None:
        if not url:
            raise ValueError("a webhook URL is required")
        self.url = url
        self._owns_client = client is None
        self._client = client or httpx.Client(timeout=httpx.Timeout(timeout))

    def send(self, alert: Alert) -> None:
        response = self._client.post(self.url, json=alert.to_dict())
        if response.status_code >= 400:
            raise RuntimeError(f"webhook returned HTTP {response.status_code}")

    def close(self) -> None:
        if self._owns_client:
            self._client.close()


class TelegramSink(AlertSink):
    """Sends the alert to a Telegram chat."""

    name = "telegram"

    def __init__(
        self,
        *,
        bot_token: str,
        chat_id: str,
        api_base: str = "https://api.telegram.org",
        timeout: float = 15.0,
        client: httpx.Client | None = None,
    ) -> None:
        if not bot_token or not chat_id:
            raise ValueError("a Telegram bot token and chat id are required")
        self.chat_id = chat_id
        self._owns_client = client is None
        self._client = client or httpx.Client(
            base_url=f"{api_base.rstrip('/')}/bot{bot_token}", timeout=httpx.Timeout(timeout)
        )

    def send(self, alert: Alert) -> None:
        response = self._client.post(
            "/sendMessage",
            json={
                "chat_id": self.chat_id,
                # No parse_mode: alert bodies contain page content and diff output, and any
                # stray Markdown character would break delivery or inject formatting.
                "text": alert.as_text()[:4096],
                "disable_web_page_preview": True,
            },
        )
        if response.status_code >= 400:
            raise RuntimeError(f"Telegram returned HTTP {response.status_code}: {response.text[:200]}")

    def close(self) -> None:
        if self._owns_client:
            self._client.close()


class AlertDispatcher:
    """Sends each alert to every configured sink, tolerating individual failures."""

    def __init__(self, sinks: list[AlertSink]) -> None:
        self.sinks = sinks
        self.sent = 0
        self.failed = 0

    def dispatch(self, alert: Alert) -> None:
        for sink in self.sinks:
            try:
                sink.send(alert)
                self.sent += 1
            except Exception as exc:
                # Deliberately broad. A monitoring run must survive a broken webhook; the
                # alternative is that one misconfigured sink silently stops all monitoring.
                self.failed += 1
                logger.warning(
                    "alert sink failed",
                    extra={"sink": sink.name, "target": alert.target_name, "error": str(exc)[:200]},
                )

    def close(self) -> None:
        for sink in self.sinks:
            try:
                sink.close()
            except Exception as exc:  # pragma: no cover - defensive
                logger.debug("error closing sink %s: %s", sink.name, exc)


def build_dispatcher(settings: Settings, *, colour: bool = True) -> AlertDispatcher:
    """Build the dispatcher named by ``settings.alert_sinks``.

    Requirements are already enforced by :class:`~raqib.config.Settings` -- selecting the webhook
    sink without a URL fails at settings construction, not here.
    """
    sinks: list[AlertSink] = []
    for name in settings.alert_sinks:
        if name == "stdout":
            sinks.append(StdoutSink(colour=colour))
        elif name == "file":
            sinks.append(FileSink(settings.alert_file))
        elif name == "webhook":
            sinks.append(WebhookSink(str(settings.webhook_url)))
        elif name == "telegram":
            sinks.append(
                TelegramSink(
                    bot_token=str(settings.telegram_bot_token),
                    chat_id=str(settings.telegram_chat_id),
                )
            )
    return AlertDispatcher(sinks)
