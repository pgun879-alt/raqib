"""Shared fixtures. Nothing here touches the network."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from raqib.alerting import Alert, AlertDispatcher, AlertSink
from raqib.config import Settings, WatchTarget
from raqib.storage import Store


class RecordingSink(AlertSink):
    """Captures alerts instead of delivering them."""

    name = "recording"

    def __init__(self, *, fail: bool = False) -> None:
        self.alerts: list[Alert] = []
        self.fail = fail
        self.closed = False

    def send(self, alert: Alert) -> None:
        if self.fail:
            raise RuntimeError("recording sink failure")
        self.alerts.append(alert)

    def close(self) -> None:
        self.closed = True

    def titles(self) -> list[str]:
        return [alert.title for alert in self.alerts]

    def kinds(self) -> list[str]:
        return [alert.kind for alert in self.alerts]


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(
        db_path=tmp_path / "raqib.sqlite3",
        targets_file=tmp_path / "targets.yaml",
        reports_dir=tmp_path / "reports",
        alert_file=tmp_path / "alerts.jsonl",
        alert_sinks=("file",),
        min_seconds_between_requests_per_host=0.0,
        allow_private_targets=True,
        max_attempts=1,
        retry_backoff_base_seconds=0.01,
        log_level="WARNING",
    )


@pytest.fixture
def store(settings: Settings) -> Iterator[Store]:
    with Store(settings.db_path) as opened:
        yield opened


@pytest.fixture
def sink() -> RecordingSink:
    return RecordingSink()


@pytest.fixture
def dispatcher(sink: RecordingSink) -> AlertDispatcher:
    return AlertDispatcher([sink])


@pytest.fixture
def target() -> WatchTarget:
    return WatchTarget(name="demo", url="http://127.0.0.1:8999/index.html", extractor="text")


SAMPLE_HTML = """<!doctype html>
<html><head><title>Shop</title>
<script>console.log("must be stripped");</script>
<style>.x{color:red}</style>
</head><body>
<!-- a comment that must be stripped -->
<h1>Catalogue</h1>
<p class="generated">Generated at 2026-09-28T01:00:00Z</p>
<table id="catalogue"><tr><td>Air conditioner</td><td class="price">89,900 DZD</td></tr></table>
<p>Free delivery over 8,000 DZD.</p>
</body></html>
"""

SAMPLE_JSON = """{"generated_at": "2026-09-28T01:00:00Z",
 "products": [{"sku": "AC-12000", "price": 89900, "in_stock": true}]}"""
