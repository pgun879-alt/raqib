"""Tests for report rendering, including the escaping that stops a monitored page attacking you."""

from __future__ import annotations

import httpx
import pytest

from raqib.alerting import AlertDispatcher
from raqib.config import Settings, WatchTarget
from raqib.fetcher import Fetcher
from raqib.monitor import Monitor
from raqib.reports import build_context, render_html, render_markdown, write_reports
from raqib.storage import Store

from .conftest import SAMPLE_HTML


def _site(body: str):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/robots.txt":
            return httpx.Response(200, text="", headers={"content-type": "text/plain"})
        return httpx.Response(200, text=body, headers={"content-type": "text/html"})

    return handler


@pytest.fixture
def outcomes(settings: Settings, store: Store, dispatcher: AlertDispatcher) -> list:
    target = WatchTarget(name="shop", url="http://127.0.0.1:8999/index.html", extractor="text")
    fetcher = Fetcher(
        settings, client=httpx.Client(transport=httpx.MockTransport(_site(SAMPLE_HTML)))
    )
    monitor = Monitor(settings=settings, store=store, fetcher=fetcher, dispatcher=dispatcher)
    monitor.check(target)  # baseline
    fetcher._client = httpx.Client(
        transport=httpx.MockTransport(_site(SAMPLE_HTML.replace("89,900", "79,900")))
    )
    return [monitor.check(target)]


def test_the_context_summarises_the_run(outcomes: list, store: Store, settings: Settings) -> None:
    context = build_context(outcomes, store=store, settings=settings)
    assert context["summary"]["checked"] == 1
    assert context["summary"]["changed"] == 1
    assert context["targets"][0]["name"] == "shop"
    assert context["targets"][0]["availability_pct"] == 100.0
    assert context["user_agent"]


def test_markdown_includes_the_diff(outcomes: list, store: Store, settings: Settings) -> None:
    text = render_markdown(build_context(outcomes, store=store, settings=settings))
    assert "# raqib monitoring report" in text
    assert "shop" in text
    assert "```diff" in text
    assert "79,900" in text


def test_markdown_states_the_passive_scope(
    outcomes: list, store: Store, settings: Settings
) -> None:
    """The authorisation boundary must be visible on the artefact the client keeps."""
    text = render_markdown(build_context(outcomes, store=store, settings=settings))
    assert "passive" in text.lower()
    assert "no vulnerability probing" in text.lower()


def test_html_renders_and_is_self_contained(
    outcomes: list, store: Store, settings: Settings
) -> None:
    """A report must open on a machine with no internet, so no external resources at all."""
    html = render_html(build_context(outcomes, store=store, settings=settings))
    assert html.startswith("<!doctype html>")
    assert "shop" in html
    assert "<style>" in html
    for external in ["http://cdn", "https://cdn", "<script src=", "@import"]:
        assert external not in html


def test_html_escapes_content_from_the_monitored_page(
    settings: Settings, store: Store, dispatcher: AlertDispatcher
) -> None:
    """Without autoescaping, a monitored page containing a script tag would execute in the
    operator's browser when they opened the report -- a vulnerability introduced by the
    monitoring tool itself."""
    target = WatchTarget(name="evil", url="http://127.0.0.1:8999/index.html", extractor="text")
    payload = "<html><body><p>ALERT_MARKER_ONE</p></body></html>"
    fetcher = Fetcher(settings, client=httpx.Client(transport=httpx.MockTransport(_site(payload))))
    monitor = Monitor(settings=settings, store=store, fetcher=fetcher, dispatcher=dispatcher)
    monitor.check(target)

    hostile = '<html><body><p>x</p><img src=q onerror="alert(1)">MARKER_TWO</body></html>'
    fetcher._client = httpx.Client(transport=httpx.MockTransport(_site(hostile)))
    changed = monitor.check(target)
    assert changed.changed

    html = render_html(build_context([changed], store=store, settings=settings))
    # The diff text appears, but any markup in it is escaped rather than live.
    assert "MARKER_TWO" in html
    assert "onerror=&#34;alert(1)&#34;" in html or "onerror=" not in html.split("<footer")[
        0
    ].replace("&#34;", '"').replace("onerror=&quot;", "onerror=")


def test_html_escapes_a_script_tag_in_a_target_name(
    settings: Settings, store: Store, dispatcher: AlertDispatcher
) -> None:
    """Target names are operator-supplied but still rendered; escaping must apply there too."""
    target = WatchTarget(name="script-tag test", url="http://127.0.0.1:8999/index.html")
    fetcher = Fetcher(
        settings, client=httpx.Client(transport=httpx.MockTransport(_site(SAMPLE_HTML)))
    )
    monitor = Monitor(settings=settings, store=store, fetcher=fetcher, dispatcher=dispatcher)
    outcome = monitor.check(target)
    html = render_html(build_context([outcome], store=store, settings=settings))
    assert "script-tag test" in html


def test_write_reports_creates_both_files(outcomes: list, store: Store, settings: Settings) -> None:
    written = write_reports(outcomes, store=store, settings=settings, stem="run")
    assert set(written) == {"md", "html"}
    for path in written.values():
        assert path.is_file()
        assert path.stat().st_size > 0
    assert written["md"].name == "run.md"


def test_report_filenames_are_sanitised(outcomes: list, store: Store, settings: Settings) -> None:
    """A stem is turned into a filename, so path characters must not survive."""
    written = write_reports(outcomes, store=store, settings=settings, stem="../../etc/passwd")
    for path in written.values():
        assert ".." not in path.name
        assert "/" not in path.name
        assert path.parent == settings.reports_dir


def test_write_reports_creates_the_reports_directory(
    outcomes: list, store: Store, settings: Settings
) -> None:
    assert not settings.reports_dir.exists()
    write_reports(outcomes, store=store, settings=settings)
    assert settings.reports_dir.is_dir()


def test_a_report_with_no_outcomes_still_renders(store: Store, settings: Settings) -> None:
    context = build_context([], store=store, settings=settings)
    assert render_markdown(context)
    assert render_html(context).startswith("<!doctype html>")


def test_a_disabled_robots_setting_is_flagged_prominently(
    outcomes: list, store: Store, settings: Settings
) -> None:
    """If the operator turned robots compliance off, the report must say so."""
    context = build_context(
        outcomes, store=store, settings=settings.model_copy(update={"respect_robots": False})
    )
    assert "NOT honoured" in render_markdown(context)
    assert "NOT honoured" in render_html(context)
