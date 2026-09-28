"""HTML and Markdown reports.

The report is the deliverable a client actually keeps. Two formats, one data structure:

* **Markdown** pastes into an email, a ticket, or a chat message.
* **HTML** is a single self-contained file -- no CDN, no external CSS, no fonts to fetch -- so it
  can be emailed as an attachment and still render on a machine with no internet.

Templates use Jinja2 with autoescaping on. Reports contain page content and diff output pulled
from third-party sites, which is untrusted text: without escaping, a monitored page containing
``<script>`` would execute in the operator's browser when they opened the report. That would be a
genuine vulnerability introduced by the monitoring tool itself.
"""

from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .config import Settings, utcnow
from .monitor import CheckOutcome, summarise_run
from .storage import Store

logger = logging.getLogger(__name__)

TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"


def _environment() -> Environment:
    return Environment(
        loader=FileSystemLoader(TEMPLATE_DIR),
        # Autoescaping is not optional here: report content comes from third-party pages.
        autoescape=select_autoescape(default_for_string=True, default=True),
        trim_blocks=True,
        lstrip_blocks=True,
    )


def _slug(name: str) -> str:
    """Filesystem-safe filename component.

    Target names are already validated against path separators, but this is the point where a
    name becomes a path, so it is checked again rather than trusted.
    """
    safe = "".join(
        character if character.isalnum() or character in "-_" else "-" for character in name
    )
    return safe.strip("-").lower() or "target"


def build_context(
    outcomes: list[CheckOutcome], *, store: Store, settings: Settings
) -> dict[str, Any]:
    """Assemble the data both templates render."""
    rows: list[dict[str, Any]] = []
    for outcome in outcomes:
        availability = store.availability_ratio(outcome.target.name)
        rows.append(
            {
                "name": outcome.target.name,
                "url": outcome.target.url,
                "available": outcome.available,
                "status_code": outcome.status_code,
                "elapsed_ms": round(outcome.elapsed_ms, 1) if outcome.elapsed_ms else None,
                "changed": outcome.changed,
                "is_first_snapshot": outcome.is_first_snapshot,
                "error": outcome.error,
                "diff": outcome.diff,
                "availability_pct": round(availability * 100, 1)
                if availability is not None
                else None,
                "snapshots": store.count_snapshots(outcome.target.name),
                "alerts": [alert.to_dict() for alert in outcome.alerts],
                "security": _security_context(outcome),
            }
        )

    return {
        "generated_at": utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "summary": summarise_run(outcomes),
        "targets": rows,
        "user_agent": settings.user_agent,
        "respect_robots": settings.respect_robots,
    }


def _security_context(outcome: CheckOutcome) -> dict[str, Any] | None:
    report = outcome.security
    if report is None:
        return None
    return {
        "score": report.score,
        "grade": report.grade,
        "tls_version": report.tls_version,
        "certificate_days_left": report.certificate_days_left,
        "certificate_expires_at": (
            report.certificate_expires_at.strftime("%Y-%m-%d")
            if isinstance(report.certificate_expires_at, datetime)
            else None
        ),
        "counts": report.counts(),
        "findings": [
            {
                "check": finding.check,
                "severity": finding.severity,
                "summary": finding.summary,
                "detail": finding.detail,
                "recommendation": finding.recommendation,
            }
            for finding in report.sorted_findings
        ],
    }


def render_markdown(context: dict[str, Any]) -> str:
    return _environment().get_template("report.md.j2").render(**context)


def render_html(context: dict[str, Any]) -> str:
    return _environment().get_template("report.html.j2").render(**context)


def write_reports(
    outcomes: list[CheckOutcome],
    *,
    store: Store,
    settings: Settings,
    stem: str | None = None,
) -> dict[str, Path]:
    """Write both report formats and return their paths."""
    context = build_context(outcomes, store=store, settings=settings)
    settings.reports_dir.mkdir(parents=True, exist_ok=True)
    base = stem or f"raqib-{utcnow().strftime('%Y%m%d-%H%M%S')}"

    written: dict[str, Path] = {}
    for suffix, renderer in (("md", render_markdown), ("html", render_html)):
        path = settings.reports_dir / f"{_slug(base)}.{suffix}"
        path.write_text(renderer(context), encoding="utf-8")
        written[suffix] = path
    logger.info("reports written", extra={"paths": ",".join(str(p) for p in written.values())})
    return written
