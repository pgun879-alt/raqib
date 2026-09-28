"""Command-line interface."""

from __future__ import annotations

import signal
import sys
from pathlib import Path
from types import FrameType
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from .alerting import build_dispatcher
from .config import Settings, get_settings, load_targets
from .fetcher import Fetcher
from .logging_setup import configure_logging
from .monitor import Monitor, Scheduler, summarise_run
from .netguard import UnsafeTargetError, validate_target
from .reports import write_reports
from .storage import Store

app = typer.Typer(
    add_completion=False,
    help="Watch web pages for content, availability and security-posture changes.",
    no_args_is_help=True,
)
console = Console()


def _bootstrap() -> Settings:
    settings = get_settings()
    configure_logging(settings.log_level, json_output=False)
    if settings.allow_private_targets:
        console.print(
            "[yellow]warning:[/] allow_private_targets is enabled. Loopback and private "
            "addresses will be fetched. Use this only for a local test server."
        )
    if not settings.respect_robots:
        console.print(
            "[red]warning:[/] respect_robots is disabled. Only monitor sites you own with this "
            "setting. See the README's authorisation section."
        )
    return settings


def _load(settings: Settings) -> list:
    try:
        return load_targets(settings.targets_file)
    except (FileNotFoundError, ValueError) as exc:
        console.print(f"[red]could not load targets:[/] {exc}")
        raise typer.Exit(code=1) from exc


@app.command()
def check(
    only: Annotated[
        list[str] | None, typer.Option("--only", help="Check just these target names.")
    ] = None,
    report: Annotated[bool, typer.Option(help="Write HTML and Markdown reports.")] = False,
) -> None:
    """Check every enabled target once."""
    settings = _bootstrap()
    targets = _load(settings)
    if only:
        wanted = set(only)
        unknown = wanted - {target.name for target in targets}
        if unknown:
            console.print(f"[red]unknown target(s):[/] {', '.join(sorted(unknown))}")
            raise typer.Exit(code=1)
        targets = [target for target in targets if target.name in wanted]
    if not targets:
        console.print("[yellow]no targets to check[/]")
        raise typer.Exit(code=1)

    with Store(settings.db_path) as store, Fetcher(settings) as fetcher:
        dispatcher = build_dispatcher(settings)
        try:
            outcomes = Monitor(
                settings=settings, store=store, fetcher=fetcher, dispatcher=dispatcher
            ).check_all(targets)
        finally:
            dispatcher.close()

        summary = summarise_run(outcomes)
        table = Table(title="Check results")
        for column in ("target", "status", "http", "ms", "changed", "note"):
            table.add_column(column)
        for outcome in outcomes:
            state = (
                "[red]error[/]"
                if outcome.error
                else "[yellow]changed[/]"
                if outcome.changed
                else "[dim]first[/]"
                if outcome.is_first_snapshot
                else "[green]ok[/]"
            )
            table.add_row(
                outcome.target.name,
                state,
                str(outcome.status_code or "-"),
                f"{outcome.elapsed_ms:.0f}" if outcome.elapsed_ms else "-",
                "yes" if outcome.changed else "no",
                (outcome.error or "")[:60],
            )
        console.print(table)
        console.print(
            f"checked={summary['checked']} available={summary['available']} "
            f"changed={summary['changed']} errors={summary['errors']} alerts={summary['alerts']}"
        )

        if report:
            written = write_reports(outcomes, store=store, settings=settings)
            for kind, path in written.items():
                console.print(f"[green]{kind} report:[/] {path}")

    # A non-zero exit lets cron or CI treat errors as a failure.
    raise typer.Exit(code=1 if summary["errors"] else 0)


@app.command()
def watch(
    tick_seconds: Annotated[
        float, typer.Option(min=1.0, help="Seconds between scheduler ticks.")
    ] = 30.0,
    max_ticks: Annotated[
        int | None, typer.Option(help="Stop after this many ticks (demos/tests).")
    ] = None,
) -> None:
    """Run continuously, checking each target on its own interval."""
    settings = _bootstrap()
    targets = _load(settings)
    if not targets:
        console.print("[yellow]no targets to watch[/]")
        raise typer.Exit(code=1)

    with Store(settings.db_path) as store, Fetcher(settings) as fetcher:
        dispatcher = build_dispatcher(settings)
        monitor = Monitor(settings=settings, store=store, fetcher=fetcher, dispatcher=dispatcher)
        scheduler = Scheduler(monitor, jitter_fraction=settings.scheduler_jitter_fraction)

        def handler(signum: int, _frame: FrameType | None) -> None:
            console.print(f"\n[cyan]signal {signum} received; finishing the current tick[/]")
            scheduler.request_stop()

        signal.signal(signal.SIGINT, handler)
        signal.signal(signal.SIGTERM, handler)

        enabled = sum(1 for target in targets if target.enabled)
        console.print(f"[cyan]watching {enabled} target(s)[/]  (Ctrl-C to stop)")
        try:
            performed = scheduler.run_forever(
                targets, tick_seconds=tick_seconds, max_ticks=max_ticks
            )
        finally:
            dispatcher.close()
        console.print(f"performed {performed} check(s)")


@app.command("list")
def list_targets() -> None:
    """List configured targets."""
    settings = _bootstrap()
    targets = _load(settings)
    if not targets:
        console.print("[yellow]no targets configured[/]")
        return
    table = Table(title=f"Targets in {settings.targets_file}")
    for column in ("name", "url", "every", "extractor", "selector", "security", "enabled"):
        table.add_column(column)
    for target in targets:
        table.add_row(
            target.name,
            target.url,
            f"{target.interval_minutes}m",
            target.extractor,
            target.selector or "-",
            "yes" if target.security_check else "no",
            "yes" if target.enabled else "[dim]no[/]",
        )
    console.print(table)


@app.command()
def validate() -> None:
    """Validate the targets file and check every URL against the SSRF guard without fetching."""
    settings = _bootstrap()
    targets = _load(settings)
    console.print(f"[green]targets file is valid[/] ({len(targets)} target(s))\n")

    problems = 0
    for target in targets:
        try:
            resolved = validate_target(target.url, allow_private=settings.allow_private_targets)
            console.print(
                f"[green]ok[/]     {target.name}: {resolved.url} -> {', '.join(resolved.addresses)}"
            )
        except UnsafeTargetError as exc:
            problems += 1
            console.print(f"[red]refused[/] {target.name}: {exc}")
    if problems:
        console.print(f"\n[red]{problems} target(s) would be refused[/]")
        raise typer.Exit(code=1)
    console.print("\n[green]every target passed validation[/]")


@app.command()
def history(
    name: Annotated[str, typer.Argument(help="Target name.")],
    limit: Annotated[int, typer.Option(min=1, max=100)] = 10,
) -> None:
    """Show snapshot and check history for a target."""
    settings = _bootstrap()
    with Store(settings.db_path) as store:
        snapshots = store.snapshot_history(name, limit=limit)
        checks = store.recent_checks(name, limit=limit)
        if not snapshots and not checks:
            console.print(f"[yellow]no history for {name!r}[/]")
            raise typer.Exit(code=1)

        if snapshots:
            table = Table(title=f"Snapshots for {name}")
            for column in ("id", "captured", "hash", "chars", "http"):
                table.add_column(column)
            for snapshot in snapshots:
                table.add_row(
                    str(snapshot.id),
                    snapshot.captured_at,
                    snapshot.content_hash[:12],
                    str(len(snapshot.content)),
                    str(snapshot.status_code or "-"),
                )
            console.print(table)

        if checks:
            table = Table(title=f"Recent checks for {name}")
            for column in ("checked", "available", "http", "ms", "changed", "error"):
                table.add_column(column)
            for record in checks:
                table.add_row(
                    record.checked_at,
                    "yes" if record.available else "[red]no[/]",
                    str(record.status_code or "-"),
                    f"{record.elapsed_ms:.0f}" if record.elapsed_ms else "-",
                    "yes" if record.changed else "no",
                    (record.error or "")[:40],
                )
            console.print(table)

        ratio = store.availability_ratio(name)
        if ratio is not None:
            console.print(f"availability over recent checks: [cyan]{ratio * 100:.1f}%[/]")


@app.command()
def diff(
    name: Annotated[str, typer.Argument(help="Target name.")],
) -> None:
    """Show the diff between the two most recent snapshots of a target."""
    from .monitor import build_diff

    settings = _bootstrap()
    with Store(settings.db_path) as store:
        snapshots = store.snapshot_history(name, limit=2)
        if len(snapshots) < 2:
            console.print(f"[yellow]{name!r} has fewer than two snapshots to compare[/]")
            raise typer.Exit(code=1)
        current, previous = snapshots[0], snapshots[1]
        rendered = build_diff(previous.content, current.content, name=name, max_lines=200)
        if not rendered:
            console.print("[green]the two most recent snapshots are identical[/]")
            return
        console.print(f"[dim]{previous.captured_at} -> {current.captured_at}[/]\n")
        for line in rendered.splitlines():
            if line.startswith("+") and not line.startswith("+++"):
                console.print(f"[green]{line}[/]")
            elif line.startswith("-") and not line.startswith("---"):
                console.print(f"[red]{line}[/]")
            elif line.startswith("@@"):
                console.print(f"[cyan]{line}[/]")
            else:
                console.print(f"[dim]{line}[/]")


@app.command()
def forget(
    name: Annotated[str, typer.Argument(help="Target name to remove all history for.")],
    yes: Annotated[bool, typer.Option("--yes", help="Skip the confirmation prompt.")] = False,
) -> None:
    """Delete all stored snapshots, checks and alert state for a target."""
    settings = _bootstrap()
    if not yes:
        typer.confirm(f"Delete all stored history for {name!r}?", abort=True)
    with Store(settings.db_path) as store:
        store.forget_target(name)
    console.print(f"[green]forgot[/] {name}")


@app.command("report")
def report_command(
    output_stem: Annotated[str | None, typer.Option(help="Filename stem for the reports.")] = None,
) -> None:
    """Check every target and write HTML and Markdown reports."""
    settings = _bootstrap()
    targets = _load(settings)
    with Store(settings.db_path) as store, Fetcher(settings) as fetcher:
        dispatcher = build_dispatcher(settings)
        try:
            outcomes = Monitor(
                settings=settings, store=store, fetcher=fetcher, dispatcher=dispatcher
            ).check_all(targets)
        finally:
            dispatcher.close()
        written = write_reports(outcomes, store=store, settings=settings, stem=output_stem)
    for kind, path in written.items():
        console.print(f"[green]{kind}:[/] {path}")


@app.command()
def config() -> None:
    """Print the effective configuration, with secrets redacted."""
    try:
        settings = get_settings()
    except Exception as exc:
        # Broad on purpose: this command exists to explain why configuration is invalid.
        console.print(f"[red]configuration is invalid:[/] {exc}")
        raise typer.Exit(code=1) from exc

    table = Table(title="Effective configuration")
    table.add_column("setting")
    table.add_column("value")
    redacted = {"webhook_url", "telegram_bot_token"}
    for key, value in settings.model_dump().items():
        table.add_row(key, "<set, redacted>" if key in redacted and value else str(value))
    console.print(table)


@app.command("serve-demo")
def serve_demo(
    port: Annotated[int, typer.Option(min=1024, max=65535)] = 8999,
    directory: Annotated[Path, typer.Option(help="Directory to serve.")] = Path("demo_site"),
) -> None:
    """Serve the bundled demo site on loopback, for the offline demo.

    Binds 127.0.0.1 only. This is a static file server for demonstration; it is not part of the
    monitoring product and should never be exposed.
    """
    import functools
    import http.server
    import socketserver

    if not directory.is_dir():
        console.print(f"[red]{directory} is not a directory[/]")
        raise typer.Exit(code=1)

    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(directory))

    class QuietServer(socketserver.TCPServer):
        allow_reuse_address = True

    with QuietServer(("127.0.0.1", port), handler) as httpd:
        console.print(f"[cyan]serving {directory} on http://127.0.0.1:{port}[/]  (Ctrl-C to stop)")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            console.print("\nstopped")


def main() -> None:  # pragma: no cover - console entry point
    try:
        app()
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":  # pragma: no cover
    main()
