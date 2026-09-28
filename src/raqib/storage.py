"""SQLite storage for snapshot history, alert de-duplication and check results.

The one design point worth explaining: **alerts are de-duplicated by content hash, not by time.**

A monitor that alerts on every poll while a condition persists is a monitor people mute. So an
alert fires when the *state changes*, and the previous state is stored. A page that changed once
produces one alert; a site that has been down for six hours produces one alert, not seventy-two.
"""

from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Final

from .config import utcnow

logger = logging.getLogger(__name__)

SCHEMA_VERSION: Final = 1

_SCHEMA: Final = """
CREATE TABLE IF NOT EXISTS snapshots (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    target_name  TEXT    NOT NULL,
    url          TEXT    NOT NULL,
    content_hash TEXT    NOT NULL,
    content      TEXT    NOT NULL,
    status_code  INTEGER,
    elapsed_ms   REAL,
    captured_at  TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_snapshots_target ON snapshots(target_name, id DESC);

CREATE TABLE IF NOT EXISTS checks (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    target_name  TEXT    NOT NULL,
    checked_at   TEXT    NOT NULL,
    available    INTEGER NOT NULL,
    status_code  INTEGER,
    elapsed_ms   REAL,
    changed      INTEGER NOT NULL DEFAULT 0,
    error        TEXT
);
CREATE INDEX IF NOT EXISTS idx_checks_target ON checks(target_name, id DESC);

-- One row per (target, alert kind). The stored fingerprint is what makes an alert fire on a
-- state *change* rather than on every poll.
CREATE TABLE IF NOT EXISTS alert_state (
    target_name  TEXT NOT NULL,
    kind         TEXT NOT NULL,
    fingerprint  TEXT NOT NULL,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    occurrences  INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (target_name, kind)
);

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


def content_fingerprint(text: str) -> str:
    """Stable hash of extracted content, used to decide whether anything changed."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class Snapshot:
    """One captured state of a target."""

    id: int
    target_name: str
    url: str
    content_hash: str
    content: str
    status_code: int | None
    elapsed_ms: float | None
    captured_at: str


@dataclass(frozen=True, slots=True)
class CheckRecord:
    """One poll's outcome."""

    id: int
    target_name: str
    checked_at: str
    available: bool
    status_code: int | None
    elapsed_ms: float | None
    changed: bool
    error: str | None


class Store:
    """Owns the SQLite connection and all reads and writes."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        if str(db_path) != ":memory:":
            db_path.parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(str(db_path), check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA journal_mode = WAL")
        self._connection.execute("PRAGMA synchronous = NORMAL")
        self._connection.execute("PRAGMA busy_timeout = 5000")
        self._migrate()

    def _migrate(self) -> None:
        with self._transaction() as connection:
            connection.executescript(_SCHEMA)
            connection.execute(
                "INSERT INTO meta(key, value) VALUES('schema_version', ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (str(SCHEMA_VERSION),),
            )

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        try:
            with self._connection:
                yield self._connection
        except sqlite3.Error as exc:  # pragma: no cover - defensive
            raise RuntimeError(f"database error: {exc}") from exc

    def close(self) -> None:
        self._connection.close()

    def __enter__(self) -> Store:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    # -- snapshots ---------------------------------------------------------------

    def latest_snapshot(self, target_name: str) -> Snapshot | None:
        row = self._connection.execute(
            "SELECT * FROM snapshots WHERE target_name = ? ORDER BY id DESC LIMIT 1",
            (target_name,),
        ).fetchone()
        return _to_snapshot(row) if row else None

    def add_snapshot(
        self,
        *,
        target_name: str,
        url: str,
        content: str,
        status_code: int | None,
        elapsed_ms: float | None,
        history_limit: int,
    ) -> Snapshot:
        """Store a snapshot and prune the target's history to ``history_limit``."""
        fingerprint = content_fingerprint(content)
        captured_at = utcnow().isoformat(timespec="seconds")
        with self._transaction() as connection:
            cursor = connection.execute(
                "INSERT INTO snapshots(target_name, url, content_hash, content, status_code,"
                " elapsed_ms, captured_at) VALUES(?, ?, ?, ?, ?, ?, ?)",
                (target_name, url, fingerprint, content, status_code, elapsed_ms, captured_at),
            )
            snapshot_id = int(cursor.lastrowid or 0)
            # Keep the newest N. Unbounded history would grow without limit on a page that
            # changes often, and old bodies are the bulkiest thing here.
            connection.execute(
                "DELETE FROM snapshots WHERE target_name = ? AND id NOT IN ("
                "  SELECT id FROM snapshots WHERE target_name = ? ORDER BY id DESC LIMIT ?"
                ")",
                (target_name, target_name, history_limit),
            )
        return Snapshot(
            id=snapshot_id,
            target_name=target_name,
            url=url,
            content_hash=fingerprint,
            content=content,
            status_code=status_code,
            elapsed_ms=elapsed_ms,
            captured_at=captured_at,
        )

    def snapshot_history(self, target_name: str, *, limit: int = 20) -> list[Snapshot]:
        rows = self._connection.execute(
            "SELECT * FROM snapshots WHERE target_name = ? ORDER BY id DESC LIMIT ?",
            (target_name, limit),
        ).fetchall()
        return [_to_snapshot(row) for row in rows]

    def count_snapshots(self, target_name: str) -> int:
        row = self._connection.execute(
            "SELECT COUNT(*) AS total FROM snapshots WHERE target_name = ?", (target_name,)
        ).fetchone()
        return int(row["total"])

    # -- checks ------------------------------------------------------------------

    def record_check(
        self,
        *,
        target_name: str,
        available: bool,
        status_code: int | None,
        elapsed_ms: float | None,
        changed: bool,
        error: str | None,
    ) -> CheckRecord:
        checked_at = utcnow().isoformat(timespec="seconds")
        with self._transaction() as connection:
            cursor = connection.execute(
                "INSERT INTO checks(target_name, checked_at, available, status_code, elapsed_ms,"
                " changed, error) VALUES(?, ?, ?, ?, ?, ?, ?)",
                (
                    target_name,
                    checked_at,
                    int(available),
                    status_code,
                    elapsed_ms,
                    int(changed),
                    error,
                ),
            )
        return CheckRecord(
            id=int(cursor.lastrowid or 0),
            target_name=target_name,
            checked_at=checked_at,
            available=available,
            status_code=status_code,
            elapsed_ms=elapsed_ms,
            changed=changed,
            error=error,
        )

    def recent_checks(self, target_name: str, *, limit: int = 50) -> list[CheckRecord]:
        rows = self._connection.execute(
            "SELECT * FROM checks WHERE target_name = ? ORDER BY id DESC LIMIT ?",
            (target_name, limit),
        ).fetchall()
        return [
            CheckRecord(
                id=int(row["id"]),
                target_name=str(row["target_name"]),
                checked_at=str(row["checked_at"]),
                available=bool(row["available"]),
                status_code=int(row["status_code"]) if row["status_code"] is not None else None,
                elapsed_ms=float(row["elapsed_ms"]) if row["elapsed_ms"] is not None else None,
                changed=bool(row["changed"]),
                error=str(row["error"]) if row["error"] is not None else None,
            )
            for row in rows
        ]

    def availability_ratio(self, target_name: str, *, limit: int = 100) -> float | None:
        """Fraction of the last ``limit`` checks that found the target available."""
        rows = self._connection.execute(
            "SELECT available FROM (SELECT available FROM checks WHERE target_name = ?"
            " ORDER BY id DESC LIMIT ?)",
            (target_name, limit),
        ).fetchall()
        if not rows:
            return None
        return sum(int(row["available"]) for row in rows) / len(rows)

    # -- alert de-duplication ----------------------------------------------------

    def should_alert(self, target_name: str, kind: str, fingerprint: str) -> bool:
        """True when this is a new state for ``(target, kind)``.

        This is what stops a six-hour outage producing seventy-two identical alerts. The stored
        fingerprint is updated either way, so a *changed* state alerts again immediately.
        """
        now = utcnow().isoformat(timespec="seconds")
        row = self._connection.execute(
            "SELECT fingerprint FROM alert_state WHERE target_name = ? AND kind = ?",
            (target_name, kind),
        ).fetchone()

        if row is not None and str(row["fingerprint"]) == fingerprint:
            with self._transaction() as connection:
                connection.execute(
                    "UPDATE alert_state SET last_seen_at = ?, occurrences = occurrences + 1"
                    " WHERE target_name = ? AND kind = ?",
                    (now, target_name, kind),
                )
            return False

        with self._transaction() as connection:
            connection.execute(
                "INSERT INTO alert_state(target_name, kind, fingerprint, first_seen_at,"
                " last_seen_at, occurrences) VALUES(?, ?, ?, ?, ?, 1)"
                " ON CONFLICT(target_name, kind) DO UPDATE SET"
                "   fingerprint = excluded.fingerprint,"
                "   first_seen_at = excluded.first_seen_at,"
                "   last_seen_at = excluded.last_seen_at,"
                "   occurrences = 1",
                (target_name, kind, fingerprint, now, now),
            )
        return True

    def clear_alert_state(self, target_name: str, kind: str | None = None) -> None:
        """Forget stored alert state, so the next occurrence alerts again."""
        with self._transaction() as connection:
            if kind is None:
                connection.execute("DELETE FROM alert_state WHERE target_name = ?", (target_name,))
            else:
                connection.execute(
                    "DELETE FROM alert_state WHERE target_name = ? AND kind = ?",
                    (target_name, kind),
                )

    def alert_states(self) -> list[dict[str, Any]]:
        rows = self._connection.execute(
            "SELECT * FROM alert_state ORDER BY target_name, kind"
        ).fetchall()
        return [dict(row) for row in rows]

    # -- housekeeping ------------------------------------------------------------

    def forget_target(self, target_name: str) -> None:
        """Remove every trace of a target, for when it is deleted from the config."""
        with self._transaction() as connection:
            for table in ("snapshots", "checks", "alert_state"):
                connection.execute(f"DELETE FROM {table} WHERE target_name = ?", (target_name,))  # noqa: S608

    def known_targets(self) -> list[str]:
        rows = self._connection.execute(
            "SELECT DISTINCT target_name FROM snapshots UNION"
            " SELECT DISTINCT target_name FROM checks"
        ).fetchall()
        return sorted(str(row[0]) for row in rows)


def _to_snapshot(row: sqlite3.Row) -> Snapshot:
    return Snapshot(
        id=int(row["id"]),
        target_name=str(row["target_name"]),
        url=str(row["url"]),
        content_hash=str(row["content_hash"]),
        content=str(row["content"]),
        status_code=int(row["status_code"]) if row["status_code"] is not None else None,
        elapsed_ms=float(row["elapsed_ms"]) if row["elapsed_ms"] is not None else None,
        captured_at=str(row["captured_at"]),
    )


def parse_timestamp(value: str) -> datetime:
    """Parse a stored ISO timestamp back into a datetime."""
    return datetime.fromisoformat(value)


def dumps(payload: Any) -> str:
    """Compact JSON for alert payloads, with Arabic left readable."""
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str)
