"""Configuration and the watch-target model.

Two separate things live here:

* :class:`Settings` -- operator-level configuration from the environment.
* :class:`WatchTarget` / :func:`load_targets` -- the list of pages to watch, from a YAML file.

Targets are a file rather than environment variables because a target has structure (a selector,
a schedule, alert routing) and a person edits the list regularly. Keeping them in YAML also means
the list can be version-controlled by the operator without their secrets going with it.
"""

from __future__ import annotations

from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Any, Literal

import yaml
from pydantic import BaseModel, Field, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

ExtractorKind = Literal["text", "css", "json"]
AlertSinkName = Literal["file", "webhook", "telegram", "stdout"]

CommaSeparated = Annotated[tuple[str, ...], NoDecode]


class Settings(BaseSettings):
    """Operator configuration, validated at startup."""

    model_config = SettingsConfigDict(
        env_prefix="RAQIB_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- storage -----------------------------------------------------------------
    db_path: Path = Field(
        default=Path("data/raqib.sqlite3"),
        description="SQLite file holding snapshot history and alert state.",
    )
    targets_file: Path = Field(default=Path("targets.yaml"))
    reports_dir: Path = Field(default=Path("reports"))

    # --- politeness --------------------------------------------------------------
    user_agent: str = Field(
        default="raqib/0.1 (+https://github.com/your-username/raqib; self-hosted monitor)",
        description="Sent on every request. An identifiable agent with contact information is "
        "what lets a site owner tell a monitor from an attack.",
    )
    respect_robots: bool = Field(
        default=True,
        description="Honour robots.txt. Disable ONLY for a site you own; see the README's "
        "authorisation section.",
    )
    min_seconds_between_requests_per_host: float = Field(default=2.0, ge=0.0, le=600.0)
    max_concurrent_requests: int = Field(default=4, ge=1, le=32)
    request_timeout_seconds: float = Field(default=20.0, gt=0, le=300)
    max_response_bytes: int = Field(
        default=5 * 1024 * 1024,
        ge=1024,
        description="Responses larger than this are truncated rather than read into memory.",
    )
    max_redirects: int = Field(default=5, ge=0, le=20)

    # --- retries -----------------------------------------------------------------
    max_attempts: int = Field(default=3, ge=1, le=10)
    retry_backoff_base_seconds: float = Field(default=2.0, gt=0, le=120)

    # --- scheduling --------------------------------------------------------------
    scheduler_jitter_fraction: float = Field(
        default=0.1,
        ge=0.0,
        le=0.5,
        description="Random fraction of the interval added to each due time, so many targets "
        "sharing a schedule do not all fire in the same second.",
    )

    # --- change detection --------------------------------------------------------
    snapshot_history_limit: int = Field(
        default=20, ge=2, le=1000, description="Snapshots kept per target."
    )

    # --- safety ------------------------------------------------------------------
    allow_private_targets: bool = Field(
        default=False,
        description="Permit loopback and private addresses. Only for a local test server.",
    )

    # --- alerting ----------------------------------------------------------------
    alert_sinks: CommaSeparated = Field(default=("stdout", "file"))
    alert_file: Path = Field(default=Path("data/alerts.jsonl"))
    webhook_url: str | None = Field(default=None, repr=False)
    telegram_bot_token: str | None = Field(default=None, repr=False)
    telegram_chat_id: str | None = Field(default=None)

    # --- logging -----------------------------------------------------------------
    log_level: str = Field(default="INFO")

    @field_validator("alert_sinks", mode="before")
    @classmethod
    def _split_csv(cls, value: object) -> object:
        if isinstance(value, str):
            return tuple(part.strip() for part in value.split(",") if part.strip())
        return value

    @field_validator("alert_sinks")
    @classmethod
    def _known_sinks(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        known = {"file", "webhook", "telegram", "stdout"}
        unknown = sorted(set(value) - known)
        if unknown:
            raise ValueError(f"unknown alert sink(s) {unknown}; known sinks: {sorted(known)}")
        return value

    @field_validator("log_level")
    @classmethod
    def _valid_log_level(cls, value: str) -> str:
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        upper = value.upper()
        if upper not in allowed:
            raise ValueError(f"log_level must be one of {sorted(allowed)}, got {value!r}")
        return upper

    @field_validator("user_agent")
    @classmethod
    def _identifiable_user_agent(cls, value: str) -> str:
        """Refuse an empty or browser-impersonating user agent.

        Pretending to be Chrome is how a monitor becomes indistinguishable from an attack, and it
        removes the site owner's ability to contact whoever is polling them. Being identifiable is
        both the polite and the safe choice.
        """
        stripped = value.strip()
        if len(stripped) < 3:
            raise ValueError("user_agent must identify this tool")
        lowered = stripped.lower()
        if "mozilla/" in lowered or "chrome/" in lowered or "safari/" in lowered:
            raise ValueError(
                "refusing a browser-impersonating user agent: a monitor should be identifiable, "
                "so a site owner can tell it from an attack and can contact you"
            )
        return stripped

    @model_validator(mode="after")
    def _check_sink_requirements(self) -> Settings:
        if "webhook" in self.alert_sinks and not self.webhook_url:
            raise ValueError("the 'webhook' alert sink requires RAQIB_WEBHOOK_URL")
        if "telegram" in self.alert_sinks and not (
            self.telegram_bot_token and self.telegram_chat_id
        ):
            raise ValueError(
                "the 'telegram' alert sink requires RAQIB_TELEGRAM_BOT_TOKEN and "
                "RAQIB_TELEGRAM_CHAT_ID"
            )
        return self


class WatchTarget(BaseModel):
    """One page to watch."""

    model_config = {"extra": "forbid"}

    name: str = Field(min_length=1, max_length=80, description="Unique label for this target.")
    url: str = Field(min_length=1)
    interval_minutes: int = Field(default=60, ge=1, le=60 * 24 * 7)
    enabled: bool = True

    #: How to reduce the page to the text being compared.
    extractor: ExtractorKind = "text"
    #: CSS selector for ``extractor: css``; JSON path (dotted, with [n] indexing) for ``json``.
    selector: str | None = None

    #: Regular expressions whose matches are removed before comparison. This is how a page with a
    #: timestamp, a CSRF token, or a rotating advert is made comparable at all -- without it every
    #: poll of a normal page reports a change and the tool is useless.
    ignore_patterns: tuple[str, ...] = ()

    #: Run the passive TLS / security-header assessment for this target.
    security_check: bool = False
    #: The operator's attestation that they own this target or are authorised to assess it.
    #: Required for ``security_check`` -- see the README's authorisation section.
    authorised: bool = False

    notify: tuple[str, ...] = ()

    @field_validator("name")
    @classmethod
    def _safe_name(cls, value: str) -> str:
        """Names become filenames in the reports directory, so keep them boring."""
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("name must not be empty")
        if any(character in cleaned for character in '/\\:*?"<>|'):
            raise ValueError(f"name {value!r} contains characters that are unsafe in a filename")
        if cleaned in {".", ".."}:
            raise ValueError("name must not be a path component")
        return cleaned

    @field_validator("ignore_patterns")
    @classmethod
    def _compilable_patterns(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        """Reject an invalid regex at load time rather than mid-poll."""
        import re

        for pattern in value:
            try:
                re.compile(pattern)
            except re.error as exc:
                raise ValueError(f"ignore_patterns entry {pattern!r} is not a valid regex: {exc}")
        return value

    @model_validator(mode="after")
    def _check_coherence(self) -> WatchTarget:
        if self.extractor in {"css", "json"} and not self.selector:
            raise ValueError(f"extractor {self.extractor!r} requires a 'selector'")
        if self.extractor == "text" and self.selector:
            raise ValueError("extractor 'text' takes no 'selector'")
        if self.security_check and not self.authorised:
            raise ValueError(
                f"target {self.name!r} requests security_check but has authorised: false. "
                "Set 'authorised: true' only for a site you own or have written permission to "
                "assess. See the README's authorisation section."
            )
        return self

    @property
    def interval_seconds(self) -> int:
        return self.interval_minutes * 60


class TargetFile(BaseModel):
    """The parsed targets file."""

    model_config = {"extra": "forbid"}

    targets: list[WatchTarget] = Field(default_factory=list)

    @model_validator(mode="after")
    def _unique_names(self) -> TargetFile:
        seen: set[str] = set()
        for target in self.targets:
            if target.name in seen:
                raise ValueError(f"duplicate target name {target.name!r}")
            seen.add(target.name)
        return self


def load_targets(path: Path) -> list[WatchTarget]:
    """Read and validate the targets file.

    Raises:
        FileNotFoundError: if the file is missing.
        ValueError: if the YAML is malformed or any target is invalid.
    """
    if not path.is_file():
        raise FileNotFoundError(f"targets file {path} does not exist")
    try:
        # safe_load, never load: full YAML can construct arbitrary Python objects, and this file
        # is exactly the kind of thing that gets copied between machines.
        raw: Any = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ValueError(f"{path} is not valid YAML: {exc}") from exc

    if raw is None:
        return []
    if isinstance(raw, list):
        raw = {"targets": raw}
    if not isinstance(raw, dict):
        raise ValueError(f"{path} must contain a mapping with a 'targets' list")
    return TargetFile.model_validate(raw).targets


def utcnow() -> datetime:
    """Timezone-aware UTC now."""
    return datetime.now(UTC)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide settings, constructed once."""
    return Settings()


def reset_settings_cache() -> None:
    """Drop the cached settings. Used by tests that manipulate the environment."""
    get_settings.cache_clear()
