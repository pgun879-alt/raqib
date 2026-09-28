"""Reducing a fetched page to the text being compared.

Change detection lives or dies on this step. A raw HTML diff reports a change on **every** poll of
a normal page, because real pages carry a clock, a CSRF token, a rotating advert, a "3 minutes ago"
label, or a build hash. A monitor that cries wolf every hour is worse than no monitor.

So there are three extractors and a normalisation pass:

``text``
    Whole-page visible text. Script, style, and comment nodes are removed first -- inline
    analytics blobs are the single largest source of spurious diffs.
``css``
    Text under a CSS selector. The precise tool: point it at the price, the stock label, the
    tender table.
``json``
    A value from a JSON response, by dotted path with ``[n]`` indexing.

HTML is parsed, never regex-matched, and never executed.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from typing import Any, Final

from bs4 import BeautifulSoup, Comment

from .config import WatchTarget

logger = logging.getLogger(__name__)

#: Nodes whose text is never page content.
_STRIPPED_TAGS: Final[tuple[str, ...]] = ("script", "style", "noscript", "template", "svg")

_WHITESPACE: Final = re.compile(r"[ \t ]+")
_BLANK_LINES: Final = re.compile(r"\n{3,}")


class ExtractionError(ValueError):
    """The configured extractor could not be applied to this response."""


@dataclass(frozen=True, slots=True)
class Extraction:
    """The comparable text pulled out of a response."""

    text: str
    matched_nodes: int = 1

    @property
    def is_empty(self) -> bool:
        return not self.text.strip()


def _parser_for(content_type: str) -> str:
    """Pick a parser. ``lxml`` is fast; ``lxml-xml`` keeps XML well-formedness rules."""
    if "xml" in content_type and "html" not in content_type:
        return "lxml-xml"
    return "lxml"


def visible_text(html: str, *, content_type: str = "text/html") -> str:
    """Return the visible text of ``html``, with scripts, styles and comments removed."""
    soup = BeautifulSoup(html, _parser_for(content_type))
    for tag in soup(list(_STRIPPED_TAGS)):
        tag.decompose()
    for comment in soup.find_all(string=lambda item: isinstance(item, Comment)):
        comment.extract()
    return soup.get_text(separator="\n")


def select_text(html: str, selector: str, *, content_type: str = "text/html") -> Extraction:
    """Return the concatenated text of every node matching ``selector``.

    Raises:
        ExtractionError: if the selector is invalid or matches nothing. "Matches nothing" is an
            error rather than an empty result, because silently comparing empty strings forever
            would look exactly like "nothing ever changes".
    """
    soup = BeautifulSoup(html, _parser_for(content_type))
    for tag in soup(list(_STRIPPED_TAGS)):
        tag.decompose()
    try:
        nodes = soup.select(selector)
    except Exception as exc:
        raise ExtractionError(f"selector {selector!r} is not valid: {exc}") from exc
    if not nodes:
        raise ExtractionError(
            f"selector {selector!r} matched no elements; the page structure may have changed"
        )
    return Extraction(
        text="\n".join(node.get_text(separator="\n") for node in nodes),
        matched_nodes=len(nodes),
    )


_JSON_STEP: Final = re.compile(r"([^.\[\]]+)|\[(\d+)\]")


def json_path(payload: Any, path: str) -> Any:
    """Read a value out of parsed JSON by dotted path with ``[n]`` indexing.

    ``data.items[0].price`` walks a mapping, then a list, then a mapping. Deliberately tiny: a
    full JSONPath implementation would be another dependency for a feature this narrow.

    Raises:
        ExtractionError: if the path does not exist.
    """
    current = payload
    for match in _JSON_STEP.finditer(path):
        key, index = match.group(1), match.group(2)
        if index is not None:
            position = int(index)
            if not isinstance(current, list):
                raise ExtractionError(f"path {path!r}: [{position}] applied to a non-list")
            if position >= len(current):
                raise ExtractionError(
                    f"path {path!r}: index {position} is out of range (length {len(current)})"
                )
            current = current[position]
        else:
            if not isinstance(current, dict):
                raise ExtractionError(f"path {path!r}: key {key!r} applied to a non-object")
            if key not in current:
                available = ", ".join(sorted(current)[:8]) or "(none)"
                raise ExtractionError(f"path {path!r}: key {key!r} not found; available: {available}")
            current = current[key]
    return current


def extract_json(body: str, selector: str) -> Extraction:
    """Parse ``body`` as JSON and return the value at ``selector`` as stable text."""
    try:
        payload = json.loads(body)
    except json.JSONDecodeError as exc:
        raise ExtractionError(f"the response is not valid JSON: {exc}") from exc
    value = json_path(payload, selector)
    if isinstance(value, str):
        return Extraction(text=value)
    # sort_keys so a server reordering its object keys is not reported as a change.
    return Extraction(text=json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True))


def normalise(text: str, *, ignore_patterns: tuple[str, ...] = ()) -> str:
    """Make ``text`` comparable across polls.

    Collapses runs of spaces and tabs, trims each line, drops blank lines to at most two in a row,
    and removes anything matching ``ignore_patterns``. This is what turns "the page contains a
    clock" from a permanent false positive into a non-event.
    """
    cleaned = text.replace("\r\n", "\n").replace("\r", "\n")
    for pattern in ignore_patterns:
        try:
            cleaned = re.sub(pattern, "", cleaned)
        except re.error as exc:  # pragma: no cover - patterns are validated at load time
            logger.warning("skipping invalid ignore pattern %r: %s", pattern, exc)
    cleaned = _WHITESPACE.sub(" ", cleaned)
    cleaned = "\n".join(line.strip() for line in cleaned.split("\n"))
    cleaned = _BLANK_LINES.sub("\n\n", cleaned)
    return cleaned.strip()


def extract(target: WatchTarget, body: str, *, content_type: str = "text/html") -> Extraction:
    """Apply ``target``'s extractor to ``body`` and normalise the result."""
    if target.extractor == "text":
        raw = Extraction(text=visible_text(body, content_type=content_type))
    elif target.extractor == "css":
        raw = select_text(body, str(target.selector), content_type=content_type)
    elif target.extractor == "json":
        raw = extract_json(body, str(target.selector))
    else:  # pragma: no cover - the type is constrained by WatchTarget
        raise ExtractionError(f"unknown extractor {target.extractor!r}")

    normalised = normalise(raw.text, ignore_patterns=target.ignore_patterns)
    if not normalised.strip():
        raise ExtractionError(
            "extraction produced no text after normalisation; check the selector and "
            "ignore_patterns for this target"
        )
    return Extraction(text=normalised, matched_nodes=raw.matched_nodes)
