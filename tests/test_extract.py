"""Tests for extraction and normalisation.

The false-positive tests here matter most: a change detector that fires on every poll of a normal
page is worse than useless, and pages carry clocks, tokens and rotating adverts by default.
"""

from __future__ import annotations

import pytest

from raqib.config import WatchTarget
from raqib.extract import (
    ExtractionError,
    extract,
    extract_json,
    json_path,
    normalise,
    select_text,
    visible_text,
)

from .conftest import SAMPLE_HTML, SAMPLE_JSON

# --------------------------------------------------------------------- visible text


def test_script_style_and_comments_are_stripped() -> None:
    """Inline analytics blobs are the single largest source of spurious diffs."""
    text = visible_text(SAMPLE_HTML)
    assert "must be stripped" not in text
    assert "color:red" not in text
    assert "a comment that must be stripped" not in text
    assert "Catalogue" in text
    assert "89,900 DZD" in text


def test_visible_text_of_an_empty_document_is_empty() -> None:
    assert visible_text("").strip() == ""


def test_malformed_html_does_not_raise() -> None:
    """Real pages are malformed constantly; the parser must cope rather than crash a run."""
    assert "hello" in visible_text("<div><p>hello<span>unclosed")


# --------------------------------------------------------------------- css selector


def test_a_selector_extracts_only_the_matching_node() -> None:
    result = select_text(SAMPLE_HTML, "#catalogue")
    assert "89,900 DZD" in result.text
    assert "Free delivery" not in result.text, "only the selected node should be extracted"
    assert result.matched_nodes == 1


def test_a_selector_matching_several_nodes_concatenates_them() -> None:
    html = "<div><p class='x'>one</p><p class='x'>two</p></div>"
    result = select_text(html, "p.x")
    assert result.matched_nodes == 2
    assert "one" in result.text and "two" in result.text


def test_a_selector_matching_nothing_is_an_error_not_an_empty_result() -> None:
    """Silently comparing empty strings forever looks exactly like "nothing ever changes"."""
    with pytest.raises(ExtractionError, match="matched no elements"):
        select_text(SAMPLE_HTML, "#does-not-exist")


def test_an_invalid_selector_is_reported_clearly() -> None:
    with pytest.raises(ExtractionError, match="not valid"):
        select_text(SAMPLE_HTML, "###")


# --------------------------------------------------------------------- json


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("generated_at", "2026-09-28T01:00:00Z"),
        ("products[0].sku", "AC-12000"),
        ("products[0].price", 89900),
        ("products[0].in_stock", True),
    ],
)
def test_json_path_reads_nested_values(path: str, expected: object) -> None:
    import json

    assert json_path(json.loads(SAMPLE_JSON), path) == expected


def test_json_path_errors_name_what_was_available() -> None:
    import json

    payload = json.loads(SAMPLE_JSON)
    with pytest.raises(ExtractionError, match="available"):
        json_path(payload, "nope")
    with pytest.raises(ExtractionError, match="out of range"):
        json_path(payload, "products[9]")
    with pytest.raises(ExtractionError, match="non-list"):
        json_path(payload, "generated_at[0]")
    with pytest.raises(ExtractionError, match="non-object"):
        json_path(payload, "products[0].price.nested")


def test_extract_json_rejects_non_json() -> None:
    with pytest.raises(ExtractionError, match="not valid JSON"):
        extract_json("<html>not json</html>", "a")


def test_json_object_keys_are_sorted_so_reordering_is_not_a_change() -> None:
    """A server that reorders its JSON keys has not changed anything meaningful."""
    first = extract_json('{"b": 2, "a": 1}', "").text
    second = extract_json('{"a": 1, "b": 2}', "").text
    assert first == second


# --------------------------------------------------------------------- normalisation


def test_whitespace_is_collapsed_and_lines_trimmed() -> None:
    assert normalise("  a   b  \n\n\n\n   c  ") == "a b\n\nc"


def test_carriage_returns_are_normalised() -> None:
    """A server switching line endings must not read as a content change."""
    assert normalise("a\r\nb") == normalise("a\nb")


def test_ignore_patterns_remove_volatile_content() -> None:
    """The mechanism that makes a page with a clock comparable at all."""
    pattern = (r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z",)
    first = normalise("Generated at 2026-09-28T01:00:00Z\nPrice: 100", ignore_patterns=pattern)
    second = normalise("Generated at 2026-09-28T09:47:33Z\nPrice: 100", ignore_patterns=pattern)
    assert first == second


def test_ignore_patterns_do_not_hide_a_real_change() -> None:
    pattern = (r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z",)
    first = normalise("Generated at 2026-09-28T01:00:00Z\nPrice: 100", ignore_patterns=pattern)
    second = normalise("Generated at 2026-09-28T09:47:33Z\nPrice: 200", ignore_patterns=pattern)
    assert first != second


# --------------------------------------------------------------------- end to end


def test_text_extractor_end_to_end() -> None:
    target = WatchTarget(name="t", url="https://example.com/", extractor="text")
    result = extract(target, SAMPLE_HTML)
    assert "Catalogue" in result.text
    assert "must be stripped" not in result.text


def test_a_page_with_only_a_changing_timestamp_produces_a_stable_extraction() -> None:
    """The headline property: this is what stops the tool crying wolf every hour."""
    target = WatchTarget(
        name="t",
        url="https://example.com/",
        extractor="text",
        ignore_patterns=(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z",),
    )
    first = extract(target, SAMPLE_HTML)
    second = extract(target, SAMPLE_HTML.replace("01:00:00", "09:47:33"))
    assert first.text == second.text


def test_without_an_ignore_pattern_the_same_page_looks_changed() -> None:
    """Proves the previous test is actually exercising ignore_patterns."""
    target = WatchTarget(name="t", url="https://example.com/", extractor="text")
    first = extract(target, SAMPLE_HTML)
    second = extract(target, SAMPLE_HTML.replace("01:00:00", "09:47:33"))
    assert first.text != second.text


def test_css_extractor_end_to_end() -> None:
    target = WatchTarget(
        name="t", url="https://example.com/", extractor="css", selector="#catalogue"
    )
    assert "89,900" in extract(target, SAMPLE_HTML).text


def test_json_extractor_end_to_end() -> None:
    target = WatchTarget(
        name="t", url="https://example.com/", extractor="json", selector="products[0]"
    )
    result = extract(target, SAMPLE_JSON, content_type="application/json")
    assert "AC-12000" in result.text


def test_extraction_producing_nothing_is_an_error() -> None:
    target = WatchTarget(
        name="t",
        url="https://example.com/",
        extractor="text",
        ignore_patterns=(r"[\s\S]+",),  # removes everything
    )
    with pytest.raises(ExtractionError, match="no text after normalisation"):
        extract(target, SAMPLE_HTML)
