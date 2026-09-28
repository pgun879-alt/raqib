"""Tests for robots.txt parsing and rule matching."""

from __future__ import annotations

import pytest

from raqib.robots import RobotsRules, _agent_token, robots_url_for

AGENT = "raqib/0.1 (+https://example.com/raqib)"


def _rules(text: str, *, user_agent: str = AGENT) -> RobotsRules:
    return RobotsRules.parse(text, user_agent=user_agent)


# --------------------------------------------------------------------- basics


def test_an_empty_file_allows_everything() -> None:
    rules = _rules("")
    assert rules.can_fetch("https://example.com/anything")
    assert rules.crawl_delay is None


def test_a_missing_file_allows_everything() -> None:
    """HTTP 404 on robots.txt means no restrictions, per the standard."""
    assert RobotsRules.allow_all(user_agent=AGENT).can_fetch("https://example.com/x")


def test_an_unreadable_file_denies_everything() -> None:
    """Fail closed: if robots.txt cannot be read, assume we are not welcome."""
    assert not RobotsRules.deny_all(user_agent=AGENT).can_fetch("https://example.com/x")


def test_a_simple_disallow_is_honoured() -> None:
    rules = _rules("User-agent: *\nDisallow: /private/")
    assert not rules.can_fetch("https://example.com/private/page")
    assert rules.can_fetch("https://example.com/public/page")


def test_disallow_slash_blocks_the_whole_site() -> None:
    rules = _rules("User-agent: *\nDisallow: /")
    assert not rules.can_fetch("https://example.com/")
    assert not rules.can_fetch("https://example.com/anything/at/all")


def test_an_empty_disallow_value_means_allow_everything() -> None:
    """``Disallow:`` with no path is the documented way to say "allow all"."""
    rules = _rules("User-agent: *\nDisallow:")
    assert rules.can_fetch("https://example.com/anything")


# --------------------------------------------------------------------- precedence


def test_the_longest_matching_path_wins() -> None:
    """How a site author writes "all of /private is off limits except /private/status"."""
    rules = _rules("User-agent: *\nDisallow: /private/\nAllow: /private/status")
    assert not rules.can_fetch("https://example.com/private/secret")
    assert rules.can_fetch("https://example.com/private/status")
    assert rules.can_fetch("https://example.com/private/status/detail")


def test_allow_beats_disallow_on_an_equal_length_tie() -> None:
    rules = _rules("User-agent: *\nDisallow: /page\nAllow: /page")
    assert rules.can_fetch("https://example.com/page")


def test_a_group_naming_us_overrides_the_wildcard_group() -> None:
    rules = _rules("User-agent: *\nDisallow: /\n\nUser-agent: raqib\nDisallow: /admin/\n")
    assert rules.matched_specific_group
    assert rules.can_fetch("https://example.com/public")  # the wildcard deny does not apply
    assert not rules.can_fetch("https://example.com/admin/panel")


def test_a_group_for_another_agent_is_ignored() -> None:
    rules = _rules("User-agent: googlebot\nDisallow: /\n\nUser-agent: *\nDisallow: /nope/")
    assert not rules.matched_specific_group
    assert rules.can_fetch("https://example.com/anything")
    assert not rules.can_fetch("https://example.com/nope/x")


def test_multiple_agents_can_share_one_group() -> None:
    rules = _rules("User-agent: bingbot\nUser-agent: raqib\nDisallow: /shared/")
    assert rules.matched_specific_group
    assert not rules.can_fetch("https://example.com/shared/x")


# --------------------------------------------------------------------- wildcards


def test_a_star_wildcard_in_a_path_is_honoured() -> None:
    """Not in the original standard, but every major crawler supports it, so a site author
    writing it expects it to work."""
    rules = _rules("User-agent: *\nDisallow: /*/private")
    assert not rules.can_fetch("https://example.com/a/private")
    assert not rules.can_fetch("https://example.com/b/private/deep")
    assert rules.can_fetch("https://example.com/public")


def test_a_dollar_end_anchor_is_honoured() -> None:
    rules = _rules("User-agent: *\nDisallow: /*.pdf$")
    assert not rules.can_fetch("https://example.com/report.pdf")
    assert rules.can_fetch("https://example.com/report.pdf.html")


def test_a_query_string_participates_in_matching() -> None:
    rules = _rules("User-agent: *\nDisallow: /search?q=")
    assert not rules.can_fetch("https://example.com/search?q=term")
    assert rules.can_fetch("https://example.com/search")


def test_percent_encoded_paths_are_compared_decoded() -> None:
    rules = _rules("User-agent: *\nDisallow: /private area/")
    assert not rules.can_fetch("https://example.com/private%20area/page")


# --------------------------------------------------------------------- crawl-delay


def test_crawl_delay_is_read() -> None:
    """urllib.robotparser ignores this directive, which is exactly the one a polite monitor
    should obey. That is a large part of why this parser exists."""
    assert _rules("User-agent: *\nCrawl-delay: 10").crawl_delay == 10.0


def test_a_fractional_crawl_delay_is_read() -> None:
    assert _rules("User-agent: *\nCrawl-delay: 2.5").crawl_delay == 2.5


def test_an_unparseable_crawl_delay_is_ignored() -> None:
    assert _rules("User-agent: *\nCrawl-delay: soon").crawl_delay is None


def test_a_negative_crawl_delay_is_ignored() -> None:
    assert _rules("User-agent: *\nCrawl-delay: -5").crawl_delay is None


def test_our_own_groups_crawl_delay_is_preferred() -> None:
    rules = _rules(
        "User-agent: *\nCrawl-delay: 60\n\nUser-agent: raqib\nCrawl-delay: 5\nDisallow:\n"
    )
    assert rules.crawl_delay == 5.0


# --------------------------------------------------------------------- robustness


def test_comments_and_blank_lines_are_ignored() -> None:
    rules = _rules(
        """
        # This is our robots file
        User-agent: *      # everyone

        Disallow: /private/   # keep out

        """
    )
    assert not rules.can_fetch("https://example.com/private/x")
    assert rules.can_fetch("https://example.com/open")


def test_directive_names_are_case_insensitive() -> None:
    rules = _rules("USER-AGENT: *\nDISALLOW: /private/")
    assert not rules.can_fetch("https://example.com/private/x")


def test_a_malformed_file_does_not_become_a_blanket_allow_or_deny() -> None:
    """A typo in robots.txt must not silently change the answer for the whole site."""
    rules = _rules("this is not a robots file at all\n{}\n<<<>>>\n")
    assert rules.can_fetch("https://example.com/x")


def test_rules_before_any_user_agent_line_are_ignored() -> None:
    rules = _rules("Disallow: /orphaned/\n\nUser-agent: *\nDisallow: /real/")
    assert rules.can_fetch("https://example.com/orphaned/x")
    assert not rules.can_fetch("https://example.com/real/x")


def test_unknown_directives_are_ignored() -> None:
    rules = _rules("User-agent: *\nSitemap: https://example.com/sitemap.xml\nDisallow: /x/")
    assert not rules.can_fetch("https://example.com/x/y")
    assert rules.can_fetch("https://example.com/y")


# --------------------------------------------------------------------- helpers


def test_the_agent_token_is_extracted_from_a_full_user_agent_string() -> None:
    assert _agent_token("raqib/0.1 (+https://example.com)") == "raqib"
    assert _agent_token("SomeBot") == "somebot"
    assert _agent_token("") == ""


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://example.com/page", "https://example.com/robots.txt"),
        ("https://example.com/deep/path?q=1", "https://example.com/robots.txt"),
        ("http://example.com/", "http://example.com/robots.txt"),
        # robots.txt is per-origin, so a port makes it a different file.
        ("https://example.com:8443/x", "https://example.com:8443/robots.txt"),
    ],
)
def test_the_robots_url_is_derived_per_origin(url: str, expected: str) -> None:
    assert robots_url_for(url) == expected
