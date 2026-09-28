"""Tests for the passive security assessment."""

from __future__ import annotations

from raqib.security_scan import (
    CERT_CRITICAL_DAYS,
    assess,
    assess_cookies,
    assess_headers,
    assess_mixed_content,
)

SECURE_HEADERS = {
    "content-security-policy": "default-src 'self'",
    "x-content-type-options": "nosniff",
    "referrer-policy": "strict-origin-when-cross-origin",
    "x-frame-options": "DENY",
    "strict-transport-security": "max-age=31536000; includeSubDomains",
}


def _checks(findings: list) -> set[str]:
    return {finding.check for finding in findings}


# --------------------------------------------------------------------- headers


def test_a_fully_configured_site_produces_no_header_findings() -> None:
    assert assess_headers(SECURE_HEADERS, is_https=True) == []


def test_every_missing_header_is_reported() -> None:
    findings = assess_headers({}, is_https=True)
    assert _checks(findings) >= {
        "header:content-security-policy",
        "header:x-content-type-options",
        "header:referrer-policy",
        "header:x-frame-options",
        "header:strict-transport-security",
    }


def test_hsts_is_only_expected_over_https() -> None:
    """Asking for HSTS on a plain-HTTP response would be noise; the transport finding covers it."""
    assert "header:strict-transport-security" not in _checks(assess_headers({}, is_https=False))
    assert "header:strict-transport-security" in _checks(assess_headers({}, is_https=True))


def test_a_short_hsts_max_age_is_reported() -> None:
    findings = assess_headers(
        {**SECURE_HEADERS, "strict-transport-security": "max-age=3600"}, is_https=True
    )
    assert "header:hsts-max-age" in _checks(findings)


def test_an_unparseable_hsts_max_age_does_not_crash() -> None:
    assess_headers({**SECURE_HEADERS, "strict-transport-security": "max-age=soon"}, is_https=True)


def test_csp_frame_ancestors_satisfies_the_x_frame_options_check() -> None:
    """Reporting both would be a false positive: frame-ancestors does the same job."""
    headers = {
        **SECURE_HEADERS,
        "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
    }
    del headers["x-frame-options"]
    assert "header:x-frame-options" not in _checks(assess_headers(headers, is_https=True))


def test_unsafe_inline_in_a_csp_is_reported() -> None:
    headers = {**SECURE_HEADERS, "content-security-policy": "default-src 'self' 'unsafe-inline'"}
    assert "header:csp-unsafe-inline" in _checks(assess_headers(headers, is_https=True))


def test_a_version_banner_is_reported_but_a_bare_product_name_is_not() -> None:
    """A product name is unremarkable; a version number tells an attacker which exploit to use."""
    with_version = assess_headers({**SECURE_HEADERS, "server": "nginx/1.18.0"}, is_https=True)
    assert "header:server" in _checks(with_version)
    without = assess_headers({**SECURE_HEADERS, "server": "nginx"}, is_https=True)
    assert "header:server" not in _checks(without)


def test_header_matching_is_case_insensitive() -> None:
    upper = {key.upper(): value for key, value in SECURE_HEADERS.items()}
    assert assess_headers(upper, is_https=True) == []


# --------------------------------------------------------------------- cookies


def test_a_fully_flagged_cookie_produces_no_findings() -> None:
    cookie = "session=abc; Path=/; Secure; HttpOnly; SameSite=Lax"
    assert assess_cookies([cookie], is_https=True) == []


def test_missing_cookie_flags_are_each_reported() -> None:
    findings = assess_cookies(["session=abc; Path=/"], is_https=True)
    assert _checks(findings) == {
        "cookie:session:secure",
        "cookie:session:httponly",
        "cookie:session:samesite",
    }


def test_secure_is_not_expected_on_plain_http() -> None:
    findings = assess_cookies(["session=abc"], is_https=False)
    assert "cookie:session:secure" not in _checks(findings)


def test_cookie_flag_matching_is_case_insensitive() -> None:
    cookie = "session=abc; secure; httponly; samesite=strict"
    assert assess_cookies([cookie], is_https=True) == []


def test_several_cookies_are_each_assessed() -> None:
    findings = assess_cookies(["a=1; Secure; HttpOnly; SameSite=Lax", "b=2"], is_https=True)
    assert all(finding.check.startswith("cookie:b:") for finding in findings)


# --------------------------------------------------------------------- mixed content


def test_an_insecure_subresource_on_an_https_page_is_reported() -> None:
    body = '<img src="http://cdn.example/logo.png">'
    assert _checks(assess_mixed_content(body, is_https=True)) == {"mixed-content"}


def test_a_plain_link_in_prose_is_not_mixed_content() -> None:
    """A http:// URL in text is a link, not a loaded subresource. Reporting it would be noise."""
    body = "<p>See http://example.com for details</p>"
    assert assess_mixed_content(body, is_https=True) == []


def test_mixed_content_is_not_checked_on_plain_http() -> None:
    assert assess_mixed_content('<img src="http://x/y.png">', is_https=False) == []


def test_https_subresources_are_fine() -> None:
    assert assess_mixed_content('<img src="https://cdn.example/logo.png">', is_https=True) == []


# --------------------------------------------------------------------- scoring


def test_a_clean_https_site_scores_full_marks() -> None:
    report = assess(
        url="https://example.com/",
        headers=SECURE_HEADERS,
        body="<html></html>",
        host="example.com",
        port=443,
        check_tls=False,
    )
    assert report.findings == []
    assert report.score == 100
    assert report.grade == "A"


def test_plain_http_is_reported_as_high_severity() -> None:
    report = assess(
        url="http://example.com/",
        headers={},
        body="",
        host="example.com",
        port=80,
        check_tls=False,
    )
    assert "transport" in _checks(report.findings)
    assert report.score < 100


def test_a_badly_configured_site_grades_poorly() -> None:
    report = assess(
        url="http://example.com/",
        headers={"set-cookie": "session=abc", "server": "Apache/2.2.0"},
        body='<img src="http://x/y.png">',
        host="example.com",
        port=80,
        check_tls=False,
    )
    assert report.grade in {"D", "E", "F"}
    assert report.score < 70


def test_the_score_never_goes_below_zero() -> None:
    from raqib.security_scan import Finding, SecurityReport

    report = SecurityReport(url="https://example.com/")
    for index in range(50):
        report.add(Finding(check=f"c{index}", severity="high", summary="bad"))
    assert report.score == 0
    assert report.grade == "F"


def test_findings_are_sorted_worst_first() -> None:
    report = assess(
        url="http://example.com/", headers={}, body="", host="example.com", port=80, check_tls=False
    )
    weights = [finding.weight for finding in report.sorted_findings]
    assert weights == sorted(weights, reverse=True)


def test_counts_cover_every_severity_level() -> None:
    report = assess(
        url="http://example.com/", headers={}, body="", host="example.com", port=80, check_tls=False
    )
    counts = report.counts()
    assert set(counts) == {"ok", "info", "low", "medium", "high"}
    assert sum(counts.values()) == len(report.findings)


def test_repeated_set_cookie_headers_are_split() -> None:
    """httpx collapses repeated headers with ", ", which collides with cookie Expires dates."""
    report = assess(
        url="https://example.com/",
        headers={**SECURE_HEADERS, "set-cookie": "a=1; Path=/, b=2; Path=/"},
        body="",
        host="example.com",
        port=443,
        check_tls=False,
    )
    names = {
        finding.check.split(":")[1]
        for finding in report.findings
        if finding.check.startswith("cookie:")
    }
    assert names == {"a", "b"}


def test_certificate_thresholds_are_ordered() -> None:
    assert CERT_CRITICAL_DAYS < 30


def test_tls_inspection_of_an_unreachable_host_is_informational_not_fatal() -> None:
    """A failed handshake must not abort the whole assessment."""
    from raqib.security_scan import inspect_certificate

    expires, version, findings = inspect_certificate(
        "127.0.0.1", 1, timeout=0.5, address="127.0.0.1"
    )
    assert expires is None
    assert version is None
    assert _checks(findings) == {"tls:connection"}
