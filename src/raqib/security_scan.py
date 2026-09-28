"""Passive security-posture assessment: TLS expiry, security headers, cookie flags.

Scope and authorisation -- read this before extending it
-------------------------------------------------------
Everything here is **passive**. The only network traffic is:

* one ordinary ``GET`` that a browser would make anyway, whose response headers are then read; and
* one TLS handshake to read the certificate, which is what any client does before any request.

There is **no** vulnerability probing, no payload injection, no path or parameter guessing, no
fuzzing, no brute force, and no authentication bypass. Nothing in this module sends a request a
normal visitor would not send.

That restriction is deliberate and permanent. Active scanning of a system you do not own is
unlawful in many jurisdictions regardless of intent, and a portfolio piece should not advertise
the capability. On top of that, ``security_check`` requires ``authorised: true`` on the target,
which is the operator's explicit attestation that the site is theirs or that they have written
permission. See the README's authorisation section.

The value of this, honestly stated: it catches **regressions**. A
``Content-Security-Policy`` that disappeared in a deploy, a cookie that lost ``Secure``, a
certificate expiring in nine days. Those cause real outages and real incidents, and nobody notices
them by looking.
"""

from __future__ import annotations

import logging
import socket
import ssl
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Final, Literal

logger = logging.getLogger(__name__)

Severity = Literal["ok", "info", "low", "medium", "high"]

#: Severity ranking, for sorting findings and computing a grade.
_SEVERITY_WEIGHT: Final[dict[Severity, int]] = {
    "ok": 0,
    "info": 1,
    "low": 4,
    "medium": 10,
    "high": 20,
}

#: Days of certificate life below which expiry is reported, and at what severity.
CERT_WARNING_DAYS: Final = 30
CERT_CRITICAL_DAYS: Final = 7


@dataclass(frozen=True, slots=True)
class Finding:
    """One observation about a target's security posture."""

    check: str
    severity: Severity
    summary: str
    detail: str = ""
    recommendation: str = ""

    @property
    def weight(self) -> int:
        return _SEVERITY_WEIGHT[self.severity]


@dataclass(slots=True)
class SecurityReport:
    """The findings for one target."""

    url: str
    findings: list[Finding] = field(default_factory=list)
    certificate_expires_at: datetime | None = None
    certificate_days_left: int | None = None
    tls_version: str | None = None

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    @property
    def score(self) -> int:
        """0-100, starting at 100 and deducting each finding's weight. A blunt instrument, but a
        comparable one -- its only real job is to show movement between two runs."""
        return max(0, 100 - sum(finding.weight for finding in self.findings))

    @property
    def grade(self) -> str:
        score = self.score
        for threshold, letter in ((90, "A"), (80, "B"), (70, "C"), (60, "D"), (40, "E")):
            if score >= threshold:
                return letter
        return "F"

    @property
    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda item: (-item.weight, item.check))

    def counts(self) -> dict[str, int]:
        counts: dict[str, int] = dict.fromkeys(_SEVERITY_WEIGHT, 0)
        for finding in self.findings:
            counts[finding.severity] += 1
        return counts


# --------------------------------------------------------------------------- headers

#: ``(header, severity, why it matters, what to set)``.
_REQUIRED_HEADERS: Final[tuple[tuple[str, Severity, str, str], ...]] = (
    (
        "content-security-policy",
        "medium",
        "Without a CSP, any injected script executes with full page privileges.",
        "Content-Security-Policy: default-src 'self'",
    ),
    (
        "x-content-type-options",
        "low",
        "Browsers may MIME-sniff a response and execute a file the server sent as text.",
        "X-Content-Type-Options: nosniff",
    ),
    (
        "referrer-policy",
        "low",
        "Full URLs, including any tokens in them, leak to third-party sites in the Referer header.",
        "Referrer-Policy: strict-origin-when-cross-origin",
    ),
    (
        "x-frame-options",
        "low",
        "The page can be framed by another site, enabling clickjacking. (A CSP "
        "'frame-ancestors' directive also covers this.)",
        "X-Frame-Options: DENY",
    ),
)


def assess_headers(headers: dict[str, str], *, is_https: bool) -> list[Finding]:
    """Check response headers for missing or weak security directives."""
    findings: list[Finding] = []
    lowered = {key.lower(): value for key, value in headers.items()}

    for name, severity, why, recommendation in _REQUIRED_HEADERS:
        if name in lowered:
            continue
        # frame-ancestors in a CSP does the same job as X-Frame-Options, so do not report both.
        if name == "x-frame-options" and "frame-ancestors" in lowered.get(
            "content-security-policy", ""
        ):
            continue
        findings.append(
            Finding(
                check=f"header:{name}",
                severity=severity,
                summary=f"{name} is not set",
                detail=why,
                recommendation=recommendation,
            )
        )

    if is_https:
        hsts = lowered.get("strict-transport-security")
        if not hsts:
            findings.append(
                Finding(
                    check="header:strict-transport-security",
                    severity="medium",
                    summary="Strict-Transport-Security is not set",
                    detail="A visitor's first request can be downgraded to HTTP and intercepted.",
                    recommendation="Strict-Transport-Security: max-age=31536000; includeSubDomains",
                )
            )
        else:
            max_age = _parse_max_age(hsts)
            if max_age is not None and max_age < 15552000:  # 180 days, the widely-cited floor
                findings.append(
                    Finding(
                        check="header:hsts-max-age",
                        severity="low",
                        summary=f"Strict-Transport-Security max-age is only {max_age}s",
                        detail="A short max-age leaves a long window in which a downgrade works.",
                        recommendation="Use max-age=31536000 (one year).",
                    )
                )

    csp = lowered.get("content-security-policy", "")
    if csp and "unsafe-inline" in csp:
        findings.append(
            Finding(
                check="header:csp-unsafe-inline",
                severity="low",
                summary="Content-Security-Policy allows 'unsafe-inline'",
                detail="Inline scripts are permitted, which removes most of the CSP's XSS value.",
                recommendation="Replace 'unsafe-inline' with nonces or hashes.",
            )
        )

    for leaky in ("server", "x-powered-by", "x-aspnet-version"):
        value = lowered.get(leaky)
        # A bare product name is unremarkable; a version number tells an attacker which exploit
        # to reach for.
        if value and any(character.isdigit() for character in value):
            findings.append(
                Finding(
                    check=f"header:{leaky}",
                    severity="info",
                    summary=f"{leaky} exposes a version: {value!r}",
                    detail="Version banners let an attacker match the target to known exploits.",
                    recommendation=f"Remove or generalise the {leaky} header.",
                )
            )

    return findings


def _parse_max_age(hsts: str) -> int | None:
    for part in hsts.split(";"):
        key, _, value = part.strip().partition("=")
        if key.strip().lower() == "max-age":
            try:
                return int(value.strip())
            except ValueError:
                return None
    return None


# --------------------------------------------------------------------------- cookies


def assess_cookies(set_cookie_headers: list[str], *, is_https: bool) -> list[Finding]:
    """Check ``Set-Cookie`` flags.

    ``Secure`` and ``HttpOnly`` on a session cookie are the difference between an XSS bug that
    defaces a page and one that takes over accounts.
    """
    findings: list[Finding] = []
    for header in set_cookie_headers:
        name = header.split("=", 1)[0].strip()
        attributes = {part.strip().lower() for part in header.split(";")[1:]}
        flags = {attribute.split("=")[0] for attribute in attributes}

        if is_https and "secure" not in flags:
            findings.append(
                Finding(
                    check=f"cookie:{name}:secure",
                    severity="medium",
                    summary=f"cookie {name!r} is missing the Secure flag",
                    detail="The cookie will be sent over plain HTTP and can be intercepted.",
                    recommendation=f"Add 'Secure' to the Set-Cookie for {name}.",
                )
            )
        if "httponly" not in flags:
            findings.append(
                Finding(
                    check=f"cookie:{name}:httponly",
                    severity="low",
                    summary=f"cookie {name!r} is missing the HttpOnly flag",
                    detail="JavaScript can read the cookie, so an XSS bug can steal the session.",
                    recommendation=f"Add 'HttpOnly' to the Set-Cookie for {name}.",
                )
            )
        if not any(attribute.startswith("samesite") for attribute in attributes):
            findings.append(
                Finding(
                    check=f"cookie:{name}:samesite",
                    severity="low",
                    summary=f"cookie {name!r} has no SameSite attribute",
                    detail="Browser defaults vary, leaving cross-site request forgery exposure.",
                    recommendation=f"Add 'SameSite=Lax' (or 'Strict') to {name}.",
                )
            )
    return findings


# --------------------------------------------------------------------------- mixed content


def assess_mixed_content(body: str, *, is_https: bool) -> list[Finding]:
    """Detect ``http://`` subresources on an HTTPS page.

    Only ``src``/``href`` attributes are considered -- a plain ``http://`` URL in prose is a link,
    not a loaded subresource, and reporting it would be noise.
    """
    if not is_https:
        return []
    import re

    pattern = re.compile(r"""(?:src|href)\s*=\s*["']http://[^"']+["']""", re.IGNORECASE)
    matches = pattern.findall(body)
    if not matches:
        return []
    return [
        Finding(
            check="mixed-content",
            severity="medium",
            summary=f"{len(matches)} insecure http:// subresource(s) on an HTTPS page",
            detail="Browsers block or downgrade these, and they can be modified in transit. "
            f"First occurrence: {matches[0][:120]}",
            recommendation="Serve every subresource over HTTPS.",
        )
    ]


# --------------------------------------------------------------------------- TLS


def inspect_certificate(
    host: str, port: int = 443, *, timeout: float = 10.0, address: str | None = None
) -> tuple[datetime | None, str | None, list[Finding]]:
    """Read the TLS certificate's expiry and the negotiated protocol version.

    A plain handshake -- exactly what any client does before sending a request. Connects to
    ``address`` when supplied (the address the SSRF guard approved) while verifying against
    ``host``, so the DNS pinning holds here too.

    Returns:
        ``(expires_at, tls_version, findings)``. On failure the first two are ``None`` and a
        finding explains why.
    """
    findings: list[Finding] = []
    context = ssl.create_default_context()
    connect_to = address or host
    try:
        with (
            socket.create_connection((connect_to, port), timeout=timeout) as raw,
            context.wrap_socket(raw, server_hostname=host) as tls,
        ):
            certificate = tls.getpeercert()
            version = tls.version()
    except ssl.SSLCertVerificationError as exc:
        findings.append(
            Finding(
                check="tls:verification",
                severity="high",
                summary="the TLS certificate failed verification",
                detail=str(exc)[:300],
                recommendation="Install a certificate valid for this hostname from a trusted CA.",
            )
        )
        return None, None, findings
    except (OSError, ssl.SSLError) as exc:
        findings.append(
            Finding(
                check="tls:connection",
                severity="info",
                summary="could not complete a TLS handshake",
                detail=str(exc)[:300],
                recommendation="",
            )
        )
        return None, None, findings

    if version in {"TLSv1", "TLSv1.1"}:
        findings.append(
            Finding(
                check="tls:version",
                severity="medium",
                summary=f"the connection negotiated {version}",
                detail="TLS 1.0 and 1.1 are deprecated and are being removed from browsers.",
                recommendation="Require TLS 1.2 or newer.",
            )
        )

    expires_at: datetime | None = None
    if certificate and certificate.get("notAfter"):
        try:
            expires_at = datetime.strptime(
                str(certificate["notAfter"]), "%b %d %H:%M:%S %Y %Z"
            ).replace(tzinfo=UTC)
        except ValueError as exc:  # pragma: no cover - defensive
            logger.warning("could not parse the certificate expiry: %s", exc)

    if expires_at is not None:
        days_left = (expires_at - datetime.now(UTC)).days
        if days_left < 0:
            findings.append(
                Finding(
                    check="tls:expired",
                    severity="high",
                    summary=f"the certificate expired {abs(days_left)} day(s) ago",
                    detail=f"Not valid after {expires_at.isoformat()}.",
                    recommendation="Renew the certificate immediately.",
                )
            )
        elif days_left <= CERT_CRITICAL_DAYS:
            findings.append(
                Finding(
                    check="tls:expiring",
                    severity="high",
                    summary=f"the certificate expires in {days_left} day(s)",
                    detail=f"Not valid after {expires_at.isoformat()}.",
                    recommendation="Renew now; automate renewal so this cannot recur.",
                )
            )
        elif days_left <= CERT_WARNING_DAYS:
            findings.append(
                Finding(
                    check="tls:expiring",
                    severity="medium",
                    summary=f"the certificate expires in {days_left} day(s)",
                    detail=f"Not valid after {expires_at.isoformat()}.",
                    recommendation="Schedule renewal, or enable automatic renewal.",
                )
            )

    return expires_at, version, findings


# --------------------------------------------------------------------------- top level


def assess(
    *,
    url: str,
    headers: dict[str, str],
    body: str,
    host: str,
    port: int,
    check_tls: bool = True,
    address: str | None = None,
    timeout: float = 10.0,
) -> SecurityReport:
    """Run every passive check and return a report.

    ``headers`` and ``body`` come from a fetch that already happened, so this adds at most one
    TLS handshake to the network traffic.
    """
    is_https = url.lower().startswith("https://")
    report = SecurityReport(url=url)

    if not is_https:
        report.add(
            Finding(
                check="transport",
                severity="high",
                summary="the page is served over plain HTTP",
                detail="All traffic, including any credentials or cookies, is readable in transit.",
                recommendation="Serve over HTTPS and redirect HTTP to it.",
            )
        )

    for finding in assess_headers(headers, is_https=is_https):
        report.add(finding)

    raw_cookie = headers.get("set-cookie", "")
    if raw_cookie:
        # httpx collapses repeated headers with ", ", which is ambiguous against cookie Expires
        # dates ("Mon, 01 Jan"). Splitting on ", " before a token followed by "=" is the
        # pragmatic separation; getting it wrong only affects how findings are grouped.
        import re

        cookies = [part for part in re.split(r",\s*(?=[^=;,\s]+=)", raw_cookie) if part.strip()]
        for finding in assess_cookies(cookies, is_https=is_https):
            report.add(finding)

    for finding in assess_mixed_content(body, is_https=is_https):
        report.add(finding)

    if is_https and check_tls:
        expires_at, version, tls_findings = inspect_certificate(
            host, port, timeout=timeout, address=address
        )
        report.certificate_expires_at = expires_at
        report.tls_version = version
        if expires_at is not None:
            report.certificate_days_left = (expires_at - datetime.now(UTC)).days
        for finding in tls_findings:
            report.add(finding)

    return report
