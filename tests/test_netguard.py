"""Tests for the SSRF guard.

This is the highest-stakes module in the project: a gap here turns a monitoring tool into a
network-probing proxy. The tests below therefore work through each bypass class deliberately
rather than spot-checking.
"""

from __future__ import annotations

import pytest

from raqib.netguard import (
    BLOCKED_PORTS,
    METADATA_ADDRESSES,
    UnsafeTargetError,
    is_public_address,
    normalise_url,
    validate_target,
)

# --------------------------------------------------------------------- classification


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",  # loopback
        "127.1.2.3",  # the whole 127/8 block is loopback
        "::1",
        "10.0.0.5",  # RFC 1918
        "172.16.31.9",
        "192.168.1.1",
        "169.254.169.254",  # cloud metadata
        "169.254.1.1",  # link-local
        "100.100.100.200",  # Alibaba metadata
        "0.0.0.0",  # unspecified  # noqa: S104 - test data, not a bind address
        "224.0.0.1",  # multicast
        "240.0.0.1",  # reserved
        "fc00::1",  # IPv6 unique-local
        "fe80::1",  # IPv6 link-local
        "::ffff:127.0.0.1",  # IPv4-mapped loopback
        "::ffff:10.0.0.1",  # IPv4-mapped private
    ],
)
def test_non_public_addresses_are_rejected(address: str) -> None:
    assert not is_public_address(address)


@pytest.mark.parametrize(
    "address",
    ["8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"],
)
def test_public_addresses_are_accepted(address: str) -> None:
    assert is_public_address(address)


def test_ipv4_mapped_ipv6_cannot_smuggle_a_loopback_address() -> None:
    """``::ffff:127.0.0.1`` is a valid IPv6 address that is not loopback by IPv6 rules, so
    without the explicit ipv4_mapped check it would pass every other test."""
    assert not is_public_address("::ffff:127.0.0.1")
    assert not is_public_address("::ffff:169.254.169.254")


def test_six_to_four_addresses_cannot_smuggle_a_private_address() -> None:
    assert not is_public_address("2002:a00:1::")  # 6to4 wrapping 10.0.0.1


def test_garbage_is_not_a_public_address() -> None:
    for value in ["", "not-an-ip", "999.999.999.999", "1.2.3"]:
        assert not is_public_address(value)


def test_every_named_metadata_address_is_refused() -> None:
    for address in METADATA_ADDRESSES:
        assert not is_public_address(address), address


# --------------------------------------------------------------------- normalisation


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("https://Example.COM/Path", "https://example.com/Path"),
        ("example.com", "https://example.com/"),  # scheme defaulted
        ("  https://example.com  ", "https://example.com/"),
        ("https://example.com", "https://example.com/"),  # empty path becomes /
        ("https://example.com/a?b=1#frag", "https://example.com/a?b=1"),  # fragment dropped
        ("HTTP://example.com/", "http://example.com/"),
        ("https://example.com:8443/x", "https://example.com:8443/x"),
    ],
)
def test_normalise_url(raw: str, expected: str) -> None:
    assert normalise_url(raw) == expected


def test_the_path_case_is_preserved() -> None:
    """Hostnames are case-insensitive; paths are not. Lower-casing a path breaks the target."""
    assert normalise_url("https://example.com/CaseSensitive") == "https://example.com/CaseSensitive"


def test_an_empty_or_over_long_url_is_refused() -> None:
    with pytest.raises(UnsafeTargetError, match="empty"):
        normalise_url("   ")
    with pytest.raises(UnsafeTargetError, match="exceeds"):
        normalise_url("https://example.com/" + "a" * 3000)


def test_a_url_with_no_hostname_is_refused() -> None:
    with pytest.raises(UnsafeTargetError, match="no hostname"):
        normalise_url("https:///just-a-path")


# --------------------------------------------------------------------- schemes


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "gopher://example.com/",
        "ftp://example.com/",
        "ldap://example.com/",
        "dict://example.com:11211/",
    ],
)
def test_non_http_schemes_are_refused(url: str) -> None:
    with pytest.raises(UnsafeTargetError, match="scheme"):
        validate_target(url)


def test_credentials_in_a_url_are_refused() -> None:
    """They would end up in the stored target list and in log lines."""
    with pytest.raises(UnsafeTargetError, match="credentials"):
        validate_target("https://user:secret@example.com/")


# --------------------------------------------------------------------- ports


@pytest.mark.parametrize("port", sorted(BLOCKED_PORTS))
def test_non_web_ports_are_refused(port: int) -> None:
    """A page monitor has no business connecting to SSH, Redis, or a database."""
    with pytest.raises(UnsafeTargetError, match="not a web port"):
        validate_target(f"http://example.com:{port}/")


def test_an_invalid_port_is_refused() -> None:
    with pytest.raises(UnsafeTargetError, match=r"[Ii]nvalid port|out of range"):
        validate_target("http://example.com:99999/")


# --------------------------------------------------------------------- resolution


def test_a_hostname_resolving_to_loopback_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    """The bypass a hostname allow-list misses.

    An attacker registers a domain whose A record points at 127.0.0.1 (this is what
    ``localtest.me`` does openly). Checking the *name* proves nothing; only the resolved address
    does.
    """
    monkeypatch.setattr("raqib.netguard.resolve_addresses", lambda host, port: ["127.0.0.1"])
    with pytest.raises(UnsafeTargetError, match="loopback"):
        validate_target("https://totally-normal-domain.example/")


def test_a_hostname_resolving_to_cloud_metadata_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The highest-value SSRF target: on several providers this endpoint hands out credentials."""
    monkeypatch.setattr("raqib.netguard.resolve_addresses", lambda host, port: ["169.254.169.254"])
    with pytest.raises(UnsafeTargetError, match=r"metadata|link-local"):
        validate_target("https://metadata.example/")


def test_every_resolved_address_is_checked_not_only_the_first(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A name with one public and one private address must be refused.

    Taking only the first answer would let DNS ordering decide whether the guard applies.
    """
    monkeypatch.setattr(
        "raqib.netguard.resolve_addresses", lambda host, port: ["93.184.216.34", "10.0.0.5"]
    )
    with pytest.raises(UnsafeTargetError, match="private"):
        validate_target("https://mixed.example/")


def test_a_public_target_is_accepted(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("raqib.netguard.resolve_addresses", lambda host, port: ["93.184.216.34"])
    target = validate_target("https://example.com/page")
    assert target.url == "https://example.com/page"
    assert target.host == "example.com"
    assert target.port == 443
    assert target.scheme == "https"
    assert target.addresses == ("93.184.216.34",)
    assert target.primary_address == "93.184.216.34"


def test_the_default_port_follows_the_scheme(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("raqib.netguard.resolve_addresses", lambda host, port: ["93.184.216.34"])
    assert validate_target("https://example.com/").port == 443
    assert validate_target("http://example.com/").port == 80
    assert validate_target("https://example.com:8443/").port == 8443


def test_an_unresolvable_host_is_refused() -> None:
    with pytest.raises(UnsafeTargetError, match="could not resolve"):
        validate_target("https://this-host-does-not-exist.invalid/")


# --------------------------------------------------------------------- escape hatch


def test_allow_private_permits_a_local_target(monkeypatch: pytest.MonkeyPatch) -> None:
    """The bundled demo watches a local test server. The flag is off by default and must be set
    explicitly."""
    monkeypatch.setattr("raqib.netguard.resolve_addresses", lambda host, port: ["127.0.0.1"])
    target = validate_target("http://127.0.0.1:8999/page.html", allow_private=True)
    assert target.host == "127.0.0.1"
    assert target.port == 8999


def test_allow_private_still_refuses_a_bad_scheme_and_port(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The escape hatch relaxes *address* classification only. Everything else still applies."""
    monkeypatch.setattr("raqib.netguard.resolve_addresses", lambda host, port: ["127.0.0.1"])
    with pytest.raises(UnsafeTargetError, match="scheme"):
        validate_target("file:///etc/passwd", allow_private=True)
    with pytest.raises(UnsafeTargetError, match="not a web port"):
        validate_target("http://127.0.0.1:6379/", allow_private=True)
    with pytest.raises(UnsafeTargetError, match="credentials"):
        validate_target("http://user:pw@127.0.0.1:8999/", allow_private=True)
