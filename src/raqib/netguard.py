"""SSRF protection: refuse URLs that point anywhere but the public internet.

Why this module exists, and why it is the first thing in the package
--------------------------------------------------------------------
``raqib`` fetches URLs that come from a configuration file. The moment a tool does that, it
becomes a potential **Server-Side Request Forgery** proxy: whoever can influence a target list
can make the machine running ``raqib`` issue requests from *inside* its own network. The classic
consequences are reading a cloud metadata endpoint (``169.254.169.254``, which on several
providers hands out credentials), probing services bound to loopback that are firewalled from
outside, and mapping an internal network by observing which hosts respond.

The defence has three parts, and all three are necessary:

1. **Scheme and shape validation.** Only ``http`` and ``https``. No ``file://``,
   ``gopher://``, ``ftp://`` or ``data:``.
2. **DNS resolution before the request.** A hostname check alone is defeated by
   ``localtest.me``-style names that resolve to ``127.0.0.1``, and by an attacker's own domain
   with an ``A`` record pointing at ``10.0.0.5``. Every resolved address is inspected.
3. **Pinning the resolved address into the connection** (see :mod:`raqib.fetcher`). Checking DNS
   and then letting the HTTP client resolve again independently leaves a **DNS-rebinding**
   window: the name resolves to a public address for the check and a private one microseconds
   later for the request.

Redirects are re-validated for the same reason -- a public URL may redirect to
``http://127.0.0.1:8080/``.

``allow_private_targets`` exists only so the bundled demo can watch a local test server. It is
off by default, must be turned on explicitly, and the CLI warns when it is on.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
from dataclasses import dataclass
from typing import Final
from urllib.parse import urlparse, urlunparse

logger = logging.getLogger(__name__)

ALLOWED_SCHEMES: Final[frozenset[str]] = frozenset({"http", "https"})

#: Ports that are not web ports and have no business being fetched by a page monitor. Blocking
#: them stops this tool being used to probe SMTP, SSH, databases, or Redis.
BLOCKED_PORTS: Final[frozenset[int]] = frozenset(
    {
        22,  # ssh
        23,  # telnet
        25,  # smtp
        110,  # pop3
        135,  # msrpc
        139,  # netbios
        143,  # imap
        445,  # smb
        1433,  # mssql
        1521,  # oracle
        3306,  # mysql
        3389,  # rdp
        5432,  # postgresql
        5984,  # couchdb
        6379,  # redis
        9200,  # elasticsearch
        11211,  # memcached
        27017,  # mongodb
    }
)

#: Cloud instance-metadata addresses. Technically link-local (and so already refused), but named
#: explicitly because they are the single highest-value SSRF target and a reader should see them.
METADATA_ADDRESSES: Final[frozenset[str]] = frozenset(
    {
        "169.254.169.254",  # AWS / Azure / GCP / DigitalOcean / OpenStack
        "fd00:ec2::254",  # AWS IMDSv6
        "100.100.100.200",  # Alibaba Cloud
    }
)

MAX_URL_LENGTH: Final = 2048


class UnsafeTargetError(ValueError):
    """The URL is not safe to fetch. The message explains why, for the operator's benefit."""


@dataclass(frozen=True, slots=True)
class ResolvedTarget:
    """A URL that passed validation, with the addresses it resolved to."""

    url: str
    host: str
    port: int
    scheme: str
    addresses: tuple[str, ...]

    @property
    def primary_address(self) -> str:
        """The address a connection should be pinned to."""
        return self.addresses[0]


def _classify(address: str) -> str | None:
    """Return why this address must not be fetched, or ``None`` when it is safe."""
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return f"{address!r} is not a valid IP address"

    if address in METADATA_ADDRESSES:
        return f"{address} is a cloud instance-metadata address"
    if parsed.is_loopback:
        return f"{address} is a loopback address"
    if parsed.is_link_local:
        return f"{address} is a link-local address"
    if parsed.is_private:
        return f"{address} is a private address"
    if parsed.is_reserved:
        return f"{address} is a reserved address"
    if parsed.is_multicast:
        return f"{address} is a multicast address"
    if parsed.is_unspecified:
        return f"{address} is the unspecified address"
    if isinstance(parsed, ipaddress.IPv6Address):
        # ::ffff:127.0.0.1 would otherwise slip past every check above.
        if parsed.ipv4_mapped is not None:
            mapped = _classify(str(parsed.ipv4_mapped))
            if mapped is not None:
                return f"{address} maps to {mapped}"
        if parsed.sixtofour is not None:
            mapped = _classify(str(parsed.sixtofour))
            if mapped is not None:
                return f"{address} embeds {mapped}"
    return None


def is_public_address(address: str) -> bool:
    """True when ``address`` is a routable public address."""
    return _classify(address) is None


def resolve_addresses(host: str, port: int) -> list[str]:
    """Resolve ``host`` to every address it maps to.

    Every address is returned, not just the first: a name resolving to one public and one
    private address must be refused, and taking only the first would miss that.

    Raises:
        UnsafeTargetError: if the name cannot be resolved.
    """
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise UnsafeTargetError(f"could not resolve {host!r}: {exc}") from exc
    # dict.fromkeys preserves order while de-duplicating.
    return list(dict.fromkeys(str(info[4][0]) for info in infos))


def _prepare(raw: str) -> str:
    """Trim, length-check, and default a missing scheme to https."""
    candidate = raw.strip()
    if not candidate:
        raise UnsafeTargetError("the URL is empty")
    if len(candidate) > MAX_URL_LENGTH:
        raise UnsafeTargetError(f"the URL exceeds {MAX_URL_LENGTH} characters")
    if "://" not in candidate:
        candidate = f"https://{candidate}"
    return candidate


def normalise_url(raw: str) -> str:
    """Return the canonical form of ``raw``: no fragment, lower-case scheme and host.

    The fragment is dropped because it is never sent to the server, so keeping it would make two
    identical requests look like two different targets.

    Note that normalisation is **lossy for credentials** -- ``netloc`` is rebuilt from the
    hostname and port alone. That is why :func:`validate_target` checks for embedded credentials
    on the *raw* input, before normalising: doing it afterwards would silently accept and strip
    them instead of refusing them.
    """
    candidate = _prepare(raw)
    parts = urlparse(candidate)
    if not parts.hostname:
        raise UnsafeTargetError(f"{raw!r} has no hostname")
    netloc = parts.hostname.lower()
    try:
        port = parts.port
    except ValueError as exc:
        raise UnsafeTargetError(f"invalid port in {raw!r}") from exc
    if port:
        netloc = f"{netloc}:{port}"
    # The path's case is preserved: hostnames are case-insensitive, paths are not.
    return urlunparse(
        (parts.scheme.lower(), netloc, parts.path or "/", parts.params, parts.query, "")
    )


def validate_target(raw: str, *, allow_private: bool = False) -> ResolvedTarget:
    """Validate and resolve ``raw``, or refuse it with an explanation.

    Args:
        raw: The URL to check.
        allow_private: Permit loopback and private addresses. **Only** for watching a local test
            server; never enable it for a target list you do not fully control.

    Raises:
        UnsafeTargetError: if the URL is malformed, uses a disallowed scheme or port, cannot be
            resolved, or resolves to a non-public address.
    """
    # Checks run against the *raw* parse, in this order, on purpose:
    #
    #   scheme -> credentials -> port -> hostname -> DNS -> address classification
    #
    # Normalising first would be wrong twice over. It rebuilds netloc from the hostname alone,
    # so embedded credentials would be silently stripped and the credential check could never
    # fire; and for `file:///etc/passwd` it would report "no hostname", which is true but
    # useless -- the real problem is the scheme, and that is what the operator needs told.
    candidate = _prepare(raw)
    parts = urlparse(candidate)

    scheme = parts.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise UnsafeTargetError(
            f"scheme {scheme!r} is not allowed; only {sorted(ALLOWED_SCHEMES)} are"
        )
    if parts.username or parts.password:
        # Credentials in a URL would be written to the target file and to log lines.
        raise UnsafeTargetError("credentials embedded in a URL are not accepted")

    try:
        port = parts.port or (443 if scheme == "https" else 80)
    except ValueError as exc:
        raise UnsafeTargetError(f"invalid port in {raw!r}") from exc

    host = parts.hostname
    if not host:
        raise UnsafeTargetError(f"{raw!r} has no hostname")

    url = normalise_url(candidate)
    if port in BLOCKED_PORTS:
        raise UnsafeTargetError(
            f"port {port} is not a web port and will not be fetched; this tool monitors web "
            "pages, not arbitrary network services"
        )
    if not 1 <= port <= 65535:
        raise UnsafeTargetError(f"port {port} is out of range")

    addresses = resolve_addresses(host, port)
    if not addresses:  # pragma: no cover - getaddrinfo raises instead
        raise UnsafeTargetError(f"{host!r} resolved to no addresses")

    if not allow_private:
        for address in addresses:
            reason = _classify(address)
            if reason is not None:
                raise UnsafeTargetError(
                    f"refusing to fetch {url}: it resolves to {reason}. If this is a local test "
                    "server you control, set allow_private_targets in the configuration."
                )
    else:
        private = [address for address in addresses if not is_public_address(address)]
        if private:
            logger.warning(
                "fetching a non-public address because allow_private_targets is enabled",
                extra={"url": url, "addresses": ",".join(private)},
            )

    return ResolvedTarget(
        url=url, host=host, port=port, scheme=parts.scheme, addresses=tuple(addresses)
    )
