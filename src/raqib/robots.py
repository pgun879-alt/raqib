"""``robots.txt`` compliance.

Why this is implemented rather than skipped
-------------------------------------------
Honouring ``robots.txt`` is the difference between a monitoring tool and an unwelcome crawler. It
is also the single clearest signal, in a portfolio piece, that the author understands that fetching
someone else's server is something you do *on their terms*.

Python ships :mod:`urllib.robotparser`, and this module deliberately does **not** use it. Two
reasons:

* It fetches the file itself, with no timeout, no custom user agent and no SSRF validation --
  handing the one part of this tool that must be careful about network access to a component that
  is not.
* It ignores ``Crawl-delay``, which is precisely the directive a *polite* monitor should obey.

So the parser here is small, has no network access of its own (the caller supplies the text), and
extracts both ``Disallow``/``Allow`` rules and ``Crawl-delay``.

Matching follows the widely-implemented convention: the **longest matching path** wins, and
``Allow`` beats ``Disallow`` on an equal-length tie. A group whose ``User-agent`` matches our
token specifically takes precedence over the ``*`` group.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Final
from urllib.parse import unquote, urlparse

logger = logging.getLogger(__name__)

#: Cap on the robots.txt body we will parse. A hostile or broken server could otherwise serve a
#: gigabyte of text to a client that has already committed to reading it.
MAX_ROBOTS_BYTES: Final = 512 * 1024


@dataclass(frozen=True, slots=True)
class Rule:
    """One ``Allow`` or ``Disallow`` directive."""

    path: str
    allowed: bool

    @property
    def specificity(self) -> int:
        return len(self.path)


@dataclass(slots=True)
class Group:
    """Rules for one or more user-agent tokens."""

    agents: set[str] = field(default_factory=set)
    rules: list[Rule] = field(default_factory=list)
    crawl_delay: float | None = None


def _agent_token(user_agent: str) -> str:
    """Reduce a full user-agent string to the token robots.txt groups are written against.

    ``"raqib/0.1 (+https://...)"`` becomes ``"raqib"``.
    """
    head = user_agent.strip().split("/", 1)[0].split()[0] if user_agent.strip() else ""
    return head.lower()


def _path_matches(pattern: str, path: str) -> bool:
    """Match a robots path pattern against ``path``, supporting ``*`` and ``$``.

    The wildcard and end-anchor extensions are not in the original standard but are honoured by
    every major crawler, so a site author writing them expects them to work.

    An empty pattern matches nothing. Empty-valued directives are dropped during parsing (see
    :meth:`RobotsRules.parse`), so this is only a second line of defence.
    """
    if not pattern:
        return False
    if "*" not in pattern and "$" not in pattern:
        return path.startswith(pattern)

    anchored = pattern.endswith("$")
    body = pattern[:-1] if anchored else pattern
    regex = "".join(".*" if char == "*" else re.escape(char) for char in body)
    return re.match(f"{regex}$" if anchored else regex, path) is not None


class RobotsRules:
    """Parsed ``robots.txt`` rules for one origin."""

    def __init__(
        self, groups: list[Group], *, user_agent: str, unavailable: bool = False
    ) -> None:
        self._token = _agent_token(user_agent)
        specific = [group for group in groups if self._token in group.agents]
        wildcard = [group for group in groups if "*" in group.agents]
        # A group naming us specifically overrides the wildcard group entirely -- that is what a
        # site author means by writing one.
        self._active = specific or wildcard
        self.matched_specific_group = bool(specific)
        #: True when these rules are a fail-closed placeholder because robots.txt could not be
        #: read, rather than rules the site actually published. Callers must distinguish the two:
        #: "the site told us not to" is a configuration fact the operator should fix, while
        #: "we could not reach the site" is an outage. Reporting an outage as a robots refusal
        #: sends the operator to edit a config file when their server is down.
        self.unavailable = unavailable

    @classmethod
    def parse(cls, text: str, *, user_agent: str) -> RobotsRules:
        """Parse ``robots.txt`` content.

        Unknown directives, comments and malformed lines are ignored, as the convention requires:
        a robots file with a typo in it must not become a blanket allow or a blanket deny.
        """
        groups: list[Group] = []
        current: Group | None = None
        expecting_agents = False

        for raw_line in text.splitlines():
            line = raw_line.split("#", 1)[0].strip()
            if not line or ":" not in line:
                continue
            key, _, value = line.partition(":")
            key = key.strip().lower()
            value = value.strip()

            if key == "user-agent":
                if current is None or not expecting_agents:
                    current = Group()
                    groups.append(current)
                    expecting_agents = True
                current.agents.add(value.lower())
                continue

            if current is None:
                # A rule before any User-agent line has no group; ignore it.
                continue
            expecting_agents = False

            if key in {"disallow", "allow"}:
                # A directive with an empty value is dropped, not stored as a match-all rule.
                # `Disallow:` with no path is the standard's documented way of saying "nothing is
                # disallowed" -- treating it as a rule matching every path would invert its
                # meaning and block the entire site.
                if not value:
                    continue
                # Paths in robots.txt may be percent-encoded; compare decoded.
                current.rules.append(Rule(path=unquote(value), allowed=key == "allow"))
            elif key == "crawl-delay":
                try:
                    delay = float(value)
                except ValueError:
                    logger.debug("ignoring unparseable crawl-delay %r", value)
                else:
                    if delay >= 0:
                        current.crawl_delay = delay

        return cls(groups, user_agent=user_agent)

    @classmethod
    def allow_all(cls, *, user_agent: str) -> RobotsRules:
        """Rules used when no ``robots.txt`` exists (HTTP 404), which means "everything allowed"."""
        return cls([], user_agent=user_agent)

    @classmethod
    def deny_all(cls, *, user_agent: str, unavailable: bool = True) -> RobotsRules:
        """Rules used when ``robots.txt`` cannot be read, i.e. fail closed.

        ``unavailable`` defaults to True because that is the only situation this is used in, and
        it lets the caller report the real cause rather than a robots refusal.
        """
        group = Group(agents={"*"}, rules=[Rule(path="/", allowed=False)])
        return cls([group], user_agent=user_agent, unavailable=unavailable)

    @property
    def crawl_delay(self) -> float | None:
        """The ``Crawl-delay`` the active group asks for, if any."""
        for group in self._active:
            if group.crawl_delay is not None:
                return group.crawl_delay
        return None

    def can_fetch(self, url: str) -> bool:
        """True when the active group permits fetching ``url``.

        Longest matching path wins; ``Allow`` beats ``Disallow`` on an equal-length tie, which is
        how a site author writes "everything under /private except /private/status".
        """
        parsed = urlparse(url)
        path = unquote(parsed.path) or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"

        best: Rule | None = None
        for group in self._active:
            for rule in group.rules:
                if not _path_matches(rule.path, path):
                    continue
                if best is None or rule.specificity > best.specificity:
                    best = rule
                elif rule.specificity == best.specificity and rule.allowed:
                    best = rule
        if best is None:
            return True  # nothing matched -> allowed
        return best.allowed


def robots_url_for(url: str) -> str:
    """The ``robots.txt`` URL for the origin of ``url``.

    Per the standard, ``robots.txt`` is per **origin** -- scheme, host and port -- so
    ``https://example.com:8443/a`` and ``https://example.com/a`` have different robots files.
    """
    parsed = urlparse(url)
    netloc = parsed.netloc
    return f"{parsed.scheme}://{netloc}/robots.txt"
