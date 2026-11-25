"""The allowlist (week 2, step 9): IOCs that week 3 should not spend API quota on.

Allowlisted means "skip the lookup", never "safe". Allowlisted IOCs stay in the report,
because attackers host phishing on trusted platforms (Google Forms, OneDrive, ...).

The file format is described at the top of allowlist.txt. In short: one domain per line,
covering its subdomains; "!" marks an exception; the most specific line wins.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from urllib.parse import urlsplit

from .domains import ascii_domain
from .models import IOC

# A URL whose path or query holds another URL may be an open redirect, such as
# https://www.google.com/url?q=https://evil.test, so it is never skipped.
EMBEDDED_URL = re.compile(r"(?i)https?(?::|%3a)")

# A valid allowlist entry: letters, digits, "-" and dots, with at least one dot
DOMAIN_ENTRY = re.compile(r"^[a-z0-9-]+(\.[a-z0-9-]+)+$")


@dataclass(frozen=True)
class Allowlist:
    """Allowed domains and exceptions, plus any lines that could not be read.

    frozen=True makes it read-only after creation, like a Java class with final fields.
    """

    domains: frozenset[str] = frozenset()
    exceptions: frozenset[str] = frozenset()
    problems: tuple[str, ...] = ()

    def covers(self, host: str) -> bool:
        """True if lookups for this host should be skipped.

        Walks from the most specific name to the least, so the first line that matches
        wins: with "google.com" and "!docs.google.com", a.docs.google.com is checked as
        a.docs.google.com, then docs.google.com (an exception: False).
        Matching whole labels means "evilgoogle.com" is NOT covered by "google.com".
        """
        labels = ascii_domain(host).split(".")
        for start in range(len(labels)):
            name = ".".join(labels[start:])
            if name in self.exceptions:
                return False
            if name in self.domains:
                return True
        return False

    def mark(self, iocs: list[IOC]) -> list[IOC]:
        """Set ioc.allowlisted on URLs, domains and email addresses. IPs are never skipped.

        Returns the same list, so it can be used in an expression.
        """
        for ioc in iocs:
            if ioc.kind == "domain":
                ioc.allowlisted = self.covers(ioc.value)
            elif ioc.kind == "email":
                ioc.allowlisted = self.covers(ioc.value.rpartition("@")[2])
            elif ioc.kind == "url":
                ioc.allowlisted = self._covers_url(ioc.value)
        return iocs

    def _covers_url(self, url: str) -> bool:
        try:
            parts = urlsplit(url)
        except ValueError:
            return False
        if EMBEDDED_URL.search(parts.path + "?" + parts.query):
            return False  # a possible open redirect: always look it up
        return self.covers(parts.hostname or "")


def parse_allowlist(text: str) -> Allowlist:
    """Build an Allowlist from the text of an allowlist file."""
    domains: set[str] = set()
    exceptions: set[str] = set()
    problems: list[str] = []

    for number, line in enumerate(text.splitlines(), start=1):
        entry = line.split("#", 1)[0].strip()  # drop comments and spaces
        if not entry:
            continue
        is_exception = entry.startswith("!")
        name = ascii_domain(entry.removeprefix("!").strip())
        if not DOMAIN_ENTRY.match(name):
            problems.append(f"line {number}: {entry!r} is not a domain name, so it was ignored")
            continue
        (exceptions if is_exception else domains).add(name)

    return Allowlist(frozenset(domains), frozenset(exceptions), tuple(problems))


def load_allowlist(path: Path | None = None) -> Allowlist:
    """Read an allowlist file, or the built-in allowlist.txt when no path is given.

    importlib.resources finds the built-in file inside the installed package, wherever
    pip put it (Java: getClass().getResourceAsStream("allowlist.txt")).
    """
    if path is None:
        text = resources.files("phishtriage").joinpath("allowlist.txt").read_text("utf-8")
    else:
        text = Path(path).read_text("utf-8")
    return parse_allowlist(text)
