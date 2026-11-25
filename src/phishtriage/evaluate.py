"""The week 2 gate: compare extracted IOCs with lists you checked by hand.

For each sample email.eml there is a hand-check file, expected/email.txt, written by
reading the email BEFORE running PhishTriage on it. write_templates() also writes
expected/email.decoded.txt: the same email with its transfer encoding undone, so links
are readable (quoted-printable writes "=" as "=3D" and splits long lines).

compare() reports, per IOC type, what both found (matched), what only you found (missed
by the tool) and what only the tool found (extra). Week 5 will reuse this idea to compare
verdicts with labels.
"""

from __future__ import annotations

import html
import ipaddress
from dataclasses import dataclass, field
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from pathlib import Path

from .allowlist import Allowlist
from .domains import ascii_domain
from .iocs import HTTP_SCHEME, extract_iocs, normalise_url, refang, unwrap_url
from .models import ParsedEmail
from .parser import MAX_FORWARD_DEPTH, walk_parts

# Sections of a hand-check file, and the IOC kind each one holds
SECTIONS = ("domains", "ips", "emails", "attachments", "urls")
KIND_OF = {"domains": "domain", "ips": "ip", "emails": "email", "urls": "url"}
OPTIONAL = {"urls"}  # an empty [urls] section means "not checked", not "no URLs"

TEMPLATE = """\
# Hand-checked IOCs for {name}
#
# Fill this in by reading {decoded} (the same email with its encoding undone)
# BEFORE running phishtriage on it, so the tool cannot influence what you write.
# One value per line, under the right [heading] at the bottom. "#" starts a comment.
# Defanged values (evil[.]test) are fine. For Safe Links or Proofpoint links, write the
# real destination (its host under [domains]); a pasted wrapped [urls] link is unwrapped.
#
# Links and addresses count only in the BODY: below the first "----- ... decoded -----"
# line. Links in headers at the top (such as List-Unsubscribe) do not count, and nor
# does www.w3.org in xmlns="..." or <!DOCTYPE ...>: it is a format label, not a link.
#
# A link is a URL written as text, or after href=, src= or action=, or in CSS after
# url( or @import. It may start with // instead of hxxps:// (href="//cdn.test/a.css").
# Other attributes are not links: prefix="hxxps://x.com/" and itemtype="//schema.org/..."
# are never visited. But alt="..." text counts as written text: mail apps show it when
# images are blocked.
# A link inside another link counts as a link of its own:
#   hxxps://t.example.com/c?u=https%3A%2F%2Fwww.shop.test%2F   ->  also www.shop.test
#   (%3A%2F%2F is "://" in code)   .../imageproxy/hxxps://cdn.test/a.png  ->  also cdn.test
#
# [emails]       the From and Reply-To (every address in each) and Return-Path addresses
#                (at the top), plus any address written in the body, except your own
# [domains]      1) the host of every link in the body: the part between
#                   "hxxps://" (or "//") and the next "/" (www.example.com, not example.com)
#                2) the part after "@" of every address under [emails]
#                3) the part after "@" in the Message-ID, only if it is a real domain
#                   ending in .com, .org, .lk ... (not service-v2-6b7f or mta1.prd.sparkpost)
# [ips]          public IPs in [brackets] in "Received: from" lines
#                (leave out 10.x, 172.16-31.x, 192.168.x and 127.x)
# [attachments]  attachment file names: search for "[attachment:"
# [urls]         optional: every link in the body. Leave it empty to skip.

[domains]

[ips]

[emails]

[attachments]

[urls]
"""


@dataclass
class Comparison:
    """The result for one section of one email."""

    matched: set[str] = field(default_factory=set)
    missed: set[str] = field(default_factory=set)  # you found it, the tool did not
    extra: set[str] = field(default_factory=set)  # the tool found it, you did not


def parse_hand_check(text: str) -> dict[str, set[str]]:
    """Read a hand-check file into {section: {normalised values}}.

    A section that is missing from the file is treated as empty.
    """
    values: dict[str, set[str]] = {section: set() for section in SECTIONS}
    section = None
    for line in text.splitlines():
        entry = line.split("#", 1)[0].strip()
        if not entry:
            continue
        if entry.startswith("[") and entry.endswith("]"):
            name = entry[1:-1].strip().lower()
            section = name if name in values else None  # unknown sections are ignored
            continue
        if section is not None:
            values[section].add(normalise(section, entry))
    return values


def tool_values(email: ParsedEmail, allowlist: Allowlist | None = None) -> dict[str, set[str]]:
    """What PhishTriage found, in the same shape as a hand-check file.

    Emails forwarded inside this one are included, because whoever reads the raw source
    by hand sees them too.
    """
    values: dict[str, set[str]] = {section: set() for section in SECTIONS}
    for part in _with_forwarded(email):
        for ioc in extract_iocs(part, allowlist):
            for section, kind in KIND_OF.items():
                if ioc.kind == kind:
                    values[section].add(normalise(section, ioc.value))
        values["attachments"].update(normalise("attachments", a.filename) for a in part.attachments)
    return values


def compare(expected: dict[str, set[str]], found: dict[str, set[str]]) -> dict[str, Comparison]:
    """Section by section: matched, missed and extra values.

    An empty optional section (urls) is skipped, so it does not count as all "extra".
    """
    results = {}
    for section in SECTIONS:
        if section in OPTIONAL and not expected[section]:
            continue
        want, got = expected[section], found[section]
        results[section] = Comparison(matched=want & got, missed=want - got, extra=got - want)
    return results


def normalise(section: str, value: str) -> str:
    """Write a value the way the tool does, so "WWW.Shop.test." and "www.shop.test" match."""
    value = refang(value.strip())
    if section == "domains":
        return ascii_domain(value)
    if section == "ips":
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            return value
    if section == "emails":
        return value.lower()
    if section == "urls":
        # pasted from the raw HTML: "&amp;" -> "&", and Safe Links/Proofpoint unwrapped
        return normalise_url(unwrap_url(html.unescape(value))[0])
    return value  # attachment names are compared exactly


def write_templates(folder: Path) -> list[Path]:
    """Create a blank hand-check file and a decoded copy for every .eml that has none.

    Existing files are never overwritten. Returns the hand-check files that were created.
    """
    expected_dir = folder / "expected"
    expected_dir.mkdir(exist_ok=True)
    created = []
    for eml in sorted(folder.glob("*.eml")):
        target = expected_dir / f"{eml.stem}.txt"
        decoded = expected_dir / f"{eml.stem}.decoded.txt"
        if not decoded.exists():
            with eml.open("rb") as fh:
                msg = BytesParser(policy=policy.default).parse(fh)
            decoded.write_text(decoded_view(msg), encoding="utf-8")
        if not target.exists():
            text = TEMPLATE.format(name=eml.name, decoded=decoded.name)
            target.write_text(text, encoding="utf-8")
            created.append(target)
    return created


def decoded_view(msg: EmailMessage) -> str:
    """An email as plain text for reading by hand: all headers, then every text part with
    its transfer encoding (quoted-printable or base64) undone.

    Nothing is extracted or rendered. Attachments are named but never decoded. Links are
    written hxxp:// so an editor does not turn them into clickable links.
    """
    lines: list[str] = []
    _describe(msg, lines, depth=0)
    return HTTP_SCHEME.sub(r"hxxp\1://", "\n".join(lines)) + "\n"


def _describe(msg: EmailMessage, lines: list[str], depth: int) -> None:
    for name, value in msg.items():
        try:
            lines.append(f"{name}: {value}")
        except Exception:  # a header too broken to print
            lines.append(f"{name}: (could not be decoded)")
    lines.append("")
    for part in walk_parts(msg):
        content_type = part.get_content_type()
        if content_type == "message/rfc822":
            if depth >= MAX_FORWARD_DEPTH:
                lines.append("[forwarded email nested too deep: not shown]")
                continue
            lines.append(f"===== forwarded email (level {depth + 1}) =====")
            _describe(part.get_content(), lines, depth + 1)
            lines.append(f"===== end of forwarded email (level {depth + 1}) =====")
        elif part.is_multipart():
            continue
        elif part.get_filename() or part.get_content_disposition() == "attachment":
            name = part.get_filename() or "(no name)"
            lines.append(f"[attachment: {name} ({content_type}), not decoded]")
        elif part.get_content_maintype() == "text":
            lines.append(f"----- {content_type} part, decoded -----")
            try:
                lines.append(part.get_content())
            except Exception:  # unknown charset: same fallback as the parser
                lines.append((part.get_payload(decode=True) or b"").decode("utf-8", "replace"))


def _with_forwarded(email: ParsedEmail) -> list[ParsedEmail]:
    """The email itself, then every email forwarded inside it, at any depth."""
    found = [email]
    for inner in email.forwarded:
        found.extend(_with_forwarded(inner))
    return found
