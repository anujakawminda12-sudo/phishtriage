"""Keep your own email address out of every threat-intel lookup (week 3, step 3).

Rule: your address (the recipient's) must never reach a third-party service. Email
addresses themselves are never looked up, but your address also hides inside URLs:

    hxxps://www.aliexpress.com/p/track?to_address=me%40gmail.com           percent-encoded
    hxxps://accounts.google.com/AccountChooser?Email=me@gmail.com           plain
    hxxps://login.evil.test/#bWVAZ21haWwuY29t                              base64
    hxxps://t.shop.test/open?eh=4f1d...c2a9                                 MD5 hash of it

AddressRedactor finds every form above and replaces it with REDACTED. The lookup planner
(step 6) runs every value through it before anything is sent: a value that changed is not
looked up as it is (a URL is replaced by its host), so the address cannot leak even if a
later change to the planner forgot to check.

Nothing here touches the network.
"""

import base64
import hashlib
import re
from collections.abc import Iterable
from dataclasses import dataclass

from phishtriage.models import ParsedEmail

REDACTED = "REDACTED"

# A base64 match shorter than this could be a coincidence, so it is not used
MIN_BASE64_LENGTH = 8


@dataclass(frozen=True)
class Redacted:
    """The result of AddressRedactor.redact() (Java: a record).

    value: the text with every form of the address replaced by REDACTED.
    forms: which forms were found, each once, in the order found, e.g. ("percent-encoded",).
    """

    value: str
    forms: tuple[str, ...] = ()

    @property
    def changed(self) -> bool:
        """True when an address was found (and removed)."""
        return bool(self.forms)


class AddressRedactor:
    """Finds and removes a set of email addresses, in any of the forms they hide in.

    Build one per email with the addresses to hide (see addresses_to_hide), then call
    contains() or redact() for each value. The regular expressions are compiled once in
    __init__ (Java: like keeping compiled java.util.regex.Pattern objects in fields).

    Forms found (all case-insensitive):
        plain            me@gmail.com, ME@Gmail.com
        percent-encoded  me%40gmail.com, me%2540gmail.com (twice), %6D%65%40... (every
                         character); any mix of these
        base64           standard (+/) or URL-safe (-_), with or without "=" padding, alone
                         or inside a longer base64 value such as encoded JSON
        hex              6d652e7669...: each byte as two hex digits (added in step 6)
        md5, sha1, sha256  the hex digest of the lower-case address (trackers often send
                         a hash of the address instead of the address)
    """

    def __init__(self, addresses: Iterable[str]) -> None:
        self.addresses = sorted({a.strip().lower() for a in addresses if "@" in a})
        self._patterns: list[tuple[str, re.Pattern[str]]] = []
        for address in self.addresses:
            self._patterns.append(("plain", _compile(_any_encoding(address))))
            for core in _base64_cores(address):
                self._patterns.append(("base64", _compile(_any_encoding(core))))
            # hex of the address itself (not a hash): fits in a host name, unlike base64's
            # "+", "/" and "=" (week 3, step 6)
            self._patterns.append(("hex", _compile(address.encode("utf-8").hex())))
            for name in ("md5", "sha1", "sha256"):
                digest = hashlib.new(name, address.encode("utf-8")).hexdigest()
                self._patterns.append((name, _compile(re.escape(digest))))

    def contains(self, text: str) -> bool:
        """True when any form of any of the addresses is in the text."""
        return any(pattern.search(text) for _, pattern in self._patterns)

    def redact(self, text: str) -> Redacted:
        """The text with every form of every address replaced by REDACTED."""
        forms: list[str] = []
        for form, pattern in self._patterns:
            for match in pattern.finditer(text):
                # The same pattern matches both: "%" in the match means it was encoded
                found = "percent-encoded" if form == "plain" and "%" in match[0] else form
                if found not in forms:
                    forms.append(found)
            text = pattern.sub(REDACTED, text)
        return Redacted(value=text, forms=tuple(forms))


def addresses_to_hide(email: ParsedEmail, configured: Iterable[str] = ()) -> set[str]:
    """Every address that must stay private for this email.

    That is the configured addresses (PHISHTRIAGE_MY_ADDRESSES in .env, read in step 4)
    plus every recipient (To, Cc, Delivered-To, X-Original-To) of the email and of every
    email forwarded inside it. With a reported phish, the outer email's recipient is the
    security team and the inner one's is the colleague who reported it: both stay private.
    """
    found = list(configured)
    stack = [email]  # walk the forwarding tree without recursion, like walk_parts()
    while stack:
        current = stack.pop()
        found.extend(current.recipients)
        found.extend(current.to)
        stack.extend(current.forwarded)
    # Cleaned here as well, so a caller that forgot to lower-case cannot weaken the match
    return {a.strip().lower() for a in found if "@" in a}


def without_fragment(url: str) -> str:
    """The URL without its "#..." part.

        hxxps://login.evil.test/verify#me@gmail.com -> hxxps://login.evil.test/verify

    The fragment is never sent to a web server (the browser keeps it), so it is not part of
    what a URL reputation service knows about. Phishing kits put the victim's address there
    so the fake login page can fill it in, often in a form not listed above.
    """
    return url.split("#", 1)[0]


# --- helpers ---------------------------------------------------------------------------


def _compile(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE)


def _any_encoding(text: str) -> str:
    """A regex for the text where any character may also be percent-encoded, once or twice.

        "a@b" -> (?:a|%61|%2561)(?:@|%40|%2540)(?:b|%62|%2562)

    One pattern covers "me%40gmail.com", "me%2540gmail.com", a fully encoded address and
    any mix. A character outside ASCII is encoded as its UTF-8 bytes, as in a real URL.
    """
    parts = []
    for character in text:
        hex_bytes = [f"{byte:02x}" for byte in character.encode("utf-8")]
        once = "".join(f"%{h}" for h in hex_bytes)
        twice = "".join(f"%25{h}" for h in hex_bytes)
        parts.append(f"(?:{re.escape(character)}|{once}|{twice})")
    return "".join(parts)


def _base64_cores(address: str) -> list[str]:
    """The parts of the address's base64 that do not depend on what is around it.

    Base64 turns every 3 bytes into 4 characters, so the same address is written
    differently depending on where it starts inside a longer value (byte 0, 1 or 2 of a
    group of 3). For each of the 3 starting positions, this keeps only the characters made
    entirely from the address's own bits:

        "me.victim@gmail.com" alone                    -> bWUudmljdGltQGdtYWlsLmNvb
        inside base64 of '{"email":"me.victim@...'      -> one of the other two cores

    The URL-safe alphabet ("-" and "_" instead of "+" and "/") gives up to 3 more.
    Padding ("=") is never part of a core, so padded and unpadded values both match.
    """
    data = address.encode("utf-8")
    cores = []
    for offset in range(3):
        encoded = base64.b64encode(b"\0" * offset + data + b"\0\0").decode("ascii")
        start = -(-8 * offset // 6)  # first character made only of address bits: ceil(8k/6)
        end = 8 * (offset + len(data)) // 6  # characters before this hold only address bits
        core = encoded[start:end]
        if len(core) >= MIN_BASE64_LENGTH:
            cores.append(core)
            url_safe = core.replace("+", "-").replace("/", "_")
            if url_safe != core:
                cores.append(url_safe)
    return cores
