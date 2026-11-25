"""Pressure and credential-request wording in an email's text (week 4, step 6).

Two findings, with no points (scoring is step 8):

    urgency_wording             pushes for quick action, or threatens the account:
                                "within 24 hours", "your account has been suspended",
                                "unusual sign-in activity", "final notice"
    credential_request_wording  asks for a password, a login or payment details:
                                "verify your account", "your password expires today",
                                "update your payment details", "mailbox is full"

Both are weak evidence on their own: genuine security alerts and invoices use the same
words. The proposal gives the row 5 points. The point is the explanation, not the score:
a report that quotes "verify your account within 24 hours" tells the analyst at once
what kind of lure this is.

What is read: the subject, the text body and the visible text of the HTML body (not
<style> or <script>). Before matching, the text is tidied so that common tricks to
dodge keyword filters do not work:
    - invisible characters are removed: "ver\u200bify" (a zero-width space) -> "verify"
    - look-alike letters from other alphabets become Latin: "verify your \u0430ccount" with
      a Cyrillic "\u0430" -> "verify your account" (digits are left alone: "within 24 hours")
    - full-width letters, non-breaking spaces and curly apostrophes become plain ones
    - all spaces and line breaks become single spaces, and everything is lower case

The subject of an email that carries a forwarded email is skipped: "Fwd: Your password
expires today" repeats the original's subject, and the original is checked on its own.

Known limits: English only (Sinhala and Tamil lures are not caught), phrases only (a
lure worded in a new way is missed), and an image of text is not read at all.
"""

from __future__ import annotations

import re
import unicodedata

from bs4 import BeautifulSoup

from .lookalike import LOOKALIKE_CHARACTERS
from .models import Finding, ParsedEmail

# Invisible characters used to break up words: zero-width space, non-joiner and joiner,
# word joiner, byte order mark, soft hyphen. str.translate() deletes a character mapped
# to None (Java: a replace of each character with "").
INVISIBLE = dict.fromkeys(map(ord, "\u200b\u200c\u200d\u2060\ufeff\u00ad"), None)

_ACCOUNT = r"(?:account|mailbox|access|card|password|service|profile)s?"
_NUMBER = r"(?:\d+|one|two|three|twenty[- ]?four|forty[- ]?eight|seventy[- ]?two)"

URGENCY = tuple(
    re.compile(pattern)
    for pattern in (
        r"\burgent(?:ly)?\b",
        r"\bimmediate(?:ly| action| attention)\b",
        r"\baction (?:is )?required\b",
        rf"\bwithin (?:the next )?{_NUMBER} ?(?:hours?|hrs?|days?)\b",
        r"\b(?:final|last) (?:notice|warning|reminder)\b",
        # the account, not "our office will be closed on Monday"
        rf"\b{_ACCOUNT} (?:will be|has been|have been|is|was|are) (?:temporarily |permanently )?"
        r"(?:suspended|locked|closed|deleted|disabled|terminated|deactivated|blocked|restricted)\b",
        r"\b(?:unusual|suspicious|unauthori[sz]ed) (?:sign[- ]?in |log[- ]?in )?"
        r"(?:activity|attempts?|access|sign[- ]?ins?|log[- ]?ins?)\b",
        r"\bexpir(?:es|ing|ed) (?:today|tomorrow|soon|tonight)\b",
        r"\b(?:avoid|prevent) (?:the )?(?:suspension|closure|deactivation|termination|"
        r"losing access)\b",
        r"\bfailure to (?:verify|confirm|update|respond|comply)\b",
    )
)

CREDENTIAL_REQUEST = tuple(
    re.compile(pattern)
    for pattern in (
        # not "verify your email address": every genuine sign-up asks for that
        r"\b(?:verify|confirm|validate|re-?confirm) (?:your )?(?:account|identity|"
        r"log[- ]?in|sign[- ]?in|password|credentials|billing|payment)\b",
        r"\bupdate (?:your )?(?:account|password|credentials|payment|billing|card)"
        r"(?: details| information| method)?\b",
        r"\bpassword (?:expires|will expire|has expired|is expiring|expired)\b",
        r"\bkeep (?:your |the )?(?:current |same )?password\b",
        r"\b(?:enter|provide|re-?enter|type) (?:your )?(?:password|credentials|"
        r"login details|pin)\b",
        r"\b(?:sign|log)[- ]?in (?:now |here |below )?to (?:verify|confirm|restore|unlock|"
        r"reactivate|keep|avoid|continue using)\b",
        r"\b(?:unlock|restore|reactivate|recover) (?:your )?(?:account|access|mailbox)\b",
        r"\b(?:mailbox|storage|inbox) (?:is )?(?:full|almost full|over (?:its )?(?:quota|limit))\b",
    )
)

MAX_PHRASES = 3  # how many matched phrases the detail quotes


def normalise(text: str) -> str:
    """Tidy text before matching, so tricks to dodge keyword filters do not work.

    "Ver\u200bify   your\nACCOUNT"  -> "verify your account"
    "verify your \u0430ccount" (a Cyrillic "\u0430") -> "verify your account"
    "you\u2019re" (a curly apostrophe) -> "you're"
    """
    text = unicodedata.normalize("NFKC", text).translate(INVISIBLE)
    text = "".join(
        char if char.isascii() else LOOKALIKE_CHARACTERS.get(char.lower(), char) for char in text
    )
    text = text.replace("\u2019", "'").replace("\u2018", "'")
    return " ".join(text.split()).lower()


def visible_html_text(html: str) -> str:
    """The text a reader sees in an HTML body. <style> and <script> text is not included."""
    if not html.strip():
        return ""
    return BeautifulSoup(html, "html.parser").get_text(" ")


def find_phrases(text: str, patterns: tuple[re.Pattern[str], ...]) -> list[str]:
    """Every phrase the patterns match in (normalised) text, each once, in the order the
    phrases appear in the text (not the order of the patterns)."""
    first_seen: dict[str, int] = {}
    for pattern in patterns:
        for match in pattern.finditer(text):
            phrase = match.group(0)
            first_seen[phrase] = min(first_seen.get(phrase, match.start()), match.start())
    return sorted(first_seen, key=first_seen.__getitem__)


def check_wording(email: ParsedEmail) -> list[Finding]:
    """urgency_wording and credential_request_wording: at most one of each."""
    places = {"the body": normalise(f"{email.text_body} {visible_html_text(email.html_body)}")}
    if not email.forwarded:  # "Fwd: ..." repeats the forwarded email's subject
        places = {"the subject": normalise(email.subject), **places}

    findings = []
    for rule, what, patterns in (
        ("urgency_wording", "Pressure to act quickly", URGENCY),
        ("credential_request_wording", "Asks for a login, password or payment", CREDENTIAL_REQUEST),
    ):
        phrases: list[str] = []
        where: list[str] = []
        for place, text in places.items():
            found = find_phrases(text, patterns)
            if found:
                where.append(place)
                phrases.extend(phrase for phrase in found if phrase not in phrases)
        if phrases:
            quoted = ", ".join(f'"{phrase}"' for phrase in phrases[:MAX_PHRASES])
            more = len(phrases) - MAX_PHRASES
            if more > 0:
                quoted += f" and {more} more"
            detail = f"{what}, in {' and '.join(where)}: {quoted}"
            findings.append(Finding(rule=rule, detail=detail))
    return findings
