"""Sender domains that imitate a brand (week 4, step 4).

Two findings, with no points (scoring is step 8):

    lookalike_sender_domain   the domain imitates a brand's name:
                                  paypa1-secure.test     "1" instead of "l"
                                  rnicrosoft.test        "rn" instead of "m"
                                  xn--pypal-4ve.com      shown as p\u0430ypal.com: Cyrillic "\u0430"
                                  paypall.test           one letter more
                              or mixes two alphabets in one name (Latin and Cyrillic, ...)
    brand_in_sender_domain    the domain uses the brand's real name as one of its words,
                              but is not one of the brand's domains:
                                  paypal-secure-login.test, paypal.com.evil.test

Every From and Reply-To address is checked. Return-Path is not: it is normally the
mailing service's bounce address, which says nothing about the brand.

Punycode on its own is not flagged. An "xn--" name is how any non-English domain is
written in DNS (Sinhala, Tamil and German names all become xn--...), so it is only
suspicious when, decoded, it mixes alphabets or imitates a brand. The proposal lists
"punycode" as a signal; this is the narrower version, on purpose.

A domain whose own name is exactly the brand (amazon.co.uk, paypal.de) is not flagged
either: those are usually the brand's country sites.

Known limits:
    - a phish on a brand's exact name with another ending (paypal.co) is missed here;
    - a brand glued to another word with no hyphen (paypallogin.test) is missed: looking
      for the brand inside every word would flag applewood, googleplex and the like;
    - a real company one letter away from a brand is flagged (paypay.ne.jp, a Japanese
      payment service, "looks like paypal"): that is the price of catching paypall.test;
    - only the brands in headers.BRAND_DOMAINS are protected.

Nothing here touches the network.
"""

from __future__ import annotations

import codecs
import unicodedata

from .domains import ascii_domain, icann_domain, registered_domain
from .headers import BRAND_DOMAINS, get_domain
from .models import Finding, ParsedEmail

# Characters that look like a Latin letter in most fonts, and the letter they imitate.
# Unicode's full list (confusables.txt) has thousands; these are the ones phishing domains
# use most: Cyrillic and Greek letters that look identical, and digit swaps.
LOOKALIKE_CHARACTERS = {
    # Cyrillic
    "\u0430": "a",  # cyrillic small letter a
    "\u0435": "e",  # cyrillic small letter ie
    "\u0451": "e",  # cyrillic small letter io
    "\u04bb": "h",  # cyrillic small letter shha
    "\u0456": "i",  # cyrillic small letter byelorussian-ukrainian i
    "\u0457": "i",  # cyrillic small letter yi
    "\u0458": "j",  # cyrillic small letter je
    "\u043a": "k",  # cyrillic small letter ka
    "\u04cf": "l",  # cyrillic small letter palochka
    "\u043e": "o",  # cyrillic small letter o
    "\u0440": "p",  # cyrillic small letter er
    "\u0441": "c",  # cyrillic small letter es
    "\u0455": "s",  # cyrillic small letter dze
    "\u0443": "y",  # cyrillic small letter u
    "\u0445": "x",  # cyrillic small letter ha
    "\u0501": "d",  # cyrillic small letter komi de
    "\u051b": "q",  # cyrillic small letter qa
    "\u051d": "w",  # cyrillic small letter we
    # Greek
    "\u03b1": "a",  # greek small letter alpha
    "\u03b5": "e",  # greek small letter epsilon
    "\u03b9": "i",  # greek small letter iota
    "\u03ba": "k",  # greek small letter kappa
    "\u03bd": "v",  # greek small letter nu
    "\u03bf": "o",  # greek small letter omicron
    "\u03c1": "p",  # greek small letter rho
    "\u03c4": "t",  # greek small letter tau
    "\u03c5": "u",  # greek small letter upsilon
    "\u03c7": "x",  # greek small letter chi
    # Latin letters from other alphabets (IPA and Turkish)
    "\u0251": "a",  # latin small letter alpha
    "\u0261": "g",  # latin small letter script g
    "\u0131": "i",  # latin small letter dotless i
    "\u0269": "i",  # latin small letter iota
    "\u026a": "i",  # latin letter small capital i
    # digits
    "0": "o",  # digit 0
    "1": "l",  # digit 1
    "3": "e",  # digit 3
    "5": "s",  # digit 5
}
# Pairs of letters that read as one letter at a glance
LOOKALIKE_PAIRS = (("rn", "m"), ("vv", "w"))

# The brand names to protect, and every brand's real domains (from headers.BRAND_DOMAINS)
BRANDS = tuple(BRAND_DOMAINS)
REAL_DOMAINS = frozenset(domain for domains in BRAND_DOMAINS.values() for domain in domains)


def edit_limit(brand: str) -> int:
    """How many letters may differ before a name stops counting as a copy of the brand.

    Short brands get none: "apple" is one letter from "apply", and "dhl" from many real
    words, so only look-alike characters count for them (app1e, dh1). Long brands can
    take two: "micr0s0ft" is caught as look-alike characters, "microsofft" as one extra
    letter, "mircosoft" as one swap.
    """
    if len(brand) >= 9:
        return 2
    if len(brand) >= 6:
        return 1
    return 0


def skeleton(text: str) -> str:
    """What a name looks like at a glance: every look-alike written as the letter it copies.

        skeleton("paypa1")   -> "paypal"
        skeleton("p\u0430ypal")   -> "paypal"   (the "\u0430" is Cyrillic)
        skeleton("rnicrosoft") -> "microsoft"
        skeleton("ｐａｙｐａｌ") -> "paypal"  (full-width letters, folded by NFKC first)

    NFKC is Unicode's "compatibility" normalisation: it turns full-width and other
    decorated forms into the plain letter (Java: java.text.Normalizer with Form.NFKC).
    """
    text = unicodedata.normalize("NFKC", text).lower()
    text = "".join(LOOKALIKE_CHARACTERS.get(char, char) for char in text)
    for pair, letter in LOOKALIKE_PAIRS:
        text = text.replace(pair, letter)
    return text


def describe_swaps(word: str) -> str:
    """Which look-alike characters a word uses, so a reader can see what is fake.

        describe_swaps("paypa1")     -> '"1" for "l"'
        describe_swaps("p\u0430ypal")     -> 'Cyrillic "\u0430" U+0430 for "a"'
        describe_swaps("rnicr0soft") -> '"0" for "o", "rn" for "m"'

    Week 4, step 5: the first version printed 'look-alike characters ("p\u0430ypal" reads as
    "paypal")', and on screen the Cyrillic "\u0430" looks exactly like a Latin "a", so the two
    words looked the same and the reason explained nothing. A character outside plain
    ASCII is named with its alphabet and its Unicode number (U+0430), which no font
    can disguise.
    """
    folded = unicodedata.normalize("NFKC", word).lower()
    swaps = []
    for char in dict.fromkeys(folded):  # each character once, in order
        letter = LOOKALIKE_CHARACTERS.get(char)
        if letter is None:
            continue
        if char.isascii():
            swaps.append(f'"{char}" for "{letter}"')
        else:
            alphabet = unicodedata.name(char, "UNKNOWN").split()[0].title()
            swaps.append(f'{alphabet} "{char}" U+{ord(char):04X} for "{letter}"')
    mapped = "".join(LOOKALIKE_CHARACTERS.get(char, char) for char in folded)
    swaps.extend(f'"{pair}" for "{letter}"' for pair, letter in LOOKALIKE_PAIRS if pair in mapped)
    return ", ".join(swaps)


def edit_distance(a: str, b: str) -> int:
    """How many single-letter edits turn a into b: insert, delete, replace, or swap two
    neighbours (the Damerau-Levenshtein "optimal string alignment" distance).

        edit_distance("paypall", "paypal")      -> 1   (one extra letter)
        edit_distance("mircosoft", "microsoft") -> 1   (two letters swapped)

    Dynamic programming over a table, row by row (Java: an int[][] filled in a double loop).
    cell [i][j] = edits to turn the first i letters of a into the first j letters of b.
    """
    rows = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        rows[i][0] = i
    for j in range(len(b) + 1):
        rows[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            rows[i][j] = min(
                rows[i - 1][j] + 1,  # delete a letter from a
                rows[i][j - 1] + 1,  # insert a letter into a
                rows[i - 1][j - 1] + cost,  # replace (or keep, if the letters are equal)
            )
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                rows[i][j] = min(rows[i][j], rows[i - 2][j - 2] + 1)  # swap two neighbours
    return rows[len(a)][len(b)]


def scripts(label: str) -> list[str]:
    """The alphabets used by the letters of a name, e.g. ["CYRILLIC", "LATIN"].

    unicodedata.name("\u0430") is "CYRILLIC SMALL LETTER A": its first word is the alphabet.
    Digits and "-" are not letters, so they do not count.
    """
    found = {unicodedata.name(char, "UNKNOWN").split()[0] for char in label if char.isalpha()}
    return sorted(found)


def decode_label(label: str) -> str:
    """'xn--pypal-4ve' -> 'p\u0430ypal'. Any other label is returned as it is.

    "xn--" marks punycode, the way DNS spells a non-ASCII name with plain letters. A label
    that is not valid punycode is kept as written.
    """
    if not label.startswith("xn--"):
        return label
    try:
        decoded = codecs.decode(label[4:].encode("ascii"), "punycode")
    except (UnicodeError, ValueError):
        return label
    return decoded or label  # "xn--" with nothing after it is not a name


class DomainReport:
    """What one sender domain imitates (Java: a small value object built by a method)."""

    def __init__(self, host: str) -> None:
        self.host = ascii_domain(host)  # p\u0430ypal.com and xn--pypal-4ve.com are the same name
        self.lookalike: list[str] = []  # reasons, e.g. 'looks like paypal: "paypa1" ...'
        self.brand_used: list[str] = []  # brands whose name it uses as one of its words
        labels = self.host.split(".")
        self.decoded = ".".join(decode_label(label) for label in labels)


def inspect_domain(host: str) -> DomainReport:
    """Everything a sender domain imitates. The real brand domains get an empty report."""
    report = DomainReport(host)
    owner = registered_domain(report.host)
    if not owner or owner in REAL_DOMAINS:
        return report

    # The labels left of the public suffix: "paypal.com.evil.test" -> paypal, com, evil
    own_label = owner.split(".")[0]
    above = report.host[: -len(owner)].rstrip(".")
    labels = [*(above.split(".") if above else []), own_label]
    # amazon.co.uk names the brand exactly: probably its country site, so not "used".
    # On a shared platform (paypal.github.io) the name is anyone's choice, so it counts.
    own_name_is_brand_site = owner == icann_domain(report.host)

    for label in labels:
        decoded = decode_label(label)
        if len(alphabets := scripts(decoded)) > 1:
            report.lookalike.append(f"mixes {' and '.join(a.title() for a in alphabets)} letters")
        words = decoded.split("-")
        for word in dict.fromkeys(words):  # each once, in order
            for brand in BRANDS:
                reason = _imitation(word, brand)
                if reason == "same":
                    if not (label == own_label and own_name_is_brand_site and len(words) == 1):
                        report.brand_used.append(brand)
                elif reason:
                    report.lookalike.append(f"looks like {brand}: {reason}")
        # "pay-pal": no word is the brand, but without the hyphens it reads as one
        if len(words) > 1:
            joined = decoded.replace("-", "")
            for brand in BRANDS:
                if (reason := _imitation(joined, brand, shown_as=decoded)) and brand not in words:
                    if reason == "same":
                        reason = f'a hyphen splits the name ("{decoded}")'
                    report.lookalike.append(f"looks like {brand}: {reason}")

    report.lookalike = list(dict.fromkeys(report.lookalike))
    report.brand_used = list(dict.fromkeys(report.brand_used))
    return report


def _imitation(word: str, brand: str, shown_as: str = "") -> str:
    """How a word copies a brand: "same", a reason, or "" if it does not.

    shown_as: how to quote the word in the reason, when it differs from the word that is
    compared (a name with its hyphens removed is compared, but quoted as written).

    ("paypal", "paypal")      -> "same"
    ("paypa1", "paypal")      -> 'look-alike characters in "paypa1" ("1" for "l")'
    ("paypall", "paypal")     -> '1 letter different ("paypall")'
    ("payments", "paypal")    -> ""
    """
    if word == brand:
        return "same"
    shown, target = skeleton(word), skeleton(brand)
    if shown == target:
        swaps = describe_swaps(word)
        quoted = shown_as or word
        return (
            f'look-alike characters in "{quoted}" ({swaps})' if swaps else "look-alike characters"
        )
    distance = edit_distance(shown, target)
    if 0 < distance <= edit_limit(brand):
        letters = "letter" if distance == 1 else "letters"
        return f'{distance} {letters} different ("{shown_as or word}")'
    return ""


def check_sender_domains(email: ParsedEmail) -> list[Finding]:
    """lookalike_sender_domain and brand_in_sender_domain for the From and Reply-To
    domains: at most one of each, naming every address that triggered it."""
    senders = (
        ("From", email.from_all or [email.from_addr]),
        ("Reply-To", email.reply_to_all or [email.reply_to]),
    )
    lookalike: list[str] = []
    brand_used: list[str] = []
    seen: set[str] = set()
    for header, addresses in senders:
        for address in addresses:
            host = get_domain(address)
            if not host or host in seen:
                continue
            seen.add(host)
            report = inspect_domain(host)
            name = f"{header} domain {report.host}"
            if report.decoded != report.host:
                name += f" (shown as {report.decoded})"
            if report.lookalike:
                lookalike.append(f"{name} {'; '.join(report.lookalike)}")
            for brand in report.brand_used:
                real = ", ".join(BRAND_DOMAINS[brand])
                brand_used.append(f"{name} uses the name {brand} but is not {brand}'s ({real})")

    findings = []
    if lookalike:
        findings.append(Finding("lookalike_sender_domain", " | ".join(lookalike)))
    if brand_used:
        findings.append(Finding("brand_in_sender_domain", " | ".join(brand_used)))
    return findings
