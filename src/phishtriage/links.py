"""Link checks on the HTML body (week 2, step 6).

check_link_text_mismatch() flags a link whose visible text shows one domain while the
link really goes to another, the classic phishing trick:

    <a href="http://paypa1-secure.test/login">https://www.paypal.com/signin</a>

Week 4, step 5: check_hidden_destinations() flags links whose real destination is
hidden from the reader:

    url_shortener   https://bit.ly/3xYz: the short code hides where it goes
    open_redirect   https://www.google.com/url?q=https://evil.test/login: a link on a
                    well-known site that forwards to another organisation's site

It returns Finding objects only. How much each finding counts is decided in week 4.
"""

from __future__ import annotations

import re
from typing import NamedTuple
from urllib.parse import urlsplit

from bs4 import BeautifulSoup

from .domains import ascii_domain, has_public_suffix, registered_domain
from .headers import org_domain
from .iocs import WEB_SCHEMES, defang, embedded_urls, extract_urls, refang, unwrap_url
from .models import Finding, ParsedEmail

# Visible text that is a URL or a bare domain, and nothing else:
#   "https://www.paypal.com/signin", "www.example.com/offers", "PayPal.com"
# A label is letters/digits (any alphabet, for international domains) with inner "-".
_LABEL = r"[^\W_](?:[\w-]*[^\W_])?"
DOMAIN_TEXT = re.compile(
    rf"^(?:https?://)?(?P<host>{_LABEL}(?:\.{_LABEL})+)\.?(?::\d+)?(?:[/?#]\S*)?$"
)

MAX_EXAMPLES = 2  # how many examples go into a finding's detail

# Week 4, step 5. Registered domains of public URL shorteners: the short code hides the
# destination, and PhishTriage never follows a link to find out where it goes.
SHORTENER_DOMAINS = frozenset(
    {
        "bit.ly", "bit.do", "buff.ly", "cutt.ly", "goo.gl", "is.gd", "lnkd.in", "ow.ly",
        "qrco.de", "rb.gy", "rebrand.ly", "s.id", "shorturl.at", "t.co", "t.ly",
        "tiny.cc", "tinyurl.com", "v.gd",
    }
)  # fmt: skip

# Where a URL was found that a reader can click or submit. A URL in <img src>, in CSS or
# in alt text is never clicked, so an image proxy that carries a URL is not a redirect.
CLICKABLE_SOURCES = ("text", "html:text", "html:a[href]", "html:area[href]", "html:form[action]")


class Link(NamedTuple):
    """One <a href> link: what the reader sees, and where it really goes."""

    text: str
    href: str


def links_from_html(html: str) -> list[Link]:
    """Every <a> with an http(s) href, with its visible text (spaces tidied)."""
    if not html.strip():
        return []
    links = []
    for anchor in BeautifulSoup(html, "html.parser").find_all("a", href=True):
        href = str(anchor["href"]).strip()
        if href.partition(":")[0].lower() in WEB_SCHEMES:
            text = " ".join(anchor.get_text(" ").split())
            links.append(Link(text=text, href=href))
    return links


def displayed_domain(text: str) -> str | None:
    """The registered domain a piece of link text shows, or None if it shows none.

    "https://www.paypal.com/signin"  -> "paypal.com"
    "hxxps://evil[.]test"             -> "evil.test"   (refanged first)
    "Click here", "invoice.pdf"      -> None          (no real domain in it)
    "Visit paypal.com today"         -> None          (the text must BE the domain)
    """
    candidate = refang(text).strip().rstrip(".,;:!?")
    match = DOMAIN_TEXT.match(candidate)
    if match is None or not has_public_suffix(match["host"]):
        return None
    return ascii_domain(registered_domain(match["host"]))


def check_link_text_mismatch(email: ParsedEmail) -> list[Finding]:
    """Flag links whose visible text shows one domain but which go to another.

    Two rules, so week 4 can weigh them differently:
      link_text_mismatch         the link goes to a third domain: the classic phishing trick
      link_text_mismatch_sender  the link goes to the sender's own domain. Newsletters do
                                 this for click tracking (Coursera's link.coursera.org),
                                 but an attacker who sends from their own domain looks
                                 the same, so it is still reported.

    The href is unwrapped first, so Safe Links and Proofpoint do not cause mismatches.
    """
    sender = ascii_domain(org_domain(email.from_addr))
    third_party: list[str] = []
    own_domain: list[str] = []

    for link in links_from_html(email.html_body):
        shown = displayed_domain(link.text)
        if shown is None:
            continue
        real_url, _ = unwrap_url(link.href)
        try:
            target = ascii_domain(registered_domain(urlsplit(real_url).hostname or ""))
        except ValueError:  # a broken href such as http://[::1
            continue
        if not target or target == shown:
            continue
        example = f'"{defang(link.text)}" goes to {defang(target)}'
        (own_domain if target == sender else third_party).append(example)

    findings = []
    if third_party:
        findings.append(Finding(rule="link_text_mismatch", detail=_summary(third_party)))
    if own_domain:
        detail = _summary(own_domain) + " (the sender's own domain, e.g. click tracking)"
        findings.append(Finding(rule="link_text_mismatch_sender", detail=detail))
    return findings


def check_hidden_destinations(email: ParsedEmail) -> list[Finding]:
    """Flag links that hide where they really go (week 4, step 5).

    url_shortener   a clickable link on a URL shortener (bit.ly, tinyurl.com, ...)
    open_redirect   a clickable link that carries a full URL to a different organisation
                    in its query or path, e.g. www.google.com/url?q=https://evil.test/

    Not an open redirect:
      - Safe Links and Proofpoint: extract_urls() has already unwrapped them, because
        they are your own security product, not part of the email;
      - a site forwarding to itself (shop.test/go?to=https://www.shop.test/sale);
      - a link forwarding to the sender's own organisation: a newsletter's click
        tracking that ends at the sender's site.
    Known limit: other security products' wrappers (Barracuda, Cisco, ...) are not
    unwrapped, so their links count as open redirects until they are added to unwrap_url.

    Both are weak on their own: genuine mail uses shorteners and trackers too. The proposal
    gives them 5 points together. Nothing is followed or fetched: the URLs are only read.
    """
    sender = ascii_domain(org_domain(email.from_addr))
    shortened: list[str] = []  # each link, defanged
    redirect_links: list[str] = []  # each link that forwards elsewhere
    redirects: list[str] = []  # "www[.]google[.]com forwards to evil[.]test", per link
    for url in extract_urls(email):
        if not _clickable(url.sources):
            continue
        host = _hostname(url.value)
        org = ascii_domain(registered_domain(host))  # for an IP address: the IP itself
        if org in SHORTENER_DOMAINS:
            shortened.append(defang(_shorten(url.value)))
        for inner in embedded_urls(url.value):
            target = ascii_domain(registered_domain(_hostname(inner)))
            if target and org and target not in (org, sender):
                redirect_links.append(url.value)
                redirects.append(f"{defang(host)} forwards to {defang(target)}")

    findings = []
    if shortened:
        detail = _count(shortened, "link uses", "links use") + " a URL shortener, e.g. "
        detail += "; ".join(list(dict.fromkeys(shortened))[:MAX_EXAMPLES])
        detail += " (PhishTriage never follows links, so where it leads is unknown)"
        findings.append(Finding(rule="url_shortener", detail=detail))
    if redirects:
        detail = _count(redirect_links, "link on one site forwards", "links on one site forward")
        detail += " to another, e.g. " + "; ".join(list(dict.fromkeys(redirects))[:MAX_EXAMPLES])
        findings.append(Finding(rule="open_redirect", detail=detail))
    return findings


def _clickable(sources: list[str]) -> bool:
    """True if any source is a place a reader clicks: "html:a[href] via Safe Links" is."""
    return any(
        source == start or source.startswith(start + " ")
        for source in sources
        for start in CLICKABLE_SOURCES
    )


def _hostname(url: str) -> str:
    """The lower-case host of a URL, or "" if it has none or is broken."""
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:  # e.g. http://[::1
        return ""


def _shorten(url: str, limit: int = 60) -> str:
    """Long URLs are cut for the report, with "…" (one character) to show it.

    Not "...": the URL is defanged after this, and defang() would turn three dots into
    "[.][.][.]", which a test caught.
    """
    return url if len(url) <= limit else url[: limit - 1] + "…"


def _count(items: list[str], one: str, many: str) -> str:
    """'1 link uses' / '3 links use': counts each different link once."""
    count = len(dict.fromkeys(items))
    return f"{count} {one if count == 1 else many}"


def _summary(examples: list[str]) -> str:
    """'3 links show one domain but go to another, e.g. ...; ...'"""
    unique = list(dict.fromkeys(examples))  # drop repeats, keep order
    count = len(examples)
    what = "link shows one domain but goes" if count == 1 else "links show one domain but go"
    return f"{count} {what} to another, e.g. " + "; ".join(unique[:MAX_EXAMPLES])
