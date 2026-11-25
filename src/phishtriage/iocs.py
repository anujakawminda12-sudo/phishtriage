"""IOC extraction: pull indicators of compromise out of a ParsedEmail.

Step 4: URLs from the plain-text body (regex) and from the HTML body (href, src and
action attributes, plus URLs written as visible text), normalised and de-duplicated,
with a record of where each one was found.

Step 5: refang() turns "hxxp://evil[.]com" back into a real URL so it can be found;
defang() makes any IOC safe to show ("hxxp://evil[.]com"); unwrap_url() undoes the
link rewriting done by Microsoft Safe Links and Proofpoint URL Defense.

Step 7: domains, IP addresses and email addresses, and extract_iocs(), which returns
all four kinds for one email.

Step 9: extract_iocs() can take an Allowlist, which marks the IOCs whose lookup should
be skipped (allowlist.py). Nothing is ever removed.

Step 10: group_urls() groups URLs by registered domain, so the report stays readable
for a newsletter with 80 links.

Step 11 (found by the Week 2 gate): URLs in CSS (url(...) and @import, used for fonts,
background images and tracking) and links carried inside other links (click trackers,
redirectors and image proxies) are extracted too.

Safety: BeautifulSoup only parses the HTML text into a tree. It does not run scripts,
load images, follow links or touch the network, so nothing in the email is ever visited.
"""

from __future__ import annotations

import base64
import ipaddress
import re
import string
from dataclasses import dataclass, field
from functools import lru_cache
from urllib.parse import parse_qs, parse_qsl, unquote, urlsplit, urlunsplit

from bs4 import BeautifulSoup

from .allowlist import Allowlist
from .domains import ascii_domain, has_public_suffix, registered_domain
from .headers import parse_auth_results
from .models import IOC, ParsedEmail, SenderIP

# A URL in plain text: http:// or https://, then everything up to a character that
# cannot be part of a URL in running text (space, quotes, angle/square/curly brackets).
# (?i) makes it case-insensitive, so HTTPS://EXAMPLE.COM is found too.
URL_IN_TEXT = re.compile(r"(?i)\bhttps?://[^\s<>\"'`{}|\\^\[\]]+")

# Punctuation that usually ends a sentence rather than a URL: "see https://x.test/a."
TRAILING_PUNCTUATION = ".,;:!?'\""

# HTML attributes that hold a link: <a href>, <img src>, <form action>, <iframe src>, ...
URL_ATTRIBUTES = ("href", "src", "action")

# Text that email apps show in place of an image when images are blocked (often the
# default), so a URL or address in <img alt="..."> is read like visible text.
TEXT_ATTRIBUTES = ("alt",)

WEB_SCHEMES = ("http", "https")

# A URL in CSS, inside a <style> block or a style="..." attribute:
#   url(https://x.test/bg.png)   url('https://x.test/font.woff2')   @import "https://x.test/a.css"
# An email client that shows images fetches these too, so they are network destinations.
# "//x.test/a.css" (no scheme) counts too: see _web_url().
CSS_URL = re.compile(r"""(?i)(?:url\(\s*['"]?|@import\s+['"])\s*((?:https?:)?//[^'"()\s]+)""")

# --- step 11: links inside links -----------------------------------------------------

# A click tracker or redirector carries the real destination in its query string:
#   https://r.imdb.com/gp/r.html?C=...&U=https%3A%2F%2Fwww.imdb.com%2F
# and an image proxy carries it in its path:
#   https://d3n.cloudfront.net/api/imageproxy/https://bucket.s3.amazonaws.com/logo.png
# Phishers use the same trick: https://www.google.com/url?q=https://evil.test/ looks like a
# Google link, but the click ends at evil.test.
EMBEDDED_IN_PATH = re.compile(r"(?i)/(?P<scheme>https?):/{1,2}(?P<rest>[^/?#\s].*)$")

# --- step 5: refang / defang ---------------------------------------------------------

# Common ways analysts "defang" an IOC so it cannot be clicked. Order matters: [://] is
# replaced before [:]. (?i) = case-insensitive.
REFANG_RULES = (
    (re.compile(r"(?i)\bhxxp(s?)\b"), r"http\1"),  # hxxp, hxxps, hXXps
    (re.compile(r"\[\s*://\s*\]"), "://"),  # [://]
    (re.compile(r"\[\s*:\s*\]"), ":"),  # [:]
    (re.compile(r"\[/\]"), "/"),  # [/]
    (re.compile(r"(?i)[\[({]\s*(?:\.|dot)\s*[\])}]"), "."),  # [.] (.) {.} [dot] (dot)
    (re.compile(r"(?i)[\[({]\s*(?:@|at)\s*[\])}]"), "@"),  # [@] (@) [at] (at)
)
HTTP_SCHEME = re.compile(r"(?i)\bhttp(s?)://")
FTP_SCHEME = re.compile(r"(?i)^ftp://")  # week 4, step 9: defang_text() only
MAX_DOMAIN_LENGTH = 253
BARE_DOT = re.compile(r"(?<!\[)\.(?!\])")  # a dot that is not already inside [ ]
BARE_AT = re.compile(r"(?<!\[)@(?!\])")

# --- step 5: link wrappers -----------------------------------------------------------

# Microsoft Defender for Office 365 rewrites every link to
#   https://<region>.safelinks.protection.outlook.com/?url=<real url>&data=...&sdata=...
SAFELINKS_HOST = "safelinks.protection.outlook.com"
# Proofpoint URL Defense v1/v2: https://urldefense.proofpoint.com/v2/url?u=<encoded>&...
PROOFPOINT_V2_HOST = "urldefense.proofpoint.com"
# Proofpoint URL Defense v3:   https://urldefense.com/v3/__<url>__;<base64>!!<ids>$
PROOFPOINT_V3_HOST = "urldefense.com"
PROOFPOINT_V3 = re.compile(r"/v3/__(?P<url>.+?)__;(?P<replacements>[^!]*)!")
# In a v3 URL each "*" stands for one character kept in the base64 part, and "**X" for a
# run of characters, where X gives the run length (A=2, B=3, ..., then a-z, 0-9, - and _).
V3_TOKEN = re.compile(r"\*(\*.)?")
V3_RUN_LENGTHS = {
    char: length
    for length, char in enumerate(
        string.ascii_uppercase + string.ascii_lowercase + string.digits + "-_", start=2
    )
}
MAX_UNWRAP = 5  # one wrapper can sit inside another; stop after this many layers

# --- step 7: IPs and email addresses -------------------------------------------------

# The "from" part of a Received header, up to " by ": the server that handed the email on.
#   from mail.evil.test (unknown [203.0.113.45]) by mx.google.com with ESMTP id ...
RECEIVED_FROM = re.compile(r"(?is)^\s*from\s+(?P<clause>.*?)(?:\s+by\s+|$)")
# Only IPs in brackets count. A free search for "1.2.3.4" also matched Gmail's SMTP ids
# ("...2026.11.19.20.33.59" -> 11.19.20.33) and version numbers ("5.3.0.32").
#   [203.0.113.45], [IPv6:2001:db8::25]   square brackets: most mail servers
#   (203.0.113.77)                        round brackets: Microsoft (week 4, step 3)
# Only brackets holding nothing but an IP count, so "(version=TLS1_2)" or
# "r(msys-ecelerity:tags/5.3.0.32)" never match.
HOP_IP = re.compile(r"(?i)\[(?:IPv6:)?(?P<square>[0-9a-f:.]+)\]|\((?P<round>[0-9a-f:.]+)\)")
# "helo=[198.51.100.1]" (Exim) is the name the sender gave itself: never the real IP
HELO_WORD = re.compile(r"(?i)\bhelo=\S+")
# RFC 5737 / RFC 3849 documentation ranges. Like the .test domains, they never appear in
# real email, so treating them as public costs nothing and lets the test fixtures use
# them instead of real addresses.
DOCUMENTATION_NETWORKS = tuple(
    ipaddress.ip_network(net)
    for net in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
)
# A simple email-address pattern. The domain is checked afterwards with
# has_public_suffix(), which rejects look-alikes such as "image001.png@01DA1B2C.3D4E5F60".
EMAIL_ADDRESS = re.compile(r"(?i)[a-z0-9._%+-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)+")


def urls_from_text(text: str) -> list[str]:
    """Every http(s) URL in a block of text, in the order found (duplicates kept).

    The text is refanged first, so "hxxps://evil[.]test/a" is found as https://evil.test/a.
    """
    return [_trim(match.group()) for match in URL_IN_TEXT.finditer(refang(text))]


def urls_from_html(html: str) -> list[tuple[str, str]]:
    """Every http(s) URL in an HTML body, as (url, source) pairs in document order.

    The source says where it was found, e.g. "html:a[href]", "html:img[src]",
    "html:form[action]", "html:text" for a URL written in the visible text, and
    "html:style" or "html:td[style]" for a URL in CSS.
    Other schemes (mailto:, tel:, cid:, data:, javascript:) and relative links are
    skipped here: mailto: addresses are collected as email IOCs in step 7.
    Other attributes are not links either: <img prefix="https://x.com/"> is never fetched.
    A link written without a scheme ("//cdn.test/a.css") is stored as https://cdn.test/a.css,
    and a URL in an image's alt text is found too, with the source "html:img[alt]".
    """
    if not html.strip():
        return []
    soup = BeautifulSoup(html, "html.parser")  # Python's own parser: no lxml needed

    found: list[tuple[str, str]] = []
    for tag in soup.find_all(True):  # True = every tag
        for attribute in URL_ATTRIBUTES:
            value = tag.get(attribute)
            url = _web_url(value) if isinstance(value, str) else None
            if url:
                found.append((url, f"html:{tag.name}[{attribute}]"))
        style = tag.get("style")
        if isinstance(style, str):
            found.extend((url, f"html:{tag.name}[style]") for url in urls_from_css(style))
        if tag.name == "style":
            found.extend((url, "html:style") for url in urls_from_css(tag.get_text()))

    visible_text = soup.get_text(" ")  # the text of <style> and <script> is not included
    found.extend((url, "html:text") for url in urls_from_text(visible_text))
    for tag, attribute, text in _attribute_texts(soup):
        found.extend((url, f"html:{tag}[{attribute}]") for url in urls_from_text(text))
    return found


def urls_from_css(css: str) -> list[str]:
    """Every http(s) URL in a piece of CSS: url(...) values and @import rules."""
    urls = (_web_url(match.group(1)) for match in CSS_URL.finditer(css))
    return [url for url in urls if url]


def embedded_urls(url: str) -> list[str]:
    """The http(s) URLs carried inside another URL, in its path or its query string.

        "https://www.google.com/url?q=https://evil.test/a"  -> ["https://evil.test/a"]
        "https://r.test/c?u=https%3A%2F%2Fshop.test%2F"      -> ["https://shop.test/"]
        "https://proxy.test/img/https://cdn.test/logo.png"  -> ["https://cdn.test/logo.png"]

    Query values are percent-decoded once by parse_qsl, and once more if they still
    start with "https%3A". Nothing is followed or fetched: the URL is only read as text.
    """
    try:
        parts = urlsplit(url)
    except ValueError:
        return []
    found: list[str] = []
    for path in (parts.path, unquote(parts.path)):
        match = EMBEDDED_IN_PATH.search(path)
        if match:
            found.append(f"{match['scheme'].lower()}://{match['rest']}")
            break
    for _, value in parse_qsl(parts.query):
        value = value.strip()
        if not _is_web_url(value):
            value = unquote(value)  # encoded twice: https%3A%2F%2F... after the first decode
        if _is_web_url(value) and _host(value):
            found.append(value)
    return found


def normalise_url(url: str) -> str:
    """Lower-case the scheme and host, keep everything else exactly as it was.

        "HTTP://Example.COM/Login?ID=Abc" -> "http://example.com/Login?ID=Abc"

    Paths and queries can be case-sensitive on a web server, so they are left alone.
    The #fragment is kept too: phishing kits often put the victim's address there.
    """
    url = url.strip()
    try:
        parts = urlsplit(url)
    except ValueError:  # e.g. a broken IPv6 address such as http://[::1
        return url
    return urlunsplit(
        (parts.scheme.lower(), parts.netloc.lower(), parts.path, parts.query, parts.fragment)
    )


def extract_urls(email: ParsedEmail) -> list[IOC]:
    """All URLs in one email's bodies: unwrapped, normalised and de-duplicated.

    A wrapped link is stored as the real destination, and its source says what wrapped
    it, e.g. "html:a[href] via Microsoft Safe Links". A link carried inside another link
    is stored as well as the outer one, e.g. "html:a[href] (inside a link to r.imdb.com)".
    """
    pairs = [(url, "text") for url in urls_from_text(email.text_body)]
    pairs.extend(urls_from_html(email.html_body))

    found: list[tuple[str, str]] = []
    for url, source in pairs:
        found.extend(_resolve_url(url, source, depth=0))
    return merge_iocs("url", found)


def _resolve_url(url: str, source: str, depth: int) -> list[tuple[str, str]]:
    """The unwrapped URL, plus (recursively) the URLs carried inside it."""
    real_url, wrappers = unwrap_url(url)
    if wrappers:
        source = f"{source} via {' + '.join(wrappers)}"
    real_url = normalise_url(real_url)
    found = [(real_url, source)]
    if depth < MAX_UNWRAP:  # a link inside a link inside a link ... stops somewhere
        inner_source = f"{source} (inside a link to {_host(real_url) or 'a broken URL'})"
        for inner in embedded_urls(real_url):
            found.extend(_resolve_url(inner, inner_source, depth + 1))
    return found


def extract_iocs(email: ParsedEmail, allowlist: Allowlist | None = None) -> list[IOC]:
    """Every IOC in one email: URLs, then domains, then IPs, then email addresses.

    Each kind is de-duplicated on its own and keeps its first-seen order. A forwarded
    email is not included: call this again on each email in email.forwarded.
    With an allowlist, IOCs it covers get allowlisted=True. They are never removed.
    """
    urls = extract_urls(email)
    addresses = extract_email_addresses(email)
    iocs = urls + extract_domains(email, urls, addresses) + extract_ips(email, urls) + addresses
    return allowlist.mark(iocs) if allowlist else iocs


def extract_email_addresses(email: ParsedEmail) -> list[IOC]:
    """Sender addresses from the headers, plus any address in the bodies or a mailto: link.

    The recipient's own address is skipped when it appears in a body ("This email was
    sent to you@..."): it is not an indicator. It is kept when it is in a sender header,
    because "From: you, To: you" is a common scam.

    Week 3, step 2: "recipient" now means any address in To, Cc, Delivered-To or
    X-Original-To. Week 2 only used To, so an email sent to you in Bcc ("To:
    undisclosed-recipients:;"), as phishing often is, listed your own address as an IOC.
    Every From address is listed too, not only the first.
    Known limit: an address the sender also puts in To or Cc counts as a recipient, so it is
    left out of the body list (it is still listed if it is in From, Reply-To or Return-Path).
    """
    # The sender headers. To/Cc are left out: they are the recipients.
    senders = (
        ("From", email.from_all or [email.from_addr]),  # every From address
        ("Reply-To", email.reply_to_all or [email.reply_to]),  # every Reply-To address
        ("Return-Path", [email.return_path]),
    )
    pairs: list[tuple[str, str]] = []
    for header, addresses in senders:
        for address in addresses:
            if _is_email_address(address):
                pairs.append((address.lower(), f"header:{header}"))

    recipients = set(email.recipients) | set(email.to)
    in_bodies = [(address, "text") for address in emails_from_text(email.text_body)]
    in_bodies.extend(emails_from_html(email.html_body))
    pairs.extend(pair for pair in in_bodies if pair[0] not in recipients)
    return merge_iocs("email", pairs)


def emails_from_text(text: str) -> list[str]:
    """Email addresses in a block of text, refanged first ("x[@]evil[.]test" counts)."""
    return [
        match.group().lower()
        for match in EMAIL_ADDRESS.finditer(refang(text))
        if _is_email_address(match.group())
    ]


def emails_from_html(html: str) -> list[tuple[str, str]]:
    """(address, source) pairs from mailto: links, the visible text and images' alt text."""
    if not html.strip():
        return []
    soup = BeautifulSoup(html, "html.parser")
    found: list[tuple[str, str]] = []
    for anchor in soup.find_all("a", href=True):
        scheme, _, rest = str(anchor["href"]).strip().partition(":")
        if scheme.lower() == "mailto":
            # mailto:a@x.test,b@x.test?subject=Hi -> two addresses, no subject
            for address in unquote(rest.split("?")[0]).split(","):
                if _is_email_address(address.strip()):
                    found.append((address.strip().lower(), "html:a[href]"))
    found.extend((address, "html:text") for address in emails_from_text(soup.get_text(" ")))
    for tag, attribute, text in _attribute_texts(soup):
        found.extend((address, f"html:{tag}[{attribute}]") for address in emails_from_text(text))
    return found


def _attribute_texts(soup: BeautifulSoup) -> list[tuple[str, str, str]]:
    """(tag name, attribute, text) for every TEXT_ATTRIBUTES value, e.g. an image's alt."""
    return [
        (tag.name, attribute, str(tag[attribute]))
        for tag in soup.find_all(True)
        for attribute in TEXT_ATTRIBUTES
        if tag.get(attribute)
    ]


def extract_domains(email: ParsedEmail, urls: list[IOC], addresses: list[IOC]) -> list[IOC]:
    """Domains of the URLs and email addresses, plus the domain in the Message-ID.

    Kept as full host names (www.paypal.com, not paypal.com): threat-intel services
    rate hosts, and the registered domain can always be worked out later.
    IP addresses and names without a public suffix (localhost, intranet) are skipped.
    """
    pairs: list[tuple[str, str]] = []
    for url in urls:
        host = _host(url.value)
        if host and not _is_ip(host):
            pairs.append((ascii_domain(host), "url"))
    for address in addresses:
        pairs.append((ascii_domain(address.value.rpartition("@")[2]), "email address"))
    if "@" in email.message_id:
        # <a8f3e2@mailer-7731.test>: often names the real sending system
        pairs.append(
            (ascii_domain(email.message_id.rpartition("@")[2].strip("<> ")), "header:Message-ID")
        )
    return merge_iocs(
        "domain", [(domain, source) for domain, source in pairs if has_public_suffix(domain)]
    )


def extract_ips(email: ParsedEmail, urls: list[IOC]) -> list[IOC]:
    """Public IPs: the sender IP, the Received chain from the sender's hop down, and URLs
    such as http://203.0.113.7/login.

    Week 4, step 3: the sender IP comes first, with the source "sender IP", so the report
    and the scoring can tell it apart from the other hops.
    """
    sender = find_sender_ip(email)
    pairs = []
    if sender and is_reportable_ip(sender.address):
        pairs.append((sender.address, "sender IP"))
    pairs += ips_from_received(email.received, sender.address if sender else None)
    for url in urls:
        host = _host(url.value)
        if host and _is_ip(host) and is_reportable_ip(host):
            pairs.append((str(ipaddress.ip_address(host)), "url"))
    return merge_iocs("ip", pairs)


def ips_from_received(received: list[str], sender_ip: str | None = None) -> list[tuple[str, str]]:
    """(ip, source) pairs from the IPs in each Received header's "from" part.

    Hop 1 is the top header, written by the last server (normally your own). The hop that
    your own server received the email from is the most useful sender IP: anything below
    it could have been written by the sender.

    Week 4, step 3: with sender_ip, the hops ABOVE the first hop that names it are left
    out. Those are your own mail provider's servers passing the email along inside, e.g.
    Outlook's "from SN6PR04MB... (2603:10b6:...) by MW4PR04MB...": not indicators, and not
    worth an AbuseIPDB lookup. If no hop names the sender IP, every hop is kept.
    """
    hops = [_hop_ips(header) for header in received]
    start = 0
    if sender_ip:
        start = next((index for index, ips in enumerate(hops) if sender_ip in ips), 0)
    return [
        (ip, f"header:Received (hop {index + 1})")
        for index, ips in enumerate(hops)
        if index >= start
        for ip in ips
        if is_reportable_ip(ip)
    ]


def _hop_ips(header: str) -> list[str]:
    """Every IP in a Received header's "from" part, in order, written the standard way."""
    match = RECEIVED_FROM.match(header)
    if match is None:
        return []  # e.g. "by 2002:a05:6504:..." with no "from" part
    ips = []
    for found in HOP_IP.finditer(match["clause"]):
        try:
            ips.append(str(ipaddress.ip_address(found["square"] or found["round"])))
        except ValueError:
            continue  # "(1.2.3)" looks like one but is not
    return ips


def find_sender_ip(email: ParsedEmail) -> SenderIP | None:
    """The IP address the email came from, or None if no header says (week 4, step 3).

    1. Your mail server's Authentication-Results header, when it names the IP (Microsoft:
       "sender IP is ..."; Google: "... designates ... as permitted sender"). Certain:
       your own server wrote it.
    2. Otherwise the Received chain: the first hop from the top whose "from" part holds a
       public IP. Less certain: a hop your server did not write could be forged, which is
       why the search stops at the first one.

    In a hop such as "from [198.51.100.1] (unknown [203.0.113.45]) by ...", the first word
    after "from" is the name the sender gave itself (HELO), which it chooses freely. It is
    skipped, as is an Exim "helo=..." word, so the IP the server saw is the one used.
    """
    auth = parse_auth_results(email.auth_results_headers)
    if auth.sender_ip:
        return SenderIP(auth.sender_ip, "Authentication-Results")
    for hop, header in enumerate(email.received, start=1):
        if ip := _connecting_ip(header):
            return SenderIP(ip, f"Received hop {hop}")
    return None


def _connecting_ip(header: str) -> str:
    """The public IP a server saw connecting, from one Received header, or ""."""
    match = RECEIVED_FROM.match(header)
    if match is None:
        return ""
    words = HELO_WORD.sub(" ", match["clause"]).split(maxsplit=1)
    after_helo = words[1] if len(words) > 1 else " ".join(words)  # "from [ip] by" alone
    for found in HOP_IP.finditer(after_helo):
        value = found["square"] or found["round"]
        if is_reportable_ip(value):
            return str(ipaddress.ip_address(value))
    return ""


def is_reportable_ip(value: str) -> bool:
    """True for a public IP worth looking up, or a documentation-range IP (see above).

    False for private (10.x, 192.168.x), loopback, link-local and other reserved ranges,
    and for anything that is not an IP address at all.
    """
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return address.is_global or any(address in network for network in DOCUMENTATION_NETWORKS)


@dataclass
class UrlGroup:
    """All the URLs on one registered domain, for a compact report."""

    domain: str  # e.g. "linkedin.com", or an IP address for http://203.0.113.7/...
    urls: list[IOC] = field(default_factory=list)

    @property
    def seen(self) -> int:
        """How many times these URLs appear in the email, in total."""
        return sum(url.count for url in self.urls)

    @property
    def sources(self) -> list[str]:
        """Every place any of these URLs was found, without repeats, in first-seen order."""
        return list(dict.fromkeys(source for url in self.urls for source in url.sources))

    @property
    def skipped(self) -> int:
        """How many of these URLs are allowlisted."""
        return sum(1 for url in self.urls if url.allowlisted)


def group_urls(urls: list[IOC]) -> list[UrlGroup]:
    """Group URL IOCs by registered domain, keeping the order domains were first seen.

    (A @property, used above, is a method you read like a field: group.seen, not
    group.seen(). Java has no direct equivalent; it is like a getter without "get".)
    """
    groups: dict[str, UrlGroup] = {}
    for url in urls:
        domain = registered_domain(_host(url.value)) or url.value  # a broken URL: itself
        groups.setdefault(domain, UrlGroup(domain)).urls.append(url)
    return list(groups.values())


def merge_iocs(kind: str, pairs: list[tuple[str, str]]) -> list[IOC]:
    """Turn (value, source) pairs into one IOC per value, remembering every source.

    A dict keeps insertion order, like a LinkedHashMap in Java, so the first place a
    value was seen decides its position in the list.
    """
    by_value: dict[str, IOC] = {}
    for value, source in pairs:
        ioc = by_value.setdefault(value, IOC(kind=kind, value=value))
        ioc.count += 1
        if source not in ioc.sources:
            ioc.sources.append(source)
    return list(by_value.values())


def refang(text: str) -> str:
    """Undo common defanging so the IOC can be processed.

    "hxxps://evil[.]test/login"  -> "https://evil.test/login"
    "billing[@]evil(dot)test"    -> "billing@evil.test"
    "203[.]0[.]113[.]7"          -> "203.0.113.7"
    """
    for pattern, replacement in REFANG_RULES:
        text = pattern.sub(replacement, text)
    return text


def defang(value: str) -> str:
    """Make an IOC safe to show, paste or email: no app will turn it into a live link.

        "https://evil.test/login.php" -> "hxxps://evil[.]test/login[.]php"
        "evil.test"                    -> "evil[.]test"
        "203.0.113.7"                  -> "203[.]0[.]113[.]7"
        "billing@evil.test"            -> "billing[@]evil[.]test"

    Every "http(s)://" is changed, including one hidden in a query string, and every dot,
    including in the path (".zip" is a real top-level domain). Running it twice changes
    nothing more, and refang(defang(x)) gives x back for a lower-case URL.
    """
    value = HTTP_SCHEME.sub(r"hxxp\1://", value)
    value = BARE_DOT.sub("[.]", value)
    return BARE_AT.sub("[@]", value)


# Week 4, step 9: anything in free text that an app could turn into a live link. An address
# or a domain can only start where a word starts (the (?<!...) look-behinds), so a long line
# is read in one pass: without them, a 100,000-character subject would be re-read from every
# position. A link needs no look-behind: it starts with a fixed scheme, so it is cheap to
# look for anywhere, and "\x1bhttps://..." (an ESC written out by visible()) is still found.
LIVE_IN_TEXT = re.compile(
    r"(?P<url>(?i:https?|ftp)://[^\s<>\"'`{}|\\^\[\]]*)"
    r"|(?P<email>(?<![\w.%+-])[\w.%+-]+@[\w-]+(?:\.[\w-]+)+)"
    r"|(?P<host>(?<![\w.@-])(?:[\w-]+\.)+[\w-]+)"
)


def defang_text(text: str) -> str:
    """Defang only the links, addresses, domains and IPs inside a line of free text.

        'Reply-To support@evil.test differs'  -> 'Reply-To support[@]evil[.]test differs'
        'Log in at paypal.com today.'         -> 'Log in at paypal[.]com today.'
        'see https://evil.test/a'             -> 'see hxxps://evil[.]test/a'
        'http://[2001:db8::1]/x'              -> 'hxxp://[2001:db8::1]/x'
        'from 203.0.113.9, e.g. invoice.pdf'  -> 'from 203[.]0[.]113[.]9, e.g. invoice.pdf'

    defang() changes every dot, which would turn a sentence into "e[.]g[.]". Here a word
    with dots is only defanged when it is, or starts with, a real domain (one ending in a
    public suffix, as has_public_suffix() decides) or an IPv4 address: see _live_host().
    So "invoice.pdf" stays as it is, but "readme.md" becomes "readme[.]md" (.md is
    Moldova's top-level domain, and a chat app would make it a link).

    \\w matches letters of every script, so a look-alike Cyrillic domain is caught too.
    Text that is already defanged has nothing left to change, so running it twice gives
    the same result.
    """
    return LIVE_IN_TEXT.sub(_defang_match, text)


def _defang_match(match: re.Match[str]) -> str:
    token = match[0]
    if match["host"] is not None and not _live_host(token):
        return token
    return FTP_SCHEME.sub("fxp://", defang(token))


@lru_cache(maxsize=4096)
def _live_host(token: str) -> bool:
    """True when the word, or its start, is a domain or an IPv4 address.

        "evil.test", "203.0.113.9"              -> True
        "paypal.com.html", "Statement.zip.exe"  -> True: "paypal.com" and "Statement.zip"
                                                   are domains (.zip is a real TLD), and
                                                   some apps link that part of the word
        "invoice.pdf", "invoice.pdf.exe", "1.5" -> False

    Only starts up to 253 characters are tried (the longest a domain name can be), so
    one enormous word costs at most about 127 checks. lru_cache remembers the answers
    (Java: a memoising Map in front of the method): one report repeats the same names.
    """
    labels = token.split(".")
    for end in range(2, len(labels) + 1):
        candidate = ".".join(labels[:end])
        if len(candidate) > MAX_DOMAIN_LENGTH:
            break
        if _is_ipv4(candidate) or has_public_suffix(candidate):
            return True
    return False


def _is_ipv4(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value)
    except ValueError:
        return False
    return True


def unwrap_url(url: str) -> tuple[str, list[str]]:
    """Undo link rewriting by email security products.

    Returns the real URL and the names of the wrappers that were removed, outermost
    first. One wrapper can sit inside another (Safe Links around Proofpoint), so this
    repeats, up to MAX_UNWRAP layers. A URL that is not wrapped comes back unchanged.

    Only the real wrapper hosts are trusted: a look-alike such as
    safelinks.protection.outlook.com.evil.test is NOT unwrapped.
    """
    wrappers: list[str] = []
    for _ in range(MAX_UNWRAP):
        inner, wrapper = _unwrap_once(url)
        if wrapper is None:
            break
        url = inner
        wrappers.append(wrapper)
    return url, wrappers


def _unwrap_once(url: str) -> tuple[str, str | None]:
    """Remove one wrapper layer, or return (url, None) if it is not wrapped."""
    try:
        parts = urlsplit(url.strip())
    except ValueError:
        return url, None
    host = (parts.hostname or "").lower()
    query = parse_qs(parts.query)  # also percent-decodes the values

    if host == SAFELINKS_HOST or host.endswith("." + SAFELINKS_HOST):
        target = query.get("url", [""])[0]
        if target:
            return target, "Microsoft Safe Links"

    if host == PROOFPOINT_V2_HOST:
        target = query.get("u", [""])[0]
        if target and parts.path.startswith("/v2/"):
            # v2 writes "%" as "-" and "/" as "_" so the URL survives as one parameter
            target = unquote(target.replace("-", "%").replace("_", "/"))
        if target:
            return target, "Proofpoint URL Defense"

    if host == PROOFPOINT_V3_HOST:
        target = _proofpoint_v3(url)
        if target:
            return target, "Proofpoint URL Defense"

    return url, None


def _proofpoint_v3(url: str) -> str | None:
    """Decode https://urldefense.com/v3/__<url>__;<base64>!!...$ , or None if it fails.

    Proofpoint replaces some characters of the real URL with "*" and keeps the originals,
    base64-encoded, after "__;". Each "*" takes the next character back; "**X" takes a
    run of characters whose length X encodes.
    """
    match = PROOFPOINT_V3.search(url)
    if match is None:
        return None
    encoded = unquote(match["url"])
    kept = match["replacements"]
    try:
        originals = base64.urlsafe_b64decode(kept + "=" * (-len(kept) % 4)).decode("utf-8")
    except ValueError:  # bad base64 or bad UTF-8: leave the link wrapped
        return None

    pieces: list[str] = []
    position = used = 0
    for token in V3_TOKEN.finditer(encoded):
        length = 1 if token.group(1) is None else V3_RUN_LENGTHS.get(token.group(1)[1], 0)
        if length == 0 or used + length > len(originals):
            return None  # the URL and its kept characters do not match: leave it wrapped
        pieces.append(encoded[position : token.start()])
        pieces.append(originals[used : used + length])
        used += length
        position = token.end()
    pieces.append(encoded[position:])
    return "".join(pieces)


def _is_email_address(value: str) -> bool:
    """True if value looks like local@domain and the domain has a real public suffix."""
    local, at, domain = value.rpartition("@")
    return bool(at and local) and has_public_suffix(domain)


def _host(url: str) -> str:
    """The host of a URL, lower-case, or "" if there is none or the URL is broken."""
    try:
        return urlsplit(url).hostname or ""
    except ValueError:
        return ""


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def _web_url(value: str) -> str | None:
    """An attribute value as an absolute http(s) URL, or None if it is not a web link.

        "https://x.test/a"  -> "https://x.test/a"
        "//cdn.test/a.css"  -> "https://cdn.test/a.css"
        "/relative", "mailto:a@x.test", "cid:logo", "#top"  -> None

    "//host/path" is protocol-relative: "use the scheme of the page". An email has no page
    scheme, and mail apps load it over https. The gate found Google writing its font link
    this way, and a phisher could do the same to slip past a check for "http".
    """
    value = value.strip()
    if value.startswith("//") and value[2:3] not in ("", "/", "\\"):
        value = "https:" + value
    return value if _is_web_url(value) else None


def _is_web_url(value: str) -> bool:
    """True for an absolute http(s) URL; False for mailto:, cid:, javascript:, #top, /path."""
    scheme, separator, _ = value.strip().partition(":")
    return bool(separator) and scheme.lower() in WEB_SCHEMES


def _trim(url: str) -> str:
    """Drop sentence punctuation stuck to the end of a URL found in text.

    A closing bracket is only dropped when it has no matching opening bracket, so
    "(see https://x.test/a)" loses the ")" but https://en.wikipedia.org/wiki/Foo_(bar)
    keeps it.
    """
    while url:
        if url[-1] in TRAILING_PUNCTUATION:
            url = url[:-1]
        elif url[-1] == ")" and url.count(")") > url.count("("):
            url = url[:-1]
        else:
            break
    return url
