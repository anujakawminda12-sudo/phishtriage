"""Domain helpers shared by the header checks and (later this week) the IOC extractor.

A "registered domain" is the part of a hostname that someone actually registered:
one label plus a public suffix such as .com, .co.uk or .ac.lk.

    mail.paypal.com     -> paypal.com
    login.evil.co.uk    -> evil.co.uk       (".co.uk" is one suffix, not two)
    www.cse.mrt.ac.lk   -> mrt.ac.lk        (".ac.lk" is one suffix)
    evil.github.io      -> evil.github.io   (every github.io site has a different owner)

The list of public suffixes is the Public Suffix List (publicsuffix.org), the same list
browsers use to decide which sites may share cookies.

Done for you:   make_extractor
Your week 2:    registered_domain, has_public_suffix (step 6), ascii_domain (step 7)
Week 3:         step 6: is_reserved, icann_domain (used by the lookup plan)
"""

from __future__ import annotations

import tldextract

# Reserved for testing by RFC 2606. They are not in the Public Suffix List, so without
# this tldextract would return "" for fixture domains such as paypa1-secure.test.
RESERVED_TLDS = ("test", "example", "invalid", "localhost")
# RFC 2606 also reserves these three names for documentation. They resolve, but nobody
# can own them, so looking them up would only waste quota (week 3, step 6).
RESERVED_DOMAINS = ("example.com", "example.net", "example.org")


def make_extractor() -> tldextract.TLDExtract:
    """A tldextract instance that never touches the network or writes to disk.

    By default tldextract downloads the latest Public Suffix List the first time it runs
    and caches it in ~/.cache. PhishTriage must work offline and must never visit anything,
    so we use the copy of the list that ships inside the tldextract package instead.
    """
    return tldextract.TLDExtract(
        suffix_list_urls=(),  # no download: use the snapshot bundled with tldextract
        cache_dir=None,  # no cache files written to disk
        include_psl_private_domains=True,  # github.io, s3.amazonaws.com, web.app, ...
        extra_suffixes=RESERVED_TLDS,
    )


# Built once, the first time this module is imported. Java equivalent:
#     private static final TLDExtract EXTRACT = makeExtractor();
_EXTRACT = make_extractor()


def registered_domain(host: str) -> str:
    """Return the registered domain of a hostname, in lower case.

        "Mail.PayPal.com"         -> "paypal.com"
        "maile-de.linkedin.com."  -> "linkedin.com"   (trailing dot, as in Received headers)
        "[192.0.2.10]"            -> "192.0.2.10"     (an IP has no registered domain)
        "intranet"                -> "intranet"       (no public suffix: return it as it is)
        ""                        -> ""

    How it works:
      1. Clean the input: spaces first, then the [ ] around an IP literal, then a
         trailing dot, then lower case (tldextract keeps whatever capitals it is given).
      2. Nothing left? Return "" straight away.
      3. Ask tldextract for the registered domain.
      4. An IP or a name with no public suffix has no registered domain (tldextract
         gives ""), so fall back to the cleaned host itself.
    """
    host = host.strip().strip("[]").rstrip(".").lower()  # step 1
    if not host:  # step 2: "" is falsy, like host.isEmpty() in Java
        return ""
    result = _EXTRACT(host)  # step 3: ExtractResult(subdomain, domain, suffix, ...)
    return result.top_domain_under_public_suffix or host  # step 4


def has_public_suffix(host: str) -> bool:
    """True if `host` is a real domain name: some label + a known public suffix.

        "paypal.com", "www.sliit.lk", "paypa1-secure.test"  -> True
        "s3.ap-southeast-1.amazonaws.com"                     -> True (see below)
        "invoice.pdf", "localhost", "192.0.2.10", "co.uk", "" -> False

    Used to decide whether text such as a link's visible text names a domain at all.

    A host can itself be a "private" suffix: Amazon lists s3.ap-southeast-1.amazonaws.com
    so that every bucket under it counts as its own site. Images served straight from it
    are still a real host on the Internet (the Week 2 gate found two bank emails doing
    this), so a second look with the ICANN part of the list only (amazonaws.com) lets it
    through. A bare suffix such as "com" or "co.uk" still does not count.
    """
    host = host.strip().strip("[]").rstrip(".").lower()
    if not host:
        return False
    if _EXTRACT(host).top_domain_under_public_suffix:
        return True
    return bool(_EXTRACT(host, include_psl_private_domains=False).top_domain_under_public_suffix)


def ascii_domain(domain: str) -> str:
    """A domain in lower case and, if it is international, in its ASCII (punycode) form.

        "Bücher.de"    -> "xn--bcher-kva.de"
        "PayPal.COM."  -> "paypal.com"

    Threat-intel services expect the punycode form, and comparing two domains only works
    if both are written the same way. A name that cannot be converted (an empty or
    over-long label) is returned in lower case.
    """
    domain = domain.strip().rstrip(".").lower()
    try:
        return domain.encode("idna").decode("ascii")
    except UnicodeError:
        return domain


# --- Week 3 step 6: names never worth a lookup, and the domain a registry sold ----------


def is_reserved(host: str) -> bool:
    """True for a test or documentation name that nobody can own.

    "paypa1-secure.test", "x.example", "example.com", "www.example.org"  -> True
    "paypal.com", "example.co.uk", "myexample.com"                       -> False
    """
    host = ascii_domain(host)
    if host.rpartition(".")[2] in RESERVED_TLDS:
        return True
    return any(host == name or host.endswith("." + name) for name in RESERVED_DOMAINS)


def icann_domain(host: str) -> str:
    """The domain a registry actually sold: the ICANN part of the list only.

        "login.paypa1-secure.com"         -> "paypa1-secure.com"
        "evil.github.io"                  -> "github.io"     (registered_domain says
                                                              "evil.github.io")
        "s3.ap-southeast-1.amazonaws.com" -> "amazonaws.com"
        "com", "192.0.2.10", ""           -> ""

    Registration dates (RDAP, step 11) exist only for these names. A registry has never
    heard of "evil.github.io": GitHub hands out those names itself.
    """
    host = ascii_domain(host)
    if not host:
        return ""
    return _EXTRACT(host, include_psl_private_domains=False).top_domain_under_public_suffix
