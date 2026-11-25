"""Tests for iocs.py (week 2)."""

from pathlib import Path
from urllib.parse import quote

import pytest

from phishtriage.iocs import (
    defang,
    emails_from_html,
    emails_from_text,
    embedded_urls,
    extract_domains,
    extract_email_addresses,
    extract_iocs,
    extract_ips,
    extract_urls,
    find_sender_ip,
    group_urls,
    ips_from_received,
    is_reportable_ip,
    merge_iocs,
    normalise_url,
    refang,
    unwrap_url,
    urls_from_css,
    urls_from_html,
    urls_from_text,
)
from phishtriage.models import ParsedEmail, SenderIP
from phishtriage.parser import parse_eml

# --- step 4: URLs from plain text ----------------------------------------------------


def test_urls_from_text_basic():
    text = "Sign in at https://www.paypal.com/signin or http://paypa1-secure.test/login now"
    assert urls_from_text(text) == [
        "https://www.paypal.com/signin",
        "http://paypa1-secure.test/login",
    ]


def test_urls_from_text_drops_sentence_punctuation():
    assert urls_from_text("Go to https://x.test/a.") == ["https://x.test/a"]
    assert urls_from_text("Really? https://x.test/b!") == ["https://x.test/b"]
    assert urls_from_text('He said "https://x.test/c",') == ["https://x.test/c"]


def test_urls_from_text_brackets():
    assert urls_from_text("(see https://x.test/a)") == ["https://x.test/a"]
    assert urls_from_text("Click <https://x.test/b>") == ["https://x.test/b"]
    # a bracket that belongs to the URL is kept
    wiki = "https://en.wikipedia.org/wiki/Phishing_(disambiguation)"
    assert urls_from_text(f"read {wiki} today") == [wiki]


def test_urls_from_text_ignores_other_schemes_and_case():
    assert urls_from_text("ftp://x.test/file mailto:a@x.test") == []
    assert urls_from_text("HTTPS://EXAMPLE.COM/Path") == ["HTTPS://EXAMPLE.COM/Path"]
    assert urls_from_text("") == []


# --- step 4: URLs from HTML ----------------------------------------------------------


def test_urls_from_html_attributes_and_sources():
    html = """
    <a href="https://shop.test/offers">Offers</a>
    <img src="https://cdn.test/logo.png">
    <form action="http://evil.test/collect"><input name="pw"></form>
    <iframe src="https://frame.test/"></iframe>
    """
    assert urls_from_html(html) == [
        ("https://shop.test/offers", "html:a[href]"),
        ("https://cdn.test/logo.png", "html:img[src]"),
        ("http://evil.test/collect", "html:form[action]"),
        ("https://frame.test/", "html:iframe[src]"),
    ]


def test_urls_from_html_skips_non_web_links():
    html = """
    <a href="mailto:help@x.test">mail</a> <a href="tel:+94112345678">call</a>
    <img src="cid:logo123"> <a href="javascript:void(0)">js</a>
    <a href="#top">top</a> <a href="/relative/path">rel</a>
    """
    assert urls_from_html(html) == []


def test_urls_from_html_decodes_entities_and_reads_visible_text():
    html = '<p>Visit https://plain.test/page</p><a href="https://x.test/?a=1&amp;b=2">x</a>'
    assert urls_from_html(html) == [
        ("https://x.test/?a=1&b=2", "html:a[href]"),  # &amp; became &
        ("https://plain.test/page", "html:text"),
    ]


def test_urls_from_html_empty_and_broken():
    assert urls_from_html("") == []
    # unclosed tags and a missing quote must not crash the parser
    assert urls_from_html('<p><a href="https://x.test/a>broken') == []


# --- step 4: normalising and merging -------------------------------------------------


def test_normalise_url():
    assert normalise_url(" HTTP://Example.COM/Login?ID=Abc#Top ") == (
        "http://example.com/Login?ID=Abc#Top"
    )
    assert normalise_url("http://[::1") == "http://[::1"  # broken URL: returned as is


def test_merge_iocs_counts_and_keeps_every_source_once():
    pairs = [
        ("https://a.test/", "text"),
        ("https://b.test/", "html:img[src]"),
        ("https://a.test/", "html:a[href]"),
        ("https://a.test/", "text"),
    ]
    iocs = merge_iocs("url", pairs)
    assert [ioc.value for ioc in iocs] == ["https://a.test/", "https://b.test/"]
    assert iocs[0].sources == ["text", "html:a[href]"]
    assert iocs[0].count == 3
    assert iocs[1].count == 1


# --- step 4: whole emails ------------------------------------------------------------


def test_extract_urls_phish(fixtures):
    iocs = extract_urls(parse_eml(fixtures / "phish_paypal_spoof.eml"))
    by_value = {ioc.value: ioc for ioc in iocs}
    assert set(by_value) == {"https://www.paypal.com/signin", "http://paypa1-secure.test/login"}
    # the real PayPal address is only shown as text; the link really goes to the lookalike
    assert by_value["https://www.paypal.com/signin"].sources == ["text", "html:text"]
    assert by_value["http://paypa1-secure.test/login"].sources == ["html:a[href]"]
    # the HTML attachment is never read: its contents are not in the bodies
    assert all(ioc.kind == "url" for ioc in iocs)


def test_extract_urls_legit_newsletter_dedups(fixtures):
    iocs = extract_urls(parse_eml(fixtures / "legit_newsletter.eml"))
    assert [ioc.value for ioc in iocs] == ["https://www.example.com/offers"]
    assert iocs[0].sources == ["text", "html:a[href]"]
    assert iocs[0].count == 2


def test_extract_urls_forwarded_email_keeps_urls_with_the_right_email(fixtures):
    outer = parse_eml(fixtures / "forwarded_phish.eml")
    assert extract_urls(outer) == []  # Nimal's note has no links
    inner_urls = {ioc.value for ioc in extract_urls(outer.forwarded[0])}
    assert inner_urls == {
        "http://micros0ft-login.test/auth?user=nimal",
        "https://login.microsoftonline.com/keep-password",
    }


# --- step 5: refang and defang -------------------------------------------------------


def test_refang():
    assert refang("hxxps://evil[.]test/login") == "https://evil.test/login"
    assert refang("HXXP[://]evil[.]test") == "http://evil.test"
    assert refang("billing[@]evil(dot)test") == "billing@evil.test"
    assert refang("support(at)evil{.}test") == "support@evil.test"
    assert refang("203[.]0[.]113[.]7") == "203.0.113.7"
    assert refang("evil[dot]test[/]a") == "evil.test/a"
    assert refang("a normal sentence (with brackets).") == "a normal sentence (with brackets)."


def test_defang():
    assert defang("https://evil.test/login.php") == "hxxps://evil[.]test/login[.]php"
    assert defang("evil.test") == "evil[.]test"
    assert defang("203.0.113.7") == "203[.]0[.]113[.]7"
    assert defang("billing@evil.test") == "billing[@]evil[.]test"
    # a second URL hidden in the query string is defanged too
    assert defang("https://a.test/?next=http://b.test") == "hxxps://a[.]test/?next=hxxp://b[.]test"


def test_defang_twice_changes_nothing_and_refang_reverses_it():
    for value in ["https://evil.test/a.php?x=1", "evil.test", "203.0.113.7", "a@evil.test"]:
        once = defang(value)
        assert defang(once) == once
        assert refang(once) == value


def test_urls_from_text_finds_defanged_urls():
    text = "Do not visit hxxps://evil-login[.]test/reset or hxxp://203[.]0[.]113[.]7/x"
    assert urls_from_text(text) == ["https://evil-login.test/reset", "http://203.0.113.7/x"]


# --- step 5: unwrapping Safe Links and Proofpoint ------------------------------------

SAFELINKS = (
    "https://nam12.safelinks.protection.outlook.com/?url=http%3A%2F%2Fmicros0ft-login.test"
    "%2Fauth%3Fuser%3Dnimal%26step%3D2&data=05%7C02%7Cnimal%40example.org%7Cabc"
    "&sdata=xyz%3D&reserved=0"
)
PROOFPOINT_V2 = (
    "https://urldefense.proofpoint.com/v2/url?u=https-3A__evil-2Dinvoice.test_view-3Fid-3D42"
    "&d=DwMFaQ&c=xyz&r=abc&m=def&s=ghi&e="
)
# The example from Proofpoint's own documentation: "*" stands for "+", kept as "Kw" (base64)
PROOFPOINT_V3 = (
    "https://urldefense.com/v3/__https://google.com:443/search?q=a*test&gs=ps__;Kw"
    "!-612Flbf0JvQ3kNJkRi5Jg!Ue6tQudNKaShHg93trcdjqDP8se2ySE65jyCIe2K1D_uNjZ1Lnf6YLQ"
    "ERujngZv9UWf66ujQIQ$"
)


def test_unwrap_safe_links():
    # The real URL comes back, and the recipient's address hidden in "data" is dropped
    assert unwrap_url(SAFELINKS) == (
        "http://micros0ft-login.test/auth?user=nimal&step=2",
        ["Microsoft Safe Links"],
    )


def test_unwrap_proofpoint_v1_v2_v3():
    v1 = "https://urldefense.proofpoint.com/v1/url?u=http://evil.test/a&k=abc"
    assert unwrap_url(v1) == ("http://evil.test/a", ["Proofpoint URL Defense"])
    assert unwrap_url(PROOFPOINT_V2) == (
        "https://evil-invoice.test/view?id=42",
        ["Proofpoint URL Defense"],
    )
    assert unwrap_url(PROOFPOINT_V3) == (
        "https://google.com:443/search?q=a+test&gs=ps",
        ["Proofpoint URL Defense"],
    )


def test_unwrap_proofpoint_v3_runs_and_plain():
    # "**A" is a run of 2 characters: "JCQ" is base64 for "$$"
    run = "https://urldefense.com/v3/__https://x.test/p?a=**Ab__;JCQ!!ABC!xyz$"
    assert unwrap_url(run) == ("https://x.test/p?a=$$b", ["Proofpoint URL Defense"])
    plain = "https://urldefense.com/v3/__https://x.test/pay__;!!ABC!xyz$"
    assert unwrap_url(plain) == ("https://x.test/pay", ["Proofpoint URL Defense"])


def test_unwrap_nested_wrappers():
    nested = (
        "https://eur01.safelinks.protection.outlook.com/?url="
        + quote(PROOFPOINT_V2, safe="")
        + "&data=abc&reserved=0"
    )
    assert unwrap_url(nested) == (
        "https://evil-invoice.test/view?id=42",
        ["Microsoft Safe Links", "Proofpoint URL Defense"],
    )


def test_unwrap_leaves_other_urls_alone():
    for url in [
        "https://evil.test/?url=https%3A%2F%2Fpaypal.com",  # not a wrapper host
        "https://safelinks.protection.outlook.com.evil.test/?url=https%3A%2F%2Fpaypal.com",
        "https://urldefense.com/v3/__https://x.test/__;A!!x$",  # broken base64
        "https://urldefense.com/v3/__https://x.test/a*b__;_w!!x$",  # kept bytes not UTF-8
        "https://urldefense.com/v3/__https://x.test/a*b__;!!x$",  # "*" but nothing kept
        "https://urldefense.com/v3/__https://x.test/a**~b__;JCQ!!x$",  # unknown run length
        "https://urldefense.com/some/other/page",  # wrapper host, but not a v3 link
        "https://nam12.safelinks.protection.outlook.com/?data=no-url-parameter",
        "http://[::1",  # broken URL
    ]:
        assert unwrap_url(url) == (url, [])


def test_extract_urls_unwraps_and_refangs(fixtures):
    iocs = extract_urls(parse_eml(fixtures / "wrapped_links.eml"))
    by_value = {ioc.value: ioc for ioc in iocs}
    assert list(by_value) == [
        "https://evil-login.test/reset",
        "https://report.example.org/phish",
        "https://partner-portal.test/news",
        "https://partner-portal.test/events?q=a+b",
    ]
    assert by_value["https://evil-login.test/reset"].sources == ["text", "html:text"]
    assert by_value["https://report.example.org/phish"].sources == [
        "text via Microsoft Safe Links",
        "html:a[href] via Microsoft Safe Links",
    ]
    # the same link, wrapped once and wrapped twice, is still one IOC
    assert by_value["https://partner-portal.test/news"].sources == [
        "html:a[href] via Proofpoint URL Defense",
        "html:a[href] via Microsoft Safe Links + Proofpoint URL Defense",
    ]
    # no wrapper host is left over as an IOC of its own
    assert not any("safelinks" in value or "urldefense" in value for value in by_value)


# --- step 7: IP addresses from Received headers --------------------------------------


def test_ips_from_received_only_takes_bracketed_ips_in_the_from_part():
    received = [
        # hop 1: our own server received it from the sender's server
        "from mail.evil.test (unknown [203.0.113.45]) by mx.example.org with ESMTP id x9y8z7",
        # hop 2: the sender's internal relay (private address)
        "from laptop.evil.test ([10.1.2.3]) by mail.evil.test with ESMTPSA id k1",
        # hop 3: an IPv6 sender
        "from v6.evil.test (v6.evil.test [IPv6:2001:db8::25]) by mail.evil.test id k2",
    ]
    assert ips_from_received(received) == [
        ("203.0.113.45", "header:Received (hop 1)"),
        ("2001:db8::25", "header:Received (hop 3)"),
    ]


def test_ips_from_received_ignores_numbers_that_only_look_like_ips():
    # The three fake IPs from the real week 2 samples
    received = [
        "by 2002:a05:6504:1d2f:b0:2d1:abcd with SMTP id fac.382.2026.11.19.20.33.59; Thu",
        "from mta.sparkpost.test (ecelerity 5.3.0.76572 r(msys-ecelerity:tags/5.3.0.32))"
        " by mx.example.org",
        "from localhost (localhost [127.0.0.1]) by mail.example.org ([198.51.100.9])",
    ]
    assert ips_from_received(received) == []


def test_is_reportable_ip():
    assert is_reportable_ip("209.85.220.41")  # public (a Google mail server)
    assert is_reportable_ip("203.0.113.45")  # documentation range, used by fixtures
    assert is_reportable_ip("2001:db8::1")
    for value in ["10.0.0.1", "192.168.1.1", "127.0.0.1", "169.254.1.1", "fe80::1", "x"]:
        assert not is_reportable_ip(value), value


# --- step 7: email addresses ---------------------------------------------------------


def test_emails_from_text_refangs_and_rejects_non_addresses():
    text = (
        "Write to Billing[@]Evil-Login[.]test or help@shop.test. "
        "Inline image: [cid:image001.png@01DA1B2C.3D4E5F60]"
    )
    assert emails_from_text(text) == ["billing@evil-login.test", "help@shop.test"]


def test_emails_from_html_mailto_and_text():
    html = (
        '<a href="mailto:a@shop.test,B@Shop.test?subject=Hi%20there">Mail us</a>'
        "<p>or write to c@shop.test</p>"
    )
    assert emails_from_html(html) == [
        ("a@shop.test", "html:a[href]"),
        ("b@shop.test", "html:a[href]"),
        ("c@shop.test", "html:text"),
    ]
    assert emails_from_html("") == []


def test_extract_email_addresses_from_headers(fixtures):
    iocs = extract_email_addresses(parse_eml(fixtures / "phish_paypal_spoof.eml"))
    assert [(ioc.value, ioc.sources) for ioc in iocs] == [
        ("service@paypal.com", ["header:From"]),
        ("support@paypa1-secure.test", ["header:Reply-To"]),
        ("bounce@mailer-7731.test", ["header:Return-Path"]),
    ]


def test_recipient_address_in_the_body_is_not_an_ioc():
    email = ParsedEmail(
        path=Path("test.eml"),
        from_addr="news@shop.test",
        to=["student@example.org"],
        text_body="This email was sent to student@example.org. Questions? help@shop.test",
    )
    values = [ioc.value for ioc in extract_email_addresses(email)]
    assert values == ["news@shop.test", "help@shop.test"]


def test_recipient_address_in_a_sender_header_is_kept():
    # "From: you, To: you" is a common scam, so the sender header still counts
    email = ParsedEmail(
        path=Path("test.eml"), from_addr="student@example.org", to=["student@example.org"]
    )
    assert [ioc.value for ioc in extract_email_addresses(email)] == ["student@example.org"]


# --- step 7: domains and the whole set -----------------------------------------------


def test_extract_iocs_phish(fixtures):
    iocs = extract_iocs(parse_eml(fixtures / "phish_paypal_spoof.eml"))
    by_kind = {}
    for ioc in iocs:
        by_kind.setdefault(ioc.kind, []).append(ioc.value)
    assert list(by_kind) == ["url", "domain", "ip", "email"]  # always in this order
    assert by_kind["domain"] == [
        "www.paypal.com",
        "paypa1-secure.test",
        "paypal.com",
        "mailer-7731.test",  # from Return-Path and from the Message-ID
    ]
    assert by_kind["ip"] == ["203.0.113.45"]
    domains = {ioc.value: ioc for ioc in iocs if ioc.kind == "domain"}
    assert domains["mailer-7731.test"].sources == ["email address", "header:Message-ID"]


def test_extract_iocs_forwarded_email_drops_private_ips(fixtures):
    outer = parse_eml(fixtures / "forwarded_phish.eml")
    # Nimal's laptop (10.20.30.40) is a private address, so the outer email has no IP
    assert [ioc.value for ioc in extract_iocs(outer) if ioc.kind == "ip"] == []
    inner = extract_iocs(outer.forwarded[0])
    assert [ioc.value for ioc in inner if ioc.kind == "ip"] == ["203.0.113.77"]


def test_extract_domains_skips_ips_local_names_and_converts_to_punycode():
    email = ParsedEmail(path=Path("test.eml"), message_id="<123@Mail.Bücher.de>")
    urls = merge_iocs(
        "url",
        [
            ("http://203.0.113.7/login", "text"),
            ("http://intranet/home", "text"),
            ("http://[::1", "text"),  # broken URL
            ("https://WWW.Shop.test/a", "text"),
        ],
    )
    domains = extract_domains(email, urls, [])
    assert [(ioc.value, ioc.sources) for ioc in domains] == [
        ("www.shop.test", ["url"]),
        ("mail.xn--bcher-kva.de", ["header:Message-ID"]),
    ]
    assert [ioc.value for ioc in extract_ips(email, urls)] == ["203.0.113.7"]


# --- step 10: grouping URLs for the report -------------------------------------------


def test_group_urls_by_registered_domain():
    urls = merge_iocs(
        "url",
        [
            ("https://www.shop.test/a", "html:a[href]"),
            ("http://203.0.113.7/login", "text"),
            ("https://img.shop.test/logo.png", "html:img[src]"),
            ("https://www.shop.test/a", "text"),
            ("http://[::1", "text"),  # broken: grouped under itself
        ],
    )
    urls[2].allowlisted = True
    groups = group_urls(urls)
    assert [group.domain for group in groups] == ["shop.test", "203.0.113.7", "http://[::1"]
    shop = groups[0]
    assert [url.value for url in shop.urls] == [
        "https://www.shop.test/a",
        "https://img.shop.test/logo.png",
    ]
    assert shop.seen == 3  # /a was seen twice, the logo once
    assert shop.sources == ["html:a[href]", "text", "html:img[src]"]
    assert shop.skipped == 1


# --- step 11: CSS URLs and links inside links (found by the Week 2 gate) -------------


def test_urls_from_css_finds_url_values_and_imports():
    css = """
    @import 'https://cdn.test/a.css';
    @import url("https://cdn.test/b.css");
    .x { background: url(https://img.test/bg.png) no-repeat; }
    @font-face { src: url('https://fonts.test/f.woff2') format("woff2"); }
    .y { background: url(data:image/png;base64,AAAA); }  /* not a web URL */
    .z { background: url(/relative/bg.png); }
    """
    assert urls_from_css(css) == [
        "https://cdn.test/a.css",
        "https://cdn.test/b.css",
        "https://img.test/bg.png",
        "https://fonts.test/f.woff2",
    ]
    assert urls_from_css("") == []


def test_urls_from_html_reads_style_blocks_and_style_attributes():
    html = """
    <style>@import 'https://cdn.test/a.css'; .b { background: url(https://img.test/b.png) }</style>
    <td style="background-image: url('https://img.test/cell.png')">hi</td>
    """
    assert urls_from_html(html) == [
        ("https://cdn.test/a.css", "html:style"),
        ("https://img.test/b.png", "html:style"),
        ("https://img.test/cell.png", "html:td[style]"),
    ]


def test_urls_from_html_ignores_attributes_that_are_not_links():
    # Coursera's social icons: prefix="..." is metadata, the browser never fetches it
    html = '<img alt="X" prefix="https://x.com/" src="https://cdn.test/x-icon.png">'
    assert urls_from_html(html) == [("https://cdn.test/x-icon.png", "html:img[src]")]


def test_embedded_urls_in_the_query_string():
    assert embedded_urls("https://www.google.com/url?q=https://evil.test/a&sa=D") == [
        "https://evil.test/a"
    ]
    # percent-encoded once (IMDb's click tracker) and twice
    once = "https://r.imdb.test/gp/r.html?C=1&U=" + quote("https://www.imdb.test/?ref_=x", safe="")
    assert embedded_urls(once) == ["https://www.imdb.test/?ref_=x"]
    twice = "https://t.test/c?u=" + quote(quote("https://shop.test/p", safe=""), safe="")
    assert embedded_urls(twice) == ["https://shop.test/p"]


def test_embedded_urls_in_the_path():
    proxy = "https://d3n.cloudfront.test/api/imageproxy/https://bucket.s3.amazonaws.com/logo.png"
    assert embedded_urls(proxy) == ["https://bucket.s3.amazonaws.com/logo.png"]
    # some proxies squash "//" to "/", some percent-encode the inner URL
    assert embedded_urls("https://p.test/fetch/http:/img.test/a.png") == ["http://img.test/a.png"]
    encoded = "https://p.test/fetch/" + quote("https://img.test/b.png", safe="")
    assert embedded_urls(encoded) == ["https://img.test/b.png"]


def test_embedded_urls_ignores_everything_else():
    for url in [
        "https://shop.test/offers?id=42&ref=newsletter",  # no URL inside
        "https://shop.test/go?next=javascript:alert(1)",  # not a web URL
        "https://shop.test/go?next=https://",  # a scheme with no host
        "https://shop.test/go?next=/account",  # a relative path
        "http://[::1",  # broken URL
    ]:
        assert embedded_urls(url) == []


def test_extract_urls_follows_links_inside_links():
    redirect = "https://www.google.com/url?q=https://evil.test/login&sa=D"
    email = ParsedEmail(
        path=Path("test.eml"),
        html_body=f'<a href="{redirect}">Google Docs</a>',
        received=["from mx.test ([203.0.113.9]) by mx.example.org"],
    )
    urls = extract_urls(email)
    assert [(ioc.value, ioc.sources) for ioc in urls] == [
        (redirect, ["html:a[href]"]),
        ("https://evil.test/login", ["html:a[href] (inside a link to www.google.com)"]),
    ]
    domains = [ioc.value for ioc in extract_iocs(email) if ioc.kind == "domain"]
    assert domains == ["www.google.com", "evil.test"]  # the real destination is an IOC


def test_extract_urls_unwraps_a_link_found_inside_a_link():
    # a redirector carrying a Safe Links URL: both layers are undone
    safelink = "https://nam12.safelinks.protection.outlook.com/?url=" + quote(
        "https://evil.test/x", safe=""
    )
    outer = "https://t.test/c?u=" + quote(safelink, safe="")
    email = ParsedEmail(path=Path("test.eml"), text_body=outer)
    assert [(ioc.value, ioc.sources) for ioc in extract_urls(email)] == [
        (outer, ["text"]),
        ("https://evil.test/x", ["text (inside a link to t.test) via Microsoft Safe Links"]),
    ]


def test_extract_urls_stops_after_too_many_links_inside_links():
    url = "https://evil.test/end"
    for level in range(8):
        url = f"https://hop{level}.test/r?u=" + quote(url, safe="")
    values = [ioc.value for ioc in extract_urls(ParsedEmail(path=Path("t.eml"), text_body=url))]
    assert len(values) == 6  # the outer link + MAX_UNWRAP (5) links inside it
    assert "https://evil.test/end" not in values


def test_an_ip_inside_a_link_is_an_ioc():
    email = ParsedEmail(
        path=Path("test.eml"), text_body="https://t.test/c?u=http://203.0.113.50/login"
    )
    assert [ioc.value for ioc in extract_iocs(email) if ioc.kind == "ip"] == ["203.0.113.50"]


# --- step 11: found by the blind gate ------------------------------------------------


def test_links_without_a_scheme_are_read_as_https():
    html = """
    <link href="//fonts.test/css?family=Sans" rel="stylesheet">
    <img src="//cdn.test/logo.png">
    <a href="///triple-slash">not a host</a> <a href="//">empty</a>
    <div itemscope itemtype="//schema.org/EmailMessage"></div>
    <style>.a { background: url(//img.test/bg.png) } .b { background: url(///x) }</style>
    """
    assert urls_from_html(html) == [
        ("https://fonts.test/css?family=Sans", "html:link[href]"),
        ("https://cdn.test/logo.png", "html:img[src]"),
        ("https://img.test/bg.png", "html:style"),
    ]  # itemtype is a label, not a link, like prefix=


def test_alt_text_is_read_like_visible_text():
    # email apps often block images and show the alt text instead
    html = '<img alt="Questions? info@bank.test or https://help.bank.test/" src="cid:banner">'
    assert urls_from_html(html) == [("https://help.bank.test/", "html:img[alt]")]
    assert emails_from_html(html) == [("info@bank.test", "html:img[alt]")]


def test_recipient_address_in_alt_text_is_still_skipped():
    email = ParsedEmail(
        path=Path("test.eml"),
        to=["student@example.org"],
        html_body='<img alt="Sent to student@example.org" src="cid:x">',
    )
    assert extract_email_addresses(email) == []


def test_every_reply_to_address_is_an_ioc():
    email = ParsedEmail(
        path=Path("test.eml"),
        from_addr="hello@secops.test",
        reply_to="hello@secops.test",
        reply_to_all=["hello@secops.test", "cert@secops.test"],
    )
    iocs = extract_email_addresses(email)
    assert [(ioc.value, ioc.sources) for ioc in iocs] == [
        ("hello@secops.test", ["header:From", "header:Reply-To"]),
        ("cert@secops.test", ["header:Reply-To"]),
    ]


# --- Week 3 step 2: every From address, and recipients beyond To ----------------------


def test_every_from_address_is_an_ioc():
    email = ParsedEmail(
        path=Path("test.eml"),
        from_addr="service@paypal.com",
        from_all=["service@paypal.com", "attacker@evil.test"],
    )
    iocs = extract_email_addresses(email)
    assert [(ioc.value, ioc.sources) for ioc in iocs] == [
        ("service@paypal.com", ["header:From"]),
        ("attacker@evil.test", ["header:From"]),
    ]


def test_recipient_known_only_from_delivered_to_is_not_an_ioc(tmp_path):
    # Bcc: To names nobody, so Week 2 listed the victim's own address from the body
    path = tmp_path / "bcc.eml"
    path.write_text(
        "From: shop@shop.test\nTo: undisclosed-recipients:;\n"
        "Delivered-To: me.victim@example.org\nSubject: Offer\n\n"
        "This email was sent to me.victim@example.org. Questions? help@shop.test\n",
        encoding="utf-8",
    )
    values = [ioc.value for ioc in extract_email_addresses(parse_eml(path))]
    assert values == ["shop@shop.test", "help@shop.test"]


def test_cc_recipient_in_the_body_is_not_an_ioc():
    email = ParsedEmail(
        path=Path("test.eml"),
        from_addr="news@shop.test",
        recipients=["colleague@example.org"],
        text_body="Also sent to colleague@example.org",
    )
    assert [ioc.value for ioc in extract_email_addresses(email)] == ["news@shop.test"]


# --- Week 4, step 3: Microsoft's round brackets, the sender IP, hops above it -------------


def test_ips_from_received_reads_microsofts_round_brackets():
    received = [
        "from mail.evil.test (203.0.113.77) by SN6PR04MB.namprd04.outlook.example "
        "(2001:db8:10::5) with Microsoft SMTP Server (version=TLS1_2) id 15.20.8200.1",
        "from v6.evil.test (2001:DB8::0:25) by mail.evil.test",
        "from odd.evil.test (1.2.3) by mail.evil.test",  # brackets, but not an IP
    ]
    assert ips_from_received(received) == [
        ("203.0.113.77", "header:Received (hop 1)"),  # the "by" side's IP is not read
        ("2001:db8::25", "header:Received (hop 2)"),
    ]


def test_ips_from_received_skips_the_hops_above_the_senders_hop():
    received = [
        # Outlook passing the email along inside Microsoft: not an indicator
        "from SN6PR04MB.outlook.example (2001:db8:10::5) by MW4PR04MB.outlook.example",
        # where Microsoft received it from the sender
        "from mail.evil.test (203.0.113.77) by SN6PR04MB.outlook.example",
        # below the sender's hop: kept, as before (it could be forged, but it is evidence)
        "from laptop.evil.test ([198.51.100.3]) by mail.evil.test",
    ]
    assert ips_from_received(received, "203.0.113.77") == [
        ("203.0.113.77", "header:Received (hop 2)"),
        ("198.51.100.3", "header:Received (hop 3)"),
    ]
    # a sender IP that no hop names: every hop is kept
    assert len(ips_from_received(received, "192.0.2.200")) == 3
    assert len(ips_from_received(received)) == 3


def make_received_email(received: list[str], auth: list[str] | None = None) -> ParsedEmail:
    return ParsedEmail(path=Path("x.eml"), received=received, auth_results_headers=auth or [])


def test_find_sender_ip_prefers_the_trusted_header():
    email = make_received_email(
        ["from mail.evil.test (unknown [203.0.113.45]) by mx.google.com"],
        ["spf=fail (sender IP is 203.0.113.46) smtp.mailfrom=evil.test"],
    )
    sender = find_sender_ip(email)
    assert sender == SenderIP("203.0.113.46", "Authentication-Results")
    assert sender.certain


@pytest.mark.parametrize(
    ("received", "expected"),
    [
        # Gmail's own top hop has no "from": the next one is where Gmail received it
        (
            [
                "by 2002:a05:6504:1d2f:b0:2d1:abcd with SMTP id x; Mon, 23 Nov 2026",
                "from mail.evil.test (mail.evil.test. [203.0.113.45]) by mx.google.com",
            ],
            SenderIP("203.0.113.45", "Received hop 2"),
        ),
        # the first word after "from" is the name the sender chose (HELO): skipped
        (
            ["from [198.51.100.1] (unknown [203.0.113.45]) by mx.example.org"],
            SenderIP("203.0.113.45", "Received hop 1"),
        ),
        # Exim puts helo= last: skipped too
        (
            ["from rdns.evil.test ([203.0.113.4] helo=[198.51.100.1]) by mx.example.org"],
            SenderIP("203.0.113.4", "Received hop 1"),
        ),
        (
            ["from rdns.evil.test (helo=[198.51.100.1] [203.0.113.4]) by mx.example.org"],
            SenderIP("203.0.113.4", "Received hop 1"),
        ),
        # only an IP after "from": that is the one
        (["from [203.0.113.5] by mx.example.org"], SenderIP("203.0.113.5", "Received hop 1")),
        # Microsoft's round brackets
        (
            ["from mail.evil.test (203.0.113.77) by SN6PR04MB.outlook.example"],
            SenderIP("203.0.113.77", "Received hop 1"),
        ),
        # a private hop is your own network: the search goes on to the next one
        (
            [
                "from localhost (localhost [127.0.0.1]) by mail.example.org",
                "from mail.evil.test ([203.0.113.6]) by mx.example.org",
            ],
            SenderIP("203.0.113.6", "Received hop 2"),
        ),
        (["by mx.example.org with SMTP"], None),
        ([], None),
    ],
)
def test_find_sender_ip_falls_back_to_the_received_chain(received, expected):
    sender = find_sender_ip(make_received_email(received))
    assert sender == expected
    if sender:
        assert not sender.certain


def test_the_sender_ip_comes_first_in_the_ip_iocs():
    email = make_received_email(
        [
            "from relay.example.org ([198.51.100.40]) by mx.example.org",
            "from mail.evil.test ([203.0.113.45]) by relay.example.org",
        ],
        ["mx.example.org; spf=fail (sender IP is 203.0.113.45) smtp.mailfrom=evil.test"],
    )
    ips = extract_ips(email, [])
    assert [(ioc.value, ioc.sources) for ioc in ips] == [
        ("203.0.113.45", ["sender IP", "header:Received (hop 2)"]),
    ]  # hop 1, above the sender's hop, is your own side's relay


def test_a_sender_ip_that_no_hop_names_is_still_an_ioc():
    email = make_received_email([], ["spf=pass (sender IP is 203.0.113.50) smtp.mailfrom=a.test"])
    assert [(ioc.value, ioc.sources) for ioc in extract_ips(email, [])] == [
        ("203.0.113.50", ["sender IP"])
    ]


def test_a_private_sender_ip_is_reported_but_never_an_ioc():
    email = make_received_email([], ["spf=pass (sender IP is 10.1.2.3) smtp.mailfrom=a.test"])
    assert find_sender_ip(email) == SenderIP("10.1.2.3", "Authentication-Results")
    assert extract_ips(email, []) == []


def test_microsoft_fixture_ips(fixtures):
    """Week 2-3 found no IP in Outlook mail: its IPs are in round brackets."""
    ips = extract_ips(parse_eml(fixtures / "phish_microsoft_format.eml"), [])
    assert [(ioc.value, ioc.sources) for ioc in ips] == [
        ("203.0.113.77", ["sender IP", "header:Received (hop 2)"]),
    ]
