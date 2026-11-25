"""Tests for links.py: the link-text vs href mismatch check (week 2, step 6), and URL
shorteners and open redirects (week 4, step 5)."""

from pathlib import Path

import pytest

from phishtriage.links import (
    SHORTENER_DOMAINS,
    Link,
    check_hidden_destinations,
    check_link_text_mismatch,
    displayed_domain,
    links_from_html,
)
from phishtriage.models import ParsedEmail
from phishtriage.parser import parse_eml


def make_email(from_addr: str, html: str) -> ParsedEmail:
    """A hand-built email with only a sender and an HTML body."""
    return ParsedEmail(path=Path("test.eml"), from_addr=from_addr, html_body=html)


def rules(findings) -> list[str]:
    return [finding.rule for finding in findings]


# --- links_from_html -----------------------------------------------------------------


def test_links_from_html():
    html = """
    <a href="https://shop.test/a">  Shop
        <b>now</b> </a>
    <a href="mailto:help@shop.test">help@shop.test</a>
    <a href="#top">Top</a>
    <a>no href</a>
    """
    assert links_from_html(html) == [Link(text="Shop now", href="https://shop.test/a")]
    assert links_from_html("") == []


# --- displayed_domain ----------------------------------------------------------------


def test_displayed_domain_finds_urls_and_bare_domains():
    assert displayed_domain("https://www.paypal.com/signin") == "paypal.com"
    assert displayed_domain("www.example.com/offers") == "example.com"
    assert displayed_domain("PayPal.com.") == "paypal.com"
    assert displayed_domain("hxxps://evil[.]test/reset") == "evil.test"
    assert displayed_domain("courseweb.sliit.lk") == "sliit.lk"


def test_displayed_domain_ignores_text_that_is_not_a_domain():
    assert displayed_domain("Click here") is None
    assert displayed_domain("invoice.pdf") is None  # .pdf is not a real suffix
    assert displayed_domain("192.0.2.1") is None
    assert displayed_domain("Visit paypal.com today") is None  # must be the whole text
    assert displayed_domain("") is None


def test_displayed_domain_international_names_become_punycode():
    assert displayed_domain("bücher.de") == "xn--bcher-kva.de"
    # a label longer than 63 characters cannot be converted: it is compared as it is
    too_long = "a" * 64 + ".test"
    assert displayed_domain(too_long) == too_long


# --- check_link_text_mismatch --------------------------------------------------------


def test_mismatch_on_the_paypal_fixture(fixtures):
    findings = check_link_text_mismatch(parse_eml(fixtures / "phish_paypal_spoof.eml"))
    assert rules(findings) == ["link_text_mismatch"]
    detail = findings[0].detail
    assert detail.startswith("1 link shows one domain but goes to another")
    # everything in the detail is defanged, so the report has no live links
    assert "hxxps://www[.]paypal[.]com/signin" in detail
    assert "paypa1-secure[.]test" in detail


def test_mismatch_inside_a_forwarded_email(fixtures):
    outer = parse_eml(fixtures / "forwarded_phish.eml")
    assert check_link_text_mismatch(outer) == []
    inner_findings = check_link_text_mismatch(outer.forwarded[0])
    assert rules(inner_findings) == ["link_text_mismatch"]
    assert "micros0ft-login[.]test" in inner_findings[0].detail


def test_no_mismatch_on_clean_fixtures(fixtures):
    for name in ["legit_newsletter.eml", "wrapped_links.eml", "broken_charset.eml"]:
        assert check_link_text_mismatch(parse_eml(fixtures / name)) == [], name


def test_same_organisation_is_not_a_mismatch():
    html = '<a href="https://mail.shop.test/offers?id=1">www.shop.test/offers</a>'
    assert check_link_text_mismatch(make_email("news@shop.test", html)) == []


def test_link_through_the_senders_own_domain_is_reported_separately():
    # The real Coursera case from the week 2 samples: click tracking on link.coursera.org
    html = (
        '<a href="https://link.coursera.org/a">facebook.com/MichiganOnline</a>'
        '<a href="https://link.coursera.org/b">x.com/UMichOnline</a>'
    )
    findings = check_link_text_mismatch(make_email("no-reply@m.learn.coursera.org", html))
    assert rules(findings) == ["link_text_mismatch_sender"]
    assert findings[0].detail.startswith("2 links show one domain but go to another")
    assert "click tracking" in findings[0].detail


def test_both_rules_can_fire_on_one_email():
    html = (
        '<a href="https://evil.test/a">paypal.com</a>'
        '<a href="https://tracker.sender.test/b">facebook.com</a>'
    )
    findings = check_link_text_mismatch(make_email("news@sender.test", html))
    assert rules(findings) == ["link_text_mismatch", "link_text_mismatch_sender"]


def test_wrapped_links_are_unwrapped_before_comparing():
    safelinks = (
        "https://nam12.safelinks.protection.outlook.com/?url="
        "https%3A%2F%2Freport.example.org%2Fphish&amp;data=abc&amp;reserved=0"
    )
    html = f'<a href="{safelinks}">report.example.org/phish</a>'
    assert check_link_text_mismatch(make_email("security@example.org", html)) == []


def test_international_domain_in_text_and_punycode_in_href_match():
    html = '<a href="https://xn--bcher-kva.de/">bücher.de</a>'
    assert check_link_text_mismatch(make_email("shop@xn--bcher-kva.de", html)) == []


def test_examples_are_limited_and_repeats_counted():
    html = '<a href="https://evil.test/1">paypal.com</a>' * 3 + (
        '<a href="https://evil.test/2">apple.com</a><a href="https://evil.test/3">dhl.com</a>'
    )
    detail = check_link_text_mismatch(make_email("x@sender.test", html))[0].detail
    assert detail.startswith("5 links show one domain but go to another")
    assert detail.count("goes to") == 2  # only the first 2 different examples
    assert "dhl" not in detail


def test_broken_href_does_not_crash():
    html = '<a href="http://[::1">paypal.com</a>'
    assert check_link_text_mismatch(make_email("x@sender.test", html)) == []


# --- Week 4, step 5: URL shorteners and open redirects ----------------------------------


def hidden(from_addr: str, html: str = "", text: str = "") -> dict[str, str]:
    """rule -> detail for check_hidden_destinations on a hand-built email."""
    email = ParsedEmail(path=Path("t.eml"), from_addr=from_addr, html_body=html, text_body=text)
    return {finding.rule: finding.detail for finding in check_hidden_destinations(email)}


@pytest.mark.parametrize(
    "url",
    [
        "https://bit.ly/3xYzAbc",
        "http://tinyurl.com/y7abc",
        "https://t.co/AbC123",
        "https://rb.gy/x1y2",
        "https://BIT.LY/upper",  # host case does not matter
        "https://www.bit.ly/www",  # nor a www in front
    ],
)
def test_url_shortener_in_a_link(url):
    found = hidden("news@shop.test", html=f'<a href="{url}">Track your parcel</a>')
    assert list(found) == ["url_shortener"]
    assert found["url_shortener"].startswith("1 link uses a URL shortener, e.g. hxxp")
    assert found["url_shortener"].endswith(
        "(PhishTriage never follows links, so where it leads is unknown)"
    )


def test_url_shortener_in_plain_text_counts_links_and_shows_two():
    text = (
        "Pay: https://bit.ly/a1 or https://bit.ly/b2 or https://tinyurl.com/c3 or https://bit.ly/a1"
    )
    detail = hidden("x@shop.test", text=text)["url_shortener"]
    assert detail.startswith(
        "3 links use a URL shortener, e.g. hxxps://bit[.]ly/a1; hxxps://bit[.]ly/b2 ("
    )


def test_a_long_shortened_url_is_cut_in_the_detail():
    detail = hidden("x@shop.test", text="https://bit.ly/" + "a" * 100)["url_shortener"]
    assert "a" * 100 not in detail
    assert "a" * 44 + "… (PhishTriage" in detail  # 60 characters, the last one "…"
    assert "[.][.][.]" not in detail


@pytest.mark.parametrize(
    "html",
    [
        '<img src="https://bit.ly/pixel">',  # an image is never clicked
        # alt text of a text box: its source is "html:textarea[alt]", which starts with
        # "html:text" (visible text, clickable) but is a different place
        '<textarea alt="https://bit.ly/x"></textarea>',
        '<a href="https://bitly.com/pages/pricing">Bitly</a>',  # the company site, not a short link
        '<a href="https://notbit.ly.example.com/x">x</a>',  # bit.ly is only a part of the name
        '<a href="https://shop.test/sale">Sale</a>',
    ],
)
def test_not_a_url_shortener(html):
    assert "url_shortener" not in hidden("x@shop.test", html=html)


def test_shortener_list_holds_registered_domains_only():
    """Each entry is compared with registered_domain(), so "www.bit.ly" would never match."""
    from phishtriage.domains import registered_domain

    assert all(registered_domain(domain) == domain for domain in SHORTENER_DOMAINS)


@pytest.mark.parametrize(
    ("href", "example"),
    [
        (
            "https://www.google.com/url?q=https://evil.test/login",
            "www[.]google[.]com forwards to evil[.]test",
        ),
        (
            "https://www.youtube.com/redirect?q=https%3A%2F%2Fevil.test%2F",
            "www[.]youtube[.]com forwards to evil[.]test",
        ),
        (
            "https://r.example.org/c?u=https%253A%252F%252Fevil.test%252F",
            "r[.]example[.]org forwards to evil[.]test",
        ),  # encoded twice
        (
            "https://proxy.example.org/go/https://evil.test/x",
            "proxy[.]example[.]org forwards to evil[.]test",
        ),  # in the path
        (
            "http://203.0.113.5/r?to=https://evil.test/",
            "203[.]0[.]113[.]5 forwards to evil[.]test",
        ),  # an IP has no domain
    ],
)
def test_open_redirect(href, example):
    found = hidden("alerts@sender.test", html=f'<a href="{href}">Sign in</a>')
    assert list(found) == ["open_redirect"]
    assert found["open_redirect"] == f"1 link on one site forwards to another, e.g. {example}"


def test_open_redirects_are_counted_per_link():
    html = (
        '<a href="https://www.google.com/url?q=https://evil.test/a">a</a>'
        '<a href="https://www.google.com/url?q=https://evil.test/b">b</a>'
        '<a href="https://r.example.org/c?u=https://other.test/">c</a>'
    )
    detail = hidden("x@sender.test", html=html)["open_redirect"]
    # two different links that read the same are counted twice, but shown once
    assert detail == (
        "3 links on one site forward to another, e.g. www[.]google[.]com forwards to "
        "evil[.]test; r[.]example[.]org forwards to other[.]test"
    )


@pytest.mark.parametrize(
    ("from_addr", "html"),
    [
        # a site forwarding to itself
        ("x@sender.test", '<a href="https://shop.test/go?to=https://www.shop.test/sale">Sale</a>'),
        # the sender's own click tracking, ending at the sender's own site
        (
            "news@shop.test",
            '<a href="https://click.esp.test/t?url=https://shop.test/sale">Sale</a>',
        ),
        # Safe Links is your own security product: unwrapped, not a redirect
        (
            "x@sender.test",
            '<a href="https://nam12.safelinks.protection.outlook.com/?url=https%3A%2F%2Fshop.test%2F'
            '&amp;data=05">Shop</a>',
        ),
        # an image proxy carries a URL, but an image is never clicked
        (
            "x@sender.test",
            '<img src="https://images.example.org/proxy?src=https://cdn.test/a.png">',
        ),
        # a query value that is not a URL
        ("x@sender.test", '<a href="https://shop.test/search?q=evil.test">search</a>'),
    ],
)
def test_not_an_open_redirect(from_addr, html):
    assert "open_redirect" not in hidden(from_addr, html=html)


def test_a_redirect_from_a_sender_with_no_from_address_is_still_reported():
    found = hidden("", html='<a href="https://www.google.com/url?q=https://evil.test/">x</a>')
    assert "open_redirect" in found


def test_a_shortened_link_inside_a_redirect_is_both():
    href = "https://www.google.com/url?q=https://bit.ly/3abc"
    assert set(hidden("x@sender.test", html=f'<a href="{href}">x</a>')) == {
        "url_shortener",
        "open_redirect",
    }


def test_broken_urls_do_not_crash():
    html = '<a href="http://[::1/r?u=https://evil.test/">x</a><a href="https://r.test/?u=http://[::1">y</a>'
    assert hidden("x@sender.test", html=html) is not None


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("phish_open_redirect.eml", {"open_redirect"}),
        ("legit_newsletter.eml", set()),
        ("wrapped_links.eml", set()),  # Safe Links and Proofpoint are not redirects
        ("phish_paypal_spoof.eml", set()),
        ("phish_microsoft_format.eml", set()),
    ],
)
def test_fixtures(fixtures, name, expected):
    findings = check_hidden_destinations(parse_eml(fixtures / name))
    assert {finding.rule for finding in findings} == expected


def test_the_fixture_detail_names_the_destination(fixtures):
    findings = check_hidden_destinations(parse_eml(fixtures / "phish_open_redirect.eml"))
    assert findings[0].detail == (
        "1 link on one site forwards to another, e.g. www[.]example[.]com forwards to "
        "docs-review[.]test"
    )
