"""Tests for allowlist.py (week 2, step 9)."""

from phishtriage.allowlist import Allowlist, load_allowlist, parse_allowlist
from phishtriage.iocs import extract_iocs
from phishtriage.models import IOC
from phishtriage.parser import parse_eml

SAMPLE = """
# a comment line
google.com
!docs.google.com        # an exception, with a comment after it
Mail.Example.ORG.       # case and the trailing dot do not matter
bücher.de
"""


def test_parse_allowlist():
    allow = parse_allowlist(SAMPLE)
    assert allow.domains == {"google.com", "mail.example.org", "xn--bcher-kva.de"}
    assert allow.exceptions == {"docs.google.com"}
    assert allow.problems == ()


def test_bad_lines_are_reported_not_fatal():
    allow = parse_allowlist("google.com\nhttps://evil.test/login\nlocalhost\n!\n")
    assert allow.domains == {"google.com"}
    assert allow.problems == (
        "line 2: 'https://evil.test/login' is not a domain name, so it was ignored",
        "line 3: 'localhost' is not a domain name, so it was ignored",
        "line 4: '!' is not a domain name, so it was ignored",
    )


def test_covers_domains_and_subdomains_but_not_lookalikes():
    allow = parse_allowlist("google.com\n")
    assert allow.covers("google.com")
    assert allow.covers("WWW.Google.com.")
    assert allow.covers("a.b.mail.google.com")
    assert not allow.covers("evilgoogle.com")  # whole labels only
    assert not allow.covers("google.com.evil.test")
    assert not allow.covers("")


def test_the_most_specific_line_wins():
    allow = parse_allowlist("google.com\n!docs.google.com\nforms.docs.google.com\n")
    assert allow.covers("www.google.com")
    assert not allow.covers("docs.google.com")
    assert not allow.covers("x.docs.google.com")  # under the exception
    assert allow.covers("forms.docs.google.com")  # more specific than the exception


def test_mark_never_removes_and_never_skips_ips():
    allow = parse_allowlist("google.com\n")
    iocs = [
        IOC(kind="url", value="https://www.google.com/search"),
        IOC(kind="domain", value="www.google.com"),
        IOC(kind="email", value="someone@google.com"),
        IOC(kind="ip", value="203.0.113.7"),
        IOC(kind="domain", value="evil.test"),
    ]
    marked = allow.mark(iocs)
    assert marked is iocs and len(marked) == 5  # the same list, nothing removed
    assert [ioc.allowlisted for ioc in iocs] == [True, True, True, False, False]


def test_possible_open_redirects_are_always_looked_up():
    allow = parse_allowlist("google.com\n")
    redirects = [
        IOC(kind="url", value="https://www.google.com/url?q=https://evil.test/login"),
        IOC(kind="url", value="https://www.google.com/url?q=https%3A%2F%2Fevil.test"),
    ]
    allow.mark(redirects)
    assert [ioc.allowlisted for ioc in redirects] == [False, False]
    broken = allow.mark([IOC(kind="url", value="http://[::1")])
    assert broken[0].allowlisted is False


def test_built_in_allowlist():
    allow = load_allowlist()
    assert allow.problems == ()
    assert allow.covers("www.google.com")
    assert allow.covers("fonts.googleapis.com")
    # anyone can host content on these, so they are always looked up
    for host in [
        "docs.google.com",
        "sites.google.com",
        "storage.googleapis.com",
        "forms.office.com",
        "onedrive.live.com",
        "evil.cloudfront.net",
    ]:
        assert not allow.covers(host), host


def test_load_allowlist_from_a_file(tmp_path):
    path = tmp_path / "mine.txt"
    path.write_text("sliit.lk\n", encoding="utf-8")
    allow = load_allowlist(path)
    assert allow.covers("courseweb.sliit.lk")
    assert not allow.covers("www.google.com")  # your file replaces the built-in one


def test_extract_iocs_with_an_allowlist(fixtures):
    email = parse_eml(fixtures / "phish_paypal_spoof.eml")
    without = extract_iocs(email)
    marked = extract_iocs(email, parse_allowlist("paypal.com\n"))
    assert [ioc.value for ioc in marked] == [ioc.value for ioc in without]  # nothing hidden
    skipped = {ioc.value for ioc in marked if ioc.allowlisted}
    assert skipped == {
        "https://www.paypal.com/signin",
        "www.paypal.com",
        "paypal.com",
        "service@paypal.com",
    }
    # the look-alike is never covered by the real brand's entry
    assert not any(ioc.allowlisted for ioc in marked if "paypa1" in ioc.value)


def test_an_empty_allowlist_covers_nothing():
    assert not Allowlist().covers("google.com")
