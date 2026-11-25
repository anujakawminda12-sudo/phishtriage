"""Tests for domains.py: registered domains from the offline Public Suffix List."""

import socket

from phishtriage import domains
from phishtriage.domains import (
    ascii_domain,
    has_public_suffix,
    icann_domain,
    is_reserved,
    registered_domain,
)

# --- done for you -----------------------------------------------------------------


def test_extractor_never_uses_the_network(monkeypatch):
    """A brand-new extractor must load the bundled list without opening any connection."""
    attempts = []

    def blocked_connect(self, address):
        attempts.append(address)
        raise OSError("network is blocked in this test")

    monkeypatch.setattr(socket.socket, "connect", blocked_connect)
    fresh = domains.make_extractor()
    assert fresh("www.example.co.uk").top_domain_under_public_suffix == "example.co.uk"
    assert attempts == []


# --- Week 2: registered_domain ---------------------------------------------------------


def test_subdomains_collapse_to_registered_domain():
    assert registered_domain("mail.paypal.com") == "paypal.com"
    assert registered_domain("em8448.mail.capcut.com") == "capcut.com"
    assert registered_domain("alibaba.selections.aliexpress.com") == "aliexpress.com"


def test_multi_part_public_suffixes():
    assert registered_domain("login.evil.co.uk") == "evil.co.uk"
    assert registered_domain("courseweb.sliit.lk") == "sliit.lk"
    assert registered_domain("www.cse.mrt.ac.lk") == "mrt.ac.lk"
    # gov.lk is itself a public suffix, so every government site is a separate owner
    assert registered_domain("mail.gov.lk") == "mail.gov.lk"


def test_hosting_platform_customers_are_separate():
    assert registered_domain("evil.github.io") == "evil.github.io"
    assert registered_domain("phish.web.app") == "phish.web.app"


def test_reserved_test_tlds_work_like_real_ones():
    assert registered_domain("paypa1-secure.test") == "paypa1-secure.test"
    assert registered_domain("login.paypa1-secure.test") == "paypa1-secure.test"


def test_input_is_cleaned():
    assert registered_domain("  Mail.PayPal.COM ") == "paypal.com"
    assert registered_domain("maile-de.linkedin.com.") == "linkedin.com"


def test_no_public_suffix_returns_the_host_itself():
    assert registered_domain("192.0.2.10") == "192.0.2.10"
    assert registered_domain("[192.0.2.10]") == "192.0.2.10"
    assert registered_domain("2001:db8::1") == "2001:db8::1"
    assert registered_domain("intranet") == "intranet"
    assert registered_domain("") == ""


# --- Week 2 step 6: has_public_suffix --------------------------------------------------


def test_has_public_suffix():
    assert has_public_suffix("paypal.com")
    assert has_public_suffix("www.sliit.lk")
    assert has_public_suffix("paypa1-secure.test")
    assert not has_public_suffix("invoice.pdf")
    assert not has_public_suffix("localhost")
    assert not has_public_suffix("192.0.2.10")
    assert not has_public_suffix("")


# --- Week 2 step 7: ascii_domain -------------------------------------------------------


def test_ascii_domain():
    assert ascii_domain("Bücher.de") == "xn--bcher-kva.de"
    assert ascii_domain(" PayPal.COM. ") == "paypal.com"
    assert ascii_domain("a" * 64 + ".test") == "a" * 64 + ".test"  # too long: left as is


def test_has_public_suffix_accepts_a_host_that_is_itself_a_private_suffix():
    # found by the blind Week 2 gate: two bank emails load images straight from here
    assert has_public_suffix("s3.ap-southeast-1.amazonaws.com")
    assert has_public_suffix("blob.core.windows.net")
    # a bare ICANN suffix is still not a domain, and nor is an internal name
    assert not has_public_suffix("co.uk")
    assert not has_public_suffix("com")
    assert not has_public_suffix("mta1.prd.sparkpost")


# --- Week 3 step 6: is_reserved, icann_domain -------------------------------------------


def test_is_reserved():
    for host in (
        "paypa1-secure.test",
        "x.example",
        "a.invalid",
        "localhost",
        "Example.COM",
        "www.example.org",
        "mail.example.net",
    ):
        assert is_reserved(host), host
    for host in ("paypal.com", "example.co.uk", "myexample.com", "examples.org", "sliit.lk"):
        assert not is_reserved(host), host


def test_icann_domain():
    assert icann_domain("login.paypa1-secure.com") == "paypa1-secure.com"
    assert icann_domain("Login.Evil.CO.UK.") == "evil.co.uk"
    assert icann_domain("evil.github.io") == "github.io"  # a platform name, not a sale
    assert icann_domain("s3.ap-southeast-1.amazonaws.com") == "amazonaws.com"
    assert icann_domain("www.cse.mrt.ac.lk") == "mrt.ac.lk"
    assert icann_domain("com") == ""
    assert icann_domain("192.0.2.10") == ""
    assert icann_domain("") == ""
