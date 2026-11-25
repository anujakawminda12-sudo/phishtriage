"""Tests for lookalike.py: sender domains that imitate a brand (week 4, step 4)."""

from pathlib import Path

import pytest
from typer.testing import CliRunner

from phishtriage.cli import app
from phishtriage.lookalike import (
    check_sender_domains,
    decode_label,
    describe_swaps,
    edit_distance,
    edit_limit,
    inspect_domain,
    scripts,
    skeleton,
)
from phishtriage.models import ParsedEmail
from phishtriage.parser import parse_eml

runner = CliRunner()


def make_email(**fields) -> ParsedEmail:
    return ParsedEmail(path=Path("test.eml"), **fields)


# --- the building blocks --------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "looks_like"),
    [
        ("paypal", "paypal"),
        ("paypa1", "paypal"),  # digit one for "l"
        ("micros0ft", "microsoft"),  # digit zero for "o"
        ("p\u0430ypal", "paypal"),  # Cyrillic "\u0430"
        ("\u0430\u0440\u0440\u04cf\u0435", "apple"),  # every letter Cyrillic
        ("g\u03bf\u03bfgle", "google"),  # Greek omicrons
        ("rnicrosoft", "microsoft"),  # "rn" reads as "m"
        ("vvalmart", "walmart"),  # "vv" reads as "w"
        ("ｐａｙｐａｌ", "paypal"),  # full-width letters (NFKC)
        ("PayPal", "paypal"),
    ],
)
def test_skeleton(text, looks_like):
    assert skeleton(text) == looks_like


@pytest.mark.parametrize(
    ("word", "swaps"),
    [
        ("paypa1", '"1" for "l"'),
        ("micr0s0ft", '"0" for "o"'),  # each character once
        ("rnicr0soft", '"0" for "o", "rn" for "m"'),
        ("vvalmart", '"vv" for "w"'),
        ("p\u0430ypal", 'Cyrillic "\u0430" U+0430 for "a"'),  # the "\u0430" is Cyrillic
        ("g\u03bf\u03bfgle", 'Greek "\u03bf" U+03BF for "o"'),
        ("\u0261oogle", 'Latin "\u0261" U+0261 for "g"'),  # an IPA letter: Latin, but not ASCII
        ("paypal", ""),  # nothing fake
    ],
)
def test_describe_swaps_names_every_fake_character(word, swaps):
    """Week 4, step 5: "p\u0430ypal reads as paypal" explained nothing, as both look the same."""
    assert describe_swaps(word) == swaps


@pytest.mark.parametrize(
    ("a", "b", "distance"),
    [
        ("paypal", "paypal", 0),
        ("paypall", "paypal", 1),  # one letter more
        ("papal", "paypal", 1),  # one letter less
        ("paypol", "paypal", 1),  # one letter changed
        ("mircosoft", "microsoft", 1),  # two neighbours swapped: one edit, not two
        ("kitten", "sitting", 3),  # the textbook example
        ("", "dhl", 3),
        ("dhl", "", 3),
    ],
)
def test_edit_distance(a, b, distance):
    assert edit_distance(a, b) == distance
    assert edit_distance(b, a) == distance  # the same in both directions


@pytest.mark.parametrize(
    ("brand", "limit"),
    [("dhl", 0), ("apple", 0), ("paypal", 1), ("netflix", 1), ("docusign", 1), ("microsoft", 2)],
)
def test_edit_limit_grows_with_the_brand_name(brand, limit):
    assert edit_limit(brand) == limit


@pytest.mark.parametrize(
    ("label", "found"),
    [
        ("paypal", ["LATIN"]),
        ("p\u0430ypal", ["CYRILLIC", "LATIN"]),
        ("paypa1-2", ["LATIN"]),  # digits and "-" are not letters
        ("ශ්‍රීලංකා", ["SINHALA"]),
        ("123", []),
    ],
)
def test_scripts(label, found):
    assert scripts(label) == found


@pytest.mark.parametrize(
    ("label", "decoded"),
    [
        ("xn--pypal-4ve", "p\u0430ypal"),
        ("xn--mnchen-3ya", "münchen"),
        ("paypal", "paypal"),
        ("xn--", "xn--"),  # not valid punycode: kept as written
        ("xn--zz-!", "xn--zz-!"),
    ],
)
def test_decode_label(label, decoded):
    assert decode_label(label) == decoded


# --- one domain ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("host", "reason"),
    [
        (
            "paypa1-secure.test",
            'looks like paypal: look-alike characters in "paypa1" ("1" for "l")',
        ),
        ("micros0ft-account.test", 'look-alike characters in "micros0ft" ("0" for "o")'),
        ("rnicrosoft.test", 'look-alike characters in "rnicrosoft" ("rn" for "m")'),
        ("app1e.test", 'looks like apple: look-alike characters in "app1e" ("1" for "l")'),
        ("dh1.test", 'looks like dhl: look-alike characters in "dh1" ("1" for "l")'),
        ("paypall.test", 'looks like paypal: 1 letter different ("paypall")'),
        ("mircosoft.test", 'looks like microsoft: 1 letter different ("mircosoft")'),
        ("mlcrosofft.test", 'looks like microsoft: 2 letters different ("mlcrosofft")'),
        ("googie.test", 'looks like google: 1 letter different ("googie")'),
        ("pay-pal.test", 'looks like paypal: a hyphen splits the name ("pay-pal")'),
        ("net-flix.test", 'looks like netflix: a hyphen splits the name ("net-flix")'),
        # split by a hyphen AND a digit swap
        ("micro-s0ft.test", 'look-alike characters in "micro-s0ft" ("0" for "o")'),
        ("mi-rcosoft.test", 'looks like microsoft: 1 letter different ("mi-rcosoft")'),
        ("secure.paypa1.test", 'looks like paypal: look-alike characters in "paypa1"'),
        ("xn--pypal-4ve.com", "mixes Cyrillic and Latin letters"),
        (
            "xn--pypal-4ve.com",
            'look-alike characters in "p\u0430ypal" (Cyrillic "\u0430" U+0430 for "a")',
        ),
        (
            "xn--80ak6aa92e.com",
            'Cyrillic "\u0440" U+0440 for "p", Cyrillic "\u04cf" U+04CF for "l"',
        ),
        # a subdomain label that mixes alphabets: "\u0430ccount" with a Cyrillic "\u0430"
        ("xn--ccount-2nf.evil.test", "mixes Cyrillic and Latin letters"),
    ],
)
def test_lookalike_domains(host, reason):
    report = inspect_domain(host)
    assert any(reason in found for found in report.lookalike), report.lookalike
    assert report.brand_used == []


@pytest.mark.parametrize(
    ("host", "brands"),
    [
        ("paypal-secure-login.test", ["paypal"]),
        ("secure-paypal.test", ["paypal"]),
        ("paypal.com.evil.test", ["paypal"]),  # the brand in a label left of the real name
        ("docusign-review.test", ["docusign"]),
        ("paypal.github.io", ["paypal"]),  # a shared platform: anyone can pick that name
        ("amazon-paypal.test", ["amazon", "paypal"]),  # in the order the words appear
    ],
)
def test_brand_used_as_a_word(host, brands):
    report = inspect_domain(host)
    assert report.brand_used == brands
    assert report.lookalike == []


@pytest.mark.parametrize(
    "host",
    [
        "paypal.com",  # the real domains
        "em.paypal.com",
        "accountprotection.microsoft.com",
        # only the brand can create names under its own domain, whatever they are called
        "microsoft-account.microsoft.com",
        "paypa1.paypal.com",
        "outlook.com",
        "amazon.co.uk",  # the brand's own name on another ending: probably a country site
        "mail.amazon.in",
        "amazonses.com",  # a longer word is a different word
        "apply-now.test",  # "apply" is one letter from "apple": too short to compare
        "dhs.test",
        "offices.test",
        "payments.test",
        "xn--mnchen-3ya.de",  # punycode, but one alphabet and no brand: münchen.de
        "ｐａｙｐａｌ.com",  # full-width letters spell the real paypal.com
        "203.0.113.9",  # an IP has no registered domain
        "localhost",
        "",
    ],
)
def test_ordinary_and_real_domains_are_not_flagged(host):
    report = inspect_domain(host)
    assert report.lookalike == []
    assert report.brand_used == []


def test_a_unicode_domain_and_its_punycode_are_the_same_name():
    unicode, puny = inspect_domain("p\u0430ypal.com"), inspect_domain("xn--pypal-4ve.com")
    assert unicode.host == puny.host == "xn--pypal-4ve.com"
    assert unicode.decoded == puny.decoded == "p\u0430ypal.com"
    assert unicode.lookalike == puny.lookalike


def test_each_reason_is_given_once():
    report = inspect_domain("paypa1.paypa1-paypa1.test")
    assert len(report.lookalike) == len(set(report.lookalike)) == 1


# --- the checks on an email ------------------------------------------------------------------


def test_from_domain_lookalike():
    email = make_email(from_addr="service@paypa1.test", from_all=["service@paypa1.test"])
    findings = check_sender_domains(email)
    assert [f.rule for f in findings] == ["lookalike_sender_domain"]
    assert findings[0].detail == (
        'From domain paypa1.test looks like paypal: look-alike characters in "paypa1" ("1" for "l")'
    )


def test_reply_to_domain_is_checked_too():
    email = make_email(from_addr="service@paypal.com", reply_to_all=["help@paypa1-help.test"])
    findings = check_sender_domains(email)
    assert [f.rule for f in findings] == ["lookalike_sender_domain"]
    assert findings[0].detail.startswith("Reply-To domain paypa1-help.test")


def test_brand_in_sender_domain_detail_names_the_real_domains():
    email = make_email(from_addr="alerts@microsoft-security.test")
    findings = check_sender_domains(email)
    assert [f.rule for f in findings] == ["brand_in_sender_domain"]
    assert findings[0].detail == (
        "From domain microsoft-security.test uses the name microsoft but is not microsoft's "
        "(microsoft.com, office.com, outlook.com)"
    )


def test_both_findings_and_every_address_are_reported_once():
    email = make_email(
        from_addr="a@paypa1.test",
        from_all=["a@paypa1.test", "b@app1e.test"],
        reply_to_all=["c@paypa1.test", "d@paypal-help.test"],  # paypa1.test again: once
    )
    findings = {f.rule: f.detail for f in check_sender_domains(email)}
    assert findings["lookalike_sender_domain"].count("paypa1.test") == 1
    assert "From domain app1e.test" in findings["lookalike_sender_domain"]
    assert " | " in findings["lookalike_sender_domain"]  # two addresses, one finding
    assert findings["brand_in_sender_domain"].startswith("Reply-To domain paypal-help.test")


def test_punycode_is_shown_decoded_in_the_detail():
    email = make_email(from_addr="service@xn--pypal-4ve.com")
    detail = check_sender_domains(email)[0].detail
    assert detail.startswith("From domain xn--pypal-4ve.com (shown as p\u0430ypal.com) mixes")


@pytest.mark.parametrize(
    "fields",
    [
        {"from_addr": "service@paypal.com", "reply_to": "help@paypal.com"},
        {"from_addr": "news@shop.test"},
        {"from_addr": "", "from_all": []},  # no sender at all
        {"from_addr": "not-an-address"},
    ],
)
def test_no_findings_for_ordinary_senders(fields):
    assert check_sender_domains(make_email(**fields)) == []


def test_a_utf8_from_header_is_read_as_its_punycode(tmp_path):
    """RFC 6532 lets a header carry the Unicode name itself, not the xn-- spelling."""
    path = tmp_path / "utf8.eml"
    path.write_bytes("From: PayPal <service@p\u0430ypal.com>\nSubject: Hi\n\nhello\n".encode())
    findings = check_sender_domains(parse_eml(path))
    assert [f.rule for f in findings] == ["lookalike_sender_domain"]
    assert "xn--pypal-4ve.com (shown as p\u0430ypal.com)" in findings[0].detail


@pytest.mark.parametrize(
    ("name", "flagged"),
    [
        ("phish_paypal_spoof.eml", "Reply-To domain paypa1-secure.test"),
        ("phish_microsoft_format.eml", "From domain micros0ft-account.test"),
        ("legit_newsletter.eml", None),
        ("attachments_phish.eml", None),
        ("wrapped_links.eml", None),
    ],
)
def test_fixtures(fixtures, name, flagged):
    findings = check_sender_domains(parse_eml(fixtures / name))
    if flagged is None:
        assert findings == []
    else:
        assert [f.rule for f in findings] == ["lookalike_sender_domain"]
        assert findings[0].detail.startswith(flagged)


def test_the_report_shows_the_finding(fixtures):
    result = runner.invoke(app, ["analyze", str(fixtures / "phish_microsoft_format.eml")])
    assert result.exit_code == 2, result.output  # malicious (week 4 exit codes)
    assert "lookalike_sender_domain" in result.output
