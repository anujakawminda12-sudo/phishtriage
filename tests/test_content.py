"""Tests for content.py: pressure and credential-request wording (week 4, step 6)."""

from pathlib import Path

import pytest

from phishtriage.content import (
    CREDENTIAL_REQUEST,
    URGENCY,
    check_wording,
    find_phrases,
    normalise,
    visible_html_text,
)
from phishtriage.models import ParsedEmail
from phishtriage.parser import parse_eml


def wording(subject: str = "", text: str = "", html: str = "", **fields) -> dict[str, str]:
    """rule -> detail for check_wording on a hand-built email."""
    email = ParsedEmail(
        path=Path("t.eml"), subject=subject, text_body=text, html_body=html, **fields
    )
    return {finding.rule: finding.detail for finding in check_wording(email)}


# --- normalise: tricks to dodge keyword filters do not work ----------------------------


@pytest.mark.parametrize(
    ("raw", "clean"),
    [
        ("Verify   your\nACCOUNT", "verify your account"),
        ("ver\u200bify your acc\u200dount", "verify your account"),  # zero-width characters
        ("veri\u00adfy", "verify"),  # a soft hyphen
        ("verify your \u0430ccount", "verify your account"),  # a Cyrillic "\u0430"
        ("\u0412erify", "\u0432erify"),  # a capital Cyrillic "\u0412" is no look-alike of "v"
        ("ｖｅｒｉｆｙ", "verify"),  # full-width letters (NFKC)
        ("within\u00a024 hours", "within 24 hours"),  # a non-breaking space
        ("within 15 days", "within 15 days"),  # digits are not look-alikes here
        ("you\u2019re", "you're"),  # a curly apostrophe
        ("", ""),
    ],
)
def test_normalise(raw, clean):
    assert normalise(raw) == clean


def test_visible_html_text_leaves_out_style_and_script():
    html = (
        "<style>.a{content:'verify your account'}</style>"
        "<script>var x = 'within 24 hours';</script><p>Hello</p>"
    )
    assert visible_html_text(html).strip() == "Hello"
    assert visible_html_text("  ") == ""


# --- the phrases --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "this is urgent",
        "please respond urgently",
        "immediate action is needed",
        "act immediately",
        "action required: your mailbox",
        "action is required",
        "verify within 24 hours",
        "within 48 hrs",
        "within twenty-four hours",
        "within the next 3 days",
        "final notice",
        "last warning",
        "your account has been suspended",
        "your account will be permanently deleted",
        "your mailbox is locked",
        "access was restricted",
        "unusual sign-in activity",
        "suspicious login attempts",
        "unauthorised access",
        "unauthorized sign-ins",
        "your subscription expires today",
        "expiring tonight",
        "to avoid suspension",
        "prevent losing access",
        "failure to verify will",
    ],
)
def test_urgency_phrases(text):
    assert find_phrases(normalise(text), URGENCY), text


@pytest.mark.parametrize(
    "text",
    [
        "verify your account",
        "confirm your identity",
        "validate your login",
        "reconfirm your sign-in",
        "confirm your billing",
        "update your payment details",
        "update your card information",
        "update billing method",
        "your password expires today",
        "your password will expire",
        "password has expired",
        "keep your current password",
        "keep the same password",
        "enter your password",
        "re-enter your credentials",
        "provide your pin",
        "sign in now to verify",
        "log in to restore",
        "login to keep",
        "unlock your account",
        "restore access",
        "reactivate your mailbox",
        "your mailbox is full",
        "storage is almost full",
        "inbox is over its quota",
    ],
)
def test_credential_request_phrases(text):
    assert find_phrases(normalise(text), CREDENTIAL_REQUEST), text


@pytest.mark.parametrize(
    "text",
    [
        "our office will be closed on monday",  # closed, but not an account
        "please verify your email address",  # every genuine sign-up asks for this
        "confirm your email",
        "please find your invoice and payment details attached",
        "report suspicious emails to the it team",
        "a phishing campaign is targeting staff",
        "offer ends soon",
        "your order has shipped",
        "here are this month's offers",
        "we'll update you within the week",
        "this password manager keeps you safe",
        "the store is full of gifts",
    ],
)
def test_ordinary_sentences_are_not_flagged(text):
    clean = normalise(text)
    assert find_phrases(clean, URGENCY) == []
    assert find_phrases(clean, CREDENTIAL_REQUEST) == []


def test_find_phrases_keeps_the_first_of_each_in_order():
    text = normalise("Urgent: within 24 hours. URGENT again, within 24 hours, final notice")
    assert find_phrases(text, URGENCY) == ["urgent", "within 24 hours", "final notice"]
    # "urgent" comes again after "final notice": its first place still counts
    assert find_phrases(normalise("Urgent: final notice. Urgent!"), URGENCY) == [
        "urgent",
        "final notice",
    ]


def test_find_phrases_follows_the_text_not_the_pattern_list():
    """ "final notice" comes after "immediately" in URGENCY, but first in this text."""
    text = normalise("Final notice: act immediately")
    assert find_phrases(text, URGENCY) == ["final notice", "immediately"]


# --- check_wording -----------------------------------------------------------------------


def test_both_findings_say_where_and_what():
    found = wording(
        subject="Your account has been suspended",
        text="Verify your account within 24 hours.",
    )
    assert found == {
        "urgency_wording": (
            'Pressure to act quickly, in the subject and the body: "account has been '
            'suspended", "within 24 hours"'
        ),
        "credential_request_wording": (
            'Asks for a login, password or payment, in the body: "verify your account"'
        ),
    }


def test_the_text_and_html_bodies_are_read_together_and_repeats_shown_once():
    found = wording(text="Final notice.", html="<p>FINAL NOTICE: act <b>immediately</b></p>")
    assert found["urgency_wording"] == (
        'Pressure to act quickly, in the body: "final notice", "immediately"'
    )


def test_at_most_three_phrases_are_quoted():
    text = "Urgent! Final notice. Within 24 hours. Your account has been locked. Act immediately."
    detail = wording(text=text)["urgency_wording"]
    assert detail.count('"') == 6  # three phrases
    assert detail.endswith(" and 2 more")


def test_a_hidden_trick_is_still_caught():
    """A zero-width space and a Cyrillic "\u0430" do not hide "verify your account"."""
    found = wording(html="<p>Ver\u200bify your \u0430ccount</p>")
    assert found["credential_request_wording"].endswith('"verify your account"')


def test_text_in_style_or_script_is_not_read():
    html = "<style>p{}/* verify your account */</style><script>// final notice</script><p>Hi</p>"
    assert wording(html=html) == {}


def test_the_subject_of_an_email_that_forwards_another_is_skipped():
    """Nimal's "Fwd: Your password expires today" repeats the phish's subject."""
    forwarded = ParsedEmail(path=Path("inner.eml"), subject="Your password expires today")
    assert wording(subject="Fwd: Your password expires today", forwarded=[forwarded]) == {}
    # without the forwarded email, the same subject is read
    assert "credential_request_wording" in wording(subject="Fwd: Your password expires today")


def test_an_ordinary_email_has_no_findings():
    assert (
        wording(subject="Your November newsletter", text="Hi, here are this month's offers") == {}
    )
    assert wording() == {}


@pytest.mark.parametrize(
    ("name", "rules"),
    [
        ("phish_paypal_spoof.eml", {"urgency_wording", "credential_request_wording"}),
        ("phish_microsoft_format.eml", {"urgency_wording"}),
        ("forwarded_phish.eml", set()),  # Nimal's own note is clean
        ("legit_newsletter.eml", set()),
        ("wrapped_links.eml", set()),  # an IT security notice: "phishing", "suspicious emails"
        ("attachments_phish.eml", set()),  # an invoice lure, with no pressure wording
        ("phish_open_redirect.eml", set()),
    ],
)
def test_fixtures(fixtures, name, rules):
    assert {finding.rule for finding in check_wording(parse_eml(fixtures / name))} == rules


def test_the_forwarded_phish_is_checked_on_its_own(fixtures):
    inner = parse_eml(fixtures / "forwarded_phish.eml").forwarded[0]
    found = {finding.rule: finding.detail for finding in check_wording(inner)}
    assert found["credential_request_wording"] == (
        "Asks for a login, password or payment, in the subject and the body: "
        '"password expires", "keep your current password"'
    )
