"""Tests for evaluate.py: the week 2 gate tooling."""

import shutil
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser

from phishtriage.evaluate import (
    TEMPLATE,
    compare,
    decoded_view,
    normalise,
    parse_hand_check,
    tool_values,
    write_templates,
)
from phishtriage.parser import MAX_FORWARD_DEPTH, parse_eml


def read_message(path) -> EmailMessage:
    with open(path, "rb") as fh:
        return BytesParser(policy=policy.default).parse(fh)


# A hand check of phish_paypal_spoof.eml with two deliberate mistakes:
# mailer-7731.test is forgotten, and evil.test was never in the email
PAYPAL_CHECK = """
# my notes
[domains]
WWW.PayPal.com
paypa1-secure[.]test      # defanged is fine
paypal.com
evil.test

[ips]
203.0.113.45

[emails]
service@paypal.com
support[@]paypa1-secure[.]test
bounce@mailer-7731.test

[attachments]
Account_Review.html

[urls]
"""


def test_parse_hand_check():
    values = parse_hand_check(PAYPAL_CHECK + "[unknown]\nignored.test\n")
    assert values["domains"] == {"www.paypal.com", "paypa1-secure.test", "paypal.com", "evil.test"}
    assert values["emails"] == {
        "service@paypal.com",
        "support@paypa1-secure.test",
        "bounce@mailer-7731.test",
    }
    assert values["urls"] == set()
    assert "ignored.test" not in str(values)


def test_normalise_writes_values_like_the_tool():
    assert normalise("domains", "Bücher.de.") == "xn--bcher-kva.de"
    assert normalise("ips", "2001:DB8:0::1") == "2001:db8::1"
    assert normalise("ips", "not an ip") == "not an ip"
    assert normalise("emails", "A[@]Shop[.]test") == "a@shop.test"
    assert normalise("attachments", " Invoice.PDF ") == "Invoice.PDF"
    # a link pasted from the raw HTML: &amp; decoded and the Safe Links wrapper removed
    pasted = (
        "https://nam12.safelinks.protection.outlook.com/?url=https%3A%2F%2Fx.test%2Fa"
        "&amp;data=abc&amp;reserved=0"
    )
    assert normalise("urls", pasted) == "https://x.test/a"


def test_compare_finds_matches_misses_and_extras(fixtures):
    found = tool_values(parse_eml(fixtures / "phish_paypal_spoof.eml"))
    results = compare(parse_hand_check(PAYPAL_CHECK), found)
    assert results["domains"].missed == {"evil.test"}  # in my list, not in the email
    assert results["domains"].extra == {"mailer-7731.test"}  # the tool found what I forgot
    assert len(results["domains"].matched) == 3
    for section in ["ips", "emails", "attachments"]:
        assert not results[section].missed and not results[section].extra, section
    assert "urls" not in results  # an empty [urls] section is not checked


def test_tool_values_include_forwarded_emails(fixtures):
    found = tool_values(parse_eml(fixtures / "forwarded_phish.eml"))
    assert found["emails"] == {
        "nimal@example.org",
        "no-reply@micros0ft-support.test",
        "bounce@mailer-4410.test",
    }
    assert found["attachments"] == {"Password_Policy.txt"}
    assert found["ips"] == {"203.0.113.77"}


def test_write_templates_never_overwrites(fixtures, tmp_path):
    shutil.copy(fixtures / "legit_newsletter.eml", tmp_path)
    shutil.copy(fixtures / "phish_paypal_spoof.eml", tmp_path)
    (tmp_path / "expected").mkdir()
    mine = tmp_path / "expected" / "phish_paypal_spoof.txt"
    mine.write_text(PAYPAL_CHECK, encoding="utf-8")

    created = write_templates(tmp_path)
    assert created == [tmp_path / "expected" / "legit_newsletter.txt"]
    assert mine.read_text(encoding="utf-8") == PAYPAL_CHECK  # untouched
    assert created[0].read_text(encoding="utf-8") == TEMPLATE.format(
        name="legit_newsletter.eml", decoded="legit_newsletter.decoded.txt"
    )
    # a decoded copy for reading is written next to each template
    assert (tmp_path / "expected" / "legit_newsletter.decoded.txt").exists()
    # a blank template expects nothing, so everything the tool finds is "extra"
    blank = parse_hand_check(TEMPLATE)
    assert all(not values for values in blank.values())


# --- the decoded copy used for hand-checking -----------------------------------------


def test_decoded_view_undoes_quoted_printable():
    raw = (
        b"From: a@shop.test\r\nSubject: QP\r\nContent-Type: text/html\r\n"
        b"Content-Transfer-Encoding: quoted-printable\r\n\r\n"
        b'<a href=3D"https://shop.test/offer?id=3D42&amp;ref=3Dmail-news=\r\nletter">x</a>\r\n'
    )
    view = decoded_view(BytesParser(policy=policy.default).parsebytes(raw))
    assert "Subject: QP" in view
    # "=3D" became "=", the soft line break "=" + newline was joined, and the link is
    # written hxxps:// so an editor does not make it clickable
    assert 'href="hxxps://shop.test/offer?id=42&amp;ref=mail-newsletter"' in view


def test_decoded_view_of_a_forwarded_email(fixtures):
    view = decoded_view(read_message(fixtures / "forwarded_phish.eml"))
    assert "===== forwarded email (level 1) =====" in view
    assert "no-reply@micros0ft-support.test" in view  # the inner email's headers
    assert "hxxp://micros0ft-login.test/auth?user=nimal" in view
    assert "[attachment: Password_Policy.txt (text/plain), not decoded]" in view
    assert "SGFybWxlc3M" not in view  # the attachment's base64 content is not shown
    assert "http://" not in view and "https://" not in view


def test_decoded_view_stops_at_the_depth_limit():
    message = EmailMessage()
    message["Subject"] = "innermost"
    message.set_content("deep")
    for _ in range(MAX_FORWARD_DEPTH + 1):
        outer = EmailMessage()
        outer["Subject"] = "outer"
        outer.set_content("note")
        outer.add_attachment(message)
        message = outer
    view = decoded_view(message)
    assert "[forwarded email nested too deep: not shown]" in view
    assert "innermost" not in view


def test_decoded_view_survives_an_unknown_charset(fixtures):
    view = decoded_view(read_message(fixtures / "broken_charset.eml"))
    assert "Body with an unknown charset" in view
