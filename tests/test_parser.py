import base64
import hashlib
from email.message import EmailMessage

from phishtriage import parser
from phishtriage.parser import MAX_FORWARD_DEPTH, parse_eml

ATTACHMENT_BYTES = (
    b"<html><body><p>Harmless PhishTriage test file. Not malware.</p></body></html>\n"
)


def test_legit_email_headers(fixtures):
    email = parse_eml(fixtures / "legit_newsletter.eml")
    assert email.subject == "Your November newsletter"
    assert email.from_name == "Example Store"
    assert email.from_addr == "news@example.com"
    assert email.reply_to == ""
    assert email.return_path == "bounce@example.com"
    assert email.to == ["student@example.org"]
    assert len(email.received) == 1
    assert len(email.auth_results_headers) == 1


def test_legit_email_bodies(fixtures):
    email = parse_eml(fixtures / "legit_newsletter.eml")
    assert "this month's offers" in email.text_body
    assert '<a href="https://www.example.com/offers">' in email.html_body
    assert email.attachments == []
    assert email.defects == []
    assert email.forwarded == []


def test_phish_email_headers(fixtures):
    email = parse_eml(fixtures / "phish_paypal_spoof.eml")
    assert email.from_name == "PayPal Security"
    assert email.from_addr == "service@paypal.com"
    assert email.reply_to == "support@paypa1-secure.test"
    assert email.return_path == "bounce@mailer-7731.test"
    assert len(email.auth_results_headers) == 2  # the real one plus a forged one


def test_phish_attachment_is_hashed_not_opened(fixtures):
    email = parse_eml(fixtures / "phish_paypal_spoof.eml")
    assert len(email.attachments) == 1
    att = email.attachments[0]
    assert att.filename == "Account_Review.html"
    assert att.content_type == "text/html"
    assert att.size == len(ATTACHMENT_BYTES)
    assert att.sha256 == hashlib.sha256(ATTACHMENT_BYTES).hexdigest()
    assert att.md5 == hashlib.md5(ATTACHMENT_BYTES).hexdigest()
    # The attachment must not leak into the email body
    assert "Harmless PhishTriage test file" not in email.html_body


def test_broken_email_does_not_crash(fixtures):
    email = parse_eml(fixtures / "broken_charset.eml")
    assert email.subject == "Broken charset test"
    assert "Body with an unknown charset" in email.text_body
    assert email.defects  # the bad charset is recorded, not raised


# --- Week 2 step 3: emails forwarded as attachments (message/rfc822) -----------------


def test_forwarded_email_is_parsed_on_its_own(fixtures):
    outer = parse_eml(fixtures / "forwarded_phish.eml")
    assert outer.depth == 0
    assert outer.from_addr == "nimal@example.org"
    assert outer.subject == "Fwd: Your password expires today"
    assert len(outer.forwarded) == 1

    inner = outer.forwarded[0]
    assert inner.depth == 1
    assert inner.from_name == "Microsoft 365 Admin"
    assert inner.from_addr == "no-reply@micros0ft-support.test"
    assert inner.return_path == "bounce@mailer-4410.test"
    assert inner.subject == "Your password expires today"
    assert len(inner.received) == 1
    assert len(inner.auth_results_headers) == 1


def test_forwarded_parts_do_not_leak_into_the_outer_email(fixtures):
    outer = parse_eml(fixtures / "forwarded_phish.eml")
    inner = outer.forwarded[0]

    # The outer email only has Nimal's note: no inner text, no inner HTML, no attachments
    assert "I think it is phishing" in outer.text_body
    assert "password expires" not in outer.text_body
    assert outer.html_body == ""
    assert outer.attachments == []

    # The inner email keeps its own bodies and its own attachment
    assert "micros0ft-login.test" in inner.text_body
    assert 'href="http://micros0ft-login.test/auth?user=nimal"' in inner.html_body
    assert [att.filename for att in inner.attachments] == ["Password_Policy.txt"]
    assert inner.forwarded == []


def _nested_forwards(levels: int) -> bytes:
    """An email with `levels` forwards nested inside each other, built in memory."""
    message = EmailMessage()
    message["From"] = f"level{levels}@example.test"
    message["Subject"] = f"level {levels}"
    message.set_content("the innermost email")
    for level in range(levels - 1, -1, -1):
        outer = EmailMessage()
        outer["From"] = f"level{level}@example.test"
        outer["Subject"] = f"level {level}"
        outer.set_content(f"note at level {level}")
        outer.add_attachment(message)  # attaches it as message/rfc822
        message = outer
    return message.as_bytes()


def test_nested_forwards_stop_at_the_depth_limit(tmp_path):
    path = tmp_path / "nested.eml"
    path.write_bytes(_nested_forwards(MAX_FORWARD_DEPTH + 2))

    email = parse_eml(path)
    subjects = []
    while email.forwarded:
        email = email.forwarded[0]
        subjects.append(email.subject)

    assert subjects == ["level 1", "level 2", "level 3"]  # stops at MAX_FORWARD_DEPTH
    assert email.depth == MAX_FORWARD_DEPTH
    assert any("nested more than" in defect for defect in email.defects)


def test_base64_encoded_forward_is_decoded(tmp_path):
    inner = b"From: Inner <inner@example.test>\r\nSubject: inner\r\n\r\nhello from inside\r\n"
    raw = (
        b"From: Outer <outer@example.test>\r\nSubject: outer\r\nMIME-Version: 1.0\r\n"
        b'Content-Type: multipart/mixed; boundary="b"\r\n\r\n'
        b"--b\r\nContent-Type: text/plain\r\n\r\nouter note\r\n"
        b"--b\r\nContent-Type: message/rfc822\r\nContent-Transfer-Encoding: base64\r\n\r\n"
        + base64.encodebytes(inner)
        + b"--b--\r\n"
    )
    path = tmp_path / "base64_forward.eml"
    path.write_bytes(raw)

    outer = parse_eml(path)
    assert outer.forwarded[0].from_addr == "inner@example.test"
    assert "hello from inside" in outer.forwarded[0].text_body
    assert any("base64" in defect for defect in outer.defects)
    # Week 1 code put the raw base64 text into the body; now it is decoded instead
    assert base64.b64encode(inner).decode()[:20] not in outer.text_body


def test_broken_forward_is_recorded_not_raised(fixtures, monkeypatch):
    def broken(part, email):
        raise ValueError("simulated broken forwarded email")

    monkeypatch.setattr(parser, "_forwarded_message", broken)
    outer = parse_eml(fixtures / "forwarded_phish.eml")
    assert outer.forwarded == []
    assert "Could not read forwarded email: ValueError" in outer.defects
    assert "I think it is phishing" in outer.text_body  # the rest was still parsed


def test_every_reply_to_address_is_kept(tmp_path):
    path = tmp_path / "two_reply_to.eml"
    path.write_text(
        "From: Shop <hello@shop.test>\nTo: student@example.org\n"
        "Reply-To: Shop <Hello@Shop.test>, cert@shop.test\nSubject: Order\n\nThanks\n",
        encoding="utf-8",
    )
    email = parse_eml(path)
    assert email.reply_to == "hello@shop.test"  # the first, as before
    assert email.reply_to_all == ["hello@shop.test", "cert@shop.test"]


# --- Week 3 step 2: every From address, and every recipient ---------------------------


def _write(tmp_path, name: str, text: str):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def test_from_with_two_addresses_keeps_both(tmp_path):
    # Week 2: parseaddr() gave ("", "") here, so the email looked as if it had no sender
    path = _write(
        tmp_path,
        "two_from.eml",
        'From: "PayPal Security" <Alerts@Paypa1-Secure.test>, other@else.test\n'
        "Subject: Verify\n\nhello\n",
    )
    email = parse_eml(path)
    assert email.from_name == "PayPal Security"
    assert email.from_addr == "alerts@paypa1-secure.test"  # the first, lower-case
    assert email.from_all == ["alerts@paypa1-secure.test", "other@else.test"]
    assert email.defects == []


def test_quoted_comma_in_a_display_name_is_one_address(tmp_path):
    path = _write(tmp_path, "comma.eml", 'From: "Doe, John" <john@x.test>\nSubject: Hi\n\nhi\n')
    email = parse_eml(path)
    assert (email.from_name, email.from_addr) == ("Doe, John", "john@x.test")
    assert email.from_all == ["john@x.test"]


def test_same_from_address_twice_counts_once(tmp_path):
    path = _write(tmp_path, "twice.eml", "From: a@x.test, A@X.test\nSubject: Hi\n\nhi\n")
    assert parse_eml(path).from_all == ["a@x.test"]


def test_from_without_an_address_is_a_defect(tmp_path):
    path = _write(tmp_path, "no_address.eml", "From: not an address\nSubject: Hi\n\nhi\n")
    email = parse_eml(path)
    assert email.from_addr == ""
    assert email.from_all == []
    assert "From header has no readable address" in email.defects


def test_recipients_come_from_every_delivery_header(tmp_path):
    # Sent in Bcc: To names nobody, but the receiving server's headers name the mailbox
    path = _write(
        tmp_path,
        "bcc.eml",
        "From: shop@shop.test\nTo: undisclosed-recipients:;\nCc: Friend <Friend@Example.org>\n"
        "Delivered-To: Me.Victim@example.org\nX-Original-To: me.victim@example.org\n"
        "Subject: Offer\n\nhi\n",
    )
    email = parse_eml(path)
    assert email.to == []
    assert email.recipients == ["friend@example.org", "me.victim@example.org"]  # no repeats
