"""Turn a raw .eml file into a ParsedEmail.

Safety: this module only reads bytes. It never renders HTML, opens attachments or
follows links. Attachments are hashed and nothing else. A forwarded email
(message/rfc822) is plain text, so it is parsed by this same code, never opened in a
mail client.

Week 2: emails forwarded as attachments are parsed on their own (email.forwarded), and
their parts no longer leak into the outer email's bodies and attachments. Each
attachment also gets its real file type and, for a ZIP, its file list (attachments.py).

Week 3, step 2: a From header with several addresses keeps them all (email.from_all), and
email.recipients collects every address the email was delivered to.
"""

from __future__ import annotations

import base64
import hashlib
from collections.abc import Iterator
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr
from pathlib import Path

from .attachments import inspect_bytes
from .models import Attachment, ParsedEmail

# How many forwards-inside-forwards we follow. Real reports rarely go past 2. The limit
# stops a crafted email with thousands of nested levels from using up memory and time.
MAX_FORWARD_DEPTH = 3

FORWARDED_TYPE = "message/rfc822"

# Headers that name the people an email was delivered to. To and Cc are written by the
# sender; Delivered-To and X-Original-To are added by the receiving mail server.
RECIPIENT_HEADERS = ("To", "Cc", "Delivered-To", "X-Original-To")


def parse_eml(path: str | Path) -> ParsedEmail:
    """Parse one .eml file. Problems are recorded in `defects` instead of crashing."""
    path = Path(path)
    with path.open("rb") as fh:
        msg = BytesParser(policy=policy.default).parse(fh)
    return parse_message(msg, path)


def parse_message(msg: EmailMessage, path: Path, depth: int = 0) -> ParsedEmail:
    """Turn an already-parsed message into a ParsedEmail.

    parse_eml() calls this for the file itself (depth 0). _read_forwarded() calls it again
    for each forwarded email inside (depth 1, 2, ...), so both get exactly the same checks.
    """
    email = ParsedEmail(path=path, depth=depth)
    bad = email.defects

    email.subject = _first(msg, "Subject", bad)

    # Every From address. parseaddr() returns nothing at all for "a@x.test, b@y.test" (the
    # same trap as Reply-To in week 2), so the first address is taken from the full list.
    from_header = _all(msg, "From", bad)
    senders = _addresses(from_header)
    if senders:
        email.from_name, email.from_addr = senders[0]
    elif from_header:
        bad.append("From header has no readable address")
    email.from_all = list(dict.fromkeys(address for _, address in senders))  # no repeats

    # Every Reply-To address, for the same reason (found by the Week 2 gate)
    email.reply_to_all = [address for _, address in _addresses(_all(msg, "Reply-To", bad))]
    email.reply_to = email.reply_to_all[0] if email.reply_to_all else ""
    email.return_path = _address(_first(msg, "Return-Path", bad))[1]
    email.to = [addr.lower() for _, addr in getaddresses(_all(msg, "To", bad)) if addr]
    email.recipients = _recipients(msg, bad)
    email.date = _first(msg, "Date", bad)
    email.message_id = _first(msg, "Message-ID", bad)
    email.received = _all(msg, "Received", bad)
    email.auth_results_headers = _all(msg, "Authentication-Results", bad)
    bad.extend(type(d).__name__ for d in msg.defects)

    _read_parts(msg, email)
    return email


# --- headers -------------------------------------------------------------------------


def _all(msg: EmailMessage, name: str, bad: list[str]) -> list[str]:
    """Every value of a header, top of the email first, with folded lines joined."""
    try:
        return [" ".join(str(value).split()) for value in msg.get_all(name, [])]
    except Exception as exc:  # a badly broken header must not stop the whole run
        bad.append(f"Could not read {name} header: {type(exc).__name__}")
        return []


def _first(msg: EmailMessage, name: str, bad: list[str]) -> str:
    values = _all(msg, name, bad)
    return values[0] if values else ""


def _address(value: str) -> tuple[str, str]:
    """'"PayPal" <Service@PayPal.com>' -> ('PayPal', 'service@paypal.com')."""
    if not value:
        return "", ""
    name, addr = parseaddr(value)
    return name.strip(), addr.strip().lower()


def _addresses(values: list[str]) -> list[tuple[str, str]]:
    """(display name, address) for every address in these header values, in order.

        ['"PayPal" <Service@PayPal.com>, x@evil.test']
            -> [('PayPal', 'service@paypal.com'), ('', 'x@evil.test')]
        ['undisclosed-recipients:;']  -> []    (a group name with no address in it)
        ['"Doe, John" <john@x.test>'] -> [('Doe, John', 'john@x.test')]   (one address)

    getaddresses() splits on commas outside quotes. Anything without an "@" is dropped.
    """
    return [
        (name.strip(), address.strip().lower())
        for name, address in getaddresses(values)
        if "@" in address
    ]


def _recipients(msg: EmailMessage, bad: list[str]) -> list[str]:
    """Every address in RECIPIENT_HEADERS, lower-case, without repeats, in header order."""
    found: list[str] = []
    for header in RECIPIENT_HEADERS:
        found.extend(address for _, address in _addresses(_all(msg, header, bad)))
    return list(dict.fromkeys(found))  # dict keeps insertion order (Java: LinkedHashSet)


# --- bodies and attachments ----------------------------------------------------------


def walk_parts(msg: EmailMessage) -> Iterator[EmailMessage]:
    """Every part of the email in order, like msg.walk(), but it does not go inside
    forwarded emails: those are parsed separately by _read_forwarded().

    It uses a stack instead of recursion (Java: a Deque used with push/pop), so a deeply
    nested email cannot hit Python's recursion limit.
    """
    stack = [msg]
    while stack:
        part = stack.pop()
        yield part  # a generator: hands back one part at a time, like a Java Iterator
        if part.is_multipart() and part.get_content_type() != FORWARDED_TYPE:
            # Push children in reverse so the first child is popped (and yielded) first.
            stack.extend(reversed(list(part.iter_parts())))


def _read_parts(msg: EmailMessage, email: ParsedEmail) -> None:
    text_parts: list[str] = []
    html_parts: list[str] = []

    for part in walk_parts(msg):
        content_type = part.get_content_type()

        if content_type == FORWARDED_TYPE:
            _read_forwarded(part, email)
            continue
        if part.is_multipart():
            continue  # containers only; walk_parts() visits their children

        filename = part.get_filename()

        if filename or part.get_content_disposition() == "attachment":
            payload = part.get_payload(decode=True) or b""
            attachment = _attachment(filename or "(no name)", content_type, payload)
            inspect_bytes(attachment, payload, email.defects)  # real type, ZIP file list
            email.attachments.append(attachment)
        elif content_type == "text/plain":
            text_parts.append(_decode_text(part, email))
        elif content_type == "text/html":
            html_parts.append(_decode_text(part, email))

        email.defects.extend(type(d).__name__ for d in part.defects)

    email.text_body = "\n".join(text_parts)
    email.html_body = "\n".join(html_parts)


def _read_forwarded(part: EmailMessage, email: ParsedEmail) -> None:
    """Parse an email attached as message/rfc822 on its own and add it to email.forwarded."""
    if email.depth >= MAX_FORWARD_DEPTH:
        email.defects.append(
            f"Forwarded email nested more than {MAX_FORWARD_DEPTH} levels deep: not analysed"
        )
        return
    try:
        inner = _forwarded_message(part, email)
    except Exception as exc:  # one broken forward must not stop the rest of the analysis
        email.defects.append(f"Could not read forwarded email: {type(exc).__name__}")
        return
    email.forwarded.append(parse_message(inner, email.path, email.depth + 1))


def _forwarded_message(part: EmailMessage, email: ParsedEmail) -> EmailMessage:
    """The email inside a message/rfc822 part.

    RFC 2046 says this part must not be base64-encoded, but some mail systems do it anyway.
    Python then reads the base64 text as the body of an email with no headers, so in that
    case we decode the base64 ourselves and parse the result as an email.
    """
    inner = part.get_content()
    encoding = str(part.get("Content-Transfer-Encoding", "")).strip().lower()
    if encoding == "base64":
        email.defects.append("Forwarded email was base64-encoded (not allowed by RFC 2046)")
        raw = base64.b64decode(inner.get_payload())
        inner = BytesParser(policy=policy.default).parsebytes(raw)
    return inner


def _decode_text(part: EmailMessage, email: ParsedEmail) -> str:
    try:
        return part.get_content()
    except Exception as exc:  # unknown or wrong charset is common in spam
        email.defects.append(f"{type(exc).__name__} decoding {part.get_content_type()} part")
        payload = part.get_payload(decode=True) or b""
        return payload.decode("utf-8", errors="replace")


def _attachment(filename: str, content_type: str, payload: bytes) -> Attachment:
    return Attachment(
        filename=filename,
        content_type=content_type,
        size=len(payload),
        md5=hashlib.md5(payload).hexdigest(),
        sha1=hashlib.sha1(payload).hexdigest(),
        sha256=hashlib.sha256(payload).hexdigest(),
    )
