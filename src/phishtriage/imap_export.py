"""Download emails from Gmail as .eml files, all from the terminal (week 3, step 13).

For the legit sets. Two ways to choose the emails:
- a label you put on them in Gmail's web page, or
- a Gmail search (--search "from:sliit.lk newer_than:6m"), using the same words as Gmail's
  search box. Gmail's IMAP server understands them through its X-GM-RAW extension.
--list shows the date, sender and subject of every match and downloads nothing, so you can
check that each one is an email you know is genuine before you download.

Safety:
- the label is opened read-only (IMAP EXAMINE) and each email is fetched with BODY.PEEK[],
  so nothing in Gmail is marked as read, moved, flagged or deleted
- the bytes are saved exactly as Gmail sent them: never parsed, opened or rendered
  (--list reads only the Date, From and Subject headers, and prints them escaped)
- files are named uid-N.eml, so no subject line ends up in a file name
- the password is typed at a hidden prompt: not shown, not in your shell history, never saved
- use a Google app password (it needs 2-Step Verification), and delete it at
  myaccount.google.com/apppasswords when you are done
- the folder and files are private to you (0700 and 0600): they are your personal emails

This never runs during `analyze`: it is a separate command you start yourself.

Java comparison: imaplib is like javax.mail's IMAPStore, but most calls return a pair
(status, data) instead of throwing, so the code checks the status itself.
"""

from __future__ import annotations

import contextlib
import imaplib
import os
import ssl
from collections.abc import Callable
from dataclasses import dataclass
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Protocol

GMAIL_HOST = "imap.gmail.com"
TIMEOUT_SECONDS = 30
FETCH_WHOLE_EMAIL = "(BODY.PEEK[])"  # PEEK: reading it does not mark it as read
FETCH_HEADERS = "(BODY.PEEK[HEADER.FIELDS (DATE FROM SUBJECT)])"  # for --list
# progress(done, total): called after each email (week 4). Java: BiConsumer<Integer, Integer>
Progress = Callable[[int, int], None]


class ImapClient(Protocol):
    """The imaplib calls used here. Like a Java interface, except a test's fake does not have
    to say `implements`: it only needs methods with these names (structural typing)."""

    def select(self, mailbox: str = ..., readonly: bool = ...) -> tuple[str, list]: ...

    def uid(self, command: str, *args: str) -> tuple[str, list]: ...


class ExportError(Exception):
    """A problem you can fix (wrong label, login refused): shown as a message, no traceback."""


@dataclass
class ExportResult:
    saved: int = 0
    failed: int = 0  # emails Gmail did not send back


@dataclass(frozen=True)
class Listed:
    """One line of --list: what you need to recognise an email, nothing more."""

    date: str
    sender: str
    subject: str


def imap_quote(text: str) -> str:
    """An IMAP quoted string: labels and searches can have spaces or quotes in them."""
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def has_files(folder: Path) -> bool:
    return folder.exists() and any(folder.iterdir())


def connect(user: str, password: str, host: str = GMAIL_HOST) -> imaplib.IMAP4_SSL:
    """Log in over TLS (port 993), checking the server's certificate. Raises ExportError."""
    try:
        client = imaplib.IMAP4_SSL(
            host, ssl_context=ssl.create_default_context(), timeout=TIMEOUT_SECONDS
        )
    except (OSError, imaplib.IMAP4.error) as error:
        raise ExportError(f"could not reach {host} ({type(error).__name__})") from None
    try:
        client.login(user, password)
    except imaplib.IMAP4.error:
        # The server's reply is not shown: the message below says what to do instead
        with contextlib.suppress(Exception):
            client.logout()
        raise ExportError(
            "Gmail refused the login. Use an app password from "
            "myaccount.google.com/apppasswords, not your normal password."
        ) from None
    return client


def find_uids(
    client: ImapClient, label: str, search: str | None = None, newest: int | None = None
) -> list[str]:
    """The UIDs of the matching emails in `label`, oldest first (only the newest N if asked)."""
    if search is not None and not search.isascii():  # checked before Gmail is asked anything
        raise ExportError("--search must be plain ASCII, e.g. from:sliit.lk newer_than:6m")
    status, _ = client.select(imap_quote(label), readonly=True)  # read-only: EXAMINE
    if status != "OK":
        raise ExportError(
            f"Gmail has no label called {label!r}. Labels are case-sensitive, and the "
            "label needs 'Show in IMAP' ticked in Gmail's label settings."
        )
    if search is None:
        status, data = client.uid("SEARCH", "ALL")
    else:
        status, data = client.uid("SEARCH", "X-GM-RAW", imap_quote(search))
    if status != "OK":
        raise ExportError("Gmail did not accept the search" if search else "Gmail sent no list")
    uids = [uid.decode("ascii") for uid in data[0].split()] if data and data[0] else []
    return uids[-newest:] if newest else uids


def export_label(
    client: ImapClient,
    label: str,
    out: Path,
    search: str | None = None,
    newest: int | None = None,
    progress: Progress | None = None,
) -> ExportResult:
    """Save every matching email into `out` as uid-N.eml. Changes nothing in Gmail.

    progress(done, total) is called after each email, saved or not.
    """
    if has_files(out):
        raise ExportError(f"{out} already has files: choose a new folder")
    uids = find_uids(client, label, search, newest)
    out.mkdir(mode=0o700, parents=True, exist_ok=True)
    result = ExportResult()
    for done, uid in enumerate(uids, 1):
        raw = _fetch_or_stop(client, uid, FETCH_WHOLE_EMAIL, f"{result.saved} emails", out)
        if raw is None:
            result.failed += 1
        else:
            _write_private(out / f"uid-{uid}.eml", raw)
            result.saved += 1
        if progress is not None:
            progress(done, len(uids))
    return result


def list_label(
    client: ImapClient,
    label: str,
    search: str | None = None,
    newest: int | None = None,
    progress: Progress | None = None,
) -> list[Listed]:
    """Date, sender and subject of every match, newest first. Downloads no email.

    progress(done, total) is called after each email's headers arrive.
    """
    uids = find_uids(client, label, search, newest)
    listed = []
    for uid in reversed(uids):
        raw = _fetch_or_stop(client, uid, FETCH_HEADERS, f"{len(listed)} emails", None)
        listed.append(_describe(raw))
        if progress is not None:
            progress(len(listed), len(uids))
    return listed


def _describe(raw: bytes | None) -> Listed:
    if raw is None:
        return Listed("?", "?", "(Gmail did not send it)")
    headers = BytesParser(policy=policy.default).parsebytes(raw, headersonly=True)
    return Listed(
        _date(_header(headers, "Date")),
        _header(headers, "From") or "-",
        _header(headers, "Subject") or "-",
    )


def _header(headers: EmailMessage, name: str) -> str:
    """A header on one line (folded lines joined), or "?" if it cannot be decoded."""
    try:
        value = headers.get(name)
    except Exception:  # a broken header must not stop the list
        return "?"
    return " ".join(str(value).split()) if value is not None else ""


def _date(value: str) -> str:
    """'Fri, 20 Nov 2026 09:15:00 +0530' -> '2026-11-20'; anything odd is shown as it is."""
    try:
        return parsedate_to_datetime(value).date().isoformat()
    except (TypeError, ValueError, IndexError, OverflowError):
        return value[:16] or "-"


def _fetch_or_stop(
    client: ImapClient, uid: str, spec: str, done: str, out: Path | None
) -> bytes | None:
    try:
        return _fetch(client, uid, spec)
    except (imaplib.IMAP4.abort, OSError):
        again = f"delete {out} and run the command again" if out else "run it again"
        raise ExportError(f"the connection was lost after {done}: {again}") from None


def _fetch(client: ImapClient, uid: str, spec: str = FETCH_WHOLE_EMAIL) -> bytes | None:
    """The requested bytes, or None if Gmail did not send them."""
    status, data = client.uid("FETCH", uid, spec)
    if status != "OK":
        return None
    for part in data:  # [(b'1 (UID 5 BODY[] {1234}', b'...the email...'), b')']
        if isinstance(part, tuple) and len(part) == 2 and isinstance(part[1], bytes) and part[1]:
            return part[1]
    return None


def _write_private(path: Path, data: bytes) -> None:
    """Write a new file only you can read (0600). O_EXCL: never overwrite an existing file."""
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(data)
