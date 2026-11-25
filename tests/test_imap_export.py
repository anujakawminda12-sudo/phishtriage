"""Tests for downloading a Gmail label read-only (week 3, step 13). A fake server, no network."""

from __future__ import annotations

import imaplib
import ssl
import stat

import pytest
from typer.testing import CliRunner

from phishtriage import cli, imap_export
from phishtriage.cli import app
from phishtriage.imap_export import (
    FETCH_HEADERS,
    FETCH_WHOLE_EMAIL,
    ExportError,
    Listed,
    connect,
    export_label,
    find_uids,
    imap_quote,
    list_label,
)

runner = CliRunner()
LABEL = "phishtriage-legit"
EMAILS = {
    "7": b"From: a@example.com\r\nSubject: one\r\n\r\nbody one\r\n",
    "12": b"From: b@example.com\r\nSubject: two\r\n\r\nbody two\r\n",
}


class FakeGmail:
    """Answers like imaplib does: (status, data). Records every call."""

    def __init__(
        self,
        emails=None,
        labels=(LABEL,),
        missing=(),
        lost_after=None,
        search="OK",
        search_hits=None,
    ):
        self.emails = dict(EMAILS if emails is None else emails)
        self.search_hits = search_hits  # uids a Gmail search (X-GM-RAW) matches
        self.labels = {imap_quote(label) for label in labels}
        self.missing = set(missing)  # uids listed by SEARCH but not sent by FETCH
        self.lost_after = lost_after  # raise imaplib's "abort" after this many fetches
        self.search_status = search
        self.calls: list[tuple] = []
        self.fetches = 0
        self.logged_out = False

    def select(self, mailbox="INBOX", readonly=False):
        self.calls.append(("select", mailbox, readonly))
        if mailbox not in self.labels:
            return "NO", [b"[NONEXISTENT] Unknown Mailbox"]
        return "OK", [str(len(self.emails)).encode()]

    def uid(self, command, *args):
        self.calls.append(("uid", command, *args))
        if command == "SEARCH":
            if args[0] == "X-GM-RAW":
                hits = self.emails if self.search_hits is None else self.search_hits
                return self.search_status, [" ".join(hits).encode()]
            return self.search_status, [" ".join(self.emails).encode()]
        if command == "FETCH":
            uid, spec = args
            self.fetches += 1
            if self.lost_after is not None and self.fetches > self.lost_after:
                raise imaplib.IMAP4.abort("socket error: EOF")
            if uid in self.missing:
                return "OK", [None]
            body = self.emails[uid]
            if spec == FETCH_HEADERS:  # Gmail sends only the asked-for header lines
                lines = body.split(b"\r\n\r\n", 1)[0].split(b"\r\n")
                wanted = (b"date:", b"from:", b"subject:")
                kept = [line for line in lines if line.lower().startswith(wanted)]
                body = b"\r\n".join(kept) + b"\r\n\r\n"
            header = f"1 (UID {uid} BODY[] {{{len(body)}}}".encode()
            return "OK", [(header, body), b")"]
        raise AssertionError(f"unexpected IMAP command {command}")

    def logout(self):
        self.logged_out = True
        return "BYE", [b"logged out"]


# --- export_label ----------------------------------------------------------------------------


def test_saves_the_exact_bytes_as_uid_files(tmp_path):
    out = tmp_path / "legit_export"
    result = export_label(FakeGmail(), LABEL, out)
    assert (result.saved, result.failed) == (2, 0)
    assert (out / "uid-7.eml").read_bytes() == EMAILS["7"]
    assert (out / "uid-12.eml").read_bytes() == EMAILS["12"]


def test_files_and_folder_are_private(tmp_path):
    out = tmp_path / "legit_export"
    export_label(FakeGmail(), LABEL, out)
    assert stat.S_IMODE(out.stat().st_mode) == 0o700
    assert stat.S_IMODE((out / "uid-7.eml").stat().st_mode) == 0o600


def test_gmail_is_only_read(tmp_path):
    """Read-only select, PEEK fetches, and no command that could change anything."""
    gmail = FakeGmail()
    export_label(gmail, LABEL, tmp_path / "out")
    assert gmail.calls[0] == ("select", imap_quote(LABEL), True)
    commands = {call[1] for call in gmail.calls if call[0] == "uid"}
    assert commands == {"SEARCH", "FETCH"}  # never STORE, COPY, MOVE or EXPUNGE
    fetch_specs = {call[3] for call in gmail.calls if call[1] == "FETCH"}
    assert fetch_specs == {FETCH_WHOLE_EMAIL}
    assert FETCH_WHOLE_EMAIL == "(BODY.PEEK[])"


def test_labels_with_spaces_and_quotes_are_quoted():
    assert imap_quote("Phish Triage") == '"Phish Triage"'
    assert imap_quote('my "legit"\\set') == '"my \\"legit\\"\\\\set"'


def test_label_with_a_space(tmp_path):
    gmail = FakeGmail(labels=("Phish Triage",))
    assert export_label(gmail, "Phish Triage", tmp_path / "out").saved == 2


def test_unknown_label_says_how_to_fix_it_and_creates_nothing(tmp_path):
    with pytest.raises(ExportError, match="no label called 'Legit'.*case-sensitive"):
        export_label(FakeGmail(), "Legit", tmp_path / "out")
    assert not (tmp_path / "out").exists()


def test_an_empty_label(tmp_path):
    result = export_label(FakeGmail(emails={}), LABEL, tmp_path / "out")
    assert result.saved == 0
    assert list((tmp_path / "out").iterdir()) == []


def test_an_email_gmail_does_not_send_is_counted(tmp_path):
    result = export_label(FakeGmail(missing={"12"}), LABEL, tmp_path / "out")
    assert (result.saved, result.failed) == (1, 1)
    assert not (tmp_path / "out" / "uid-12.eml").exists()


def test_a_failed_fetch_status_is_counted(tmp_path, monkeypatch):
    gmail = FakeGmail()
    original = gmail.uid

    def refuse_fetch(command, *args):
        return ("NO", [b"try later"]) if command == "FETCH" else original(command, *args)

    monkeypatch.setattr(gmail, "uid", refuse_fetch)
    assert export_label(gmail, LABEL, tmp_path / "out").failed == 2


def test_a_lost_connection_stops_with_a_clear_message(tmp_path):
    with pytest.raises(ExportError, match="lost after 1 emails"):
        export_label(FakeGmail(lost_after=1), LABEL, tmp_path / "out")


def test_search_refused(tmp_path):
    with pytest.raises(ExportError, match="sent no list"):
        export_label(FakeGmail(search="NO"), LABEL, tmp_path / "out")


def test_a_used_folder_is_refused_before_gmail_is_asked(tmp_path):
    (tmp_path / "out").mkdir()
    (tmp_path / "out" / "old.eml").write_bytes(b"x")
    gmail = FakeGmail()
    with pytest.raises(ExportError, match="already has files"):
        export_label(gmail, LABEL, tmp_path / "out")
    assert gmail.calls == []


# --- connect ---------------------------------------------------------------------------------


class FakeImapSSL:
    """Stands in for imaplib.IMAP4_SSL: records how it was built and what login got."""

    made: list[FakeImapSSL] = []
    refuse_login = False

    def __init__(self, host, *, ssl_context, timeout):
        self.host, self.ssl_context, self.timeout = host, ssl_context, timeout
        self.login_args = None
        self.logged_out = False
        FakeImapSSL.made.append(self)

    def login(self, user, password):
        self.login_args = (user, password)
        if FakeImapSSL.refuse_login:
            raise imaplib.IMAP4.error("b'[AUTHENTICATIONFAILED] Invalid credentials'")
        return "OK", [b"welcome"]

    def logout(self):
        self.logged_out = True


@pytest.fixture
def fake_ssl(monkeypatch):
    FakeImapSSL.made = []
    FakeImapSSL.refuse_login = False
    monkeypatch.setattr(imap_export.imaplib, "IMAP4_SSL", FakeImapSSL)
    return FakeImapSSL


def test_connect_checks_the_certificate(fake_ssl):
    connect("me@gmail.com", "app-password")
    client = fake_ssl.made[0]
    assert client.host == "imap.gmail.com"
    assert client.ssl_context.verify_mode == ssl.CERT_REQUIRED
    assert client.ssl_context.check_hostname is True
    assert client.timeout == 30
    assert client.login_args == ("me@gmail.com", "app-password")


def test_a_refused_login_explains_app_passwords_and_logs_out(fake_ssl):
    fake_ssl.refuse_login = True
    with pytest.raises(ExportError, match="app password") as caught:
        connect("me@gmail.com", "secret-pw")
    assert "secret-pw" not in str(caught.value)
    assert "AUTHENTICATIONFAILED" not in str(caught.value)
    assert fake_ssl.made[0].logged_out


def test_an_unreachable_server(monkeypatch):
    def unreachable(*args, **kwargs):
        raise OSError("no route to host")

    monkeypatch.setattr(imap_export.imaplib, "IMAP4_SSL", unreachable)
    with pytest.raises(ExportError, match=r"could not reach imap\.gmail\.com \(OSError\)"):
        connect("me@gmail.com", "pw")


# --- the command -----------------------------------------------------------------------------


@pytest.fixture
def gmail(monkeypatch):
    """The command gets the fake server; records what connect() was given."""
    fake = FakeGmail()
    fake.connect_args = None

    def fake_connect(user, password, host):
        fake.connect_args = (user, password, host)
        return fake

    monkeypatch.setattr("phishtriage.cli.connect", fake_connect)
    return fake


def fetch(tmp_path, password="abcd efgh ijkl mnop", label=LABEL):
    args = ["fetch-label", label, str(tmp_path / "out"), "--user", "me@gmail.com"]
    return runner.invoke(app, args, input=f"{password}\n")


def test_fetch_label_command(tmp_path, gmail):
    result = fetch(tmp_path)
    text = " ".join(result.output.split())
    assert result.exit_code == 0, result.output
    assert "Downloaded 2 emails into" in text
    assert "Nothing in Gmail was changed" in text
    assert "delete the app password" in text
    assert gmail.logged_out
    assert sorted(p.name for p in (tmp_path / "out").iterdir()) == ["uid-12.eml", "uid-7.eml"]


def test_the_password_is_hidden_and_its_spaces_removed(tmp_path, gmail):
    result = fetch(tmp_path, password="abcd efgh ijkl mnop")
    assert gmail.connect_args == ("me@gmail.com", "abcdefghijklmnop", "imap.gmail.com")
    assert "abcd" not in result.output  # hide_input: the typed password is not echoed


def test_an_unknown_label_still_logs_out(tmp_path, gmail):
    result = fetch(tmp_path, label="Nope")
    assert result.exit_code == 1
    assert "no label called 'Nope'" in " ".join(result.output.split())
    assert gmail.logged_out


def test_a_used_folder_is_refused_before_the_password_is_asked(tmp_path, gmail):
    (tmp_path / "out").mkdir()
    (tmp_path / "out" / "old.eml").write_bytes(b"x")
    result = fetch(tmp_path)
    assert result.exit_code == 1
    assert "already has files" in " ".join(result.output.split())
    assert "App password" not in result.output
    assert gmail.connect_args is None


def test_a_refused_login_in_the_command(tmp_path, monkeypatch):
    def refused(user, password, host):
        raise ExportError("Gmail refused the login. Use an app password from ...")

    monkeypatch.setattr("phishtriage.cli.connect", refused)
    result = fetch(tmp_path)
    assert result.exit_code == 1
    assert "Gmail refused the login" in result.output
    assert not (tmp_path / "out").exists()


def test_missing_emails_are_reported(tmp_path, monkeypatch):
    fake = FakeGmail(emails={"3": b"x"}, missing={"3"})
    monkeypatch.setattr("phishtriage.cli.connect", lambda user, password, host: fake)
    text = " ".join(fetch(tmp_path).output.split())
    assert "1 emails could not be downloaded" in text
    assert "The label is empty" not in text  # it was not empty: Gmail did not send it


def test_an_empty_label_is_reported(tmp_path, monkeypatch):
    fake = FakeGmail(emails={})
    monkeypatch.setattr("phishtriage.cli.connect", lambda user, password, host: fake)
    text = " ".join(fetch(tmp_path).output.split())
    assert "Downloaded 0 emails" in text
    assert "The label is empty" in text


# --- choosing emails by Gmail search, and --list ------------------------------------------------

HEADERED = {
    "3": b"Date: Fri, 20 Nov 2026 09:15:00 +0530\r\nFrom: SLIIT <noreply@sliit.lk>\r\n"
    b"Subject: Exam timetable\r\nX-Other: hidden\r\n\r\nThe body is never fetched.\r\n",
    "9": b"Date: someday\r\nFrom: Shop <orders@shop.example>\r\n"
    b"Subject: =?UTF-8?B?WW91ciBvcmRlciDinJQ=?=\r\n\r\nbody\r\n",
    "14": b"Subject: [bold]no date or sender\r\n\r\nbody\r\n",
}


def test_search_uses_gmail_search_words(tmp_path):
    gmail = FakeGmail(labels=("INBOX",), search_hits=["12"])
    result = export_label(gmail, "INBOX", tmp_path / "out", search="from:sliit.lk newer_than:6m")
    search = [call for call in gmail.calls if call[1] == "SEARCH"]
    assert search == [("uid", "SEARCH", "X-GM-RAW", '"from:sliit.lk newer_than:6m"')]
    assert result.saved == 1
    assert [p.name for p in (tmp_path / "out").iterdir()] == ["uid-12.eml"]


def test_a_search_must_be_ascii():
    gmail = FakeGmail(labels=("INBOX",))
    with pytest.raises(ExportError, match="plain ASCII"):
        find_uids(gmail, "INBOX", search="subject:café")
    assert gmail.calls == []  # Gmail was not asked anything


def test_a_refused_search():
    with pytest.raises(ExportError, match="did not accept the search"):
        find_uids(FakeGmail(labels=("INBOX",), search="BAD"), "INBOX", search="from:(")


def test_newest_keeps_the_last_uids():
    gmail = FakeGmail(emails={str(n): b"x" for n in (3, 5, 8, 13)}, labels=("INBOX",))
    assert find_uids(gmail, "INBOX", newest=2) == ["8", "13"]
    assert find_uids(gmail, "INBOX", newest=10) == ["3", "5", "8", "13"]


def test_list_shows_date_sender_subject_newest_first():
    gmail = FakeGmail(emails=HEADERED, labels=("INBOX",))
    listed = list_label(gmail, "INBOX")
    assert listed == [
        Listed("-", "-", "[bold]no date or sender"),
        Listed("someday", "Shop <orders@shop.example>", "Your order ✔"),
        Listed("2026-11-20", "SLIIT <noreply@sliit.lk>", "Exam timetable"),
    ]


def test_list_reads_only_three_headers_and_changes_nothing():
    gmail = FakeGmail(emails=HEADERED, labels=("INBOX",))
    list_label(gmail, "INBOX")
    fetch_specs = {call[3] for call in gmail.calls if call[1] == "FETCH"}
    assert fetch_specs == {FETCH_HEADERS}
    assert FETCH_HEADERS == "(BODY.PEEK[HEADER.FIELDS (DATE FROM SUBJECT)])"
    assert gmail.calls[0][2] is True  # read-only select


def test_list_with_a_missing_email_and_a_lost_connection():
    gmail = FakeGmail(emails=HEADERED, labels=("INBOX",), missing={"9"})
    assert list_label(gmail, "INBOX")[1] == Listed("?", "?", "(Gmail did not send it)")
    with pytest.raises(ExportError, match="lost after 1 emails: run it again"):
        list_label(FakeGmail(emails=HEADERED, labels=("INBOX",), lost_after=1), "INBOX")


def test_a_header_that_cannot_be_decoded_is_shown_as_a_question_mark(monkeypatch):
    class BrokenHeaders:
        def get(self, name):
            raise ValueError("broken header")

    class Parser:
        def __init__(self, policy):
            pass

        def parsebytes(self, raw, headersonly):
            return BrokenHeaders()

    monkeypatch.setattr("phishtriage.imap_export.BytesParser", Parser)
    listed = list_label(FakeGmail(emails={"1": HEADERED["3"]}, labels=("INBOX",)), "INBOX")
    assert listed == [Listed("?", "?", "?")]


@pytest.fixture
def inbox(monkeypatch):
    fake = FakeGmail(emails=HEADERED, labels=("INBOX",), search_hits=["3", "9"])
    monkeypatch.setattr("phishtriage.cli.connect", lambda user, password, host: fake)
    return fake


def run(*args):
    return runner.invoke(app, ["fetch-label", *args, "--user", "me@gmail.com"], input="pw\n")


def test_list_command_needs_no_folder_and_downloads_nothing(tmp_path, inbox, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = run("INBOX", "--search", "newer_than:6m", "--list")
    text = " ".join(result.output.split())
    assert result.exit_code == 0, result.output
    assert "2 emails match (newest first)" in text
    assert "Exam timetable" in text
    assert "Your order ✔" in text
    assert "Nothing was downloaded" in text
    assert list(tmp_path.iterdir()) == []
    assert inbox.logged_out


def test_list_command_escapes_header_text(tmp_path, inbox):
    result = run("INBOX", "--list")
    assert "[bold]no date or sender" in result.output  # shown, not used as formatting


def test_list_command_with_no_matches(inbox):
    inbox.search_hits = []
    result = run("INBOX", "--search", "from:nobody.example", "--list")
    assert "No emails match. Nothing was downloaded." in result.output


def test_a_folder_or_list_is_needed_before_the_password_is_asked(inbox):
    result = run("INBOX")
    assert result.exit_code == 1
    assert "Give a folder to save into, or use --list" in result.output
    assert "App password" not in result.output


def test_search_and_newest_reach_the_download(tmp_path, inbox):
    out = tmp_path / "legit_export"
    result = run("INBOX", str(out), "--search", "newer_than:6m", "--newest", "1")
    assert result.exit_code == 0, result.output
    assert [p.name for p in out.iterdir()] == ["uid-9.eml"]


def test_newest_must_be_at_least_one(inbox):
    assert run("INBOX", "--list", "--newest", "0").exit_code == 2


# --- week 4: the right words, and progress -----------------------------------------------------


def test_inbox_is_a_mailbox_and_the_rest_are_labels(tmp_path, monkeypatch):
    fake = FakeGmail(emails=EMAILS, labels=("INBOX", LABEL))
    monkeypatch.setattr("phishtriage.cli.connect", lambda user, password, host: fake)
    text = " ".join(fetch(tmp_path / "a", label="INBOX").output.split())
    assert "Nothing in Gmail was changed (the mailbox was opened read-only)." in text
    text = " ".join(fetch(tmp_path / "b").output.split())
    assert "Nothing in Gmail was changed (the label was opened read-only)." in text
    for name in ("INBOX", "inbox", "Inbox"):  # IMAP: INBOX in any case is the inbox
        assert cli._mailbox_kind(name) == "mailbox"
    for name in ("Phishing samples", "INBOX2", "Inboxes", "[Gmail]/Spam"):
        assert cli._mailbox_kind(name) == "label"


def test_an_empty_inbox_and_a_search_with_no_match(tmp_path, monkeypatch):
    fake = FakeGmail(emails={}, labels=("INBOX",))
    monkeypatch.setattr("phishtriage.cli.connect", lambda user, password, host: fake)
    text = " ".join(fetch(tmp_path / "a", label="INBOX").output.split())
    assert "The inbox is empty." in text and "label is empty" not in text
    fake = FakeGmail(emails=HEADERED, labels=("INBOX",), search_hits=[])
    monkeypatch.setattr("phishtriage.cli.connect", lambda user, password, host: fake)
    text = " ".join(run("INBOX", str(tmp_path / "b"), "--search", "from:nobody").output.split())
    assert "No emails match the search, so nothing was downloaded." in text
    assert "is empty" not in text


def test_progress_is_reported_after_every_email():
    seen: list[tuple[int, int]] = []
    list_label(
        FakeGmail(emails=HEADERED, labels=("INBOX",)), "INBOX", progress=lambda *a: seen.append(a)
    )
    assert seen == [(1, 3), (2, 3), (3, 3)]


def test_progress_counts_an_email_gmail_did_not_send(tmp_path):
    seen: list[tuple[int, int]] = []
    gmail = FakeGmail(emails={"3": b"x", "4": b"y"}, missing={"3"})
    result = export_label(gmail, LABEL, tmp_path / "out", progress=lambda *a: seen.append(a))
    assert seen == [(1, 2), (2, 2)]
    assert (result.saved, result.failed) == (1, 1)


def test_the_command_shows_progress_lines(tmp_path, inbox, monkeypatch):
    monkeypatch.setattr(cli, "PROGRESS_EVERY", 2)
    lines = run("INBOX", "--list").output.splitlines()
    progress = [line.strip() for line in lines if "emails done" in line]
    assert progress == ["2 of 3 emails done", "3 of 3 emails done"]  # every 2nd, and the end
    first_row = next(number for number, line in enumerate(lines) if "Exam timetable" in line)
    assert all(lines.index(line) < first_row for line in lines if "emails done" in line)
    lines = run("INBOX", str(tmp_path / "out")).output.splitlines()
    assert [line.strip() for line in lines if "emails done" in line] == [
        "2 of 3 emails done",
        "3 of 3 emails done",
    ]
