"""Tests for printing outside text safely (week 3, step 13).

Found during the gate: rich.markup.escape() let control characters through, so an email
could send commands to the terminal. These tests attack the report the way an email would.
"""

from __future__ import annotations

import base64
import re
import sys
import unicodedata
from urllib.parse import quote

import pytest
from rich.console import Console
from typer.testing import CliRunner

from phishtriage import cli
from phishtriage.cli import app
from phishtriage.display import safe, visible

runner = CliRunner()

# What an attacker would use: a clickable link, clear screen, window title, clipboard write,
# an 8-bit CSI, a bell, and a fake new report line
ATTACK = (
    "\x1b]8;;https://evil.example/\x07click\x1b]8;;\x07"
    "\x1b[2J\x1b]0;title\x07\x1b]52;c;ZXZpbA==\x07\x9b31m\x07"
    "\nFindings: none"
)
NEVER_PRINTED = ("\x1b", "\x07", "\x9b", "\u202e", "\u2066", "\u2028")


# --- visible() and safe() -------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("a\x1b[2Jb", "a\\x1b[2Jb"),
        ("bell\x07", "bell\\x07"),
        ("c1\x9b31m", "c1\\x9b31m"),
        ("del\x7f", "del\\x7f"),
        ("nul\x00", "nul\\x00"),
        ("two\nlines\r", "two\\x0alines\\x0d"),
        ("tab\there", "tab\\x09here"),
        ("invoice\u202efdp.exe", "invoice\\u202efdp.exe"),
        ("isolate\u2066x\u2069", "isolate\\u2066x\\u2069"),
        ("line\u2028sep", "line\\u2028sep"),
    ],
)
def test_control_and_layout_characters_are_written_out(text, expected):
    assert visible(text) == expected


@pytest.mark.parametrize(
    "text",
    [
        "Plain ASCII subject: 50% off!",
        "ශ්‍රී ලංකා",  # Sinhala with a zero-width joiner (U+200D)
        "👨‍👩‍👧 family emoji",  # emoji joined with U+200D
        "Café, naïve, 東京, مرحبا",  # accents, Japanese, Arabic letters
        "C:\\Users\\name",  # backslashes stay as they are
    ],
)
def test_ordinary_text_is_unchanged(text):
    assert visible(text) == text


def test_no_control_character_survives_anywhere_in_unicode():
    every_character = "".join(chr(code) for code in range(sys.maxunicode + 1) if code != 0xD800)
    shown = visible(every_character)
    assert not any(unicodedata.category(ch) == "Cc" for ch in shown)
    for code in (0x061C, 0x200E, 0x200F, 0x202A, 0x202E, 0x2066, 0x2069, 0x2028, 0x2029):
        assert chr(code) not in shown


def test_safe_writes_out_then_escapes_markup():
    assert safe("[bold]x\x1b") == "\\[bold]x\\x1b"


def test_rich_prints_nothing_harmful_after_safe():
    """The real check: what reaches the terminal, with colours on."""
    console = Console(force_terminal=True, color_system="truecolor", width=300, record=True)
    with console.capture() as captured:
        console.print(f"[red]{safe(ATTACK)}[/]")
    out = captured.get()
    # Rich's own colour codes are ESC [ numbers m (its highlighter adds bold and underline
    # too); once they are removed, no ESC may be left
    without_colours = re.sub(r"\x1b\[[0-9;]*m", "", out)
    assert "\x1b" not in without_colours
    assert "\x07" not in out
    assert "\x9b" not in out
    assert without_colours.rstrip("\n").count("\n") == 0  # one line, as printed


# --- the report, attacked through a real email -------------------------------------------------


def encoded_word(text: str) -> str:
    """RFC 2047, as a sender writes non-ASCII (or control characters) in a header."""
    return "=?UTF-8?B?" + base64.b64encode(text.encode()).decode() + "?="


def hostile_email() -> bytes:
    filename = quote("invoice\u202efdp.exe\x1b[2J\nFake line")
    return (
        f'From: "{encoded_word("Pay" + ATTACK + "Pal")}" <alerts@paypa1-login.example>\r\n'
        "To: someone@example.com\r\n"
        f"Subject: {encoded_word('Your account ' + ATTACK + ' \u202eTRAP')}\r\n"
        "Date: Mon, 23 Nov 2026 10:00:00 +0530\r\n"
        "Message-ID: <hostile@paypa1-login.example>\r\n"
        "MIME-Version: 1.0\r\n"
        'Content-Type: multipart/mixed; boundary="b"\r\n'
        "\r\n"
        "--b\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
        "Log in at https://paypa1-login.example/verify\r\n"
        "--b\r\n"
        "Content-Type: application/octet-stream\r\n"
        f"Content-Disposition: attachment; filename*=UTF-8''{filename}\r\n"
        "Content-Transfer-Encoding: base64\r\n"
        "\r\n"
        "TVqQAAMAAAAEAAAA\r\n"
        "--b--\r\n"
    ).encode()


@pytest.fixture
def wide(monkeypatch):
    monkeypatch.setattr(cli, "console", Console(width=400))


def test_the_report_never_prints_control_characters(tmp_path, wide):
    path = tmp_path / "hostile.eml"
    path.write_bytes(hostile_email())
    result = runner.invoke(app, ["analyze", str(path)])
    assert result.exit_code == 0, result.output
    for character in NEVER_PRINTED:
        assert character not in result.output, repr(character)
    # Shown, written out, not dropped: the analyst can see what the email tried
    assert "\\x1b]8;;" in result.output  # the link attempt, in the From name and Subject
    assert "TRAP" in result.output and "\\u202eTRAP" in result.output
    assert "invoice\\u202efdp.exe" in result.output  # the attachment name trick
    # A newline in a name cannot start a fake report line: it is written out
    assert "\\x0aFake line" in result.output
    assert not any(line.lstrip().startswith("Fake line") for line in result.output.splitlines())
    # (headers are joined onto one line by the parser already, so no fake line there either)
    lines = result.output.splitlines()
    assert not any(line.lstrip().startswith("Findings: none") for line in lines)


def test_the_report_with_enrich_options_but_no_enrich(tmp_path, wide):
    """The warning path prints too; still nothing harmful."""
    path = tmp_path / "hostile.eml"
    path.write_bytes(hostile_email())
    result = runner.invoke(app, ["analyze", str(path), "--hosts-only"])
    for character in NEVER_PRINTED:
        assert character not in result.output, repr(character)


def test_a_hostile_file_name_is_written_out(tmp_path, wide):
    folder = tmp_path / "batch"
    folder.mkdir()
    (folder / "x\x1b[2J.eml").write_bytes(hostile_email())
    result = runner.invoke(app, ["analyze", str(folder)])
    assert "x\\x1b[2J.eml" in result.output
    assert "\x1b" not in result.output


def test_fetch_label_list_writes_out_header_tricks(monkeypatch, wide):
    from test_imap_export import FakeGmail

    raw = (
        f"Date: Mon, 23 Nov 2026 10:00:00 +0530\r\nFrom: {encoded_word('Bank' + ATTACK)}"
        f" <x@bank.example>\r\nSubject: {encoded_word('Statement ' + ATTACK)}\r\n\r\nbody"
    ).encode()
    fake = FakeGmail(emails={"1": raw}, labels=("INBOX",))
    monkeypatch.setattr("phishtriage.cli.connect", lambda user, password, host: fake)
    args = ["fetch-label", "INBOX", "--user", "me@gmail.com", "--list"]
    result = runner.invoke(app, args, input="pw\n")
    assert result.exit_code == 0, result.output
    for character in NEVER_PRINTED:
        assert character not in result.output, repr(character)
    assert "Statement \\x1b]8;;" in result.output
