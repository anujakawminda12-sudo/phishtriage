"""Tests for render/terminal.py and the CLI's use of the report model (week 4, step 10)."""

import dataclasses
import re

import pytest
from conftest import FIXTURES, PHISH_ME, isolate_settings
from rich.console import Console
from typer.testing import CliRunner

from phishtriage import cli, report
from phishtriage.allowlist import load_allowlist
from phishtriage.analysis import analyse_file
from phishtriage.render.terminal import print_file, print_report
from phishtriage.report import Answer, build_report
from phishtriage.scoring import load_scoring

runner = CliRunner()
ALLOWLIST = load_allowlist()
CONFIG = load_scoring()


@pytest.fixture
def wide(monkeypatch):
    monkeypatch.setattr(cli, "console", Console(width=200))


def analyze(*args: str):
    return runner.invoke(cli.app, ["analyze", *map(str, args)])


def built(*names: str, **options):
    analyses = [analyse_file(FIXTURES / name, ALLOWLIST) for name in names]
    return build_report(analyses, CONFIG, **options)


def has_row(out: str, label: str, value: str) -> bool:
    """A summary row: the label, the column gap (its width depends on the longest
    label), then the value."""
    return re.search(rf"^\s*{re.escape(label)}\s+{re.escape(value)}", out, re.MULTILINE) is not None


def coloured(value) -> str:
    """What a colour terminal receives: the text with its ANSI colour codes.

    highlight=True is Rich's default; the renderer must switch it off itself.
    """
    console = Console(force_terminal=True, color_system="truecolor", highlight=True, width=200)
    with console.capture() as capture:
        print_report(value, console)
    return capture.get()


# --- what the terminal shows -------------------------------------------------------------------


def test_only_what_is_meant_to_be_coloured_is_coloured():
    """Step 8's screenshot: Rich coloured "7731" blue and "header(s)" pink. An ANSI code
    inside these strings would split them, so finding them whole proves there is none."""
    output = coloured(built("phish_paypal_spoof.eml"))
    assert "bounce[@]mailer-7731[.]test differs from From service[@]paypal[.]com" in output
    assert "1 more Authentication-Results header(s) lower down" in output
    assert "\x1b[1;31mMALICIOUS\x1b[0m  100/100" in output  # red verdict, plain score


def test_a_file_name_is_neither_highlighted_nor_read_as_markup():
    file = built("phish_paypal_spoof.eml").files[0]
    console = Console(force_terminal=True, color_system="truecolor", highlight=True, width=200)
    with console.capture() as capture:
        print_file(dataclasses.replace(file, name="[red]report 7731.eml"), console)
    assert "[red]report 7731.eml" in capture.get()


def test_the_report_comes_from_the_model(wide):
    result = analyze(FIXTURES / "phish_paypal_spoof.eml")
    out = result.output
    assert result.exit_code == 2  # malicious
    assert has_row(out, "From", "PayPal Security <service[@]paypal[.]com>")
    assert has_row(out, "Message-ID", "<")
    assert has_row(out, "Sender IP", "203[.]0[.]113[.]45 (from Authentication-Results)")
    assert "Authentication (from mx[.]google[.]com)" in out
    assert "! reply_to_mismatch: Reply-To support[@]paypa1-secure[.]test differs" in out
    assert "service@paypal.com" not in out


def test_your_address_never_reaches_the_screen(phish_email, wide):
    out = analyze(phish_email).output
    assert PHISH_ME not in out
    assert "hxxps://paypa1-login[.]com/verify?u=REDACTED" in out


def test_configured_addresses_are_hidden_too(monkeypatch, wide):
    monkeypatch.setenv("PHISHTRIAGE_MY_ADDRESSES", "service@paypal.com")
    out = analyze(FIXTURES / "phish_paypal_spoof.eml").output
    assert has_row(out, "From", "PayPal Security <REDACTED>")
    assert "PHISHTRIAGE_MY_ADDRESSES is not set" not in out


def test_a_forward_gets_its_own_section(wide):
    out = analyze(FIXTURES / "forwarded_phish.eml").output
    assert "Forwarded email 1 inside forwarded_phish.eml (level 1)" in out
    assert "File       SUSPICIOUS  60/100  decided by forwarded email 1" in out
    assert out.count("File       ") == 1  # only at the top, not in the forwarded section


def test_a_deeper_forward_is_named_by_its_path():
    file = built("forwarded_phish.eml").files[0]
    outer, inner = file.emails
    deeper = dataclasses.replace(inner, where="1 > 2", level=2)
    console = Console(width=200)
    with console.capture() as capture:
        print_file(dataclasses.replace(file, emails=(outer, deeper)), console)
    assert "Forwarded email 1 > 2 inside forwarded_phish.eml (level 2)" in capture.get()


def test_archive_members_and_allowlisted_iocs(wide):
    out = analyze(FIXTURES / "attachments_phish.eml").output
    assert "Payment_Details[.]zip (password-protected) contains: Payment_Details.pdf.js" in out
    out = analyze(FIXTURES / "forwarded_phish.eml").output
    assert has_row(out, "Lookups skipped", "2 allowlisted IOCs (still listed, not trusted)")
    # table cells are separated by a box character; allowlisted values are not looked up
    assert re.search(r"domain\s*\u2502\s*example\[\.\]org\s*\u2502.*skip", out) is not None
    assert re.search(r"email address\s*\u2502\s*REDACTED\s*\u2502.*skip", out) is not None


def test_many_urls_are_grouped_by_domain(tmp_path, wide):
    links = "\n".join(f"https://shop.test/item/{n}" for n in [*range(11), 0])  # 0 twice
    path = tmp_path / "many.eml"
    path.write_text(
        f"From: Shop <news@shop.test>\nTo: student@example.org\nSubject: Offers\n\n{links}\n"
    )
    out = analyze(path).output
    assert (
        re.search(r"11 on shop\[\.\]test\s*\u2502\s*12\s*\u2502", out) is not None
    )  # seen 12 times
    assert "11 URLs grouped by domain. Add --all-urls to list every one." in out
    out = analyze(path, "--all-urls").output
    assert "hxxps://shop[.]test/item/10" in out
    assert "grouped by domain" not in out
    ten = "\n".join(f"https://shop.test/item/{n}" for n in range(10))
    path.write_text(
        f"From: Shop <news@shop.test>\nTo: student@example.org\nSubject: Offers\n\n{ten}\n"
    )
    assert "grouped by domain" not in analyze(path).output  # 10 is listed, 11 is grouped


def test_group_reputation():
    file = built("phish_paypal_spoof.eml").files[0]
    (email,) = file.emails
    flagged = Answer("VirusTotal: 9 of 90 engines: malicious", flagged=True, answered=True)
    clean = Answer("VirusTotal: 0 of 90 engines: malicious", answered=True)
    urls = tuple(
        dataclasses.replace(email.iocs[0], value=f"hxxps://www[.]paypal[.]com/{n}", **kind)
        for n, kind in enumerate(
            [{"looked_up": True, "reputation": (flagged,)}] * 2
            + [{"looked_up": True, "reputation": (clean,)}] * 8
            + [{"looked_up": False, "reputation": (Answer("not looked up: x", skipped=True),)}]
        )
    )
    many = dataclasses.replace(file, emails=(dataclasses.replace(email, iocs=urls),))
    console = Console(width=200)
    with console.capture() as capture:
        print_file(many, console, enriched=True)
    out = capture.get()
    assert "10 checked, 2 flagged, 1 not looked up (--all-urls for each)" in out


# --- the run as a whole --------------------------------------------------------------------------


def test_a_file_whose_report_cannot_be_built_does_not_stop_the_run(monkeypatch, wide):
    real = report.email_report

    def email_report(analysis, *args):
        if analysis.path.name == "legit_newsletter.eml":
            raise RuntimeError("boom")
        return real(analysis, *args)

    monkeypatch.setattr(report, "email_report", email_report)
    result = analyze(FIXTURES)
    assert result.exit_code == 3  # no verdict for every file (week 4 exit codes)
    out = result.output
    assert "Could not analyse legit_newsletter.eml: the report could not be built:" in out
    assert "RuntimeError('boom')" in out
    assert "phish_paypal_spoof.eml" in out
    assert "Analysed 7 of 8 files." in out


def test_a_file_that_cannot_be_read_is_listed(monkeypatch, wide):
    def broken(path, allowlist):
        raise ValueError(f"cannot read {path.name}")

    monkeypatch.setattr(cli, "analyse_file", broken)
    result = analyze(FIXTURES / "legit_newsletter.eml")
    assert result.exit_code == 3  # no verdict for every file (week 4 exit codes)
    assert "Could not analyse legit_newsletter.eml: ValueError('cannot read" in result.output


def test_settings_warnings_are_shown_once(phish_email, tmp_path, monkeypatch, wide, fake_apis):
    for name in ("VT_API_KEY", "ABUSEIPDB_API_KEY", "ABUSECH_AUTH_KEY"):
        monkeypatch.setenv(name, "k" * 64)
    monkeypatch.setenv("PHISHTRIAGE_CACHE", str(tmp_path / "cache.sqlite3"))
    fake_apis(created="2026-11-13T09:00:00Z")
    out = analyze(phish_email, "--enrich").output
    assert out.count("PHISHTRIAGE_MY_ADDRESSES is not set") == 1
    assert PHISH_ME not in out
    # email addresses and the URL carrying your address are never looked up
    assert has_row(out, "Lookups", "3 of 6 IOCs looked up (the reasons for the rest are below)")


def test_no_test_reads_the_env_file_in_the_folder_it_runs_in(tmp_path, monkeypatch, wide):
    """Your real .env sits in the project folder; conftest.isolated_settings keeps every
    test away from it. Here a .env that hides an address is put in the current folder,
    and the run must not see it."""
    (tmp_path / ".env").write_text("PHISHTRIAGE_MY_ADDRESSES=service@paypal.com\n")
    monkeypatch.chdir(tmp_path)
    out = analyze(FIXTURES / "phish_paypal_spoof.eml").output
    assert "PHISHTRIAGE_MY_ADDRESSES is not set" in out
    assert "service[@]paypal[.]com" in out


def render(file, enriched: bool = False) -> str:
    console = Console(width=200)
    with console.capture() as capture:
        print_file(file, console, enriched=enriched)
    return capture.get()


def test_checks_not_written_yet_are_listed():
    file = built("legit_newsletter.eml").files[0]
    email = dataclasses.replace(file.emails[0], not_written=("check_a", "check_b"))
    out = render(dataclasses.replace(file, emails=(email,)))
    assert "Not written yet: check_a, check_b" in out


def test_a_group_with_allowlisted_urls():
    file = built("phish_paypal_spoof.eml").files[0]
    (email,) = file.emails
    urls = tuple(
        dataclasses.replace(
            email.iocs[0], value=f"hxxps://www[.]paypal[.]com/{n}", allowlisted=n < 2
        )
        for n in range(11)
    )
    out = render(dataclasses.replace(file, emails=(dataclasses.replace(email, iocs=urls),)))
    assert "9 yes, 2 skip" in out
    every = tuple(dataclasses.replace(url, allowlisted=True) for url in urls)
    out = render(dataclasses.replace(file, emails=(dataclasses.replace(email, iocs=every),)))
    assert re.search(r"11 on paypal\[\.\]com.*skip", out) is not None


def test_answers_are_coloured_by_what_they_mean():
    file = built("phish_paypal_spoof.eml").files[0]
    (email,) = file.emails
    answers = (
        Answer("VirusTotal: 9 of 90 engines: malicious", flagged=True, answered=True),
        Answer("not looked up: contains your address", skipped=True),
        Answer("URLhaus: not listed", answered=True),
    )
    ioc = dataclasses.replace(email.iocs[0], looked_up=True, reputation=answers)
    one = dataclasses.replace(file, emails=(dataclasses.replace(email, iocs=(ioc,)),))
    console = Console(force_terminal=True, color_system="truecolor", width=200)
    with console.capture() as capture:
        print_file(one, console, enriched=True)
    out = capture.get()
    assert "\x1b[31mVirusTotal: 9 of 90 engines: malicious" in out  # red
    assert "\x1b[2mnot looked up: contains your address" in out  # dim
    assert "URLhaus: not listed" in out


def test_the_isolation_removes_real_keys_and_the_real_env_file(tmp_path, monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "a-real-key")
    monkeypatch.setenv("PHISHTRIAGE_MY_ADDRESSES", "me@real.test")
    isolate_settings(tmp_path, monkeypatch)
    settings = cli.load_settings()
    assert not settings.vt_api_key
    assert settings.my_addresses.reveal() == ()
    assert settings.env_file is None  # the .env in the project folder was not read


def test_a_long_finding_wraps_under_its_own_text():
    file = built("forwarded_phish.eml").files[0]
    console = Console(width=80)
    with console.capture() as capture:
        print_file(file, console)
    lines = capture.get().splitlines()
    start = next(n for n, line in enumerate(lines) if "! link_text_mismatch:" in line)
    assert lines[start + 1].startswith("    ") and lines[start + 1].strip()
