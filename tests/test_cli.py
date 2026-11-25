import pytest
from rich.console import Console
from typer.testing import CliRunner

from phishtriage import cli
from phishtriage.cli import app

runner = CliRunner()


@pytest.fixture
def wide(monkeypatch):
    """A 200-column report, so long values are not wrapped in the middle of a string."""
    monkeypatch.setattr(cli, "console", Console(width=200))


def many_links_email(tmp_path, links: list[str]) -> str:
    """A small .eml whose HTML body has the given links. Returns its path."""
    anchors = "".join(f'<a href="{link}">link</a>' for link in links)
    path = tmp_path / "many_links.eml"
    path.write_text(
        "From: News <news@shop.test>\nTo: student@example.org\nSubject: Offers\n"
        f"Content-Type: text/html\n\n<html><body>{anchors}</body></html>\n",
        encoding="utf-8",
    )
    return str(path)


def test_analyze_single_file(fixtures):
    result = runner.invoke(app, ["analyze", str(fixtures / "phish_paypal_spoof.eml")])
    assert result.exit_code == 2, result.output  # malicious (week 4 exit codes)
    assert "PayPal Security" in result.output
    assert "dmarc_fail" in result.output
    assert "Account_Review.html" in result.output
    assert "2 URLs, 4 domains, 1 IP, 3 email addresses" in result.output  # week 2 step 7
    assert "link_text_mismatch" in result.output  # week 2 step 6


def test_analyze_folder(fixtures):
    count = len(list(fixtures.glob("*.eml")))  # not hard-coded: new fixtures keep coming
    result = runner.invoke(app, ["analyze", str(fixtures)])
    assert result.exit_code == 2, result.output  # malicious (week 4 exit codes)
    assert f"Analysed {count} of {count} files" in result.output


def test_analyze_forwarded_email(fixtures):
    result = runner.invoke(app, ["analyze", str(fixtures / "forwarded_phish.eml")])
    assert result.exit_code == 1, result.output  # suspicious (week 4 exit codes)
    assert "Nimal Perera" in result.output  # the outer email
    assert "Forwarded emails" in result.output
    assert "Forwarded email 1 inside forwarded_phish.eml (level 1)" in result.output
    assert "Microsoft 365 Admin" in result.output  # the inner email
    assert "display_name_spoof" in result.output
    assert "Password_Policy.txt" in result.output  # the inner email's attachment


def test_analyze_attachments(fixtures):
    result = runner.invoke(app, ["analyze", str(fixtures / "attachments_phish.eml")])
    assert result.exit_code == 1, result.output  # suspicious (week 4 exit codes)
    assert "Real type" in result.output
    assert "(password-protected) contains: Payment_Details.pdf.js" in result.output
    assert "attachment_double_extension" in result.output
    assert "attachment_encrypted_archive" in result.output


def test_analyze_with_my_own_allowlist(fixtures, tmp_path):
    mine = tmp_path / "mine.txt"
    mine.write_text("paypal.com\nnot a domain\n", encoding="utf-8")
    email = str(fixtures / "phish_paypal_spoof.eml")
    result = runner.invoke(app, ["analyze", email, "--allowlist", str(mine)])
    assert result.exit_code == 2, result.output  # malicious (week 4 exit codes)
    assert "4 allowlisted IOCs" in result.output
    assert "line 2: 'not a domain' is not a domain name" in result.output


def test_ioc_table_is_defanged(fixtures, wide):
    result = runner.invoke(app, ["analyze", str(fixtures / "phish_paypal_spoof.eml")])
    assert result.exit_code == 2, result.output  # malicious (week 4 exit codes)
    assert "IOCs (defanged)" in result.output
    assert "hxxp://paypa1-secure[.]test/login" in result.output
    assert "203[.]0[.]113[.]45" in result.output
    assert "support[@]paypa1-secure[.]test" in result.output
    assert "header:Received (hop 1)" in result.output
    assert "html:a[href]" in result.output  # escaped, so Rich does not eat "[href]"


def test_report_never_contains_a_live_link(fixtures, wide):
    result = runner.invoke(app, ["analyze", str(fixtures), "--all-urls"])
    assert result.exit_code == 2, result.output  # malicious (week 4 exit codes)
    assert "hxxp" in result.output
    assert "http://" not in result.output
    assert "https://" not in result.output


def test_many_urls_are_grouped_by_domain(tmp_path, wide):
    links = [f"https://shop.test/item/{n}" for n in range(11)] + ["https://other.test/a"]
    path = many_links_email(tmp_path, links)

    grouped = runner.invoke(app, ["analyze", path])
    assert "11 on shop[.]test" in grouped.output
    assert "hxxps://other[.]test/a" in grouped.output  # a group of one shows the URL
    assert "12 URLs grouped by domain. Add --all-urls to list every one." in grouped.output

    listed = runner.invoke(app, ["analyze", path, "--all-urls"])
    assert "hxxps://shop[.]test/item/10" in listed.output
    assert "grouped by domain" not in listed.output


def test_lookup_column_shows_skips(tmp_path, wide):
    links = [f"https://shop.test/item/{n}" for n in range(10)]
    links.append("https://shop.test/r?u=https://evil.test")  # a possible open redirect
    path = many_links_email(tmp_path, links)
    mine = tmp_path / "mine.txt"
    mine.write_text("shop.test\n", encoding="utf-8")

    result = runner.invoke(app, ["analyze", path, "--allowlist", str(mine)])
    assert "11 on shop[.]test" in result.output
    assert "1 yes, 10 skip" in result.output  # only the redirect is still looked up


def test_check_iocs_gate(fixtures, tmp_path, wide):
    import shutil

    for name in ["phish_paypal_spoof.eml", "legit_newsletter.eml"]:
        shutil.copy(fixtures / name, tmp_path)

    made = runner.invoke(app, ["check-iocs", str(tmp_path), "--make-templates"])
    assert "2 new hand-check file(s)" in made.output

    # Fill in the PayPal one, forgetting the Message-ID domain; leave the other blank
    (tmp_path / "expected" / "phish_paypal_spoof.txt").write_text(
        "[domains]\nwww.paypal.com\npaypa1-secure.test\npaypal.com\n"
        "[ips]\n203.0.113.45\n[emails]\nservice@paypal.com\nsupport@paypa1-secure.test\n"
        "bounce@mailer-7731.test\n[attachments]\nAccount_Review.html\n",
        encoding="utf-8",
    )
    # legit_newsletter.txt is still the blank template

    result = runner.invoke(app, ["check-iocs", str(tmp_path)])
    assert result.exit_code == 0, result.output
    # a blank template is skipped, so none of the tool's answers are shown for it
    assert "legit_newsletter.eml: hand-check file still empty, skipped" in result.output
    assert "www[.]example[.]com" not in result.output
    assert "domains      3 matched, 0 missed, 1 extra" in result.output
    assert "found only by the tool: mailer-7731[.]test" in result.output
    assert "Week 2 gate: 1 hand-checked emails" in result.output

    (tmp_path / "expected" / "legit_newsletter.txt").unlink()
    result = runner.invoke(app, ["check-iocs", str(tmp_path)])
    assert "No hand-check file for legit_newsletter.eml: skipped" in result.output


def test_version():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "0.1.0" in result.output


def test_analyze_shows_every_reply_to_address(tmp_path, wide):
    path = tmp_path / "two_reply_to.eml"
    path.write_text(
        "From: Shop <hello@shop.test>\nTo: student@example.org\n"
        "Reply-To: hello@shop.test, cert@shop.test\nSubject: Order\n\nThanks\n",
        encoding="utf-8",
    )
    result = runner.invoke(app, ["analyze", str(path)])
    assert result.exit_code == 0, result.output
    assert "hello[@]shop[.]test, cert[@]shop[.]test" in result.output  # defanged since step 10


def test_analyze_shows_every_from_address(tmp_path, wide):
    path = tmp_path / "two_from.eml"
    path.write_text(
        'From: "PayPal Security" <alerts@paypa1-secure.test>, other@else.test\n'
        "Subject: Verify\n\nhello\n",
        encoding="utf-8",
    )
    result = runner.invoke(app, ["analyze", str(path)])
    assert result.exit_code in (0, 1, 2), result.output  # a verdict (week 4 exit codes)
    sender = "PayPal Security <alerts[@]paypa1-secure[.]test> + other[@]else[.]test"
    assert sender in result.output  # defanged since week 4, step 10
    assert "multiple_from_addresses" in result.output
    assert "display_name_spoof" in result.output


# --- Week 3 step 5: analyse first, print second ---------------------------------------


def test_analyze_an_empty_folder(tmp_path):
    result = runner.invoke(app, ["analyze", str(tmp_path)])
    assert result.exit_code == 3  # no verdict for every file (week 4 exit codes)
    assert "No .eml files found" in result.output


def test_one_failing_email_does_not_stop_the_others(fixtures, tmp_path, monkeypatch, wide):
    for name in ("legit_newsletter.eml", "phish_paypal_spoof.eml"):
        (tmp_path / name).write_bytes((fixtures / name).read_bytes())
    real = cli.analyse_file

    def fail_on_newsletter(path, allowlist):
        if path.name == "legit_newsletter.eml":
            raise RuntimeError("simulated crash")
        return real(path, allowlist)

    monkeypatch.setattr(cli, "analyse_file", fail_on_newsletter)
    result = runner.invoke(app, ["analyze", str(tmp_path)])
    assert result.exit_code == 3  # no verdict for every file (week 4 exit codes)
    assert "Could not analyse legit_newsletter.eml: RuntimeError('simulated crash')" in (
        result.output
    )
    assert "PayPal Security" in result.output  # the other email is still reported
    assert "Analysed 1 of 2 files" in result.output


def test_microsoft_format_heading_and_compauth(fixtures, wide):
    """Week 4, step 2: Microsoft's header names no server, and adds compauth=."""
    result = runner.invoke(app, ["analyze", str(fixtures / "phish_microsoft_format.eml")])
    assert result.exit_code == 2, result.output  # malicious (week 4 exit codes)
    assert "Authentication (top header, Microsoft's format with no server name)" in result.output
    assert "SPF   softfail" in result.output  # lost before step 2
    assert "COMPAUTH fail (reason 001)" in result.output


def test_compauth_line_only_when_microsoft_wrote_one(fixtures, wide):
    result = runner.invoke(app, ["analyze", str(fixtures / "phish_paypal_spoof.eml")])
    assert "Authentication (from mx[.]google[.]com)" in result.output
    assert "COMPAUTH" not in result.output


def test_compauth_without_reason_prints_no_brackets(tmp_path, wide):
    path = tmp_path / "softpass.eml"
    path.write_text(
        "Authentication-Results: spf=pass smtp.mailfrom=shop.test; compauth=softpass\n"
        "From: Shop <news@shop.test>\nSubject: Hi\n\nhello\n",
        encoding="utf-8",
    )
    result = runner.invoke(app, ["analyze", str(path)])
    assert "COMPAUTH softpass\n" in result.output


@pytest.mark.parametrize(
    ("name", "row"),
    [
        (
            "phish_microsoft_format.eml",
            "Sender IP          203[.]0[.]113[.]77 (from Authentication-Results)",
        ),
        (
            "attachments_phish.eml",
            "Sender IP          198[.]51[.]100[.]23 (from Received hop 1, less certain)",
        ),
        ("broken_charset.eml", "Sender IP          -"),
    ],
)
def test_the_summary_shows_the_sender_ip(fixtures, wide, name, row):
    """Week 4, step 3. Defanged like every IP in the report."""
    result = runner.invoke(app, ["analyze", str(fixtures / name)])
    assert row in result.output
