"""Tests for report.py and iocs.defang_text() (week 4, step 9).

The main test is a sweep: every string anywhere in a report, built from every fixture,
from an email carrying your address, from a hostile email and from an enriched run, must
be clean: no live link, no control character, none of your addresses in any form.
Special characters are built with chr(), so this file stays plain ASCII.
"""

import dataclasses
import hashlib
import time
from datetime import UTC, date, datetime, timedelta, timezone
from importlib import resources
from pathlib import Path
from types import SimpleNamespace

import pytest
from conftest import FIXTURES, PHISH_ME

from phishtriage.allowlist import load_allowlist
from phishtriage.analysis import EmailAnalysis, analyse_file
from phishtriage.config import Secret, Settings
from phishtriage.display import CONTROL_CHARACTERS, LAYOUT_CHARACTERS
from phishtriage.enrich.enricher import Enrichment, enrich
from phishtriage.enrich.models import DEFERRED, FAILED, FOUND, UNSUPPORTED, Lookup, LookupResult
from phishtriage.enrich.plan import build_plan
from phishtriage.iocs import defang_text
from phishtriage.models import IOC, AuthResults, Finding, ParsedEmail
from phishtriage.privacy import REDACTED, AddressRedactor
from phishtriage.report import (
    Cleaner,
    answer_text,
    build_report,
    finding_view,
    ioc_view,
    numbered,
)
from phishtriage.scoring import LIKELY_BENIGN, MALICIOUS, SUSPICIOUS, load_scoring, parse_scoring

ALLOWLIST = load_allowlist()
CONFIG = load_scoring()
ESC, RLO, ZWSP = chr(0x1B), chr(0x202E), chr(0x200B)
CYRILLIC_PAYPA = "".join(map(chr, (0x440, 0x430, 0x443, 0x440, 0x430)))  # looks like "paypa"
UNSAFE = {chr(code) for code in CONTROL_CHARACTERS + LAYOUT_CHARACTERS}
NOW = datetime(2026, 11, 23, 18, 30, tzinfo=UTC)


def analyse(name: str):
    return analyse_file(FIXTURES / name, ALLOWLIST)


def fixtures_report(**options):
    analyses = [analyse_file(path, ALLOWLIST) for path in sorted(FIXTURES.glob("*.eml"))]
    return build_report(analyses, CONFIG, now=NOW, **options)


def by_name(report, name: str):
    return next(file for file in report.files if file.name == name)


def strings(value):
    """Every string in a report, however deeply it sits (dataclasses, tuples, dicts)."""
    if isinstance(value, str):
        yield value
    elif dataclasses.is_dataclass(value):
        for field in dataclasses.fields(value):
            yield from strings(getattr(value, field.name))
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from strings(key)
            yield from strings(item)
    elif isinstance(value, tuple | list):
        for item in value:
            yield from strings(item)


def assert_clean(report, hidden: tuple[str, ...] = ()) -> None:
    redactor = AddressRedactor(hidden)
    texts = list(strings(report))
    assert len(texts) > 20
    for text in texts:
        assert defang_text(text) == text, f"something could still become a link: {text!r}"
        assert not UNSAFE & set(text), f"a control or layout character: {text!r}"
        assert "http://" not in text.lower() and "https://" not in text.lower(), text
        assert not redactor.contains(text), f"one of your addresses: {text!r}"


# --- defang_text(): defang the live parts of free text, leave the words alone -------------------

DEFANG = {
    "an address": ("Reply-To support@evil.test differs", "Reply-To support[@]evil[.]test differs"),
    "a domain in a sentence": ("Log in at paypal.com today.", "Log in at paypal[.]com today."),
    "a URL": ("see https://evil.test/a", "see hxxps://evil[.]test/a"),
    "a capital scheme": ("HTTPS://Evil.test/A", "hxxpS://Evil[.]test/A"),
    "an IPv6 URL": ("http://[2001:db8::1]/x", "hxxp://[2001:db8::1]/x"),
    "ftp": ("ftp://files.evil.test/x", "fxp://files[.]evil[.]test/x"),
    "an IPv4 address": ("from 203.0.113.9, e.g.", "from 203[.]0[.]113[.]9, e.g."),
    "www without a scheme": ("www.evil.test/login?a=b", "www[.]evil[.]test/login?a=b"),
    "a look-alike in Cyrillic": (f"{CYRILLIC_PAYPA}l.com", f"{CYRILLIC_PAYPA}l[.]com"),
    "a reserved test domain": ("paypa1-secure.test", "paypa1-secure[.]test"),
    "mailto": ("mailto:a@evil.test", "mailto:a[@]evil[.]test"),
    "file names": ("Account_Review.html invoice.pdf.exe", "Account_Review.html invoice.pdf.exe"),
    "a file name that starts with a domain": ("paypal.com.html", "paypal[.]com[.]html"),
    ".zip is a top-level domain": ("Statement.zip.exe", "Statement[.]zip[.]exe"),
    ".md is a top-level domain": ("readme.md", "readme[.]md"),
    "version numbers": ("ver 1.5 or 2.0.1", "ver 1.5 or 2.0.1"),
    "abbreviations": ("e.g. this, i.e. that", "e.g. this, i.e. that"),
    "a missing space": ("Hello there.It works", "Hello there[.]It works"),
    "already defanged": ("hxxps://evil[.]test/a b[@]evil[.]test", None),
    "longer than any domain": ("a" * 300 + ".com", None),
    "a zero-width space splits the name": (f"pay{ZWSP}pal.com", f"pay{ZWSP}pal[.]com"),
}


@pytest.mark.parametrize(("text", "expected"), DEFANG.values(), ids=DEFANG.keys())
def test_defang_text(text, expected):
    result = defang_text(text)
    assert result == (text if expected is None else expected)
    assert defang_text(result) == result  # nothing left to change


def test_defang_text_reads_a_huge_line_in_one_pass():
    started = time.perf_counter()
    for line in ("a" * 200_000, "a." * 100_000, "a@" * 100_000, "a." * 100_000 + "com"):
        defang_text(line)
    assert time.perf_counter() - started < 2


# --- Cleaner: redact, then visible, then defang ----------------------------------------------


def test_addresses_are_removed_before_defanging():
    cleaner = Cleaner(AddressRedactor(["me@gmail.com"]))
    text = cleaner.text("mail Me@Gmail.com or me%40gmail.com, not you@gmail.com")
    assert text == "mail REDACTED or REDACTED, not you[@]gmail[.]com"
    assert len(cleaner.redacted) == 1
    cleaner.text("mail Me@Gmail.com or me%40gmail.com, not you@gmail.com")
    assert len(cleaner.redacted) == 1  # the same text again is not counted twice


def test_control_characters_are_written_out_and_cannot_hide_a_domain():
    cleaner = Cleaner()
    assert cleaner.text(f"evil{ESC}.test") == "evil\\x1b[.]test"
    assert cleaner.text(f"invoice{RLO}fdp.exe") == "invoice\\u202efdp.exe"


def test_a_link_glued_to_other_text_is_still_found():
    assert Cleaner().text(f"{ESC}https://evil.test/a") == "\\x1bhxxps://evil[.]test/a"
    assert defang_text("xhttps://evil.test") == "xhxxps://evil[.]test"


def test_markup_is_left_for_the_renderers():
    assert Cleaner().text("[bold]x[/bold] <b>y</b> *z*") == "[bold]x[/bold] <b>y</b> *z*"


def test_ioc_values_have_every_dot_defanged():
    cleaner = Cleaner(AddressRedactor(["me@gmail.com"]))
    value = "https://evil.test/a.php?u=me%40gmail.com"
    assert cleaner.ioc(value) == "hxxps://evil[.]test/a[.]php?u=REDACTED"


# --- the model, built from the fixtures --------------------------------------------------------


def test_the_run():
    report = fixtures_report()
    assert (report.tool, report.version, report.generated_at) == (
        "PhishTriage",
        "0.1.0",
        "2026-11-23T18:30:00Z",
    )
    built_in = resources.files("phishtriage").joinpath("scoring.yaml").read_text("utf-8")
    assert report.scoring_sha256 == hashlib.sha256(built_in.encode("utf-8")).hexdigest()
    assert report.scoring_source == "built-in scoring.yaml"
    assert report.enriched is False
    assert [file.name for file in report.files] == sorted(p.name for p in FIXTURES.glob("*.eml"))


def test_the_time_is_written_in_utc():
    colombo = timezone(timedelta(hours=5, minutes=30))
    report = build_report([], CONFIG, now=datetime(2026, 11, 24, 0, 5, tzinfo=colombo))
    assert report.generated_at == "2026-11-23T18:35:00Z"
    assert build_report([], CONFIG).generated_at.endswith("Z")


def test_a_user_scoring_file_is_named_without_its_folder(tmp_path):
    path = tmp_path / "mine.yaml"
    path.write_text(resources.files("phishtriage").joinpath("scoring.yaml").read_text("utf-8"))
    assert build_report([], load_scoring(path)).scoring_source == "mine.yaml"


@pytest.mark.parametrize(
    ("name", "verdict", "total"),
    [
        ("phish_paypal_spoof.eml", MALICIOUS, 100),
        ("phish_microsoft_format.eml", MALICIOUS, 85),
        ("attachments_phish.eml", SUSPICIOUS, 50),
        ("phish_open_redirect.eml", SUSPICIOUS, 35),
        ("forwarded_phish.eml", SUSPICIOUS, 60),  # decided by the forwarded email
        ("legit_newsletter.eml", LIKELY_BENIGN, 0),
    ],
)
def test_file_verdicts(name, verdict, total):
    file = by_name(fixtures_report(), name)
    assert file.verdict is not None
    assert (file.verdict.verdict, file.verdict.total) == (verdict, total)


def test_the_paypal_email():
    report = build_report([analyse("phish_paypal_spoof.eml")], CONFIG)
    (email,) = report.files[0].emails
    assert (email.where, email.level, email.forwarded) == ("", 0, 0)
    assert (email.from_name, email.from_address) == ("PayPal Security", "service[@]paypal[.]com")
    assert email.reply_to == ("support[@]paypa1-secure[.]test",)
    assert (email.other_from, email.hops, email.defects) == ((), 1, ())
    assert email.return_path == "bounce[@]mailer-7731[.]test"
    assert email.subject == "Your account has been suspended"
    assert email.message_id.endswith("[@]mailer-7731[.]test>")
    assert (email.sender_ip, email.sender_ip_certain) == ("203[.]0[.]113[.]45", True)
    assert email.sender_ip_source == "Authentication-Results"
    assert (email.auth.source, email.auth.spf, email.auth.dmarc) == (
        "from mx[.]google[.]com",
        "softfail",
        "fail",
    )
    (attachment,) = email.attachments
    assert (attachment.name, attachment.size, len(attachment.sha256)) == (
        "Account_Review.html",
        78,
        64,
    )
    assert attachment.reputation == ()


def test_the_paypal_score_and_findings():
    (email,) = build_report([analyse("phish_paypal_spoof.eml")], CONFIG).files[0].emails
    assert (email.score.verdict, email.score.total) == (MALICIOUS, 100)
    assert [(tag.id, tag.name) for tag in email.score.attack] == [
        ("T1566.001", "Phishing: Spearphishing Attachment"),
        ("T1566.002", "Phishing: Spearphishing Link"),
    ]
    first = email.score.reasons[0]
    assert (first.signal, first.points, first.details) == (
        "dmarc_fail",
        25,
        ("DMARC result: fail",),
    )
    details = {finding.rule: finding.detail for finding in email.findings}
    assert details["reply_to_mismatch"] == (
        "Reply-To support[@]paypa1-secure[.]test differs from From service[@]paypal[.]com"
    )
    reply_to = next(r for r in email.score.reasons if r.signal == "reply_to_mismatch")
    assert reply_to.details == (details["reply_to_mismatch"],)


def test_iocs():
    (email,) = build_report([analyse("phish_paypal_spoof.eml")], CONFIG).files[0].emails
    url = email.iocs[0]
    assert (url.kind, url.value, url.seen, url.group) == (
        "url",
        "hxxps://www[.]paypal[.]com/signin",
        2,
        "paypal[.]com",
    )
    assert (url.sources, url.allowlisted, url.looked_up, url.reputation) == (
        ("text", "html:text"),
        False,
        None,
        (),
    )
    assert {ioc.group for ioc in email.iocs if ioc.kind != "url"} == {""}


def test_a_forward_and_the_email_inside_it():
    file = by_name(fixtures_report(), "forwarded_phish.eml")
    outer, inner = file.emails
    assert [(e.where, e.level) for e in file.emails] == [("", 0), ("1", 1)]
    assert (outer.forwarded, outer.score.verdict, inner.score.verdict) == (
        1,
        LIKELY_BENIGN,
        SUSPICIOUS,
    )
    assert file.decided_by == "1"
    assert file.verdict == inner.score
    # Nimal received the inner email, so his address is hidden everywhere, including as
    # the sender of the outer one: the report does not say who reported the phish
    assert outer.from_address == REDACTED


def test_numbered():
    deep = SimpleNamespace(forwarded=[])
    root = SimpleNamespace(
        forwarded=[SimpleNamespace(forwarded=[]), SimpleNamespace(forwarded=[deep])]
    )
    assert [where for where, _ in numbered(root)] == ["", "1", "2", "2 > 1"]


def test_a_file_that_could_not_be_read(tmp_path):
    report = build_report(
        [],
        CONFIG,
        my_addresses=["me@gmail.com"],
        failed=[(tmp_path / "secret folder" / "broken.eml", "cannot read me@gmail.com.eml")],
    )
    (file,) = report.files
    assert (file.name, file.verdict, file.emails) == ("broken.eml", None, ())
    assert file.error == "cannot read REDACTED.eml"
    assert report.redacted == 1


# --- nothing unsafe anywhere in a report -------------------------------------------------------


def test_the_fixtures_reports_are_clean():
    report = fixtures_report()
    assert_clean(report, ("nimal@example.org", "soc@example.org"))


def test_your_address_is_removed_everywhere(phish_email):
    report = build_report([analyse_file(phish_email, ALLOWLIST)], CONFIG)
    assert_clean(report, (PHISH_ME,))
    values = [ioc.value for ioc in report.files[0].emails[0].iocs]
    assert "hxxps://paypa1-login[.]com/verify?u=REDACTED" in values
    assert report.redacted == 1


def test_options_must_be_named():
    with pytest.raises(TypeError):
        build_report([], CONFIG, None, ["me@gmail.com"])  # type: ignore[misc]


def test_configured_addresses_are_removed_too():
    report = build_report(
        [analyse("phish_paypal_spoof.eml")], CONFIG, my_addresses=["Service@PayPal.com"]
    )
    (email,) = report.files[0].emails
    assert email.from_address == REDACTED
    assert_clean(report, ("service@paypal.com",))


HOSTILE = (
    "Delivered-To: me.victim@gmail.com\n"
    'From: "me.victim@gmail.com via [bold]IT" <it@evil.test>\n'
    "To: me.victim@gmail.com\n"
    "Subject: =?utf-8?q?Reset=1B[2J_invoice=E2=80=AEfdp.exe_[bold]now[/bold]_"
    "https://evil.test/x_=D1=80=D0=B0=D1=83=D1=80=D0=B0l.com_for_me.victim@gmail.com?=\n"
    "Message-ID: <1@evil.test>\n"
    "MIME-Version: 1.0\n"
    "Content-Type: multipart/mixed; boundary=b\n\n"
    "--b\nContent-Type: text/plain\n\nhello\n"
    '--b\nContent-Type: text/html; name="paypal.com.html"\n'
    'Content-Disposition: attachment; filename="paypal.com.html"\n\n<p>x</p>\n--b--\n'
)


def test_a_hostile_email(tmp_path):
    path = tmp_path / "hostile.eml"
    path.write_text(HOSTILE, encoding="utf-8")
    report = build_report([analyse_file(path, ALLOWLIST)], CONFIG)
    (email,) = report.files[0].emails
    assert email.subject == (
        "Reset\\x1b[2J invoice\\u202efdp.exe [bold]now[/bold] hxxps://evil[.]test/x "
        f"{CYRILLIC_PAYPA}l[.]com for REDACTED"
    )
    assert (email.from_name, email.from_address) == ("REDACTED via [bold]IT", "it[@]evil[.]test")
    assert email.attachments[0].name == "paypal[.]com[.]html"
    assert report.redacted == 2
    assert_clean(report, (PHISH_ME,))


KEY = Secret("k" * 64)


def enriched(phish_email, tmp_path, **options):
    analysis = analyse_file(phish_email, ALLOWLIST)
    settings = Settings(
        cache_path=tmp_path / "cache" / "cache.sqlite3",
        vt_api_key=KEY,
        abuseipdb_api_key=KEY,
        abusech_auth_key=KEY,
    )
    enrichment = enrich(
        [analysis], settings, ALLOWLIST, sleep=lambda _: None, jitter=lambda: 0.0, **options
    )
    return analysis, enrichment


def test_an_enriched_report(phish_email, tmp_path, fake_apis):
    fake_apis(created="2026-11-13T00:00:00Z")
    analysis, enrichment = enriched(phish_email, tmp_path)
    report = build_report([analysis], CONFIG, enrichment=enrichment)
    assert report.enriched is True
    assert_clean(report, (PHISH_ME,))
    (email,) = report.files[0].emails
    assert email.score.basis == "complete"
    domain = next(ioc for ioc in email.iocs if ioc.value == "paypa1-login[.]com")
    assert domain.looked_up is True
    texts = [answer.text for answer in domain.reputation]
    assert any(text.startswith("VirusTotal: ") for text in texts)
    assert any(text.startswith("RDAP: ") and text.endswith("days ago)") for text in texts)
    assert any(answer.flagged for answer in domain.reputation)
    assert not any(text.startswith("Age:") for text in texts)  # RDAP's age is on its line
    victim_url = next(ioc for ioc in email.iocs if "REDACTED" in ioc.value)
    assert victim_url.looked_up is False
    assert any(answer.skipped for answer in victim_url.reputation)
    assert email.attachments[0].reputation
    rules = {finding.rule for finding in email.findings}
    assert {"vt_flagged", "abuseipdb_reported", "domain_new"} <= rules
    vt = next(finding for finding in email.findings if finding.rule == "vt_flagged")
    assert vt.facts["service"] == "virustotal"


def test_a_dry_run_is_not_an_enriched_report(phish_email, tmp_path, fake_apis):
    fake_apis(created="2026-11-13T00:00:00Z")
    analysis, enrichment = enriched(phish_email, tmp_path, dry_run=True)
    report = build_report([analysis], CONFIG, enrichment=enrichment)
    assert report.enriched is False
    assert {ioc.looked_up for ioc in report.files[0].emails[0].iocs} == {None}


@pytest.mark.parametrize(
    ("status", "summary", "error", "text"),
    [
        (FOUND, "6 of 94 engines say malicious", "", "6 of 94 engines say malicious"),
        (FOUND, "", "", "found"),
        (FAILED, "", "timed out after 3 tries", "failed (timed out after 3 tries)"),
        (DEFERRED, "", "daily limit reached", "not asked (daily limit reached)"),
        (UNSUPPORTED, "", "no RDAP server for .lk", "no answer possible (no RDAP server for .lk)"),
    ],
)
def test_answer_text(status, summary, error, text):
    lookup = Lookup("virustotal", "domain", "evil.test")
    assert answer_text(LookupResult(lookup, status, summary=summary, error=error)) == text


def test_a_domain_age_from_virustotal_gets_its_own_line():
    host = IOC("domain", "paypa1-login.lk", ["url"], 1)
    analysis = EmailAnalysis(email=ParsedEmail(path=Path("x.eml")), auth=AuthResults(), iocs=[host])
    enrichment = Enrichment(
        plan=build_plan([analysis], Settings(vt_api_key=KEY), ALLOWLIST),
        analysed_on=date(2026, 11, 23),
    )
    vt, rdap = Lookup("virustotal", "domain", host.value), Lookup("rdap", "domain", host.value)
    enrichment.results[vt] = LookupResult(
        vt, FOUND, summary="0 of 90", data={"created": "2026-11-01"}
    )
    enrichment.results[rdap] = LookupResult(rdap, UNSUPPORTED, error="no RDAP server for .lk")
    report = build_report([analysis], CONFIG, enrichment=enrichment)
    (ioc,) = report.files[0].emails[0].iocs
    assert [answer.text for answer in ioc.reputation] == [
        "VirusTotal: 0 of 90",
        "RDAP: no answer possible (no RDAP server for .lk)",
        "Age: registered 2026-11-01, 22 days ago (VirusTotal WHOIS)",
    ]
    assert [answer.answered for answer in ioc.reputation] == [True, False, False]


def test_a_url_python_cannot_split_is_grouped_by_itself():
    view = ioc_view(IOC("url", "http://[broken/x", ["text"], 1), None, Cleaner())
    assert view.group == "hxxp://[broken/x"


def test_where_the_authentication_results_come_from():
    report = fixtures_report()
    unknown = by_name(report, "broken_charset.eml").emails[0]
    assert (unknown.auth.source, unknown.auth.found) == ("no trusted header", False)
    microsoft = by_name(report, "phish_microsoft_format.eml").emails[0].auth
    assert microsoft.source == "top header, Microsoft's format with no server name"


def test_archive_members_and_parsing_notes():
    report = fixtures_report()
    attachments = by_name(report, "attachments_phish.eml").emails[0].attachments
    archive = next(att for att in attachments if att.members)
    assert (archive.name, archive.members, archive.encrypted) == (
        "Payment_Details[.]zip",  # .zip is a real top-level domain
        ("Payment_Details.pdf.js",),
        True,
    )
    email = ParsedEmail(path=Path("x.eml"), defects=["b note", "a note", "b note"])
    built = build_report([EmailAnalysis(email=email, auth=AuthResults())], CONFIG)
    assert built.files[0].emails[0].defects == ("a note", "b note")


def test_text_from_scoring_yaml_is_cleaned_too():
    text = resources.files("phishtriage").joinpath("scoring.yaml").read_text("utf-8")
    label = 'label: "See evil.test now\\e[2J"'
    config = parse_scoring(text.replace("label: The From domain failed DMARC", label))
    (email,) = build_report([analyse("phish_paypal_spoof.eml")], config).files[0].emails
    assert email.score.reasons[0].label == "See evil[.]test now\\x1b[2J"


def test_facts_are_cleaned_if_a_check_ever_breaks_the_rule():
    view = finding_view(Finding("x", "d", {"note": "see evil.test", "count": 3}), Cleaner())
    assert view.facts == {"note": "see evil[.]test", "count": 3}
