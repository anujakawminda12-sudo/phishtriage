"""Week 3, step 12: "phishtriage analyze --enrich" from the command line.

Keys come from environment variables set by the test, and --env-file always points at a
file that does not exist, so your real .env, keys and cache are never used. Every
answer comes from the fake APIs in conftest.py.
"""

import json
import time
from datetime import UTC, datetime, timedelta

import pytest
from conftest import PHISH_EML
from rich.console import Console
from typer.testing import CliRunner

from phishtriage import cli
from phishtriage.cli import app
from phishtriage.enrich.cache import Cache
from phishtriage.enrich.enricher import Enrichment
from phishtriage.enrich.plan import LookupPlan

runner = CliRunner()
# UTC, like the program: date.today() is the local date, which in Sri Lanka is a day ahead
# of UTC from 00:00 to 05:30, and this test failed then (found in week 4, step 9)
CREATED = datetime.now(UTC).date() - timedelta(days=10)


@pytest.fixture
def env(tmp_path, monkeypatch):
    """Fake keys and a cache in tmp_path; returns the --env-file option (a missing file)."""
    for name in ("VT_API_KEY", "ABUSEIPDB_API_KEY", "ABUSECH_AUTH_KEY"):
        monkeypatch.setenv(name, "k" * 64)
    monkeypatch.setenv("PHISHTRIAGE_MY_ADDRESSES", "me.victim@gmail.com")
    monkeypatch.setenv("PHISHTRIAGE_CACHE", str(tmp_path / "cache.sqlite3"))
    monkeypatch.setattr(cli, "console", Console(width=250))
    return ["--env-file", str(tmp_path / "no-such.env")]


def analyze(path, env, *options: str):
    return runner.invoke(app, ["analyze", str(path), *env, *options])


# --- without --enrich, nothing is sent ------------------------------------------------------


def test_without_enrich_nothing_is_sent_even_with_keys(phish_email, env, respx_mock, monkeypatch):
    def must_not_run(*args, **kwargs):
        raise AssertionError("enrich() ran without --enrich")

    monkeypatch.setattr(cli, "enrich", must_not_run)
    result = analyze(phish_email, env)
    assert result.exit_code == 1, result.output  # suspicious (week 4 exit codes)
    assert respx_mock.calls.call_count == 0  # not a single request
    assert "Lookup" in result.output
    assert "Reputation" not in result.output


def test_enrich_options_alone_only_warn(phish_email, env, respx_mock):
    result = analyze(phish_email, env, "--hosts-only", "--max-lookups", "5")
    assert result.exit_code == 1, result.output  # suspicious (week 4 exit codes)
    assert "only work with --enrich" in result.output
    assert respx_mock.calls.call_count == 0


# --- with --enrich ----------------------------------------------------------------------------


@pytest.mark.parametrize("zone", ["Etc/GMT-14", "Etc/GMT+12"])  # UTC+14 and UTC-12
def test_domain_ages_are_counted_in_utc(zone, monkeypatch):
    """At any moment, the local date in one of these two zones differs from UTC's, so a
    default that used the local date fails here whatever time the test runs."""
    monkeypatch.setenv("TZ", zone)
    time.tzset()  # make Python read TZ again (macOS and Linux)
    try:
        assert Enrichment(plan=LookupPlan()).analysed_on == datetime.now(UTC).date()
    finally:
        monkeypatch.undo()
        time.tzset()


def test_enrich_end_to_end(phish_email, env, fake_apis):
    fake_apis(created=f"{CREATED}T09:00:00Z")
    result = analyze(phish_email, env, "--enrich")
    out = result.output
    assert result.exit_code == 2, out  # malicious (week 4 exit codes)
    assert "Lookups planned: 8 (VirusTotal 3, AbuseIPDB 1, URLhaus 3, RDAP 1)" in out
    assert "Reputation" in out
    assert "VirusTotal: 5 of 95 engines: malicious" in out
    assert "URLhaus: listed: malware_download (online)" in out
    assert "AbuseIPDB: confidence 90%, 30 reports from 12 users in 90 days" in out
    assert f"RDAP: registered {CREATED} (10 days ago)" in out
    assert "VirusTotal: never seen" in out  # the attachment's hash
    assert "not looked up: contains your address" in out
    assert "not looked up: email addresses are never sent to any service" in out
    for rule in ("vt_flagged", "urlhaus_listed", "abuseipdb_reported", "domain_new"):
        assert rule in out
    assert "Enrichment complete" in out
    assert "up to 1 minute," in out
    assert "RDAP's API calls include 1 for IANA's list of servers" in out
    assert "API calls in the last 24 hours: VirusTotal 3 of 480" in out
    assert "http://" not in out and "https://" not in out  # still nothing clickable


def test_a_second_run_comes_from_the_cache(phish_email, env, fake_apis):
    router = fake_apis(created=f"{CREATED}T09:00:00Z")
    analyze(phish_email, env, "--enrich")
    sent = router.calls.call_count
    result = analyze(phish_email, env, "--enrich")
    assert router.calls.call_count == sent
    assert "Enrichment complete" in result.output


def test_stats_file_has_counts_and_no_iocs(phish_email, env, fake_apis, tmp_path):
    fake_apis(created=f"{CREATED}T09:00:00Z")
    stats = tmp_path / "run.json"
    result = analyze(phish_email, env, "--enrich", "--stats", str(stats))
    assert result.exit_code == 2, result.output  # malicious (week 4 exit codes)
    assert "Counts written to" in result.output
    data = json.loads(stats.read_text())
    assert data["emails"] == 1
    assert data["emails_failed"] == 0
    assert data["lookups_planned"] == 8
    assert data["unanswered"] == 0
    assert data["quota_errors"] == 0
    assert data["services"]["virustotal"]["api_calls"] == 3
    assert data["services"]["rdap"]["planned"] == 1
    assert data["daily_budget"]["virustotal"] == 480
    text = stats.read_text()
    for private in ("paypa1", "45.33.32.156", "gmail", "invoice", "k" * 64):
        assert private not in text


def test_an_unwritable_stats_file_is_a_warning(phish_email, env, fake_apis, tmp_path):
    fake_apis(created=f"{CREATED}T09:00:00Z")
    result = analyze(phish_email, env, "--enrich", "--stats", str(tmp_path / "no" / "run.json"))
    assert result.exit_code == 2, result.output  # malicious (week 4 exit codes)
    assert "Could not write" in result.output


def test_hosts_only_sends_no_url(phish_email, env, fake_apis):
    router = fake_apis(created=f"{CREATED}T09:00:00Z")
    result = analyze(phish_email, env, "--enrich", "--hosts-only")
    assert result.exit_code in (0, 1, 2), result.output  # a verdict (week 4 exit codes)
    paths = [call.request.url.path for call in router.calls]
    assert not any("/urls/" in path or path.endswith("/v1/url/") for path in paths)
    assert "not looked up: --hosts-only" in result.output


def test_max_lookups_gives_a_partial_run(phish_email, env, fake_apis):
    fake_apis(created=f"{CREATED}T09:00:00Z")
    result = analyze(phish_email, env, "--enrich", "--max-lookups", "1")
    assert "Enrichment partial" in result.output
    assert "not asked (this run's limit of 1 lookups (--max-lookups))" in result.output


def test_a_refused_key_is_reported(phish_email, env, fake_apis, respx_mock):
    respx_mock.get(url__startswith="https://www.virustotal.com/").respond(401)
    fake_apis(created=f"{CREATED}T09:00:00Z")
    result = analyze(phish_email, env, "--enrich")
    assert "VirusTotal stopped: the key was refused (401): check VT_API_KEY in .env" in (
        result.output
    )


def test_without_keys_only_rdap_runs(phish_email, env, fake_apis, monkeypatch):
    for name in ("VT_API_KEY", "ABUSEIPDB_API_KEY", "ABUSECH_AUTH_KEY"):
        monkeypatch.delenv(name)
    router = fake_apis(created=f"{CREATED}T09:00:00Z")
    result = analyze(phish_email, env, "--enrich")
    assert "VirusTotal off: VT_API_KEY is not set" in result.output
    hosts = {call.request.url.host for call in router.calls}
    assert hosts == {"data.iana.org", "rdap.verisign.com"}


def test_many_urls_are_summed_up_per_domain(env, fake_apis, tmp_path):
    links = "".join(f'<a href="https://paypa1-login.com/c/{n}">{n}</a>' for n in range(12))
    body = PHISH_EML.split("--b1")[0]  # the headers only: no Received IP, no attachment
    body = body.replace("Received: from mail.paypa1-login.com (mail.paypa1-login.com", "X-Old:")
    body = body.replace('multipart/mixed; boundary="b1"', "text/html; charset=utf-8")
    path = tmp_path / "many.eml"
    path.write_text(body + links + "\n", encoding="utf-8")
    fake_apis(created=f"{CREATED}T09:00:00Z")
    result = analyze(path, env, "--enrich")
    assert result.exit_code in (0, 1, 2), result.output  # a verdict (week 4 exit codes)
    assert "12 checked, 12 flagged" in result.output


# --- the rarer paths ----------------------------------------------------------------------------


def test_nothing_to_look_up(fixtures, env, respx_mock):
    # Every name in this fixture is reserved (example.com/org) and it has no attachment
    result = analyze(fixtures / "legit_newsletter.eml", env, "--enrich")
    assert result.exit_code == 0, result.output
    assert "Lookups planned: 0 (none)" in result.output
    assert "Nothing to look up" in result.output
    assert "From cache" not in result.output  # no all-zero table (step 13)
    assert respx_mock.calls.call_count == 0


def test_warnings_are_shown(phish_email, env, fake_apis, monkeypatch, tmp_path):
    monkeypatch.delenv("PHISHTRIAGE_MY_ADDRESSES")
    damaged = tmp_path / "damaged.sqlite3"
    damaged.write_bytes(b"not a database" * 100)
    monkeypatch.setenv("PHISHTRIAGE_CACHE", str(damaged))
    fake_apis(created=f"{CREATED}T09:00:00Z")
    result = analyze(phish_email, env, "--enrich")
    assert result.exit_code in (0, 1, 2), result.output  # a verdict (week 4 exit codes)
    assert "Warning: PHISHTRIAGE_MY_ADDRESSES is not set" in result.output
    assert "could not be used (DatabaseError)" in result.output
    # Delivered-To still names the victim, so the link with the address is still not sent
    assert "not looked up: contains your address" in result.output


def test_a_tld_without_rdap_gets_its_age_from_virustotal(env, respx_mock, tmp_path):
    five_days_ago = int((datetime.now(UTC) - timedelta(days=5)).timestamp())
    created = datetime.fromtimestamp(five_days_ago, UTC).date()
    email = (
        'From: "Bank" <alerts@paypa1-login.lk>\nSubject: Verify\nContent-Type: text/html\n\n'
        '<a href="https://paypa1-login.lk/x">verify</a>\n'
    )
    path = tmp_path / "lk.eml"
    path.write_text(email, encoding="utf-8")
    stats = {"malicious": 0, "harmless": 60, "undetected": 30}
    body = {"data": {"attributes": {"last_analysis_stats": stats, "creation_date": five_days_ago}}}
    respx_mock.get(url__startswith="https://www.virustotal.com/").respond(200, json=body)
    respx_mock.post(url__startswith="https://urlhaus-api.abuse.ch/").respond(
        200, json={"query_status": "no_results"}
    )
    respx_mock.get("https://data.iana.org/rdap/dns.json").respond(
        200, json={"services": [[["com"], ["https://rdap.verisign.com/com/v1/"]]]}
    )
    result = analyze(path, env, "--enrich")
    out = result.output
    assert result.exit_code in (0, 1, 2), out  # a verdict
    assert "RDAP: no answer possible (no RDAP server for .lk in IANA's list)" in out
    assert f"Age: registered {created}, 5 days ago (VirusTotal WHOIS)" in out
    assert "domain_new" in out
    assert "(from VirusTotal WHOIS)" in out


def test_grouped_urls_that_were_not_looked_up(env, fake_apis, tmp_path):
    links = "".join(f'<a href="https://paypa1-login.com/c/{n}">{n}</a>' for n in range(12))
    body = PHISH_EML.split("--b1")[0]
    body = body.replace("Received: from mail.paypa1-login.com (mail.paypa1-login.com", "X-Old:")
    body = body.replace('multipart/mixed; boundary="b1"', "text/html; charset=utf-8")
    path = tmp_path / "many.eml"
    path.write_text(body + links + "\n", encoding="utf-8")
    fake_apis(created=f"{CREATED}T09:00:00Z")
    result = analyze(path, env, "--enrich", "--hosts-only")
    assert "0 checked, 12 not looked up" in result.output


# --- step 13: --dry-run ------------------------------------------------------------------------


def test_dry_run_sends_nothing_and_creates_no_cache(phish_email, env, respx_mock, tmp_path):
    result = analyze(phish_email, env, "--enrich", "--dry-run")
    out = result.output
    assert result.exit_code == 0, out
    assert "Dry run for 1 email: nothing was sent." in out
    assert "Already answered in the cache: 0 of 8" in out
    assert "VirusTotal: 3 to send (480 of today's 480 left), about 1 minute at 4 a minute" in out
    assert "AbuseIPDB: 1 to send (950 of today's 950 left)" in out
    assert "URLhaus: 3 to send" in out
    assert "RDAP: 1 to send" in out
    assert "Findings" not in out  # the plan only, no reports
    assert respx_mock.calls.call_count == 0
    assert not (tmp_path / "cache.sqlite3").exists()


def test_dry_run_after_a_real_run(phish_email, env, fake_apis):
    router = fake_apis(created=f"{CREATED}T09:00:00Z")
    analyze(phish_email, env, "--enrich")
    sent = router.calls.call_count
    result = analyze(phish_email, env, "--enrich", "--dry-run")
    assert "Already answered in the cache: 8 of 8" in result.output
    assert "VirusTotal: 0 to send (477 of today's 480 left)" in result.output
    assert router.calls.call_count == sent


def test_dry_run_warns_when_today_s_quota_is_too_small(phish_email, env, tmp_path, respx_mock):
    with Cache(tmp_path / "cache.sqlite3") as cache:
        for _ in range(479):
            cache.record_call("virustotal")
    result = analyze(phish_email, env, "--enrich", "--dry-run")
    assert "VirusTotal: 3 to send (1 of today's 480 left) more than is left today" in result.output


def test_dry_run_with_nothing_to_look_up(fixtures, env, respx_mock):
    result = analyze(fixtures / "legit_newsletter.eml", env, "--enrich", "--dry-run")
    assert "Nothing to look up: run without --dry-run" in result.output


def test_dry_run_without_keys_says_which_services_are_off(
    phish_email, env, monkeypatch, respx_mock
):
    monkeypatch.delenv("VT_API_KEY")
    result = analyze(phish_email, env, "--enrich", "--dry-run")
    assert "VirusTotal off: VT_API_KEY is not set" in result.output
    assert "VirusTotal:" not in result.output.replace("VirusTotal off", "")


def test_dry_run_alone_only_warns(phish_email, env, respx_mock):
    result = analyze(phish_email, env, "--dry-run")
    assert "only work with --enrich" in result.output


def test_nothing_to_look_up_without_keys(fixtures, env, monkeypatch, respx_mock):
    """The situation in Anuja's first --enrich screenshot (no keys in .env yet)."""
    for name in ("VT_API_KEY", "ABUSEIPDB_API_KEY", "ABUSECH_AUTH_KEY"):
        monkeypatch.delenv(name)
    result = analyze(fixtures / "legit_newsletter.eml", env, "--enrich")
    out = result.output
    assert "VirusTotal off: VT_API_KEY is not set" in out
    assert "URLhaus off: ABUSECH_AUTH_KEY is not set" in out
    assert "Nothing to look up" in out
    assert "From cache" not in out
    assert respx_mock.calls.call_count == 0


def test_stats_count_emails_that_could_not_be_analysed(phish_email, env, fake_apis, tmp_path):
    fake_apis(created=f"{CREATED}T09:00:00Z")
    folder = tmp_path / "batch"
    folder.mkdir()
    (folder / "good.eml").write_bytes(phish_email.read_bytes())
    (folder / "broken.eml").mkdir()  # a folder named .eml: cannot be read as a file
    stats = tmp_path / "run.json"
    result = analyze(folder, env, "--enrich", "--stats", str(stats))
    assert result.exit_code == 3  # no verdict for every file (week 4 exit codes)
    assert "Could not analyse broken.eml" in result.output
    assert json.loads(stats.read_text())["emails_failed"] == 1
