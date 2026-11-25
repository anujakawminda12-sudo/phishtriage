"""Week 3, step 12: the enricher runs the plan and turns answers into findings."""

from datetime import UTC, date, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from conftest import PHISH_ME

from phishtriage.allowlist import load_allowlist
from phishtriage.analysis import EmailAnalysis, analyse_file
from phishtriage.config import Secret, Settings
from phishtriage.enrich.enricher import (
    NEW_DOMAIN_DAYS,
    Enrichment,
    enrich,
    facts_for,
    make_services,
    notable,
    shared_platform,
)
from phishtriage.enrich.models import (
    DEFERRED,
    FOUND,
    NOT_FOUND,
    UNSUPPORTED,
    Lookup,
    LookupResult,
)
from phishtriage.enrich.plan import YOUR_ADDRESS, build_plan
from phishtriage.models import IOC, AuthResults, Finding, ParsedEmail, SenderIP
from phishtriage.privacy import AddressRedactor

ALLOWLIST = load_allowlist()
KEY = Secret("k" * 64)
NOW = datetime(2026, 11, 23, 9, 0, tzinfo=UTC)
TEN_DAYS_AGO = (NOW - timedelta(days=10)).strftime("%Y-%m-%dT%H:%M:%SZ")


class Clock:
    def __init__(self) -> None:
        self.now = NOW
        self.slept: list[float] = []

    def __call__(self) -> datetime:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.now += timedelta(seconds=seconds)


def settings(tmp_path: Path, **keys) -> Settings:
    keys = keys or {"vt_api_key": KEY, "abuseipdb_api_key": KEY, "abusech_auth_key": KEY}
    return Settings(cache_path=tmp_path / "cache" / "cache.sqlite3", **keys)


def run(analyses, config: Settings, clock: Clock | None = None, **options) -> Enrichment:
    clock = clock or Clock()
    return enrich(
        analyses, config, ALLOWLIST, clock=clock, sleep=clock.sleep, jitter=lambda: 0.0, **options
    )


@pytest.fixture
def phish(phish_email) -> EmailAnalysis:
    return analyse_file(phish_email, ALLOWLIST)


def ioc(analysis: EmailAnalysis, kind: str, value: str | None = None) -> IOC:
    return next(i for i in analysis.iocs if i.kind == kind and (value is None or i.value == value))


# --- the whole run ----------------------------------------------------------------------------


def test_every_planned_lookup_gets_an_answer(phish, tmp_path, fake_apis):
    fake_apis(created=TEN_DAYS_AGO)
    enrichment = run([phish], settings(tmp_path))

    assert len(enrichment.results) == len(enrichment.plan.lookups) == 8
    assert enrichment.unanswered() == 0
    assert enrichment.stopped == {}
    assert enrichment.warnings == []
    stats = enrichment.stats
    assert (stats["virustotal"].found, stats["virustotal"].not_found) == (2, 1)  # file: 404
    assert stats["rdap"].api_calls == 2  # IANA's list, then the domain
    assert sum(s.quota_errors for s in stats.values()) == 0
    assert enrichment.calls_24h == {"virustotal": 3, "abuseipdb": 1, "urlhaus": 3, "rdap": 2}
    assert enrichment.budgets == {
        "virustotal": 480,
        "abuseipdb": 950,
        "urlhaus": None,
        "rdap": None,
    }


def test_findings_without_points(phish, tmp_path, fake_apis):
    fake_apis(created=TEN_DAYS_AGO)
    findings = run([phish], settings(tmp_path)).findings_for(phish)
    details = {(f.rule, f.detail) for f in findings}
    assert details == {
        (
            "vt_flagged",
            "hxxps://paypa1-login[.]com/login: VirusTotal says 5 of 95 engines: malicious",
        ),
        ("vt_flagged", "paypa1-login[.]com: VirusTotal says 5 of 95 engines: malicious"),
        (
            "urlhaus_listed",
            "hxxps://paypa1-login[.]com/login: URLhaus says listed: malware_download (online)",
        ),
        (
            "abuseipdb_reported",
            "45[.]33[.]32[.]156: AbuseIPDB says confidence 90%, 30 reports from 12 users "
            "in 90 days",
        ),
        (
            "domain_new",
            "paypa1-login[.]com was registered 2026-11-13, 10 days before this analysis "
            "(from RDAP)",
        ),
    }
    assert all("http://" not in f.detail and "https://" not in f.detail for f in findings)


def test_your_address_is_never_sent_to_any_service(phish, tmp_path, fake_apis):
    router = fake_apis(created=TEN_DAYS_AGO)
    enrichment = run([phish], settings(tmp_path))
    redactor = AddressRedactor([PHISH_ME])
    assert router.calls  # requests were made ...
    for call in router.calls:  # ... and none of them carries the address in any form
        sent = str(call.request.url) + call.request.content.decode()
        assert not redactor.contains(sent), sent
    verify = ioc(phish, "url", "https://paypa1-login.com/verify?u=me.victim%40gmail.com")
    assert enrichment.target(verify).skipped == [YOUR_ADDRESS]


def test_a_second_run_is_answered_from_the_cache(phish, tmp_path, fake_apis):
    router = fake_apis(created=TEN_DAYS_AGO)
    config = settings(tmp_path)
    clock = Clock()
    run([phish], config, clock)
    sent = len(router.calls)
    clock.now += timedelta(hours=1)
    second = run([phish], config, clock)
    assert len(router.calls) == sent  # nothing new was sent
    assert sum(s.cache_hits for s in second.stats.values()) == 8  # IANA's list is not counted
    assert sum(s.api_calls for s in second.stats.values()) == 0


def answers(stats) -> int:
    """Every answer column of the summary table: one per lookup that was planned."""
    return (
        stats.cache_hits
        + stats.found
        + stats.not_found
        + stats.failed
        + stats.deferred
        + stats.unsupported
    )


def test_the_answer_columns_add_up_to_planned(phish, tmp_path, fake_apis):
    """Week 4: IANA's list of RDAP servers used to be counted as a found domain."""
    fake_apis(created=TEN_DAYS_AGO)
    config = settings(tmp_path)
    clock = Clock()
    for _ in range(2):  # the first run asks the APIs, the second the cache
        enrichment = run([phish], config, clock)
        for name, stats in enrichment.stats.items():
            assert answers(stats) == enrichment.plan.count(name), name
        clock.now += timedelta(hours=1)
    first_rdap = run([phish], settings(tmp_path / "new"), Clock()).stats["rdap"]
    # the list is really downloaded, so it still counts as an API call (and in the daily log)
    assert first_rdap.api_calls == first_rdap.found + first_rdap.not_found + 1


def test_nothing_to_look_up_opens_no_cache_and_sends_nothing(tmp_path, respx_mock):
    reserved = [
        IOC("domain", "paypa1-secure.test", ["url"], 1),
        IOC("ip", "203.0.113.45", ["header:Received (hop 1)"], 1),
        IOC("email", "x@paypa1-secure.test", ["header:From"], 1),
    ]
    analysis = EmailAnalysis(
        email=ParsedEmail(path=Path("x.eml")), auth=AuthResults(), iocs=reserved
    )
    config = settings(tmp_path)
    enrichment = run([analysis], config)
    assert enrichment.plan.lookups == []
    assert enrichment.results == {}
    assert not config.cache_path.exists()
    assert respx_mock.calls.call_count == 0


def test_max_lookups_and_hosts_only_are_passed_on(phish, tmp_path, fake_apis):
    fake_apis(created=TEN_DAYS_AGO)
    limited = run([phish], settings(tmp_path), max_lookups=1)
    assert limited.unanswered() > 0
    assert limited.stats["virustotal"].deferred == 2
    hosts = run([phish], settings(tmp_path / "other"), hosts_only=True)
    assert all(lookup.kind != "url" for lookup in hosts.plan.lookups)


# --- when things go wrong ------------------------------------------------------------------------


def test_without_iana_s_list_rdap_is_stopped_and_the_rest_still_runs(phish, tmp_path, fake_apis):
    fake_apis(created=TEN_DAYS_AGO, iana_status=503)
    enrichment = run([phish], settings(tmp_path))
    rdap = Lookup("rdap", "domain", "paypa1-login.com")
    assert enrichment.results[rdap].status == DEFERRED
    # (base.py retried the 503 twice before giving up, as for any server error)
    assert enrichment.stopped["rdap"] == (
        "IANA's list of RDAP servers could not be loaded (server error 503 after 3 tries)"
    )
    assert enrichment.results[Lookup("abuseipdb", "ip", "45.33.32.156")].status == FOUND


def test_ctrl_c_keeps_the_answers_so_far(phish, tmp_path, fake_apis, respx_mock):
    fake_apis(created=TEN_DAYS_AGO)

    def press_ctrl_c(request: httpx.Request) -> httpx.Response:
        raise KeyboardInterrupt  # what pressing Ctrl+C does while a request is waiting

    respx_mock.get("https://api.abuseipdb.com/api/v2/check").mock(side_effect=press_ctrl_c)
    config = settings(tmp_path)
    enrichment = run([phish], config)  # AbuseIPDB is the last lookup: Ctrl+C there
    assert len(enrichment.results) == 8
    ip = enrichment.results[Lookup("abuseipdb", "ip", "45.33.32.156")]
    assert (ip.status, ip.error) == (DEFERRED, "stopped with Ctrl+C")
    assert enrichment.stopped == dict.fromkeys(
        ("virustotal", "abuseipdb", "urlhaus", "rdap"), "stopped with Ctrl+C"
    )
    assert enrichment.unanswered() == 1
    # Everything before it was cached: the next run starts from there
    again = run([phish], config)
    assert again.stats["virustotal"].cache_hits == 3


def test_services_without_keys_are_not_built(tmp_path):
    assert set(make_services(settings(tmp_path))) == {"virustotal", "abuseipdb", "urlhaus", "rdap"}
    assert set(make_services(settings(tmp_path, abusech_auth_key=KEY))) == {"urlhaus", "rdap"}


# --- domain age and the findings' thresholds ---------------------------------------------------


def lk_domain_enrichment(created: str) -> tuple[Enrichment, IOC]:
    """A .lk domain: RDAP has no server for it, VirusTotal knows its WHOIS date."""
    host = IOC("domain", "paypa1-login.lk", ["url"], 1)
    analysis = EmailAnalysis(email=ParsedEmail(path=Path("x.eml")), auth=AuthResults(), iocs=[host])
    plan = build_plan([analysis], Settings(vt_api_key=KEY), ALLOWLIST)
    enrichment = Enrichment(plan=plan, analysed_on=date(2026, 11, 23))
    vt, rdap = (Lookup("virustotal", "domain", host.value), Lookup("rdap", "domain", host.value))
    enrichment.results[vt] = LookupResult(
        vt, FOUND, summary="0 of 90 engines flag it", data={"created": created}
    )
    enrichment.results[rdap] = LookupResult(rdap, UNSUPPORTED, error="no RDAP server for .lk")
    return enrichment, host  # fmt: skip


def test_a_domain_without_rdap_gets_its_age_from_virustotal():
    enrichment, host = lk_domain_enrichment("2026-11-18")
    assert enrichment.domain_age(host) == ("2026-11-18", 5, "VirusTotal WHOIS")
    analysis = EmailAnalysis(email=ParsedEmail(path=Path("x.eml")), auth=AuthResults(), iocs=[host])
    [finding] = enrichment.findings_for(analysis)
    assert finding.rule == "domain_new"
    assert finding.detail.endswith("5 days before this analysis (from VirusTotal WHOIS)")


def test_an_old_domain_or_an_unreadable_date_gives_no_finding():
    for created in ("2020-01-01", "not-a-date"):
        enrichment, host = lk_domain_enrichment(created)
        analysis = EmailAnalysis(
            email=ParsedEmail(path=Path("x.eml")), auth=AuthResults(), iocs=[host]
        )
        assert enrichment.findings_for(analysis) == []
    enrichment, host = lk_domain_enrichment("2026-10-24")  # exactly 30 days: not "new"
    assert enrichment.domain_age(host)[1] == NEW_DOMAIN_DAYS
    assert enrichment.domain_age(IOC("url", "https://x.lk/", ["html"], 1)) is None


@pytest.mark.parametrize(
    ("service", "status", "data", "rule"),
    [
        ("virustotal", FOUND, {"malicious": 1}, "vt_flagged"),
        ("virustotal", FOUND, {"suspicious": 1}, "vt_flagged"),
        ("virustotal", FOUND, {"malicious": 0, "suspicious": 0}, None),
        ("virustotal", NOT_FOUND, {}, None),
        ("urlhaus", FOUND, {}, "urlhaus_listed"),
        ("urlhaus", NOT_FOUND, {}, None),
        ("abuseipdb", FOUND, {"reports": 1, "score": 0}, "abuseipdb_reported"),
        ("abuseipdb", FOUND, {"reports": 0, "score": 0}, None),
        ("rdap", FOUND, {"created": "2026-11-20"}, None),  # age is its own rule
    ],
)
def test_which_answers_become_findings(service, status, data, rule):
    assert notable(LookupResult(Lookup(service, "x", "y"), status, data=data)) == rule


def test_forwarded_emails_get_their_own_findings(tmp_path, fake_apis):
    """The findings for an email cover its own IOCs, not those of an email inside it."""
    fake_apis(created=TEN_DAYS_AGO)
    inner_email = ParsedEmail(path=Path("inner.eml"), depth=1)
    hop = IOC("ip", "45.33.32.156", ["header:Received (hop 1)"], 1)  # AbuseIPDB only
    inner = EmailAnalysis(email=inner_email, auth=AuthResults(), iocs=[hop])
    outer = EmailAnalysis(
        email=ParsedEmail(path=Path("outer.eml")), auth=AuthResults(), forwarded=[inner]
    )
    enrichment = run([outer], settings(tmp_path))  # fmt: skip
    assert enrichment.findings_for(outer) == []
    assert [f.rule for f in enrichment.findings_for(inner)] == ["abuseipdb_reported"]


def test_rdap_lookups_without_an_rdap_client_fail_cleanly(phish, tmp_path, fake_apis):
    """If the services given have no RDAP client, its lookups fail; nothing crashes."""
    fake_apis(created=TEN_DAYS_AGO)
    services = {name: s for name, s in make_services(settings(tmp_path)).items() if name != "rdap"}
    clock = Clock()
    enrichment = enrich(
        [phish], settings(tmp_path), ALLOWLIST, clock=clock, sleep=clock.sleep, services=services
    )
    rdap = enrichment.results[Lookup("rdap", "domain", "paypa1-login.com")]
    assert (rdap.status, rdap.error) == ("failed", "no client for rdap")


# --- week 4, step 7: the numbers behind each finding (Finding.facts) -----------------------


def test_each_finding_carries_its_numbers(phish, tmp_path, fake_apis):
    """The test phish has no Authentication-Results, so its sender IP comes from the
    Received chain: 45.33.32.156, the IP AbuseIPDB was asked about."""
    fake_apis(created=TEN_DAYS_AGO)
    findings = run([phish], settings(tmp_path)).findings_for(phish)
    facts = {(f.rule, f.facts.get("kind")): f.facts for f in findings}
    assert facts == {
        ("vt_flagged", "url"): {
            "service": "virustotal",
            "kind": "url",
            "malicious": 5,
            "suspicious": 0,
            "engines": 95,
            "shared_platform": False,
        },
        ("vt_flagged", "domain"): {
            "service": "virustotal",
            "kind": "domain",
            "malicious": 5,
            "suspicious": 0,
            "engines": 95,
            "shared_platform": False,
        },
        ("urlhaus_listed", "url"): {
            "service": "urlhaus",
            "kind": "url",
            "online": True,
            "shared_platform": False,
        },
        ("abuseipdb_reported", "ip"): {
            "service": "abuseipdb",
            "kind": "ip",
            "score": 90,
            "reports": 30,
            "whitelisted": False,
            "shared_platform": False,
            "sender_ip": True,
        },
        ("domain_new", "domain"): {"service": "rdap", "kind": "domain", "days": 10},
    }


def test_facts_never_hold_a_value_from_the_email(phish, tmp_path, fake_apis):
    """Only numbers, true/false and fixed words: so facts can never be a live link."""
    fake_apis(created=TEN_DAYS_AGO)
    words = {"virustotal", "urlhaus", "abuseipdb", "rdap", "url", "domain", "host", "ip", "file"}
    for finding in run([phish], settings(tmp_path)).findings_for(phish):
        for value in finding.facts.values():
            assert isinstance(value, (bool, int)) or value in words, (finding.rule, value)


def answer(service: str, kind: str, query: str, **data) -> LookupResult:
    return LookupResult(Lookup(service, kind, query), FOUND, data=data)


@pytest.mark.parametrize(
    ("result", "facts"),
    [
        # URLhaus: a URL that is no longer online
        (
            answer("urlhaus", "url", "https://evil.test/a", url_status="offline"),
            {"service": "urlhaus", "kind": "url", "online": False, "shared_platform": False},
        ),
        # URLhaus: a host, with how many listed URLs are still online
        (
            answer("urlhaus", "host", "www.patreon.com", url_count=1, online=0),
            {
                "service": "urlhaus",
                "kind": "host",
                "online_urls": 0,
                "listed_urls": 1,
                "shared_platform": False,
            },
        ),
        # URLhaus and VirusTotal on a file: no platform, no sender
        (
            answer("urlhaus", "file", "a" * 64, signature="Emotet"),
            {"service": "urlhaus", "kind": "file"},
        ),
        (
            answer("virustotal", "file", "a" * 64, malicious=7, suspicious=1, engines=70),
            {
                "service": "virustotal",
                "kind": "file",
                "malicious": 7,
                "suspicious": 1,
                "engines": 70,
            },
        ),
        # AbuseIPDB's own list of known-good IPs
        (
            answer("abuseipdb", "ip", "203.0.113.9", score=0, reports=2, is_whitelisted=True),
            {
                "service": "abuseipdb",
                "kind": "ip",
                "score": 0,
                "reports": 2,
                "whitelisted": True,
                "shared_platform": False,
                "sender_ip": False,
            },
        ),
        # numbers the answer did not include count as 0
        (
            answer("virustotal", "domain", "evil.test"),
            {
                "service": "virustotal",
                "kind": "domain",
                "malicious": 0,
                "suspicious": 0,
                "engines": 0,
                "shared_platform": False,
            },
        ),
    ],
)
def test_facts_for_each_service(result, facts):
    assert facts_for(result, "45.33.32.156", ALLOWLIST) == facts


@pytest.mark.parametrize(
    ("query", "sender", "is_sender"),
    [
        ("45.33.32.156", "45.33.32.156", True),
        ("45.33.32.156", "198.51.100.7", False),
        ("45.33.32.156", "", False),  # no sender IP known
        ("2001:DB8::0:1", "2001:db8::1", True),  # one address, two spellings
    ],
)
def test_sender_ip_fact(query, sender, is_sender):
    for service, kind in (("abuseipdb", "ip"), ("virustotal", "ip"), ("urlhaus", "host")):
        assert facts_for(answer(service, kind, query), sender, ALLOWLIST)["sender_ip"] is is_sender


def test_no_sender_ip_fact_for_a_name():
    facts = facts_for(answer("urlhaus", "host", "mail.evil.test"), "45.33.32.156", ALLOWLIST)
    assert "sender_ip" not in facts


@pytest.mark.parametrize(
    ("host", "allowlist", "shared"),
    [
        ("user.github.io", ALLOWLIST, True),  # a private suffix
        ("user.github.io", None, True),  # needs no allowlist
        ("docs.google.com", ALLOWLIST, True),  # a user-content host of an allowlisted owner
        ("docs.google.com", None, False),  # without the allowlist, nothing says so
        ("paypa1-login.com", ALLOWLIST, False),
        ("www.patreon.com", ALLOWLIST, False),  # a big site on its own name: thresholds instead
        ("45.33.32.156", ALLOWLIST, False),
        ("", ALLOWLIST, False),
    ],
)
def test_shared_platform(host, allowlist, shared):
    assert shared_platform(host, allowlist) is shared


@pytest.mark.parametrize(
    ("url", "shared"),
    [
        ("https://user.github.io/login", True),  # the URL's host decides
        ("https://paypa1-login.com/login", False),
        ("http://[::1", False),  # a broken URL has no host
    ],
)
def test_a_urls_host_decides_its_platform(url, shared):
    facts = facts_for(answer("virustotal", "url", url), "", ALLOWLIST)
    assert facts["shared_platform"] is shared


def test_domain_age_facts_name_their_source():
    enrichment, host = lk_domain_enrichment("2026-11-18")
    analysis = EmailAnalysis(email=ParsedEmail(path=Path("x.eml")), auth=AuthResults(), iocs=[host])
    [finding] = enrichment.findings_for(analysis)
    assert finding.facts == {"service": "virustotal", "kind": "domain", "days": 5}


def test_an_analysis_without_a_sender_ip(tmp_path, fake_apis):
    fake_apis(created=TEN_DAYS_AGO)
    hop = IOC("ip", "45.33.32.156", ["header:Received (hop 2)"], 1)
    analysis = EmailAnalysis(email=ParsedEmail(path=Path("x.eml")), auth=AuthResults(), iocs=[hop])
    [finding] = run([analysis], settings(tmp_path)).findings_for(analysis)
    assert finding.facts["sender_ip"] is False
    analysis.sender_ip = SenderIP("45.33.32.156", "Authentication-Results")
    [finding] = run([analysis], settings(tmp_path)).findings_for(analysis)
    assert finding.facts["sender_ip"] is True


def test_the_enrichment_keeps_the_allowlist_it_used(phish, tmp_path, fake_apis):
    fake_apis(created=TEN_DAYS_AGO)
    assert run([phish], settings(tmp_path)).allowlist is ALLOWLIST


def test_facts_are_empty_by_default_and_part_of_equality():
    plain = Finding("reply_to_mismatch", "Reply-To differs")
    assert plain.facts == {}
    assert plain == Finding("reply_to_mismatch", "Reply-To differs")
    assert plain != Finding("reply_to_mismatch", "Reply-To differs", {"days": 1})
