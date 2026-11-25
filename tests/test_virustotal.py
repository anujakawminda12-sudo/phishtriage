"""Week 3, step 9: the VirusTotal client, with hand-made answers shaped like the real API.

The JSON below follows VirusTotal's documented objects (data.attributes, with
last_analysis_stats, reputation, tags, creation_date), trimmed to the fields we read.
"""

from datetime import UTC, datetime

import httpx
import pytest

from phishtriage.config import Secret
from phishtriage.enrich.base import Fetcher, ServiceLimits
from phishtriage.enrich.cache import Cache
from phishtriage.enrich.models import DEFERRED, FAILED, FOUND, NOT_FOUND, Lookup
from phishtriage.enrich.virustotal import API, VirusTotal, url_id

KEY = "v" * 64
VT = VirusTotal(Secret(KEY))
SHA = "e" * 64
WHEN = int(datetime(2026, 11, 20, tzinfo=UTC).timestamp())


def vt_object(malicious=0, suspicious=0, harmless=60, undetected=30, **attributes) -> dict:
    stats = {
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
        "timeout": 0,
    }
    return {
        "data": {
            "id": "x",
            "type": "domain",
            "attributes": {"last_analysis_stats": stats, "last_analysis_date": WHEN, **attributes},
        }
    }


def vt_error(code: str) -> dict:
    return {"error": {"code": code, "message": "a message"}}


def lookup(kind: str, query: str) -> Lookup:
    return Lookup("virustotal", kind, query)


def parse(kind: str, query: str, status: int, body=None):
    return VT.parse(lookup(kind, query), httpx.Response(status, json=body))


# --- requests ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("kind", "query", "url"),
    [
        ("file", SHA, f"{API}/files/{SHA}"),
        ("domain", "login.paypa1-login.com", f"{API}/domains/login.paypa1-login.com"),
        ("ip", "45.33.32.156", f"{API}/ip_addresses/45.33.32.156"),
        ("ip", "2001:4860:4860::8888", f"{API}/ip_addresses/2001:4860:4860::8888"),
        ("url", "http://www.example.com/", f"{API}/urls/aHR0cDovL3d3dy5leGFtcGxlLmNvbS8"),
    ],
)
def test_requests(kind, query, url):
    spec = VT.request(lookup(kind, query))
    assert (spec.method, spec.url) == ("GET", url)
    assert spec.headers == {"x-apikey": KEY}


def test_url_id_is_url_safe_base64_without_padding():
    assert url_id("http://www.example.com/") == "aHR0cDovL3d3dy5leGFtcGxlLmNvbS8"
    odd = url_id("https://x.test/?a=1&b=%2F~")  # would contain "/" or "+" in plain base64
    assert "=" not in odd and "/" not in odd and "+" not in odd


def test_an_unknown_kind_is_a_bug_not_a_request():
    with pytest.raises(KeyError):
        VT.request(lookup("host", "x.com"))  # "host" is URLhaus's kind, not VirusTotal's


def test_limits_match_the_free_plan():
    assert VT.limits == ServiceLimits(per_minute=4, per_day=500, reserve=20)
    assert VT.limits.daily_budget == 480
    assert VT.key_name == "VT_API_KEY"


# --- answers -------------------------------------------------------------------------------


def test_a_flagged_domain():
    body = vt_object(
        malicious=6, suspicious=1, harmless=50, undetected=37, reputation=-12,
        creation_date=int(datetime(2026, 11, 15, tzinfo=UTC).timestamp()),
        tags=["phishing", "dga"],
    )  # fmt: skip
    result = parse("domain", "paypa1-login.com", 200, body)
    assert result.status == FOUND
    assert result.summary == "6 of 94 engines: malicious, 1 suspicious"
    assert result.data == {
        "malicious": 6,
        "suspicious": 1,
        "harmless": 50,
        "undetected": 37,
        "timeout": 0,
        "engines": 94,
        "reputation": -12,
        "last_analysis": "2026-11-20",
        "created": "2026-11-15",  # WHOIS creation date: a backup domain age
        "tags": ["phishing", "dga"],
    }


def test_suspicious_only_and_clean():
    assert parse("url", "https://x.com/", 200, vt_object(suspicious=2)).summary == (
        "2 of 92 engines: suspicious"
    )
    clean = parse("ip", "8.8.8.8", 200, vt_object())
    assert clean.status == FOUND  # known to VirusTotal ...
    assert clean.summary == "0 of 90 engines flag it"  # ... and nothing flags it


def test_known_but_never_scanned():
    body = {"data": {"attributes": {}}}
    result = parse("file", SHA, 200, body)
    assert result.status == FOUND
    assert result.summary == "known to VirusTotal, not scanned yet"
    assert result.data["engines"] == 0
    assert "last_analysis" not in result.data


def test_creation_date_is_only_read_for_domains():
    body = vt_object(creation_date=WHEN)
    assert "created" not in parse("ip", "8.8.8.8", 200, body).data


@pytest.mark.parametrize("bad", ["2026-11-15", -5, 0, True, None, 1.5])
def test_odd_timestamps_and_tags_are_ignored(bad):
    body = vt_object(creation_date=bad, tags="not-a-list")
    body["data"]["attributes"]["last_analysis_date"] = bad
    result = parse("domain", "paypa1-login.com", 200, body)
    assert "created" not in result.data
    assert "last_analysis" not in result.data
    assert "tags" not in result.data


def test_only_the_first_ten_tags_are_kept():
    body = vt_object(tags=[f"t{n}" for n in range(25)])
    assert parse("domain", "x.com", 200, body).data["tags"] == [f"t{n}" for n in range(10)]


def test_never_seen():
    result = parse("url", "https://x.com/", 404, vt_error("NotFoundError"))
    assert (result.status, result.summary) == (NOT_FOUND, "never seen")


@pytest.mark.parametrize("code", ["InvalidArgumentError", "NotAvailableYet"])
def test_a_400_is_a_failed_answer(code):
    result = parse("domain", "bad..name", 400, vt_error(code))
    assert (result.status, result.error) == (FAILED, f"VirusTotal said {code} (400)")


def test_an_error_without_a_code():
    result = parse("domain", "x.com", 400, {})
    assert result.error == "VirusTotal said an error (400)"


# --- through the Fetcher (rate limits, cache, key handling) ------------------------------------


class Clock:
    def __init__(self) -> None:
        self.now = datetime(2026, 11, 23, 9, 0, tzinfo=UTC)
        self.slept: list[float] = []

    def __call__(self) -> datetime:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.now = datetime.fromtimestamp(self.now.timestamp() + seconds, UTC)


@pytest.fixture
def setup(tmp_path):
    clock = Clock()
    with Cache(tmp_path / "cache.sqlite3", clock) as cache:
        with Fetcher(
            {"virustotal": VT}, cache, clock=clock, sleep=clock.sleep, jitter=lambda: 0.0
        ) as fetcher:
            yield fetcher, cache, clock


def test_end_to_end_found_and_cached(setup, respx_mock):
    fetcher, cache, _ = setup
    route = respx_mock.get(f"{API}/domains/paypa1-login.com").mock(
        return_value=httpx.Response(200, json=vt_object(malicious=4))
    )
    first = fetcher.fetch(lookup("domain", "paypa1-login.com"))
    assert first.status == FOUND
    assert route.calls[0].request.headers["x-apikey"] == KEY
    assert fetcher.fetch(lookup("domain", "paypa1-login.com")).from_cache is True
    assert route.call_count == 1
    assert cache.calls_within("virustotal") == 1


def test_end_to_end_url_lookup_uses_the_base64_id(setup, respx_mock):
    fetcher, _, _ = setup
    url = "https://login.paypa1-login.com/verify?a=1"
    route = respx_mock.get(f"{API}/urls/{url_id(url)}").mock(
        return_value=httpx.Response(404, json=vt_error("NotFoundError"))
    )
    assert fetcher.fetch(lookup("url", url)).status == NOT_FOUND
    assert route.call_count == 1


def test_a_wrong_key_stops_virustotal_for_the_run(setup, respx_mock):
    fetcher, _, _ = setup
    respx_mock.get(f"{API}/domains/a.com").mock(
        return_value=httpx.Response(401, json=vt_error("WrongCredentialsError"))
    )
    first = fetcher.fetch(lookup("domain", "a.com"))
    assert first.error == (
        "the key was refused (401; the service said: WrongCredentialsError: a message): "
        "check VT_API_KEY in .env"
    )
    assert fetcher.fetch(lookup("domain", "b.com")).status == DEFERRED


def test_a_quota_error_without_retry_after_waits_a_minute(setup, respx_mock):
    fetcher, _, clock = setup
    respx_mock.get(f"{API}/domains/a.com").mock(
        side_effect=[
            httpx.Response(429, json=vt_error("QuotaExceededError")),
            httpx.Response(200, json=vt_object()),
        ]
    )
    assert fetcher.fetch(lookup("domain", "a.com")).status == FOUND
    assert 60.0 in clock.slept
    assert fetcher.stats["virustotal"].quota_errors == 1


def test_four_a_minute(setup, respx_mock):
    fetcher, _, clock = setup
    respx_mock.get(url__startswith=f"{API}/domains/").mock(
        return_value=httpx.Response(200, json=vt_object())
    )
    for n in range(9):
        fetcher.fetch(lookup("domain", f"site-{n}.com"))
    assert clock.slept == [61.0, 61.0]  # requests 5 and 9 each wait for a free slot
