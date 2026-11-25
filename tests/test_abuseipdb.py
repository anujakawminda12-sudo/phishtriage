"""Week 3, step 10: the AbuseIPDB client.

The answers follow the "data" object in AbuseIPDB's API documentation (check endpoint),
trimmed to the fields we read, with made-up values.
"""

from datetime import UTC, datetime

import httpx
import pytest

from phishtriage.config import Secret
from phishtriage.enrich.abuseipdb import API, AbuseIPDB
from phishtriage.enrich.base import Fetcher, ServiceLimits
from phishtriage.enrich.cache import Cache
from phishtriage.enrich.models import DEFERRED, FAILED, FOUND, Lookup

KEY = "a" * 80
CLIENT = AbuseIPDB(Secret(KEY))
IP = "45.33.32.156"


def check_data(**fields) -> dict:
    data = {
        "ipAddress": IP,
        "isPublic": True,
        "ipVersion": 4,
        "isWhitelisted": False,
        "abuseConfidenceScore": 0,
        "countryCode": "US",
        "usageType": "Data Center/Web Hosting/Transit",
        "isp": "Example Hosting LLC",
        "domain": "example-hosting.com",
        "hostnames": [],
        "isTor": False,
        "totalReports": 0,
        "numDistinctUsers": 0,
        "lastReportedAt": None,
    }
    data.update(fields)
    return {"data": data}


def lookup(query: str = IP, kind: str = "ip") -> Lookup:
    return Lookup("abuseipdb", kind, query)


def parse(status: int, body):
    return CLIENT.parse(lookup(), httpx.Response(status, json=body))


def test_the_request():
    spec = CLIENT.request(lookup())
    assert (spec.method, spec.url) == ("GET", API)
    assert spec.params == {"ipAddress": IP, "maxAgeInDays": "90"}
    assert spec.headers == {"Key": KEY, "Accept": "application/json"}


def test_only_ips_are_checked():
    with pytest.raises(ValueError, match="only checks IP addresses"):
        CLIENT.request(lookup("paypa1-login.com", kind="domain"))


def test_limits_match_the_free_plan():
    assert CLIENT.limits == ServiceLimits(per_minute=60, per_day=1000, reserve=50)
    assert CLIENT.key_name == "ABUSEIPDB_API_KEY"


def test_a_reported_ip():
    body = check_data(
        abuseConfidenceScore=87,
        totalReports=45,
        numDistinctUsers=20,
        lastReportedAt="2026-11-20T08:15:00+00:00",
    )
    result = parse(200, body)
    assert result.status == FOUND
    assert result.summary == "confidence 87%, 45 reports from 20 users in 90 days (last 2026-11-20)"
    assert result.data == {
        "score": 87,
        "reports": 45,
        "distinct_users": 20,
        "is_tor": False,
        "is_whitelisted": False,
        "country": "US",
        "usage_type": "Data Center/Web Hosting/Transit",
        "isp": "Example Hosting LLC",
        "last_reported": "2026-11-20",
    }


def test_an_ip_with_no_reports_is_still_found():
    result = parse(200, check_data())
    assert result.status == FOUND  # AbuseIPDB knows every public IP
    assert result.summary == "confidence 0%, no reports in 90 days"


def test_a_tor_exit_node():
    result = parse(200, check_data(isTor=True, totalReports=3, numDistinctUsers=2))
    assert result.summary == "confidence 0%, 3 reports from 2 users in 90 days, Tor exit node"
    assert "last_reported" not in result.data


def test_missing_and_null_fields_are_handled():
    body = {"data": {"ipAddress": IP, "isWhitelisted": None, "countryCode": None}}
    result = parse(200, body)
    assert result.status == FOUND
    assert result.data == {
        "score": 0,
        "reports": 0,
        "distinct_users": 0,
        "is_tor": False,
        "is_whitelisted": False,
    }


def test_an_error_answer():
    body = {"errors": [{"detail": "The max age in days must be between 1 and 365.", "status": 422}]}
    result = parse(422, body)
    assert result.status == FAILED
    assert result.error == "AbuseIPDB said: The max age in days must be between 1 and 365. (422)"
    assert parse(400, {}).error == "AbuseIPDB said: an error (400)"


# --- through the Fetcher -------------------------------------------------------------------


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
def fetcher(tmp_path):
    clock = Clock()
    with Cache(tmp_path / "cache.sqlite3", clock) as cache:
        with Fetcher(
            {"abuseipdb": CLIENT}, cache, clock=clock, sleep=clock.sleep, jitter=lambda: 0.0
        ) as opened:
            yield opened


def test_end_to_end(fetcher, respx_mock):
    route = respx_mock.get(API, params={"ipAddress": IP, "maxAgeInDays": "90"}).mock(
        return_value=httpx.Response(200, json=check_data(abuseConfidenceScore=55, totalReports=9))
    )
    result = fetcher.fetch(lookup())
    assert result.status == FOUND
    assert result.data["score"] == 55
    request = route.calls[0].request
    assert request.headers["Key"] == KEY
    assert request.headers["Accept"] == "application/json"
    assert KEY not in str(request.url)  # the key is never in the URL
    assert fetcher.fetch(lookup()).from_cache is True


def test_the_daily_limit_answer_stops_abuseipdb(fetcher, respx_mock):
    respx_mock.get(API).mock(
        return_value=httpx.Response(
            429,
            headers={"Retry-After": "40000"},  # hours until the daily reset
            json={"errors": [{"detail": "Daily rate limit of 1000 requests exceeded"}]},
        )
    )
    assert fetcher.fetch(lookup()).status == FAILED
    assert fetcher.fetch(lookup("8.8.8.8")).status == DEFERRED
    assert fetcher.stats["abuseipdb"].quota_errors == 1
