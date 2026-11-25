"""Week 3, step 10: the URLhaus client (abuse.ch community API v1).

The answers are made up, shaped like the community API's answers (a query_status plus
the fields we read). Both "firstseen" and "first_seen" are tested, because the newer
abuse.ch documentation spells some fields differently.
"""

from datetime import UTC, datetime

import httpx
import pytest

from phishtriage.config import Secret
from phishtriage.enrich.base import Fetcher, ServiceLimits
from phishtriage.enrich.cache import Cache
from phishtriage.enrich.models import DEFERRED, FAILED, FOUND, NOT_FOUND, Lookup
from phishtriage.enrich.urlhaus import API, URLhaus

KEY = "c" * 48
CLIENT = URLhaus(Secret(KEY))
URL = "http://203-0-113-9.example-cdn.com/invoice.zip"
SHA = "f" * 64


def lookup(kind: str, query: str) -> Lookup:
    return Lookup("urlhaus", kind, query)


def parse(kind: str, query: str, body, status: int = 200):
    return CLIENT.parse(lookup(kind, query), httpx.Response(status, json=body))


# --- requests ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("kind", "query", "path", "field"),
    [
        ("url", URL, f"{API}/url/", "url"),
        ("host", "example-cdn.com", f"{API}/host/", "host"),
        ("host", "45.33.32.156", f"{API}/host/", "host"),  # a host can be an IP
        ("file", SHA, f"{API}/payload/", "sha256_hash"),
    ],
)
def test_requests(kind, query, path, field):
    spec = CLIENT.request(lookup(kind, query))
    assert (spec.method, spec.url) == ("POST", path)
    assert spec.data == {field: query}
    assert spec.headers == {"Auth-Key": KEY}  # in a header, never in the URL


def test_an_unknown_kind_is_a_bug():
    with pytest.raises(KeyError):
        CLIENT.request(lookup("domain", "x.com"))  # URLhaus calls it "host"


def test_limits():
    assert CLIENT.limits == ServiceLimits(per_minute=60)  # fair use: no daily quota
    assert CLIENT.limits.daily_budget is None
    assert CLIENT.key_name == "ABUSECH_AUTH_KEY"


# --- answers -------------------------------------------------------------------------------


def test_a_listed_url():
    body = {
        "query_status": "ok",
        "url": URL,
        "url_status": "online",
        "threat": "malware_download",
        "date_added": "2026-11-02 08:15:00 UTC",
        "tags": ["zip", "AgentTesla"],
        "blacklists": {"spamhaus_dbl": "abused_legit_malware", "surbl": "not listed"},
    }
    result = parse("url", URL, body)
    assert result.status == FOUND
    assert result.summary == "listed: malware_download (online), added 2026-11-02"
    assert result.data == {
        "url_status": "online",
        "threat": "malware_download",
        "tags": ["zip", "AgentTesla"],
        "added": "2026-11-02",
        "spamhaus_dbl": "abused_legit_malware",  # "not listed" entries are dropped
    }


def test_a_listed_url_with_the_newer_field_names():
    body = {"query_status": "ok", "url_status": "offline", "first_seen": "2026-10-30T10:00:00Z"}
    result = parse("url", URL, body)
    assert result.summary == "listed: unknown (offline), added 2026-10-30"


def test_a_listed_url_with_odd_values():
    body = {"query_status": "ok", "tags": "zip", "blacklists": "none", "date_added": "yesterday"}
    result = parse("url", URL, body)
    assert result.summary == "listed: unknown (unknown)"
    assert result.data == {"url_status": "unknown", "threat": "unknown", "tags": []}


def test_a_listed_host():
    body = {
        "query_status": "ok",
        "host": "example-cdn.com",
        "firstseen": "2026-09-01 12:00:00 UTC",
        "url_count": "3",
        "blacklists": {"spamhaus_dbl": "not listed", "surbl": "listed"},
        "urls": [
            {"url": "http://example-cdn.com/a", "url_status": "online"},
            {"url": "http://example-cdn.com/b", "url_status": "offline"},
            {"url": "http://example-cdn.com/c", "url_status": "offline"},
        ],
    }
    result = parse("host", "example-cdn.com", body)
    assert result.summary == "lists 3 malware URLs on this host (1 online)"
    assert result.data == {
        "url_count": 3,
        "online": 1,
        "first_seen": "2026-09-01",
        "surbl": "listed",
    }


def test_a_host_without_a_usable_url_count():
    body = {"query_status": "ok", "url_count": "many", "urls": [{"url_status": "online"}, "junk"]}
    assert parse("host", "x.com", body).data == {"url_count": 2, "online": 1}
    assert parse("host", "x.com", {"query_status": "ok", "urls": "junk"}).data == {
        "url_count": 0,
        "online": 0,
    }


def test_a_known_payload():
    body = {
        "query_status": "ok",
        "sha256_hash": SHA,
        "file_type": "exe",
        "signature": "AgentTesla",
        "url_count": 12,
        "firstseen": "2026-11-01 00:00:00",
        "lastseen": "2026-11-20 00:00:00",
    }
    result = parse("file", SHA, body)
    assert result.summary == "known malware: AgentTesla (exe)"
    assert result.data == {
        "file_type": "exe",
        "signature": "AgentTesla",
        "url_count": 12,
        "first_seen": "2026-11-01",
        "last_seen": "2026-11-20",
    }


def test_a_payload_without_a_family_name():
    body = {"query_status": "ok", "file_type": "zip", "signature": None}
    assert parse("file", SHA, body).summary == "known malware: family unknown (zip)"


def test_not_in_urlhaus():
    result = parse("host", "paypa1-login.com", {"query_status": "no_results"})
    assert (result.status, result.summary) == (NOT_FOUND, "not listed")


@pytest.mark.parametrize(
    ("body", "error"),
    [
        ({"query_status": "invalid_host"}, "URLhaus said invalid_host"),
        ({"query_status": "invalid_sha256_hash"}, "URLhaus said invalid_sha256_hash"),
        ({}, "URLhaus said nothing"),
    ],
)
def test_other_query_statuses_are_failed(body, error):
    result = parse("host", "x.com", body)
    assert (result.status, result.error) == (FAILED, error)


# --- through the Fetcher -----------------------------------------------------------------------


class Clock:
    def __init__(self) -> None:
        self.now = datetime(2026, 11, 23, 9, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now = datetime.fromtimestamp(self.now.timestamp() + seconds, UTC)


@pytest.fixture
def fetcher(tmp_path):
    clock = Clock()
    with Cache(tmp_path / "cache.sqlite3", clock) as cache:
        with Fetcher(
            {"urlhaus": CLIENT}, cache, clock=clock, sleep=clock.sleep, jitter=lambda: 0.0
        ) as opened:
            yield opened


def test_end_to_end_a_form_post_with_the_key_in_a_header(fetcher, respx_mock):
    route = respx_mock.post(f"{API}/url/").mock(
        return_value=httpx.Response(200, json={"query_status": "no_results"})
    )
    assert fetcher.fetch(lookup("url", URL)).status == NOT_FOUND
    request = route.calls[0].request
    assert request.headers["Auth-Key"] == KEY
    assert request.content == b"url=http%3A%2F%2F203-0-113-9.example-cdn.com%2Finvoice.zip"
    assert KEY not in str(request.url)


@pytest.mark.parametrize("status", [200, 401])
def test_an_unknown_auth_key_stops_urlhaus_for_the_run(fetcher, respx_mock, status):
    respx_mock.post(f"{API}/host/").mock(
        return_value=httpx.Response(status, json={"query_status": "unknown_auth_key"})
    )
    first = fetcher.fetch(lookup("host", "a.com"))
    assert (first.status, first.error) == (
        FAILED,
        f"the key was refused ({status}; the service said: unknown_auth_key): "
        "check ABUSECH_AUTH_KEY in .env",
    )
    assert fetcher.fetch(lookup("host", "b.com")).status == DEFERRED
    assert fetcher.stats["urlhaus"].api_calls == 1
