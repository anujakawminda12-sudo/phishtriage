"""Week 3, step 11: the RDAP client (domain registration dates).

The answers are made up, in the shapes RFC 9224 (IANA's dns.json) and RFC 9083 (an RDAP
domain object: events, entities with a vCard, status) describe.
"""

from datetime import UTC, datetime

import httpx
import pytest

from phishtriage.enrich.base import Fetcher, ServiceLimits, Unsupported
from phishtriage.enrich.cache import Cache
from phishtriage.enrich.models import DEFERRED, FAILED, FOUND, NOT_FOUND, UNSUPPORTED, Lookup
from phishtriage.enrich.rdap import BOOTSTRAP_URL, RDAP

VERISIGN = "https://rdap.verisign.com/com/v1/"
BOOTSTRAP = {
    "description": "RDAP bootstrap file for Domain Name System registrations",
    "publication": "2026-11-01T00:00:00Z",
    "version": "1.0",
    "services": [
        [["com"], [VERISIGN]],
        [["net"], ["https://rdap.verisign.com/net/v1"]],  # no trailing "/": one is added
        [["ORG", "ngo"], ["http://rdap.example-org.test/", "https://rdap.publicinterest.test/"]],
        [["onlyhttp"], ["http://rdap.onlyhttp.test/"]],  # never used: no HTTPS
        [["ac.example"], ["https://rdap.ac-example.test/"]],  # a two-label entry
        ["broken"],
        "junk",
    ],
}


# A vCard in JSON (jCard, RFC 7095): [name, parameters, type, value] for each property
REGISTRAR_VCARD = [
    "vcard",
    [["version", {}, "text", "4.0"], ["fn", {}, "text", "Example Registrar, Inc."]],
]


def loaded() -> RDAP:
    rdap = RDAP()
    result = rdap.parse(rdap.bootstrap_lookup(), httpx.Response(200, json=BOOTSTRAP))
    assert rdap.load_servers(result)
    return rdap


def domain(query: str) -> Lookup:
    return Lookup("rdap", "domain", query)


def registration(**extra) -> dict:
    body = {
        "objectClassName": "domain",
        "ldhName": "PAYPA1-LOGIN.COM",
        "events": [
            {"eventAction": "registration", "eventDate": "2026-11-15T09:12:00Z"},
            {"eventAction": "expiration", "eventDate": "2027-11-15T09:12:00Z"},
            {"eventAction": "last changed", "eventDate": "2026-11-16T00:00:00Z"},
            {"eventAction": "last update of RDAP database", "eventDate": "2026-11-23T00:00:00Z"},
        ],
        "entities": [
            {
                "objectClassName": "entity",
                "roles": ["registrar"],
                "vcardArray": REGISTRAR_VCARD,
            }
        ],
        "status": ["client transfer prohibited"],
    }
    body.update(extra)
    return body


# --- IANA's list ----------------------------------------------------------------------------


def test_the_bootstrap_list():
    rdap = loaded()
    assert rdap.servers == {
        "com": VERISIGN,
        "net": "https://rdap.verisign.com/net/v1/",
        "org": "https://rdap.publicinterest.test/",  # the HTTPS one, and lower-case
        "ngo": "https://rdap.publicinterest.test/",
        "ac.example": "https://rdap.ac-example.test/",
    }


def test_the_bootstrap_request_and_a_failed_download():
    rdap = RDAP()
    spec = rdap.request(rdap.bootstrap_lookup())
    assert (spec.method, spec.url) == ("GET", BOOTSTRAP_URL)
    failed = rdap.parse(rdap.bootstrap_lookup(), httpx.Response(503))
    assert (failed.status, failed.error) == (FAILED, "IANA answered 503")
    assert rdap.load_servers(failed) is False
    assert rdap.servers is None


def test_an_empty_list_is_not_loaded():
    rdap = RDAP()
    empty = rdap.parse(rdap.bootstrap_lookup(), httpx.Response(200, json={"services": []}))
    assert empty.status == FOUND
    assert rdap.load_servers(empty) is False


@pytest.mark.parametrize(
    ("query", "server"),
    [
        ("paypa1-login.com", VERISIGN),
        ("PAYPA1-LOGIN.COM.", VERISIGN),
        ("uni.ac.example", "https://rdap.ac-example.test/"),  # the longest match wins
        ("mrt.ac.lk", None),
        ("x.onlyhttp", None),
    ],
)
def test_server_for(query, server):
    assert loaded().server_for(query) == server


def test_no_list_no_server():
    assert RDAP().server_for("paypa1-login.com") is None


# --- requests -------------------------------------------------------------------------------


def test_a_domain_request():
    spec = loaded().request(domain("paypa1-login.com"))
    assert (spec.method, spec.url) == ("GET", f"{VERISIGN}domain/paypa1-login.com")
    assert spec.headers == {"Accept": "application/rdap+json, application/json"}


def test_no_server_for_the_tld_is_unsupported():
    with pytest.raises(Unsupported, match=r"no RDAP server for \.lk in IANA's list"):
        loaded().request(domain("sliit.lk"))


def test_requests_that_are_bugs():
    with pytest.raises(ValueError, match="only answers for domains"):
        loaded().request(Lookup("rdap", "ip", "8.8.8.8"))
    with pytest.raises(RuntimeError, match="not loaded"):
        RDAP().request(domain("paypa1-login.com"))


def test_limits():
    rdap = RDAP()
    assert rdap.limits == ServiceLimits(per_minute=30)
    assert rdap.needs_key is False


# --- answers ----------------------------------------------------------------------------------


def parse(status: int, body=None):
    return loaded().parse(domain("paypa1-login.com"), httpx.Response(status, json=body))


def test_a_registered_domain():
    result = parse(200, registration())
    assert result.status == FOUND
    assert result.summary == "registered 2026-11-15, registrar Example Registrar, Inc."
    assert result.data == {
        "created": "2026-11-15",
        "expires": "2027-11-15",
        "last_changed": "2026-11-16",
        "registrar": "Example Registrar, Inc.",
        "status": ["client transfer prohibited"],
    }


def test_a_suspended_domain_keeps_its_status():
    result = parse(200, registration(status=["client hold", "server hold"]))
    assert result.data["status"] == ["client hold", "server hold"]


def test_no_registration_date():
    result = parse(200, {"objectClassName": "domain", "events": [], "entities": "junk"})
    assert result.status == FOUND
    assert result.summary == "no registration date given"
    assert result.data == {}


def test_odd_events_and_entities_are_ignored():
    body = registration(
        events=[
            "junk",
            {"eventAction": "registration", "eventDate": "15/11/2026"},
            {"eventAction": "Registration", "eventDate": "2026-11-14T00:00:00Z"},
        ],
        entities=[
            "junk",
            {"roles": ["registrant"], "vcardArray": ["vcard", [["fn", {}, "text", "A Person"]]]},
            {"roles": ["registrar"], "vcardArray": "junk"},
        ],
        status="active",
    )
    result = parse(200, body)
    assert result.data == {"created": "2026-11-14"}  # no registrant data is ever kept
    assert result.summary == "registered 2026-11-14"


def test_not_registered():
    result = parse(404)
    assert (result.status, result.summary) == (
        NOT_FOUND,
        "not registered (the registry has no record of it)",
    )


def test_a_redirect_or_other_answer_is_failed():
    assert parse(302).error == "RDAP answered 302"
    assert parse(400).status == FAILED


# --- through the Fetcher ------------------------------------------------------------------------


class Clock:
    def __init__(self) -> None:
        self.now = datetime(2026, 11, 23, 9, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now = datetime.fromtimestamp(self.now.timestamp() + seconds, UTC)


@pytest.fixture
def setup(tmp_path):
    clock = Clock()
    rdap = RDAP()
    with Cache(tmp_path / "cache.sqlite3", clock) as cache:
        with Fetcher(
            {"rdap": rdap}, cache, clock=clock, sleep=clock.sleep, jitter=lambda: 0.0
        ) as fetcher:
            yield rdap, fetcher, cache


def test_end_to_end_list_then_domains(setup, respx_mock):
    rdap, fetcher, cache = setup
    iana = respx_mock.get(BOOTSTRAP_URL).mock(return_value=httpx.Response(200, json=BOOTSTRAP))
    registry = respx_mock.get(f"{VERISIGN}domain/paypa1-login.com").mock(
        return_value=httpx.Response(200, json=registration())
    )

    assert rdap.load_servers(fetcher.fetch(rdap.bootstrap_lookup()))
    assert fetcher.fetch(domain("paypa1-login.com")).data["created"] == "2026-11-15"

    lk = fetcher.fetch(domain("sliit.lk"))
    assert (lk.status, lk.error) == (UNSUPPORTED, "no RDAP server for .lk in IANA's list")
    assert cache.get(domain("sliit.lk")) is None  # costs nothing, so not stored

    stats = fetcher.stats["rdap"]
    assert (stats.api_calls, stats.found, stats.unsupported, stats.failed) == (2, 2, 1, 0)
    assert (iana.call_count, registry.call_count) == (1, 1)
    assert registry.calls[0].request.headers["Accept"] == "application/rdap+json, application/json"

    # The list is cached too: a second run loads it without asking IANA
    second = RDAP()
    assert second.load_servers(fetcher.fetch(second.bootstrap_lookup()))
    assert iana.call_count == 1


def test_unsupported_lookups_do_not_use_the_run_limit(tmp_path, respx_mock):
    clock = Clock()
    rdap = loaded()
    respx_mock.get(f"{VERISIGN}domain/paypa1-login.com").mock(
        return_value=httpx.Response(200, json=registration())
    )
    with Cache(tmp_path / "cache.sqlite3", clock) as cache:
        with Fetcher(
            {"rdap": rdap}, cache, max_lookups=1, clock=clock, sleep=clock.sleep
        ) as fetcher:
            for name in ("a.lk", "b.lk", "c.lk"):
                assert fetcher.fetch(domain(name)).status == UNSUPPORTED
            assert fetcher.fetch(domain("paypa1-login.com")).status == FOUND


def test_a_403_from_a_registry_does_not_stop_rdap(setup, respx_mock):
    rdap, fetcher, _ = setup
    rdap.servers = {"com": VERISIGN}
    respx_mock.get(f"{VERISIGN}domain/a.com").mock(return_value=httpx.Response(403))
    respx_mock.get(f"{VERISIGN}domain/b.com").mock(return_value=httpx.Response(404))
    assert fetcher.fetch(domain("a.com")).error == "RDAP answered 403"
    assert fetcher.fetch(domain("b.com")).status == NOT_FOUND  # still asked: no key to refuse


def test_stopping_a_service_from_outside(setup):
    _, fetcher, _ = setup
    fetcher.stop("rdap", "the RDAP server list could not be loaded")
    result = fetcher.fetch(domain("paypa1-login.com"))
    assert (result.status, result.error) == (DEFERRED, "the RDAP server list could not be loaded")
