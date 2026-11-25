"""Week 3, step 8: limits, retries, timeouts and errors, with a fake service.

respx answers every request (see test_network_guard.py), and the clock and sleep() are
fake, so a test that "waits a minute" finishes instantly and always gives the same result.
"""

from datetime import UTC, datetime, timedelta
from email.utils import format_datetime

import httpx
import pytest

from phishtriage.config import Secret
from phishtriage.enrich.base import (
    DEFAULT_RETRY_AFTER,
    Fetcher,
    RateLimiter,
    RequestSpec,
    Service,
    ServiceLimits,
    json_body,
)
from phishtriage.enrich.cache import Cache
from phishtriage.enrich.models import DEFERRED, FAILED, FOUND, NOT_FOUND, Lookup, LookupResult

API = "https://api.fake-intel.test/v1"
KEY = "SECRET-KEY-123"


class FakeTime:
    """A clock that only moves when sleep() is called; sleep() returns at once."""

    def __init__(self) -> None:
        self.now = datetime(2026, 11, 22, 12, 0, tzinfo=UTC)
        self.slept: list[float] = []

    def __call__(self) -> datetime:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.slept.append(round(seconds, 3))
        self.now += timedelta(seconds=seconds)


class FakeIntel(Service):
    """A made-up service: GET /v1/<kind>/<value>, key in a header, JSON {"bad": n}."""

    name = "fakeintel"
    limits = ServiceLimits(per_minute=4, per_day=10, reserve=2)
    key_name = "FAKE_KEY"

    def __init__(self, url: str = API) -> None:
        self.key = Secret(KEY)
        self.url = url

    def request(self, lookup: Lookup) -> RequestSpec:
        return RequestSpec(
            "GET",
            f"{self.url}/{lookup.kind}/{lookup.query}",
            headers={"x-apikey": self.key.reveal()},
        )

    def parse(self, lookup: Lookup, response: httpx.Response) -> LookupResult:
        if response.status_code == 404:
            return LookupResult(lookup, NOT_FOUND)
        bad = json_body(response)["bad"]
        return LookupResult(
            lookup, FOUND, summary=f"{bad} engines say malicious", data={"bad": bad}
        )


class OpenIntel(FakeIntel):
    """The same, but needs no key (like RDAP): a 403 is just an answer."""

    name = "openintel"
    needs_key = False


class FormIntel(FakeIntel):
    """POSTs a form, like URLhaus."""

    name = "formintel"

    def request(self, lookup: Lookup) -> RequestSpec:
        return RequestSpec("POST", f"{API}/host/", data={"host": lookup.query})


def look(query: str = "evil-site.com", service: str = "fakeintel") -> Lookup:
    return Lookup(service, "domain", query)


def ok(bad: int = 3) -> httpx.Response:
    return httpx.Response(200, json={"bad": bad})


@pytest.fixture
def clock() -> FakeTime:
    return FakeTime()


@pytest.fixture
def cache(tmp_path, clock):
    with Cache(tmp_path / "cache.sqlite3", clock) as opened:
        yield opened


def make_fetcher(cache, clock, *services: Service, **options) -> Fetcher:
    services = services or (FakeIntel(),)
    return Fetcher(
        {service.name: service for service in services},
        cache,
        clock=clock,
        sleep=clock.sleep,
        jitter=lambda: 0.0,  # no randomness in tests
        **options,
    )


@pytest.fixture
def fetcher(cache, clock):
    with make_fetcher(cache, clock) as opened:
        yield opened


# --- the normal path --------------------------------------------------------------------


def test_found_then_answered_from_the_cache(fetcher, cache, respx_mock):
    route = respx_mock.get(f"{API}/domain/evil-site.com").mock(return_value=ok(3))

    first = fetcher.fetch(look())
    assert first.status == FOUND
    assert first.summary == "3 engines say malicious"
    assert first.data == {"bad": 3}
    assert first.checked_at == "2026-11-22T12:00:00+00:00"
    assert first.from_cache is False

    second = fetcher.fetch(look())
    assert second.from_cache is True
    assert route.call_count == 1  # the second answer cost nothing
    stats = fetcher.stats["fakeintel"]
    assert (stats.found, stats.cache_hits, stats.api_calls) == (1, 1, 1)
    assert cache.calls_within("fakeintel") == 1


def test_not_found_is_an_answer_and_is_cached(fetcher, cache, respx_mock):
    respx_mock.get(f"{API}/domain/evil-site.com").mock(return_value=httpx.Response(404))
    assert fetcher.fetch(look()).status == NOT_FOUND
    assert cache.get(look()).status == NOT_FOUND
    assert fetcher.stats["fakeintel"].not_found == 1


def test_the_key_goes_in_a_header_and_every_request_has_timeouts(fetcher, respx_mock):
    def check(request: httpx.Request) -> httpx.Response:
        assert request.headers["x-apikey"] == KEY
        assert KEY not in str(request.url)
        assert request.headers["user-agent"].startswith("PhishTriage/")
        assert request.extensions["timeout"] == {"connect": 5, "read": 20, "write": 20, "pool": 20}
        return ok()

    respx_mock.get(f"{API}/domain/evil-site.com").mock(side_effect=check)
    assert fetcher.fetch(look()).status == FOUND


# --- retries ------------------------------------------------------------------------------


def test_server_errors_are_retried_with_backoff(fetcher, clock, respx_mock):
    respx_mock.get(f"{API}/domain/evil-site.com").mock(
        side_effect=[httpx.Response(500), httpx.Response(503), ok()]
    )
    assert fetcher.fetch(look()).status == FOUND
    assert clock.slept == [2.0, 4.0]  # 2 s, then 4 s
    stats = fetcher.stats["fakeintel"]
    assert (stats.api_calls, stats.retries) == (3, 2)


def test_it_gives_up_after_three_tries_and_caches_nothing(fetcher, cache, respx_mock):
    respx_mock.get(f"{API}/domain/evil-site.com").mock(return_value=httpx.Response(503))
    result = fetcher.fetch(look())
    assert result.status == FAILED
    assert result.error == "server error 503 after 3 tries"
    assert cache.get(look()) is None  # the next run asks again
    assert fetcher.stats["fakeintel"].failed == 1


@pytest.mark.parametrize(
    ("exception", "error"),
    [
        (httpx.ConnectTimeout, "timed out after 3 tries"),
        (httpx.ReadTimeout, "timed out after 3 tries"),
        (httpx.ConnectError, "connection failed (ConnectError) after 3 tries"),
        (httpx.DecodingError, "request failed (DecodingError) after 3 tries"),
    ],
)
def test_network_problems_become_failed_results(fetcher, respx_mock, exception, error):
    respx_mock.get(f"{API}/domain/evil-site.com").mock(side_effect=exception)
    result = fetcher.fetch(look())
    assert (result.status, result.error) == (FAILED, error)


def test_a_post_form_is_sent_again_unchanged_on_a_retry(cache, clock, respx_mock):
    route = respx_mock.post(f"{API}/host/").mock(side_effect=[httpx.Response(502), ok()])
    with make_fetcher(cache, clock, FormIntel()) as fetcher:
        assert fetcher.fetch(look(service="formintel")).status == FOUND
    bodies = [call.request.content for call in route.calls]
    assert bodies == [b"host=evil-site.com", b"host=evil-site.com"]


# --- 429: too many requests ----------------------------------------------------------------


def test_a_429_with_a_short_wait_is_retried_and_counted(fetcher, clock, respx_mock):
    respx_mock.get(f"{API}/domain/evil-site.com").mock(
        side_effect=[httpx.Response(429, headers={"Retry-After": "5"}), ok()]
    )
    assert fetcher.fetch(look()).status == FOUND
    assert 5.0 in clock.slept
    assert fetcher.stats["fakeintel"].quota_errors == 1  # the gate still counts it


def test_a_429_without_retry_after_waits_a_minute(fetcher, clock, respx_mock):
    respx_mock.get(f"{API}/domain/evil-site.com").mock(side_effect=[httpx.Response(429), ok()])
    assert fetcher.fetch(look()).status == FOUND
    assert DEFAULT_RETRY_AFTER in clock.slept


def test_a_429_with_an_http_date(fetcher, clock, respx_mock):
    when = format_datetime(clock.now + timedelta(seconds=30), usegmt=True)
    respx_mock.get(f"{API}/domain/evil-site.com").mock(
        side_effect=[httpx.Response(429, headers={"Retry-After": when}), ok()]
    )
    assert fetcher.fetch(look()).status == FOUND
    assert 30.0 in clock.slept


def test_a_429_with_a_retry_after_that_cannot_be_read_waits_a_minute(fetcher, clock, respx_mock):
    respx_mock.get(f"{API}/domain/evil-site.com").mock(
        side_effect=[httpx.Response(429, headers={"Retry-After": "soon"}), ok()]
    )
    assert fetcher.fetch(look()).status == FOUND
    assert DEFAULT_RETRY_AFTER in clock.slept


def test_a_429_with_a_long_wait_stops_the_service_for_this_run(fetcher, respx_mock):
    respx_mock.get(f"{API}/domain/evil-site.com").mock(
        return_value=httpx.Response(429, headers={"Retry-After": "3600"})
    )
    other = respx_mock.get(f"{API}/domain/other-site.com").mock(return_value=ok())

    first = fetcher.fetch(look())
    assert (first.status, first.error) == (FAILED, "the service said the quota is used up (429)")
    second = fetcher.fetch(look("other-site.com"))
    assert second.status == DEFERRED  # not asked at all
    assert second.error == "the service said the quota is used up (429)"
    assert other.call_count == 0


def test_a_429_on_every_try_stops_the_service(fetcher, respx_mock):
    respx_mock.get(f"{API}/domain/evil-site.com").mock(
        return_value=httpx.Response(429, headers={"Retry-After": "1"})
    )
    assert fetcher.fetch(look()).status == FAILED
    assert fetcher.stats["fakeintel"].quota_errors == 3
    assert "fakeintel" in fetcher.stopped


# --- a refused key, and other answers ---------------------------------------------------------


@pytest.mark.parametrize(
    ("response", "said"),
    [
        (httpx.Response(403, json={"query_status": "unknown_auth_key"}), "unknown_auth_key"),
        (httpx.Response(403, json={"message": "Forbidden"}), "Forbidden"),
        (
            httpx.Response(
                401, json={"errors": [{"detail": "Authentication failed.", "status": 401}]}
            ),
            "Authentication failed.",
        ),
        (
            httpx.Response(
                401, json={"error": {"code": "WrongCredentialsError", "message": "bad"}}
            ),
            "WrongCredentialsError: bad",
        ),
        (
            httpx.Response(403, text="<html><body>Access denied | Cloudflare</body></html>"),
            "an HTML page, not the API (a firewall or proxy may have blocked it)",
        ),
        (
            httpx.Response(403, text="Error 1020", headers={"content-type": "text/html"}),
            "an HTML page, not the API (a firewall or proxy may have blocked it)",
        ),
        (httpx.Response(403, text="plain words"), "plain words"),
        (httpx.Response(403, json=["not", "an", "object"]), "a JSON answer without a message"),
        (httpx.Response(403, json={"message": "evil\x1b[2J\nline"}), "evil\\x1b[2J line"),
    ],
)
def test_a_refusal_keeps_what_the_service_said(fetcher, respx_mock, response, said):
    """Week 3 gate: URLhaus answered 403, and the bare status could not say why."""
    respx_mock.get(f"{API}/domain/evil-site.com").mock(return_value=response)
    result = fetcher.fetch(look())
    status = response.status_code
    assert result.error == f"the key was refused ({status}; the service said: {said}): " + (
        "check FAKE_KEY in .env"
    )


def test_a_refusal_that_repeats_the_key_does_not_leak_it(fetcher, respx_mock):
    respx_mock.get(f"{API}/domain/evil-site.com").mock(
        return_value=httpx.Response(403, json={"message": f"key {KEY} is not valid"})
    )
    result = fetcher.fetch(look())
    assert KEY not in result.error
    assert "key ******** is not valid" in result.error
    assert KEY not in str(fetcher.stopped)


def test_a_long_refusal_is_cut(fetcher, respx_mock):
    respx_mock.get(f"{API}/domain/evil-site.com").mock(
        return_value=httpx.Response(403, json={"message": "x" * 500})
    )
    said = fetcher.fetch(look()).error.split("the service said: ")[1].split("): check")[0]
    assert len(said) == 120
    assert said.endswith("…")


@pytest.mark.parametrize("status", [401, 403])
def test_a_refused_key_stops_the_service(fetcher, respx_mock, status):
    respx_mock.get(f"{API}/domain/evil-site.com").mock(return_value=httpx.Response(status))
    other = respx_mock.get(f"{API}/domain/other-site.com").mock(return_value=ok())
    result = fetcher.fetch(look())
    assert result.error == f"the key was refused ({status}): check FAKE_KEY in .env"
    assert fetcher.fetch(look("other-site.com")).status == DEFERRED
    assert other.call_count == 0


def test_a_403_from_a_service_without_a_key_is_just_one_failed_answer(cache, clock, respx_mock):
    respx_mock.get(f"{API}/domain/evil-site.com").mock(return_value=httpx.Response(403))
    with make_fetcher(cache, clock, OpenIntel()) as fetcher:
        result = fetcher.fetch(look(service="openintel"))
        assert result.status == FAILED
        assert result.error.startswith("unexpected answer (403")
        assert fetcher.stopped == {}


@pytest.mark.parametrize(
    ("response", "error"),
    [
        (
            httpx.Response(200, text="<html>not json</html>"),
            "unexpected answer (200, JSONDecodeError)",
        ),
        (httpx.Response(200, json=[1, 2]), "unexpected answer (200, ValueError)"),
        (httpx.Response(200, json={"other": 1}), "unexpected answer (200, KeyError)"),
    ],
)
def test_an_unexpected_answer_is_a_failed_result_not_a_crash(fetcher, respx_mock, response, error):
    respx_mock.get(f"{API}/domain/evil-site.com").mock(return_value=response)
    result = fetcher.fetch(look())
    assert (result.status, result.error) == (FAILED, error)


def test_a_redirect_is_never_followed(fetcher, respx_mock):
    respx_mock.get(f"{API}/domain/evil-site.com").mock(
        return_value=httpx.Response(302, headers={"Location": "https://evil-site.com/"})
    )
    evil = respx_mock.get("https://evil-site.com/").mock(return_value=ok())
    assert fetcher.fetch(look()).status == FAILED
    assert evil.call_count == 0


# --- limits ----------------------------------------------------------------------------------


def test_the_per_minute_limit_waits_before_the_fifth_request(fetcher, clock, respx_mock):
    respx_mock.get(url__startswith=f"{API}/domain/").mock(return_value=ok())
    for n in range(5):
        fetcher.fetch(look(f"site-{n}.com"))
    assert clock.slept == [61.0]  # 4 a minute: wait until the first is 60 s old, +1 s
    assert fetcher.stats["fakeintel"].waited == 61.0


def test_the_limit_remembers_requests_from_a_run_that_just_ended(cache, clock, respx_mock):
    respx_mock.get(url__startswith=f"{API}/domain/").mock(return_value=ok())
    for _ in range(4):
        cache.record_call("fakeintel")  # an earlier run's 4 requests
    clock.sleep(30)
    with make_fetcher(cache, clock) as fetcher:
        fetcher.fetch(look())
    assert clock.slept == [30.0, 31.0]  # (the test's own 30 s), then 31 s more


def test_the_daily_quota_stops_before_asking(fetcher, cache, respx_mock):
    route = respx_mock.get(f"{API}/domain/evil-site.com").mock(return_value=ok())
    for _ in range(8):  # 10 a day, 2 kept in reserve
        cache.record_call("fakeintel")
    result = fetcher.fetch(look())
    assert result.status == DEFERRED
    assert result.error == (
        "daily quota: 8 of 10 calls used in the last 24 hours (2 kept for checks by hand)"
    )
    assert route.call_count == 0
    assert fetcher.stats["fakeintel"].deferred == 1


def test_max_lookups_limits_new_lookups_but_not_cache_hits(cache, clock, respx_mock):
    respx_mock.get(url__startswith=f"{API}/domain/").mock(return_value=ok())
    with make_fetcher(cache, clock, max_lookups=2) as fetcher:
        assert fetcher.fetch(look("a.com")).status == FOUND
        assert fetcher.fetch(look("a.com")).from_cache is True  # free: not counted
        assert fetcher.fetch(look("b.com")).status == FOUND
        third = fetcher.fetch(look("c.com"))
    assert third.status == DEFERRED
    assert third.error == "this run's limit of 2 lookups (--max-lookups)"


def test_limits_without_numbers():
    assert ServiceLimits().daily_budget is None
    limiter = RateLimiter(None, [], FakeTime(), FakeTime().sleep)
    assert limiter.wait() == 0.0


# --- never visit, never crash, never show the key --------------------------------------


def test_only_https_is_sent(cache, clock, respx_mock):
    with make_fetcher(cache, clock, FakeIntel(url="http://api.fake-intel.test/v1")) as fetcher:
        result = fetcher.fetch(look())
    assert result.error == "refused: only HTTPS requests are sent"


@pytest.mark.parametrize(
    "lookup",
    [
        Lookup("fakeintel", "domain", "evil-site.com"),
        Lookup("fakeintel", "url", "https://Evil-Site.com/login"),
    ],
)
def test_a_request_to_the_ioc_itself_is_refused(cache, clock, respx_mock, lookup):
    class Buggy(FakeIntel):
        def request(self, lookup: Lookup) -> RequestSpec:
            return RequestSpec("GET", "https://evil-site.com/")  # a bug: visits the IOC

    with make_fetcher(cache, clock, Buggy()) as fetcher:
        result = fetcher.fetch(lookup)
    assert result.error == "refused: the request would go to the IOC itself"


def test_a_broken_service_is_a_failed_result(cache, clock):
    class Broken(FakeIntel):
        def request(self, lookup: Lookup) -> RequestSpec:
            raise KeyError("oops")

    with make_fetcher(cache, clock, Broken()) as fetcher:
        result = fetcher.fetch(look())
    assert (result.status, result.error) == (FAILED, "no request built (KeyError)")


def test_a_lookup_for_an_unknown_service(fetcher):
    result = fetcher.fetch(Lookup("nosuchservice", "domain", "evil-site.com"))
    assert (result.status, result.error) == (FAILED, "no client for nosuchservice")


def test_the_key_never_appears_in_any_result_or_request_description(fetcher, respx_mock):
    answers = {
        "a.com": httpx.Response(500),
        "b.com": httpx.Response(200, text="not json"),
        "c.com": httpx.Response(401),
        "d.com": httpx.Response(404),
    }
    for query, response in answers.items():
        respx_mock.get(f"{API}/domain/{query}").mock(return_value=response)
    results = [fetcher.fetch(look(query)) for query in answers]
    for result in results:
        assert KEY not in repr(result)
    assert KEY not in repr(FakeIntel().request(look()))  # headers are hidden from repr()
