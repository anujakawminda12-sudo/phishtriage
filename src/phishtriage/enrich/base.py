"""Sending lookups safely: rate limits, retries, timeouts, errors (week 3, step 8).

Each service (steps 9-11) only has to do two things:

    request(lookup)          -> RequestSpec   describe the HTTP request (no sending)
    parse(lookup, response)  -> LookupResult  turn the service's answer into a result

Everything else is written once, here, in Fetcher.fetch():

    1. the cache                answered from it if possible: no request at all
    2. limits                   stop at this run's --max-lookups, or the daily quota
                                (counted in the cache's 24-hour call log)
    3. a safety check           HTTPS only, and never a request to the IOC itself
    4. the per-minute limit     wait, if needed, before every request (retries too)
    5. send, with timeouts      every request is built by the client, so none can
                                miss the timeouts
    6. handle the answer        5xx / timeout / connection error: retry with backoff
                                429: wait (Retry-After) and retry, then stop the service
                                401 / 403: the key was refused: stop the service
                                anything else: the service's parse() (which can also
                                say the key was refused: KeyRefused)
    7. store and count          the cache keeps FOUND and NOT_FOUND; stats count it all

Java comparison: the Template Method pattern. Fetcher.fetch() is the fixed algorithm, and
each Service fills in the two steps that differ (an abstract class with two abstract
methods).

Rules: a failure is a result (FAILED or DEFERRED), never an exception; error messages
are built from status codes and exception class names only, so a key can never end up
in one; redirects are never followed.
"""

import random
import time
from abc import ABC, abstractmethod
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from email.utils import parsedate_to_datetime
from types import TracebackType
from typing import Any
from urllib.parse import urlsplit

import httpx

from phishtriage import __version__
from phishtriage.display import visible
from phishtriage.enrich.cache import Cache, Clock, utc_now
from phishtriage.enrich.models import (
    DEFERRED,
    FAILED,
    FOUND,
    NOT_FOUND,
    UNSUPPORTED,
    Lookup,
    LookupResult,
)

MAX_ATTEMPTS = 3  # one try and two retries
BACKOFF_SECONDS = 2.0  # waits 2 s, then 4 s (plus up to 1 s of random jitter)
DEFAULT_RETRY_AFTER = 60.0  # a 429 without a Retry-After header: wait a minute
MAX_RETRY_AFTER = 120.0  # asked to wait longer than this: the quota is gone for today
MINUTE = timedelta(minutes=1)
SAFETY_MARGIN = 1.0  # seconds added to every rate-limit wait (clocks differ slightly)
TIMEOUT = httpx.Timeout(20.0, connect=5.0)  # seconds
USER_AGENT = f"PhishTriage/{__version__} (threat-intel lookups, hashes and IOCs only)"


@dataclass(frozen=True)
class ServiceLimits:
    """A service's free-plan limits.

    per_minute: requests in any 60 seconds (for services with no published limit, a
                polite pace chosen by us)
    per_day:    requests in any 24 hours, or None if there is no daily limit
    reserve:    requests a day deliberately left unused, so you can still check
                something by hand with the same key
    """

    per_minute: int | None = None
    per_day: int | None = None
    reserve: int = 0

    @property
    def daily_budget(self) -> int | None:
        return None if self.per_day is None else self.per_day - self.reserve


@dataclass(frozen=True)
class RequestSpec:
    """What a service wants sent. Fetcher turns it into a real request.

    headers usually hold the API key, so they are left out of repr(): printing a
    RequestSpec, or an error message that includes one, cannot show the key.
    """

    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict, repr=False)
    params: dict[str, str] | None = None
    data: dict[str, str] | None = None  # form fields (URLhaus uses POST forms)


class Unsupported(Exception):
    """Raised by a service's request() when it has nothing to ask for this value (RDAP has
    no server for .lk, step 11). Nothing is sent, the run's limits are not used, and the
    result is UNSUPPORTED, which is not a failure and is not cached (it costs nothing)."""


class KeyRefused(Exception):
    """Raised by a service's parse() when its answer says the key is wrong although the
    HTTP status is not 401/403 (URLhaus can answer 200 "unknown_auth_key", step 10).
    Fetcher stops the service, exactly as for a 401."""


class Service(ABC):
    """One threat-intel service. Steps 9-11 write one subclass per service.

    name:      "virustotal", "abuseipdb", "urlhaus" or "rdap"
    limits:    its free-plan limits
    needs_key: True if a 401/403 answer means the key was refused
    key_name:  the .env variable to check when the key is refused
    """

    name: str = ""
    limits: ServiceLimits = ServiceLimits()
    needs_key: bool = True
    key_name: str = ""

    @abstractmethod
    def request(self, lookup: Lookup) -> RequestSpec:
        """Describe the request for one lookup. Must not send anything."""

    @abstractmethod
    def parse(self, lookup: Lookup, response: httpx.Response) -> LookupResult:
        """Turn the service's answer (any status except 429, 5xx, and 401/403 for a
        service with a key) into a LookupResult. May raise: that becomes FAILED."""


@dataclass
class ServiceStats:
    """What happened to one service's lookups in this run (shown in the report)."""

    cache_hits: int = 0
    api_calls: int = 0  # requests sent, retries included
    found: int = 0
    not_found: int = 0
    failed: int = 0
    deferred: int = 0
    unsupported: int = 0  # nothing to ask (e.g. no RDAP server for the TLD); nothing sent
    quota_errors: int = 0  # 429 answers. The Week 3 gate needs this to stay 0.
    retries: int = 0
    waited: float = 0.0  # seconds spent waiting for the per-minute limit

    def count(self, result: LookupResult) -> None:
        if result.from_cache:
            self.cache_hits += 1
        elif result.status == FOUND:
            self.found += 1
        elif result.status == NOT_FOUND:
            self.not_found += 1
        elif result.status == FAILED:
            self.failed += 1
        elif result.status == DEFERRED:
            self.deferred += 1
        elif result.status == UNSUPPORTED:
            self.unsupported += 1


class RateLimiter:
    """At most `per_minute` requests in any 60 seconds, for one service.

    A sliding-window log: the times of the requests sent in the last minute. Before a
    request, if the log is full, wait until its oldest entry is a minute old. It starts
    from the cache's call log, so a run started straight after another one still knows
    about the other run's requests.
    """

    def __init__(
        self,
        per_minute: int | None,
        recent: list[datetime],
        clock: Clock,
        sleep: Callable[[float], None],
    ) -> None:
        self.per_minute = per_minute
        self.times: deque[datetime] = deque(recent)  # Java: ArrayDeque
        self.clock = clock
        self.sleep = sleep

    def wait(self) -> float:
        """Wait if needed, then return how many seconds were waited."""
        if self.per_minute is None:
            return 0.0
        self._forget_old()
        if len(self.times) < self.per_minute:
            return 0.0
        delay = (self.times[0] + MINUTE - self.clock()).total_seconds() + SAFETY_MARGIN
        delay = max(delay, 0.0)
        self.sleep(delay)
        self._forget_old()
        return delay

    def record(self) -> None:
        self.times.append(self.clock())

    def _forget_old(self) -> None:
        cutoff = self.clock() - MINUTE
        while self.times and self.times[0] <= cutoff:
            self.times.popleft()


class Fetcher:
    """Looks up one value at a time, following every rule in the module docstring.

    clock, sleep and jitter are injected, so tests run instantly and give the same
    answer every time (Java: passing a Clock and a Random into the constructor).
    """

    def __init__(
        self,
        services: dict[str, Service],
        cache: Cache,
        *,
        max_lookups: int | None = None,
        client: httpx.Client | None = None,
        clock: Clock = utc_now,
        sleep: Callable[[float], None] = time.sleep,
        jitter: Callable[[], float] = random.random,
    ) -> None:
        self.services = services
        self.cache = cache
        self.max_lookups = max_lookups
        self.client = client or httpx.Client(
            timeout=TIMEOUT,
            follow_redirects=False,  # a redirect could lead anywhere: never followed
            headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
        )
        self.clock = clock
        self.sleep = sleep
        self.jitter = jitter
        self.stats = {name: ServiceStats() for name in services}
        self.stopped: dict[str, str] = {}  # service -> why it was stopped in this run
        self._sent: dict[str, int] = dict.fromkeys(services, 0)  # lookups sent, this run
        self._limiters: dict[str, RateLimiter] = {}

    # --- the algorithm --------------------------------------------------------------

    def fetch(self, lookup: Lookup, *, counted: bool = True) -> LookupResult:
        """The answer for one lookup. Never raises: a problem becomes FAILED or DEFERRED.

        counted=False (week 4) is for a request the service needs before it can answer,
        such as IANA's list of RDAP servers: it is not one of the planned lookups, so it
        stays out of "From cache", "Found" and the other answer columns. A request that
        is really sent still counts in "API calls" and in the daily log.
        """
        service = self.services.get(lookup.service)
        if service is None:
            return LookupResult(lookup, FAILED, error=f"no client for {lookup.service}")
        result = self._fetch(service, lookup)
        if counted:
            self.stats[service.name].count(result)
        if not result.from_cache:
            self.cache.put(result)  # FOUND and NOT_FOUND only; the cache ignores the rest
        return result

    def _fetch(self, service: Service, lookup: Lookup) -> LookupResult:
        if (cached := self.cache.get(lookup)) is not None:
            return cached
        if (why := self._why_not_now(service)) is not None:
            return LookupResult(lookup, DEFERRED, error=why)

        try:
            spec = service.request(lookup)
            request = self.client.build_request(
                spec.method, spec.url, headers=spec.headers, params=spec.params, data=spec.data
            )
        except Unsupported as exc:  # nothing to ask: no request, no limit used
            return LookupResult(lookup, UNSUPPORTED, error=str(exc))
        except Exception as exc:  # a bug, or a value httpx will not accept: not a crash
            return LookupResult(lookup, FAILED, error=f"no request built ({type(exc).__name__})")
        if (unsafe := _unsafe(request, lookup)) is not None:
            return LookupResult(lookup, FAILED, error=unsafe)
        self._sent[service.name] += 1
        return self._send(service, lookup, request)

    def _why_not_now(self, service: Service) -> str | None:
        """Why this service must not be asked now, or None if it may."""
        name = service.name
        if name in self.stopped:
            return self.stopped[name]
        if self.max_lookups is not None and self._sent[name] >= self.max_lookups:
            return f"this run's limit of {self.max_lookups} lookups (--max-lookups)"
        budget = service.limits.daily_budget
        if budget is not None:
            used = self.cache.calls_within(name)
            if used >= budget:
                self.stopped[name] = (
                    f"daily quota: {used} of {service.limits.per_day} calls used in the "
                    f"last 24 hours ({service.limits.reserve} kept for checks by hand)"
                )
                return self.stopped[name]
        return None

    def _send(self, service: Service, lookup: Lookup, request: httpx.Request) -> LookupResult:
        stats = self.stats[service.name]
        error = ""
        for attempt in range(1, MAX_ATTEMPTS + 1):
            if attempt > 1:
                stats.retries += 1
            stats.waited += self._limiter(service).wait()
            self.cache.record_call(service.name)  # counted whether or not it succeeds
            self._limiter(service).record()
            stats.api_calls += 1
            try:
                response = self.client.send(request)
            except httpx.TimeoutException:
                error = "timed out"
            except httpx.TransportError as exc:
                error = f"connection failed ({type(exc).__name__})"
            except httpx.HTTPError as exc:  # anything else httpx raises, e.g. a bad body
                error = f"request failed ({type(exc).__name__})"
            else:
                status = response.status_code
                if status == 429:
                    stats.quota_errors += 1
                    wait = _retry_after(response, self.clock())
                    if wait > MAX_RETRY_AFTER or attempt == MAX_ATTEMPTS:
                        self.stopped[service.name] = "the service said the quota is used up (429)"
                        return LookupResult(lookup, FAILED, error=self.stopped[service.name])
                    self.sleep(wait)
                    continue
                if status >= 500:
                    error = f"server error {status}"
                elif status in (401, 403) and service.needs_key:
                    return self._key_refused(service, lookup, status, _reply(response, request))
                else:
                    return self._parse(service, lookup, response)
            if attempt < MAX_ATTEMPTS:
                self.sleep(BACKOFF_SECONDS * 2 ** (attempt - 1) + self.jitter())
        return LookupResult(lookup, FAILED, error=f"{error} after {MAX_ATTEMPTS} tries")

    def _parse(self, service: Service, lookup: Lookup, response: httpx.Response) -> LookupResult:
        try:
            result = service.parse(lookup, response)
        except KeyRefused as exc:  # e.g. URLhaus: 200 with query_status "unknown_auth_key"
            return self._key_refused(service, lookup, response.status_code, _clean(str(exc)))
        except Exception as exc:  # an answer we did not expect: recorded, never a crash
            return LookupResult(
                lookup,
                FAILED,
                error=f"unexpected answer ({response.status_code}, {type(exc).__name__})",
            )
        return replace(result, checked_at=self.clock().isoformat(timespec="seconds"))

    def stop(self, service: str, reason: str) -> None:
        """Stop a service for the rest of this run: its later lookups become DEFERRED.

        Used from outside, e.g. when RDAP's list of servers cannot be loaded (step 12).
        """
        self.stopped[service] = reason

    def _key_refused(
        self, service: Service, lookup: Lookup, status: int, reply: str = ""
    ) -> LookupResult:
        """Stop the service for this run: every later lookup would be refused too.

        Week 3 gate: the service's own words are kept (`reply`). A bare "403" could mean a
        wrong key, an account that is not set up yet, or a firewall page, and only the reply
        tells them apart.
        """
        said = f"; the service said: {reply}" if reply else ""
        self.stopped[service.name] = (
            f"the key was refused ({status}{said}): check {service.key_name} in .env"
        )
        return LookupResult(lookup, FAILED, error=self.stopped[service.name])

    def _limiter(self, service: Service) -> RateLimiter:
        if service.name not in self._limiters:
            recent = self.cache.call_times(service.name, MINUTE)
            self._limiters[service.name] = RateLimiter(
                service.limits.per_minute, recent, self.clock, self.sleep
            )
        return self._limiters[service.name]

    # --- closing ----------------------------------------------------------------------------

    def close(self) -> None:
        self.client.close()

    def __enter__(self) -> "Fetcher":
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()


def _retry_after(response: httpx.Response, now: datetime) -> float:
    """Seconds to wait, from a Retry-After header: "30" or an HTTP date."""
    value = response.headers.get("Retry-After", "").strip()
    if not value:
        return DEFAULT_RETRY_AFTER
    if value.isdigit():
        return float(value)
    try:
        return max((parsedate_to_datetime(value) - now).total_seconds(), 0.0)
    except (TypeError, ValueError):
        return DEFAULT_RETRY_AFTER


def _unsafe(request: httpx.Request, lookup: Lookup) -> str | None:
    """Why a request must not be sent, or None. The last guard for "never visit".

    Only HTTPS is used, so nothing (the key included) crosses the network unencrypted.
    A request whose host is the IOC itself would mean visiting the attacker: refused,
    whatever bug produced it. (Looking up the API's own host, e.g. www.virustotal.com,
    is refused too; that costs nothing.)
    """
    if request.url.scheme != "https":
        return "refused: only HTTPS requests are sent"
    target = urlsplit(lookup.query).hostname if lookup.kind == "url" else lookup.query
    if target and request.url.host == target.lower():
        return "refused: the request would go to the IOC itself"
    return None


REPLY_MAX_CHARS = 120
REPLY_FIELDS = ("query_status", "message", "detail", "error", "errors")


def _reply(response: httpx.Response, request: httpx.Request) -> str:
    """A short, safe description of a refusal: what the service said, never the key.

    JSON: its message field (APIs differ: query_status, message, error, errors[0].detail).
    An HTML page is not the API answering, so that is said instead of quoting it.
    """
    try:
        body: Any = response.json()
    except ValueError:
        text = response.text.strip()
        if text.startswith("<") or "html" in response.headers.get("content-type", ""):
            return "an HTML page, not the API (a firewall or proxy may have blocked it)"
        reply = text
    else:
        reply = _message(body)
    for value in request.headers.values():  # a service that echoes the key must not leak it
        if len(value) >= 8:
            reply = reply.replace(value, "********")
    return _clean(reply)


def _message(body: Any) -> str:
    if isinstance(body, dict):
        for field in REPLY_FIELDS:
            value = body.get(field)
            if isinstance(value, list) and value:
                value = value[0]
            if isinstance(value, dict):  # VirusTotal: {"code": ..., "message": ...}
                parts = [value.get("code"), value.get("message") or value.get("detail")]
                value = ": ".join(str(part) for part in parts if part)
            if value:
                return str(value)
    return "a JSON answer without a message"


def _clean(text: str) -> str:
    """One short line of outside text: control characters written out, then cut."""
    text = visible(" ".join(text.split()))
    return text if len(text) <= REPLY_MAX_CHARS else text[: REPLY_MAX_CHARS - 1] + "…"


def json_body(response: httpx.Response) -> dict[str, Any]:
    """The answer as a JSON object (a dict). Raises ValueError if it is anything else."""
    body = response.json()
    if not isinstance(body, dict):
        raise ValueError("the answer is not a JSON object")
    return body
