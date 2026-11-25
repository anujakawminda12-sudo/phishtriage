"""The two types every enrichment module shares: a question and its answer (week 3).

Lookup was written in step 6 (plan.py) and moved here in step 7, so the plan, the cache
and the service clients can all use it without importing each other.
"""

from dataclasses import dataclass, field
from typing import Any

# What a lookup's answer says
FOUND = "found"  # the service knows this value (that alone does NOT mean malicious)
NOT_FOUND = "not_found"  # the service has never seen it
FAILED = "failed"  # no answer: timeout, bad key, quota... (never cached)
DEFERRED = "deferred"  # not asked: this run's limit or the daily quota was reached
UNSUPPORTED = "unsupported"  # nothing to ask, nothing sent: e.g. no RDAP server for .lk


@dataclass(frozen=True)
class Lookup:
    """One question to one service.

    frozen=True makes it immutable and hashable (Java: a record, which gets equals() and
    hashCode() for free), so it can be a dict key. That is how the same domain in 30
    emails becomes one lookup.

    service: "virustotal", "abuseipdb", "urlhaus" or "rdap"
    kind:    "file" (a SHA-256), "url", "domain", "host" (URLhaus: a domain or an IP), "ip"
    query:   exactly what is sent: refanged, without #fragment, never your address
    """

    service: str
    kind: str
    query: str


@dataclass(frozen=True)
class LookupResult:
    """What one service said about one value.

    status:     FOUND, NOT_FOUND, FAILED, DEFERRED or UNSUPPORTED (week 3, step 11)
    summary:    one short line for the report, e.g. "6 of 94 engines say malicious"
    data:       the numbers behind it, for week 4's scoring, e.g. {"malicious": 6}
                (facts only: no points, no verdict)
    error:      why it FAILED, was DEFERRED or is UNSUPPORTED, e.g. "timed out"
    checked_at: when the service answered (UTC, ISO 8601)
    from_cache: True when this came from the cache, not a new API call
    """

    lookup: Lookup
    status: str
    summary: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    error: str = ""
    checked_at: str = ""
    from_cache: bool = False
