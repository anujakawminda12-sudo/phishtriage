"""VirusTotal (API v3): what antivirus engines and URL scanners say (week 3, step 9).

Lookups only: nothing is ever uploaded or submitted for scanning, so VirusTotal only
answers about things it already knows.

    file    GET /files/{sha256}            an attachment's hash
    url     GET /urls/{id}                 id = the URL in URL-safe base64, no "=" padding
                                           (VirusTotal normalises the URL itself)
    domain  GET /domains/{host}
    ip      GET /ip_addresses/{ip}

The key goes in the x-apikey header. Answers:

    200  FOUND       engine counts from last_analysis_stats, plus reputation, tags and,
                     for a domain, its WHOIS creation date (a backup domain age for names
                     RDAP cannot answer, such as .lk)
    404  NOT_FOUND   "never seen": VirusTotal does not know it (NotFoundError)
    400  FAILED      e.g. InvalidArgumentError or NotAvailableYet (not cached: asked again)
    401, 403, 429, 5xx are handled by base.py (key refused, quota, retries).

FOUND only means "VirusTotal knows it". "0 of 92 engines flag it" is a FOUND result too.
How much a count matters is week 4's decision (the proposal: 3+ engines for a URL or
domain, 5+ for a file).

Free plan: 500 lookups a day and 4 a minute, and the Public API must not be used in
commercial products or business workflows. PhishTriage is a personal, non-commercial
project, which the free plan allows.
"""

import base64
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote

import httpx

from phishtriage.config import Secret
from phishtriage.enrich.base import RequestSpec, Service, ServiceLimits, json_body
from phishtriage.enrich.models import FAILED, FOUND, NOT_FOUND, Lookup, LookupResult

API = "https://www.virustotal.com/api/v3"
PATHS = {"file": "files", "url": "urls", "domain": "domains", "ip": "ip_addresses"}
VERDICTS = ("malicious", "suspicious", "harmless", "undetected", "timeout")
MAX_TAGS = 10


class VirusTotal(Service):
    name = "virustotal"
    # 20 of the 500 are left unused, for checking something on the API by hand
    limits = ServiceLimits(per_minute=4, per_day=500, reserve=20)
    key_name = "VT_API_KEY"

    def __init__(self, key: Secret[str]) -> None:
        self._key = key

    def request(self, lookup: Lookup) -> RequestSpec:
        path = PATHS[lookup.kind]  # another kind is a bug: base.py turns it into FAILED
        value = url_id(lookup.query) if lookup.kind == "url" else lookup.query
        return RequestSpec(
            "GET",
            f"{API}/{path}/{quote(value, safe=':')}",  # ":" kept for IPv6 addresses
            headers={"x-apikey": self._key.reveal()},
        )

    def parse(self, lookup: Lookup, response: httpx.Response) -> LookupResult:
        if response.status_code == 404:
            return LookupResult(lookup, NOT_FOUND, summary="never seen")
        body = json_body(response)
        if response.status_code != 200:
            code = (body.get("error") or {}).get("code", "an error")
            error = f"VirusTotal said {code} ({response.status_code})"
            return LookupResult(lookup, FAILED, error=error)
        attributes: dict[str, Any] = body["data"]["attributes"]

        stats = attributes.get("last_analysis_stats") or {}
        counts = {verdict: int(stats.get(verdict, 0)) for verdict in VERDICTS}
        data: dict[str, Any] = {
            **counts,
            "engines": sum(counts.values()),
            "reputation": int(attributes.get("reputation", 0)),
        }
        if last := _date(attributes.get("last_analysis_date")):
            data["last_analysis"] = last
        if lookup.kind == "domain" and (created := _date(attributes.get("creation_date"))):
            data["created"] = created
        tags = attributes.get("tags")
        if isinstance(tags, list) and tags:
            data["tags"] = [str(tag) for tag in tags[:MAX_TAGS]]
        return LookupResult(lookup, FOUND, summary=_summary(data), data=data)


def url_id(url: str) -> str:
    """VirusTotal's URL identifier: the URL in URL-safe base64 without "=" padding.

    "http://www.example.com/" -> "aHR0cDovL3d3dy5leGFtcGxlLmNvbS8"
    """
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")


def _summary(data: dict[str, Any]) -> str:
    """One line for the report: facts, no verdict."""
    engines, malicious, suspicious = data["engines"], data["malicious"], data["suspicious"]
    if engines == 0:
        return "known to VirusTotal, not scanned yet"
    if malicious:
        extra = f", {suspicious} suspicious" if suspicious else ""
        return f"{malicious} of {engines} engines: malicious{extra}"
    if suspicious:
        return f"{suspicious} of {engines} engines: suspicious"
    return f"0 of {engines} engines flag it"


def _date(value: object) -> str | None:
    """A UTC timestamp (seconds since 1970) as "YYYY-MM-DD", or None if it is not one."""
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        return None
    return datetime.fromtimestamp(value, UTC).date().isoformat()
