"""AbuseIPDB (API v2): how often an IP address has been reported for abuse (week 3, step 10).

    GET https://api.abuseipdb.com/api/v2/check?ipAddress=<ip>&maxAgeInDays=90
    headers: Key: <key>, Accept: application/json (without Accept the API answers with HTML)

The answer's "data" object gives abuseConfidenceScore (0-100), totalReports,
numDistinctUsers and lastReportedAt for the last 90 days, plus what the address is:
country, ISP, usageType ("Data Center/Web Hosting/Transit"...), and whether it is a Tor
exit node.

AbuseIPDB always has an answer for a public IP, so every 200 is FOUND, even with no
reports ("confidence 0%, no reports in 90 days"): like VirusTotal's "0 of 90 engines
flag it". The proposal's week 4 rule uses the score (50 or more).

Free plan: 1,000 checks a day (50 are left unused, for checks by hand). No per-minute
limit is published, so we send at most one a second. A 429 carries Retry-After until the
daily reset, which base.py treats as "quota used up: stop for this run".
"""

from typing import Any

import httpx

from phishtriage.config import Secret
from phishtriage.enrich.base import RequestSpec, Service, ServiceLimits, json_body
from phishtriage.enrich.models import FAILED, FOUND, Lookup, LookupResult

API = "https://api.abuseipdb.com/api/v2/check"
MAX_AGE_DAYS = 90  # the API allows 1-365; the default is only 30


class AbuseIPDB(Service):
    name = "abuseipdb"
    limits = ServiceLimits(per_minute=60, per_day=1000, reserve=50)
    key_name = "ABUSEIPDB_API_KEY"

    def __init__(self, key: Secret[str]) -> None:
        self._key = key

    def request(self, lookup: Lookup) -> RequestSpec:
        if lookup.kind != "ip":
            raise ValueError(f"AbuseIPDB only checks IP addresses, not {lookup.kind}")
        return RequestSpec(
            "GET",
            API,
            headers={"Key": self._key.reveal(), "Accept": "application/json"},
            params={"ipAddress": lookup.query, "maxAgeInDays": str(MAX_AGE_DAYS)},
        )

    def parse(self, lookup: Lookup, response: httpx.Response) -> LookupResult:
        body = json_body(response)
        if response.status_code != 200:
            errors = body.get("errors") or [{}]
            detail = str(errors[0].get("detail", "an error"))[:80]
            return LookupResult(
                lookup, FAILED, error=f"AbuseIPDB said: {detail} ({response.status_code})"
            )
        info: dict[str, Any] = body["data"]
        data: dict[str, Any] = {
            "score": int(info.get("abuseConfidenceScore") or 0),
            "reports": int(info.get("totalReports") or 0),
            "distinct_users": int(info.get("numDistinctUsers") or 0),
            "is_tor": bool(info.get("isTor")),
            "is_whitelisted": bool(info.get("isWhitelisted")),  # AbuseIPDB's own list
        }
        for field, key in (
            ("country", "countryCode"),
            ("usage_type", "usageType"),
            ("isp", "isp"),
        ):
            if isinstance(value := info.get(key), str) and value:
                data[field] = value
        last = info.get("lastReportedAt")
        if isinstance(last, str) and len(last) >= 10:
            data["last_reported"] = last[:10]  # "2026-11-20T08:15:00+00:00" -> the date
        return LookupResult(lookup, FOUND, summary=_summary(data), data=data)


def _summary(data: dict[str, Any]) -> str:
    """One line for the report: facts, no verdict."""
    if data["reports"]:
        line = (
            f"confidence {data['score']}%, {data['reports']} reports from "
            f"{data['distinct_users']} users in {MAX_AGE_DAYS} days"
        )
        if "last_reported" in data:
            line += f" (last {data['last_reported']})"
    else:
        line = f"confidence {data['score']}%, no reports in {MAX_AGE_DAYS} days"
    if data["is_tor"]:
        line += ", Tor exit node"
    return line
