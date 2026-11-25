"""URLhaus (abuse.ch community API v1): known malware-distribution URLs (week 3, step 10).

    url   POST https://urlhaus-api.abuse.ch/v1/url/      form: url=<url>
    host  POST https://urlhaus-api.abuse.ch/v1/host/     form: host=<domain or IP>
    file  POST https://urlhaus-api.abuse.ch/v1/payload/  form: sha256_hash=<sha256>

The free Auth-Key (from auth.abuse.ch) goes in the Auth-Key header. abuse.ch also accepts
it inside the URL, but keys in URLs end up in proxy and browser logs, so the header is used.
Every answer has a query_status:

    "ok"                         FOUND: listed, with status (online/offline), threat, tags
    "no_results"                 NOT_FOUND: "not listed"
    "invalid_url", "invalid_host", "invalid_sha256_hash" ...   FAILED (not cached)
    anything about the auth key  the key was refused: stop URLhaus for this run (KeyRefused)

Know what URLhaus covers: it collects URLs used to spread MALWARE (threat
"malware_download"). A credential-phishing page is usually not in it, so "not in
URLhaus" says little about a fake login page. It matters most for attachments and
download links.

abuse.ch publishes no numeric rate limit (fair use), so we send at most one a second.
The newer abuse.ch API hosted by Spamhaus (Bearer token, GET paths) is a different
product and is not used here.

Field names are read defensively ("firstseen" or "first_seen"), because the official
API page could not be checked automatically when this was written.
"""

from typing import Any

import httpx

from phishtriage.config import Secret
from phishtriage.enrich.base import KeyRefused, RequestSpec, Service, ServiceLimits, json_body
from phishtriage.enrich.models import FAILED, FOUND, NOT_FOUND, Lookup, LookupResult

API = "https://urlhaus-api.abuse.ch/v1"
ENDPOINTS = {"url": ("url", "url"), "host": ("host", "host"), "file": ("payload", "sha256_hash")}
MAX_TAGS = 10


class URLhaus(Service):
    name = "urlhaus"
    limits = ServiceLimits(per_minute=60)  # fair use: no daily quota published
    key_name = "ABUSECH_AUTH_KEY"

    def __init__(self, key: Secret[str]) -> None:
        self._key = key

    def request(self, lookup: Lookup) -> RequestSpec:
        endpoint, field = ENDPOINTS[lookup.kind]  # another kind is a bug: becomes FAILED
        return RequestSpec(
            "POST",
            f"{API}/{endpoint}/",
            headers={"Auth-Key": self._key.reveal()},
            data={field: lookup.query},
        )

    def parse(self, lookup: Lookup, response: httpx.Response) -> LookupResult:
        body = json_body(response)
        status = str(body.get("query_status", ""))
        if "auth" in status:  # "unknown_auth_key", "no_auth_key"...
            raise KeyRefused(status)
        if status == "no_results":
            return LookupResult(lookup, NOT_FOUND, summary="not listed")
        if status != "ok":
            return LookupResult(lookup, FAILED, error=f"URLhaus said {status or 'nothing'}")
        if lookup.kind == "url":
            data = _url_data(body)
        elif lookup.kind == "host":
            data = _host_data(body)
        else:
            data = _payload_data(body)
        return LookupResult(lookup, FOUND, summary=_summary(lookup.kind, data), data=data)


def _url_data(body: dict[str, Any]) -> dict[str, Any]:
    data: dict[str, Any] = {
        "url_status": str(body.get("url_status") or "unknown"),  # online / offline / unknown
        "threat": str(body.get("threat") or "unknown"),
        "tags": _tags(body.get("tags")),
    }
    if added := _date(body.get("date_added") or body.get("first_seen")):
        data["added"] = added
    data.update(_blacklists(body))
    return data


def _host_data(body: dict[str, Any]) -> dict[str, Any]:
    urls = body.get("urls") if isinstance(body.get("urls"), list) else []
    online = sum(1 for url in urls if isinstance(url, dict) and url.get("url_status") == "online")
    data: dict[str, Any] = {"url_count": _int(body.get("url_count"), len(urls)), "online": online}
    if first := _date(body.get("firstseen") or body.get("first_seen")):
        data["first_seen"] = first
    data.update(_blacklists(body))
    return data


def _payload_data(body: dict[str, Any]) -> dict[str, Any]:
    data: dict[str, Any] = {
        "file_type": str(body.get("file_type") or "unknown"),
        "signature": str(body.get("signature") or ""),  # the malware family, if known
        "url_count": _int(body.get("url_count"), 0),
    }
    for field, keys in (
        ("first_seen", ("firstseen", "first_seen")),
        ("last_seen", ("lastseen", "last_seen")),
    ):
        if when := _date(body.get(keys[0]) or body.get(keys[1])):
            data[field] = when
    return data


def _summary(kind: str, data: dict[str, Any]) -> str:
    """One line for the report: facts, no verdict."""
    if kind == "url":
        line = f"listed: {data['threat']} ({data['url_status']})"
        return line + (f", added {data['added']}" if "added" in data else "")
    if kind == "host":
        return f"lists {data['url_count']} malware URLs on this host ({data['online']} online)"
    family = data["signature"] or "family unknown"
    return f"known malware: {family} ({data['file_type']})"


def _blacklists(body: dict[str, Any]) -> dict[str, str]:
    """Other blocklists URLhaus checked, when they list it (e.g. Spamhaus DBL)."""
    lists = body.get("blacklists")
    if not isinstance(lists, dict):
        return {}
    return {
        name: str(value)
        for name, value in lists.items()
        if isinstance(name, str) and value and value != "not listed"
    }


def _tags(value: object) -> list[str]:
    return [str(tag) for tag in value[:MAX_TAGS]] if isinstance(value, list) else []


def _date(value: object) -> str | None:
    """ "2026-11-02 08:15:00 UTC" -> "2026-11-02"; anything else -> None."""
    if isinstance(value, str) and len(value) >= 10 and value[4] == "-" and value[7] == "-":
        return value[:10]
    return None


def _int(value: object, default: int) -> int:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default
