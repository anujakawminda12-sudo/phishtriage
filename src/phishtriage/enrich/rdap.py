"""RDAP: when a domain was registered, from the registry that sold it (week 3, step 11).

RDAP (RFC 9083) is WHOIS's replacement: the same registration data, as JSON over HTTPS,
with no account and no key. ICANN stopped requiring WHOIS for most generic TLDs in
January 2025, so RDAP is the supported way to ask. Port-43 WHOIS (plain text, a
different format per registry, hard to test) is not used.

Two kinds of lookup:

    bootstrap  GET https://data.iana.org/rdap/dns.json
               IANA's list of which RDAP server answers for which TLD (RFC 9224).
               Loaded once and cached for 30 days, like any other answer.
    domain     GET {that TLD's server}domain/{domain}
               "events" holds the registration date (eventAction "registration").

Answers for a domain:

    200  FOUND        the registration date, plus expiry, last change, registrar name
                      and status codes ("client hold" can mean the registrar suspended it)
    404  NOT_FOUND    the registry has no record: the name is not registered
    no server         UNSUPPORTED: some TLDs (e.g. .lk) have no RDAP server in IANA's
                      list, so there is nothing to ask. VirusTotal's WHOIS creation date
                      is the backup for these (step 12).
    3xx and others    FAILED (redirects are never followed)

The query is the domain the registry sold (icann_domain, step 6), never the full host.
The summary holds the date, not the age: "8 days old" would be wrong after 30 days in
the cache, so the age is worked out when the report is made (step 12).

Only HTTPS servers from IANA's list are used. No account means no daily quota, but
registries do limit how fast you ask, so we send at most one every 2 seconds.
"""

from typing import Any

import httpx

from phishtriage.enrich.base import RequestSpec, Service, ServiceLimits, Unsupported, json_body
from phishtriage.enrich.models import FAILED, FOUND, NOT_FOUND, Lookup, LookupResult

BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
ACCEPT = "application/rdap+json, application/json"
MAX_STATUSES = 10


class RDAP(Service):
    name = "rdap"
    limits = ServiceLimits(per_minute=30)  # no quota, but registries limit the pace
    needs_key = False

    def __init__(self) -> None:
        # TLD -> RDAP server base URL, from IANA's list. None until load_servers().
        self.servers: dict[str, str] | None = None

    # --- IANA's list of servers ----------------------------------------------------------

    @staticmethod
    def bootstrap_lookup() -> Lookup:
        """The lookup that fetches IANA's list (through the Fetcher, so it is cached)."""
        return Lookup("rdap", "bootstrap", BOOTSTRAP_URL)

    def load_servers(self, result: LookupResult) -> bool:
        """Use the list from a bootstrap result. False if the result has no list."""
        servers = result.data.get("servers") if result.status == FOUND else None
        if not isinstance(servers, dict) or not servers:
            return False
        self.servers = {str(tld): str(url) for tld, url in servers.items()}
        return True

    def server_for(self, domain: str) -> str | None:
        """The RDAP server for a domain, by its longest matching ending in IANA's list.

        "paypa1-login.com" -> "https://rdap.verisign.com/com/v1/"
        "mrt.ac.lk"        -> None (no .lk server in the list)
        """
        if not self.servers:
            return None
        labels = domain.lower().rstrip(".").split(".")
        for start in range(1, len(labels)):  # "ac.lk" before "lk"
            if (server := self.servers.get(".".join(labels[start:]))) is not None:
                return server
        return None

    # --- the Service interface -------------------------------------------------------------

    def request(self, lookup: Lookup) -> RequestSpec:
        if lookup.kind == "bootstrap":
            return RequestSpec("GET", BOOTSTRAP_URL, headers={"Accept": "application/json"})
        if lookup.kind != "domain":
            raise ValueError(f"RDAP only answers for domains, not {lookup.kind}")
        if self.servers is None:
            raise RuntimeError("the RDAP server list is not loaded")  # a bug in step 12
        server = self.server_for(lookup.query)
        if server is None:
            tld = lookup.query.rstrip(".").rsplit(".", 1)[-1].lower()
            raise Unsupported(f"no RDAP server for .{tld} in IANA's list")
        return RequestSpec("GET", f"{server}domain/{lookup.query}", headers={"Accept": ACCEPT})

    def parse(self, lookup: Lookup, response: httpx.Response) -> LookupResult:
        if lookup.kind == "bootstrap":
            return _parse_bootstrap(lookup, response)
        if response.status_code == 404:
            summary = "not registered (the registry has no record of it)"
            return LookupResult(lookup, NOT_FOUND, summary=summary)
        if response.status_code != 200:
            return LookupResult(lookup, FAILED, error=f"RDAP answered {response.status_code}")
        body = json_body(response)
        data = _events(body.get("events"))
        if registrar := _registrar(body.get("entities")):
            data["registrar"] = registrar
        statuses = body.get("status")
        if isinstance(statuses, list) and statuses:
            data["status"] = [str(status) for status in statuses[:MAX_STATUSES]]
        return LookupResult(lookup, FOUND, summary=_summary(data), data=data)


def _parse_bootstrap(lookup: Lookup, response: httpx.Response) -> LookupResult:
    """IANA's dns.json: {"services": [[["com", "net"], ["https://..."]], ...]} -> TLD map."""
    if response.status_code != 200:
        return LookupResult(lookup, FAILED, error=f"IANA answered {response.status_code}")
    servers: dict[str, str] = {}
    for entry in json_body(response).get("services") or []:
        if not (isinstance(entry, list) and len(entry) >= 2):
            continue
        tlds, urls = entry[0], entry[1]
        https = [u for u in urls if isinstance(u, str) and u.startswith("https://")]
        if not https or not isinstance(tlds, list):
            continue  # a server without HTTPS is never used
        base = https[0] if https[0].endswith("/") else https[0] + "/"
        for tld in tlds:
            servers[str(tld).lower()] = base
    summary = f"RDAP servers for {len(servers)} TLDs"
    return LookupResult(lookup, FOUND, summary=summary, data={"servers": servers})


def _events(events: object) -> dict[str, Any]:
    """The dates that matter, as "YYYY-MM-DD"."""
    wanted = {"registration": "created", "expiration": "expires", "last changed": "last_changed"}
    data: dict[str, Any] = {}
    for event in events if isinstance(events, list) else []:
        if not isinstance(event, dict):
            continue
        field = wanted.get(str(event.get("eventAction", "")).lower())
        date = event.get("eventDate")
        if field and isinstance(date, str) and len(date) >= 10 and date[4] == "-":
            data.setdefault(field, date[:10])
    return data


def _registrar(entities: object) -> str | None:
    """The registrar's name, from the entity with the role "registrar" (a vCard "fn")."""
    for entity in entities if isinstance(entities, list) else []:
        if not isinstance(entity, dict) or "registrar" not in (entity.get("roles") or []):
            continue
        vcard = entity.get("vcardArray")
        if isinstance(vcard, list) and len(vcard) == 2 and isinstance(vcard[1], list):
            for item in vcard[1]:
                if isinstance(item, list) and len(item) == 4 and item[0] == "fn":
                    return str(item[3])
    return None


def _summary(data: dict[str, Any]) -> str:
    line = f"registered {data['created']}" if "created" in data else "no registration date given"
    if "registrar" in data:
        line += f", registrar {data['registrar']}"
    return line
