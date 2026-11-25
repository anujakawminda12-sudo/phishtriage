"""Run the lookups for a batch of emails, and turn the answers into findings (week 3, step 12).

    enrich(analyses, settings, allowlist)  ->  Enrichment

1. build the plan (plan.py): what to ask, where, in what order; nothing sent yet
2. open the cache (cache.py), and one client per service that has a key
3. load IANA's list of RDAP servers, if any domain age is needed
4. run every planned lookup through the Fetcher (base.py), most important first
5. keep every answer, by Lookup, for the report

Ctrl+C is safe: every finished lookup is already in the cache, the rest are marked "not
asked", the report is still printed, and running again carries on from the cache.

A dry run (week 3, step 13) stops after the plan: it only reads the cache, to count what
is already answered and what would be sent, and sends nothing.

Findings (no points: scoring is week 4). Week 4, step 7: each one also carries its
numbers in Finding.facts (facts_for below), so the scoring can apply the proposal's
thresholds (3+ engines for a URL or domain, 5+ for a file, AbuseIPDB 50+) and tell a
URL-level listing from a host-level one, a shared platform from an ordinary site, and
the sender's IP from any other:

    vt_flagged          at least one VirusTotal engine says malicious or suspicious
    urlhaus_listed      URLhaus lists the URL, host or file
    abuseipdb_reported  AbuseIPDB has at least one report for the IP
    domain_new          registered less than 30 days before this analysis (RDAP; for a
                        TLD without RDAP, VirusTotal's WHOIS date)
"""

import ipaddress
import random
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from typing import Any
from urllib.parse import urlsplit

from phishtriage.allowlist import Allowlist
from phishtriage.analysis import EmailAnalysis
from phishtriage.config import Settings
from phishtriage.domains import icann_domain, registered_domain
from phishtriage.enrich.abuseipdb import AbuseIPDB
from phishtriage.enrich.base import Fetcher, Service, ServiceStats
from phishtriage.enrich.cache import Clock, open_cache, utc_now
from phishtriage.enrich.models import DEFERRED, FAILED, FOUND, Lookup, LookupResult
from phishtriage.enrich.plan import LookupPlan, TargetPlan, build_plan
from phishtriage.enrich.rdap import RDAP
from phishtriage.enrich.urlhaus import URLhaus
from phishtriage.enrich.virustotal import VirusTotal
from phishtriage.iocs import defang
from phishtriage.models import IOC, Finding

# Detection thresholds: when a fact becomes a finding. Week 4 decides what it is worth.
VT_MIN_ENGINES = 1
ABUSEIPDB_MIN_REPORTS = 1
NEW_DOMAIN_DAYS = 30

SERVICE_NAMES = {
    "virustotal": "VirusTotal",
    "abuseipdb": "AbuseIPDB",
    "urlhaus": "URLhaus",
    "rdap": "RDAP",
}

Progress = Callable[[int, int, LookupResult], None]
PlanShown = Callable[[LookupPlan], None]


@dataclass
class Enrichment:
    """Everything one --enrich run learned, ready for the report.

    plan:         what was planned (plan.py), with the reason for every skipped value
    results:      the answer to every planned lookup
    stats:        per service: cache hits, API calls, found, failed... (base.py)
    stopped:      services stopped part-way, and why (bad key, quota, Ctrl+C...)
    calls_24h:    per service: API calls in the last 24 hours, after this run
    budgets:      per service: how many calls a day PhishTriage may use (None: no limit)
    warnings:     problems that did not stop the run (e.g. an unusable cache file)
    analysed_on:  the date domain ages are counted to, in UTC like the services' dates
                  (the local date was one day ahead in Sri Lanka from 00:00 to 05:30)
    dry_run:      True if nothing was sent (only the plan and the cache were read)
    to_send:      dry run only: per service, the lookups the cache cannot answer yet
    allowlist:    the allowlist the plan used; it tells shared platforms apart (step 7)
    """

    plan: LookupPlan
    results: dict[Lookup, LookupResult] = field(default_factory=dict)
    stats: dict[str, ServiceStats] = field(default_factory=dict)
    stopped: dict[str, str] = field(default_factory=dict)
    calls_24h: dict[str, int] = field(default_factory=dict)
    budgets: dict[str, int | None] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    analysed_on: date = field(default_factory=lambda: datetime.now(UTC).date())
    dry_run: bool = False
    to_send: dict[str, int] = field(default_factory=dict)
    allowlist: Allowlist | None = None

    # --- answers for one IOC or attachment ------------------------------------------------

    def target(self, ioc: IOC) -> TargetPlan:
        return self.plan.for_ioc(ioc)

    def answers(self, target: TargetPlan) -> list[LookupResult]:
        return [self.results[lookup] for lookup in target.lookups if lookup in self.results]

    def domain_age(self, ioc: IOC) -> tuple[str, int, str] | None:
        """(registration date, age in days, source) for a domain IOC, or None.

        RDAP first; for a TLD RDAP cannot answer (.lk), VirusTotal's WHOIS date.
        """
        if ioc.kind != "domain":
            return None
        answers = self.answers(self.target(ioc))
        for service, source in (("rdap", "RDAP"), ("virustotal", "VirusTotal WHOIS")):
            for result in answers:
                created = result.data.get("created")
                if result.lookup.service == service and result.status == FOUND and created:
                    try:
                        days = (self.analysed_on - date.fromisoformat(created)).days
                    except ValueError:
                        continue
                    return created, days, source
        return None

    def unanswered_for(self, analysis: EmailAnalysis) -> int:
        """How many lookups for this email's IOCs and attachments got no answer: failed,
        or not asked (a limit, Ctrl+C). Week 4, step 8: the score says when it is partial.

        "No answer possible" (UNSUPPORTED, e.g. a TLD with no RDAP server) is not counted:
        asking again would not change it. Forwarded emails are counted on their own.
        """
        targets = [self.target(ioc) for ioc in analysis.iocs]
        targets += [self.plan.for_file(att.sha256) for att in analysis.email.attachments]
        lookups = {lookup for target in targets for lookup in target.lookups}
        return sum(
            1
            for lookup in lookups
            if (result := self.results.get(lookup)) is None or result.status in (FAILED, DEFERRED)
        )

    # --- the run as a whole ------------------------------------------------------------------

    def unanswered(self) -> int:
        """Planned lookups that got no answer: failed, or not asked (limits, Ctrl+C...)."""
        missing = len(self.plan.lookups) - len(self.results)
        return missing + sum(1 for r in self.results.values() if r.status in (DEFERRED, FAILED))

    # --- findings ----------------------------------------------------------------------------

    def findings_for(self, analysis: EmailAnalysis) -> list[Finding]:
        """The enrichment findings for one email (not the emails forwarded inside it)."""
        findings: list[Finding] = []
        sender_ip = analysis.sender_ip.address if analysis.sender_ip else ""
        targets = [(defang(ioc.value), self.target(ioc)) for ioc in analysis.iocs]
        for attachment in analysis.email.attachments:
            shown = f"{attachment.filename} (SHA-256 {attachment.sha256[:12]}...)"
            targets.append((shown, self.plan.for_file(attachment.sha256)))
        for shown, target in targets:
            for result in self.answers(target):
                if (rule := notable(result)) is not None:
                    service = SERVICE_NAMES[result.lookup.service]
                    detail = f"{shown}: {service} says {result.summary}"
                    facts = facts_for(result, sender_ip, self.allowlist)
                    findings.append(Finding(rule=rule, detail=detail, facts=facts))
        findings.extend(self._new_domains(analysis.iocs))
        return findings

    def _new_domains(self, iocs: Iterable[IOC]) -> list[Finding]:
        found: list[Finding] = []
        seen: set[str] = set()
        for ioc in iocs:
            age = self.domain_age(ioc)
            owner = icann_domain(ioc.value) or ioc.value
            if age is None or owner in seen:
                continue
            created, days, source = age
            if days < NEW_DOMAIN_DAYS:
                seen.add(owner)
                detail = (
                    f"{defang(owner)} was registered {created}, {days} days before this "
                    f"analysis (from {source})"
                )
                service = "rdap" if source == "RDAP" else "virustotal"
                facts = {"service": service, "kind": "domain", "days": days}
                found.append(Finding(rule="domain_new", detail=detail, facts=facts))
        return found


def facts_for(result: LookupResult, sender_ip: str, allowlist: Allowlist | None) -> dict[str, Any]:
    """The numbers behind one enrichment finding (week 4, step 7).

    Always:     service ("virustotal", "urlhaus", "abuseipdb"), kind (what was asked
                about: "url", "domain", "host", "ip" or "file")
    VirusTotal: malicious, suspicious, engines (how many engines gave a verdict)
    URLhaus:    url:  online (true if the listed URL still serves malware)
                host: online_urls, listed_urls (how many of the host's URLs are listed,
                      and how many of those are still online)
                file: nothing more: a listed file is known malware
    AbuseIPDB:  score (confidence, 0-100), reports, whitelisted (AbuseIPDB's own list
                of known-good IPs, such as big mail providers)
    Not a file: shared_platform (see below)
    An IP:      sender_ip (true if it is the IP this email came from, step 3)

    Only numbers, true/false and fixed words: never the value that was looked up.
    """
    lookup, data = result.lookup, result.data
    facts: dict[str, Any] = {"service": lookup.service, "kind": lookup.kind}
    if lookup.service == "virustotal":
        facts |= {name: int(data.get(name, 0)) for name in ("malicious", "suspicious", "engines")}
    elif lookup.service == "urlhaus" and lookup.kind == "url":
        facts["online"] = data.get("url_status") == "online"
    elif lookup.service == "urlhaus" and lookup.kind == "host":
        facts["online_urls"] = int(data.get("online", 0))
        facts["listed_urls"] = int(data.get("url_count", 0))
    elif lookup.service == "abuseipdb":
        facts["score"] = int(data.get("score", 0))
        facts["reports"] = int(data.get("reports", 0))
        facts["whitelisted"] = bool(data.get("is_whitelisted", False))

    if lookup.kind != "file":
        host = _host(lookup)
        facts["shared_platform"] = shared_platform(host, allowlist)
        if (ip := _ip(host)) is not None:
            facts["sender_ip"] = ip == _ip(sender_ip)
    return facts


def shared_platform(host: str, allowlist: Allowlist | None) -> bool:
    """True if many people's content lives under this name, so a verdict on the whole
    name says little about one email.

        user.github.io       a private suffix: registered_domain() is user.github.io,
                             but the name a registry sold (icann_domain) is github.io
        docs.google.com      a user-content host of an allowlisted platform: google.com
                             is allowlisted, docs.google.com is an exception that is
                             still looked up (anyone can publish a Google Doc)
        paypa1-login.com     an ordinary site: False
        an IP address        False

    Not caught: a big site on its own name, such as www.patreon.com or
    www.pinterest.com, the two weak hits in week 3's gate. Step 8's thresholds deal
    with those instead: Patreon's listing had 0 URLs online, Pinterest 1 engine of 92.
    """
    if not host or _ip(host) is not None:
        return False
    owner = icann_domain(host)
    if registered_domain(host) != owner:
        return True
    return allowlist is not None and allowlist.covers(owner)


def _host(lookup: Lookup) -> str:
    """The host a lookup is about: a URL's host, or the domain, host or IP itself."""
    if lookup.kind != "url":
        return lookup.query
    try:
        return (urlsplit(lookup.query).hostname or "").lower()
    except ValueError:  # a broken URL such as http://[::1
        return ""


def _ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """The value as an IP address, or None if it is not one. Two spellings of the same
    IPv6 address ("2001:DB8::0:1", "2001:db8::1") compare equal this way."""
    try:
        return ipaddress.ip_address(value.strip("[]"))
    except ValueError:
        return None


def notable(result: LookupResult) -> str | None:
    """The finding rule a result triggers, or None. Facts only: no points."""
    if result.status != FOUND:
        return None
    service, data = result.lookup.service, result.data
    if service == "virustotal" and data.get("malicious", 0) + data.get("suspicious", 0) >= (
        VT_MIN_ENGINES
    ):
        return "vt_flagged"
    if service == "urlhaus":
        return "urlhaus_listed"
    if service == "abuseipdb" and data.get("reports", 0) >= ABUSEIPDB_MIN_REPORTS:
        return "abuseipdb_reported"
    return None


def make_services(settings: Settings) -> dict[str, Service]:
    """One client per service that can be used (its key is set; RDAP needs none)."""
    builders: dict[str, Callable[[], Service]] = {
        "virustotal": lambda: VirusTotal(settings.vt_api_key),
        "abuseipdb": lambda: AbuseIPDB(settings.abuseipdb_api_key),
        "urlhaus": lambda: URLhaus(settings.abusech_auth_key),
        "rdap": RDAP,
    }
    return {name: build() for name, build in builders.items() if settings.missing_key(name) is None}


def enrich(
    analyses: Iterable[EmailAnalysis],
    settings: Settings,
    allowlist: Allowlist,
    *,
    hosts_only: bool = False,
    max_lookups: int | None = None,
    progress: Progress | None = None,
    on_plan: PlanShown | None = None,
    dry_run: bool = False,
    clock: Clock = utc_now,
    sleep: Callable[[float], None] = time.sleep,
    jitter: Callable[[], float] = random.random,
    services: dict[str, Service] | None = None,
) -> Enrichment:
    """Look up everything the plan allows, for a whole batch of emails at once."""
    analyses = list(analyses)
    plan = build_plan(analyses, settings, allowlist, hosts_only=hosts_only)
    # dry_run is set here, before any early return, so the caller always knows nothing
    # was sent (a dry run with an empty plan once printed full reports: step 13's tests)
    enrichment = Enrichment(
        plan=plan, analysed_on=clock().date(), dry_run=dry_run, allowlist=allowlist
    )
    if on_plan is not None:
        on_plan(plan)  # e.g. the CLI shows how many lookups, and how long they may take
    if not plan.lookups:
        return enrichment  # nothing to ask: no cache, no client, no network

    services = make_services(settings) if services is None else services
    if dry_run:
        return _dry_run(enrichment, settings, services, clock)
    cache, enrichment.warnings = open_cache(settings.cache_path, clock)
    with (
        cache,
        Fetcher(
            services, cache, max_lookups=max_lookups, clock=clock, sleep=sleep, jitter=jitter
        ) as fetcher,
    ):
        if any(lookup.service == "rdap" for lookup in plan.lookups):
            _load_rdap_servers(fetcher, services.get("rdap"))
        total = len(plan.lookups)
        try:
            for done, lookup in enumerate(plan.lookups, start=1):
                result = fetcher.fetch(lookup)
                enrichment.results[lookup] = result
                if progress is not None:
                    progress(done, total, result)
        except KeyboardInterrupt:
            for name in services:
                fetcher.stop(name, "stopped with Ctrl+C")
            for lookup in plan.lookups:
                if lookup not in enrichment.results:
                    result = LookupResult(lookup, DEFERRED, error="stopped with Ctrl+C")
                    enrichment.results[lookup] = result
                    fetcher.stats[lookup.service].count(result)
        enrichment.stats = fetcher.stats
        enrichment.stopped = dict(fetcher.stopped)
        enrichment.calls_24h = {name: cache.calls_within(name) for name in services}
        enrichment.budgets = {name: s.limits.daily_budget for name, s in services.items()}
    return enrichment


def _dry_run(
    enrichment: Enrichment, settings: Settings, services: dict[str, Service], clock: Clock
) -> Enrichment:
    """Count what the cache already answers and what would be sent. Sends nothing.

    A missing cache file is not created: everything would be sent.
    """
    enrichment.budgets = {name: s.limits.daily_budget for name, s in services.items()}
    to_send = dict.fromkeys(services, 0)
    if not settings.cache_path.exists():
        for lookup in enrichment.plan.lookups:
            to_send[lookup.service] += 1
        enrichment.to_send = to_send
        enrichment.calls_24h = dict.fromkeys(services, 0)
        return enrichment
    cache, enrichment.warnings = open_cache(settings.cache_path, clock)
    with cache:
        for lookup in enrichment.plan.lookups:
            if cache.get(lookup) is None:
                to_send[lookup.service] += 1
        enrichment.calls_24h = {name: cache.calls_within(name) for name in services}
    enrichment.to_send = to_send
    return enrichment


def _load_rdap_servers(fetcher: Fetcher, rdap: Service | None) -> None:
    """Fetch IANA's list (cached for 30 days). Without it, RDAP is stopped for the run."""
    if not isinstance(rdap, RDAP):
        return
    result = fetcher.fetch(rdap.bootstrap_lookup(), counted=False)  # not a planned lookup
    if not rdap.load_servers(result):
        reason = result.error or "it was empty"
        fetcher.stop("rdap", f"IANA's list of RDAP servers could not be loaded ({reason})")
