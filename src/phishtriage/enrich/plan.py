"""Decide what to look up, where, and in what order (week 3, step 6).

The plan is the privacy and quota control for the whole week. It is a pure function:
analyses in, a list of lookups out, and nothing is sent anywhere. That makes every rule
easy to test, and the code that does send requests (steps 8-12) stays simple: it only
ever sends what is in the plan.

What goes where:

    attachment SHA-256   VirusTotal (file), URLhaus (payload)
    URL                  URLhaus; VirusTotal for the first 3 URLs on each domain
    domain (host)        VirusTotal, URLhaus (host); RDAP for the domain's registration date
    IP from a link       AbuseIPDB, VirusTotal, URLhaus (host)
    IP from Received     AbuseIPDB only (VirusTotal's 500 a day are kept for the rest)
    email address        never sent anywhere (its domain is a domain IOC already)

Rules applied before anything is added:
    - allowlisted values, test names (.test, example.com) and non-public IPs are skipped;
    - nothing that contains your address, in any form, can enter the plan (privacy.py);
      a URL that does is not looked up, but its host still is;
    - URLs lose their #fragment;
    - with --hosts-only, no full URL is sent at all;
    - a value seen in many emails is looked up once.

Lookup order (from the proposal): attachment hashes, then URLs, then domains, then IPs.
If the daily quota runs out part-way, the most important lookups are already done.
"""

import ipaddress
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from phishtriage.allowlist import Allowlist
from phishtriage.analysis import EmailAnalysis, walk
from phishtriage.config import SERVICE_KEYS, Settings
from phishtriage.domains import (
    ascii_domain,
    has_public_suffix,
    icann_domain,
    is_reserved,
    registered_domain,
)
from phishtriage.enrich.models import Lookup
from phishtriage.models import IOC
from phishtriage.privacy import AddressRedactor, addresses_to_hide, without_fragment

# Lookup kinds, in the order they run (the proposal's priority order)
PRIORITY = {"file": 0, "url": 1, "domain": 2, "host": 2, "ip": 3}

# A newsletter can hold 80 tracking links on one domain: VirusTotal gets only the first few
VT_URLS_PER_DOMAIN = 3

# Why something is not looked up. The report shows these, so they are written for a reader.
ALLOWLISTED = "allowlisted (lookup skipped, not trusted)"
EMAIL_NEVER_SENT = "email addresses are never sent to any service"
YOUR_ADDRESS = "contains your address: not sent (its host is looked up instead)"
HOSTS_ONLY = "--hosts-only: full URLs are not sent"
RESERVED_NAME = "reserved test or documentation name"
NOT_PUBLIC_IP = "not a public IP address"
NOT_PUBLIC_NAME = "not a public domain name"
EMPTY_FILE = "empty file"
VT_URL_LIMIT = f"VirusTotal: already {VT_URLS_PER_DOMAIN} URLs on this domain (saves quota)"
SHARED_PLATFORM = "no domain age: {owner} is a shared platform, its age says nothing here"
ALLOWLISTED_OWNER = "no domain age: {owner} is allowlisted, its age says nothing here"


@dataclass
class TargetPlan:
    """What happens to one IOC or attachment: the lookups that answer it, or why not."""

    lookups: list[Lookup] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)


@dataclass
class LookupPlan:
    """The whole batch's plan.

    lookups:      every lookup, once, most important first
    targets:      (kind, value) -> TargetPlan, for every IOC and attachment in the batch;
                  kind is the IOC kind, or "file" with the attachment's SHA-256
    services_off: service -> why it cannot be used (no key)
    """

    lookups: list[Lookup] = field(default_factory=list)
    targets: dict[tuple[str, str], TargetPlan] = field(default_factory=dict)
    services_off: dict[str, str] = field(default_factory=dict)

    def for_ioc(self, ioc: IOC) -> TargetPlan:
        return self.targets[(ioc.kind, ioc.value)]

    def for_file(self, sha256: str) -> TargetPlan:
        return self.targets[("file", sha256)]

    def count(self, service: str) -> int:
        """How many lookups this plan has for one service."""
        return sum(1 for lookup in self.lookups if lookup.service == service)


def build_plan(
    analyses: Iterable[EmailAnalysis],
    settings: Settings,
    allowlist: Allowlist,
    hosts_only: bool = False,
) -> LookupPlan:
    """Plan the lookups for a batch of analysed emails (and every email forwarded in them).

    Addresses are hidden batch-wide: anyone who received any email in the batch, plus
    PHISHTRIAGE_MY_ADDRESSES, is hidden from every lookup. Otherwise a URL carrying a
    colleague's address could be sent while planning an email where they were not a
    recipient.
    """
    analyses = list(analyses)
    hidden = set(settings.my_addresses.reveal())
    for analysis in analyses:
        hidden |= addresses_to_hide(analysis.email)  # walks forwarded emails itself

    builder = _PlanBuilder(
        ready=set(settings.ready_services()),
        redactor=AddressRedactor(hidden),
        allowlist=allowlist,
        hosts_only=hosts_only,
    )
    # Pass 1: every unique target, with the sources of every copy merged, in the order
    # first seen. Pass 2 plans each once, so an IP that is a Received hop in one email and
    # a link in another gets the link's lookups too.
    for analysis in analyses:
        for level in walk(analysis):
            for attachment in level.email.attachments:
                builder.add_file(attachment.sha256, attachment.size)
            for ioc in level.iocs:
                builder.add_ioc(ioc)

    off = {s: reason for s in SERVICE_KEYS if (reason := settings.missing_key(s)) is not None}
    return builder.build(services_off=off)


@dataclass
class _Target:
    kind: str
    value: str
    sources: set[str] = field(default_factory=set)
    allowlisted: bool = False
    size: int = -1  # files only


class _PlanBuilder:
    """Collects targets, then plans them (Java: the Builder pattern)."""

    def __init__(
        self, ready: set[str], redactor: AddressRedactor, allowlist: Allowlist, hosts_only: bool
    ) -> None:
        self.ready = ready
        self.redactor = redactor
        self.allowlist = allowlist
        self.hosts_only = hosts_only
        self.targets: dict[tuple[str, str], _Target] = {}
        self.lookups: dict[Lookup, None] = {}  # a dict used as an ordered set
        self.vt_urls: Counter[str] = Counter()  # VirusTotal URL lookups per domain

    # --- pass 1 ---------------------------------------------------------------------

    def add_file(self, sha256: str, size: int) -> None:
        self.targets.setdefault(("file", sha256), _Target("file", sha256, size=size))

    def add_ioc(self, ioc: IOC) -> None:
        target = self.targets.setdefault((ioc.kind, ioc.value), _Target(ioc.kind, ioc.value))
        target.sources.update(ioc.sources)
        target.allowlisted = target.allowlisted or ioc.allowlisted

    # --- pass 2 ---------------------------------------------------------------------

    def build(self, services_off: dict[str, str]) -> LookupPlan:
        plans = {key: self._plan(target) for key, target in self.targets.items()}
        # sorted() is stable: within one kind, the order things were first seen is kept
        ordered = sorted(self.lookups, key=lambda lookup: PRIORITY[lookup.kind])
        return LookupPlan(lookups=ordered, targets=plans, services_off=services_off)

    def _plan(self, target: _Target) -> TargetPlan:
        plan = TargetPlan()
        if target.kind == "email":
            plan.skipped.append(EMAIL_NEVER_SENT)
        elif target.allowlisted:
            plan.skipped.append(ALLOWLISTED)
        elif target.kind == "file":
            self._plan_file(target, plan)
        elif target.kind == "url":
            self._plan_url(target.value, plan)
        elif target.kind == "domain":
            self._plan_domain(target.value, plan)
        elif target.kind == "ip":
            self._plan_ip(target, plan)
        return plan

    def _plan_file(self, target: _Target, plan: TargetPlan) -> None:
        # A hash cannot be turned back into the file, so hash lookups are always safe
        if target.size == 0:
            plan.skipped.append(EMPTY_FILE)
            return
        self._add(plan, "virustotal", "file", target.value)
        self._add(plan, "urlhaus", "file", target.value)

    def _plan_url(self, url: str, plan: TargetPlan) -> None:
        url = without_fragment(url)
        host = _host(url)
        if problem := _host_problem(host):
            plan.skipped.append(problem)
        elif self.redactor.contains(url):
            plan.skipped.append(YOUR_ADDRESS)
        elif self.hosts_only:
            plan.skipped.append(HOSTS_ONLY)
        else:
            self._add(plan, "urlhaus", "url", url)
            self._add_vt_url(plan, url, host)

    def _add_vt_url(self, plan: TargetPlan, url: str, host: str) -> None:
        if "virustotal" not in self.ready:
            return
        domain = host if _is_ip(host) else registered_domain(ascii_domain(host))
        if self.vt_urls[domain] >= VT_URLS_PER_DOMAIN:
            plan.skipped.append(VT_URL_LIMIT)
        elif self._add(plan, "virustotal", "url", url):
            self.vt_urls[domain] += 1

    def _plan_domain(self, host: str, plan: TargetPlan) -> None:
        if problem := _host_problem(host):
            plan.skipped.append(problem)
            return
        self._add(plan, "virustotal", "domain", host)
        self._add(plan, "urlhaus", "host", host)
        owner = icann_domain(host)  # the name a registry sold, the only one with an age
        if registered_domain(host) != owner:
            plan.skipped.append(SHARED_PLATFORM.format(owner=owner))
        elif self.allowlist.covers(owner):  # e.g. sites.google.com: Google's age is no help
            plan.skipped.append(ALLOWLISTED_OWNER.format(owner=owner))
        else:
            self._add(plan, "rdap", "domain", owner)

    def _plan_ip(self, target: _Target, plan: TargetPlan) -> None:
        if problem := _host_problem(target.value):
            plan.skipped.append(problem)
            return
        self._add(plan, "abuseipdb", "ip", target.value)
        if "url" in target.sources:  # a link straight to an IP: rare, and worth the quota
            self._add(plan, "virustotal", "ip", target.value)
            self._add(plan, "urlhaus", "host", target.value)

    def _add(self, plan: TargetPlan, service: str, kind: str, query: str) -> bool:
        """Add one lookup, if the service is ready. The last privacy check is here too.

        Every lookup passes through this one method, so this check guards all of them,
        whatever a future rule above forgets.
        """
        if service not in self.ready:
            return False
        if self.redactor.contains(query):
            if YOUR_ADDRESS not in plan.skipped:
                plan.skipped.append(YOUR_ADDRESS)
            return False
        lookup = Lookup(service, kind, query)
        self.lookups[lookup] = None
        plan.lookups.append(lookup)
        return True


def _host(url: str) -> str:
    try:
        return urlsplit(url).hostname or ""
    except ValueError:
        return ""


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def _host_problem(host: str) -> str | None:
    """Why a host is never worth a lookup, or None when it is."""
    if _is_ip(host):
        # documentation ranges (192.0.2.x, 203.0.113.x ...) are not global either
        return None if ipaddress.ip_address(host).is_global else NOT_PUBLIC_IP
    if is_reserved(host):
        return RESERVED_NAME
    if not has_public_suffix(ascii_domain(host)):
        return NOT_PUBLIC_NAME
    return None
