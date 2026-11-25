"""Week 3, step 6: the lookup plan decides what is sent, where, and in what order."""

import base64
import hashlib
from pathlib import Path
from urllib.parse import urlsplit

from phishtriage.allowlist import load_allowlist
from phishtriage.analysis import EmailAnalysis, analyse_file
from phishtriage.config import Secret, Settings
from phishtriage.enrich.plan import (
    ALLOWLISTED,
    EMAIL_NEVER_SENT,
    EMPTY_FILE,
    HOSTS_ONLY,
    NOT_PUBLIC_IP,
    NOT_PUBLIC_NAME,
    RESERVED_NAME,
    VT_URL_LIMIT,
    VT_URLS_PER_DOMAIN,
    YOUR_ADDRESS,
    Lookup,
    build_plan,
)
from phishtriage.models import IOC, Attachment, AuthResults, ParsedEmail
from phishtriage.privacy import AddressRedactor

ALLOWLIST = load_allowlist()
ME = "me.victim@gmail.com"
KEY = Secret("k" * 64)
ALL_READY = Settings(
    vt_api_key=KEY, abuseipdb_api_key=KEY, abusech_auth_key=KEY, my_addresses=Secret((ME,))
)
SHA = "a" * 64


def make(*iocs: IOC, attachments=(), recipients=(), forwarded=()) -> EmailAnalysis:
    """A hand-built analysis with just the IOCs a test needs."""
    email = ParsedEmail(
        path=Path("test.eml"), attachments=list(attachments), recipients=list(recipients)
    )
    return EmailAnalysis(
        email=email, auth=AuthResults(), iocs=list(iocs), forwarded=list(forwarded)
    )


def url(value: str, allowlisted: bool = False) -> IOC:
    return IOC("url", value, ["html:a[href]"], 1, allowlisted)


def domain(value: str, allowlisted: bool = False) -> IOC:
    return IOC("domain", value, ["url"], 1, allowlisted)


def ip(value: str, source: str = "header:Received (hop 2)") -> IOC:
    return IOC("ip", value, [source], 1)


def attachment(sha256: str = SHA, size: int = 1000) -> Attachment:
    return Attachment(
        filename="a.pdf", content_type="application/pdf", size=size, md5="", sha1="", sha256=sha256
    )


def pairs(lookups) -> list[tuple[str, str]]:
    return [(lookup.service, lookup.kind) for lookup in lookups]


# --- each kind goes to the right services ------------------------------------------------


def test_a_url_goes_to_urlhaus_and_virustotal():
    plan = build_plan([make(url("https://paypa1-login.com/verify"))], ALL_READY, ALLOWLIST)
    target = plan.for_ioc(url("https://paypa1-login.com/verify"))
    assert pairs(target.lookups) == [("urlhaus", "url"), ("virustotal", "url")]
    assert target.skipped == []


def test_a_domain_goes_to_virustotal_urlhaus_and_rdap():
    plan = build_plan([make(domain("login.paypa1-login.com"))], ALL_READY, ALLOWLIST)
    assert plan.for_ioc(domain("login.paypa1-login.com")).lookups == [
        Lookup("virustotal", "domain", "login.paypa1-login.com"),
        Lookup("urlhaus", "host", "login.paypa1-login.com"),
        Lookup("rdap", "domain", "paypa1-login.com"),  # the name the registry sold
    ]


def test_a_received_ip_goes_to_abuseipdb_only_but_a_linked_ip_goes_everywhere():
    plan = build_plan([make(ip("8.8.8.8"), ip("1.1.1.1", source="url"))], ALL_READY, ALLOWLIST)
    assert pairs(plan.for_ioc(ip("8.8.8.8")).lookups) == [("abuseipdb", "ip")]
    assert pairs(plan.for_ioc(ip("1.1.1.1", "url")).lookups) == [
        ("abuseipdb", "ip"),
        ("virustotal", "ip"),
        ("urlhaus", "host"),
    ]


def test_an_attachment_hash_goes_to_virustotal_and_urlhaus():
    plan = build_plan([make(attachments=[attachment()])], ALL_READY, ALLOWLIST)
    assert plan.for_file(SHA).lookups == [
        Lookup("virustotal", "file", SHA),
        Lookup("urlhaus", "file", SHA),
    ]


def test_email_addresses_are_never_sent():
    address = IOC("email", "attacker@paypa1-login.com", ["header:From"], 1)
    plan = build_plan([make(address)], ALL_READY, ALLOWLIST)
    assert plan.for_ioc(address).lookups == []
    assert plan.for_ioc(address).skipped == [EMAIL_NEVER_SENT]
    assert plan.lookups == []


# --- order and de-duplication -------------------------------------------------------------


def test_order_is_files_then_urls_then_domains_then_ips():
    analysis = make(
        ip("8.8.8.8"),
        domain("paypa1-login.com"),
        url("https://paypa1-login.com/a"),
        attachments=[attachment()],
    )
    plan = build_plan([analysis], ALL_READY, ALLOWLIST)
    kinds = [lookup.kind for lookup in plan.lookups]
    assert kinds == ["file", "file", "url", "url", "domain", "host", "domain", "ip"]


def test_a_value_seen_in_many_emails_is_looked_up_once():
    emails = [make(domain("paypa1-login.com")) for _ in range(30)]
    plan = build_plan(emails, ALL_READY, ALLOWLIST)
    assert plan.count("virustotal") == 1
    assert plan.count("rdap") == 1
    assert len(plan.targets) == 1


def test_an_ip_seen_as_a_hop_and_as_a_link_gets_the_link_lookups():
    emails = [make(ip("1.1.1.1")), make(ip("1.1.1.1", source="url"))]
    plan = build_plan(emails, ALL_READY, ALLOWLIST)
    assert ("virustotal", "ip") in pairs(plan.lookups)


def test_forwarded_emails_are_planned_too():
    inner = make(domain("paypa1-login.com"))
    plan = build_plan([make(forwarded=[inner])], ALL_READY, ALLOWLIST)
    assert Lookup("virustotal", "domain", "paypa1-login.com") in plan.lookups


# --- what is skipped, and why ----------------------------------------------------------------


def test_allowlisted_reserved_and_non_public_values_are_skipped():
    values = [
        url("https://www.paypal.com/signin", allowlisted=True),
        domain("paypa1-secure.test"),
        domain("www.example.com"),
        domain("intranet.corp"),
        ip("203.0.113.45"),  # documentation range
        url("http://192.168.1.1/admin"),
        url("https://localhost/x"),
    ]
    plan = build_plan([make(*values)], ALL_READY, ALLOWLIST)
    reasons = [plan.for_ioc(ioc).skipped for ioc in values]
    assert reasons == [
        [ALLOWLISTED],
        [RESERVED_NAME],
        [RESERVED_NAME],
        [NOT_PUBLIC_NAME],
        [NOT_PUBLIC_IP],
        [NOT_PUBLIC_IP],
        [RESERVED_NAME],
    ]
    assert plan.lookups == []


def test_an_empty_attachment_is_not_looked_up():
    empty = hashlib.sha256(b"").hexdigest()
    plan = build_plan([make(attachments=[attachment(empty, size=0)])], ALL_READY, ALLOWLIST)
    assert plan.for_file(empty).skipped == [EMPTY_FILE]
    assert plan.lookups == []


def test_virustotal_gets_only_the_first_urls_on_each_domain():
    links = [url(f"https://t.paypa1-login.com/c/{n}") for n in range(5)]
    plan = build_plan([make(*links)], ALL_READY, ALLOWLIST)
    assert plan.count("virustotal") == VT_URLS_PER_DOMAIN
    assert plan.count("urlhaus") == 5  # URLhaus has no daily quota
    assert plan.for_ioc(links[4]).skipped == [VT_URL_LIMIT]
    # a different domain starts its own count
    other = build_plan([make(*links, url("https://other-site.com/x"))], ALL_READY, ALLOWLIST)
    assert other.count("virustotal") == VT_URLS_PER_DOMAIN + 1


def test_hosts_only_sends_no_full_url():
    analysis = make(url("https://bank.example-bank.com/statement?id=12345"))
    plan = build_plan([analysis], ALL_READY, ALLOWLIST, hosts_only=True)
    assert plan.lookups == []
    assert plan.for_ioc(analysis.iocs[0]).skipped == [HOSTS_ONLY]


# --- domain age (RDAP) --------------------------------------------------------------------------


def test_no_domain_age_for_shared_platforms_or_allowlisted_owners():
    site = domain("phish-kit.github.io")  # GitHub hands these out; no registry sold it
    user_content = domain("sites.google.com")  # not allowlisted ("!" exception), owner is
    plan = build_plan([make(site, user_content)], ALL_READY, ALLOWLIST)
    assert "rdap" not in [lookup.service for lookup in plan.lookups]
    assert plan.for_ioc(site).skipped == [
        "no domain age: github.io is a shared platform, its age says nothing here"
    ]
    assert plan.for_ioc(user_content).skipped == [
        "no domain age: google.com is allowlisted, its age says nothing here"
    ]
    # the hosts themselves are still looked up
    assert Lookup("virustotal", "domain", "phish-kit.github.io") in plan.lookups


# --- your address -------------------------------------------------------------------------------


def test_a_url_with_your_address_is_not_sent_but_its_host_is():
    tracking = url(f"https://track.shop-mail.com/o?to={ME.replace('@', '%40')}")
    plan = build_plan([make(tracking, domain("track.shop-mail.com"))], ALL_READY, ALLOWLIST)
    assert plan.for_ioc(tracking).lookups == []
    assert plan.for_ioc(tracking).skipped == [YOUR_ADDRESS]
    assert Lookup("virustotal", "domain", "track.shop-mail.com") in plan.lookups


def test_the_fragment_is_removed_before_a_url_is_sent():
    # The address is only in the fragment, so the URL without it can be looked up
    link = url(f"https://login.paypa1-login.com/verify#{ME}")
    plan = build_plan([make(link)], ALL_READY, ALLOWLIST)
    assert Lookup("urlhaus", "url", "https://login.paypa1-login.com/verify") in plan.lookups


def test_recipients_of_any_email_in_the_batch_are_hidden_in_every_email():
    colleague = "nimal@company-mail.com"
    link = url(f"https://track.shop-mail.com/o?e={colleague}")
    # Nimal received the first email; the link with his address is in the second one
    emails = [make(recipients=[colleague]), make(link)]
    settings = Settings(vt_api_key=KEY, abusech_auth_key=KEY)  # no configured addresses
    plan = build_plan(emails, settings, ALLOWLIST)
    assert plan.for_ioc(link).skipped == [YOUR_ADDRESS]


def test_no_query_ever_contains_your_address_in_any_form():
    encoded = base64.b64encode(ME.encode()).decode()
    hashed = hashlib.md5(ME.encode()).hexdigest()
    links = [
        url(f"https://a.shop-mail.com/?e={ME}"),
        url("https://b.shop-mail.com/?e=me.victim%40gmail.com"),
        url(f"https://c.shop-mail.com/?d={encoded}"),
        url(f"https://d.shop-mail.com/?h={hashed}"),
        url(f"https://e.shop-mail.com/#{encoded}"),
        url("https://f.shop-mail.com/clean"),
    ]
    plan = build_plan([make(*links)], ALL_READY, ALLOWLIST)
    redactor = AddressRedactor([ME])
    assert plan.lookups  # the clean ones are still looked up
    for lookup in plan.lookups:
        assert not redactor.contains(lookup.query), lookup


def test_a_host_carrying_your_address_is_stopped_by_the_last_check():
    # Some trackers give each recipient a subdomain made from their address. A host name
    # cannot hold base64's "=", and it is lower-case; the redactor still finds it.
    label = base64.b64encode(ME.encode()).decode().rstrip("=").lower()
    tracker = domain(f"{label}.track-mail.com")
    plan = build_plan([make(tracker)], ALL_READY, ALLOWLIST)
    target = plan.for_ioc(tracker)
    assert target.skipped == [YOUR_ADDRESS]  # once, though two lookups were refused
    # only the registration date of the registry's name is still asked for
    assert target.lookups == [Lookup("rdap", "domain", "track-mail.com")]


def test_a_host_made_from_your_address_in_hex_is_stopped_too():
    tracker = domain(f"{ME.encode().hex()}.track-mail.com")
    plan = build_plan([make(tracker)], ALL_READY, ALLOWLIST)
    assert plan.for_ioc(tracker).skipped == [YOUR_ADDRESS]
    assert plan.for_ioc(tracker).lookups == [Lookup("rdap", "domain", "track-mail.com")]


def test_a_broken_url_is_not_sent():
    broken = url("https://[not-an-ip/login")
    plan = build_plan([make(broken)], ALL_READY, ALLOWLIST)
    assert plan.for_ioc(broken).skipped == [NOT_PUBLIC_NAME]
    assert plan.lookups == []


# --- services without a key ---------------------------------------------------------------------


def test_a_service_without_a_key_is_off_and_never_planned():
    only_vt = Settings(vt_api_key=KEY)
    plan = build_plan([make(ip("8.8.8.8"), domain("paypa1-login.com"))], only_vt, ALLOWLIST)
    assert {lookup.service for lookup in plan.lookups} == {"virustotal", "rdap"}
    assert plan.services_off == {
        "abuseipdb": "ABUSEIPDB_API_KEY is not set",
        "urlhaus": "ABUSECH_AUTH_KEY is not set",
    }
    assert plan.for_ioc(ip("8.8.8.8")).skipped == []  # the reason is given once, plan-wide


def test_without_virustotal_urls_still_go_to_urlhaus():
    links = [url(f"https://t.paypa1-login.com/c/{n}") for n in range(5)]
    plan = build_plan([make(*links)], Settings(abusech_auth_key=KEY), ALLOWLIST)
    assert plan.count("urlhaus") == 5
    assert plan.count("virustotal") == 0
    assert all(plan.for_ioc(link).skipped == [] for link in links)  # no per-domain limit


def test_no_keys_at_all_leaves_only_rdap():
    plan = build_plan([make(domain("paypa1-login.com"))], Settings(), ALLOWLIST)
    assert plan.lookups == [Lookup("rdap", "domain", "paypa1-login.com")]
    assert plan.for_ioc(domain("paypa1-login.com")).skipped == []


# --- what the test emails can cause ----------------------------------------------------


def test_the_fixtures_only_name_the_real_brands_they_imitate(fixtures):
    """Every other name in the fixtures is .test, example.com/org or a documentation IP.

    The two phishing fixtures show the real brand in a link's visible text, on purpose,
    and those two brands are not in the default allowlist. If a new fixture adds another
    real domain, this test fails, so it cannot slip into a real lookup unnoticed.
    """
    analyses = [analyse_file(path, ALLOWLIST) for path in sorted(fixtures.glob("*.eml"))]
    plan = build_plan(analyses, ALL_READY, ALLOWLIST)
    hosts = {
        urlsplit(lookup.query).hostname if lookup.kind == "url" else lookup.query
        for lookup in plan.lookups
        if lookup.kind != "file"
    }
    assert hosts == {
        "paypal.com",
        "www.paypal.com",
        "login.microsoftonline.com",
        "microsoftonline.com",  # its registration date (RDAP)
    }
    assert plan.count("virustotal") > 0
