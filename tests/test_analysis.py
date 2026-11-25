"""Week 3, step 5: analysis is separate from printing, and gives the same results."""

import pytest

from phishtriage.allowlist import load_allowlist
from phishtriage.analysis import analyse_email, analyse_file, walk
from phishtriage.attachments import check_attachments
from phishtriage.content import check_wording
from phishtriage.headers import run_header_checks
from phishtriage.iocs import extract_iocs
from phishtriage.links import check_hidden_destinations, check_link_text_mismatch
from phishtriage.lookalike import check_sender_domains
from phishtriage.parser import parse_eml

ALLOWLIST = load_allowlist()


def test_analyse_file_runs_every_check(fixtures):
    analysis = analyse_file(fixtures / "phish_paypal_spoof.eml", ALLOWLIST)
    assert analysis.path.name == "phish_paypal_spoof.eml"
    assert analysis.email.from_name == "PayPal Security"
    assert analysis.auth.dmarc == "fail"
    rules = {finding.rule for finding in analysis.findings}
    assert {"dmarc_fail", "link_text_mismatch"} <= rules
    assert {ioc.kind for ioc in analysis.iocs} == {"url", "domain", "ip", "email"}
    assert analysis.forwarded == []


@pytest.mark.parametrize(
    "name",
    [
        "legit_newsletter.eml",
        "phish_paypal_spoof.eml",
        "broken_charset.eml",
        "forwarded_phish.eml",
        "wrapped_links.eml",
        "attachments_phish.eml",
        "phish_microsoft_format.eml",
        "phish_open_redirect.eml",
    ],
)
def test_same_results_as_calling_each_check_directly(fixtures, name):
    """The refactor changed where the checks run, not what they find."""
    email = parse_eml(fixtures / name)
    analysis = analyse_email(email, ALLOWLIST)

    auth, findings, not_written = run_header_checks(email)
    findings += check_sender_domains(email)  # week 4, step 4
    findings += check_link_text_mismatch(email)
    findings += check_hidden_destinations(email)  # week 4, step 5
    findings += check_wording(email)  # week 4, step 6
    findings += check_attachments(email)

    assert analysis.auth == auth
    assert analysis.findings == findings
    assert analysis.not_written == not_written
    assert analysis.iocs == extract_iocs(email, ALLOWLIST)


def test_forwarded_emails_are_analysed_too(fixtures):
    analysis = analyse_file(fixtures / "forwarded_phish.eml", ALLOWLIST)
    assert len(analysis.forwarded) == 1
    inner = analysis.forwarded[0]
    assert inner.email.depth == 1
    assert inner.email.from_name == "Microsoft 365 Admin"
    # The header checks and the link check, exactly as the Week 2 report showed them,
    # plus week 4's lookalike check (the sender is micros0ft-support.test) and wording
    # check ("Your password expires today")
    assert {f.rule for f in inner.findings} == {
        "display_name_spoof",
        "return_path_mismatch",
        "link_text_mismatch",
        "lookalike_sender_domain",
        "urgency_wording",
        "credential_request_wording",
    }
    assert analysis.findings == []  # Nimal's own forward is clean


def test_walk_visits_every_level_in_report_order(fixtures):
    analysis = analyse_file(fixtures / "forwarded_phish.eml", ALLOWLIST)
    levels = list(walk(analysis))
    assert [a.email.depth for a in levels] == [0, 1]
    assert levels[0] is analysis
    assert levels[1] is analysis.forwarded[0]
    plain = analyse_file(fixtures / "legit_newsletter.eml", ALLOWLIST)
    assert list(walk(plain)) == [plain]


# --- Week 4, step 3: the sender IP ---------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "address", "certain"),
    [
        ("phish_microsoft_format.eml", "203.0.113.77", True),
        ("phish_paypal_spoof.eml", "203.0.113.45", True),
        ("attachments_phish.eml", "198.51.100.23", False),
    ],
)
def test_the_analysis_knows_the_sender_ip(fixtures, name, address, certain):
    sender = analyse_file(fixtures / name, ALLOWLIST).sender_ip
    assert sender.address == address
    assert sender.certain is certain


def test_no_sender_ip_without_headers(fixtures):
    assert analyse_file(fixtures / "broken_charset.eml", ALLOWLIST).sender_ip is None


def test_a_forwarded_email_has_its_own_sender_ip(fixtures):
    outer = analyse_file(fixtures / "forwarded_phish.eml", ALLOWLIST)
    assert outer.sender_ip is None
    assert outer.forwarded[0].sender_ip.address == "203.0.113.77"
