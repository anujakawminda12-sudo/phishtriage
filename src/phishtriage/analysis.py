"""Analyse an email without printing anything (week 3, step 5).

Before week 3, cli.py ran the checks and printed the report in one function. Splitting
them lets a folder run work in phases:

    1. analyse every email                     (this module)
    2. look up every IOC from every email      (step 12: one batch, so a domain seen in
                                                30 emails is looked up once, and the most
                                                important lookups go first)
    3. print the reports                       (cli.py; week 4 adds report.py and JSON)

Java comparison: the classic split between a service layer (this module returns plain
objects) and the presentation layer (cli.py turns them into text).

Nothing here touches the network.
"""

from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

from phishtriage.allowlist import Allowlist
from phishtriage.attachments import check_attachments
from phishtriage.content import check_wording
from phishtriage.headers import run_header_checks
from phishtriage.iocs import extract_iocs, find_sender_ip
from phishtriage.links import check_hidden_destinations, check_link_text_mismatch
from phishtriage.lookalike import check_sender_domains
from phishtriage.models import IOC, AuthResults, Finding, ParsedEmail, SenderIP
from phishtriage.parser import parse_eml


@dataclass
class EmailAnalysis:
    """Everything the checks found in one email, ready to be reported.

    email:        the parsed email itself
    auth:         SPF, DKIM and DMARC from the trusted Authentication-Results header
    findings:     every Finding, in report order (no points: scoring is week 4)
    iocs:         every IOC, with allowlisted ones marked
    sender_ip:    the IP the email came from, and how sure that is (week 4, step 3)
    not_written:  names of checks that are not written yet
    forwarded:    one EmailAnalysis per email forwarded inside this one (as attachments)
    """

    email: ParsedEmail
    auth: AuthResults
    findings: list[Finding] = field(default_factory=list)
    iocs: list[IOC] = field(default_factory=list)
    sender_ip: SenderIP | None = None
    not_written: list[str] = field(default_factory=list)
    forwarded: list["EmailAnalysis"] = field(default_factory=list)

    @property
    def path(self) -> Path:
        return self.email.path


def analyse_email(email: ParsedEmail, allowlist: Allowlist) -> EmailAnalysis:
    """Run every check on a parsed email, and on every email forwarded inside it.

    The order of the findings is the order the report has always used: header checks,
    then link checks, then attachment checks. Week 4, step 4: the lookalike sender-domain
    checks come straight after the header checks.
    """
    auth, findings, not_written = run_header_checks(email)
    findings += check_sender_domains(email)
    findings += check_link_text_mismatch(email)
    findings += check_hidden_destinations(email)  # week 4, step 5
    findings += check_wording(email)  # week 4, step 6
    findings += check_attachments(email)
    return EmailAnalysis(
        email=email,
        auth=auth,
        findings=findings,
        iocs=extract_iocs(email, allowlist),
        sender_ip=find_sender_ip(email),
        not_written=not_written,
        # Recursion is safe: the parser stops at MAX_FORWARD_DEPTH levels
        forwarded=[analyse_email(inner, allowlist) for inner in email.forwarded],
    )


def analyse_file(path: Path, allowlist: Allowlist) -> EmailAnalysis:
    """Parse an .eml file and analyse it."""
    return analyse_email(parse_eml(path), allowlist)


def walk(analysis: EmailAnalysis) -> Iterator[EmailAnalysis]:
    """This analysis, then every forwarded one, in the order the report shows them.

        outer.eml -> outer, forwarded 1, (forwarded inside 1), forwarded 2, ...

    A generator (yield) hands back one item at a time (Java: an Iterator whose next()
    is written as a plain loop). Step 6 uses it to collect the IOCs of every level.
    """
    yield analysis
    for inner in analysis.forwarded:
        yield from walk(inner)
