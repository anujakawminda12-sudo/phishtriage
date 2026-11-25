"""The report model: everything a report shows, as plain data (week 4, step 9).

The terminal (step 10), Markdown and HTML (step 11) and JSON (step 12) reports are all
printed from one Report, so they cannot disagree, and these rules are applied once, here:

1. Your addresses are removed. Every recipient of every email in the run, plus
   PHISHTRIAGE_MY_ADDRESSES, becomes REDACTED in every form privacy.AddressRedactor
   knows (plain, percent-encoded, base64, hex, hashed). Reports get pasted into tickets
   and chats: they must not say who received the phish.
2. Nothing can be clicked. IOC values are defanged as before. All other outside text
   (subjects, names, finding details, the services' answers) goes through defang_text(),
   which defangs the links, addresses, domains and IPs inside it and leaves words alone.
3. Nothing can control a terminal or hide text: display.visible() writes control and
   layout characters out as their codes (see display.py).

The order is always: redact, then visible, then defang (Cleaner). Redaction first,
because a defanged "me[@]gmail[.]com" no longer matches the address. visible() before
defanging, because an ESC character inside "evil.test" is written out as text that leaves
a new "domain" behind, and that one must be defanged too.

Not done here: escaping for one format (Rich markup, Markdown, HTML). That is each
renderer's job, because "[bold]" is harmless in HTML and "<b>" is harmless in a terminal.

Java comparison: immutable DTOs (records) built by an assembler, kept apart from the
domain objects (EmailAnalysis) and from the views (the renderers).
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from . import __version__
from .analysis import EmailAnalysis
from .display import visible
from .domains import registered_domain
from .enrich.enricher import SERVICE_NAMES, Enrichment, notable
from .enrich.models import DEFERRED, FAILED, FOUND, NOT_FOUND, UNSUPPORTED, LookupResult
from .enrich.plan import TargetPlan
from .iocs import defang, defang_text
from .models import IOC, Attachment, AuthResults, Finding
from .privacy import AddressRedactor, addresses_to_hide
from .scoring import ATTACK_NAMES, Score, ScoringConfig, score_analysis, worst

TOOL = "PhishTriage"


class Cleaner:
    """Applies the three rules to outside text. One per run, shared by every file in it.

    redacted: the pieces of text that had an address removed, each once. Only how many
    is ever reported; the set lives in memory for this run and is never written out.
    """

    def __init__(self, redactor: AddressRedactor | None = None) -> None:
        self.redactor = redactor or AddressRedactor(())
        self.redacted: set[str] = set()

    def _redact(self, value: str) -> str:
        result = self.redactor.redact(value)
        if result.changed:
            self.redacted.add(value)
        return result.value

    def text(self, value: str) -> str:
        """Free text: a subject, a name, a finding's detail, a service's answer."""
        return defang_text(visible(self._redact(value)))

    def ioc(self, value: str) -> str:
        """An IOC value: every dot defanged, as the IOC table has done since week 2."""
        return defang(visible(self._redact(value)))

    def all(self, values: Iterable[str]) -> tuple[str, ...]:
        return tuple(self.text(value) for value in values)


# --- the model --------------------------------------------------------------------------------
# frozen=True: built once, then only read (Java: records). Lists are stored as tuples, the
# immutable kind of list, so no renderer can change what another one will print.


@dataclass(frozen=True)
class AttackTag:
    id: str  # "T1566.002"
    name: str  # "Phishing: Spearphishing Link"


@dataclass(frozen=True)
class ReasonView:
    """One line of "Reasons": a signal from scoring.yaml and what it added."""

    signal: str
    label: str
    points: int
    rules: tuple[str, ...]
    details: tuple[str, ...]
    note: str = ""  # why it added nothing, e.g. "1 of 92 engines say malicious; 3 needed"
    override: bool = False  # it made the verdict Malicious on its own


@dataclass(frozen=True)
class ScoreView:
    """An email's verdict, or a whole file's (the worst email in it)."""

    verdict: str  # "malicious", "suspicious" or "likely benign"
    total: int  # 0-100
    attack: tuple[AttackTag, ...]
    basis: str  # "not_enriched", "complete" or "partial"
    basis_text: str  # the same, as a sentence
    unanswered: int  # with "partial": lookups that got no answer
    reasons: tuple[ReasonView, ...]


@dataclass(frozen=True)
class Answer:
    """One line of reputation: a service's answer, a domain's age, or why not asked."""

    text: str
    flagged: bool = False  # this answer became a finding
    skipped: bool = False  # a reason the value was not looked up
    answered: bool = False  # the service really answered: found, or did not know it


@dataclass(frozen=True)
class IOCView:
    kind: str  # "url", "domain", "ip" or "email"
    value: str  # defanged
    seen: int  # how many times it is in the email
    sources: tuple[str, ...]  # where, e.g. ("text", "html:a[href]")
    allowlisted: bool  # not looked up (still listed: allowlisted is not "safe")
    group: str  # URLs: the registered domain, defanged, to group many URLs; else ""
    looked_up: bool | None  # with --enrich: was any lookup planned; None without
    reputation: tuple[Answer, ...]  # with --enrich: one line per answer


@dataclass(frozen=True)
class AttachmentView:
    name: str
    declared_type: str
    real_type: str  # from the content (libmagic); "" if unknown
    size: int
    md5: str
    sha1: str
    sha256: str
    members: tuple[str, ...]  # the names inside a ZIP
    encrypted: bool  # a password-protected ZIP
    reputation: tuple[Answer, ...]


@dataclass(frozen=True)
class AuthView:
    source: str  # "from mx.google.com", "no trusted header", ...
    found: bool
    spf: str
    dkim: str
    dmarc: str
    compauth: str  # Microsoft's own verdict, "unknown" when its servers wrote none
    compauth_reason: str


@dataclass(frozen=True)
class FindingView:
    rule: str
    detail: str
    facts: dict[str, Any]  # step 7's numbers (numbers, true/false and fixed words only)


@dataclass(frozen=True)
class EmailReport:
    """One email: the file itself, or one forwarded inside it."""

    where: str  # "" for the file itself; "1", "1 > 2" for forwarded emails
    level: int  # 0 for the file itself, 1 inside it, 2 inside that, ...
    from_name: str
    from_address: str
    other_from: tuple[str, ...]  # a second From address is a red flag in itself
    reply_to: tuple[str, ...]
    return_path: str
    subject: str
    date: str
    message_id: str  # to search other mailboxes for the same email
    hops: int  # Received headers
    sender_ip: str  # defanged; "" if no header says
    sender_ip_source: str
    sender_ip_certain: bool
    auth: AuthView
    score: ScoreView
    attachments: tuple[AttachmentView, ...]
    iocs: tuple[IOCView, ...]
    findings: tuple[FindingView, ...]
    forwarded: int  # how many emails are forwarded inside this one
    defects: tuple[str, ...]  # parsing notes
    not_written: tuple[str, ...]


@dataclass(frozen=True)
class FileReport:
    """One .eml file: its verdict and every email in it, in report order."""

    name: str  # the file name only: a full path would show your user name
    verdict: ScoreView | None  # the worst email's; None when the file could not be read
    decided_by: str  # "" when the file's own email decides, else that email's "where"
    emails: tuple[EmailReport, ...]
    error: str = ""  # why the file could not be analysed


@dataclass(frozen=True)
class Report:
    """One run: every file, plus what is needed to repeat or trust the result."""

    tool: str
    version: str
    generated_at: str  # UTC, ISO 8601
    scoring_source: str  # "built-in scoring.yaml", or the file name given
    scoring_sha256: str  # the exact weights used (step 15 freezes them)
    enriched: bool
    redacted: int  # how many pieces of text had your address removed
    files: tuple[FileReport, ...]


# --- building it ------------------------------------------------------------------------------


def build_report(
    analyses: Iterable[EmailAnalysis],
    config: ScoringConfig,
    *,
    enrichment: Enrichment | None = None,
    my_addresses: Iterable[str] = (),
    failed: Iterable[tuple[Path, str]] = (),
    now: datetime | None = None,
) -> Report:
    """The report for a run: analysed files in the order given, then the failed ones.

    The "*" makes every argument after it keyword-only (Java has no such thing): a call
    must say my_addresses=[...], so a list of addresses can never land in enrichment.

    my_addresses: PHISHTRIAGE_MY_ADDRESSES. Every recipient of every email in the run is
    hidden as well, batch-wide like the lookup plan: a link in one email can carry the
    address of a colleague who received another email in the same folder.
    """
    analyses = list(analyses)
    hidden = {address.strip().lower() for address in my_addresses if "@" in address}
    for analysis in analyses:
        hidden |= addresses_to_hide(analysis.email)  # walks forwarded emails itself
    cleaner = Cleaner(AddressRedactor(hidden))
    lookups = enrichment if enrichment is not None and not enrichment.dry_run else None

    files: list[FileReport] = []
    for analysis in analyses:
        try:
            files.append(file_report(analysis, config, lookups, cleaner))
        except Exception as error:  # one broken file must not stop the batch: record it
            name = cleaner.text(analysis.path.name)
            text = cleaner.text(f"the report could not be built: {error!r}")
            files.append(FileReport(name, None, "", (), error=text))
    for path, error in failed:
        name = cleaner.text(Path(path).name)
        files.append(FileReport(name, None, "", (), error=cleaner.text(error)))
    moment = (now or datetime.now(UTC)).astimezone(UTC)
    return Report(
        tool=TOOL,
        version=__version__,
        generated_at=moment.strftime("%Y-%m-%dT%H:%M:%SZ"),
        scoring_source=Path(config.source).name,
        scoring_sha256=config.sha256,
        enriched=lookups is not None,
        redacted=len(cleaner.redacted),
        files=tuple(files),
    )


def file_report(
    analysis: EmailAnalysis,
    config: ScoringConfig,
    enrichment: Enrichment | None,
    cleaner: Cleaner,
) -> FileReport:
    """One file: each email scored on its own, then the worst one decides the file."""
    emails: list[EmailReport] = []
    scores: list[tuple[str, ScoreView]] = []
    raw: list[tuple[str, Score]] = []
    for where, each in numbered(analysis):
        score = score_analysis(each, config, enrichment)
        view = score_view(score, cleaner)
        emails.append(email_report(each, where, view, enrichment, cleaner))
        scores.append((where, view))
        raw.append((where, score))
    decided_by, _ = worst(raw)
    file_score = dict(scores)[decided_by]
    return FileReport(cleaner.text(analysis.path.name), file_score, decided_by, tuple(emails))


def numbered(analysis: EmailAnalysis, where: str = "") -> Iterator[tuple[str, EmailAnalysis]]:
    """The email, then every email forwarded inside it, each with its place:
    "" for the file itself, "1" for the first forwarded email, "1 > 2" inside that."""
    yield where, analysis
    for number, inner in enumerate(analysis.forwarded, start=1):
        yield from numbered(inner, f"{where} > {number}" if where else str(number))


def score_view(score: Score, cleaner: Cleaner) -> ScoreView:
    reasons = tuple(
        ReasonView(
            signal=reason.signal,
            label=cleaner.text(reason.label),  # from scoring.yaml, which a user can edit
            points=reason.points,
            rules=reason.rules,
            details=cleaner.all(reason.details),
            note=cleaner.text(reason.note),
            override=reason.override,
        )
        for reason in score.reasons
    )
    return ScoreView(
        verdict=score.verdict,
        total=score.total,
        attack=tuple(AttackTag(tag, ATTACK_NAMES[tag]) for tag in score.attack),
        basis=score.basis,
        basis_text=score.basis_text,
        unanswered=score.unanswered,
        reasons=reasons,
    )


def email_report(
    analysis: EmailAnalysis,
    where: str,
    score: ScoreView,
    enrichment: Enrichment | None,
    cleaner: Cleaner,
) -> EmailReport:
    email, sender = analysis.email, analysis.sender_ip
    findings = list(analysis.findings)
    if enrichment is not None:
        findings += enrichment.findings_for(analysis)
    return EmailReport(
        where=where,
        level=email.depth,
        from_name=cleaner.text(email.from_name),
        from_address=cleaner.text(email.from_addr),
        other_from=cleaner.all(email.from_all[1:]),
        reply_to=cleaner.all(email.reply_to_all),  # reply_to is always the first of these
        return_path=cleaner.text(email.return_path),
        subject=cleaner.text(email.subject),
        date=cleaner.text(email.date),
        message_id=cleaner.text(email.message_id),
        hops=len(email.received),
        sender_ip=cleaner.ioc(sender.address) if sender else "",
        sender_ip_source=sender.source if sender else "",
        sender_ip_certain=sender.certain if sender else False,
        auth=auth_view(analysis.auth, cleaner),
        score=score,
        attachments=tuple(attachment_view(att, enrichment, cleaner) for att in email.attachments),
        iocs=tuple(ioc_view(ioc, enrichment, cleaner) for ioc in analysis.iocs),
        findings=tuple(finding_view(finding, cleaner) for finding in findings),
        forwarded=len(email.forwarded),
        defects=cleaner.all(sorted(set(email.defects))),
        not_written=tuple(analysis.not_written),
    )


def auth_view(auth: AuthResults, cleaner: Cleaner) -> AuthView:
    return AuthView(
        source=cleaner.text(auth_source(auth)),
        found=auth.found,
        spf=cleaner.text(auth.spf),
        dkim=cleaner.text(auth.dkim),
        dmarc=cleaner.text(auth.dmarc),
        compauth=cleaner.text(auth.compauth),
        compauth_reason=cleaner.text(auth.compauth_reason),
    )


def auth_source(auth: AuthResults) -> str:
    """Which header the SPF/DKIM/DMARC results come from."""
    if not auth.found:
        return "no trusted header"
    if auth.authserv_id is None:  # "spf=pass (sender IP is ...) ...": Microsoft's format
        return "top header, Microsoft's format with no server name"
    return f"from {auth.authserv_id}"


def finding_view(finding: Finding, cleaner: Cleaner) -> FindingView:
    # Facts should only hold numbers and fixed words, but they are cleaned anyway: a
    # future check that broke that rule would otherwise put a live link in every report
    facts = {
        key: cleaner.text(value) if isinstance(value, str) else value
        for key, value in finding.facts.items()
    }
    return FindingView(finding.rule, cleaner.text(finding.detail), facts)


def ioc_view(ioc: IOC, enrichment: Enrichment | None, cleaner: Cleaner) -> IOCView:
    group = ""
    if ioc.kind == "url":
        group = cleaner.ioc(registered_domain(_hostname(ioc.value)) or ioc.value)
    looked_up: bool | None = None
    reputation: tuple[Answer, ...] = ()
    if enrichment is not None:
        target = enrichment.target(ioc)
        looked_up = bool(target.lookups)
        reputation = answers(enrichment, target, cleaner, ioc)
    return IOCView(
        kind=ioc.kind,
        value=cleaner.ioc(ioc.value),
        seen=ioc.count,
        sources=cleaner.all(ioc.sources),
        allowlisted=ioc.allowlisted,
        group=group,
        looked_up=looked_up,
        reputation=reputation,
    )


def attachment_view(
    att: Attachment, enrichment: Enrichment | None, cleaner: Cleaner
) -> AttachmentView:
    reputation: tuple[Answer, ...] = ()
    if enrichment is not None:
        reputation = answers(enrichment, enrichment.plan.for_file(att.sha256), cleaner)
    return AttachmentView(
        name=cleaner.text(att.filename),
        declared_type=cleaner.text(att.content_type),
        real_type=cleaner.text(att.detected_type),
        size=att.size,
        md5=att.md5,
        sha1=att.sha1,
        sha256=att.sha256,
        members=cleaner.all(att.archive_members),
        encrypted=att.encrypted,
        reputation=reputation,
    )


def answers(
    enrichment: Enrichment, target: TargetPlan, cleaner: Cleaner, ioc: IOC | None = None
) -> tuple[Answer, ...]:
    """One line per service answer, then the domain's age, then why anything was not asked."""
    lines: list[Answer] = []
    age = enrichment.domain_age(ioc) if ioc is not None else None
    for result in enrichment.answers(target):
        service = result.lookup.service
        text = f"{SERVICE_NAMES.get(service, service)}: {answer_text(result)}"
        if service == "rdap" and age is not None and age[2] == "RDAP":
            text += f" ({age[1]} days ago)"
        lines.append(
            Answer(
                cleaner.text(text),
                flagged=notable(result) is not None,
                answered=result.status in (FOUND, NOT_FOUND),
            )
        )
    if age is not None and age[2] != "RDAP":
        lines.append(
            Answer(cleaner.text(f"Age: registered {age[0]}, {age[1]} days ago ({age[2]})"))
        )
    for reason in target.skipped:
        lines.append(Answer(cleaner.text(f"not looked up: {reason}"), skipped=True))
    return tuple(lines)


def answer_text(result: LookupResult) -> str:
    """'6 of 94 engines say malicious', 'failed (timed out after 3 tries)', ..."""
    if result.status == FAILED:
        return f"failed ({result.error})"
    if result.status == DEFERRED:
        return f"not asked ({result.error})"
    if result.status == UNSUPPORTED:
        return f"no answer possible ({result.error})"
    return result.summary or result.status


def _hostname(url: str) -> str:
    """The host of a URL, or "" for one Python cannot split (a broken IPv6 literal)."""
    try:
        return urlsplit(url).hostname or ""
    except ValueError:
        return ""
