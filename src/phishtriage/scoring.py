"""Turn findings into points, a score and a verdict (week 4, step 8).

The checks (headers.py, links.py, ...) only say WHAT they found: a Finding has a rule
name and a detail, and no points. This module is the only place that decides what a
finding is worth, and the numbers come from scoring.yaml, so tuning needs no code change.

    load_scoring()                     scoring.yaml -> ScoringConfig (checked when loaded)
    score_findings(findings, config)   -> Score: total (0-100), verdict, reasons, ATT&CK
    score_analysis(analysis, config, enrichment)   one email, with its lookups if any
    score_file(analysis, config, enrichment)       the email and every email inside it

Two layers, so every point can be explained:

1. classify(): each finding gets the rule name it is scored under. For the checks' own
   findings that is the finding's rule. A threat-intel finding (vt_flagged, ...) is only
   a hit; its facts (step 7) decide whether it meets the evidence thresholds in
   scoring.yaml, e.g. "3 engines say malicious". It gets a scoring rule either way, plus
   a note saying why it did not count when it did not ("1 of 92 engines; 3 needed").
2. scoring.yaml groups rules into signals. A signal counts once per email, with its
   points, however many of its findings there are. The score is the sum, capped at 100.

The verdict: 70-100 Malicious, 25-69 Suspicious, 0-24 Likely benign (from scoring.yaml;
Suspicious started at 30 until week 5's calibration).
A known-malware attachment makes it Malicious on its own (the proposal's override).

Security: scoring.yaml is read with yaml.safe_load(), never yaml.load(). Plain yaml.load
can be told by the file to build any Python object, so a crafted file could run code
(Java: the same class of bug as deserialising untrusted objects).
"""

from __future__ import annotations

import difflib
import hashlib
import re
from collections.abc import Iterable
from dataclasses import dataclass
from functools import cached_property
from importlib import resources
from pathlib import Path
from typing import Any

import yaml

from .analysis import EmailAnalysis, walk
from .enrich.enricher import Enrichment
from .models import Finding

BUILT_IN = "built-in scoring.yaml"
MAX_SCORE = 100

MALICIOUS, SUSPICIOUS, LIKELY_BENIGN = "malicious", "suspicious", "likely benign"
# Higher is worse. Step 13 uses the same numbers as exit codes: 0, 1, 2.
VERDICT_RANK = {LIKELY_BENIGN: 0, SUSPICIOUS: 1, MALICIOUS: 2}

ATTACK_NAMES = {
    "T1566": "Phishing",
    "T1566.001": "Phishing: Spearphishing Attachment",
    "T1566.002": "Phishing: Spearphishing Link",
}

# Every rule a check can put on a Finding. A test reads the code itself to keep this
# list complete, so a new check cannot be quietly worth 0.
DETECTION_RULES = frozenset(
    {
        # headers.py
        "spf_fail", "spf_softfail", "dkim_fail", "dkim_none", "dmarc_fail", "dkim_missing",
        "dkim_not_aligned", "no_auth_results", "extra_auth_results", "reply_to_mismatch",
        "return_path_mismatch", "display_name_spoof", "multiple_from_addresses",
        # lookalike.py, links.py, content.py
        "lookalike_sender_domain", "brand_in_sender_domain", "link_text_mismatch",
        "link_text_mismatch_sender", "url_shortener", "open_redirect", "urgency_wording",
        "credential_request_wording",
        # attachments.py
        "attachment_risky_type", "attachment_double_extension", "attachment_type_mismatch",
        "attachment_encrypted_archive",
        # enrich/enricher.py
        "vt_flagged", "urlhaus_listed", "abuseipdb_reported", "domain_new",
    }
)  # fmt: skip
# Threat-intel hits are not scored by their own name, but by what their facts show:
THREAT_INTEL_RULES = frozenset({"vt_flagged", "urlhaus_listed", "abuseipdb_reported"})
EVIDENCE_RULES = frozenset(
    {
        "virustotal_malicious",  # a URL, domain or IP, at or over the threshold
        "virustotal_malicious_file",  # an attachment, at or over the file threshold
        "urlhaus_url_listed",  # this exact URL is listed (online or not)
        "urlhaus_host_listed",  # the host is listed, with a listed URL still online
        "urlhaus_file_listed",  # the attachment is known malware
        "abuseipdb_sender_ip",  # the sender's IP, with enough confidence
    }
)
SCORED_RULES = (DETECTION_RULES - THREAT_INTEL_RULES) | EVIDENCE_RULES

ATTACK_TAGS = frozenset({"T1566.001", "T1566.002"})
SIGNAL_NAME = re.compile(r"^[a-z][a-z0-9_]*$")
SHARED_PLATFORM_NOTE = "on a shared platform, where a verdict on the whole site says little"

BASIS_TEXT = {
    "not_enriched": "headers and content only: not enriched (--enrich adds reputation lookups)",
    "complete": "headers, content and reputation lookups",
    "partial": "headers, content and some reputation lookups ({unanswered} got no answer)",
}


class ScoringError(ValueError):
    """scoring.yaml cannot be used. The message says which file, where and why."""


# --- the configuration ------------------------------------------------------------------------


@dataclass(frozen=True)
class Signal:
    """One row of scoring.yaml (Java: a record).

    points:   added once when any of its findings counts (0 for an override signal)
    override: True if one counted finding makes the verdict Malicious on its own
    attack:   the MITRE ATT&CK sub-technique it is evidence for, or ""
    """

    name: str
    label: str
    points: int
    rules: tuple[str, ...]
    override: bool = False
    attack: str = ""


@dataclass(frozen=True)
class Evidence:
    """When a threat-intel finding counts (the numbers from scoring.yaml)."""

    virustotal_min_malicious: int = 3
    virustotal_file_min_malicious: int = 5
    abuseipdb_min_score: int = 50
    urlhaus_host_min_online: int = 1


@dataclass(frozen=True)
class ScoringConfig:
    """A checked scoring.yaml."""

    malicious: int
    suspicious: int
    evidence: Evidence
    signals: tuple[Signal, ...]
    source: str = "scoring.yaml"
    sha256: str = ""  # of the file's text: a report names the exact weights it used (step 9)

    @cached_property
    def by_rule(self) -> dict[str, Signal]:
        """rule name -> its signal. Worked out once, on first use (cached_property)."""
        return {rule: signal for signal in self.signals for rule in signal.rules}

    def verdict(self, total: int) -> str:
        if total >= self.malicious:
            return MALICIOUS
        return SUSPICIOUS if total >= self.suspicious else LIKELY_BENIGN


def load_scoring(path: Path | None = None) -> ScoringConfig:
    """Read and check scoring.yaml: the built-in one, or the file at path (step 13).

    The built-in file is package data, read with importlib.resources like allowlist.txt,
    so it is found however PhishTriage is installed (Java: getResourceAsStream).
    """
    if path is None:
        text = resources.files("phishtriage").joinpath("scoring.yaml").read_text("utf-8")
        return parse_scoring(text, source=BUILT_IN)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as error:
        raise ScoringError(f"{path}: cannot be read ({error.strerror or error})") from error
    return parse_scoring(text, source=str(path))


def parse_scoring(text: str, source: str = "scoring.yaml") -> ScoringConfig:
    """Check the YAML text and build a ScoringConfig. Any problem raises ScoringError."""
    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as error:
        first_line = str(error).splitlines()[0] if str(error) else "unreadable"
        raise ScoringError(f"{source}: not valid YAML ({first_line})") from error

    top = _mapping(raw, source, required={"verdicts", "signals"}, optional={"evidence", "version"})
    verdicts = _mapping(
        top["verdicts"], f"{source}: verdicts", required={"malicious", "suspicious"}
    )
    malicious = _whole(verdicts["malicious"], f"{source}: verdicts.malicious", 1, MAX_SCORE)
    suspicious = _whole(verdicts["suspicious"], f"{source}: verdicts.suspicious", 1, MAX_SCORE)
    if suspicious >= malicious:
        raise ScoringError(
            f"{source}: verdicts.suspicious ({suspicious}) must be lower than "
            f"verdicts.malicious ({malicious})"
        )
    evidence = _evidence(top.get("evidence") or {}, source)
    signals = _signals(top["signals"], source)
    sha256 = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return ScoringConfig(malicious, suspicious, evidence, signals, source, sha256)


def _evidence(raw: Any, source: str) -> Evidence:
    where = f"{source}: evidence"
    names = {"virustotal_min_malicious", "virustotal_file_min_malicious"}
    names |= {"abuseipdb_min_score", "urlhaus_host_min_online"}
    given = _mapping(raw, where, optional=names)
    lowest = {"urlhaus_host_min_online": 0}  # 0 is allowed: it counts every listed host
    values = {
        name: _whole(value, f"{where}.{name}", lowest.get(name, 1), MAX_SCORE)
        for name, value in given.items()
    }
    return Evidence(**values)


def _signals(raw: Any, source: str) -> tuple[Signal, ...]:
    where = f"{source}: signals"
    if not isinstance(raw, dict) or not raw:
        raise ScoringError(f"{where}: must be a mapping of named signals")
    signals: list[Signal] = []
    owner: dict[str, str] = {}  # rule -> the signal that has it
    for name, body in raw.items():
        here = f"{where}.{name}"
        if not isinstance(name, str) or not SIGNAL_NAME.match(name):
            raise ScoringError(f"{here}: a signal name is lower case letters, digits and _")
        fields = _mapping(
            body, here, required={"label", "rules"}, optional={"points", "override", "attack"}
        )
        label = fields["label"]
        if not isinstance(label, str) or not label.strip():
            raise ScoringError(f"{here}.label: must be some text")
        if ("points" in fields) == ("override" in fields):
            raise ScoringError(f"{here}: give it either points or override, not both or neither")
        if "override" in fields and fields["override"] != MALICIOUS:
            raise ScoringError(f"{here}.override: the only override is 'malicious'")
        points = _whole(fields.get("points", 0), f"{here}.points", 0, MAX_SCORE)
        attack = fields.get("attack", "")
        if attack and attack not in ATTACK_TAGS:
            raise ScoringError(f"{here}.attack: must be one of {', '.join(sorted(ATTACK_TAGS))}")
        rules = fields["rules"]
        if not isinstance(rules, list) or not rules:
            raise ScoringError(f"{here}.rules: must be a list of at least one rule name")
        for rule in rules:
            if not isinstance(rule, str) or rule not in SCORED_RULES:
                raise ScoringError(f"{here}.rules: unknown rule {rule!r}{_did_you_mean(rule)}")
            if rule in owner:
                raise ScoringError(f"{here}.rules: {rule} is already in {owner[rule]}")
            owner[rule] = name
        signals.append(
            Signal(name, label.strip(), points, tuple(rules), "override" in fields, attack)
        )

    if missing := sorted(SCORED_RULES - set(owner)):
        raise ScoringError(
            f"{where}: no signal has {', '.join(missing)}. Every rule needs one, so nothing "
            "is worth 0 points without a decision: add it to a signal (points: 0 is fine)"
        )
    return tuple(signals)


def _mapping(
    raw: Any, where: str, required: Iterable[str] = (), optional: Iterable[str] = ()
) -> dict[str, Any]:
    """Check that raw is a mapping with these keys and no others (a typo is an error)."""
    required, allowed = set(required), set(required) | set(optional)
    if not isinstance(raw, dict):
        raise ScoringError(f"{where}: must be a mapping of names to values")
    if missing := sorted(required - set(raw)):
        raise ScoringError(f"{where}: missing {', '.join(missing)}")
    if unknown := sorted(str(key) for key in raw if key not in allowed):
        raise ScoringError(
            f"{where}: unknown key {unknown[0]!r} (expected {', '.join(sorted(allowed))})"
        )
    return raw


def _whole(value: Any, where: str, low: int, high: int) -> int:
    """A whole number from low to high. True and False are not numbers here, although
    Python counts bool as a kind of int (True == 1), so they are refused by name."""
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise ScoringError(f"{where}: must be a whole number from {low} to {high}, not {value!r}")
    return value


def _did_you_mean(rule: Any) -> str:
    """' (did you mean dmarc_fail?)' for a near miss, else ''."""
    if not isinstance(rule, str):
        return ""
    close = difflib.get_close_matches(rule, sorted(SCORED_RULES), n=1)
    return f" (did you mean {close[0]}?)" if close else ""


# --- scoring ----------------------------------------------------------------------------------


@dataclass(frozen=True)
class Reason:
    """One line of the report's "reasons": a signal, and what it added to the score.

    points:   what it added (0 if nothing counted, or if the signal is worth 0)
    rules:    the findings behind it, by rule name, e.g. ("vt_flagged",)
    details:  those findings' details, as the report shows them
    note:     why it added nothing, e.g. "1 of 92 engines say malicious; 3 needed"
    override: True if it made the verdict Malicious on its own
    """

    signal: str
    label: str
    points: int
    rules: tuple[str, ...]
    details: tuple[str, ...]
    note: str = ""
    override: bool = False


@dataclass(frozen=True)
class Score:
    """The verdict for one email.

    total:      0-100 (100 when an override decided it)
    verdict:    "malicious", "suspicious" or "likely benign"
    reasons:    what counted first, highest points first; then what did not count
    attack:     MITRE ATT&CK techniques, e.g. ("T1566.002",); empty for Likely benign
    basis:      "not_enriched", "complete" or "partial": what the score could use
    unanswered: with "partial", how many of this email's lookups got no answer
    """

    total: int
    verdict: str
    reasons: tuple[Reason, ...]
    attack: tuple[str, ...]
    basis: str = "not_enriched"
    unanswered: int = 0

    @property
    def rank(self) -> int:
        return VERDICT_RANK[self.verdict]

    @property
    def basis_text(self) -> str:
        return BASIS_TEXT[self.basis].format(unanswered=self.unanswered)


def classify(finding: Finding, evidence: Evidence) -> tuple[str, str]:
    """(the rule it is scored under, why it does not count or "" if it does).

    The checks' own findings count as they are. Threat-intel hits are judged by their
    facts against the evidence thresholds:

        vt_flagged, file, 7 of 70 malicious          -> virustotal_malicious_file, counts
        vt_flagged, domain, 1 of 92 malicious        -> virustotal_malicious, "1 of 92 ..."
        urlhaus_listed, host, 0 URLs online          -> urlhaus_host_listed, "0 of its 1 ..."
        abuseipdb_reported, not the sender's IP      -> abuseipdb_sender_ip, "not the IP ..."
    """
    rule, facts = finding.rule, finding.facts
    if rule == "vt_flagged":
        malicious, engines = int(facts.get("malicious", 0)), int(facts.get("engines", 0))
        said = f"{malicious} of {engines} engines say malicious"
        if facts.get("kind") == "file":
            need = evidence.virustotal_file_min_malicious
            return (
                "virustotal_malicious_file",
                "" if malicious >= need else f"{said}; {need} needed",
            )
        need = evidence.virustotal_min_malicious
        if malicious < need:
            return "virustotal_malicious", f"{said}; {need} needed"
        if facts.get("shared_platform") and facts.get("kind") != "url":
            return "virustotal_malicious", SHARED_PLATFORM_NOTE
        return "virustotal_malicious", ""
    if rule == "urlhaus_listed":
        kind = facts.get("kind")
        if kind == "file":
            return "urlhaus_file_listed", ""
        if kind == "url":
            return "urlhaus_url_listed", ""
        if facts.get("shared_platform"):
            return "urlhaus_host_listed", SHARED_PLATFORM_NOTE
        online, listed = int(facts.get("online_urls", 0)), int(facts.get("listed_urls", 0))
        need = evidence.urlhaus_host_min_online
        if online < need:
            return (
                "urlhaus_host_listed",
                f"{online} of its {listed} listed URLs online; {need} needed",
            )
        return "urlhaus_host_listed", ""
    if rule == "abuseipdb_reported":
        if not facts.get("sender_ip"):
            return "abuseipdb_sender_ip", "not the IP this email came from"
        if facts.get("whitelisted"):
            return "abuseipdb_sender_ip", "on AbuseIPDB's own list of known-good IPs"
        score, need = int(facts.get("score", 0)), evidence.abuseipdb_min_score
        if score < need:
            return "abuseipdb_sender_ip", f"confidence {score}%; {need}% needed"
        return "abuseipdb_sender_ip", ""
    return rule, ""


def score_findings(
    findings: Iterable[Finding],
    config: ScoringConfig,
    basis: str = "not_enriched",
    unanswered: int = 0,
) -> Score:
    """Add up one email's findings. Each signal counts once."""
    grouped: dict[str, list[tuple[Finding, str]]] = {}
    unknown: list[Finding] = []
    for finding in findings:
        rule, note = classify(finding, config.evidence)
        signal = config.by_rule.get(rule)
        if signal is None:  # a rule scoring.yaml does not know: shown, worth 0
            unknown.append(finding)
        else:
            grouped.setdefault(signal.name, []).append((finding, note))

    reasons: list[Reason] = []
    for signal in config.signals:  # in scoring.yaml's order, so ties read the same way
        items = grouped.get(signal.name)
        if not items:
            continue
        counted = [finding for finding, note in items if not note]
        shown = counted or [finding for finding, _ in items]
        rules = tuple(dict.fromkeys(finding.rule for finding in shown))
        details = tuple(dict.fromkeys(finding.detail for finding in shown))
        if not counted:
            note = "; ".join(dict.fromkeys(note for _, note in items))
            reasons.append(Reason(signal.name, signal.label, 0, rules, details, note))
        elif signal.override:
            reasons.append(Reason(signal.name, signal.label, 0, rules, details, override=True))
        else:  # counted; a 0-point signal is shown for information (its label says why)
            reasons.append(Reason(signal.name, signal.label, signal.points, rules, details))
    for finding in unknown:
        note = "not in scoring.yaml, so worth 0 points"
        reasons.append(
            Reason(finding.rule, finding.rule, 0, (finding.rule,), (finding.detail,), note)
        )

    override = any(reason.override for reason in reasons)
    total = MAX_SCORE if override else min(MAX_SCORE, sum(r.points for r in reasons))
    verdict = config.verdict(total)  # an override's 100 is always Malicious (limits <= 100)
    # what counted first (an override, then the most points), then the rest; sorted() is
    # stable, so equal reasons keep scoring.yaml's order
    reasons.sort(key=lambda reason: (not reason.override, -reason.points, bool(reason.note)))
    return Score(
        total=total,
        verdict=verdict,
        reasons=tuple(reasons),
        attack=_attack(reasons, config, verdict),
        basis=basis,
        unanswered=unanswered,
    )


def _attack(reasons: list[Reason], config: ScoringConfig, verdict: str) -> tuple[str, ...]:
    """MITRE ATT&CK techniques for a Suspicious or Malicious email.

    T1566.001 when an attachment signal counted, T1566.002 when a link signal counted.
    Phishing that shows neither (only sender and wording signs) is tagged with the parent
    technique, T1566 Phishing, rather than a sub-technique the evidence does not show.
    """
    if verdict == LIKELY_BENIGN:
        return ()
    signals = {signal.name: signal for signal in config.signals}
    tags = {
        signals[reason.signal].attack
        for reason in reasons
        if reason.signal in signals and (reason.points or reason.override)
    }
    tags.discard("")
    return tuple(sorted(tags)) or ("T1566",)


def score_analysis(
    analysis: EmailAnalysis, config: ScoringConfig, enrichment: Enrichment | None = None
) -> Score:
    """Score one email (not the emails forwarded inside it), with its lookups if any.

    The basis says what the score could use, so the report can be honest about gaps:
    no --enrich, or a dry run: "not_enriched"; some lookups failed: "partial".
    """
    findings = list(analysis.findings)
    if enrichment is None or enrichment.dry_run:
        return score_findings(findings, config)
    findings += enrichment.findings_for(analysis)
    unanswered = enrichment.unanswered_for(analysis)
    basis = "partial" if unanswered else "complete"
    return score_findings(findings, config, basis, unanswered)


def score_file(
    analysis: EmailAnalysis, config: ScoringConfig, enrichment: Enrichment | None = None
) -> list[tuple[EmailAnalysis, Score]]:
    """Score the email and every email forwarded inside it, in report order."""
    return [(each, score_analysis(each, config, enrichment)) for each in walk(analysis)]


def worst[T](scored: list[tuple[T, Score]]) -> tuple[T, Score]:
    """The pair that decides the file's verdict: the one with the highest score. A user
    who forwards a phish as an attachment sends a harmless email around a dangerous one,
    and the file is the phish.

    [T] makes it generic (Python 3.12+; Java: <T> Pair<T, Score> worst(List<Pair<T,
    Score>>)): the CLI pairs scores with EmailAnalysis objects, report.py with names.

    The highest score always has the highest verdict too, since the verdict comes from the
    score (an override is 100). On a tie the first wins (the outer email): max() returns
    the first of equal items.
    """
    return max(scored, key=lambda pair: pair[1].total)
