"""Wording shared by every renderer, so the terminal, Markdown and HTML say the same thing."""

from __future__ import annotations

from collections.abc import Iterable

from ..report import Answer, EmailReport, FileReport, IOCView, ReasonView, ScoreView
from ..scoring import VERDICT_RANK

# The helpers the Markdown and HTML templates may call (Jinja "globals")
__all__ = [
    "answers",
    "attack",
    "count_iocs",
    "ioc_label",
    "lookup",
    "points",
    "ranked",
    "sender",
    "sender_ip",
    "verdict",
    "verdict_class",
]

# How each IOC kind is named: (one, many)
IOC_LABELS = {
    "url": ("URL", "URLs"),
    "domain": ("domain", "domains"),
    "ip": ("IP", "IPs"),
    "email": ("email address", "email addresses"),
}


def ranked(files: Iterable[FileReport]) -> list[FileReport]:
    """Worst first, for every summary (step 13): highest verdict, then highest score, then
    by name; the files that could not be analysed come last, as there is no verdict.

    sorted() with a key is Java's list.sort(Comparator.comparing(...)); a minus sign
    turns "highest first" into the ascending order sorted() uses.
    """

    def key(file: FileReport) -> tuple[int, int, int, str]:
        if file.verdict is None:
            return (1, 0, 0, file.name)
        return (0, -VERDICT_RANK[file.verdict.verdict], -file.verdict.total, file.name)

    return sorted(files, key=key)


def ioc_label(kind: str) -> str:
    return IOC_LABELS[kind][0]


def count_iocs(iocs: Iterable[IOCView]) -> str:
    """'2 URLs, 4 domains, 1 IP, 3 email addresses'"""
    iocs = list(iocs)
    parts = []
    for kind, (one, many) in IOC_LABELS.items():
        count = sum(1 for ioc in iocs if ioc.kind == kind)
        parts.append(f"{count} {one if count == 1 else many}")
    return ", ".join(parts)


def sender(email: EmailReport) -> str:
    """'PayPal Security <service[@]paypal[.]com>', plus any other From addresses (week 3:
    a second From address is a red flag in itself, so it is always shown)."""
    text = f"{email.from_name} <{email.from_address}>"
    if email.other_from:
        text += " + " + ", ".join(email.other_from)
    return text


def sender_ip(email: EmailReport) -> str:
    """'203[.]0[.]113[.]9 (from Authentication-Results)', or '-' when no header says."""
    if not email.sender_ip:
        return "-"
    note = "" if email.sender_ip_certain else ", less certain"
    return f"{email.sender_ip} (from {email.sender_ip_source}{note})"


def points(reason: ReasonView) -> str:
    """'override', '+25' or '0'"""
    if reason.override:
        return "override"
    return f"+{reason.points}" if reason.points else "0"


def verdict(score: ScoreView) -> str:
    """'MALICIOUS 100/100'"""
    return f"{score.verdict.upper()} {score.total}/100"


def verdict_class(score: ScoreView) -> str:
    """'likely benign' -> 'likely-benign', a name usable as an HTML class"""
    return score.verdict.replace(" ", "-")


def attack(score: ScoreView) -> str:
    """'T1566.002 Phishing: Spearphishing Link', or '' for Likely benign"""
    return ", ".join(f"{tag.id} {tag.name}" for tag in score.attack)


def lookup(ioc: IOCView, enriched: bool) -> str:
    """Without --enrich: would it be looked up. With it: every answer, on one line."""
    if not enriched:
        return "skip (allowlisted)" if ioc.allowlisted else "yes"
    return answers(ioc.reputation)


def answers(lines: Iterable[Answer]) -> str:
    return "; ".join(answer.text for answer in lines) or "-"
