"""Calibration: try new weights on runs already made, without reading any email (week 4).

Step 15 tunes scoring.yaml once, on the gate sets, with genuine and phishing mail side by
side. Re-running analyze for every idea would cost lookups (the cache keeps answers for
hours, not days) and means opening the phishing emails again, so instead:

    analyze SET --stats run.json    also writes one row per file: its score, its verdict,
                                    and each email's findings as rule names and facts
    calibrate LEGIT.json PHISH.json --scoring candidate.yaml
                                    scores those rows again with the candidate, using
                                    scoring.py's own classify() and score_findings()

Because the rows keep each finding's facts (engine counts, AbuseIPDB confidence, ...),
the evidence thresholds can be tried too, not only the points.

What a row holds, and why it is safe to carry from the VM to the Mac: rule names, and
facts that are numbers, true/false or one short lowercase word ("domain", "virustotal").
Anything else in a fact is dropped (and counted), so a future check that broke the facts
rule could still not put a URL, an address or a name into a stats file. No file name, no
detail text, no IOC. The rows are sorted by score, not by name, so not even the order
says which file is which.

A stats file made from a held-out set (analyze --heldout-ok) is refused: tuning on it
would make week 5's blind test not blind. Only results.py (week 5) reads such a file,
with load_stats(path, heldout_ok=True): it reports a run and never changes the scoring.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .models import Finding
from .report import Report
from .scoring import DETECTION_RULES, VERDICT_RANK, Score, ScoringConfig, score_findings

# A fact's word: "domain", "virustotal", "url". Long or odd text is never a fixed word
FACT_WORD = re.compile(r"[a-z][a-z_]{0,31}")
STATS_ROWS_VERSION = 1


class CalibrationError(ValueError):
    """A stats file that cannot be used, with a message saying why and what to do."""


# --- writing: one row per file, for analyze --stats --------------------------------------------


def safe_facts(facts: Mapping[str, Any]) -> tuple[dict[str, Any], int]:
    """(the facts that are numbers, true/false or one fixed word; how many were dropped)."""
    kept: dict[str, Any] = {}
    for key, value in facts.items():
        if not isinstance(key, str) or not FACT_WORD.fullmatch(key):
            continue
        if isinstance(value, bool | int | float) or (
            isinstance(value, str) and FACT_WORD.fullmatch(value)
        ):
            kept[key] = value
    return kept, len(facts) - len(kept)


def stats_rows(report: Report) -> tuple[list[dict[str, Any]], int]:
    """One row per analysed file, highest score first; and how many facts were dropped.

    A row: {"score": 60, "verdict": "suspicious", "emails": [[finding, ...], ...]}, where
    a finding is {"rule": "dmarc_fail"} or {"rule": "vt_flagged", "facts": {...}}. The
    first email is the file's own; the rest were forwarded inside it.
    """
    rows: list[dict[str, Any]] = []
    dropped = 0
    for file in report.files:
        if file.verdict is None:  # could not be analysed: counted in emails_failed
            continue
        emails = []
        for email in file.emails:
            findings = []
            for finding in email.findings:
                facts, lost = safe_facts(finding.facts)
                dropped += lost
                findings.append({"rule": finding.rule, **({"facts": facts} if facts else {})})
            emails.append(findings)
        rows.append(
            {"score": file.verdict.total, "verdict": file.verdict.verdict, "emails": emails}
        )
    rows.sort(key=lambda row: (-row["score"], json.dumps(row, sort_keys=True)))
    return rows, dropped


# --- reading a stats file back ------------------------------------------------------------------


@dataclass(frozen=True)
class Row:
    """One file from a stats file: what it scored then, and its findings per email."""

    score: int
    verdict: str
    emails: tuple[tuple[Finding, ...], ...]


@dataclass(frozen=True)
class StatsFile:
    """A stats file read back. info: everything else it says about the run (emails,
    emails_failed, enriched, heldout_ok, the lookups' counts...), for results.py."""

    path: Path
    scoring_source: str
    scoring_sha256: str
    rows: tuple[Row, ...]
    info: dict[str, Any]


def load_stats(path: Path, *, heldout_ok: bool = False) -> StatsFile:
    """Read a stats file written by analyze --stats. Raises CalibrationError.

    heldout_ok: accept a run of a held-out set (analyze --heldout-ok). Only results.py
    does, because it never tunes anything; calibrate keeps the default and refuses one.
    The * makes it keyword-only: a caller must write heldout_ok=True, and
    load_stats(path, True) is a TypeError. Java has no keyword arguments; the nearest is
    an enum parameter instead of a bare boolean, so a call site says what it means.
    """
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CalibrationError(f"{path}: cannot be read ({type(error).__name__})") from None
    if not isinstance(data, dict) or "emails" not in data:
        raise CalibrationError(f"{path}: not a stats file from phishtriage analyze --stats")
    if data.get("heldout_ok") and not heldout_ok:
        raise CalibrationError(
            f"{path}: made from a held-out set (--heldout-ok). Calibrating on it would make "
            "week 5's test not blind"
        )
    if not isinstance(data.get("files"), list):
        raise CalibrationError(
            f"{path}: has no per-file rows (made before calibrate existed). "
            "Run analyze --stats again to make a new one"
        )
    if (version := data.get("rows_version")) != STATS_ROWS_VERSION:
        raise CalibrationError(
            f"{path}: its rows are version {version!r}, and this PhishTriage reads version "
            f"{STATS_ROWS_VERSION}. Run analyze --stats again with this version"
        )
    scoring = data.get("scoring") if isinstance(data.get("scoring"), dict) else {}
    rows = tuple(_row(path, number, raw) for number, raw in enumerate(data["files"], 1))
    info = {key: value for key, value in data.items() if key != "files"}
    return StatsFile(
        path, str(scoring.get("source", "")), str(scoring.get("sha256", "")), rows, info
    )


def _row(path: Path, number: int, raw: Any) -> Row:
    where = f"{path}: file row {number}"
    if not isinstance(raw, dict):
        raise CalibrationError(f"{where} is not an object")
    score, verdict, emails = raw.get("score"), raw.get("verdict"), raw.get("emails")
    if not isinstance(score, int) or verdict not in VERDICT_RANK or not isinstance(emails, list):
        raise CalibrationError(f"{where} needs a score, a verdict and its emails")
    if not emails:
        raise CalibrationError(f"{where} has no emails")
    parsed = []
    for email in emails:
        if not isinstance(email, list):
            raise CalibrationError(f"{where}: an email must be a list of findings")
        findings = []
        for item in email:
            rule = item.get("rule") if isinstance(item, dict) else None
            facts = item.get("facts", {}) if isinstance(item, dict) else None
            if not isinstance(rule, str) or not isinstance(facts, dict):
                raise CalibrationError(f"{where}: a finding needs a rule name (and facts)")
            if rule not in DETECTION_RULES:
                # scoring would quietly give it 0 points: a renamed rule must not look harmless
                raise CalibrationError(
                    f"{where}: unknown rule {rule!r}. The stats file comes from another version "
                    "of PhishTriage: run analyze --stats again"
                )
            findings.append(Finding(rule, "", dict(facts)))  # a replayed rule: see DETECTION_RULES
        parsed.append(tuple(findings))
    return Row(score, verdict, tuple(parsed))


# --- scoring the rows again ---------------------------------------------------------------------


@dataclass(frozen=True)
class Rescored:
    """One row under the candidate: the file's total and verdict (its worst email), and
    the signals that counted in any of its emails."""

    total: int
    verdict: str
    signals: frozenset[str]


def rescore(row: Row, config: ScoringConfig) -> Rescored:
    """The file's verdict under `config`: each email scored by score_findings(), the file
    judged by its worst email, as analyze does (scoring.worst: the first wins a tie)."""
    scores: list[Score] = [score_findings(email, config) for email in row.emails]
    worst = max(scores, key=lambda score: score.total)
    counted = {r.signal for score in scores for r in score.reasons if not r.note}
    return Rescored(worst.total, worst.verdict, frozenset(counted))


@dataclass
class Half:
    """One side of the comparison: genuine or phishing."""

    name: str
    stats: StatsFile
    rescored: list[Rescored] = field(default_factory=list)

    def measured(self) -> dict[str, int]:
        return _count(row.verdict for row in self.stats.rows)

    def candidate(self) -> dict[str, int]:
        return _count(row.verdict for row in self.rescored)

    def fired(self, signal: str) -> int:
        return sum(signal in row.signals for row in self.rescored)

    def mismatches(self) -> int:
        """Rows whose candidate score differs from the one recorded (0 expected when the
        candidate is the scoring file the run used)."""
        return sum(
            row.score != new.total for row, new in zip(self.stats.rows, self.rescored, strict=True)
        )


def _count(verdicts: Iterable[str]) -> dict[str, int]:
    counts = dict.fromkeys(sorted(VERDICT_RANK, key=VERDICT_RANK.__getitem__), 0)
    for verdict in verdicts:
        counts[verdict] += 1
    return counts


def compare_halves(legit: StatsFile, phish: StatsFile, config: ScoringConfig) -> tuple[Half, Half]:
    """Score both halves again with `config`."""
    halves = (Half("Genuine", legit), Half("Phishing", phish))
    for half in halves:
        half.rescored = [rescore(row, config) for row in half.stats.rows]
    return halves
