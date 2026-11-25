"""Results of analyze runs, read from their --stats files (week 5). Reads no email.

    phishtriage results GENUINE.json               genuine mail: how many were flagged
    phishtriage results GENUINE.json PHISH.json    also phishing caught, and both side by
                                                   side (the proposal's O6 measures)

calibrate (week 4) tries new scoring on runs already made, so it refuses held-out runs.
results is the other way round: it is FOR the held-out runs, so it never changes the
scoring. It scores a run's rows again only with the scoring file that run used (the
SHA-256 must match), and only for two things:

1. Rebuilt scores: every file's score and verdict are worked out again from its rule
   names and facts alone. They all match when every point comes from a named rule (the
   proposal's O5) and the stats file is the one analyze wrote.
2. "Headers and content only" for an --enrich run: the same rows without the lookups'
   findings (ENRICHMENT_RULES). score_analysis() adds those to an email's own findings
   and changes nothing else, so this is what the run gives without --enrich (a test
   checks it against a real run). One run of a held-out set gives both numbers.

Rates come with an exact 95% range (Clopper-Pearson): with 50 emails, 0 flagged still
allows a true rate of up to 7.1%. The proposal's O6 targets are checked against the rate
itself, and the range is printed beside it so nobody reads more into it than it holds.
A run made without --heldout-ok is labelled NOT blind.
"""

from __future__ import annotations

import math
from collections.abc import Callable
from dataclasses import dataclass
from fractions import Fraction
from pathlib import Path
from typing import Any

from .calibrate import Row, StatsFile, load_stats, rescore
from .scoring import LIKELY_BENIGN, THREAT_INTEL_RULES, VERDICT_RANK, ScoringConfig

# What --enrich adds to an email's findings (enrich/enricher.py). A test reads the
# enricher's code, so a new kind of lookup finding cannot be missed here.
ENRICHMENT_RULES = THREAT_INTEL_RULES | {"domain_new"}

WITH_LOOKUPS = "with lookups"
OFFLINE = "headers and content only"

CONFIDENCE = 0.95
# The proposal's O6 targets, for a labelled set of 50 phishing and 50 genuine emails.
# Fractions, not floats: 5 of 50 is exactly 1/10, so "under 10%" is decided exactly.
FALSE_POSITIVE_TARGET = Fraction(1, 10)  # genuine emails flagged: under 10%
ACCURACY_TARGET = Fraction(85, 100)  # correct verdicts: at least 85%


class ResultsError(ValueError):
    """A stats file that cannot give results, with a message saying why."""


# --- rates and their ranges ---------------------------------------------------------------------


def exact_interval(hits: int, total: int, confidence: float = CONFIDENCE) -> tuple[float, float]:
    """The exact (Clopper-Pearson) range of true rates that fit `hits` of `total`.

    The lower end is the rate under which a result of `hits` or more has a chance of only
    (1 - confidence) / 2; the upper end is the rate under which `hits` or fewer has that
    chance. 0 of 50 gives 0% to 1 - 0.025 ** (1 / 50) = 7.1%. Each end is found by
    bisection on the binomial distribution, so no statistics library is needed.
    """
    if total <= 0 or not 0 <= hits <= total:
        raise ValueError(f"{hits} of {total} is not a rate")
    tail = (1 - confidence) / 2
    low = 0.0 if hits == 0 else _bisect(lambda p: 1 - _at_most(hits - 1, total, p), tail)
    high = 1.0 if hits == total else _bisect(lambda p: 1 - _at_most(hits, total, p), 1 - tail)
    return low, high


def _at_most(k: int, n: int, p: float) -> float:
    """P(X <= k) when X counts hits in n tries, each a hit with chance p (binomial).

    Each term is worked out with logarithms (lgamma(n + 1) is log n!), because n! itself
    is too big for a float when n is in the hundreds.
    """
    if p <= 0.0:
        return 1.0
    if p >= 1.0:
        return 1.0 if k >= n else 0.0
    log_p, log_q = math.log(p), math.log1p(-p)
    total = sum(
        math.exp(
            math.lgamma(n + 1)
            - math.lgamma(i + 1)
            - math.lgamma(n - i + 1)
            + i * log_p
            + (n - i) * log_q
        )
        for i in range(k + 1)
    )
    return min(total, 1.0)


def _bisect(rising: Callable[[float], float], target: float) -> float:
    """The p in 0..1 where rising(p) reaches target; rising must only go up with p.

    Halves the interval 60 times (Java: the same loop as a binary search on doubles), which
    is far closer than the one decimal place the report shows.
    """
    low, high = 0.0, 1.0
    for _ in range(60):
        middle = (low + high) / 2
        if rising(middle) < target:
            low = middle
        else:
            high = middle
    return (low + high) / 2


@dataclass(frozen=True)
class Rate:
    """hits of total, e.g. genuine emails flagged: 2 of 50."""

    hits: int
    total: int

    @property
    def share(self) -> Fraction:
        return Fraction(self.hits, self.total) if self.total else Fraction(0)

    def text(self) -> str:
        """'2 of 50 = 4.0% (95% range 0.5% to 13.7%)', or '0 of 0' with nothing to count."""
        if not self.total:
            return "0 of 0"
        low, high = exact_interval(self.hits, self.total)
        return (
            f"{self.hits} of {self.total} = {float(self.share):.1%} "
            f"({CONFIDENCE:.0%} range {low:.1%} to {high:.1%})"
        )


def meets_false_positive_target(rate: Rate) -> bool:
    """Under 10%. Nothing measured is not "0% flagged", so it never meets the target."""
    return rate.total > 0 and rate.share < FALSE_POSITIVE_TARGET


def meets_accuracy_target(rate: Rate) -> bool:
    """At least 85%. Nothing measured has a share of 0, so it cannot meet this one either."""
    return rate.share >= ACCURACY_TARGET


# --- one run, read two ways -----------------------------------------------------------------------


@dataclass(frozen=True)
class View:
    """One way of reading a run: per file, its verdict, score and the signals that counted.

    label:    WITH_LOOKUPS or OFFLINE
    derived:  True when OFFLINE was worked out from an --enrich run (lookups removed)
    """

    label: str
    derived: bool
    verdicts: tuple[str, ...]
    scores: tuple[int, ...]
    signals: tuple[frozenset[str], ...]

    def counts(self) -> dict[str, int]:
        """Files per verdict, from likely benign to malicious."""
        counts = dict.fromkeys(sorted(VERDICT_RANK, key=VERDICT_RANK.__getitem__), 0)
        for verdict in self.verdicts:
            counts[verdict] += 1
        return counts

    def flagged(self) -> Rate:
        """Files scored suspicious or malicious (the proposal: suspicious counts as flagged)."""
        return Rate(sum(v != LIKELY_BENIGN for v in self.verdicts), len(self.verdicts))

    def fired(self, signal: str, *, flagged_only: bool = False) -> int:
        """Files where `signal` counted (only flagged files, with flagged_only)."""
        return sum(
            signal in found
            for found, verdict in zip(self.signals, self.verdicts, strict=True)
            if not flagged_only or verdict != LIKELY_BENIGN
        )


@dataclass(frozen=True)
class Run:
    """One --stats file, ready to report.

    name:     "Genuine" or "Phishing": what the emails in it are
    views:    as measured first; then OFFLINE worked out from the same rows, for --enrich
    rebuilt:  files whose score and verdict came out the same when worked out again
    """

    name: str
    stats: StatsFile
    views: tuple[View, ...]
    rebuilt: int

    @property
    def files(self) -> int:
        return len(self.stats.rows)

    @property
    def heldout(self) -> bool:
        return self.stats.info.get("heldout_ok") is True

    @property
    def enriched(self) -> bool:
        return self.stats.info.get("enriched") is True

    def view(self, label: str) -> View | None:
        return next((view for view in self.views if view.label == label), None)


def without_lookups(row: Row) -> Row:
    """The row as it would be without --enrich: every lookup finding removed."""
    emails = tuple(
        tuple(finding for finding in email if finding.rule not in ENRICHMENT_RULES)
        for email in row.emails
    )
    return Row(row.score, row.verdict, emails)


def _count(value: Any) -> bool:
    """A count from a stats file: a whole number, 0 or more (True is not a count)."""
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def load_run(name: str, path: Path, config: ScoringConfig) -> Run:
    """Read one stats file, held-out runs included. Raises CalibrationError (a file that
    is not a usable stats file) or ResultsError (one that cannot give honest results)."""
    stats = load_stats(path, heldout_ok=True)
    if stats.scoring_sha256 != config.sha256:
        raise ResultsError(
            f"{path}: the run was scored with {stats.scoring_source or 'an unknown file'} "
            f"(SHA-256 {stats.scoring_sha256[:12] or 'not recorded'}), not with "
            f"{config.source} ({config.sha256[:12]}). results scores rows again only with "
            "the file the run used: give that file with --scoring"
        )
    info = stats.info
    emails, failed = info.get("emails"), info.get("emails_failed")
    if not (_count(emails) and _count(failed) and emails - failed == len(stats.rows)):
        raise ResultsError(
            f"{path}: it has {len(stats.rows)} file rows, but says {emails!r} files of which "
            f"{failed!r} failed. The file is incomplete or was changed"
        )
    enriched = info.get("enriched")
    if not isinstance(enriched, bool):
        raise ResultsError(f"{path}: does not say whether --enrich was used")
    found = {finding.rule for row in stats.rows for email in row.emails for finding in email}
    if not enriched and found & ENRICHMENT_RULES:
        raise ResultsError(
            f"{path}: has lookup findings but says it was made without --enrich. "
            "The file was changed"
        )

    measured = [rescore(row, config) for row in stats.rows]
    rebuilt = sum(
        new.total == row.score and new.verdict == row.verdict
        for row, new in zip(stats.rows, measured, strict=True)
    )
    views = [
        View(
            WITH_LOOKUPS if enriched else OFFLINE,
            False,
            tuple(row.verdict for row in stats.rows),
            tuple(row.score for row in stats.rows),
            tuple(new.signals for new in measured),
        )
    ]
    if enriched:
        offline = [rescore(without_lookups(row), config) for row in stats.rows]
        views.append(
            View(
                OFFLINE,
                True,
                tuple(new.verdict for new in offline),
                tuple(new.total for new in offline),
                tuple(new.signals for new in offline),
            )
        )
    return Run(name, stats, tuple(views), rebuilt)


# --- the lookups of an --enrich run ---------------------------------------------------------------

SERVICE_COUNTS = (
    "cache_hits",
    "api_calls",
    "found",
    "not_found",
    "failed",
    "deferred",
    "unsupported",
    "quota_errors",
)


@dataclass(frozen=True)
class Lookups:
    """What an --enrich run's lookups did, from its stats file.

    services: per service, its planned lookups and SERVICE_COUNTS (enrich/base.py's
              ServiceStats: deferred = not asked, unsupported = no answer possible)
    stopped:  services stopped part-way, and why
    """

    hosts_only: bool
    planned: int
    unanswered: int
    quota_errors: int
    services: dict[str, dict[str, int]]
    stopped: dict[str, str]

    def total(self, count: str) -> int:
        return sum(service[count] for service in self.services.values())

    @property
    def complete(self) -> bool:
        return self.unanswered == 0


def lookups(run: Run) -> Lookups | None:
    """The lookups of an --enrich run (None without --enrich). Raises ResultsError."""
    if not run.enriched:
        return None
    info, where = run.stats.info, run.stats.path
    numbers = {key: info.get(key) for key in ("lookups_planned", "unanswered", "quota_errors")}
    raw_services, stopped = info.get("services"), info.get("stopped")
    if not all(_count(value) for value in numbers.values()) or not (
        isinstance(raw_services, dict) and isinstance(stopped, dict)
    ):
        raise ResultsError(f"{where}: an --enrich run without its lookup counts")
    services: dict[str, dict[str, int]] = {}
    for name, counts in raw_services.items():
        wanted = ("planned", *SERVICE_COUNTS)
        if not isinstance(counts, dict) or not all(_count(counts.get(key)) for key in wanted):
            raise ResultsError(f"{where}: the lookup counts of {name!r} are not whole numbers")
        services[str(name)] = {key: counts[key] for key in wanted}
    return Lookups(
        hosts_only=info.get("hosts_only") is True,
        planned=numbers["lookups_planned"],
        unanswered=numbers["unanswered"],
        quota_errors=numbers["quota_errors"],
        services=services,
        stopped={str(name): str(reason) for name, reason in stopped.items()},
    )


# --- genuine and phishing side by side ------------------------------------------------------------


@dataclass(frozen=True)
class Both:
    """Genuine and phishing in the same view: the proposal's measures.

    Phishing flagged (suspicious or malicious) is caught, genuine flagged is a false
    positive. "Correct" is phishing flagged plus genuine passed as likely benign.
    """

    label: str
    genuine: View
    phishing: View

    def caught(self) -> Rate:  # recall: phishing caught
        return self.phishing.flagged()

    def false_positives(self) -> Rate:  # false positive rate: genuine flagged
        return self.genuine.flagged()

    def precision(self) -> Rate:
        """Of everything flagged, the share that is phishing."""
        caught, false = self.caught().hits, self.false_positives().hits
        return Rate(caught, caught + false)

    def correct(self) -> Rate:
        passed = self.genuine.counts()[LIKELY_BENIGN]
        total = len(self.genuine.verdicts) + len(self.phishing.verdicts)
        return Rate(self.caught().hits + passed, total)


def side_by_side(genuine: Run, phishing: Run) -> list[Both]:
    """A Both for each view the two runs share: WITH_LOOKUPS when both used --enrich, and
    always OFFLINE (an --enrich run is read without its lookups), so a genuine run with
    lookups can still be put next to a phishing run made without them."""
    both = []
    for label in (WITH_LOOKUPS, OFFLINE):
        ours, theirs = genuine.view(label), phishing.view(label)
        if ours is not None and theirs is not None:
            both.append(Both(label, ours, theirs))
    return both
