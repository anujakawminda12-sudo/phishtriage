"""Tests for results: rates, ranges and the proposal's targets from --stats runs (week 5)."""

from __future__ import annotations

import json
import re
from datetime import date, timedelta
from importlib import resources
from pathlib import Path

import pytest
from conftest import FIXTURES
from rich.console import Console
from test_scoring import DYNAMIC_SITES, finding_calls

from phishtriage import cli
from phishtriage.calibrate import CalibrationError, Row, load_stats
from phishtriage.models import Finding
from phishtriage.results import (
    ACCURACY_TARGET,
    ENRICHMENT_RULES,
    FALSE_POSITIVE_TARGET,
    OFFLINE,
    WITH_LOOKUPS,
    Both,
    Rate,
    ResultsError,
    View,
    _at_most,
    exact_interval,
    load_run,
    lookups,
    meets_accuracy_target,
    meets_false_positive_target,
    side_by_side,
    without_lookups,
)
from phishtriage.scoring import load_scoring, parse_scoring

BAR = chr(0x2502)  # the line between table cells; written as a number to keep this file ASCII
HEADER_BAR = chr(0x2503)  # the heavier line Rich draws between header cells
GENUINE = ("legit_newsletter.eml", "wrapped_links.eml", "broken_charset.eml")
# The built-in file's SHA-256, read from the file: test_scoring.py pins the frozen value once
SHA = load_scoring().sha256


@pytest.fixture(autouse=True)
def wide(monkeypatch):
    monkeypatch.setattr(cli, "console", Console(width=200))


def run(*args) -> int:
    return cli.main([str(arg) for arg in args])


def lines(out: str) -> list[str]:
    return [line.strip() for line in out.splitlines()]


def cells(out: str, first: str) -> list[str]:
    """The cells of the table row whose first cell is `first`."""
    for line in out.splitlines():
        parts = [part.strip() for part in line.replace(HEADER_BAR, BAR).split(BAR)[1:-1]]
        if parts and parts[0] == first:
            return parts
    raise AssertionError(f"no table row starts with {first!r}")


@pytest.fixture
def genuine_run(tmp_path) -> Path:
    """Stats of 3 genuine fixtures, made without --heldout-ok: NOT blind."""
    folder = tmp_path / "genuine"
    folder.mkdir()
    for name in GENUINE:
        (folder / name).write_bytes((FIXTURES / name).read_bytes())
    stats = tmp_path / "genuine.json"
    assert run("analyze", folder, "--stats", stats, "--json") == 0
    return stats


@pytest.fixture
def phishing_run(tmp_path) -> Path:
    """Stats of all 8 fixtures, made with --heldout-ok, as the week 5 runs are."""
    stats = tmp_path / "phishing.json"
    assert run("analyze", FIXTURES, "--heldout-ok", "--stats", stats, "--json") == 2
    return stats


def stats_file(tmp_path, rows, name="hand.json", **info) -> Path:
    """A stats file written by hand: these rows, and counts that agree with them."""
    data = {
        "phishtriage": "0.1.0",
        "analysed_on": "2026-11-24",
        "emails": len(rows),
        "emails_failed": 0,
        "heldout_skipped": 0,
        "scoring": {"source": "built-in scoring.yaml", "sha256": SHA},
        "enriched": False,
        "heldout_ok": False,
        "rows_version": 1,
        "files": rows,
    } | info
    path = tmp_path / name
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def row(*rules, score=0, verdict="likely benign") -> dict:
    return {"score": score, "verdict": verdict, "emails": [[{"rule": r} for r in rules]]}


# --- exact ranges -------------------------------------------------------------------------------


def test_nothing_flagged_still_allows_a_rate_above_zero():
    """0 of n: the upper end has a closed form, 1 - 0.025 ** (1 / n)."""
    low, high = exact_interval(0, 50)
    assert low == 0.0
    assert high == pytest.approx(1 - 0.025 ** (1 / 50), abs=1e-9)
    assert round(high, 3) == 0.071


def test_everything_flagged_mirrors_it():
    low, high = exact_interval(50, 50)
    assert low == pytest.approx(0.025 ** (1 / 50), abs=1e-9)
    assert high == 1.0


@pytest.mark.parametrize(
    ("hits", "total", "low", "high"),
    [  # published Clopper-Pearson values (e.g. any statistics table, or R's binom.test)
        (1, 10, 0.0025, 0.4450),
        (5, 10, 0.1871, 0.8129),
        (9, 10, 0.5550, 0.9975),  # one short of all: its upper end is not 100%
        (2, 50, 0.0049, 0.1371),
        (5, 8, 0.2449, 0.9148),
    ],
)
def test_known_ranges(hits, total, low, high):
    found = exact_interval(hits, total)
    assert found == (pytest.approx(low, abs=5e-5), pytest.approx(high, abs=5e-5))


@pytest.mark.parametrize(("hits", "total"), [(0, 7), (3, 7), (7, 7), (10, 2000), (1990, 2000)])
def test_a_range_is_the_mirror_of_its_opposite(hits, total):
    """k of n and (n - k) of n are mirror images; also works when n! is too big for a float."""
    low, high = exact_interval(hits, total)
    other_low, other_high = exact_interval(total - hits, total)
    assert low == pytest.approx(1 - other_high, abs=1e-9)
    assert high == pytest.approx(1 - other_low, abs=1e-9)
    assert low <= hits / total <= high


def test_a_lower_confidence_gives_a_narrower_range():
    wide_low, wide_high = exact_interval(2, 50)
    narrow_low, narrow_high = exact_interval(2, 50, confidence=0.80)
    assert wide_low < narrow_low < narrow_high < wide_high


@pytest.mark.parametrize(("hits", "total"), [(1, 0), (0, 0), (-1, 5), (6, 5)])
def test_not_a_rate(hits, total):
    with pytest.raises(ValueError, match="is not a rate"):
        exact_interval(hits, total)


def test_the_binomial_at_its_edges():
    assert _at_most(0, 5, 0.0) == 1.0
    assert _at_most(4, 5, 1.0) == 0.0
    assert _at_most(5, 5, 1.0) == 1.0
    assert _at_most(5, 5, 0.3) == 1.0  # every outcome: the sum is capped at exactly 1
    assert _at_most(0, 2, 0.5) == pytest.approx(0.25)
    assert _at_most(1, 2, 0.5) == pytest.approx(0.75)


# --- rates and targets --------------------------------------------------------------------------


def test_a_rate_as_text():
    assert Rate(2, 50).text() == "2 of 50 = 4.0% (95% range 0.5% to 13.7%)"
    assert Rate(0, 0).text() == "0 of 0"
    assert Rate(0, 0).share == 0


@pytest.mark.parametrize(("hits", "met"), [(0, True), (4, True), (5, False), (6, False)])
def test_the_false_positive_target_is_under_ten_percent(hits, met):
    assert FALSE_POSITIVE_TARGET == pytest.approx(0.10)
    assert meets_false_positive_target(Rate(hits, 50)) is met


@pytest.mark.parametrize(("hits", "met"), [(100, True), (85, True), (84, False), (0, False)])
def test_the_accuracy_target_is_at_least_85_percent(hits, met):
    assert ACCURACY_TARGET == pytest.approx(0.85)
    assert meets_accuracy_target(Rate(hits, 100)) is met


def test_nothing_measured_meets_no_target():
    assert not meets_false_positive_target(Rate(0, 0))
    assert not meets_accuracy_target(Rate(0, 0))


# --- views and both halves ----------------------------------------------------------------------


def view(*verdicts, signals=None, label=OFFLINE, derived=False) -> View:
    found = signals or [frozenset()] * len(verdicts)
    return View(label, derived, tuple(verdicts), tuple(0 for _ in verdicts), tuple(found))


def test_a_view_counts_verdicts_and_flagged_files():
    seen = view(
        "likely benign",
        "suspicious",
        "malicious",
        "likely benign",
        signals=[frozenset({"a"}), frozenset({"a"}), frozenset({"b"}), frozenset({"a", "b"})],
    )
    assert seen.counts() == {"likely benign": 2, "suspicious": 1, "malicious": 1}
    assert list(seen.counts()) == ["likely benign", "suspicious", "malicious"]
    assert seen.flagged() == Rate(2, 4)
    assert (seen.fired("a"), seen.fired("b"), seen.fired("c")) == (3, 2, 0)
    assert (seen.fired("a", flagged_only=True), seen.fired("b", flagged_only=True)) == (1, 1)


def test_both_halves():
    genuine = view("likely benign", "likely benign", "likely benign", "suspicious")
    phishing = view("malicious", "suspicious", "likely benign")
    both = Both(OFFLINE, genuine, phishing)
    assert both.caught() == Rate(2, 3)
    assert both.false_positives() == Rate(1, 4)
    assert both.precision() == Rate(2, 3)  # 2 phishing and 1 genuine flagged
    assert both.correct() == Rate(5, 7)  # 2 caught + 3 genuine passed


def test_precision_with_nothing_flagged():
    both = Both(OFFLINE, view("likely benign"), view("likely benign"))
    assert both.precision() == Rate(0, 0)


# --- reading a run ------------------------------------------------------------------------------


def test_a_run_without_lookups(genuine_run):
    loaded = load_run("Genuine", genuine_run, load_scoring())
    assert (loaded.name, loaded.files, loaded.rebuilt) == ("Genuine", 3, 3)
    assert not loaded.heldout and not loaded.enriched
    assert [v.label for v in loaded.views] == [OFFLINE]
    assert loaded.views[0].derived is False
    assert loaded.view(OFFLINE) is loaded.views[0] and loaded.view(WITH_LOOKUPS) is None
    assert lookups(loaded) is None


def test_a_held_out_run_is_read_but_still_refused_by_calibrate(phishing_run):
    loaded = load_run("Phishing", phishing_run, load_scoring())
    assert loaded.heldout and loaded.files == 8 and loaded.rebuilt == 8
    assert loaded.views[0].scores == (100, 85, 60, 50, 35, 0, 0, 0)
    assert loaded.views[0].verdicts[:2] == ("malicious", "malicious")
    assert "dmarc_fail" in loaded.views[0].signals[0]
    with pytest.raises(CalibrationError, match="held-out set"):
        load_stats(phishing_run)


def test_load_stats_keeps_the_run_counts_and_needs_the_flag_by_name(phishing_run):
    stats = load_stats(phishing_run, heldout_ok=True)
    assert stats.info["heldout_ok"] is True and stats.info["emails"] == 8
    assert "files" not in stats.info and stats.info["rows_version"] == 1
    with pytest.raises(TypeError):
        load_stats(phishing_run, True)  # keyword-only: a bare True cannot mean "held-out ok"


def test_a_run_scored_with_another_file_is_refused(genuine_run, tmp_path):
    other = tmp_path / "other.yaml"
    text = resources.files("phishtriage").joinpath("scoring.yaml").read_text("utf-8")
    changed = text.replace("suspicious: 25", "suspicious: 40")
    assert changed != text  # a replace that finds nothing would quietly test nothing
    other.write_text(changed, encoding="utf-8")
    config = load_scoring(other)
    expected = re.escape(f"scored with built-in scoring.yaml (SHA-256 {SHA[:12]})")
    with pytest.raises(ResultsError, match=expected):
        load_run("Genuine", genuine_run, config)
    with pytest.raises(ResultsError, match="give that file with --scoring"):
        load_run("Genuine", genuine_run, config)


def test_a_run_without_a_recorded_scoring_file(tmp_path):
    path = stats_file(tmp_path, [row()], scoring={})
    with pytest.raises(ResultsError, match=r"an unknown file \(SHA-256 not recorded\)"):
        load_run("Genuine", path, load_scoring())


@pytest.mark.parametrize(
    "info",
    [
        {"emails": 2},
        {"emails_failed": 1},
        {"emails": True},
        {"emails_failed": -1, "emails": 0},
        {"emails": "1"},
        {"emails_failed": None},
    ],
)
def test_counts_that_disagree_with_the_rows(tmp_path, info):
    path = stats_file(tmp_path, [row()], **info)
    with pytest.raises(ResultsError, match="has 1 file rows, but says .* was changed"):
        load_run("Genuine", path, load_scoring())


def test_failed_files_are_counted_apart_from_the_rows(tmp_path):
    path = stats_file(tmp_path, [row()], emails=3, emails_failed=2)
    assert load_run("Genuine", path, load_scoring()).files == 1


@pytest.mark.parametrize("enriched", [None, "yes", 1])
def test_a_run_must_say_whether_it_used_lookups(tmp_path, enriched):
    path = stats_file(tmp_path, [row()], enriched=enriched)
    with pytest.raises(ResultsError, match="does not say whether --enrich was used"):
        load_run("Genuine", path, load_scoring())


@pytest.mark.parametrize("rule", sorted(ENRICHMENT_RULES))
def test_lookup_findings_in_a_run_without_lookups(tmp_path, rule):
    path = stats_file(tmp_path, [row("dmarc_fail", rule)])
    with pytest.raises(ResultsError, match="has lookup findings but says it was made without"):
        load_run("Genuine", path, load_scoring())


def test_a_changed_score_is_noticed(tmp_path):
    right = row("dmarc_fail", score=25, verdict="suspicious")  # a DMARC fail alone: 25
    wrong_score = row("dmarc_fail", score=27, verdict="suspicious")  # right verdict only
    wrong_verdict = row(score=0, verdict="malicious")  # right score only
    rows = [right, wrong_score, wrong_verdict]
    path = stats_file(tmp_path, rows)
    loaded = load_run("Genuine", path, load_scoring())
    assert loaded.rebuilt == 1  # each wrong row is wrong in one way only, so both are checked
    # the results are what analyze recorded, not what the check worked out again
    assert loaded.views[0].scores == (25, 27, 0)
    assert loaded.views[0].verdicts == ("suspicious", "suspicious", "malicious")


def test_without_lookups_keeps_everything_else():
    email = (Finding("dmarc_fail", ""), Finding("vt_flagged", ""), Finding("domain_new", ""))
    forwarded = (Finding("abuseipdb_reported", ""), Finding("urlhaus_listed", ""))
    kept = without_lookups(Row(60, "suspicious", (email, forwarded)))
    assert kept.score == 60 and kept.verdict == "suspicious"
    assert [[f.rule for f in each] for each in kept.emails] == [["dmarc_fail"], []]


def test_enrichment_rules_are_every_rule_the_enricher_can_make():
    made = {
        rule.value
        for where, _, rule in finding_calls()
        if where.startswith("enrich/") and getattr(rule, "value", None)
    }
    made |= DYNAMIC_SITES[("enrich/enricher.py", "findings_for")]
    assert made == ENRICHMENT_RULES


# --- an --enrich run read without its lookups ---------------------------------------------------


# Fixtures with nothing to look up (reserved or allowlisted names only). The others hold
# real domains the fake services do not answer, and would wait for VirusTotal's 4 a minute.
NO_LOOKUPS = (
    "broken_charset.eml",
    "legit_newsletter.eml",
    "phish_microsoft_format.eml",
    "phish_open_redirect.eml",
    "wrapped_links.eml",
)


@pytest.fixture
def both_ways(tmp_path, monkeypatch, phish_email, fake_apis) -> tuple[Path, Path]:
    """5 fixtures and the lookup test email, analysed with and without --enrich.

    The fake answers make every kind of lookup finding: 5 VirusTotal engines, a URLhaus
    URL online, an AbuseIPDB report and a domain registered 3 days ago.
    """
    for name in ("VT_API_KEY", "ABUSEIPDB_API_KEY", "ABUSECH_AUTH_KEY"):
        monkeypatch.setenv(name, "k" * 64)
    monkeypatch.setenv("PHISHTRIAGE_CACHE", str(tmp_path / "cache.sqlite3"))
    created = (date.today() - timedelta(days=3)).isoformat()
    fake_apis(created=f"{created}T00:00:00Z", vt_engines=5)
    folder = tmp_path / "mixed"
    folder.mkdir()
    for path in [*(FIXTURES / name for name in NO_LOOKUPS), phish_email]:
        (folder / path.name).write_bytes(path.read_bytes())
    enriched, offline = tmp_path / "enriched.json", tmp_path / "offline.json"
    assert run("analyze", folder, "--enrich", "--stats", enriched, "--json") == 2
    assert run("analyze", folder, "--stats", offline, "--json") == 2
    return enriched, offline


def test_an_enriched_run_without_its_lookups_is_the_run_without_enrich(both_ways):
    enriched, offline = both_ways
    config = load_scoring()
    with_lookups, without = load_run("P", enriched, config), load_run("P", offline, config)
    found = {f.rule for r in with_lookups.stats.rows for email in r.emails for f in email}
    assert ENRICHMENT_RULES <= found  # the fake answers made every kind of lookup finding
    assert with_lookups.enriched and with_lookups.rebuilt == with_lookups.files == 6
    assert [v.label for v in with_lookups.views] == [WITH_LOOKUPS, OFFLINE]
    assert [v.derived for v in with_lookups.views] == [False, True]
    worked_out, measured = with_lookups.views[1], without.views[0]
    # the rows are sorted by score, so compare as sorted lists, not file by file
    assert sorted(zip(worked_out.scores, worked_out.verdicts, strict=True)) == sorted(
        zip(measured.scores, measured.verdicts, strict=True)
    )

    def rules(rows):
        return sorted(json.dumps([[f.rule for f in e] for e in r.emails]) for r in rows)

    assert rules(map(without_lookups, with_lookups.stats.rows)) == rules(without.stats.rows)
    # and the lookups did change something: the test email scores higher with them
    assert sum(with_lookups.views[0].scores) > sum(worked_out.scores)
    assert any("flagged_link_or_domain" in found for found in with_lookups.views[0].signals)
    assert not any("flagged_link_or_domain" in found for found in worked_out.signals)


def test_the_lookups_of_an_enriched_run(both_ways):
    enriched, _ = both_ways
    loaded = load_run("P", enriched, load_scoring())
    counts = lookups(loaded)
    assert counts is not None and counts.complete and counts.unanswered == 0
    assert counts.planned == json.loads(enriched.read_text())["lookups_planned"] > 0
    assert counts.hosts_only is False and counts.quota_errors == 0 and counts.stopped == {}
    assert set(counts.services) == {"virustotal", "urlhaus", "abuseipdb", "rdap"}
    assert counts.total("api_calls") == sum(s["api_calls"] for s in counts.services.values())
    assert counts.total("api_calls") > 0 and counts.total("cache_hits") == 0
    assert set(counts.services["virustotal"]) == {
        "planned",
        "cache_hits",
        "api_calls",
        "found",
        "not_found",
        "failed",
        "deferred",
        "unsupported",
        "quota_errors",
    }


def enriched_file(tmp_path, **changes) -> Path:
    service = dict.fromkeys(
        (
            "planned",
            "cache_hits",
            "api_calls",
            "found",
            "not_found",
            "failed",
            "deferred",
            "unsupported",
            "quota_errors",
        ),
        1,
    )
    info = {
        "enriched": True,
        "hosts_only": True,
        "lookups_planned": 4,
        "unanswered": 1,
        "quota_errors": 0,
        "services": {"virustotal": service | {"waited": 1.5, "retries": 0}},
        "stopped": {"virustotal": "daily budget used"},
    } | changes
    return stats_file(tmp_path, [row()], **info)


def test_lookup_counts_read_by_hand(tmp_path):
    counts = lookups(load_run("G", enriched_file(tmp_path), load_scoring()))
    assert counts is not None
    assert (counts.hosts_only, counts.planned, counts.unanswered) == (True, 4, 1)
    assert not counts.complete
    assert counts.stopped == {"virustotal": "daily budget used"}
    assert "waited" not in counts.services["virustotal"]


@pytest.mark.parametrize(
    "changes",
    [
        {"lookups_planned": None},
        {"unanswered": -1},
        {"quota_errors": "0"},
        {"services": []},
        {"stopped": None},
    ],
)
def test_an_enriched_run_without_its_lookup_counts(tmp_path, changes):
    loaded = load_run("G", enriched_file(tmp_path, **changes), load_scoring())
    with pytest.raises(ResultsError, match="an --enrich run without its lookup counts"):
        lookups(loaded)


@pytest.mark.parametrize("bad", [None, 1.5, -1, True])
@pytest.mark.parametrize("key", ["planned", "api_calls", "quota_errors"])
def test_service_counts_must_be_whole_numbers(tmp_path, key, bad):
    path = enriched_file(tmp_path)
    data = json.loads(path.read_text())
    data["services"]["virustotal"][key] = bad
    path.write_text(json.dumps(data))
    with pytest.raises(ResultsError, match="lookup counts of 'virustotal' are not whole"):
        lookups(load_run("G", path, load_scoring()))


def test_a_service_that_is_not_an_object(tmp_path):
    path = enriched_file(tmp_path, services={"virustotal": 3})
    with pytest.raises(ResultsError, match="lookup counts of 'virustotal'"):
        lookups(load_run("G", path, load_scoring()))


# --- side by side ------------------------------------------------------------------------------


def test_side_by_side_uses_the_views_both_runs_have(genuine_run, phishing_run, both_ways):
    config = load_scoring()
    plain_g, plain_p = load_run("G", genuine_run, config), load_run("P", phishing_run, config)
    enriched = load_run("P", both_ways[0], config)
    assert [b.label for b in side_by_side(plain_g, plain_p)] == [OFFLINE]
    mixed = side_by_side(enriched, plain_p)  # a genuine run with lookups, phishing without
    assert [b.label for b in mixed] == [OFFLINE]
    assert mixed[0].genuine.derived and not mixed[0].phishing.derived
    assert [b.label for b in side_by_side(enriched, enriched)] == [WITH_LOOKUPS, OFFLINE]


# --- the command --------------------------------------------------------------------------------


def test_the_command_with_one_run(genuine_run, capsys):
    capsys.readouterr()
    assert run("results", genuine_run) == 0
    out = capsys.readouterr().out
    assert lines(out)[:8] == [
        "Results from --stats files only: no email is opened and the scoring is not changed.",
        f"Scoring: built-in scoring.yaml (SHA-256 {SHA[:12]})",
        "",
        f"Genuine: {genuine_run}",
        "NOT blind: not a held-out run (made without --heldout-ok)",
        f"Analysed on {date.today().isoformat()} by PhishTriage 0.1.0, without --enrich",
        "3 files analysed, 0 failed (no verdict), 0 held-out skipped",
        "Scores rebuilt from their rule names alone: 3 of 3 match",
    ]
    assert cells(out, OFFLINE) == [OFFLINE, "3", "0", "0"]
    assert (
        "Flagged, headers and content only: 0 of 3 = 0.0% (95% range 0.0% to 70.8%). "
        "Target under 10% (proposal O6): met"
    ) in lines(out)
    assert "Highest scores, headers and content only: 0, 0, 0" in lines(out)
    assert "Signals in the flagged files" not in out and "Phishing" not in out
    assert cells(out, "authentication_unknown") == ["authentication_unknown", "0", "1"]


def test_the_command_with_both_runs(genuine_run, phishing_run, capsys):
    capsys.readouterr()
    assert run("results", genuine_run, phishing_run) == 0
    out = capsys.readouterr().out
    assert f"Phishing: {phishing_run}" in lines(out)
    assert (
        "Held-out run (--heldout-ok): blind if this set was analysed only once, with the "
        "scoring frozen before"
    ) in lines(out)
    assert (
        "Caught, headers and content only: 5 of 8 = 62.5% (95% range 24.5% to 91.5%); malicious 2"
    ) in lines(out)
    assert "Lowest scores, headers and content only: 0, 0, 0, 35, 50, 60, 85, 100" in lines(out)
    assert (
        "Genuine and phishing side by side, headers and content only "
        "(NOT blind: not both held-out runs)"
    ) in lines(out)
    assert cells(out, "Genuine") == ["Genuine", "3", "0", "0"]
    assert cells(out, "Phishing") == ["Phishing", "3", "3", "2"]
    assert (
        "Correct verdicts: 8 of 11 = 72.7% (95% range 39.0% to 94.0%). "
        "Target at least 85% (proposal O6): NOT met"
    ) in lines(out)
    assert "Phishing caught (recall): 5 of 8 = 62.5% (95% range 24.5% to 91.5%)" in lines(out)
    assert (
        "Flagged that is phishing (precision): 5 of 5 = 100.0% (95% range 47.8% to 100.0%)"
    ) in lines(out)
    assert (
        "Genuine flagged (false positive rate): 0 of 3 = 0.0% (95% range 0.0% to 70.8%). "
        "Target under 10% (proposal O6): met"
    ) in lines(out)
    header = cells(out, "Signal")
    assert header == [
        "Signal",
        "Points",
        "Genuine, headers and content only",
        "Phishing, headers and content only",
    ]
    assert cells(out, "dmarc_fail") == ["dmarc_fail", "25", "0", "2"]
    assert "worked out from" not in out


def test_both_held_out_runs_are_not_called_not_blind(phishing_run, capsys):
    capsys.readouterr()
    assert run("results", phishing_run, phishing_run) == 0
    out = capsys.readouterr().out
    assert "Genuine and phishing side by side, headers and content only" in lines(out)
    assert "NOT blind" not in out


def test_flagged_genuine_files_show_their_signals(phishing_run, capsys):
    """The fixtures read as if they were genuine: 5 of 8 flagged, so the target is missed."""
    capsys.readouterr()
    assert run("results", phishing_run) == 0
    out = capsys.readouterr().out
    assert (
        "Flagged, headers and content only: 5 of 8 = 62.5% (95% range 24.5% to 91.5%). "
        "Target under 10% (proposal O6): NOT met"
    ) in lines(out)
    assert "Highest scores, headers and content only: 100, 85, 60, 50, 35, 0, 0, 0" in lines(out)
    # the line is longer than the console, so Rich wraps it: read the text with the
    # wrapping undone (a first version of this test read only the first part, and missed
    # a mutant that counted every file instead of the flagged ones)
    text = " ".join(out.split())
    start = text.index("Signals in the flagged files, headers and content only: ")
    signals = text[start : text.index(" Signals: files where", start)]
    assert signals == (
        "Signals in the flagged files, headers and content only: double_extension 1, "
        "dmarc_fail 2, lookalike_sender 3, risky_attachment 2, brand_in_sender_domain 1, "
        "link_text_mismatch 2, reply_to_mismatch 1, display_name_spoof 3, spf_fail 2, "
        "dkim_problem 2, hidden_destination 1, pressure_wording 3, return_path_mismatch 2, "
        "extra_auth_results 1"
    )  # no authentication_unknown: it counted only in a likely benign file
    assert cells(out, "authentication_unknown") == ["authentication_unknown", "0", "1"]


def test_the_command_with_an_enriched_run(both_ways, phishing_run, capsys):
    enriched, _ = both_ways
    capsys.readouterr()
    assert run("results", enriched, phishing_run) == 0
    out = capsys.readouterr().out
    assert "Analysed on" in out and ", with --enrich" in out and "--hosts-only" not in out
    assert cells(out, "VirusTotal")[0] == "VirusTotal" and cells(out, "RDAP")[0] == "RDAP"
    assert "Lookups complete: every planned lookup got an answer; 0 quota errors (HTTP 429)" in (
        lines(out)
    )
    calls = sum(s["api_calls"] for s in json.loads(enriched.read_text())["services"].values())
    assert f"API calls: {calls} for 6 files = {calls / 6:.1f} a file" in lines(out)
    assert any(line.startswith("From the cache: 0 of ") and "(0%)" in line for line in lines(out))
    assert cells(out, WITH_LOOKUPS)[0] == WITH_LOOKUPS
    worked_out = f"{OFFLINE} (worked out from the same run)"
    assert cells(out, worked_out)[0] == worked_out
    assert any(line.startswith(f"Flagged, {worked_out}: ") for line in lines(out))
    assert "Genuine: worked out from its --enrich run, without the lookups' findings" in lines(out)
    assert "Phishing: worked out from" not in out
    assert "Genuine, with lookups" in cells(out, "Signal")
    assert cells(out, "flagged_link_or_domain")[1:3] == ["35", "1"]


def test_a_partial_enriched_run(tmp_path, capsys):
    path = enriched_file(tmp_path)
    capsys.readouterr()
    assert run("results", path) == 0
    out = capsys.readouterr().out
    assert ", with --enrich --hosts-only" in out
    assert "Lookups partial: 1 of 4 got no answer; 0 quota errors (HTTP 429)" in lines(out)
    assert "API calls: 1 for 1 files = 1.0 a file" in lines(out)
    assert "From the cache: 1 of 4 planned lookups (25%)" in lines(out)
    assert "VirusTotal stopped: daily budget used" in lines(out)
    assert cells(out, "VirusTotal") == ["VirusTotal", *["1"] * 9]
    assert "No signal counted in any file." in lines(out)


def test_an_enriched_run_with_no_lookups_planned(tmp_path, capsys):
    path = enriched_file(tmp_path, lookups_planned=0, unanswered=0, services={}, stopped={})
    capsys.readouterr()
    assert run("results", path) == 0
    out = capsys.readouterr().out
    assert "From the cache: 0 of 0 planned lookups" in lines(out)
    assert "Lookups complete: every planned lookup got an answer; 0 quota errors (HTTP 429)" in (
        lines(out)
    )


def test_a_run_of_no_files(tmp_path, capsys):
    path = enriched_file(
        tmp_path, emails=0, files=[], lookups_planned=0, unanswered=0, services={}, stopped={}
    )
    capsys.readouterr()
    assert run("results", path) == 0
    out = capsys.readouterr().out
    assert "API calls: 0 for 0 files" in lines(out)
    assert "Flagged, with lookups: 0 of 0. Target under 10% (proposal O6): NOT met" in lines(out)
    assert "Highest scores, with lookups: -" in lines(out)


def test_a_signal_that_decides_alone_shows_malicious_as_its_points(tmp_path, capsys):
    known = {"rule": "vt_flagged", "facts": {"kind": "file", "malicious": 7, "engines": 70}}
    malware = {"score": 100, "verdict": "malicious", "emails": [[known]]}
    path = enriched_file(tmp_path, files=[malware], unanswered=0, stopped={})
    capsys.readouterr()
    assert run("results", path) == 0
    out = capsys.readouterr().out
    assert cells(out, "known_malware_attachment") == [
        "known_malware_attachment",
        "malicious",
        "1",
        "0",
    ]
    assert "Scores rebuilt from their rule names alone: 1 of 1 match" in lines(out)


def test_a_changed_score_is_reported(tmp_path, capsys):
    path = stats_file(tmp_path, [row("dmarc_fail", score=7)])
    capsys.readouterr()
    assert run("results", path) == 0
    out = " ".join(capsys.readouterr().out.split())
    assert (
        "Scores rebuilt from their rule names alone: only 0 of 1 match. The stats file was "
        "changed or comes from another version."
    ) in out


def test_values_from_the_file_are_escaped(tmp_path, capsys):
    path = stats_file(tmp_path, [row()], analysed_on="\x1b[2Jtoday", phishtriage="[red]x[/]")
    capsys.readouterr()
    assert run("results", path) == 0
    out = capsys.readouterr().out
    assert "\x1b" not in out
    assert "Analysed on \\x1b[2Jtoday by PhishTriage [red]x[/], without --enrich" in lines(out)


def test_problems_are_exit_1(genuine_run, tmp_path, capsys):
    broken = stats_file(tmp_path, [row()], emails=5)
    assert run("results", broken) == 1
    assert "has 1 file rows, but says 5 files" in capsys.readouterr().out
    other = tmp_path / "other.yaml"
    other.write_text("version: 1\n", encoding="utf-8")
    assert run("results", genuine_run, "--scoring", other) == 1
    old = tmp_path / "old.json"
    old.write_text('{"emails": 1}')
    assert run("results", genuine_run, old) == 1
    assert "has no per-file rows" in capsys.readouterr().out
    bad_lookups = enriched_file(tmp_path, services=[])
    assert run("results", bad_lookups) == 1
    assert "without its lookup counts" in capsys.readouterr().out


def test_another_scoring_file_that_the_run_used(tmp_path, capsys):
    text = resources.files("phishtriage").joinpath("scoring.yaml").read_text("utf-8")
    custom = tmp_path / "custom.yaml"
    changed = text.replace("suspicious: 25", "suspicious: 40")
    assert changed != text
    custom.write_text(changed, encoding="utf-8")
    config = parse_scoring(custom.read_text(encoding="utf-8"), str(custom))
    path = stats_file(tmp_path, [row()], scoring={"source": "custom.yaml", "sha256": config.sha256})
    capsys.readouterr()
    assert run("results", path, "--scoring", custom) == 0
    assert "Scores rebuilt from their rule names alone: 1 of 1 match" in capsys.readouterr().out


def test_results_reads_no_email(genuine_run, phishing_run, monkeypatch):
    def never(*args, **kwargs):
        raise AssertionError("results opened an email")

    monkeypatch.setattr(cli, "analyse_file", never)
    monkeypatch.setattr(cli, "parse_eml", never)
    assert run("results", genuine_run, phishing_run) == 0
