"""Tests for calibrate: per-file rows in --stats, scored again with a candidate (week 4)."""

from __future__ import annotations

import json
import os
import stat
from importlib import resources
from pathlib import Path

import pytest
from conftest import FIXTURES
from rich.console import Console
from typer.testing import CliRunner

from phishtriage import cli
from phishtriage.calibrate import (
    CalibrationError,
    Row,
    compare_halves,
    load_stats,
    rescore,
    safe_facts,
)
from phishtriage.models import Finding
from phishtriage.scoring import DETECTION_RULES, load_scoring, parse_scoring

runner = CliRunner()
BAR = chr(0x2502)  # the line between table cells; written as a number to keep this file ASCII
GENUINE = ("legit_newsletter.eml", "wrapped_links.eml", "broken_charset.eml")


@pytest.fixture(autouse=True)
def wide(monkeypatch):
    monkeypatch.setattr(cli, "console", Console(width=200))


def run(*args) -> int:
    return cli.main([str(arg) for arg in args])


def built_in() -> str:
    return resources.files("phishtriage").joinpath("scoring.yaml").read_text("utf-8")


@pytest.fixture
def halves(tmp_path) -> tuple[Path, Path]:
    """Stats of 3 genuine fixtures and of all 8 fixtures, made by analyze --stats."""
    genuine = tmp_path / "genuine"
    genuine.mkdir()
    for name in GENUINE:
        (genuine / name).write_bytes((FIXTURES / name).read_bytes())
    legit, phish = tmp_path / "legit.json", tmp_path / "phish.json"
    assert run("analyze", genuine, "--stats", legit, "--json") == 0
    assert run("analyze", FIXTURES, "--stats", phish, "--json") == 2
    return legit, phish


# --- what a row may hold ------------------------------------------------------------------------


def test_only_numbers_true_false_and_fixed_words_are_kept():
    facts = {
        "service": "virustotal",
        "kind": "domain",
        "malicious": 5,
        "share": 0.5,
        "sender_ip": True,
        "url": "https://paypa1.test/login",
        "host": "paypa1[.]test",
        "who": "me.victim@gmail.com",
        "name": "Nimal Perera",
        "long": "a" * 40,
        "Kind": "domain",  # an odd key: not one of ours
        "nested": {"x": 1},
    }
    kept, dropped = safe_facts(facts)
    assert kept == {
        "service": "virustotal",
        "kind": "domain",
        "malicious": 5,
        "share": 0.5,
        "sender_ip": True,
    }
    assert dropped == 7


def test_rows_hold_no_names_and_no_iocs(halves, tmp_path, capsys):
    _, phish = halves
    text = phish.read_text(encoding="utf-8")
    data = json.loads(text)
    assert data["rows_version"] == 1 and data["facts_dropped"] == 0
    assert data["heldout_ok"] is False
    assert len(data["files"]) == data["emails"] == 8
    for email in FIXTURES.glob("*.eml"):
        assert email.stem not in text
    # every IOC the JSON report shows, defanged and refanged, is absent from the stats
    capsys.readouterr()
    assert run("analyze", FIXTURES, "--json") == 2
    report = json.loads(capsys.readouterr().out)
    values = {
        ioc["value"]
        for file in report["files"]
        for email in file["emails"]
        for ioc in email["iocs"]
    }
    assert values
    for value in values:
        refanged = value.replace("hxxp", "http").replace("[.]", ".").replace("[@]", "@")
        assert value not in text and refanged not in text
    for word in ("http", "@", "[.]", "Subject", "detail"):
        assert word not in text


def test_rows_are_sorted_by_score_not_by_name(halves):
    _, phish = halves
    rows = json.loads(phish.read_text())["files"]
    assert [row["score"] for row in rows] == [100, 85, 60, 50, 35, 0, 0, 0]
    forwarded = next(row for row in rows if row["score"] == 60)
    assert len(forwarded["emails"]) == 2  # the file's own email, and the one inside it


# --- scoring the rows again ---------------------------------------------------------------------


def test_the_same_scoring_gives_the_same_scores(halves):
    legit, phish = halves
    genuine, phishing = compare_halves(load_stats(legit), load_stats(phish), load_scoring())
    for half in (genuine, phishing):
        assert [r.total for r in half.rescored] == [row.score for row in half.stats.rows]
        assert half.candidate() == half.measured()
        assert half.mismatches() == 0
    assert phishing.measured() == {"likely benign": 3, "suspicious": 3, "malicious": 2}


def test_a_file_is_judged_by_its_worst_email():
    config = load_scoring()
    row = Row(
        60, "suspicious", ((), (Finding("dmarc_fail", ""), Finding("lookalike_sender_domain", "")))
    )
    rescored = rescore(row, config)
    assert (rescored.total, rescored.verdict) == (45, "suspicious")
    assert rescored.signals == {"dmarc_fail", "lookalike_sender"}
    equal = Row(0, "likely benign", ((Finding("spf_fail", ""),), (Finding("dkim_none", ""),)))
    assert rescore(equal, config).total == 10  # a tie: either one, same total


def test_new_thresholds_change_the_verdicts(halves):
    legit, phish = halves
    lower = parse_scoring(built_in().replace("malicious: 70", "malicious: 50"), "candidate.yaml")
    _, phishing = compare_halves(load_stats(legit), load_stats(phish), lower)
    # the scores 100, 85, 60, 50, 35, 0, 0, 0 under 30 / 50
    assert phishing.candidate() == {"likely benign": 3, "suspicious": 1, "malicious": 4}
    assert phishing.measured() == {"likely benign": 3, "suspicious": 3, "malicious": 2}


def test_new_points_change_the_scores(halves):
    legit, phish = halves
    text = built_in().replace(
        "but the link goes to another\n    points: 15",
        "but the link goes to another\n    points: 0",
    )
    assert text != built_in()
    _, phishing = compare_halves(load_stats(legit), load_stats(phish), parse_scoring(text, "c"))
    assert phishing.fired("link_text_mismatch") == 2  # still counts, now for 0 points
    before = [row.score for row in phishing.stats.rows]
    after = [row.total for row in phishing.rescored]
    assert sum(after) < sum(before)
    assert all(new in (old, old - 15) or old == 100 for old, new in zip(before, after, strict=True))


def test_evidence_thresholds_can_be_tried_too(tmp_path, monkeypatch, phish_email, fake_apis):
    """The facts are kept, so classify() runs again with the candidate's thresholds."""
    for name in ("VT_API_KEY", "ABUSEIPDB_API_KEY", "ABUSECH_AUTH_KEY"):
        monkeypatch.setenv(name, "k" * 64)
    monkeypatch.setenv("PHISHTRIAGE_CACHE", str(tmp_path / "cache.sqlite3"))
    fake_apis(created="2020-01-01T00:00:00Z", vt_engines=5)
    stats = tmp_path / "enriched.json"
    # --hosts-only: URLhaus is asked about hosts only (not listed here), so only
    # VirusTotal's 5 engines can make the flagged_link_or_domain signal count
    assert run("analyze", phish_email, "--enrich", "--hosts-only", "--stats", stats, "--json") == 2
    data = json.loads(stats.read_text())
    facts = [f["facts"] for f in data["files"][0]["emails"][0] if f["rule"] == "vt_flagged"]
    assert facts and all(fact["malicious"] == 5 for fact in facts)
    assert data["facts_dropped"] == 0
    rows = load_stats(stats).rows
    same = rescore(rows[0], load_scoring())
    assert same.total == rows[0].score and "flagged_link_or_domain" in same.signals
    stricter = parse_scoring(
        built_in().replace("virustotal_min_malicious: 3", "virustotal_min_malicious: 6"), "c"
    )
    harder = rescore(rows[0], stricter)
    assert "flagged_link_or_domain" not in harder.signals  # 5 engines; 6 needed now
    assert harder.total < same.total


# --- reading stats files ------------------------------------------------------------------------


def with_rows(*files) -> str:
    """A stats file holding these rows."""
    return json.dumps({"emails": len(files), "rows_version": 1, "files": list(files)})


def one_row(emails, verdict="suspicious") -> str:
    return with_rows({"score": 1, "verdict": verdict, "emails": emails})


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ("not json", "cannot be read"),
        ("[1, 2]", "not a stats file"),
        ('{"emails": 3, "verdicts": {}}', "has no per-file rows"),
        ('{"emails": 1, "rows_version": 2, "files": []}', "version 2, and this PhishTriage reads"),
        ('{"emails": 1, "files": []}', "version None, and this PhishTriage reads version 1"),
        ('{"emails": 1, "heldout_ok": true, "rows_version": 1, "files": []}', "held-out set"),
        (with_rows(3), "file row 1 is not an object"),
        (one_row([[]], verdict="bad"), "needs a score, a verdict and its emails"),
        (one_row([]), "has no emails"),
        (one_row([3]), "an email must be a list of findings"),
        (one_row([[{"facts": {}}]]), "a finding needs a rule name"),
        (one_row([[{"rule": "x", "facts": 3}]]), "a finding needs a rule name"),
        (one_row([["dmarc_fail"]]), "a finding needs a rule name"),
        (one_row([[{"rule": "dmarc_fial"}]]), "unknown rule 'dmarc_fial'.* another version"),
    ],
)
def test_a_stats_file_that_cannot_be_used(tmp_path, content, message):
    path = tmp_path / "stats.json"
    path.write_text(content)
    with pytest.raises(CalibrationError, match=message):
        load_stats(path)


def test_a_week_3_stats_file_says_what_to_do(tmp_path):
    path = tmp_path / "old.json"
    path.write_text(json.dumps({"emails": 50, "emails_failed": 0, "enriched": True}))
    with pytest.raises(CalibrationError, match="Run analyze --stats again"):
        load_stats(path)


def test_a_held_out_run_cannot_be_calibrated_on(tmp_path, capsys):
    stats = tmp_path / "held.json"
    newsletter = FIXTURES / "legit_newsletter.eml"
    assert run("analyze", newsletter, "--heldout-ok", "--stats", stats, "--json") == 0
    assert json.loads(stats.read_text())["heldout_ok"] is True
    capsys.readouterr()
    assert run("calibrate", stats, stats) == 1
    assert "made from a held-out set (--heldout-ok)" in capsys.readouterr().out


# --- the command --------------------------------------------------------------------------------


def lines(out: str) -> list[str]:
    return [line.strip() for line in out.splitlines()]


def test_the_command(halves, capsys):
    legit, phish = halves
    capsys.readouterr()
    assert run("calibrate", legit, phish) == 0
    out = capsys.readouterr().out
    assert out.startswith("Calibration: NOT blind.")
    assert f"Candidate: built-in scoring.yaml (SHA-256 {load_scoring().sha256[:12]})" in out
    assert f"Genuine: {legit}, 3 files, measured with built-in scoring.yaml" in out
    assert "Genuine flagged (suspicious or malicious): 0 of 3 -> 0 of 3" in lines(out)
    assert (
        "Phishing caught (suspicious or malicious): 5 of 8 -> 5 of 8; malicious: 2 -> 2"
        in lines(out)
    )
    table = [line for line in out.splitlines() if line.startswith(f"{BAR} Phishing")]
    assert [cell.strip() for cell in table[0].split(BAR)[1:-1]] == [
        "Phishing",
        "as measured",
        "3",
        "3",
        "2",
    ]
    row = next(line for line in out.splitlines() if f"{BAR} dmarc_fail " in line)
    assert [cell.strip() for cell in row.split(BAR)[1:-1]] == ["dmarc_fail", "25", "0", "2"]
    assert "lookalike_sender" in out and "new_domain" not in out  # only signals that counted
    assert "Highest genuine scores: 0, 0, 0" in out
    assert "Lowest phishing scores: 0, 0, 0, 35, 50, 60, 85, 100" in out
    assert "Suspicious from 25, malicious from 70" in out
    assert "score differently" not in out


def test_the_command_with_a_candidate(halves, tmp_path, capsys):
    legit, phish = halves
    candidate = tmp_path / "candidate.yaml"
    text = built_in().replace("suspicious: 25", "suspicious: 40")
    assert text != built_in()  # a replace that finds nothing would quietly test nothing
    candidate.write_text(text, encoding="utf-8")
    capsys.readouterr()
    assert run("calibrate", legit, phish, "--scoring", candidate) == 0
    out = capsys.readouterr().out
    assert f"Candidate: {candidate.name}" in out or f"Candidate: {candidate}" in out
    assert "Phishing caught (suspicious or malicious): 5 of 8 -> 4 of 8;" in out
    assert "Suspicious from 40, malicious from 70" in out


def test_a_tampered_row_is_noticed(halves, capsys):
    legit, phish = halves
    data = json.loads(phish.read_text())
    data["files"][0]["score"] = 7
    phish.write_text(json.dumps(data))
    capsys.readouterr()
    assert run("calibrate", legit, phish) == 0
    out = " ".join(capsys.readouterr().out.split())
    assert "1 phishing files score differently now than when they were measured" in out


def test_a_broken_candidate_or_stats_file_is_exit_1(halves, tmp_path, capsys):
    legit, phish = halves
    candidate = tmp_path / "bad.yaml"
    candidate.write_text(built_in().replace("dmarc_fail]", "dmarc_fial]"), encoding="utf-8")
    assert run("calibrate", legit, phish, "--scoring", candidate) == 1
    assert "unknown rule 'dmarc_fial'" in capsys.readouterr().out
    old = tmp_path / "old.json"
    old.write_text('{"emails": 1}')
    assert run("calibrate", legit, old) == 1
    assert "has no per-file rows" in capsys.readouterr().out


def test_calibrate_reads_no_email(halves, monkeypatch):
    legit, phish = halves

    def never(*args, **kwargs):
        raise AssertionError("calibrate opened an email")

    monkeypatch.setattr(cli, "analyse_file", never)
    monkeypatch.setattr(cli, "parse_eml", never)
    assert run("calibrate", legit, phish) == 0


# --- owner-only reports ---------------------------------------------------------------------------


def mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def test_reports_are_written_for_you_only(tmp_path):
    folder = tmp_path / "new" / "reports"
    assert run("analyze", FIXTURES / "legit_newsletter.eml", "--out", folder) == 0
    assert mode(folder) == 0o700
    for name in ("report.md", "report.html", "report.json"):
        assert mode(folder / name) == 0o600


def test_old_readable_reports_and_leftovers_are_replaced(tmp_path):
    folder = tmp_path / "reports"
    folder.mkdir(mode=0o755)
    old = folder / "report.md"
    old.write_text("old")
    os.chmod(old, 0o644)
    leftover = folder / ".report.html.partial"
    leftover.write_text("from a crash")
    os.chmod(leftover, 0o644)
    assert run("analyze", FIXTURES / "legit_newsletter.eml", "--out", folder) == 0
    assert mode(old) == 0o600 and old.read_text() != "old"
    assert mode(folder / "report.html") == 0o600
    assert not leftover.exists()
    assert mode(folder) == 0o755  # a folder you made yourself is left as it is


def test_every_rule_a_check_can_produce_can_be_read_back(tmp_path):
    """The refusal above must never hit a real rule: each one is accepted."""
    path = tmp_path / "all.json"
    path.write_text(one_row([[{"rule": rule} for rule in sorted(DETECTION_RULES)]]))
    (row,) = load_stats(path).rows
    assert {finding.rule for finding in row.emails[0]} == DETECTION_RULES


def test_a_file_that_could_not_be_analysed_has_no_row(tmp_path, monkeypatch):
    """It is counted in emails_failed; its row would have no verdict to score again."""
    real = cli.analyse_file

    def broken(path, allowlist):
        if path.name == "legit_newsletter.eml":
            raise OSError("cannot read it")
        return real(path, allowlist)

    monkeypatch.setattr(cli, "analyse_file", broken)
    stats = tmp_path / "run.json"
    assert run("analyze", FIXTURES, "--stats", stats, "--json") == 3
    data = json.loads(stats.read_text())
    assert (data["emails"], data["emails_failed"], len(data["files"])) == (8, 1, 7)
    assert len(load_stats(stats).rows) == 7


def test_the_highest_and_lowest_scores_are_in_order(halves, capsys):
    _, phish = halves
    capsys.readouterr()
    assert run("calibrate", phish, phish) == 0  # the phishing half twice: varied scores
    out = capsys.readouterr().out
    assert "Highest genuine scores: 100, 85, 60, 50, 35, 0, 0, 0" in out
    assert "Lowest phishing scores: 0, 0, 0, 35, 50, 60, 85, 100" in out


def test_other_points_are_not_reported_as_a_changed_version(halves, tmp_path, capsys):
    """The warning compares like with like: only when the candidate is the run's own file."""
    legit, phish = halves
    candidate = tmp_path / "candidate.yaml"
    text = built_in().replace(
        "but the link goes to another\n    points: 15",
        "but the link goes to another\n    points: 0",
    )
    assert text != built_in()
    candidate.write_text(text, encoding="utf-8")
    capsys.readouterr()
    assert run("calibrate", legit, phish, "--scoring", candidate) == 0
    out = capsys.readouterr().out
    assert "score differently" not in out
    # 2 files had the signal: the forwarded one drops 60 -> 45; PayPal stays at the 100 cap
    assert "Lowest phishing scores: 0, 0, 0, 35, 45, 50, 85, 100" in out
