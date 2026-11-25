"""Tests for the run as a whole: exit codes, --out, --scoring, --stats, the held-out guard
and the summary (week 4, step 13). main() is called directly, like the real command."""

import json
import re
import tomllib
from importlib import resources
from pathlib import Path

import pytest
import typer
from conftest import FIXTURES
from rich.console import Console

from phishtriage import cli
from phishtriage.datasets import message_id
from phishtriage.render.common import ranked
from phishtriage.render.safety import HTML, JSON, MARKDOWN, find_unsafe
from phishtriage.report import FileReport, ScoreView
from phishtriage.scoring import LIKELY_BENIGN, MALICIOUS, SUSPICIOUS

PAYPAL = FIXTURES / "phish_paypal_spoof.eml"
FORWARD = FIXTURES / "forwarded_phish.eml"
NEWSLETTER = FIXTURES / "legit_newsletter.eml"


@pytest.fixture(autouse=True)
def wide(monkeypatch):
    monkeypatch.setattr(cli, "console", Console(width=200))


def run(*args) -> int:
    return cli.main([str(arg) for arg in args])


# --- exit codes ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("path", "code"),
    [(PAYPAL, 2), (FORWARD, 1), (NEWSLETTER, 0), (FIXTURES, 2)],
    ids=["malicious", "suspicious", "likely benign", "a folder: the worst file"],
)
def test_the_exit_code_is_the_worst_verdict(path, code):
    assert run("analyze", path) == code


def test_a_file_without_a_verdict_wins_in_a_folder(tmp_path, monkeypatch, capsys):
    for name in ("phish_paypal_spoof.eml", "legit_newsletter.eml"):
        (tmp_path / name).write_bytes((FIXTURES / name).read_bytes())
    real = cli.analyse_file

    def analyse_file(path, allowlist):
        if path.name == "legit_newsletter.eml":
            raise RuntimeError("simulated crash")
        return real(path, allowlist)

    monkeypatch.setattr(cli, "analyse_file", analyse_file)
    assert run("analyze", tmp_path) == 3  # not 2: the run is incomplete
    assert "Could not analyse legit_newsletter.eml" in capsys.readouterr().out


def test_nothing_to_analyse_is_no_verdict(tmp_path):
    assert run("analyze", tmp_path) == 3


@pytest.mark.parametrize(
    ("args", "message"),
    [
        (["analyze", str(PAYPAL), "--jsn"], "No such option"),
        (["analyze", "no/such/file.eml"], "does not exist"),
        (["analyse", str(PAYPAL)], "No such command"),
    ],
)
def test_a_mistake_on_the_command_line_is_3_not_2(args, message, capsys):
    """Click would exit 2, which here means malicious."""
    assert cli.main(args) == 3
    assert message in capsys.readouterr().err


def test_other_typer_errors_keep_their_code(monkeypatch):
    """Only Click's usage errors (code 2) become 3; anything else keeps its own code."""

    def fails(*args, **kwargs):
        raise typer.exceptions.TyperException("no show(), no exit code")

    monkeypatch.setattr(cli, "load_settings", fails)
    assert run("analyze", PAYPAL) == 1


def test_help_and_other_commands_keep_their_codes(capsys):
    assert cli.main(["--help"]) == 0
    assert cli.main(["version"]) == 0
    assert "phishtriage" in capsys.readouterr().out


def test_ctrl_c_is_130(monkeypatch):
    def interrupted(path, allowlist):
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "analyse_file", interrupted)
    assert run("analyze", PAYPAL) == 130


def test_an_abort_is_130(monkeypatch):
    """Typer raises Abort for Ctrl+D at a prompt (fetch-label asks for a password).
    Raised here from reading the settings, outside the loop that keeps a batch going."""

    def aborted(*args, **kwargs):
        raise typer.Abort()

    monkeypatch.setattr(cli, "load_settings", aborted)
    assert run("analyze", PAYPAL) == 130


def test_a_dry_run_analyses_nothing_and_exits_0():
    assert run("analyze", PAYPAL, "--enrich", "--dry-run") == 0


def score(verdict: str, total: int) -> ScoreView:
    return ScoreView(verdict, total, (), "not_enriched", "", 0, ())


def test_exit_code():
    def report(*files):
        return type("R", (), {"files": files})()

    benign, bad = (
        FileReport("a", score(LIKELY_BENIGN, 0), "", ()),
        FileReport("b", None, "", (), "x"),
    )
    assert cli.exit_code(report(benign)) == 0
    assert cli.exit_code(report(benign, FileReport("c", score(MALICIOUS, 90), "", ()))) == 2
    assert cli.exit_code(report(benign, bad)) == 3
    assert cli.exit_code(report()) == 3


# --- the held-out guard ---------------------------------------------------------------------


@pytest.fixture
def heldout(tmp_path, monkeypatch):
    """A set made like split-sets makes it: OUT/heldout next to OUT/heldout.sha256."""
    out = tmp_path / "legit"
    (out / "heldout").mkdir(parents=True)
    (out / "heldout" / "a.eml").write_bytes(NEWSLETTER.read_bytes())
    (out / "heldout.sha256").write_text("x  heldout/a.eml\n")
    (out / "gate.eml").write_bytes(NEWSLETTER.read_bytes())
    read: list[str] = []
    real = cli.analyse_file

    def analyse_file(path, allowlist):
        read.append(path.name)
        return real(path, allowlist)

    monkeypatch.setattr(cli, "analyse_file", analyse_file)
    return out, read


def test_a_heldout_folder_is_refused_before_anything_is_read(heldout, capsys):
    out, read = heldout
    assert run("analyze", out / "heldout") == 3
    assert run("analyze", out / "heldout" / "a.eml") == 3
    assert read == []
    message = capsys.readouterr().out
    assert "is a held-out set (heldout.sha256 is next to it)" in message
    assert "--heldout-ok" in message


def test_the_guard_cannot_be_walked_around(heldout, tmp_path):
    out, read = heldout
    link = tmp_path / "innocent"
    link.symlink_to(out / "heldout")
    assert run("analyze", link) == 3  # a symlink is followed
    assert run("analyze", out / "heldout" / ".." / "heldout") == 3
    upper = tmp_path / "other"
    (upper / "HELDOUT").mkdir(parents=True)  # macOS would find this for "heldout" too
    (upper / "HELDOUT" / "a.eml").write_bytes(NEWSLETTER.read_bytes())
    (upper / "heldout.sha256").write_text("x\n")
    assert run("analyze", upper / "HELDOUT") == 3
    assert read == []


def test_the_folder_around_it_and_a_plain_heldout_folder_are_fine(heldout, tmp_path):
    out, read = heldout
    assert run("analyze", out) == 0  # *.eml in that folder only: heldout/ is not read
    assert read == ["gate.eml"]
    plain = tmp_path / "plain" / "heldout"  # no heldout.sha256 beside it
    plain.mkdir(parents=True)
    (plain / "b.eml").write_bytes(NEWSLETTER.read_bytes())
    assert run("analyze", plain) == 0


def test_heldout_ok_is_for_week_5(heldout):
    out, read = heldout
    assert run("analyze", out / "heldout", "--heldout-ok") == 0
    assert read == ["a.eml"]


def test_with_json_the_refusal_goes_to_stderr(heldout, capsys):
    out, _ = heldout
    assert run("analyze", out / "heldout", "--json") == 3
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "held-out set" in captured.err


# --- --scoring --------------------------------------------------------------------------------


def built_in() -> str:
    return resources.files("phishtriage").joinpath("scoring.yaml").read_text("utf-8")


def test_your_own_scoring_file(tmp_path, capsys):
    mine = tmp_path / "mine.yaml"
    mine.write_text(built_in().replace("malicious: 70", "malicious: 60"), encoding="utf-8")
    assert run("analyze", FORWARD) == 1
    capsys.readouterr()  # forget the first run's terminal report
    assert run("analyze", FORWARD, "--scoring", mine, "--json") == 2  # 60 is now malicious
    data = json.loads(capsys.readouterr().out)
    assert data["scoring_source"] == "mine.yaml"
    assert data["files"][0]["verdict"]["verdict"] == "malicious"


def test_a_broken_scoring_file_is_no_verdict(tmp_path, capsys):
    mine = tmp_path / "mine.yaml"
    mine.write_text(built_in().replace("dmarc_fail]", "dmarc_fial]"), encoding="utf-8")
    assert run("analyze", PAYPAL, "--scoring", mine) == 3
    assert "unknown rule 'dmarc_fial' (did you mean dmarc_fail?)" in capsys.readouterr().out
    assert run("analyze", PAYPAL, "--scoring", tmp_path / "missing.yaml") == 3


# --- --out --------------------------------------------------------------------------------------


def test_out_writes_three_safe_reports(tmp_path, capsys):
    folder = tmp_path / "reports" / "run1"
    assert run("analyze", FIXTURES, "--out", folder) == 2
    names = sorted(path.name for path in folder.iterdir())
    assert names == ["report.html", "report.json", "report.md"]  # no .partial left behind
    for name, kind in (("report.md", MARKDOWN), ("report.html", HTML), ("report.json", JSON)):
        assert find_unsafe((folder / name).read_text(encoding="utf-8"), kind) == []
    data = json.loads((folder / "report.json").read_text(encoding="utf-8"))
    assert len(data["files"]) == len(list(FIXTURES.glob("*.eml")))
    assert f"Reports written: {folder}/report.md, report.html and report.json" in (
        capsys.readouterr().out.replace("\n", "")
    )


def test_out_and_json_together(tmp_path, capsys):
    assert run("analyze", PAYPAL, "--out", tmp_path / "r", "--json") == 2
    captured = capsys.readouterr()
    assert json.loads(captured.out)["files"][0]["name"] == "phish_paypal_spoof.eml"
    assert "Reports written" in captured.err
    stdout_report = json.loads(captured.out)
    file_report = json.loads((tmp_path / "r" / "report.json").read_text(encoding="utf-8"))
    assert stdout_report["files"] == file_report["files"]


def test_nothing_is_written_when_a_report_is_unsafe(tmp_path, monkeypatch, capsys):
    unsafe = (("report.md", MARKDOWN, lambda report: "<script>alert(1)</script>\n"),)
    monkeypatch.setattr(cli, "REPORT_FILES", (*unsafe, *cli.REPORT_FILES[1:]))
    folder = tmp_path / "r"
    assert run("analyze", PAYPAL, "--out", folder) == 3
    assert not folder.exists()
    out = capsys.readouterr().out
    assert "No report was written: the check found something unsafe." in out
    assert "report.md: a <script> tag" in out


def test_a_folder_that_cannot_be_made(tmp_path, capsys):
    blocker = tmp_path / "a-file"
    blocker.write_text("x")
    assert run("analyze", PAYPAL, "--out", blocker / "reports") == 3
    assert "Could not write the reports" in capsys.readouterr().out


def test_a_failed_write_never_leaves_half_a_report(tmp_path, monkeypatch, capsys):
    """The disk fills up halfway through report.md: the report from the last run must
    still be whole, and no temporary file is left behind."""
    folder = tmp_path / "r"
    assert run("analyze", NEWSLETTER, "--out", folder) == 0
    before = (folder / "report.md").read_text(encoding="utf-8")
    real_write = cli._write_owner_only

    def disk_full(path, text):
        if "report.md" in path.name:
            real_write(path, text[: len(text) // 2])
            raise OSError(28, "No space left on device")
        return real_write(path, text)

    monkeypatch.setattr(cli, "_write_owner_only", disk_full)
    assert run("analyze", PAYPAL, "--out", folder) == 3
    assert (folder / "report.md").read_text(encoding="utf-8") == before
    assert sorted(path.name for path in folder.iterdir()) == [
        "report.html",
        "report.json",
        "report.md",
    ]
    assert "No space left on device" in capsys.readouterr().out


# --- --stats -----------------------------------------------------------------------------------


def test_stats_without_enrich(tmp_path, capsys):
    stats = tmp_path / "run.json"
    assert run("analyze", FIXTURES, "--stats", stats, "--json") == 2
    report = json.loads(capsys.readouterr().out)
    data = json.loads(stats.read_text(encoding="utf-8"))
    assert data["enriched"] is False and "services" not in data
    assert (data["emails"], data["emails_failed"]) == (8, 0)
    assert data["verdicts"] == {"malicious": 2, "suspicious": 3, "likely benign": 3}
    assert data["scores"] == [100, 85, 60, 50, 35, 0, 0, 0]
    assert data["scoring"] == {
        "source": report["scoring_source"],
        "sha256": report["scoring_sha256"],
    }
    assert data["analysed_on"] == report["generated_at"][:10]
    # cross-check with the JSON report: files where a signal added points to the verdict
    expected: dict[str, int] = {}
    for file in report["files"]:
        for reason in file["verdict"]["reasons"]:
            if reason["points"] or reason["override"]:
                expected[reason["signal"]] = expected.get(reason["signal"], 0) + 1
    assert data["signals"] == dict(sorted(expected.items()))
    assert data["rules"]["dmarc_fail"] >= 1 and list(data["rules"]) == sorted(data["rules"])


def test_stats_can_go_into_the_new_report_folder(tmp_path):
    folder = tmp_path / "reports" / "run1"
    assert run("analyze", PAYPAL, "--out", folder, "--stats", folder / "stats.json") == 2
    assert json.loads((folder / "stats.json").read_text(encoding="utf-8"))["emails"] == 1


def test_stats_hold_no_iocs_and_no_file_names(tmp_path):
    stats = tmp_path / "run.json"
    run("analyze", FIXTURES, "--stats", stats)
    text = stats.read_text(encoding="utf-8")
    for leak in ("paypa1", "micros0ft", ".eml", "example", "[.]", "@"):
        assert leak not in text


# --- the summary, worst first -------------------------------------------------------------------


def test_a_folder_ends_with_a_summary_worst_first(capsys):
    assert run("analyze", FIXTURES) == 2
    out = capsys.readouterr().out
    table = out[out.index("Summary (worst first)") :]
    order = re.findall(r"\b([a-z_]+\.eml)\b", table)
    assert order == [
        "phish_paypal_spoof.eml",
        "phish_microsoft_format.eml",
        "forwarded_phish.eml",
        "attachments_phish.eml",
        "phish_open_redirect.eml",
        "broken_charset.eml",
        "legit_newsletter.eml",
        "wrapped_links.eml",
    ]
    assert "forwarded email 1" in table


def test_one_file_has_no_summary(capsys):
    run("analyze", PAYPAL)
    assert "Summary (worst first)" not in capsys.readouterr().out


def test_a_file_without_a_verdict_is_last_in_the_summary(tmp_path, monkeypatch, capsys):
    for name in ("broken.eml", "legit_newsletter.eml"):
        (tmp_path / name).write_bytes(NEWSLETTER.read_bytes())
    real = cli.analyse_file

    def analyse_file(path, allowlist):
        if path.name == "broken.eml":
            raise ValueError("bad")
        return real(path, allowlist)

    monkeypatch.setattr(cli, "analyse_file", analyse_file)
    run("analyze", tmp_path)
    out = capsys.readouterr().out
    table = out[out.index("Summary (worst first)") :]
    assert (
        table.index("legit_newsletter.eml") < table.index("NO VERDICT") < table.index("broken.eml")
    )


def test_ranked():
    files = [
        FileReport("b", score(SUSPICIOUS, 40), "", ()),
        FileReport("failed", None, "", (), "x"),
        FileReport("a", score(SUSPICIOUS, 40), "", ()),
        FileReport("z", score(MALICIOUS, 70), "", ()),
        FileReport("c", score(SUSPICIOUS, 65), "", ()),
        FileReport("y", score(MALICIOUS, 100), "", ()),
    ]
    assert [file.name for file in ranked(files)] == ["y", "z", "c", "a", "b", "failed"]


def test_markdown_and_html_summaries_are_worst_first(tmp_path):
    folder = tmp_path / "r"
    run("analyze", FIXTURES, "--out", folder)
    markdown = (folder / "report.md").read_text(encoding="utf-8")
    rows = re.findall(r"^\| ([a-z_]+\.eml) \|", markdown, re.MULTILINE)
    assert rows[:3] == [
        "phish_paypal_spoof.eml",
        "phish_microsoft_format.eml",
        "forwarded_phish.eml",
    ]
    page = (folder / "report.html").read_text(encoding="utf-8")
    summary = page[page.index("<h2>Summary</h2>") : page.index("</table>")]
    assert summary.index("phish_paypal_spoof.eml") < summary.index("broken_charset.eml")
    # the JSON keeps the files in the order given: it is data, not a reading order
    data = json.loads((folder / "report.json").read_text(encoding="utf-8"))
    assert [file["name"] for file in data["files"]] == sorted(
        p.name for p in FIXTURES.glob("*.eml")
    )


# --- ruff never reads samples/ or reports/ ------------------------------------------------------


def test_ruff_is_kept_out_of_samples_and_reports():
    """Without git (until after week 5) ruff does not apply .gitignore; `ruff format .`
    would read, and could rewrite, Markdown in those folders."""
    pyproject = Path(__file__).parent.parent / "pyproject.toml"
    config = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    assert {"samples", "reports"} <= set(config["tool"]["ruff"]["extend-exclude"])
    assert config["project"]["scripts"]["phishtriage"] == "phishtriage.cli:run"


# --- long paths stay on one line; the CLI's own lines are not highlighted --------------------


@pytest.fixture
def deep(tmp_path):
    """A folder whose path is longer than the 200-column test console (macOS's pytest
    folders under /private/var/folders/... are long too: the bug was found there)."""
    folder = tmp_path / ("a" * 90) / ("b" * 90)
    folder.mkdir(parents=True)
    return folder


def lines_with(text: str, out: str) -> list[str]:
    return [line for line in out.splitlines() if text in line]


def test_a_scoring_error_with_a_long_path_stays_on_one_line(deep, capsys):
    mine = deep / "mine.yaml"
    mine.write_text(built_in().replace("dmarc_fail]", "dmarc_fial]"), encoding="utf-8")
    assert run("analyze", PAYPAL, "--scoring", mine) == 3
    (line,) = lines_with("unknown rule 'dmarc_fial'", capsys.readouterr().out)
    assert str(mine) in line and line.endswith("(did you mean dmarc_fail?)")


def test_messages_with_long_paths_stay_on_one_line(deep, monkeypatch, capsys):
    folder = deep / "reports"
    stats = folder / "stats.json"
    assert run("analyze", PAYPAL, "--out", folder, "--stats", stats) == 2
    out = capsys.readouterr().out
    assert lines_with("Reports written: ", out) == [
        f"Reports written: {folder}/report.md, report.html and report.json"
    ]
    assert lines_with("Counts written to ", out) == [f"  Counts written to {stats}"]

    def unreadable(path, allowlist):
        raise OSError(f"cannot read {path}")

    monkeypatch.setattr(cli, "analyse_file", unreadable)
    email = deep / "x.eml"
    email.write_bytes(NEWSLETTER.read_bytes())
    assert run("analyze", email) == 3
    (line,) = lines_with("Could not analyse x.eml", capsys.readouterr().out)
    assert line.endswith(f"cannot read {email}')")


def test_the_cli_lines_are_not_highlighted(monkeypatch):
    console = Console(force_terminal=True, color_system="truecolor", highlight=True, width=200)
    monkeypatch.setattr(cli, "console", console)
    with console.capture() as capture:
        assert run("analyze", FIXTURES) == 2
    assert "Analysed 8 of 8 files." in capture.get()  # no colour codes around the 8s


def test_refusals_and_write_errors_with_long_paths_stay_on_one_line(deep, capsys):
    held = deep / "legit" / "heldout"
    held.mkdir(parents=True)
    (held / "a.eml").write_bytes(NEWSLETTER.read_bytes())
    (deep / "legit" / "heldout.sha256").write_text("x  heldout/a.eml\n")
    assert run("analyze", held) == 3
    (line,) = lines_with("is a held-out set", capsys.readouterr().out)
    assert line == f"{held} is a held-out set (heldout.sha256 is next to it)."

    empty = deep / "empty"
    empty.mkdir()
    assert run("analyze", empty) == 3
    assert lines_with("No .eml files found", capsys.readouterr().out) == [
        f"No .eml files found in {empty}"
    ]

    blocker = deep / "a-file"
    blocker.write_text("x")
    assert run("analyze", PAYPAL, "--out", blocker / "reports") == 3
    (line,) = lines_with("Could not write the reports", capsys.readouterr().out)
    assert str(blocker) in line

    stats = deep / "no" / "run.json"
    assert run("analyze", PAYPAL, "--stats", stats) == 2
    assert lines_with("Could not write ", capsys.readouterr().out) == [
        f"Could not write {stats}: FileNotFoundError"
    ]


# --- held-out copies: the folder the sets were picked from (week 4) ---------------------------


@pytest.fixture
def project(tmp_path, monkeypatch):
    """Your Mac's layout: inbox/ with every email, and split-sets' samples/legit/ beside it.

    Returns the inbox, the held-out file names, and the names analyse_file was given.
    Built deep down, so every message holding a path is longer than the console.
    """
    inbox = tmp_path / ("a" * 90) / ("b" * 90) / "inbox"
    inbox.mkdir(parents=True)
    for email in FIXTURES.glob("*.eml"):
        (inbox / email.name).write_bytes(email.read_bytes())
    samples = inbox.parent / "samples"
    seed = ("--seed", 20261123, "--heldout", 3, "--gate", 2)
    assert run("split-sets", inbox, samples / "legit", *seed) == 0
    monkeypatch.setattr(cli, "SAMPLES", samples)
    held = {path.name for path in (samples / "legit" / "heldout").iterdir()}
    read: list[str] = []
    real = cli.analyse_file

    def analyse_file(path, allowlist):
        read.append(path.name)
        return real(path, allowlist)

    monkeypatch.setattr(cli, "analyse_file", analyse_file)
    return inbox, held, read


def test_held_out_copies_are_skipped_before_they_are_read(project, capsys):
    inbox, held, read = project
    assert len(held) == 3
    assert run("analyze", inbox) in (0, 1, 2)
    assert set(read) == {path.name for path in inbox.iterdir()} - held
    assert len(read) == 5
    out = capsys.readouterr().out
    listing = (inbox.parent / "samples" / "legit" / "heldout.sha256").resolve()
    assert f"Skipped 3 held-out emails (same bytes or Message-ID as in {listing})." in out
    assert "Analysed 5 of 5 files." in out
    for name in held:  # not even the name of a held-out email is shown
        assert Path(name).stem not in out


def test_a_single_held_out_copy_is_no_verdict(project, tmp_path, capsys):
    inbox, held, read = project
    folder, stats = tmp_path / "reports", tmp_path / "run.json"
    assert run("analyze", inbox / sorted(held)[0], "--out", folder, "--stats", stats) == 3
    assert read == []
    out = capsys.readouterr().out
    assert "Skipped 1 held-out email (same bytes" in out
    # it stops there: no empty report, no counts of nothing, no report header
    assert not folder.exists() and not stats.exists()
    assert "Verdict" not in out and "Summary" not in out


def test_a_new_download_of_a_held_out_email_is_skipped(project, tmp_path):
    inbox, held, read = project
    again = tmp_path / "downloads"
    again.mkdir()
    with_id = sorted(name for name in held if message_id(inbox / name))
    assert with_id  # this seed picks at least one email with a Message-ID
    for name in with_id:  # other bytes, same Message-ID: as Gmail's "Download message" might
        (again / name).write_bytes(b"X-Downloaded-Again: yes\r\n" + (inbox / name).read_bytes())
    (again / "other.eml").write_bytes(NEWSLETTER.read_bytes().replace(b"12345@", b"99999@"))
    assert run("analyze", again) == 0
    assert read == ["other.eml"]


def test_heldout_ok_reads_them_all(project):
    inbox, _, read = project
    assert run("analyze", inbox, "--heldout-ok") == 2
    assert len(read) == 8


def test_held_out_lists_are_found_from_any_folder(project, monkeypatch, tmp_path):
    """Run from another folder: a samples folder above the path is searched too."""
    inbox, held, read = project
    monkeypatch.setattr(cli, "SAMPLES", tmp_path / "elsewhere")
    moved = inbox.parent / "samples" / "inbox"
    inbox.rename(moved)
    assert run("analyze", moved) in (0, 1, 2)
    assert held.isdisjoint(read) and len(read) == 5
    read.clear()
    link = tmp_path / "innocent"  # outside any samples folder, but leads into one
    link.symlink_to(moved)
    assert run("analyze", link) in (0, 1, 2)
    assert held.isdisjoint(read) and len(read) == 5


def test_a_broken_held_out_list_stops_the_run(project, capsys):
    inbox, _, read = project
    listing = inbox.parent / "samples" / "legit" / "heldout.sha256"
    listing.write_text(listing.read_text() + "edited by hand\n")
    assert run("analyze", inbox) == 3
    assert read == []
    out = capsys.readouterr().out
    (line,) = lines_with("Could not read a held-out list", out)
    assert line.endswith("line 4: not a sha256sum line")
    assert "Nothing was analysed" in out


def test_stats_and_json_with_skipped_emails(project, tmp_path, capsys):
    inbox, _, _ = project
    stats = tmp_path / "run.json"
    assert run("analyze", inbox, "--stats", stats, "--json") in (0, 1, 2)
    captured = capsys.readouterr()
    assert len(json.loads(captured.out)["files"]) == 5  # stdout is the report only
    assert "Skipped 3 held-out emails" in captured.err
    data = json.loads(stats.read_text())
    assert (data["emails"], data["heldout_skipped"]) == (5, 3)


def test_the_tests_never_see_your_real_samples():
    assert cli.SAMPLES.name == "no-samples" and not cli.SAMPLES.exists()
