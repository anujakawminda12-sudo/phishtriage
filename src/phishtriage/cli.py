"""Command-line interface.

phishtriage analyze email.eml
phishtriage analyze ./folder-of-emails/
phishtriage analyze email.eml --allowlist my-allowlist.txt
phishtriage analyze email.eml --all-urls
phishtriage analyze folder/ --enrich       (week 3: threat-intel lookups; uses the network)
phishtriage analyze folder/ --enrich --hosts-only --max-lookups 50 --stats run.json
phishtriage analyze folder/ --enrich --dry-run   (what would be sent, and how long; sends nothing)
phishtriage analyze folder/ --json > report.json  (week 4: the report as JSON; messages on stderr)
phishtriage analyze folder/ --out reports/run1     (week 4: also report.md, .html and .json)
phishtriage analyze folder/ --stats run.json --scoring my-scoring.yaml
phishtriage check-iocs samples/            (week 2 gate: compare with hand-checked lists)
phishtriage check-iocs samples/ --make-templates
phishtriage config                        (week 3: which lookup services are ready)
phishtriage cache [--clear]               (week 3: stored results, API calls in 24 h)
phishtriage split-sets SOURCE OUT --seed N (week 3 gate: pick held-out and gate sets once)
phishtriage fetch-label LABEL OUT --user ME (download a Gmail label read-only, as .eml files)
phishtriage fetch-label INBOX --user ME --search "newer_than:6m" --newest 120 --list
phishtriage calibrate LEGIT.json PHISH.json --scoring candidate.yaml   (week 4: not blind)
phishtriage results GENUINE.json [PHISH.json]   (week 5: rates, ranges and O6 targets of runs)
phishtriage version

An email forwarded as an attachment gets its own section after the email it came in.
Week 4: analyze builds a report.Report (scored, redacted, defanged, control characters
written out) and render/terminal.py prints it. This module only collects the options,
runs the phases and prints the run's summaries.
Without --enrich, analyze never touches the network (a test checks this).

Exit codes of analyze (week 4, step 13), so a script can act on the result:
    0  likely benign: every file scored 0-24 (that is not "safe", only "no strong signs")
    1  suspicious: the worst file scored 25-69 (30-69 before week 5's calibration)
    2  malicious: the worst file scored 70-100
    3  no verdict: a file could not be analysed, a held-out set was refused, scoring.yaml
       or the command line was wrong, or a report could not be written safely. In a
       folder run 3 wins: one file without a verdict makes the whole run incomplete
  130  stopped with Ctrl+C
Click uses 2 for a mistake on the command line; main() turns that into 3, so 2 can only
ever mean malicious. A dry run (--enrich --dry-run) analyses nothing and exits 0.
"""

from __future__ import annotations

import contextlib
import json
import os
import sys
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.console import Console
from rich.table import Table

from . import __version__
from .allowlist import Allowlist, load_allowlist
from .analysis import EmailAnalysis, analyse_file
from .calibrate import (
    STATS_ROWS_VERSION,
    CalibrationError,
    Half,
    compare_halves,
    load_stats,
    stats_rows,
)
from .config import DEFAULT_ENV_FILE, SERVICE_KEYS, Settings, load_settings
from .datasets import GATE, HELDOUT, find_heldout_lists, pick_sets, write_sets
from .display import safe
from .enrich.base import ServiceStats
from .enrich.cache import open_cache
from .enrich.enricher import SERVICE_NAMES as SERVICE_LABELS
from .enrich.enricher import Enrichment, enrich
from .enrich.models import LookupResult
from .enrich.plan import LookupPlan
from .evaluate import SECTIONS, Comparison, compare, parse_hand_check, tool_values, write_templates
from .imap_export import (
    GMAIL_HOST,
    ExportError,
    Listed,
    connect,
    export_label,
    has_files,
    list_label,
)
from .iocs import defang
from .parser import parse_eml
from .render.html import render_html
from .render.json_report import render_json
from .render.markdown import render_markdown
from .render.safety import HTML, JSON, MARKDOWN, find_unsafe
from .render.terminal import print_report, print_summary
from .report import Report, build_report
from .results import (
    ACCURACY_TARGET,
    FALSE_POSITIVE_TARGET,
    Both,
    Lookups,
    ResultsError,
    Run,
    View,
    load_run,
    lookups,
    meets_accuracy_target,
    meets_false_positive_target,
    side_by_side,
)
from .scoring import MALICIOUS, VERDICT_RANK, ScoringConfig, ScoringError, load_scoring

app = typer.Typer(
    help="Phishing email triage: .eml in, explainable verdict out.", no_args_is_help=True
)
console = Console()

# Week 3: how often to show progress during the lookups
PROGRESS_EVERY = 25

# Week 4, step 13: exit codes (see the module docstring). 0-2 are VERDICT_RANK's numbers
EXIT_NO_VERDICT = 3
EXIT_INTERRUPTED = 130
CLICK_USAGE_ERROR = 2

# Week 4: where split-sets puts the sets, relative to the project folder you run from.
# analyze looks for heldout.sha256 files in here (tests point it at an empty folder)
SAMPLES = Path("samples")


def say(*objects: Any, **options: Any) -> None:
    """Print a message from the CLI (week 4, step 13).

    highlight=False by default: Rich would otherwise colour numbers and words it guesses
    are code ("Analysed 8 of 8 files" came out with blue 8s), as in the report itself.
    Messages that hold a path pass soft_wrap=True: Rich then never breaks the line with a
    newline (the terminal still wraps it on screen), so a path copied from the terminal
    stays whole. Found on the Mac, where pytest's folders under /private/var/folders/...
    made an error line longer than the window and Rich split it.
    """
    options.setdefault("highlight", False)
    console.print(*objects, **options)


def main(argv: list[str] | None = None) -> int:
    """The phishtriage command (pyproject's console script calls run()). Returns the exit
    code instead of leaving, so tests can call it like any function.

    standalone_mode=False makes Typer hand back what happened instead of exiting itself:
    a typer.Exit comes back as its code, and Click's own errors (a misspelt option) come
    back as exceptions. Those are caught by their public base, TyperException, and their
    exit code 2 becomes 3: a typo on the command line is not a malicious email.
    """
    try:
        code = app(args=argv, prog_name="phishtriage", standalone_mode=False)
    except typer.exceptions.TyperException as error:
        show = getattr(error, "show", None)
        if show is not None:
            show()  # "Usage: phishtriage analyze ... Error: No such option: --jsn"
        code = getattr(error, "exit_code", 1)
        return EXIT_NO_VERDICT if code == CLICK_USAGE_ERROR else code
    except typer.Abort:  # Typer's other way of saying the user stopped it
        return EXIT_INTERRUPTED
    return code if isinstance(code, int) else 0


def run() -> None:  # pragma: no cover - the console script; main() is what tests call
    sys.exit(main())


EmlPath = Annotated[
    Path,
    typer.Argument(
        exists=True, readable=True, metavar="PATH", help=".eml file or a folder of them"
    ),
]
AllowlistPath = Annotated[
    Path | None,
    typer.Option(
        "--allowlist",
        exists=True,
        dir_okay=False,
        readable=True,
        help="Your own allowlist file (default: the built-in allowlist.txt)",
    ),
]
AllUrls = Annotated[
    bool, typer.Option("--all-urls", help="List every URL instead of grouping them by domain")
]
SampleFolder = Annotated[
    Path,
    typer.Argument(exists=True, file_okay=False, help="Folder of .eml files with expected/"),
]
MakeTemplates = Annotated[
    bool,
    typer.Option("--make-templates", help="Create blank hand-check files for new emails"),
]
Enrich = Annotated[
    bool,
    typer.Option(
        "--enrich",
        help="Look up IOCs in VirusTotal, AbuseIPDB, URLhaus and RDAP (uses the network)",
    ),
]
HostsOnly = Annotated[
    bool, typer.Option("--hosts-only", help="With --enrich: send hosts, never full URLs")
]
MaxLookups = Annotated[
    int | None,
    typer.Option("--max-lookups", min=1, help="With --enrich: at most N new lookups a service"),
]
DryRun = Annotated[
    bool,
    typer.Option("--dry-run", help="With --enrich: show what would be looked up; send nothing"),
]
StatsFile = Annotated[
    Path | None,
    typer.Option(
        "--stats",
        dir_okay=False,
        help="Write the run's counts as JSON: verdicts, scores, rules (no IOCs, no file names)",
    ),
]
ReportFolder = Annotated[
    Path | None,
    typer.Option(
        "--out",
        file_okay=False,
        help="Also write report.md, report.html and report.json into this folder",
    ),
]
ScoringFile = Annotated[
    Path | None,
    typer.Option(
        "--scoring",
        exists=True,
        dir_okay=False,
        readable=True,
        help="Your own scoring file (default: the built-in scoring.yaml)",
    ),
]
HeldoutOk = Annotated[
    bool,
    typer.Option(
        "--heldout-ok", help="Allow a held-out set (week 5 only: its blind test reads it once)"
    ),
]
JsonOutput = Annotated[
    bool,
    typer.Option("--json", help="Write the report as JSON to stdout; every message goes to stderr"),
]
EnvFile = Annotated[
    Path,
    typer.Option("--env-file", dir_okay=False, help="File with your API keys (default: .env)"),
]
ClearCache = Annotated[
    bool,
    typer.Option("--clear", help="Forget the stored results (the log of API calls is kept)"),
]
SourceFolder = Annotated[
    Path,
    typer.Argument(exists=True, file_okay=False, help="Folder of .eml files to pick from"),
]
LegitStats = Annotated[
    Path,
    typer.Argument(
        exists=True, dir_okay=False, readable=True, help="--stats file of a genuine-mail run"
    ),
]
PhishStats = Annotated[
    Path,
    typer.Argument(
        exists=True, dir_okay=False, readable=True, help="--stats file of a phishing run"
    ),
]
MorePhishStats = Annotated[
    Path | None,
    typer.Argument(
        exists=True, dir_okay=False, readable=True, help="--stats file of a phishing run (optional)"
    ),
]
OutFolder = Annotated[
    Path, typer.Argument(file_okay=False, help="New folder for OUT/heldout and OUT/gate")
]
Seed = Annotated[
    int, typer.Option("--seed", help="Any whole number: choose it and write it down first")
]
HeldoutCount = Annotated[
    int, typer.Option("--heldout", min=0, help="Emails kept unseen for week 5")
]
GateCount = Annotated[int, typer.Option("--gate", min=0, help="Emails for the week 3 gate")]
LabelName = Annotated[str, typer.Argument(help="A Gmail label exactly as Gmail shows it, or INBOX")]
ExportFolder = Annotated[
    Path | None,
    typer.Argument(file_okay=False, help="New folder for the .eml files (not needed with --list)"),
]
GmailSearch = Annotated[
    str | None,
    typer.Option("--search", help='Gmail search words, e.g. "from:sliit.lk newer_than:6m"'),
]
Newest = Annotated[
    int | None, typer.Option("--newest", min=1, help="Only the newest N matching emails")
]
ListOnly = Annotated[
    bool, typer.Option("--list", help="Show date, sender and subject; download nothing")
]
ImapUser = Annotated[str, typer.Option("--user", help="Your Gmail address (used to log in)")]
ImapHost = Annotated[str, typer.Option("--host", help="IMAP server (default: Gmail's)")]
Exclude = Annotated[
    list[Path] | None,
    typer.Option(
        "--exclude", exists=True, help="Emails already used while building (can be repeated)"
    ),
]


@dataclass(frozen=True)
class RunOptions:
    """Everything analyze was asked to do, as one object passed to the phases."""

    allowlist: Path | None = None
    all_urls: bool = False
    enrich: bool = False
    hosts_only: bool = False
    max_lookups: int | None = None
    stats: Path | None = None
    dry_run: bool = False
    env_file: Path = DEFAULT_ENV_FILE
    scoring: Path | None = None
    out: Path | None = None
    heldout_ok: bool = False
    show_report: bool = True


@app.command()
def analyze(
    path: EmlPath,
    allowlist: AllowlistPath = None,
    all_urls: AllUrls = False,
    enrich_iocs: Enrich = False,
    hosts_only: HostsOnly = False,
    max_lookups: MaxLookups = None,
    stats: StatsFile = None,
    dry_run: DryRun = False,
    env_file: EnvFile = DEFAULT_ENV_FILE,
    as_json: JsonOutput = False,
    out: ReportFolder = None,
    scoring: ScoringFile = None,
    heldout_ok: HeldoutOk = False,
) -> None:
    """Analyse one .eml file, or every .eml file in a folder."""
    options = RunOptions(
        allowlist, all_urls, enrich_iocs, hosts_only, max_lookups, stats, dry_run, env_file,
        scoring, out, heldout_ok, show_report=not as_json,
    )  # fmt: skip
    # Week 4, step 12: with --json, stdout carries the JSON and nothing else, so it can be
    # piped into jq or a SIEM. redirect_stdout sends every message printed on the way
    # (warnings, the lookup plan, progress) to stderr instead. Java: System.setOut()
    # for the length of the block, put back afterwards even if it fails.
    quiet = contextlib.redirect_stdout(sys.stderr) if as_json else contextlib.nullcontext()
    with quiet:
        report = _analyze(path, options)
    if report is None:  # a dry run: nothing was analysed, so there is no report
        return
    if as_json:
        typer.echo(render_json(report), nl=False)
    raise typer.Exit(exit_code(report))


def exit_code(report: Report) -> int:
    """0, 1 or 2 for the worst verdict; 3 when any file has none (see the docstring)."""
    if not report.files or any(file.verdict is None for file in report.files):
        return EXIT_NO_VERDICT
    return max(VERDICT_RANK[file.verdict.verdict] for file in report.files if file.verdict)


def heldout_roots(path: Path) -> list[Path]:
    """Where analyze looks for heldout.sha256 files (week 4).

    The project's samples/ folder (you run phishtriage from the project folder), and any
    folder called samples that the analysed path is in, so it works from elsewhere too.
    """
    resolved = path.resolve()
    above = [folder for folder in (resolved, *resolved.parents) if folder.name.lower() == "samples"]
    return [SAMPLES.resolve(), *above]


def _without_heldout(path: Path, files: list[Path]) -> tuple[list[Path], int]:
    """Drop every held-out email from `files`, before a single one is parsed (week 4).

    heldout_set() catches the held-out folder itself. This catches the copies: split-sets
    copies what it picks, so the held-out emails are also still in the folder they were
    picked from, and one could be downloaded again. Matched by bytes and Message-ID, like
    --exclude. Returns the files to analyse and how many were skipped.
    """
    try:
        lists = find_heldout_lists(heldout_roots(path))
    except (OSError, ValueError) as error:
        say(
            f"[bold red]Could not read a held-out list: {safe(str(error))}[/]\n"
            "Nothing was analysed: a list that cannot be read could let held-out emails through.",
            soft_wrap=True,
        )
        raise typer.Exit(EXIT_NO_VERDICT) from None
    kept = [file for file in files if not lists.holds(file)]
    skipped = len(files) - len(kept)
    if skipped:
        where = ", ".join(safe(str(listing)) for listing in lists.files)
        say(
            f"[yellow]Skipped {skipped} held-out email{'' if skipped == 1 else 's'} "
            f"(same bytes or Message-ID as in {where}).[/]\n"
            "They stay unseen until week 5. Add --heldout-ok only for week 5's blind test.",
            soft_wrap=True,
        )
    if not kept:
        raise typer.Exit(EXIT_NO_VERDICT)
    return kept, skipped


def heldout_set(path: Path) -> Path | None:
    """The held-out set path is in, or None.

    split-sets (week 3) wrote OUT/heldout next to OUT/heldout.sha256. A folder with that
    name and that neighbour is a held-out set, whichever way it is reached (a relative
    path, a single .eml inside it, a symlink: resolve() follows them). The name is
    compared without case, because macOS finds "HELDOUT" as well as "heldout".
    """
    resolved = path.resolve()
    for folder in (resolved, *resolved.parents):
        if folder.name.lower() == HELDOUT and (folder.parent / f"{HELDOUT}.sha256").is_file():
            return folder
    return None


def _analyze(path: Path, options: RunOptions) -> Report | None:
    """The phases of analyze. Returns the report, or None after a dry run."""
    # Week 4: a held-out set must stay unseen until week 5's blind test, so it is refused
    # before a single email in it is read
    if not options.heldout_ok and (held := heldout_set(path)) is not None:
        say(
            f"[bold red]{safe(str(held))} is a held-out set ({HELDOUT}.sha256 is next to it).[/]\n"
            "It stays unseen until week 5. Add --heldout-ok only for week 5's blind test.",
            soft_wrap=True,
        )
        raise typer.Exit(EXIT_NO_VERDICT)

    files = sorted(path.glob("*.eml")) if path.is_dir() else [path]
    if not files:
        say(f"[yellow]No .eml files found in {safe(str(path))}[/]", soft_wrap=True)
        raise typer.Exit(EXIT_NO_VERDICT)
    skipped = 0
    if not options.heldout_ok:
        files, skipped = _without_heldout(path, files)

    try:  # week 4: a broken scoring.yaml stops the run before any work is done
        scoring = load_scoring(options.scoring)
    except ScoringError as error:
        say(f"[bold red]{safe(str(error))}[/]", soft_wrap=True)
        raise typer.Exit(EXIT_NO_VERDICT) from None
    rules = load_allowlist(options.allowlist)
    for problem in rules.problems:
        say(f"[yellow]Allowlist {safe(problem)}[/]")
    # Week 4: read every run, not only with --enrich, because the report hides
    # PHISHTRIAGE_MY_ADDRESSES too. Reading the settings uses no network.
    settings = load_settings(options.env_file)
    for warning in settings.warnings:
        say(f"[yellow]Warning:[/yellow] {safe(warning)}")

    # Phase 1: analyse every email, printing nothing yet
    analyses: list[EmailAnalysis] = []
    failed: list[tuple[Path, str]] = []
    for file in files:
        try:
            analyses.append(analyse_file(file, rules))
        except Exception as exc:  # keep going in batch mode; reported with the others
            failed.append((file, repr(exc)))

    # Phase 2 (week 3, only with --enrich): look up the IOCs of every email in one batch,
    # so a value seen in 30 emails is asked about once, the most important first
    enrichment = None
    if options.enrich:
        enrichment = _enrich(
            analyses, rules, settings, options.hosts_only, options.max_lookups, options.dry_run
        )
        if enrichment.dry_run:
            _print_dry_run(enrichment, len(files))
            return None
    elif options.hosts_only or options.max_lookups is not None or options.dry_run:
        say("[yellow]--hosts-only, --max-lookups and --dry-run only work with --enrich[/]")

    # Phase 3 (week 4): build the report once, then print it (or leave it for --json)
    report = build_report(
        analyses,
        scoring,
        enrichment=enrichment,
        my_addresses=settings.my_addresses.reveal(),
        failed=failed,
    )
    if options.show_report:
        print_report(report, console, all_urls=options.all_urls)
        if len(files) > 1:
            print_summary(report, console)
    unreadable = sum(1 for file in report.files if file.error)

    if enrichment is not None:
        _print_enrichment_summary(enrichment)
    if options.out is not None:  # first, so --stats can go into the same new folder
        _write_reports(options.out, report)
    if options.stats is not None:
        _write_stats(options, report, enrichment, len(files), unreadable, skipped)
    if len(files) > 1:
        say(f"\nAnalysed {len(files) - unreadable} of {len(files)} files.")
    return report


REPORT_FILES = (
    ("report.md", MARKDOWN, render_markdown),
    ("report.html", HTML, render_html),
    ("report.json", JSON, render_json),
)


def _write_reports(folder: Path, report: Report) -> None:
    """Write the three report files, or none of them.

    Each one is read back by find_unsafe() first; one problem in any of them and nothing
    is written (exit 3), because a half-written set of reports is easy to mistake for a
    whole one. Each file is written to a temporary name and then renamed (os.replace),
    so a crash cannot leave a half-written report behind under the real name.
    """
    texts = [(name, render(report)) for name, _, render in REPORT_FILES]
    problems = [
        f"{name}: {problem}"
        for (name, kind, _), (_, text) in zip(REPORT_FILES, texts, strict=True)
        for problem in find_unsafe(text, kind)
    ]
    if problems:
        say("[bold red]No report was written: the check found something unsafe.[/]")
        for problem in problems:
            say(f"  {safe(problem)}")
        raise typer.Exit(EXIT_NO_VERDICT)
    try:
        folder.mkdir(mode=0o700, parents=True, exist_ok=True)  # a new folder: only you
        for name, text in texts:
            partial = folder / f".{name}.partial"
            _write_owner_only(partial, text)
            os.replace(partial, folder / name)  # one step: the old file or the new one
    except OSError as error:
        for name, _ in texts:  # a half-written temporary file is not left behind
            with contextlib.suppress(OSError):  # best effort: the folder may not exist
                (folder / f".{name}.partial").unlink(missing_ok=True)
        say(f"[bold red]Could not write the reports: {safe(str(error))}[/]", soft_wrap=True)
        raise typer.Exit(EXIT_NO_VERDICT) from None
    written = f"{safe(str(folder))}/report.md, report.html and report.json"
    say(f"\nReports written: {written}", soft_wrap=True)


def _write_owner_only(path: Path, text: str) -> None:
    """Write `path` so only you can read it (0600), as fetch-label and split-sets do.

    A report holds the emails' senders, subjects and links, the same personal data as
    the emails. os.open() gives the file its mode as it is created, so it is never
    readable by others, not even for a moment (Java: Files.newOutputStream with
    PosixFilePermissions.asFileAttribute). A leftover from a crash is removed first.
    """
    path.unlink(missing_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(text)


@app.command("check-iocs")
def check_iocs(folder: SampleFolder, make_templates: MakeTemplates = False) -> None:
    """Week 2 gate: compare extracted IOCs with your hand-checked lists in FOLDER/expected/."""
    if make_templates:
        created = write_templates(folder)
        for path in created:
            say(f"Created {safe(str(path))}")
        say(f"{len(created)} new hand-check file(s). Existing files were not changed.")
        return

    totals = {section: Comparison() for section in SECTIONS}
    checked = 0
    for eml in sorted(folder.glob("*.eml")):
        expected_file = folder / "expected" / f"{eml.stem}.txt"
        if not expected_file.exists():
            say(f"[dim]No hand-check file for {safe(eml.name)}: skipped[/]")
            continue
        expected = parse_hand_check(expected_file.read_text(encoding="utf-8"))
        if not any(expected.values()):
            # Comparing an empty list would print all the tool's answers before you have
            # written yours, and the check would no longer be blind
            say(f"[dim]{safe(eml.name)}: hand-check file still empty, skipped[/]")
            continue
        checked += 1
        results = compare(expected, tool_values(parse_eml(eml)))
        console.rule(safe(eml.name))
        for section, result in results.items():
            total = totals[section]
            total.matched |= {f"{eml.name}:{v}" for v in result.matched}
            total.missed |= {f"{eml.name}:{v}" for v in result.missed}
            total.extra |= {f"{eml.name}:{v}" for v in result.extra}
            line = f"  {section:<12} {len(result.matched)} matched"
            line += f", {len(result.missed)} missed, {len(result.extra)} extra"
            say(line if result.missed or result.extra else f"[green]{line}[/]")
            for value in sorted(result.missed):
                say(f"    [red]missed by the tool:[/] {safe(defang(value))}")
            for value in sorted(result.extra):
                say(f"    [yellow]found only by the tool:[/] {safe(defang(value))}")

    _print_gate_summary(totals, checked)


@app.command("split-sets")
def split_sets(
    source: SourceFolder,
    out: OutFolder,
    seed: Seed,
    heldout: HeldoutCount = 50,
    gate: GateCount = 50,
    exclude: Exclude = None,
) -> None:
    """Pick a held-out set (week 5) and a gate set (week 3) at random, and fingerprint them."""
    try:
        split = pick_sets(source, heldout, gate, seed, exclude or [])
        record = write_sets(split, out, seed=seed, source=source)
    except (ValueError, FileExistsError) as error:
        say(f"[red]{safe(str(error))}[/]")
        raise typer.Exit(1) from None
    by_id = split.excluded_by_message_id
    used = f"{split.excluded} already used" + (f", {by_id} of them by Message-ID" if by_id else "")
    say(
        f"Picked at random with seed {seed} from {split.found} emails "
        f"({split.duplicates} duplicates, {used}, {split.skipped} skipped)."
    )
    for name, label in ((HELDOUT, "Held-out (week 5)"), (GATE, "Gate (week 3)")):
        if name in record["sets"]:
            details = record["sets"][name]
            folder = safe(str(out / name))
            say(f"  {label}: {details['emails']} emails in {folder}")
            say(f"    fingerprint {details['fingerprint']}")
    if HELDOUT in record["sets"]:
        say(
            "Write the seed and the held-out fingerprint down now. "
            f"Do not run phishtriage on {safe(str(out / HELDOUT))} until week 5."
        )
        say(f"To check it later: cd {safe(str(out))} and run sha256sum -c heldout.sha256")


@app.command("fetch-label")
def fetch_label(
    label: LabelName,
    user: ImapUser,
    out: ExportFolder = None,
    search: GmailSearch = None,
    newest: Newest = None,
    list_only: ListOnly = False,
    host: ImapHost = GMAIL_HOST,
) -> None:
    """Download emails from a Gmail label or search as .eml files. Read-only: changes nothing."""
    # Both checks come before the password is asked for
    if out is None and not list_only:
        say("[red]Give a folder to save into, or use --list to only look[/]")
        raise typer.Exit(1)
    if out is not None and not list_only and has_files(out):
        say(f"[red]{safe(str(out))} already has files: choose a new folder[/]")
        raise typer.Exit(1)
    password = typer.prompt("App password (hidden as you type)", hide_input=True)
    try:
        client = connect(user, password.replace(" ", ""), host)  # Google shows it in 4 groups
    except ExportError as error:
        say(f"[red]{safe(str(error))}[/]")
        raise typer.Exit(1) from None
    try:
        if list_only:
            listed = list_label(client, label, search, newest, progress=_show_imap_progress)
            _print_listed(listed)
            return
        assert out is not None  # checked above; tells the type checker too
        result = export_label(client, label, out, search, newest, progress=_show_imap_progress)
    except ExportError as error:
        say(f"[red]{safe(str(error))}[/]")
        raise typer.Exit(1) from None
    finally:
        with contextlib.suppress(Exception):
            client.logout()
    say(
        f"Downloaded {result.saved} emails into {safe(str(out))}. "
        f"Nothing in Gmail was changed (the {_mailbox_kind(label)} was opened read-only).",
        soft_wrap=True,
    )
    if result.failed:
        say(f"[yellow]{result.failed} emails could not be downloaded.[/]")
    if not result.saved and not result.failed:
        if search:
            say("[yellow]No emails match the search, so nothing was downloaded.[/]")
        elif _mailbox_kind(label) == "mailbox":
            say("[yellow]The inbox is empty.[/]")
        else:
            say("[yellow]The label is empty: add the label to some emails in Gmail.[/]")
    say("When you are done, delete the app password at myaccount.google.com/apppasswords")


def _mailbox_kind(label: str) -> str:
    """What Gmail calls it: INBOX is a mailbox (in any case, as IMAP says), the rest labels."""
    return "mailbox" if label.upper() == "INBOX" else "label"


def _show_imap_progress(done: int, total: int) -> None:
    """A progress line every PROGRESS_EVERY emails and at the end (week 4).

    Gmail sends one email at a time, so 120 emails take a while: without this, the screen
    stays still and looks stuck. Counts only: no sender or subject is printed here.
    "done" includes an email Gmail did not send; the summary after says how many.
    """
    if done % PROGRESS_EVERY == 0 or done == total:
        say(f"[dim]  {done} of {total} emails done[/]")


def _print_listed(listed: list[Listed]) -> None:
    """The --list table. Header text comes from the emails, so every cell is escaped."""
    if not listed:
        say("No emails match. Nothing was downloaded.")
        return
    table = Table(title=f"{len(listed)} emails match (newest first)", title_justify="left")
    table.add_column("Date", no_wrap=True)
    table.add_column("From", no_wrap=True, overflow="ellipsis", max_width=45)
    table.add_column("Subject", no_wrap=True, overflow="ellipsis", max_width=70)
    for row in listed:
        table.add_row(safe(row.date), safe(row.sender), safe(row.subject))
    say(table)
    say(
        "Nothing was downloaded. If every line is an email you know is genuine, run the "
        "same command with a folder and without --list. This list is your mail: keep it private."
    )


@app.command()
def calibrate(legit: LegitStats, phish: PhishStats, scoring: ScoringFile = None) -> None:
    """Week 4: score two --stats runs again with a candidate scoring file. Reads no email."""
    try:
        config = load_scoring(scoring)
        halves = compare_halves(load_stats(legit), load_stats(phish), config)
    except (ScoringError, CalibrationError) as error:
        say(f"[bold red]{safe(str(error))}[/]", soft_wrap=True)
        raise typer.Exit(1) from None
    say(
        "[bold]Calibration: NOT blind.[/] Both halves were seen while building; "
        "week 5's held-out sets decide."
    )
    say(f"Candidate: {safe(config.source)} (SHA-256 {config.sha256[:12]})", soft_wrap=True)
    for half in halves:
        stats = half.stats
        say(
            f"{half.name}: {safe(str(stats.path))}, {len(stats.rows)} files, measured with "
            f"{safe(stats.scoring_source)} ({safe(stats.scoring_sha256[:12])})",
            soft_wrap=True,
        )
    _print_verdict_table(halves)
    _print_signal_table(halves, config)
    genuine, phishing = halves
    highest = sorted((row.total for row in genuine.rescored), reverse=True)[:10]
    lowest = sorted(row.total for row in phishing.rescored)[:10]
    say(f"Highest genuine scores: {', '.join(map(str, highest)) or '-'}")
    say(f"Lowest phishing scores: {', '.join(map(str, lowest)) or '-'}")
    say(
        f"Suspicious from {config.suspicious}, malicious from {config.malicious} "
        "(the candidate's thresholds)."
    )
    for half in halves:
        if half.stats.scoring_sha256 == config.sha256 and (wrong := half.mismatches()):
            say(
                f"[yellow]{wrong} {half.name.lower()} files score differently now than when "
                "they were measured with this same scoring file: the stats file may come from "
                "another version of PhishTriage.[/]"
            )


def _print_verdict_table(halves: tuple[Half, Half]) -> None:
    """Each half's verdicts as measured and under the candidate, and the two rates."""
    table = Table(title="Verdicts (files)", title_justify="left")
    for column in ("", "Scoring", "Likely benign", "Suspicious", "Malicious"):
        table.add_column(column, justify="right" if column not in ("", "Scoring") else "left")
    for half in halves:
        for label, counts in (("as measured", half.measured()), ("candidate", half.candidate())):
            table.add_row(half.name, label, *(str(counts[v]) for v in counts))
    say(table)
    genuine, phishing = halves

    def flagged(counts: dict[str, int]) -> int:
        return counts["suspicious"] + counts["malicious"]

    total_g, total_p = len(genuine.stats.rows), len(phishing.stats.rows)
    say(
        f"Genuine flagged (suspicious or malicious): {flagged(genuine.measured())} of {total_g} "
        f"-> {flagged(genuine.candidate())} of {total_g}"
    )
    say(
        f"Phishing caught (suspicious or malicious): {flagged(phishing.measured())} of {total_p} "
        f"-> {flagged(phishing.candidate())} of {total_p}; malicious: "
        f"{phishing.measured()['malicious']} -> {phishing.candidate()['malicious']}"
    )


def _print_signal_table(halves: tuple[Half, Half], config: ScoringConfig) -> None:
    """For every signal that counted in either half: its points and how often it counted.

    A signal with 0 points still "counts" here when its findings met the evidence: that
    shows what giving it points would do.
    """
    genuine, phishing = halves
    table = Table(
        title="Signals under the candidate (files where it counted)", title_justify="left"
    )
    for column in ("Signal", "Points", "Genuine", "Phishing"):
        table.add_column(column, justify="left" if column == "Signal" else "right")
    for signal in config.signals:
        in_genuine, in_phishing = genuine.fired(signal.name), phishing.fired(signal.name)
        if in_genuine or in_phishing:
            points = "malicious" if signal.override else str(signal.points)
            table.add_row(signal.name, points, str(in_genuine), str(in_phishing))
    say(table)


@app.command()
def results(genuine: LegitStats, phish: MorePhishStats = None, scoring: ScoringFile = None) -> None:
    """Week 5: what --stats runs show, held-out runs included. Reads no email."""
    try:
        config = load_scoring(scoring)
        runs = [load_run("Genuine", genuine, config)]
        if phish is not None:
            runs.append(load_run("Phishing", phish, config))
        counts = [lookups(run) for run in runs]
    except (ScoringError, CalibrationError, ResultsError) as error:
        say(f"[bold red]{safe(str(error))}[/]", soft_wrap=True)
        raise typer.Exit(1) from None
    say(
        "[bold]Results[/] from --stats files only: no email is opened and the scoring is "
        "not changed."
    )
    say(f"Scoring: {safe(config.source)} (SHA-256 {config.sha256[:12]})", soft_wrap=True)
    for number, (run, lookup_counts) in enumerate(zip(runs, counts, strict=True)):
        _print_run(run, lookup_counts, config, genuine=number == 0)
    if len(runs) == 2:
        for both in side_by_side(*runs):
            _print_both(both, blind=all(run.heldout for run in runs))
    _print_results_signals(runs, config)


def _view_name(view: View) -> str:
    return f"{view.label} (worked out from the same run)" if view.derived else view.label


def _print_run(run: Run, counts: Lookups | None, config: ScoringConfig, *, genuine: bool) -> None:
    """One run: where it came from, its lookups, its verdicts and its rates."""
    info = run.stats.info
    say("")
    say(f"[bold]{run.name}:[/] {safe(str(run.stats.path))}", soft_wrap=True)
    if run.heldout:
        say(
            "  Held-out run (--heldout-ok): blind if this set was analysed only once, with "
            "the scoring frozen before"
        )
    else:
        say("  [yellow]NOT blind:[/] not a held-out run (made without --heldout-ok)")
    how = "without --enrich"
    if counts is not None:
        how = "with --enrich" + (" --hosts-only" if counts.hosts_only else "")
    when, made_by = safe(str(info.get("analysed_on", "?"))), safe(str(info.get("phishtriage", "?")))
    say(f"  Analysed on {when} by PhishTriage {made_by}, {how}")
    skipped = safe(str(info.get("heldout_skipped", "?")))
    say(
        f"  {run.files} files analysed, {info['emails_failed']} failed (no verdict), "
        f"{skipped} held-out skipped"
    )
    if counts is not None:
        _print_lookups(counts, run.files)
    if run.rebuilt == run.files:
        say(f"  Scores rebuilt from their rule names alone: {run.rebuilt} of {run.files} match")
    else:
        say(
            f"  [yellow]Scores rebuilt from their rule names alone: only {run.rebuilt} of "
            f"{run.files} match. The stats file was changed or comes from another version.[/]"
        )

    table = Table(title=f"{run.name}: verdicts (files)", title_justify="left")
    for column in ("View", "Likely benign", "Suspicious", "Malicious"):
        table.add_column(column, justify="left" if column == "View" else "right")
    for view in run.views:
        table.add_row(_view_name(view), *(str(count) for count in view.counts().values()))
    say(table)

    for view in run.views:
        rate, name = view.flagged(), _view_name(view)
        if genuine:
            met = "met" if meets_false_positive_target(rate) else "NOT met"
            say(
                f"  Flagged, {name}: {rate.text()}. "
                f"Target under {float(FALSE_POSITIVE_TARGET):.0%} (proposal O6): {met}"
            )
            highest = sorted(view.scores, reverse=True)[:10]
            say(f"  Highest scores, {name}: {', '.join(map(str, highest)) or '-'}")
            if rate.hits:
                fired = (
                    f"{signal.name} {count}"
                    for signal in config.signals
                    if (count := view.fired(signal.name, flagged_only=True))
                )
                say(f"  Signals in the flagged files, {name}: {', '.join(fired)}")
        else:
            say(f"  Caught, {name}: {rate.text()}; malicious {view.counts()[MALICIOUS]}")
            lowest = sorted(view.scores)[:10]
            say(f"  Lowest scores, {name}: {', '.join(map(str, lowest)) or '-'}")


def _print_lookups(counts: Lookups, files: int) -> None:
    """An --enrich run's lookups: per service, then whether every lookup got an answer."""
    table = Table(title="Lookups", title_justify="left")
    columns = {
        "Service": "",
        "Planned": "planned",
        "From cache": "cache_hits",
        "API calls": "api_calls",
        "Found": "found",
        "Not found": "not_found",
        "Failed": "failed",
        "Not asked": "deferred",
        "No answer possible": "unsupported",
        "429s": "quota_errors",
    }
    for column in columns:
        table.add_column(column, justify="left" if column == "Service" else "right")
    for name, service in counts.services.items():
        label = safe(SERVICE_LABELS.get(name, name))
        table.add_row(label, *(str(service[key]) for key in list(columns.values())[1:]))
    say(table)
    if counts.complete:
        status = "complete: every planned lookup got an answer"
    else:
        status = f"[yellow]partial: {counts.unanswered} of {counts.planned} got no answer[/]"
    say(f"  Lookups {status}; {counts.quota_errors} quota errors (HTTP 429)")
    calls, hits = counts.total("api_calls"), counts.total("cache_hits")
    per_file = f" = {calls / files:.1f} a file" if files else ""
    say(f"  API calls: {calls} for {files} files{per_file}")
    share = f" ({hits / counts.planned:.0%})" if counts.planned else ""
    say(f"  From the cache: {hits} of {counts.planned} planned lookups{share}")
    for name, reason in counts.stopped.items():
        say(f"  [yellow]{safe(SERVICE_LABELS.get(name, name))} stopped:[/] {safe(reason)}")


def _print_both(both: Both, *, blind: bool) -> None:
    """Genuine and phishing in one view: the proposal's O6 measures."""
    say("")
    title = f"[bold]Genuine and phishing side by side, {both.label}[/]"
    say(title if blind else f"{title} [yellow](NOT blind: not both held-out runs)[/]")
    for name, view in (("Genuine", both.genuine), ("Phishing", both.phishing)):
        if view.derived:
            say(f"  {name}: worked out from its --enrich run, without the lookups' findings")
    table = Table()
    for column in ("Emails", "Likely benign", "Suspicious", "Malicious"):
        table.add_column(column, justify="left" if column == "Emails" else "right")
    for name, view in (("Genuine", both.genuine), ("Phishing", both.phishing)):
        table.add_row(name, *(str(count) for count in view.counts().values()))
    say(table)
    correct, false_positives = both.correct(), both.false_positives()
    say(
        f"  Correct verdicts: {correct.text()}. Target at least "
        f"{float(ACCURACY_TARGET):.0%} (proposal O6): "
        f"{'met' if meets_accuracy_target(correct) else 'NOT met'}"
    )
    say(f"  Phishing caught (recall): {both.caught().text()}")
    say(f"  Flagged that is phishing (precision): {both.precision().text()}")
    say(
        f"  Genuine flagged (false positive rate): {false_positives.text()}. Target under "
        f"{float(FALSE_POSITIVE_TARGET):.0%} (proposal O6): "
        f"{'met' if meets_false_positive_target(false_positives) else 'NOT met'}"
    )


def _print_results_signals(runs: list[Run], config: ScoringConfig) -> None:
    """For every signal that counted somewhere: its points and the files where it counted,
    in every view of every run."""
    views = [(f"{run.name}, {view.label}", view) for run in runs for view in run.views]
    table = Table(title="Signals: files where each one counted", title_justify="left")
    table.add_column("Signal")
    table.add_column("Points", justify="right")
    for title, _ in views:
        table.add_column(title, justify="right")
    for signal in config.signals:
        fired = [view.fired(signal.name) for _, view in views]
        if any(fired):
            points = "malicious" if signal.override else str(signal.points)
            table.add_row(signal.name, points, *(str(count) for count in fired))
    say("")
    if table.row_count:
        say(table)
    else:
        say("No signal counted in any file.")


@app.command()
def version() -> None:
    """Show the PhishTriage version."""
    say(__version__)


@app.command("config")
def show_config(env_file: EnvFile = DEFAULT_ENV_FILE) -> None:
    """Show which lookup services are ready. Keys and your addresses are never shown."""
    settings = load_settings(env_file)
    if settings.env_file is not None:
        say(f"Settings file: {safe(str(settings.env_file))}")
    else:
        say(
            f"Settings file: {safe(str(env_file))} not found "
            "(copy .env.example to .env and add your keys)"
        )

    table = Table(title="Threat-intel lookups")
    table.add_column("Service")
    table.add_column("Key")
    table.add_column("Status")
    for service, variable in SERVICE_KEYS.items():
        missing = settings.missing_key(service)
        if variable is None:
            key = "not needed"
        else:
            key = f"{variable} set" if missing is None else f"{variable} missing"
        status = "[green]ready[/green]" if missing is None else "[yellow]off[/yellow]"
        table.add_row(service, key, status)
    say(table)

    count = len(settings.my_addresses.reveal())  # only the number is shown
    say(
        f"Your addresses: {count} in PHISHTRIAGE_MY_ADDRESSES "
        "(never shown; removed from every value before a lookup)"
    )
    say(f"Cache: {safe(str(settings.cache_path))}")
    for warning in settings.warnings:
        say(f"[yellow]Warning:[/yellow] {safe(warning)}")


@app.command("cache")
def show_cache(env_file: EnvFile = DEFAULT_ENV_FILE, clear: ClearCache = False) -> None:
    """Show what the lookup cache holds, and the API calls made in the last 24 hours."""
    path = load_settings(env_file).cache_path
    if not path.exists():
        say(f"No cache yet at {safe(str(path))} (the first lookup run creates it)")
        return
    cache, warnings = open_cache(path)
    with cache:
        for warning in warnings:
            say(f"[yellow]Warning:[/yellow] {safe(warning)}")
        if clear:
            removed = cache.clear()
            say(
                f"Removed {removed} stored results. The log of API calls is kept: "
                "the services' own daily counts do not reset either."
            )
        stats = cache.stats()

    say(f"Cache: {safe(str(path))}")
    table = Table(title="Lookup cache")
    table.add_column("Service")
    table.add_column("Stored results", justify="right")
    table.add_column("API calls (last 24 h)", justify="right")
    for service in SERVICE_KEYS:
        row = stats.get(service, {"stored": 0, "calls_24h": 0})
        table.add_row(service, str(row["stored"]), str(row["calls_24h"]))
    say(table)


# --- week 3: enrichment in the report ----------------------------------------------------


def _enrich(
    analyses: list[EmailAnalysis],
    allowlist: Allowlist,
    settings: Settings,
    hosts_only: bool,
    max_lookups: int | None,
    dry_run: bool = False,
) -> Enrichment:
    """Run the lookups, showing the plan first and progress while they run."""

    def show_plan(plan: LookupPlan) -> None:
        counts = ", ".join(
            f"{SERVICE_LABELS[name]} {plan.count(name)}"
            for name in SERVICE_LABELS
            if plan.count(name)
        )
        say(f"\n[bold]Lookups planned:[/] {len(plan.lookups)} ({counts or 'none'})")
        if (vt := plan.count("virustotal")) and not dry_run:
            minutes = -(-vt // 4)  # rounded up
            say(
                f"[dim]  VirusTotal allows 4 a minute: up to {minutes} minute"
                f"{'' if minutes == 1 else 's'}, less for answers already in the cache. "
                "Ctrl+C is safe: answers so far are kept.[/]"
            )

    def show_progress(done: int, total: int, result: LookupResult) -> None:
        if done % PROGRESS_EVERY == 0 or done == total:
            say(f"[dim]  {done} of {total} lookups done[/]")

    enrichment = enrich(
        analyses,
        settings,
        allowlist,
        hosts_only=hosts_only,
        max_lookups=max_lookups,
        progress=show_progress,
        on_plan=show_plan,
        dry_run=dry_run,
    )
    for warning in enrichment.warnings:
        say(f"[yellow]Warning:[/yellow] {safe(warning)}")
    return enrichment


def _print_dry_run(enrichment: Enrichment, emails: int) -> None:
    """What a real run would send, and how long VirusTotal would take. Nothing was sent."""
    plan = enrichment.plan
    plural = "" if emails == 1 else "s"
    say(f"\n[bold]Dry run for {emails} email{plural}: nothing was sent.[/]")
    for name, reason in plan.services_off.items():
        say(f"  [yellow]{SERVICE_LABELS[name]} off:[/] {safe(reason)}")
    if not plan.lookups:
        say("  Nothing to look up: run without --dry-run to see the reasons per IOC.")
        return
    answered = len(plan.lookups) - sum(enrichment.to_send.values())
    say(f"  Already answered in the cache: {answered} of {len(plan.lookups)}")
    for name, count in enrichment.to_send.items():
        budget = enrichment.budgets.get(name)
        used = enrichment.calls_24h.get(name, 0)
        line = f"  {SERVICE_LABELS[name]}: {count} to send"
        if budget is not None:
            line += f" ({budget - used} of today's {budget} left)"
            if count > budget - used:
                line += " [yellow]more than is left today: the rest waits for a later run[/]"
        if name == "virustotal" and count:
            minutes = -(-count // 4)
            line += f", about {minutes} minute{'' if minutes == 1 else 's'} at 4 a minute"
        say(line)


def _print_enrichment_summary(enrichment: Enrichment) -> None:
    """Per service: what the run asked, what came from the cache, what went wrong."""
    console.rule("[bold]Threat-intel lookups")
    plan = enrichment.plan
    if not plan.lookups:  # nothing was asked: an all-zero table would only confuse
        for name, reason in plan.services_off.items():
            say(f"  [yellow]{SERVICE_LABELS[name]} off:[/] {safe(reason)}")
        say("  Nothing to look up: the reasons are in each email's tables.")
        return
    table = Table(title_justify="left")
    columns = (
        "Service",
        "Planned",
        "From cache",
        "API calls",
        "Found",
        "Not found",
        "Failed",
        "Not asked",
        "No answer possible",
        "429s",
    )
    for column in columns:
        table.add_column(column, justify="left" if column == "Service" else "right")
    for name, label in SERVICE_LABELS.items():
        if name in plan.services_off:
            continue
        s = enrichment.stats.get(name, ServiceStats())
        numbers = (
            plan.count(name),
            s.cache_hits,
            s.api_calls,
            s.found,
            s.not_found,
            s.failed,
            s.deferred,
            s.unsupported,
            s.quota_errors,
        )
        table.add_row(label, *(str(number) for number in numbers))
    say(table)
    if "rdap" in enrichment.stats:
        say(
            "  [dim]RDAP's API calls include 1 for IANA's list of servers when it is "
            "downloaded (once in 30 days); the other columns count your domains only.[/]"
        )

    for name, reason in plan.services_off.items():
        say(f"  [yellow]{SERVICE_LABELS[name]} off:[/] {safe(reason)}")
    for name, reason in enrichment.stopped.items():
        say(f"  [yellow]{SERVICE_LABELS[name]} stopped:[/] {safe(reason)}")
    if enrichment.calls_24h:
        used = []
        for name, calls in enrichment.calls_24h.items():
            budget = enrichment.budgets.get(name)
            limit = f"of {budget}" if budget is not None else "(no daily limit)"
            used.append(f"{SERVICE_LABELS[name]} {calls} {limit}")
        say(f"  API calls in the last 24 hours: {', '.join(used)}")

    if unanswered := enrichment.unanswered():
        say(
            f"  [yellow]Enrichment partial: {unanswered} lookups got no answer.[/] Run again "
            "later: answers already received come from the cache, at no cost."
        )
    else:
        say("  [green]Enrichment complete:[/] every planned lookup was answered.")


def _write_stats(
    options: RunOptions,
    report: Report,
    enrichment: Enrichment | None,
    emails: int,
    emails_failed: int,
    heldout_skipped: int = 0,
) -> None:
    """The run's counts as JSON, for the gates and for calibration (step 15).

    No IOC value and no file name is ever written: only numbers, verdict names and rule
    names. "scores" is every file's score, highest first, without names, which is
    enough to see where a threshold would cut. "rules" counts the files where a rule
    found something; "signals" the files where a signal added points to the verdict.
    """
    analysed = [file for file in report.files if file.verdict is not None]
    rows, dropped = stats_rows(report)
    rules: Counter[str] = Counter()
    signals: Counter[str] = Counter()
    for file in analysed:
        rules.update({finding.rule for email in file.emails for finding in email.findings})
        assert file.verdict is not None
        signals.update({r.signal for r in file.verdict.reasons if r.points or r.override})
    data: dict[str, object] = {
        "phishtriage": __version__,
        "analysed_on": report.generated_at[:10],
        "emails": emails,
        "emails_failed": emails_failed,  # the gate's "no crashes": could not be analysed
        "heldout_skipped": heldout_skipped,  # not analysed: in a held-out set (week 4)
        "scoring": {"source": report.scoring_source, "sha256": report.scoring_sha256},
        "verdicts": {
            verdict: sum(1 for file in analysed if file.verdict and file.verdict.verdict == verdict)
            for verdict in sorted(VERDICT_RANK, key=VERDICT_RANK.__getitem__, reverse=True)
        },
        "scores": sorted((file.verdict.total for file in analysed if file.verdict), reverse=True),
        "rules": dict(sorted(rules.items())),
        "signals": dict(sorted(signals.items())),
        "enriched": enrichment is not None,
        "heldout_ok": options.heldout_ok,  # calibrate refuses a held-out run (week 4)
        "rows_version": STATS_ROWS_VERSION,
        "files": rows,  # for calibrate: score, verdict, findings; no names, no IOCs
        "facts_dropped": dropped,  # facts that were not a number or a fixed word (0)
    }
    if enrichment is not None:
        plan = enrichment.plan
        data |= {
            "hosts_only": options.hosts_only,
            "max_lookups": options.max_lookups,
            "lookups_planned": len(plan.lookups),
            "unanswered": enrichment.unanswered(),
            "quota_errors": sum(stats.quota_errors for stats in enrichment.stats.values()),
            "services": {
                name: {"planned": plan.count(name), **asdict(stats)}
                for name, stats in enrichment.stats.items()
            },
            "services_off": plan.services_off,
            "stopped": enrichment.stopped,
            "calls_last_24h": enrichment.calls_24h,
            "daily_budget": enrichment.budgets,
        }
    path = options.stats
    assert path is not None
    try:
        path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    except OSError as error:
        say(f"[yellow]Could not write {safe(str(path))}: {type(error).__name__}[/]", soft_wrap=True)
    else:
        say(f"  Counts written to {safe(str(path))}", soft_wrap=True)


def _print_gate_summary(totals: dict[str, Comparison], checked: int) -> None:
    """Totals per IOC type over every checked email, with recall and precision."""
    table = Table(title=f"Week 2 gate: {checked} hand-checked emails", title_justify="left")
    for column in ("IOC type", "Matched", "Missed", "Extra", "Recall", "Precision"):
        table.add_column(column, justify="left" if column == "IOC type" else "right")
    for section, total in totals.items():
        matched, missed, extra = len(total.matched), len(total.missed), len(total.extra)
        table.add_row(
            section,
            str(matched),
            str(missed),
            str(extra),
            _percent(matched, matched + missed),  # of what you found, how much the tool found
            _percent(matched, matched + extra),  # of what the tool found, how much was right
        )
    say()
    say(table)


def _percent(part: int, whole: int) -> str:
    return f"{100 * part / whole:.0f}%" if whole else "-"
