"""The terminal report, printed from the report model (week 4, step 10).

Until step 9 the CLI printed straight from EmailAnalysis. Now it prints a report.Report, so
the terminal shows what every other format will show: your addresses REDACTED, every link
and address defanged, control characters written out.

What is left to do here is Rich's own syntax. Rich reads [square brackets] as formatting,
and defanged values are full of them ("evil[.]test"), so every piece of text goes through
display.safe() (escape() for Rich markup; visible() again, which changes nothing in text
the model already cleaned, and is kept as a second guard).

highlight=False on every print: by default Rich colours numbers and words it guesses are
code, so "mailer-7731[.]test" came out with a blue 7731 and "header(s)" in pink (seen in
step 8's screenshots). A report should only colour what it means to colour.
"""

from __future__ import annotations

from collections.abc import Callable
from functools import partial

from rich.console import Console
from rich.table import Table
from rich.text import Text

from ..display import safe
from ..report import Answer, AttachmentView, EmailReport, FileReport, IOCView, Report, ScoreView
from ..scoring import LIKELY_BENIGN, MALICIOUS, SUSPICIOUS
from .common import count_iocs, ioc_label, points, ranked, sender, sender_ip

RESULT_COLOURS = {"pass": "green", "fail": "red", "softfail": "yellow", "none": "yellow"}
VERDICT_STYLES = {MALICIOUS: "bold red", SUSPICIOUS: "bold yellow", LIKELY_BENIGN: "bold green"}

# With more URLs than this, the IOC table shows one row per domain (unless --all-urls)
MAX_URLS_LISTED = 10

Printer = Callable[..., None]


def print_report(report: Report, console: Console, all_urls: bool = False) -> None:
    """Every file in the run: analysed files first, then the ones that failed."""
    for file in report.files:
        print_file(file, console, enriched=report.enriched, all_urls=all_urls)


def print_summary(report: Report, console: Console) -> None:
    """One line per file, worst first: the triage order for a folder (step 13)."""
    table = Table(title="Summary (worst first)", title_justify="left")
    table.add_column("Verdict", no_wrap=True)
    table.add_column("Score", justify="right")
    table.add_column("File", overflow="fold")
    table.add_column("Decided by", overflow="fold")
    for file in ranked(report.files):
        if file.verdict is None:
            table.add_row("[bold]NO VERDICT[/]", "-", safe(file.name), "could not be analysed")
            continue
        style = VERDICT_STYLES[file.verdict.verdict]
        verdict = f"[{style}]{file.verdict.verdict.upper()}[/]"
        decided = f"forwarded email {safe(file.decided_by)}" if file.decided_by else "the email"
        table.add_row(verdict, str(file.verdict.total), safe(file.name), decided)
    console.print()
    console.print(table, highlight=False)


def print_file(
    file: FileReport, console: Console, enriched: bool = False, all_urls: bool = False
) -> None:
    """One file: its email, then each email forwarded inside it, each with a full report.

    partial() fixes some arguments of a function in advance (Java: a lambda that calls
    console.print(..., false)), so every print below has highlight=False.
    """
    out: Printer = partial(console.print, highlight=False)
    if file.error:
        # soft_wrap: an error often holds a path; Rich must not break it with a newline
        out(f"[bold red]Could not analyse {safe(file.name)}: {safe(file.error)}[/]", soft_wrap=True)
        return
    for email in file.emails:
        if email.level == 0:
            title = f"[bold]{safe(file.name)}"
        else:
            where = f"{safe(email.where)} inside {safe(file.name)}"
            title = f"[bold cyan]Forwarded email {where} (level {email.level})"
        console.rule(Text.from_markup(title))  # Text: a title Rich will not highlight
        print_email(email, file, out, enriched, all_urls)


def print_email(
    email: EmailReport, file: FileReport, out: Printer, enriched: bool, all_urls: bool
) -> None:
    _print_score(email, file, out)
    _print_summary(email, out, enriched)
    _print_authentication(email, out)
    if email.attachments:
        _print_attachments(email.attachments, out, enriched)
    if email.iocs:
        _print_iocs(email.iocs, out, enriched, all_urls)
    out("\n[bold]Findings[/]")
    if email.findings:
        # A grid, like the reasons: a long finding wraps under its own text, not at the
        # left edge (seen in step 10's screenshot of the forwarded email)
        grid = Table.grid(padding=(0, 1))
        grid.add_column(no_wrap=True)
        grid.add_column()
        for finding in email.findings:
            grid.add_row("  [red]![/]", f"{safe(finding.rule)}: {safe(finding.detail)}")
        out(grid)
    else:
        out("  [green]none so far[/]")
    if email.not_written:
        out(f"\n[dim]Not written yet: {safe(', '.join(email.not_written))}[/]")
    if email.defects:
        out(f"[dim]Parsing notes: {safe(', '.join(email.defects))}[/]")
    out()


# --- the parts of one email's report -----------------------------------------------------------


def _print_score(email: EmailReport, file: FileReport, out: Printer) -> None:
    """Verdict, score, ATT&CK and every reason, at the top (step 8)."""
    score = email.score
    out(_verdict_line("Verdict", score))
    out(f"Based on   {safe(score.basis_text)}")
    if score.attack:
        out(f"ATT&CK     {safe(', '.join(f'{tag.id} {tag.name}' for tag in score.attack))}")
    if email.level == 0 and file.decided_by and file.verdict is not None:
        where = safe(file.decided_by)
        line = _verdict_line("File", file.verdict)
        out(f"{line}  decided by forwarded email {where}: a forward is judged by what it carries")
    if not score.reasons:
        out("Reasons    none")
        out()
        return
    out("[bold]Reasons[/]")
    # A grid (a table without borders) keeps a long reason indented when it wraps
    grid = Table.grid(padding=(0, 2))
    grid.add_column(justify="right", min_width=10, no_wrap=True)
    grid.add_column()
    for reason in score.reasons:
        text = f"{safe(reason.label)} ({safe(', '.join(reason.rules))})"
        if reason.note:
            text += f": [dim]{safe(reason.note)}[/]"
        grid.add_row(points(reason), text)
    out(grid)
    out()


def _verdict_line(title: str, score: ScoreView) -> str:
    style = VERDICT_STYLES[score.verdict]
    return f"{title:<10} [{style}]{score.verdict.upper()}[/]  {score.total}/100"


def _print_summary(email: EmailReport, out: Printer, enriched: bool) -> None:
    summary = Table(show_header=False, box=None, padding=(0, 2))
    summary.add_row("From", safe(sender(email)))
    summary.add_row("Reply-To", safe(", ".join(email.reply_to) or "-"))
    summary.add_row("Return-Path", safe(email.return_path or "-"))
    summary.add_row("Subject", safe(email.subject or "-"))
    summary.add_row("Date", safe(email.date or "-"))
    summary.add_row("Message-ID", safe(email.message_id or "-"))
    summary.add_row("Received hops", str(email.hops))
    summary.add_row("Sender IP", safe(sender_ip(email)))
    summary.add_row("IOCs found", count_iocs(email.iocs))
    if enriched:
        looked = sum(1 for ioc in email.iocs if ioc.looked_up)
        text = f"{looked} of {len(email.iocs)} IOCs looked up (the reasons for the rest are below)"
        summary.add_row("Lookups", text)
    else:
        skipped = sum(1 for ioc in email.iocs if ioc.allowlisted)
        summary.add_row(
            "Lookups skipped", f"{skipped} allowlisted IOCs (still listed, not trusted)"
        )
    if email.forwarded:
        summary.add_row("Forwarded emails", f"{email.forwarded} (analysed separately below)")
    out(summary)


def _print_authentication(email: EmailReport, out: Printer) -> None:
    auth = email.auth
    out(f"\n[bold]Authentication[/] ({safe(auth.source)})")
    for name, result in (("SPF", auth.spf), ("DKIM", auth.dkim), ("DMARC", auth.dmarc)):
        out(f"  {name:<6}[{RESULT_COLOURS.get(result, 'white')}]{safe(result)}[/]")
    if auth.compauth != "unknown":  # Microsoft's own verdict, when its servers wrote one
        colour = RESULT_COLOURS.get(auth.compauth, "white")
        reason = f" (reason {auth.compauth_reason})" if auth.compauth_reason else ""
        out(f"  COMPAUTH [{colour}]{safe(auth.compauth)}[/]{safe(reason)}")


def _print_attachments(
    attachments: tuple[AttachmentView, ...], out: Printer, enriched: bool
) -> None:
    table = Table(title="Attachments", title_justify="left")
    # overflow="fold" wraps long text instead of cutting it: "Statement.pdf..." would hide
    # the ".exe" an analyst needs to see
    table.add_column("Name", overflow="fold")
    table.add_column("Declared type", overflow="fold")
    table.add_column("Real type", overflow="fold")  # from the content, by libmagic
    table.add_column("Size", justify="right")
    table.add_column("SHA-256", overflow="fold")  # never cut a hash short
    if enriched:
        table.add_column("Reputation", overflow="fold")
    for att in attachments:
        cells = [
            safe(att.name),
            safe(att.declared_type),
            safe(att.real_type or "?"),
            str(att.size),
            att.sha256,
        ]
        if enriched:
            cells.append(_answers(att.reputation))
        table.add_row(*cells)
    out()
    out(table)
    for att in attachments:
        if att.members:
            locked = " (password-protected)" if att.encrypted else ""
            out(f"  {safe(att.name)}{locked} contains: {safe(', '.join(att.members))}")


def _print_iocs(iocs: tuple[IOCView, ...], out: Printer, enriched: bool, all_urls: bool) -> None:
    """The IOC table. With --enrich, the last column shows each service's answer."""
    table = Table(title="IOCs (defanged)", title_justify="left")
    table.add_column("Type")
    table.add_column("Value", overflow="fold")  # wrap long URLs, never cut them
    table.add_column("Seen", justify="right")
    table.add_column("Found in", overflow="fold")
    table.add_column("Reputation" if enriched else "Lookup", overflow="fold")

    urls = [ioc for ioc in iocs if ioc.kind == "url"]
    grouped = len(urls) > MAX_URLS_LISTED and not all_urls
    if grouped:
        for group in _groups(urls):
            table.add_row(*_group_cells(group, enriched))
    else:
        for ioc in urls:
            table.add_row(*_ioc_cells(ioc, enriched))
    for ioc in iocs:
        if ioc.kind != "url":
            table.add_row(*_ioc_cells(ioc, enriched))
    out()
    out(table)
    if grouped:
        out(f"  [dim]{len(urls)} URLs grouped by domain. Add --all-urls to list every one.[/]")


def _ioc_cells(ioc: IOCView, enriched: bool) -> tuple[str, ...]:
    if enriched:
        last = _answers(ioc.reputation)
    else:
        last = "[dim]skip[/]" if ioc.allowlisted else "yes"
    return ioc_label(ioc.kind), safe(ioc.value), str(ioc.seen), safe(", ".join(ioc.sources)), last


def _groups(urls: list[IOCView]) -> list[list[IOCView]]:
    """URLs grouped by registered domain, in the order the domains were first seen.
    A dict keeps insertion order (Java: LinkedHashMap)."""
    groups: dict[str, list[IOCView]] = {}
    for url in urls:
        groups.setdefault(url.group, []).append(url)
    return list(groups.values())


def _group_cells(group: list[IOCView], enriched: bool) -> tuple[str, ...]:
    """One row standing for every URL on one domain."""
    count = len(group)
    value = f"{count} on {group[0].group}" if count > 1 else group[0].value
    sources = dict.fromkeys(source for url in group for source in url.sources)
    if enriched:
        last = _group_reputation(group)
    else:
        skipped = sum(1 for url in group if url.allowlisted)
        last = _yes_skip(count - skipped, skipped)
    seen = str(sum(url.seen for url in group))
    return "URLs" if count > 1 else "URL", safe(value), seen, safe(", ".join(sources)), last


def _yes_skip(to_check: int, skipped: int) -> str:
    """'yes', '[dim]skip[/]', or '3 yes, 2 skip' for a group."""
    if not skipped:
        return "yes"
    if not to_check:
        return "[dim]skip[/]"
    return f"{to_check} yes, {skipped} skip"


def _group_reputation(group: list[IOCView]) -> str:
    """For a row that stands for many URLs: how many were checked, flagged, skipped."""
    checked = sum(1 for url in group if url.looked_up and _any(url.reputation, "answered"))
    flagged = sum(1 for url in group if _any(url.reputation, "flagged"))
    skipped = sum(1 for url in group if not url.looked_up)
    parts = [f"{checked} checked"]
    if flagged:
        parts.append(f"[red]{flagged} flagged[/]")
    if skipped:
        parts.append(f"{skipped} not looked up")
    return ", ".join(parts) + " [dim](--all-urls for each)[/]"


def _any(answers: tuple[Answer, ...], flag: str) -> bool:
    return any(getattr(answer, flag) for answer in answers)


def _answers(answers: tuple[Answer, ...]) -> str:
    """One line per answer: red if it became a finding, dim if it says why not asked."""
    lines = []
    for answer in answers:
        text = safe(answer.text)
        lines.append(
            f"[red]{text}[/]" if answer.flagged else f"[dim]{text}[/]" if answer.skipped else text
        )
    return "\n".join(lines) or "-"
