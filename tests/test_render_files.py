"""Tests for the Markdown and HTML reports and for find_unsafe() (week 4, step 11).

The snapshots in tests/snapshots are the reports as they should look. After a change that
is meant to alter them (a template, a weight in scoring.yaml), write them again with

    PHISHTRIAGE_UPDATE_SNAPSHOTS=1 pytest tests/test_render_files.py

and read the difference before keeping it. They are NOT blind: built from the fixtures.
"""

import html
import os
import re
from datetime import UTC, datetime
from pathlib import Path

import pytest
from conftest import FIXTURES, PHISH_ME
from markdown_it import MarkdownIt
from markupsafe import escape

from phishtriage.allowlist import load_allowlist
from phishtriage.analysis import analyse_file
from phishtriage.config import Secret, Settings
from phishtriage.enrich.enricher import enrich
from phishtriage.render.html import CSP, CSS, render_html
from phishtriage.render.markdown import MdSafe, code, md_escape, render_markdown
from phishtriage.render.safety import HTML, MARKDOWN, find_unsafe, style_hash
from phishtriage.report import build_report
from phishtriage.scoring import load_scoring

ALLOWLIST = load_allowlist()
CONFIG = load_scoring()
NOW = datetime(2026, 11, 24, 3, 0, tzinfo=UTC)
SNAPSHOTS = Path(__file__).parent / "snapshots"
SNAPSHOT_FIXTURES = [
    "phish_paypal_spoof.eml",
    "forwarded_phish.eml",
    "attachments_phish.eml",
    "broken_charset.eml",
]
MD = MarkdownIt("commonmark").enable("table")
ESC = chr(0x1B)


def report_of(*paths: Path, **options):
    analyses = [analyse_file(path, ALLOWLIST) for path in paths]
    return build_report(analyses, CONFIG, now=NOW, **options)


def fixtures(*names: str):
    return report_of(*(FIXTURES / name for name in names))


def shown(markdown: str) -> str:
    """The text a reader sees once Markdown is rendered (tags removed, entities decoded)."""
    return html.unescape(re.sub(r"<[^>]+>", "", MD.render(markdown))).strip()


# --- md_escape() and code() ----------------------------------------------------------------------

ESCAPES = {
    "a file name stays readable": ("phish_paypal_spoof.eml", "phish_paypal_spoof.eml"),
    "emphasis": ("*bold* _it_ x_", "\\*bold\\* \\_it\\_ x\\_"),
    "a link": ("[click](hxxp://e)", "\\[click](hxxp://e)"),
    "raw HTML": ("<script>", "\\<script>"),
    "an entity": ("&lt;", "\\&lt;"),
    "a table cell break": ("a|b", "a\\|b"),
    "strikethrough": ("~~gone~~", "\\~\\~gone\\~\\~"),
    "a heading mark": ("# h", "\\# h"),
    "a backslash and code": ("a\\b `c`", "a\\\\b \\`c\\`"),
    "defanged text": ("support[@]evil[.]test", "support\\[@]evil\\[.]test"),
}


@pytest.mark.parametrize(("text", "escaped"), ESCAPES.values(), ids=ESCAPES.keys())
def test_md_escape(text, escaped):
    assert md_escape(text) == escaped


TRICKY = [
    "*bold* _it_ x_y [l](u) ![i](s) <b>x</b> &amp; a|b ~~s~~ # h \\ `c`",
    "<script>alert(1)</script>",
    "[x]: hxxp://evil[.]test",
    "&#106;avascript&colon;",
    "a__b__c **d** __e__",
]


@pytest.mark.parametrize("text", TRICKY)
def test_escaped_text_is_shown_exactly_as_it_was(text):
    """The reader sees the original characters: nothing became formatting or a tag."""
    rendered = MD.render("x " + md_escape(text))
    assert rendered.count("<") == 2  # only <p> and </p>
    assert shown("x " + md_escape(text)) == "x " + text


@pytest.mark.parametrize(
    ("text", "span"),
    [
        ("a", "`a`"),
        ("a`b", "``a`b``"),
        ("`a", "`` `a ``"),
        (" a", "`  a `"),
        ("a|b", "`a\\|b`"),
        ("", ""),
    ],
)
def test_code(text, span):
    assert code(text) == span
    assert isinstance(code(text), MdSafe)
    assert md_escape(code(text)) == span  # finalize lets it through unchanged


@pytest.mark.parametrize("text", ["a", "a``b`", "`a`", " a ", "a|b", "hxxps://e[.]t/p?q=`x`|y"])
def test_a_code_span_shows_its_text_exactly_even_in_a_table(text):
    table = MD.render(f"| v |\n| --- |\n| {code(text)} |\n")
    (inner,) = re.findall(r"<code>(.*?)</code>", table)
    assert html.unescape(inner) == text


# --- the reports, built from every fixture -------------------------------------------------------


def all_fixtures():
    return report_of(*sorted(FIXTURES.glob("*.eml")))


def test_every_fixture_gives_safe_reports():
    report = all_fixtures()
    assert find_unsafe(render_markdown(report), MARKDOWN) == []
    assert find_unsafe(render_html(report), HTML) == []


def test_the_markdown_report():
    text = render_markdown(fixtures("phish_paypal_spoof.eml", "forwarded_phish.eml"))
    assert "| phish_paypal_spoof.eml | **MALICIOUS 100/100** | the email itself |" in text
    assert "| forwarded_phish.eml | **SUSPICIOUS 60/100** | forwarded email 1 |" in text
    assert "| From | `PayPal Security <service[@]paypal[.]com>` |" in text
    assert "| URL | `hxxps://www[.]paypal[.]com/signin` | 2 | text, html:text | yes |" in text
    assert "- `dmarc_fail`: DMARC result: fail" in text
    assert "### Forwarded email 1 (level 1)" in text
    assert "Pieces of text your addresses were removed from: 1." in text


def test_the_html_report():
    page = render_html(fixtures("phish_paypal_spoof.eml"))
    assert page.startswith("<!DOCTYPE html>")
    assert f'<meta http-equiv="Content-Security-Policy" content="{escape(CSP)}">' in page
    assert f"<style>{CSS}</style>" in page
    assert '<span class="verdict malicious">MALICIOUS 100/100</span>' in page
    assert '<td class="value">PayPal Security &lt;service[@]paypal[.]com&gt;</td>' in page
    assert "<a " not in page and " href=" not in page and "<script" not in page


def test_the_csp_allows_only_our_style():
    assert CSP.startswith("default-src 'none'; style-src 'sha256-")
    assert style_hash(CSS) in CSP
    assert style_hash(CSS + " ") not in CSP  # one character more is another style
    assert "base-uri 'none'; form-action 'none'" in CSP


def test_archive_contents_parsing_notes_and_failed_files(tmp_path):
    report = report_of(
        FIXTURES / "attachments_phish.eml",
        FIXTURES / "broken_charset.eml",
        failed=[(tmp_path / "broken.eml", "ValueError('not an email')")],
    )
    text, page = render_markdown(report), render_html(report)
    assert "- Inside Payment_Details\\[.]zip (password-protected): Payment_Details.pdf.js" in text
    assert "contains: <code>Payment_Details.pdf.js</code>" in page
    assert "Parsing notes: From header has no readable address" in text
    assert "Parsing notes: From header has no readable address" in page
    assert "| broken.eml | could not be analysed | - |" in text
    assert "Could not be analysed: ValueError('not an email')" in text
    assert "<p>Could not be analysed: ValueError(&#39;not an email&#39;)</p>" in page
    assert find_unsafe(text, MARKDOWN) == [] and find_unsafe(page, HTML) == []


INJECTION = (
    "Delivered-To: me.victim@gmail.com\n"
    'From: "<img src=x onerror=alert(1)> [x](http://evil.test)" <it@evil.test>\n'
    "To: me.victim@gmail.com\n"
    "Subject: <script>alert(1)</script> ![p](http://evil.test/p.png) `c` | a &amp; b "
    "*x* _y_ ~~z~~ # h <!-- c --> me.victim@gmail.com\n"
    "MIME-Version: 1.0\n"
    "Content-Type: multipart/mixed; boundary=b\n\n"
    "--b\nContent-Type: text/plain\n\nhello\n"
    '--b\nContent-Type: text/html; name="x.html"\n'
    'Content-Disposition: attachment; filename="<b>x</b>|`y`.html"\n\n<p>x</p>\n--b--\n'
)


def test_an_email_full_of_markup_gives_safe_reports(tmp_path):
    path = tmp_path / "injection.eml"
    path.write_text(INJECTION, encoding="utf-8")
    report = report_of(path)
    text, page = render_markdown(report), render_html(report)
    assert find_unsafe(text, MARKDOWN) == []
    assert find_unsafe(page, HTML) == []
    assert PHISH_ME not in text and PHISH_ME not in page
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page
    assert "&lt;img src=x onerror=alert(1)&gt;" in page
    assert (
        "| Subject | \\<script>alert(1)\\</script> !\\[p](hxxp://evil\\[.]test/p\\[.]png)" in text
    )
    (subject,) = re.findall(r"^\| Subject \| (.*) \|$", text, re.MULTILINE)
    assert shown(subject) == (
        "<script>alert(1)</script> ![p](hxxp://evil[.]test/p[.]png) `c` | a &amp; b "
        "*x* _y_ ~~z~~ # h <!-- c --> REDACTED"
    )


KEY = Secret("k" * 64)


def test_an_enriched_report(phish_email, tmp_path, fake_apis):
    fake_apis(created="2026-11-13T09:00:00Z")
    analysis = analyse_file(phish_email, ALLOWLIST)
    settings = Settings(
        cache_path=tmp_path / "cache.sqlite3",
        vt_api_key=KEY,
        abuseipdb_api_key=KEY,
        abusech_auth_key=KEY,
    )
    enrichment = enrich([analysis], settings, ALLOWLIST, sleep=lambda _: None, jitter=lambda: 0.0)
    report = build_report([analysis], CONFIG, enrichment=enrichment, now=NOW)
    text, page = render_markdown(report), render_html(report)
    assert find_unsafe(text, MARKDOWN) == [] and find_unsafe(page, HTML) == []
    assert "With reputation lookups." in text
    assert "| Type | Value | Seen | Found in | Reputation |" in text
    assert "VirusTotal: 5 of 95 engines: malicious" in text
    assert '<li class="flagged">VirusTotal: 5 of 95 engines: malicious</li>' in page
    assert '<li class="skipped">not looked up: contains your address: not sent' in page
    assert "<th>Reputation</th>" in page
    assert PHISH_ME not in text and PHISH_ME not in page


# --- find_unsafe() reports what must never be in a report ----------------------------------------


def good_page() -> str:
    return render_html(fixtures("phish_paypal_spoof.eml"))


HTML_PROBLEMS = {
    "a script": ("<script>alert(1)</script>", "a <script> tag"),
    "a link": ('<a href="x">x</a>', "a href= attribute on <a>"),
    "an image": ('<img src="x">', "a <img> tag"),
    "an event handler": ('<p onclick="x">x</p>', "a onclick= attribute on <p>"),
    "an inline style": ('<p style="color:red">x</p>', "a style= attribute on <p>"),
    "a self-closing tag": ("<br/>", "a <br> tag"),
    "a comment": ("<!-- hidden -->", "an HTML comment"),
    "a live domain": ("<p>visit evil.com</p>", "a live link, address, domain or IP"),
    "a control character": (f"<p>x{ESC}y</p>", "a control character in the text"),
    "a refresh": ('<meta http-equiv="refresh" content="0">', "a <meta http-equiv='refresh'>"),
    "a second CSP": ('<meta http-equiv="Content-Security-Policy" content="x">', "2 Content-"),
    "a second style": ("<style>body {}</style>", "2 <style> blocks, not 1"),
    "a self-closing style": ("<style/>", "2 <style> blocks, not 1"),
    "a processing instruction": ("<?php x ?>", "a processing instruction"),
    "CDATA": ("<![CDATA[x]]>", "an unknown declaration"),
    "another doctype": ("<!DOCTYPE other>", "a <!DOCTYPE other> declaration"),
}


@pytest.mark.parametrize(("added", "problem"), HTML_PROBLEMS.values(), ids=HTML_PROBLEMS.keys())
def test_find_unsafe_html(added, problem):
    page = good_page().replace("</main>", f"{added}</main>")
    problems = find_unsafe(page, HTML)
    assert any(found.startswith(problem) for found in problems), problems


def test_a_changed_style_or_a_missing_csp_is_reported():
    page = good_page()
    changed = page.replace("#c62828", "#000000")
    assert find_unsafe(changed, HTML) == ["the Content-Security-Policy does not match the style"]
    no_csp = re.sub(r'<meta http-equiv="Content-Security-Policy"[^>]*>', "", page)
    assert find_unsafe(no_csp, HTML) == ["0 Content-Security-Policy tags, not 1"]


MARKDOWN_PROBLEMS = {
    "a link": ("[x](hxxp://e)", "a <a> tag"),
    "an autolink": ("<http://evil.test>", "a <a> tag"),
    "an image": ("![p](hxxp://e/p.png)", "a <img> tag"),
    "raw HTML": ("<b>x</b>", "a <b> tag"),
    "a numbered list": ("1. item", "a <ol> tag"),
    "a quote": ("> quote", "a <blockquote> tag"),
    "a live domain": ("see evil.test", "a live link, address, domain or IP"),
    "a style": ("<style>x</style>", "a <style> tag"),
}


@pytest.mark.parametrize(
    ("added", "problem"), MARKDOWN_PROBLEMS.values(), ids=MARKDOWN_PROBLEMS.keys()
)
def test_find_unsafe_markdown(added, problem):
    text = render_markdown(fixtures("phish_paypal_spoof.eml")) + f"\n{added}\n"
    problems = find_unsafe(text, MARKDOWN)
    assert any(found.startswith(problem) for found in problems), problems


def test_a_style_block_in_markdown_is_reported_as_such():
    assert "a <style> block" in find_unsafe("text\n\n<style>x</style>\n", MARKDOWN)


def test_a_long_problem_is_shortened():
    (problem,) = find_unsafe("x " * 60 + "evil.test", MARKDOWN)
    assert problem.endswith("...'") and len(problem) < 130


def test_an_unknown_kind():
    with pytest.raises(ValueError, match="unknown report kind 'pdf'"):
        find_unsafe("", "pdf")


# --- snapshots -------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "render"), [("report.md", render_markdown), ("report.html", render_html)]
)
def test_snapshot(name, render):
    text = render(fixtures(*SNAPSHOT_FIXTURES))
    path = SNAPSHOTS / name
    if os.environ.get("PHISHTRIAGE_UPDATE_SNAPSHOTS") == "1":
        path.parent.mkdir(exist_ok=True)
        path.write_text(text, encoding="utf-8")
    assert text == path.read_text(encoding="utf-8"), (
        f"{name} changed. If that was meant, run "
        "PHISHTRIAGE_UPDATE_SNAPSHOTS=1 pytest tests/test_render_files.py and read the diff"
    )


def test_a_typo_in_a_template_is_an_error_not_an_empty_cell():
    """StrictUndefined (Java: a NullPointerException instead of printing "null")."""
    from jinja2 import UndefinedError

    from phishtriage.render import html as html_renderer
    from phishtriage.render import markdown as markdown_renderer

    for environment in (markdown_renderer.ENVIRONMENT, html_renderer.ENVIRONMENT):
        with pytest.raises(UndefinedError):
            environment.from_string("{{ report.no_such_field }}").render(report=all_fixtures())


def test_our_css_is_written_exactly_as_hashed(monkeypatch):
    """Markup tells autoescape the CSS is ours. Without it an apostrophe would be written
    as &#39;, the browser would read a different style, and its hash would not match."""
    from phishtriage.render import html as html_renderer
    from phishtriage.render.safety import content_security_policy

    css = CSS + "\nbody::after { content: 'x'; }"
    monkeypatch.setattr(html_renderer, "CSS", css)
    monkeypatch.setattr(html_renderer, "CSP", content_security_policy(css))
    page = render_html(fixtures("legit_newsletter.eml"))
    assert f"<style>{css}</style>" in page
    assert find_unsafe(page, HTML) == []


def test_text_after_a_self_closing_style_is_still_checked():
    page = good_page().replace("</main>", "<style/><p>visit evil.com</p></main>")
    problems = find_unsafe(page, HTML)
    assert any(problem.startswith("a live link") for problem in problems), problems
