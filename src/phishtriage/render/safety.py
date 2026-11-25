"""find_unsafe(): the last check on a rendered report before anyone opens it (step 11).

The report model already redacted, defanged and wrote out control characters, and the
renderers escape for their format. This module checks the finished text anyway, the way
a reader's software will see it, so a mistake in a template or a missed escape is caught
by a test (and, from step 13, stops the file being written) instead of reaching a reader:

HTML      parsed with Python's own HTMLParser. Only the tags and attributes our template
          writes are allowed, so <script>, <a href>, <img src>, onclick=... or a comment
          from an email would each be reported. The text between the tags must have no
          live link, address, domain or IP (defang_text() would change nothing), and no
          control characters. There must be exactly our Content-Security-Policy, and the
          one <style> block must be the one its hash allows.
Markdown  first turned into HTML with markdown-it (CommonMark, as GitHub, GitLab and most
          ticket systems read it, with raw HTML allowed as they allow it), then checked
          like HTML. So "<script>" that slipped through unescaped, a [link](url) or an
          <autolink> would each show up as a tag that is not allowed.
JSON      parsed, then every string in it (keys too) checked like the text of a page: a
          browser's JSON viewer or a SIEM may turn a live link into one you can click.

An allowlist (only what we write) rather than a blocklist (everything known to be bad):
a blocklist misses the trick nobody listed yet. Java comparison: OWASP's HTML sanitizers
work the same way.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from collections.abc import Iterator
from html.parser import HTMLParser

from markdown_it import MarkdownIt

from ..display import CONTROL_CHARACTERS, LAYOUT_CHARACTERS
from ..iocs import defang_text

HTML, MARKDOWN, JSON = "html", "markdown", "json"

# What our HTML template writes, and nothing else
HTML_TAGS = {"html", "head", "meta", "title", "style", "body", "main", "header", "section"}
HTML_TAGS |= {"h1", "h2", "h3", "h4", "p", "table", "thead", "tbody", "tr", "th", "td"}
HTML_TAGS |= {"ul", "li", "span", "strong", "code", "small"}
HTML_ATTRIBUTES = {"class", "lang", "charset", "name", "content", "http-equiv"}

# What markdown-it makes of our Markdown template. No attributes at all: our tables have
# no alignment (that would add style="text-align:..."), and we never write links
MARKDOWN_TAGS = {"h1", "h2", "h3", "h4", "p", "table", "thead", "tbody", "tr", "th", "td"}
MARKDOWN_TAGS |= {"ul", "li", "strong", "em", "code"}

# Newlines and tabs are how HTML and Markdown are laid out; any other control character
# in a report means something was not written out
CONTROL_OR_LAYOUT = {chr(code) for code in CONTROL_CHARACTERS + LAYOUT_CHARACTERS}
UNSAFE_CHARACTERS = CONTROL_OR_LAYOUT - set("\n\t")

MARKDOWN_PARSER = MarkdownIt("commonmark").enable("table")
STYLE_HASH = re.compile(r"style-src '(sha256-[A-Za-z0-9+/=]+)'")


def find_unsafe(text: str, kind: str) -> list[str]:
    """Every problem found in a rendered report; an empty list means it is safe to write."""
    if kind == HTML:
        checker = _Checker(HTML_TAGS, HTML_ATTRIBUTES, need_csp=True)
        checker.feed(text)
    elif kind == MARKDOWN:
        checker = _Checker(MARKDOWN_TAGS, set(), need_csp=False)
        checker.feed(MARKDOWN_PARSER.render(text))
    elif kind == JSON:
        return _check_json(text)
    else:
        raise ValueError(f"unknown report kind {kind!r}")
    checker.close()
    return checker.finish()


def _check_json(text: str) -> list[str]:
    try:
        data = json.loads(text)
    except ValueError as error:
        return [f"not valid JSON ({error})"]
    problems = []
    for value in _strings(data):
        # No newline or tab either: in JSON every one of them was meant to be written out
        if CONTROL_OR_LAYOUT & set(value):
            problems.append(f"a control character in a value: {_short(value)}")
        if defang_text(value) != value:
            problems.append(f"a live link, address, domain or IP: {_short(value)}")
    return problems


def _strings(data: object) -> Iterator[str]:
    """Every string in parsed JSON, keys included."""
    if isinstance(data, str):
        yield data
    elif isinstance(data, dict):
        for key, value in data.items():
            yield key
            yield from _strings(value)
    elif isinstance(data, list):
        for item in data:
            yield from _strings(item)


def style_hash(css: str) -> str:
    """The CSP source that allows exactly this <style> block and no other."""
    digest = hashlib.sha256(css.encode("utf-8")).digest()
    return f"sha256-{base64.b64encode(digest).decode('ascii')}"


def content_security_policy(css: str) -> str:
    """Nothing may load or run: no scripts, images, fonts, frames or form posts, and no
    style but ours. A report from a phishing email is opened by curious people."""
    return f"default-src 'none'; style-src '{style_hash(css)}'; base-uri 'none'; form-action 'none'"


class _Checker(HTMLParser):
    """Collects problems while HTMLParser reads the document (Java: a SAX handler)."""

    def __init__(self, tags: set[str], attributes: set[str], need_csp: bool) -> None:
        super().__init__(convert_charrefs=True)  # "&lt;" arrives as "<", as a browser shows it
        self.tags, self.attributes, self.need_csp = tags, attributes, need_csp
        self.problems: list[str] = []
        self.csp: list[str] = []
        self.styles: list[str] = []
        self.in_style = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag not in self.tags:
            self.problems.append(f"a <{tag}> tag")
        for name, value in attrs:
            if name not in self.attributes:
                self.problems.append(f"a {name}= attribute on <{tag}>")
            elif tag == "meta" and name == "http-equiv":
                if (value or "").lower() != "content-security-policy":
                    self.problems.append(f"a <meta http-equiv={value!r}>")
                else:
                    self.csp.append(dict(attrs).get("content") or "")
        if tag == "style":
            self.in_style = True
            self.styles.append("")

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)
        if tag == "style":
            self.in_style = False

    def handle_endtag(self, tag: str) -> None:
        if tag == "style":
            self.in_style = False

    def handle_data(self, data: str) -> None:
        if self.in_style:
            self.styles[-1] += data
            return
        if UNSAFE_CHARACTERS & set(data):
            self.problems.append(f"a control character in the text: {_short(data)}")
        if defang_text(data) != data:
            self.problems.append(f"a live link, address, domain or IP: {_short(data)}")

    def handle_comment(self, data: str) -> None:
        self.problems.append("an HTML comment")

    def handle_decl(self, decl: str) -> None:
        if decl.lower() != "doctype html":
            self.problems.append(f"a <!{decl}> declaration")

    def handle_pi(self, data: str) -> None:
        self.problems.append("a processing instruction")

    def unknown_decl(self, data: str) -> None:
        self.problems.append("an unknown declaration")

    def finish(self) -> list[str]:
        if self.need_csp:
            if len(self.csp) != 1:
                self.problems.append(f"{len(self.csp)} Content-Security-Policy tags, not 1")
            elif len(self.styles) > 1:
                self.problems.append(f"{len(self.styles)} <style> blocks, not 1")
            elif self.styles and self.csp[0] != content_security_policy(self.styles[0]):
                self.problems.append("the Content-Security-Policy does not match the style")
        elif self.styles:
            self.problems.append("a <style> block")
        return self.problems


def _short(text: str) -> str:
    text = " ".join(text.split())
    return repr(text if len(text) <= 80 else text[:77] + "...")
