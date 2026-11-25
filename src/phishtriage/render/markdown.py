"""The Markdown report, for tickets, wikis and chat (week 4, step 11).

Markdown has no escaping rules of its own: any text can turn into formatting, a link, a
table cell break or raw HTML (which GitHub, GitLab and most ticket systems let through).
So every value printed by the template is escaped by md_escape(), through Jinja's
finalize hook: Jinja calls finalize on the result of every {{ ... }} before writing it
(Java: a decorator around every write), so no value can be printed unescaped by mistake.

Two exceptions are built here, and marked by their type (MdSafe), so finalize lets them
through:
- code(): a code span, for IOC values and hashes. Inside `...` nothing is formatting and
  nothing becomes a link, and "[.]" stays readable instead of turning into "\\[.\\]".
- the template's own text (headings, "|", "**"), which is not a {{ value }}.

The template is ours; email text only ever arrives as values. A template is never built
from email text: that would be server-side template injection (Jinja runs code found in
a template).
"""

from __future__ import annotations

import re

from jinja2 import Environment, PackageLoader, StrictUndefined

from ..report import Report
from . import common

# The characters that can change what text means in the middle of a line (the template
# never starts a line with a value, so "1.", "-", "+" and ">" cannot start a list or a
# quote; safety.find_unsafe() would report the <ol> or <blockquote> if one ever did):
#   \ `        escape the next character, start code
#   * ~ #      emphasis, strikethrough (GitHub), a heading's closing marks
#   [          a link or an image: "[text](url)", "![alt](src)"
#   < &        raw HTML and autolinks, entities ("&lt;" would show as "<")
#   |          the end of a table cell
#   _          emphasis, but only at the edge of a word: CommonMark never makes
#              "phish_paypal_spoof" emphasis, so those stay readable
# A backslash before any ASCII punctuation is always allowed and shows the character.
MD_SPECIAL = re.compile(r"[\\`*~#\[<&|]|(?<![^\W_])_|_(?![^\W_])")


class MdSafe(str):
    """Text already made safe for Markdown (a code span built by code()).

    A subclass of str adds no data, only a type that finalize can recognise (Java: a
    marker type, like markupsafe.Markup does for HTML).
    """


def md_escape(value: object) -> str:
    """Escape one value for Markdown: 'evil_name.exe' -> 'evil\\_name\\.exe'."""
    if isinstance(value, MdSafe):
        return value
    return MD_SPECIAL.sub(lambda match: "\\" + match[0], str(value))


def code(value: object) -> MdSafe:
    """A code span: shown exactly as it is, never formatted, never a link.

    The fence is one backtick longer than any run of backticks inside, and a space pads
    each side when the text starts or ends with a backtick or a space (CommonMark then
    removes exactly one space from each side). A "|" is written as "\\|", which GitHub
    and markdown-it read as "|" inside a table cell instead of the end of the cell.
    """
    text = str(value).replace("|", "\\|")
    if not text:
        return MdSafe("")
    longest = max((len(run) for run in re.findall(r"`+", text)), default=0)
    fence = "`" * (longest + 1)
    pad = " " if text[0] in "` " or text[-1] in "` " else ""
    return MdSafe(f"{fence}{pad}{text}{pad}{fence}")


ENVIRONMENT = Environment(
    loader=PackageLoader("phishtriage", "render/templates"),
    autoescape=False,  # HTML escaping would be wrong here; md_escape does the job
    finalize=md_escape,
    undefined=StrictUndefined,  # a typo in the template is an error, not an empty cell
    trim_blocks=True,
    lstrip_blocks=True,
    keep_trailing_newline=True,
)
ENVIRONMENT.filters |= {"code": code}
ENVIRONMENT.globals |= {name: getattr(common, name) for name in common.__all__}


def render_markdown(report: Report) -> str:
    return ENVIRONMENT.get_template("report.md.j2").render(report=report)
