"""The HTML report: one file, opened in any browser (week 4, step 11).

Safe to open because of three layers:
1. The report model (step 9): addresses redacted, links defanged, control characters
   written out. The template never makes a link, so nothing in the page can be clicked.
2. Jinja's autoescape: every {{ value }} has & < > " ' turned into entities, so text from
   an email can never become a tag or leave an attribute.
3. A Content-Security-Policy in the page: nothing may load or run (no scripts, images,
   fonts, frames, form posts), and the only style allowed is our own <style> block, named
   by its SHA-256 hash. If an injection ever got through 1 and 2, the browser would
   still refuse to run or fetch anything.

safety.find_unsafe() then checks the finished page (step 11's tests, and step 13 before
writing a file).
"""

from __future__ import annotations

from jinja2 import Environment, PackageLoader, StrictUndefined
from markupsafe import Markup

from ..report import Report
from . import common
from .safety import content_security_policy

# No "<", ">" or "&" in here: inside <style> the browser reads them as they are, and our
# own text should not need escaping rules to be correct. Light and dark mode follow the
# reader's system setting.
CSS = """
:root { color-scheme: light dark; --line: #8884; --muted: #888; }
body { font: 15px/1.5 system-ui, sans-serif; margin: 2rem auto; max-width: 72rem; padding: 0 1rem; }
h1, h2, h3, h4 { line-height: 1.2; }
h2 { border-top: 2px solid var(--line); padding-top: 1rem; margin-top: 2.5rem; }
table { border-collapse: collapse; margin: 0.5rem 0 1rem; width: 100%; }
th, td { border: 1px solid var(--line); padding: 0.3rem 0.5rem; text-align: left; }
th, td { vertical-align: top; }
th { background: #8881; }
td.value, code { font-family: ui-monospace, Menlo, monospace; font-size: 13px; }
td.value, code { overflow-wrap: anywhere; }
.verdict { font-weight: 700; padding: 0.1rem 0.5rem; border-radius: 4px; color: #fff; }
.malicious { background: #c62828; }
.suspicious { background: #b26a00; }
.likely-benign { background: #2e7d32; }
.flagged { color: #e53935; font-weight: 600; }
.skipped, .note, small { color: var(--muted); }
""".strip()

CSP = content_security_policy(CSS)

ENVIRONMENT = Environment(
    loader=PackageLoader("phishtriage", "render/templates"),
    autoescape=True,  # every value: & < > " ' become entities
    undefined=StrictUndefined,
    trim_blocks=True,
    lstrip_blocks=True,
    keep_trailing_newline=True,
)
ENVIRONMENT.globals |= {name: getattr(common, name) for name in common.__all__}


def render_html(report: Report) -> str:
    # Markup marks our own CSS as already safe (Java: a type the escaper trusts). It is
    # written exactly as hashed, so the CSP allows it and nothing else.
    template = ENVIRONMENT.get_template("report.html.j2")
    return template.render(report=report, css=Markup(CSS), csp=CSP)
