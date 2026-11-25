"""The JSON report, for scripts, a SIEM or a SOAR playbook (week 4, step 12).

It is the report model itself: dataclasses.asdict() turns the frozen dataclasses into
dicts and lists (Java: Jackson writing records), so JSON shows exactly what the other
formats show. report.schema.json describes every field; the tests check every report
against it, so a field added to the model without the schema fails a test.

Choices:
- Values stay defanged (hxxps://evil[.]test) and your addresses REDACTED, as everywhere.
  A script that needs live values refangs them itself (iocs.refang), on purpose, in its
  own code: a report file that is safe by default stays safe when it is passed around.
- ensure_ascii=True: every non-ASCII character is written as a \\uXXXX escape. The file
  is plain ASCII, so it cannot be misread in another encoding, and a look-alike letter
  (Cyrillic "a" is \\u0430) is visible as an escape instead of hiding as a Latin "a".
- The module is json_report.py, not json.py: inside the package, "import json" must
  keep meaning Python's own json module.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from importlib import resources
from typing import Any

from ..report import Report

SCHEMA_VERSION = 1  # also in report.schema.json; changes when readers would break


def to_dict(report: Report) -> dict[str, Any]:
    return {"schema_version": SCHEMA_VERSION, "defanged": True, **asdict(report)}


def render_json(report: Report) -> str:
    return json.dumps(to_dict(report), indent=2, ensure_ascii=True) + "\n"


def load_schema() -> dict[str, Any]:
    """report.schema.json, shipped inside the package (like scoring.yaml)."""
    text = resources.files("phishtriage.render").joinpath("report.schema.json").read_text("utf-8")
    return json.loads(text)
