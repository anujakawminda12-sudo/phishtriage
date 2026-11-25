"""Tests for the JSON report, report.schema.json and --json (week 4, step 12)."""

import dataclasses
import json
from datetime import UTC, datetime
from importlib import resources
from pathlib import Path

import pytest
from conftest import FIXTURES, PHISH_ME
from jsonschema import Draft202012Validator
from rich.console import Console
from typer.testing import CliRunner

from phishtriage import cli, report
from phishtriage.allowlist import load_allowlist
from phishtriage.analysis import analyse_file
from phishtriage.config import Secret, Settings
from phishtriage.enrich.enricher import enrich
from phishtriage.render.json_report import SCHEMA_VERSION, load_schema, render_json, to_dict
from phishtriage.render.safety import JSON, find_unsafe
from phishtriage.report import build_report
from phishtriage.scoring import load_scoring

ALLOWLIST = load_allowlist()
CONFIG = load_scoring()
NOW = datetime(2026, 11, 24, 3, 0, tzinfo=UTC)
SCHEMA = load_schema()
VALIDATOR = Draft202012Validator(SCHEMA)
runner = CliRunner()


def report_of(*paths: Path, **options):
    analyses = [analyse_file(path, ALLOWLIST) for path in paths]
    return build_report(analyses, CONFIG, now=NOW, **options)


def errors(data) -> list[str]:
    """Every way data breaks the schema, as 'path: message' lines."""
    found = sorted(VALIDATOR.iter_errors(data), key=lambda error: list(error.path))
    return [f"{'/'.join(map(str, error.path))}: {error.message}" for error in found]


def checked(text: str) -> dict:
    """Parse a JSON report and check it the three ways a reader would rely on."""
    assert text.isascii()
    assert find_unsafe(text, JSON) == []
    data = json.loads(text)
    assert errors(data) == []
    return data


# --- the schema ---------------------------------------------------------------------------------


def test_the_schema_is_a_valid_draft_2020_12_schema():
    Draft202012Validator.check_schema(SCHEMA)
    assert SCHEMA["properties"]["schema_version"]["const"] == SCHEMA_VERSION
    text = resources.files("phishtriage.render").joinpath("report.schema.json").read_bytes()
    assert text.isascii()


SCHEMA_NAMES = {
    report.AttackTag: "attack_tag",
    report.ReasonView: "reason",
    report.ScoreView: "score",
    report.Answer: "answer",
    report.IOCView: "ioc",
    report.AttachmentView: "attachment",
    report.AuthView: "auth",
    report.FindingView: "finding",
    report.EmailReport: "email",
    report.FileReport: "file",
}


@pytest.mark.parametrize("model", SCHEMA_NAMES, ids=lambda model: model.__name__)
def test_the_schema_describes_every_field_of_the_model(model):
    """A field added to (or removed from) the model must be added to the schema too."""
    definition = SCHEMA["$defs"][SCHEMA_NAMES[model]]
    fields = [field.name for field in dataclasses.fields(model)]
    assert list(definition["properties"]) == fields
    assert definition["required"] == fields
    assert definition["additionalProperties"] is False
    assert all(
        definition["properties"][name].get("description")
        or "$ref" in definition["properties"][name]
        for name in fields
    )


def test_the_top_level_matches_the_report():
    fields = [field.name for field in dataclasses.fields(report.Report) if field.name != "files"]
    top = list(SCHEMA["properties"])
    assert top == ["schema_version", "defanged", *fields, "files"]
    assert SCHEMA["required"] == top


# --- reports ----------------------------------------------------------------------------------


def test_every_fixture():
    data = checked(render_json(report_of(*sorted(FIXTURES.glob("*.eml")))))
    assert [file["name"] for file in data["files"]] == sorted(
        p.name for p in FIXTURES.glob("*.eml")
    )
    assert (data["schema_version"], data["defanged"], data["tool"]) == (1, True, "PhishTriage")
    assert data["generated_at"] == "2026-11-24T03:00:00Z"


def test_the_json_is_the_model():
    built = report_of(FIXTURES / "phish_paypal_spoof.eml")
    data = to_dict(built)
    assert data == {"schema_version": 1, "defanged": True, **dataclasses.asdict(built)}
    assert json.loads(render_json(built)) == json.loads(json.dumps(data))


def test_the_paypal_email():
    data = checked(render_json(report_of(FIXTURES / "phish_paypal_spoof.eml")))
    (file,) = data["files"]
    (email,) = file["emails"]
    assert (file["verdict"]["verdict"], file["verdict"]["total"], file["decided_by"]) == (
        "malicious",
        100,
        "",
    )
    assert email["from_address"] == "service[@]paypal[.]com"
    assert email["iocs"][0] == {
        "kind": "url",
        "value": "hxxps://www[.]paypal[.]com/signin",
        "seen": 2,
        "sources": ["text", "html:text"],
        "allowlisted": False,
        "group": "paypal[.]com",
        "looked_up": None,
        "reputation": [],
    }
    assert email["score"]["attack"] == [
        {"id": "T1566.001", "name": "Phishing: Spearphishing Attachment"},
        {"id": "T1566.002", "name": "Phishing: Spearphishing Link"},
    ]


def test_a_forward_and_a_file_that_failed(tmp_path):
    data = checked(
        render_json(
            report_of(
                FIXTURES / "forwarded_phish.eml",
                failed=[(tmp_path / "bad.eml", "ValueError('not an email')")],
            )
        )
    )
    forward, bad = data["files"]
    assert [(email["where"], email["level"]) for email in forward["emails"]] == [("", 0), ("1", 1)]
    assert forward["decided_by"] == "1"
    assert (bad["name"], bad["verdict"], bad["emails"], bad["error"]) == (
        "bad.eml",
        None,
        [],
        "ValueError('not an email')",
    )


def test_your_address_is_removed_and_look_alikes_are_escaped(tmp_path):
    cyrillic = "=D1=80=D0=B0=D1=83=D1=80=D0=B0l.com"  # looks like "paypal.com"
    path = tmp_path / "hostile.eml"
    path.write_text(
        "Delivered-To: me.victim@gmail.com\nFrom: IT <it@evil.test>\n"
        f"Subject: =?utf-8?q?Log_in_at_{cyrillic}_for_me.victim@gmail.com?=\n\nhello\n",
        encoding="utf-8",
    )
    text = render_json(report_of(path))
    data = checked(text)
    assert PHISH_ME not in text
    assert "\\u0440\\u0430\\u0443\\u0440\\u0430l[.]com" in text  # visible as escapes
    assert data["files"][0]["emails"][0]["subject"].endswith("l[.]com for REDACTED")
    assert data["redacted"] == 1


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
    text = render_json(build_report([analysis], CONFIG, enrichment=enrichment, now=NOW))
    data = checked(text)
    assert PHISH_ME not in text
    email = data["files"][0]["emails"][0]
    assert data["enriched"] is True and email["score"]["basis"] == "complete"
    flagged = [line for ioc in email["iocs"] for line in ioc["reputation"] if line["flagged"]]
    assert flagged
    vt = next(finding for finding in email["findings"] if finding["rule"] == "vt_flagged")
    assert vt["facts"]["service"] == "virustotal" and isinstance(vt["facts"]["malicious"], int)


# --- the schema catches what does not belong ------------------------------------------------------


def good() -> dict:
    return json.loads(render_json(report_of(FIXTURES / "phish_paypal_spoof.eml")))


def test_the_schema_catches_mistakes():
    data = good()
    email = data["files"][0]["emails"][0]
    email["surprise"] = 1
    del email["subject"]
    email["attachments"][0]["sha256"] = "abc"  # hex, but not 64 characters
    data["files"][0]["verdict"]["verdict"] = "fine"
    data["defanged"] = False
    found = errors(data)
    assert len(found) == 5
    assert "defanged: True was expected" in found
    assert any("'surprise' was unexpected" in line for line in found)
    assert any("'subject' is a required property" in line for line in found)
    assert any(line.startswith("files/0/emails/0/attachments/0/sha256: 'abc'") for line in found)
    assert any(line.startswith("files/0/verdict: ") for line in found)  # not a verdict, not null


@pytest.mark.parametrize(
    ("text", "problem"),
    [
        ("{not json", "not valid JSON"),
        ('{"url": "https://evil.test/a"}', "a live link, address, domain or IP"),
        ('{"evil.test": 1}', "a live link, address, domain or IP"),
        ('{"subject": "a\\u001bb"}', "a control character in a value"),
        ('{"subject": "line\\nbreak"}', "a control character in a value"),
        ('{"list": ["ok", "mail me@evil.test"]}', "a live link, address, domain or IP"),
    ],
)
def test_find_unsafe_json(text, problem):
    problems = find_unsafe(text, JSON)
    assert len(problems) == 1 and problems[0].startswith(problem), problems


def test_numbers_and_booleans_are_not_text():
    assert find_unsafe('{"a": 1.5, "b": true, "c": null, "d": [2, 3]}', JSON) == []


# --- phishtriage analyze --json ------------------------------------------------------------------


@pytest.fixture
def wide(monkeypatch):
    monkeypatch.setattr(cli, "console", Console(width=200))


def test_stdout_holds_only_the_json(wide):
    result = runner.invoke(cli.app, ["analyze", str(FIXTURES), "--json"])
    assert result.exit_code == 2  # the worst fixture is malicious
    data = checked(result.stdout)
    assert len(data["files"]) == len(list(FIXTURES.glob("*.eml")))
    assert "PHISHTRIAGE_MY_ADDRESSES is not set" in result.stderr
    assert "Analysed 8 of 8 files." in result.stderr
    assert "Verdict" not in result.stdout + result.stderr  # no terminal report at all


def test_a_failed_file_is_in_the_json_and_the_exit_code(monkeypatch, wide):
    def broken(path, allowlist):
        raise ValueError("not an email")

    monkeypatch.setattr(cli, "analyse_file", broken)
    result = runner.invoke(cli.app, ["analyze", str(FIXTURES / "legit_newsletter.eml"), "--json"])
    assert result.exit_code == 3  # no verdict for every file (week 4 exit codes)
    (file,) = checked(result.stdout)["files"]
    assert file["error"] == "ValueError('not an email')"


def test_with_enrich_the_lookup_messages_go_to_stderr(
    phish_email, tmp_path, monkeypatch, wide, fake_apis
):
    for name in ("VT_API_KEY", "ABUSEIPDB_API_KEY", "ABUSECH_AUTH_KEY"):
        monkeypatch.setenv(name, "k" * 64)
    monkeypatch.setenv("PHISHTRIAGE_CACHE", str(tmp_path / "cache.sqlite3"))
    fake_apis(created="2026-11-13T09:00:00Z")
    result = runner.invoke(cli.app, ["analyze", str(phish_email), "--enrich", "--json"])
    assert result.exit_code == 2  # malicious with the lookups
    data = checked(result.stdout)
    assert data["enriched"] is True
    assert "Lookups planned: 8" in result.stderr
    assert "Threat-intel lookups" in result.stderr
    assert PHISH_ME not in result.stdout + result.stderr


def test_a_dry_run_writes_no_json(phish_email, wide):
    result = runner.invoke(
        cli.app, ["analyze", str(phish_email), "--enrich", "--dry-run", "--json"]
    )
    assert result.exit_code == 0
    assert result.stdout == ""
    assert "Lookups planned" in result.stderr


def test_without_json_the_terminal_report_is_on_stdout(wide):
    result = runner.invoke(cli.app, ["analyze", str(FIXTURES / "phish_paypal_spoof.eml")])
    assert "Verdict    MALICIOUS  100/100" in result.stdout
    assert result.stdout.lstrip().startswith(("Warning", chr(0x2500)))  # a rule line
