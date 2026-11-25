"""Tests for scoring.py and scoring.yaml (week 4, step 8).

The fixture verdicts below are NOT blind: the weights were chosen knowing these fixtures
(the double_extension row exists because of attachments_phish.eml). Week 5's held-out
sets are the blind test.
"""

import ast
import os
from importlib import resources
from pathlib import Path

import pytest
import yaml
from conftest import FIXTURES
from rich.console import Console
from typer.testing import CliRunner

from phishtriage import cli, headers, report, scoring
from phishtriage.allowlist import load_allowlist
from phishtriage.analysis import analyse_file
from phishtriage.config import Secret, Settings
from phishtriage.enrich.enricher import Enrichment, enrich
from phishtriage.enrich.models import (
    DEFERRED,
    FAILED,
    FOUND,
    NOT_FOUND,
    UNSUPPORTED,
    Lookup,
    LookupResult,
)
from phishtriage.enrich.plan import LookupPlan, TargetPlan
from phishtriage.models import Finding
from phishtriage.scoring import (
    DETECTION_RULES,
    LIKELY_BENIGN,
    MALICIOUS,
    SCORED_RULES,
    SHARED_PLATFORM_NOTE,
    SUSPICIOUS,
    Evidence,
    Score,
    ScoringError,
    classify,
    load_scoring,
    parse_scoring,
    score_analysis,
    score_file,
    score_findings,
    worst,
)

CONFIG = load_scoring()
ALLOWLIST = load_allowlist()
SRC = Path(scoring.__file__).parent
runner = CliRunner()


def built_in_text() -> str:
    return resources.files("phishtriage").joinpath("scoring.yaml").read_text("utf-8")


def built_in() -> dict:
    return yaml.safe_load(built_in_text())


def find(rule: str, detail: str = "", **facts) -> Finding:
    return Finding(rule=rule, detail=detail or rule, facts=facts)


def signals_of(score: Score) -> list[str]:
    return [reason.signal for reason in score.reasons]


# --- the built-in scoring.yaml -----------------------------------------------------------------


def test_the_built_in_file_loads_and_covers_every_rule():
    assert (CONFIG.malicious, CONFIG.suspicious) == (70, 25)  # 30 until week 5's calibration
    assert CONFIG.evidence == Evidence(3, 5, 50, 1)
    assert set(CONFIG.by_rule) == SCORED_RULES
    assert CONFIG.source == scoring.BUILT_IN


# Week 5, step 3: the scoring file the blind tests use, frozen before any held-out email
# was read. Changing scoring.yaml after this is a decision: change this number in the same
# step and say why in the README. Every other test reads the SHA-256 from the file itself.
FROZEN_SCORING_SHA256 = "77c8089435bc8c70f6ad79a74e98004b65a64cf2c9255bccfe9adc2ed190bcf3"


def test_the_scoring_file_is_the_frozen_one():
    """One byte changed anywhere in scoring.yaml, even in a comment, fails this test
    (Java: like checking a signed JAR's digest before trusting it). Every report and
    every stats file records the same SHA-256, so a result can be traced to this file."""
    assert CONFIG.sha256 == FROZEN_SCORING_SHA256


def test_the_built_in_file_is_plain_ascii():
    """Hidden or look-alike characters could make a rule name look right but not match."""
    assert built_in_text().isascii()


def test_the_weights_are_the_agreed_ones():
    """Pins every number, so a change to scoring.yaml is a decision, not an accident.
    Calibration (step 15) updates this test along with the file."""
    points = {signal.name: signal.points for signal in CONFIG.signals}
    assert points == {
        "known_malware_attachment": 0,
        "flagged_link_or_domain": 35,
        "double_extension": 30,
        "dmarc_fail": 25,
        "lookalike_sender": 20,
        "risky_attachment": 20,
        "brand_in_sender_domain": 15,
        "link_text_mismatch": 15,
        "reply_to_mismatch": 15,
        "display_name_spoof": 15,
        "new_domain": 15,
        "spf_fail": 10,
        "dkim_problem": 10,
        "sender_ip_reported": 10,
        "multiple_from": 10,
        "hidden_destination": 5,
        "pressure_wording": 5,
        "return_path_mismatch": 5,
        "link_to_sender_site": 0,
        "authentication_unknown": 0,
        "extra_auth_results": 0,
    }
    assert [signal.name for signal in CONFIG.signals if signal.override] == [
        "known_malware_attachment"
    ]


def test_a_scoring_file_given_by_path(tmp_path):
    path = tmp_path / "mine.yaml"
    path.write_text(built_in_text().replace("malicious: 70", "malicious: 80"), encoding="utf-8")
    config = load_scoring(path)
    assert config.malicious == 80
    assert config.source == str(path)


def test_a_missing_scoring_file(tmp_path):
    with pytest.raises(ScoringError, match=r"nothing\.yaml: cannot be read"):
        load_scoring(tmp_path / "nothing.yaml")


# --- every rule the checks can produce has a decision in scoring.yaml --------------------------

# Finding(...) calls whose rule name is built while the program runs, and what they can build
DYNAMIC_SITES = {
    ("attachments.py", "check_attachments"): {
        "attachment_risky_type",
        "attachment_double_extension",
        "attachment_type_mismatch",
        "attachment_encrypted_archive",
    },
    ("content.py", "check_wording"): {"urgency_wording", "credential_request_wording"},
    ("enrich/enricher.py", "findings_for"): {"vt_flagged", "urlhaus_listed", "abuseipdb_reported"},
    ("headers.py", "run_header_checks"): {
        f"{method}_{result}"
        for method, results in headers.FLAGGED_RESULTS.items()
        for result in results
    },
}


def finding_calls() -> list[tuple[str, str, ast.expr | None]]:
    """(file, function, rule argument) for every Finding(...) call in the package.

    ast reads the source as a tree without running it (Java: a parser like JavaParser).
    """
    calls = []
    for path in sorted(SRC.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        function: dict[ast.AST, str] = {}
        for node in ast.walk(tree):  # outer functions come first, so inner ones win
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                for inside in ast.walk(node):
                    function[inside] = node.name
        for node in ast.walk(tree):
            name = getattr(node, "func", None)
            if isinstance(node, ast.Call) and getattr(name, "id", "") == "Finding":
                given = {keyword.arg: keyword.value for keyword in node.keywords}
                rule = node.args[0] if node.args else given.get("rule")
                where = path.relative_to(SRC).as_posix()
                calls.append((where, function.get(node, "<module>"), rule))
    return calls


def literal_rules() -> set[str]:
    return {
        rule.value
        for _, _, rule in finding_calls()
        if isinstance(rule, ast.Constant) and isinstance(rule.value, str)
    }


def test_the_scan_finds_the_checks():
    assert len(finding_calls()) >= 15
    assert {"dmarc_fail", "spf_fail"} <= DYNAMIC_SITES[("headers.py", "run_header_checks")]


# Finding(...) calls that detect nothing: they replay rule names read back from a file, and
# refuse any name that is not in DETECTION_RULES (week 4: calibrate reads --stats rows)
REPLAY_SITES = {("calibrate.py", "_row")}


def test_rule_names_built_at_run_time_are_known():
    dynamic = {
        (where, function)
        for where, function, rule in finding_calls()
        if not isinstance(rule, ast.Constant)
    }
    assert dynamic == set(DYNAMIC_SITES) | REPLAY_SITES, (
        "A Finding's rule name is built while the program runs somewhere new: add the "
        "file, function and the names it can build to DYNAMIC_SITES"
    )


@pytest.mark.parametrize("site", [site for site in DYNAMIC_SITES if site[0] != "headers.py"])
def test_names_built_at_run_time_are_written_in_their_file(site):
    """The names come from a table or a return in the same file, as plain strings."""
    tree = ast.parse((SRC / site[0]).read_text(encoding="utf-8"))
    strings = {node.value for node in ast.walk(tree) if isinstance(node, ast.Constant)}
    assert DYNAMIC_SITES[site] <= strings


def test_the_list_of_rules_matches_the_code():
    found = literal_rules().union(*DYNAMIC_SITES.values())
    assert found == DETECTION_RULES, (
        f"in the code but not in DETECTION_RULES: {sorted(found - DETECTION_RULES)}; "
        f"in DETECTION_RULES but not in the code: {sorted(DETECTION_RULES - found)}"
    )


# --- a broken scoring.yaml is an error, never a silent 0 ----------------------------------------


def changed(change) -> str:
    raw = built_in()
    change(raw)
    return yaml.safe_dump(raw, sort_keys=False)


def setter(*keys, value):
    def change(raw):
        for key in keys[:-1]:
            raw = raw[key]
        raw[keys[-1]] = value

    return change


def deleter(*keys):
    def change(raw):
        for key in keys[:-1]:
            raw = raw[key]
        del raw[keys[-1]]

    return change


def move_rule(raw):
    raw["signals"]["spf_fail"]["rules"].append("dmarc_fail")


def add_signal(name, **body):
    def change(raw):
        raw["signals"][name] = body

    return change


BROKEN = {
    "not YAML": ("signals: [", "not valid YAML"),
    "empty": ("", "must be a mapping"),
    "a list": ("- one\n- two\n", "must be a mapping"),
    "no verdicts": (changed(deleter("verdicts")), "missing verdicts"),
    "a typo key": (changed(setter("verdict", value=1)), "unknown key 'verdict'"),
    "True as a number": (
        changed(setter("verdicts", "malicious", value=True)),
        "verdicts.malicious: must be a whole number from 1 to 100, not True",
    ),
    "a quoted number": (changed(setter("verdicts", "malicious", value="70")), "not '70'"),
    "over 100": (changed(setter("verdicts", "malicious", value=101)), "from 1 to 100"),
    "suspicious too high": (
        changed(setter("verdicts", "suspicious", value=70)),
        "verdicts.suspicious (70) must be lower than verdicts.malicious (70)",
    ),
    "evidence typo": (
        changed(setter("evidence", "virustotal_min", value=3)),
        "unknown key 'virustotal_min'",
    ),
    "evidence 0": (
        changed(setter("evidence", "virustotal_min_malicious", value=0)),
        "evidence.virustotal_min_malicious: must be a whole number from 1 to 100",
    ),
    "evidence not a mapping": (changed(setter("evidence", value=[3])), "evidence: must be"),
    "no signals": (changed(setter("signals", value={})), "mapping of named signals"),
    "a bad signal name": (
        changed(add_signal("Bad-Name", label="x", points=1, rules=["dmarc_fail"])),
        "a signal name is lower case",
    ),
    "a signal without a label": (
        changed(deleter("signals", "dmarc_fail", "label")),
        "signals.dmarc_fail: missing label",
    ),
    "an empty label": (changed(setter("signals", "dmarc_fail", "label", value=" ")), "some text"),
    "points and override": (
        changed(setter("signals", "dmarc_fail", "override", value="malicious")),
        "either points or override",
    ),
    "neither points nor override": (
        changed(deleter("signals", "dmarc_fail", "points")),
        "either points or override",
    ),
    "another override": (
        changed(setter("signals", "known_malware_attachment", "override", value="suspicious")),
        "the only override is 'malicious'",
    ),
    "negative points": (
        changed(setter("signals", "dmarc_fail", "points", value=-5)),
        "from 0 to 100, not -5",
    ),
    "fractional points": (
        changed(setter("signals", "dmarc_fail", "points", value=12.5)),
        "not 12.5",
    ),
    "an unknown ATT&CK tag": (
        changed(setter("signals", "dmarc_fail", "attack", value="T1566.003")),
        "attack: must be one of T1566.001, T1566.002",
    ),
    "rules not a list": (
        changed(setter("signals", "dmarc_fail", "rules", value="dmarc_fail")),
        "must be a list of at least one rule name",
    ),
    "no rules": (changed(setter("signals", "dmarc_fail", "rules", value=[])), "at least one"),
    "a misspelt rule": (
        changed(setter("signals", "dmarc_fail", "rules", value=["dmarc_fial"])),
        "unknown rule 'dmarc_fial' (did you mean dmarc_fail?)",
    ),
    "a raw threat-intel rule": (
        changed(setter("signals", "dmarc_fail", "rules", value=["dmarc_fail", "vt_flagged"])),
        "unknown rule 'vt_flagged'",
    ),
    "a rule that is not text": (
        changed(setter("signals", "dmarc_fail", "rules", value=[5])),
        "unknown rule 5",
    ),
    "a rule in two signals": (changed(move_rule), "dmarc_fail is already in dmarc_fail"),
    "a rule in no signal": (
        changed(deleter("signals", "dmarc_fail")),
        "no signal has dmarc_fail. Every rule needs one",
    ),
}


@pytest.mark.parametrize(("text", "message"), BROKEN.values(), ids=BROKEN.keys())
def test_a_broken_scoring_file_says_where_and_why(text, message):
    with pytest.raises(ScoringError) as error:
        parse_scoring(text, source="mine.yaml")
    assert str(error.value).startswith("mine.yaml")
    assert message in str(error.value)


def test_a_far_off_rule_name_gets_no_suggestion():
    text = changed(setter("signals", "dmarc_fail", "rules", value=["zzzz"]))
    with pytest.raises(ScoringError) as error:
        parse_scoring(text)
    assert "did you mean" not in str(error.value)


def test_evidence_can_be_left_out_and_host_0_is_allowed():
    assert parse_scoring(changed(deleter("evidence"))).evidence == Evidence()
    text = changed(setter("evidence", "urlhaus_host_min_online", value=0))
    assert parse_scoring(text).evidence.urlhaus_host_min_online == 0


def test_yaml_cannot_run_code(monkeypatch):
    """yaml.load() would build any Python object the file asks for; safe_load refuses."""
    ran = []
    monkeypatch.setattr(os, "system", lambda command: ran.append(command))
    with pytest.raises(ScoringError, match="not valid YAML"):
        parse_scoring('verdicts: !!python/object/apply:os.system ["echo pwned"]\n')
    assert ran == []


# --- when a threat-intel hit counts (the evidence thresholds) ----------------------------------

VT, UH, ABUSE = "vt_flagged", "urlhaus_listed", "abuseipdb_reported"
EVIDENCE = {
    "VT URL, 3 engines": (
        find(VT, kind="url", malicious=3, engines=90),
        "virustotal_malicious",
        "",
    ),
    "VT URL, 2 engines": (
        find(VT, kind="url", malicious=2, engines=90),
        "virustotal_malicious",
        "2 of 90 engines say malicious; 3 needed",
    ),
    "VT URL on a shared platform": (
        find(VT, kind="url", malicious=9, engines=90, shared_platform=True),
        "virustotal_malicious",
        "",
    ),
    "VT domain on a shared platform": (
        find(VT, kind="domain", malicious=9, engines=90, shared_platform=True),
        "virustotal_malicious",
        SHARED_PLATFORM_NOTE,
    ),
    "VT domain, 2 engines, shared": (
        find(VT, kind="domain", malicious=2, engines=90, shared_platform=True),
        "virustotal_malicious",
        "2 of 90 engines say malicious; 3 needed",
    ),
    "VT IP, 3 engines": (find(VT, kind="ip", malicious=3, engines=90), "virustotal_malicious", ""),
    "VT file, 5 engines": (
        find(VT, kind="file", malicious=5, engines=70),
        "virustotal_malicious_file",
        "",
    ),
    "VT file, 4 engines": (
        find(VT, kind="file", malicious=4, engines=70),
        "virustotal_malicious_file",
        "4 of 70 engines say malicious; 5 needed",
    ),
    "VT without facts": (
        find(VT),
        "virustotal_malicious",
        "0 of 0 engines say malicious; 3 needed",
    ),
    "URLhaus file": (find(UH, kind="file"), "urlhaus_file_listed", ""),
    "URLhaus URL, offline": (find(UH, kind="url", online=False), "urlhaus_url_listed", ""),
    "URLhaus host, 1 online": (
        find(UH, kind="host", online_urls=1, listed_urls=4),
        "urlhaus_host_listed",
        "",
    ),
    "URLhaus host, none online": (
        find(UH, kind="host", online_urls=0, listed_urls=4),
        "urlhaus_host_listed",
        "0 of its 4 listed URLs online; 1 needed",
    ),
    "URLhaus host, shared": (
        find(UH, kind="host", online_urls=3, listed_urls=4, shared_platform=True),
        "urlhaus_host_listed",
        SHARED_PLATFORM_NOTE,
    ),
    "AbuseIPDB sender, 50%": (
        find(ABUSE, score=50, sender_ip=True, whitelisted=False),
        "abuseipdb_sender_ip",
        "",
    ),
    "AbuseIPDB sender, 49%": (
        find(ABUSE, score=49, sender_ip=True),
        "abuseipdb_sender_ip",
        "confidence 49%; 50% needed",
    ),
    "AbuseIPDB another IP": (
        find(ABUSE, score=100, sender_ip=False),
        "abuseipdb_sender_ip",
        "not the IP this email came from",
    ),
    "AbuseIPDB whitelisted": (
        find(ABUSE, score=100, sender_ip=True, whitelisted=True),
        "abuseipdb_sender_ip",
        "known-good",
    ),
    "a check's own finding": (find("dmarc_fail"), "dmarc_fail", ""),
}


@pytest.mark.parametrize(("finding", "rule", "note"), EVIDENCE.values(), ids=EVIDENCE.keys())
def test_classify(finding, rule, note):
    scored_as, why = classify(finding, Evidence())
    assert scored_as == rule
    assert (note in why) if note else why == ""


def test_the_thresholds_come_from_scoring_yaml():
    lenient = Evidence(virustotal_min_malicious=1, abuseipdb_min_score=10)
    assert classify(find(VT, kind="url", malicious=1, engines=90), lenient)[1] == ""
    assert classify(find(ABUSE, score=10, sender_ip=True), lenient)[1] == ""
    strict = Evidence(urlhaus_host_min_online=2)
    assert classify(find(UH, kind="host", online_urls=1, listed_urls=1), strict)[1]


# --- from findings to a score ------------------------------------------------------------------


def test_no_findings():
    score = score_findings([], CONFIG)
    assert (score.total, score.verdict, score.reasons, score.attack) == (0, LIKELY_BENIGN, (), ())
    assert score.basis == "not_enriched"


def test_a_signal_counts_once_however_many_findings():
    score = score_findings(
        [find("link_text_mismatch", "a"), find("link_text_mismatch", "b")]
        + [find("link_text_mismatch", "a"), find("spf_fail"), find("spf_softfail")],
        CONFIG,
    )
    assert score.total == 15 + 10
    links = score.reasons[0]
    assert (links.signal, links.points, links.details) == ("link_text_mismatch", 15, ("a", "b"))
    assert score.reasons[1].rules == ("spf_fail", "spf_softfail")


def config_with_dmarc(points: int):
    return parse_scoring(changed(setter("signals", "dmarc_fail", "points", value=points)))


@pytest.mark.parametrize(
    ("points", "verdict"),
    [(0, LIKELY_BENIGN), (24, LIKELY_BENIGN), (25, SUSPICIOUS), (69, SUSPICIOUS)]
    + [(70, MALICIOUS), (100, MALICIOUS)],
)
def test_verdict_boundaries(points, verdict):
    score = score_findings([find("dmarc_fail")], config_with_dmarc(points))
    assert (score.total, score.verdict) == (points, verdict)


def test_the_score_is_capped_at_100():
    rules = ["attachment_double_extension", "dmarc_fail", "lookalike_sender_domain"]
    rules += ["attachment_risky_type", "link_text_mismatch"]  # 30+25+20+20+15 = 110
    score = score_findings([find(rule) for rule in rules], CONFIG)
    assert sum(reason.points for reason in score.reasons) == 110
    assert (score.total, score.verdict) == (100, MALICIOUS)


def test_known_malware_decides_on_its_own():
    score = score_findings([find("pressure", "x"), find(UH, "invoice.exe", kind="file")], CONFIG)
    assert (score.total, score.verdict, score.attack) == (100, MALICIOUS, ("T1566.001",))
    first = score.reasons[0]
    assert (first.signal, first.override, first.points) == ("known_malware_attachment", True, 0)


def test_a_file_too_few_engines_flag_is_not_an_override():
    score = score_findings([find(VT, "invoice.pdf", kind="file", malicious=2, engines=70)], CONFIG)
    assert (score.total, score.verdict) == (0, LIKELY_BENIGN)
    (reason,) = score.reasons
    assert (reason.override, reason.points, reason.note) == (
        False,
        0,
        "2 of 70 engines say malicious; 5 needed",
    )


def test_what_counted_is_shown_and_what_did_not_says_why():
    findings = [
        find(VT, "weak.test", kind="domain", malicious=1, engines=90),
        find(VT, "bad.test", kind="domain", malicious=8, engines=90),
    ]
    (reason,) = score_findings(findings, CONFIG).reasons
    assert (reason.points, reason.details, reason.note) == (35, ("bad.test",), "")
    (reason,) = score_findings(findings[:1], CONFIG).reasons
    assert (reason.points, reason.details) == (0, ("weak.test",))
    assert reason.note == "1 of 90 engines say malicious; 3 needed"


def test_an_unknown_rule_is_shown_and_worth_0():
    score = score_findings([find("brand_new_check", "something odd")], CONFIG)
    (reason,) = score.reasons
    assert (reason.signal, reason.points, reason.details) == (
        "brand_new_check",
        0,
        ("something odd",),
    )
    assert reason.note == "not in scoring.yaml, so worth 0 points"
    assert score.total == 0


def test_reason_order():
    """Override first, then most points (ties in scoring.yaml's order), then the 0-point
    information, then what did not count."""
    findings = [
        find("urgency_wording"),
        find("display_name_spoof"),
        find("extra_auth_results"),
        find(VT, kind="url", malicious=1, engines=90),
        find("reply_to_mismatch"),
        find("dmarc_fail"),
        find(UH, kind="file"),
        find("mystery_rule"),
    ]
    assert signals_of(score_findings(findings, CONFIG)) == [
        "known_malware_attachment",
        "dmarc_fail",
        "reply_to_mismatch",
        "display_name_spoof",
        "pressure_wording",
        "extra_auth_results",
        "flagged_link_or_domain",
        "mystery_rule",
    ]


@pytest.mark.parametrize(
    ("rules", "attack"),
    [
        (["dmarc_fail", "link_text_mismatch"], ("T1566.002",)),
        (["attachment_double_extension"], ("T1566.001",)),
        (["dmarc_fail", "attachment_risky_type", "url_shortener"], ("T1566.001", "T1566.002")),
        (["dmarc_fail", "display_name_spoof"], ("T1566",)),
        (["link_text_mismatch"], ()),  # 15: Likely benign, so no technique
        (["dmarc_fail", "reply_to_mismatch", "link_text_mismatch_sender"], ("T1566",)),
    ],
)
def test_attack_tags(rules, attack):
    assert score_findings([find(rule) for rule in rules], CONFIG).attack == attack


def test_a_link_signal_that_did_not_count_gives_no_link_tag():
    findings = [find("dmarc_fail"), find("reply_to_mismatch")]
    findings.append(find(VT, kind="url", malicious=1, engines=90))
    assert score_findings(findings, CONFIG).attack == ("T1566",)


def test_rank_and_basis_text():
    score = score_findings([find("dmarc_fail")], CONFIG, basis="partial", unanswered=2)
    assert score.rank == 1  # a DMARC fail alone (25) is Suspicious since week 5's calibration
    assert score.basis_text == "headers, content and some reputation lookups (2 got no answer)"
    assert "not enriched" in score_findings([], CONFIG).basis_text
    assert score_findings([], CONFIG, basis="complete").basis_text.endswith("reputation lookups")


# --- the fixtures (NOT blind: the weights were set knowing them) --------------------------------

FIXTURE_VERDICTS = {
    "phish_paypal_spoof.eml": (100, MALICIOUS, ("T1566.001", "T1566.002")),
    "phish_microsoft_format.eml": (85, MALICIOUS, ("T1566",)),
    "attachments_phish.eml": (50, SUSPICIOUS, ("T1566.001",)),
    "phish_open_redirect.eml": (35, SUSPICIOUS, ("T1566.002",)),
    "forwarded_phish.eml": (0, LIKELY_BENIGN, ()),  # the outer email; see below
    "legit_newsletter.eml": (0, LIKELY_BENIGN, ()),
    "wrapped_links.eml": (0, LIKELY_BENIGN, ()),
    "broken_charset.eml": (0, LIKELY_BENIGN, ()),
}


def test_every_fixture_has_an_expected_verdict():
    assert {path.name for path in FIXTURES.glob("*.eml")} == set(FIXTURE_VERDICTS)


@pytest.mark.parametrize("name", FIXTURE_VERDICTS)
def test_fixture_verdicts(name):
    score = score_analysis(analyse_file(FIXTURES / name, ALLOWLIST), CONFIG)
    assert (score.total, score.verdict, score.attack) == FIXTURE_VERDICTS[name]


def test_a_forward_is_judged_by_what_it_carries():
    scored = score_file(analyse_file(FIXTURES / "forwarded_phish.eml", ALLOWLIST), CONFIG)
    assert [score.verdict for _, score in scored] == [LIKELY_BENIGN, SUSPICIOUS]
    analysis, score = worst(scored)
    assert analysis.email.depth == 1
    assert (score.total, score.attack) == (60, ("T1566.002",))
    assert signals_of(score)[0] == "lookalike_sender"


def make_score(total: int, verdict: str) -> Score:
    return Score(total=total, verdict=verdict, reasons=(), attack=())


def test_worst_takes_the_highest_score_and_the_first_on_a_tie():
    a, b, c = make_score(0, LIKELY_BENIGN), make_score(40, SUSPICIOUS), make_score(70, MALICIOUS)
    assert worst([("outer", a), ("inner", b)])[0] == "inner"
    assert worst([("outer", c), ("inner", b)])[0] == "outer"
    assert worst([("outer", b), ("first", c), ("second", c)])[0] == "first"
    assert worst([("outer", a), ("inner", make_score(0, LIKELY_BENIGN))])[0] == "outer"
    override = make_score(100, MALICIOUS)
    assert worst([("outer", make_score(85, MALICIOUS)), ("inner", override)])[0] == "inner"


# --- with --enrich ------------------------------------------------------------------------------

KEY = Secret("k" * 64)


def enriched(phish_email, tmp_path, **options):
    analysis = analyse_file(phish_email, ALLOWLIST)
    settings = Settings(
        cache_path=tmp_path / "cache" / "cache.sqlite3",
        vt_api_key=KEY,
        abuseipdb_api_key=KEY,
        abusech_auth_key=KEY,
    )
    enrichment = enrich(
        [analysis], settings, ALLOWLIST, sleep=lambda _: None, jitter=lambda: 0.0, **options
    )
    return analysis, enrichment


def test_enriched_findings_are_scored(phish_email, tmp_path, fake_apis):
    fake_apis(created="2026-11-13T00:00:00Z", vt_engines=5)
    analysis, enrichment = enriched(phish_email, tmp_path)
    score = score_analysis(analysis, CONFIG, enrichment)
    assert score.basis == "complete"
    assert score.verdict == MALICIOUS
    points = {reason.signal: reason.points for reason in score.reasons}
    assert points["flagged_link_or_domain"] == 35
    assert points["sender_ip_reported"] == 10
    assert points["new_domain"] == 15
    assert "T1566.002" in score.attack
    assert score_analysis(analysis, CONFIG).basis == "not_enriched"


def test_lookups_without_an_answer_make_the_score_partial(phish_email, tmp_path, fake_apis):
    fake_apis(created="2026-11-13T00:00:00Z")
    analysis, enrichment = enriched(phish_email, tmp_path, max_lookups=1)
    score = score_analysis(analysis, CONFIG, enrichment)
    assert score.basis == "partial"
    assert score.unanswered == enrichment.unanswered_for(analysis) > 0


def test_a_dry_run_is_not_enriched(phish_email, tmp_path, fake_apis):
    fake_apis(created="2026-11-13T00:00:00Z")
    analysis, enrichment = enriched(phish_email, tmp_path, dry_run=True)
    assert score_analysis(analysis, CONFIG, enrichment).basis == "not_enriched"


def test_unanswered_for_counts_failed_deferred_and_missing_once(phish_email):
    analysis = analyse_file(phish_email, ALLOWLIST)
    plan = LookupPlan(targets={(ioc.kind, ioc.value): TargetPlan() for ioc in analysis.iocs})
    (attachment,) = analysis.email.attachments
    asked = {
        status: Lookup("virustotal", "url", status)
        for status in (FOUND, NOT_FOUND, FAILED, DEFERRED, UNSUPPORTED, "never answered")
    }
    first, second = analysis.iocs[:2]
    plan.targets[(first.kind, first.value)] = TargetPlan(list(asked.values()))
    plan.targets[(second.kind, second.value)] = TargetPlan([asked[FAILED]])  # the same lookup
    file_lookup = Lookup("virustotal", "file", attachment.sha256)
    plan.targets[("file", attachment.sha256)] = TargetPlan([file_lookup])
    results = {
        lookup: LookupResult(lookup, status)
        for status, lookup in asked.items()
        if status != "never answered"
    }
    enrichment = Enrichment(plan=plan, results=results)
    assert enrichment.unanswered_for(analysis) == 4  # failed, deferred, never answered, file
    results[file_lookup] = LookupResult(file_lookup, NOT_FOUND)
    assert enrichment.unanswered_for(analysis) == 3


# --- the terminal report -------------------------------------------------------------------------


@pytest.fixture
def wide(monkeypatch):
    monkeypatch.setattr(cli, "console", Console(width=200))


def test_the_report_starts_with_the_verdict(wide):
    result = runner.invoke(cli.app, ["analyze", str(FIXTURES / "phish_paypal_spoof.eml")])
    assert result.exit_code == 2  # malicious
    lines = result.output.splitlines()
    rule = next(n for n, line in enumerate(lines) if "phish_paypal_spoof.eml" in line)
    assert lines[rule + 1].startswith("Verdict    MALICIOUS  100/100")
    assert "ATT&CK     T1566.001 Phishing: Spearphishing Attachment, T1566.002" in result.output
    assert "+25  The From domain failed DMARC (dmarc_fail)" in result.output
    assert "0  More Authentication-Results headers" in result.output


def test_a_benign_email_has_no_attack_line(wide):
    result = runner.invoke(cli.app, ["analyze", str(FIXTURES / "legit_newsletter.eml")])
    assert "Verdict    LIKELY BENIGN  0/100" in result.output
    assert "Reasons    none" in result.output
    assert "ATT&CK" not in result.output


def test_the_outer_email_shows_the_file_verdict(wide):
    result = runner.invoke(cli.app, ["analyze", str(FIXTURES / "forwarded_phish.eml")])
    assert "File       SUSPICIOUS  60/100  decided by forwarded email 1" in result.output
    assert result.output.count("Verdict    ") == 2


def test_a_broken_scoring_file_stops_the_run_first(monkeypatch, wide):
    def broken(path=None):  # step 13: load_scoring(path) takes --scoring
        raise ScoringError("mine.yaml: signals.dmarc_fail: missing label")

    monkeypatch.setattr(cli, "load_scoring", broken)
    result = runner.invoke(cli.app, ["analyze", str(FIXTURES / "phish_paypal_spoof.eml")])
    assert result.exit_code == 3  # no verdict
    assert isinstance(result.exception, SystemExit)  # a clean stop, not a crash
    assert "mine.yaml: signals.dmarc_fail: missing label" in result.output
    assert "Verdict" not in result.output


def test_text_from_scoring_yaml_cannot_style_or_control_the_terminal(monkeypatch, wide):
    label = "[bold red]FAKE[/bold red] \x1b[2J"
    config = parse_scoring(changed(setter("signals", "dmarc_fail", "label", value=label)))
    monkeypatch.setattr(cli, "load_scoring", lambda path=None: config)
    result = runner.invoke(cli.app, ["analyze", str(FIXTURES / "phish_paypal_spoof.eml")])
    assert "[bold red]FAKE[/bold red]" in result.output
    assert "\x1b" not in result.output


OUTER_WORSE = """\
Authentication-Results: mx.example.org; spf=fail smtp.mailfrom=evil.test;
 dkim=none; dmarc=fail header.from=evil.test
From: Helpdesk <help@evil.test>
To: student@example.org
Subject: Fwd: notes
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="b1"

--b1
Content-Type: text/plain

See the attached email.
--b1
Content-Type: message/rfc822

From: Friend <friend@example.org>
To: student@example.org
Subject: notes

Here are the notes.
--b1--
"""


def test_no_file_line_when_the_outer_email_is_the_worst(tmp_path, wide):
    path = tmp_path / "outer_worse.eml"
    path.write_text(OUTER_WORSE, encoding="utf-8")
    result = runner.invoke(cli.app, ["analyze", str(path)])
    assert "Verdict    SUSPICIOUS  45/100" in result.output
    assert "Verdict    LIKELY BENIGN  0/100" in result.output
    assert "File       " not in result.output


def test_overrides_and_notes_are_shown(monkeypatch, wide):
    findings = [find(UH, "a.exe", kind="file"), find(VT, kind="url", malicious=1, engines=90)]
    fake = lambda *_: score_findings(findings, CONFIG)  # noqa: E731
    monkeypatch.setattr(report, "score_analysis", fake)  # step 10: scored in report.py
    result = runner.invoke(cli.app, ["analyze", str(FIXTURES / "legit_newsletter.eml")])
    assert "Verdict    MALICIOUS  100/100" in result.output
    assert "override  An attachment is known malware (urlhaus_listed)" in result.output
    assert "(vt_flagged): 1 of 90 engines say malicious; 3 needed" in result.output
