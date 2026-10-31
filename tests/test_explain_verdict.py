"""DoD gate: --explain-verdict -- every verdict explainable (ground rule 11).

task.md section 15 (Definition of Done):

    `--explain-drops`, `--explain-score`, `--explain-verdict` all functional.

--explain-drops serializes the drop ledger (T-0.1) and --explain-score
surfaces scoring contributions (T-7.1); --explain-verdict is the third
leg: every REPORTED finding's UFIB verdict (disposition +
release_eligible) serialized beside clean_report.json as verdicts.json,
each row carrying the gate results, the category contract and the
rationale that produced it.  The UFIB brain already stamps that audit
onto each finding; this gate pins the serialization surface and the
flag-off invariance (no flag -> no verdicts.json, no payload key, the
report byte-identical to a non-flag scan).
"""
from __future__ import annotations

import json
import pathlib
import subprocess
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

MAIN = REPO / "main.py"


def _ufib_block(category="sql_injection"):
    return {
        "schema": "UFIB-BRAIN-1",
        "contract_schema": "UFIB-CONTRACT-1",
        "category": category,
        "claim": "request value flows to a SQL execute sink",
        "claim_strength": "strong",
        "evidence": [{"kind": "taint", "state": "OBSERVED", "detail": "d"}],
        "gates": [
            {"gate": "G1", "name": "raw_detection_validity", "result": "PASS",
             "reason": "sink match"},
            {"gate": "G3", "name": "evidence_contract", "result": "PASS",
             "reason": "taint path present"},
        ],
        "limitations": ["static-only, no runtime trace"],
        "confirmation_policy": "AUTO_CONFIRM",
        "disposition_rationale": "all mandatory gates passed",
        "original_detector_fields": {"rule_id": "R1"},
    }


def _finding(rule_id="R1", file="app/a.py", line=7, disposition="CONFIRMED",
             release=True, ufib=None, **extra):
    row = {
        "rule_id": rule_id, "file": file, "line": line,
        "title": "sql injection",
        "disposition": disposition, "release_eligible": release,
        "ufib": ufib if ufib is not None else _ufib_block(),
    }
    row.update(extra)
    return row


# ---------------------------------------------------------------------------
# 1. document shape (schema, summary, rows)
# ---------------------------------------------------------------------------
def test_verdicts_document_schema_and_summary():
    from analysis.ufib_release import (
        VERDICTS_SCHEMA, build_verdicts_document,
    )
    payload = {"findings": [
        _finding(rule_id="A", disposition="CONFIRMED", release=True),
        _finding(rule_id="B", disposition="REJECTED_FALSE_POSITIVE",
                 release=False),
        _finding(rule_id="C", disposition="NEEDS_REVIEW", release=False),
    ]}
    doc = build_verdicts_document(payload)
    assert doc["schema"] == VERDICTS_SCHEMA
    s = doc["summary"]
    assert s["total_findings"] == 3
    assert s["released_count"] == 1
    assert s["held_count"] == 2
    assert s["by_disposition"] == {
        "CONFIRMED": 1, "NEEDS_REVIEW": 1, "REJECTED_FALSE_POSITIVE": 1,
    }
    assert s["rows_skipped_not_objects"] == 0
    assert len(doc["verdicts"]) == 3


def test_verdict_rows_sorted_and_explainable():
    from analysis.ufib_release import build_verdicts_document
    payload = {"findings": [
        _finding(rule_id="Z", disposition="CONFIRMED"),
        _finding(rule_id="A", disposition="CONFIRMED"),
        _finding(rule_id="M", disposition="INSUFFICIENT_EVIDENCE",
                 release=False),
    ]}
    doc = build_verdicts_document(payload)
    rows = doc["verdicts"]
    # disposition groups, then rule_id -- deterministic byte-for-byte
    assert [r["rule_id"] for r in rows] == ["A", "Z", "M"]
    for row in rows:
        assert row["disposition"]
        assert isinstance(row["release_eligible"], bool)
        assert row["disposition_rationale"], "every verdict needs a why"
        # gate results travel with the verdict (ground rule 11)
        for gate in row["gates"]:
            assert gate["gate"] and gate["result"] and "reason" in gate


def test_verdict_row_carries_contract_and_gates():
    from analysis.ufib_release import build_verdicts_document
    doc = build_verdicts_document({"findings": [_finding()]})
    row = doc["verdicts"][0]
    assert row["category"] == "sql_injection"
    assert row["claim"] == "request value flows to a SQL execute sink"
    assert row["claim_strength"] == "strong"
    assert row["confirmation_policy"] == "AUTO_CONFIRM"
    assert row["limitations"] == ["static-only, no runtime trace"]
    assert [g["gate"] for g in row["gates"]] == ["G1", "G3"]
    assert row["gates"][0]["result"] == "PASS"
    assert row["gates"][0]["reason"] == "sink match"
    assert row["rule_id"] == "R1" and row["file"] == "app/a.py"
    assert row["line"] == 7


# ---------------------------------------------------------------------------
# 2. held-by-default: an unvalidated finding is never released
# ---------------------------------------------------------------------------
def test_bare_finding_is_held_as_needs_review():
    from analysis.ufib_release import build_verdicts_document
    bare = {"rule_id": "BARE", "file": "x.py", "line": 1}
    doc = build_verdicts_document({"findings": [bare]})
    row = doc["verdicts"][0]
    assert row["disposition"] == "NEEDS_REVIEW"
    assert row["release_eligible"] is False
    assert "zero-silent-loss" in row["disposition_rationale"]
    assert row["gates"] == []
    assert row["category"] == "_unevaluated"


def test_analysis_error_verdict_keeps_error_rationale():
    from analysis.ufib_release import build_verdicts_document
    f = _finding(disposition="ANALYSIS_ERROR", release=False,
                 ufib={"schema": "UFIB-BRAIN-1",
                       "error": "RuntimeError: boom",
                       "disposition_rationale": "the brain could not "
                                                "evaluate this finding"})
    doc = build_verdicts_document({"findings": [f]})
    row = doc["verdicts"][0]
    assert row["disposition"] == "ANALYSIS_ERROR"
    assert row["release_eligible"] is False
    assert "could not evaluate" in row["disposition_rationale"]
    assert row["gates"] == []


def test_non_dict_rows_are_counted_never_crash():
    from analysis.ufib_release import build_verdicts_document
    doc = build_verdicts_document({"findings": [
        _finding(), "junk", None, 42,
    ]})
    assert doc["summary"]["total_findings"] == 1
    assert doc["summary"]["rows_skipped_not_objects"] == 3


def test_empty_payload_is_valid():
    from analysis.ufib_release import build_verdicts_document
    doc = build_verdicts_document({"findings": []})
    assert doc["verdicts"] == []
    assert doc["summary"]["total_findings"] == 0
    assert doc["summary"]["released_count"] == 0
    assert doc["summary"]["held_count"] == 0
    assert doc["summary"]["by_disposition"] == {}
    assert doc["summary"]["scan_status"] == "INCOMPLETE"


# ---------------------------------------------------------------------------
# 3. determinism + vocabulary consistency
# ---------------------------------------------------------------------------
def test_document_is_byte_identical_across_builds():
    import copy
    from analysis.ufib_release import build_verdicts_document
    payload = {"findings": [
        _finding(rule_id="B", disposition="LIKELY", release=True),
        _finding(rule_id="A", disposition="CONFIRMED", release=True),
        _finding(rule_id="C", disposition="NEEDS_REVIEW", release=False),
        {"rule_id": "D"},
    ]}
    d1 = build_verdicts_document(payload)
    d2 = build_verdicts_document(copy.deepcopy(payload))
    assert (json.dumps(d1, sort_keys=True, default=str)
            == json.dumps(d2, sort_keys=True, default=str))


def test_release_flag_mirrors_the_vocabulary():
    from analysis.ufib_release import (
        RELEASE_DISPOSITIONS, build_release_manifest,
        build_verdicts_document,
    )
    findings = [_finding(disposition=d, release=RELEASE_DISPOSITIONS[d])
                for d in sorted(RELEASE_DISPOSITIONS)]
    doc = build_verdicts_document({"findings": findings})
    manifest = build_release_manifest({"findings": findings})
    assert doc["summary"]["released_count"] == manifest["released_count"]
    assert doc["summary"]["held_count"] == manifest["held_count"]
    assert doc["summary"]["by_disposition"] == manifest["by_disposition"]


def test_rows_follow_the_real_brain_verdict():
    """End-to-end at unit level: evaluate_finding -> document row."""
    from analysis.ufib_brain import evaluate_finding
    from analysis.ufib_release import build_verdicts_document
    f = {"rule_id": "REAL", "severity": "high", "confidence": "HIGH",
         "file": "app/s.py", "line": 3,
         "snippet": "cur.execute('SELECT ' + request.args['q'])"}
    disposition = evaluate_finding(f, target=None)
    doc = build_verdicts_document({"findings": [f]})
    row = doc["verdicts"][0]
    assert row["disposition"] == disposition
    assert row["release_eligible"] is (disposition in ("CONFIRMED", "LIKELY"))
    assert row["gates"], "brain gates must ride into the verdict document"
    assert row["disposition_rationale"]


# ---------------------------------------------------------------------------
# 4. CLI: --explain-verdict writes verdicts.json; flag-off is invariant
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module")
def scan_with_flag(tmp_path_factory):
    proj = tmp_path_factory.mktemp("rsx_verdict_proj")
    (proj / "vuln.py").write_text(
        "import subprocess\n"
        "def handler(request):\n"
        "    subprocess.call('ls ' + request.args['q'], shell=True)\n",
        encoding="utf-8")
    outdir = tmp_path_factory.mktemp("rsx_verdict_out_on")
    proc = subprocess.run(
        [sys.executable, str(MAIN), str(proj),
         "--output-dir", str(outdir), "--no-pdf", "--no-excel",
         "--explain-verdict", "--workers", "1"],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        cwd=str(REPO), timeout=1800,
    )
    return proc, outdir


@pytest.fixture(scope="module")
def scan_without_flag(tmp_path_factory):
    proj = tmp_path_factory.mktemp("rsx_verdict_proj_off")
    (proj / "vuln.py").write_text(
        "import subprocess\n"
        "def handler(request):\n"
        "    subprocess.call('ls ' + request.args['q'], shell=True)\n",
        encoding="utf-8")
    outdir = tmp_path_factory.mktemp("rsx_verdict_out_off")
    proc = subprocess.run(
        [sys.executable, str(MAIN), str(proj),
         "--output-dir", str(outdir), "--no-pdf", "--no-excel",
         "--workers", "1"],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        cwd=str(REPO), timeout=1800,
    )
    return proc, outdir


def test_cli_scan_exits_zero(scan_with_flag):
    proc, _outdir = scan_with_flag
    assert proc.returncode == 0, (
        f"main.py exited {proc.returncode}.\n"
        f"--- stdout tail ---\n{(proc.stdout or '')[-3000:]}\n"
        f"--- stderr tail ---\n{(proc.stderr or '')[-3000:]}"
    )


def test_cli_writes_verdicts_json(scan_with_flag):
    _proc, outdir = scan_with_flag
    path = outdir / "verdicts.json"
    assert path.exists(), "--explain-verdict must write verdicts.json"
    doc = json.loads(path.read_text(encoding="utf-8"))
    from analysis.ufib_release import VERDICTS_SCHEMA
    assert doc["schema"] == VERDICTS_SCHEMA
    report = json.loads((outdir / "clean_report.json").read_text(
        encoding="utf-8"))
    n_findings = len([f for f in report.get("findings") or []
                      if isinstance(f, dict)])
    assert doc["summary"]["total_findings"] == n_findings
    assert len(doc["verdicts"]) == n_findings
    assert doc["summary"]["released_count"] + doc["summary"]["held_count"] \
        == n_findings
    for row in doc["verdicts"]:
        assert row["disposition"], row
        assert isinstance(row["release_eligible"], bool)
        assert row["disposition_rationale"], row


def test_cli_summary_rides_inside_report(scan_with_flag):
    _proc, outdir = scan_with_flag
    report = json.loads((outdir / "clean_report.json").read_text(
        encoding="utf-8"))
    summary = report.get("verdict_explanation_summary")
    assert summary, "report must self-describe its verdict summary"
    doc = json.loads((outdir / "verdicts.json").read_text(encoding="utf-8"))
    assert summary == doc["summary"]


def test_cli_flag_off_writes_no_verdict_artifacts(scan_without_flag):
    proc, outdir = scan_without_flag
    assert proc.returncode == 0, (
        f"main.py exited {proc.returncode}.\n"
        f"--- stderr tail ---\n{(proc.stderr or '')[-3000:]}"
    )
    assert not (outdir / "verdicts.json").exists(), (
        "without --explain-verdict no verdicts.json may appear"
    )
    report = json.loads((outdir / "clean_report.json").read_text(
        encoding="utf-8"))
    assert "verdict_explanation_summary" not in report, (
        "flag-off payload must not gain verdict keys (byte-identity)"
    )
