"""Coverage for the report A/B + cross-artifact validators (B/C batch).

Why this exists
---------------
1. Dead-code reachability (G-060): analysis/validation/*.py modules are roots
   for the audit only through their test imports (test_v02 imports run.py,
   test_v1_mutation imports mutation.py, ...).  val_ab_diff.py and
   val_cross_artifact.py are new modules with no importer, so
   tests/test_v11_dead_code_guard.py fails until a test claims them.
2. The validators themselves are gates -- a bug that made val_ab_diff accept
   an unattributed removal, or val_cross_artifact accept a disagreeing
   artifact, would silently defeat the whole B/C-batch audit trail.  Both are
   exercised here on synthetic report dirs (no network, no real reports).
"""
from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from analysis.validation.val_ab_diff import (  # noqa: E402
    FIX_FAMILIES,
    REPORTS,
    main as ab_main,
)
from analysis.validation.val_cross_artifact import validate  # noqa: E402


# --------------------------------------------------------------------------
# val_ab_diff attribution map
# --------------------------------------------------------------------------

def test_family_map_covers_every_fix_that_can_change_rule_counts():
    """Every batch fix except the PDF-only one must own its rule(s).

    B1 changes no rule counts (render-layer splitInRow), so its absence is
    correct; every other member of the batch must appear, or the A/B diff
    would report its removals as UNATTRIBUTED and fail a correct scan.
    """
    assert set(FIX_FAMILIES) == {
        "B2", "B3", "B4", "B5", "B6", "B7", "B8", "C1", "C2", "C3",
        "D1", "D2"}
    assert "B1" not in FIX_FAMILIES
    # The specific contracts the real A/B runs relied on.
    assert "TAINT_GRAPHQL_INTROSPECTION_ENABLED" in FIX_FAMILIES["B2"]
    assert "CONFIG_CONTEXTUAL_CREDENTIAL" in FIX_FAMILIES["B4"]
    assert "OAUTH_CLIENT_SECRET" in FIX_FAMILIES["B8"]
    assert "TAINT_SQL_INJECTION" in FIX_FAMILIES["C3"]
    assert "EVAL_CALL" in FIX_FAMILIES["C1"]
    assert "LLM02_INSECURE_OUTPUT_HANDLING" in FIX_FAMILIES["D1"]
    assert "PROMPT_TEMPLATE_SECRET_EXPOSURE" in FIX_FAMILIES["D2"]


def test_every_mapped_rule_has_a_nonempty_family():
    for fam, rules in FIX_FAMILIES.items():
        assert rules, fam
        for r in rules:
            assert isinstance(r, str) and r, (fam, r)


def test_report_map_covers_every_audited_target():
    # D-batch defect: REPORTS lacked "diffusers-main", so
    # ``val_ab_diff.py diffusers-main`` compared ZERO targets and still
    # printed the green verdict -- a vacuous PASS is a broken gate.
    for target in ("peft-main", "Open-Assistant-main", "llama_index-main",
                   "diffusers-main"):
        assert target in REPORTS, target
        assert Path(REPORTS[target]).name == "clean_report.json"


def test_empty_target_selection_fails_instead_of_vacuous_pass(monkeypatch,
                                                              capsys):
    monkeypatch.setattr(sys, "argv", ["val_ab_diff.py", "no-such-target"])
    try:
        ab_main()
    except SystemExit as exc:
        assert exc.code == 1
    else:
        raise AssertionError("empty target selection must exit non-zero")
    out = capsys.readouterr().out
    assert "FAIL" in out
    assert "no-such-target" in out


# --------------------------------------------------------------------------
# val_cross_artifact on synthetic report dirs
# --------------------------------------------------------------------------

def _finding(rule, line=1):
    return {"rule_id": rule, "file": "app.py", "line": line,
            "severity": "High", "snippet": "x = 1"}


def _sarif(rules):
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "R-SecOpsX"}},
                      "results": [{"ruleId": r, "ruleIndex": i,
                                   "message": {"text": "m"},
                                   "locations": [{"physicalLocation": {
                                       "artifactLocation": {"uri": "app.py"},
                                       "region": {"startLine": 1}}}]}
                                  for i, r in enumerate(rules)]}]}


def _blueprint(sarif):
    return {
        "tool": "R-SecOpsX",
        "purpose": "DefectDojo import-scan blueprint",
        "api": "/api/v2/import-scan/",
        "file": {"field": "file", "name": "Security_Report.sarif",
                 "content_base64": base64.b64encode(
                     json.dumps(sarif).encode()).decode()},
        "form_fields": {"scan_type": "SARIF", "verified": "false",
                        "minimum_severity": "Info", "active": "true",
                        "close_old_findings": "false", "engagement": "1",
                        "environment": "Development", "tags": "rsecopsx"},
        "curl": "curl -X POST ...",
    }


def _make_report_dir(tmp_path, rules=("R_ALPHA", "R_BETA"),
                     sarif_rules=None, dd_rules=None, pdf_bytes=20_000):
    """Build a minimal internally-consistent report directory."""
    findings = [_finding(r) for r in rules]
    data = {"findings": findings,
            "metadata": {"risk_score": 42.0, "sast_findings": len(findings)}}
    (tmp_path / "clean_report.json").write_text(
        json.dumps(data), encoding="utf-8")
    s = _sarif(list(sarif_rules if sarif_rules is not None else rules))
    (tmp_path / "Security_Report.sarif").write_text(
        json.dumps(s), encoding="utf-8")
    dd = _blueprint(_sarif(list(dd_rules if dd_rules is not None else rules)))
    (tmp_path / "Security_DefectDojo_Import.json").write_text(
        json.dumps(dd), encoding="utf-8")
    for pdf in ("Security_Report.pdf", "Security_Executive_Report.pdf"):
        (tmp_path / pdf).write_bytes(b"0" * pdf_bytes)
    (tmp_path / "Security_CycloneDX.json").write_text(
        json.dumps({"components": [{"name": "pkg", "version": "1.0"}]}),
        encoding="utf-8")
    return tmp_path


def test_consistent_report_dir_passes(tmp_path):
    _make_report_dir(tmp_path)
    errs, notes = validate(str(tmp_path))
    assert errs == [], errs
    joined = "\n".join(notes)
    assert "2 findings" in joined
    assert "DefectDojo blueprint" in joined


def test_sarif_rule_mismatch_is_an_error(tmp_path):
    _make_report_dir(tmp_path, sarif_rules=("R_ALPHA",))  # missing R_BETA
    errs, _ = validate(str(tmp_path))
    assert any("SARIF missing rules" in e and "R_BETA" in e for e in errs), errs


def test_defectdojo_embedded_payload_drift_is_an_error(tmp_path):
    # The blueprint embeds a DIFFERENT SARIF than the on-disk one: the exact
    # drift class the A/B audit trail must never silently accept.
    _make_report_dir(tmp_path, dd_rules=("R_ALPHA", "R_BETA", "R_GAMMA"))
    errs, _ = validate(str(tmp_path))
    assert any("DefectDojo embedded SARIF extra rules" in e and "R_GAMMA" in e
               for e in errs), errs


def test_blueprint_with_wrong_attachment_name_is_an_error(tmp_path):
    _make_report_dir(tmp_path)
    p = tmp_path / "Security_DefectDojo_Import.json"
    dd = json.loads(p.read_text(encoding="utf-8"))
    dd["file"]["name"] = "something_else.json"
    p.write_text(json.dumps(dd), encoding="utf-8")
    errs, _ = validate(str(tmp_path))
    assert any("attaches" in e for e in errs), errs


def test_blueprint_missing_scan_type_is_an_error(tmp_path):
    _make_report_dir(tmp_path)
    p = tmp_path / "Security_DefectDojo_Import.json"
    dd = json.loads(p.read_text(encoding="utf-8"))
    del dd["form_fields"]["scan_type"]
    p.write_text(json.dumps(dd), encoding="utf-8")
    errs, _ = validate(str(tmp_path))
    assert any("scan_type" in e for e in errs), errs


def test_unreadable_embedded_payload_is_an_error_not_a_crash(tmp_path):
    _make_report_dir(tmp_path)
    p = tmp_path / "Security_DefectDojo_Import.json"
    dd = json.loads(p.read_text(encoding="utf-8"))
    dd["file"]["content_base64"] = base64.b64encode(b"not json").decode()
    p.write_text(json.dumps(dd), encoding="utf-8")
    errs, _ = validate(str(tmp_path))
    assert any("unreadable" in e for e in errs), errs


def test_risk_score_disagreement_between_blocks_is_an_error(tmp_path):
    _make_report_dir(tmp_path)
    p = tmp_path / "clean_report.json"
    data = json.loads(p.read_text(encoding="utf-8"))
    data["insights"] = {"risk_score": 11.0}
    p.write_text(json.dumps(data), encoding="utf-8")
    errs, _ = validate(str(tmp_path))
    assert any("risk_score mismatch" in e for e in errs), errs


def test_missing_clean_report_reports_and_does_not_raise(tmp_path):
    errs, notes = validate(str(tmp_path))
    assert errs and "missing clean_report.json" in errs[0]
    assert notes == []
