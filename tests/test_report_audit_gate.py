"""B8 (SAST overnight): the report audit gate runs its FULL registered
CHECKS suite fail-closed, and the new SAST invariants (AUD-S01 identity,
AUD-S02 verdict consistency/suppression explainability) reject real
breaches without failing on legitimate payloads.
"""
from __future__ import annotations

import json
from pathlib import Path

from tools import report_audit


def _payload(**over):
    findings = over.pop("findings", None) or [
        {"rule_id": "SQL_INJECTION_DEMO", "severity": "critical",
         "file": "app.py", "line": 3, "disposition": "CONFIRMED"},
        {"rule_id": "XSS_DEMO", "severity": "low",
         "file": "web.js", "line": 8, "disposition": "NEEDS_REVIEW",
         "accuracy": {"verdict": "NEEDS_REVIEW", "reason": "static"}},
    ]
    # aggregates/filter_trace/metadata must describe the FINAL findings
    # population (the audit's AUD-003/004 invariants are exactly that).
    payload = {
        "findings": findings,
        "metadata": {"raw_candidates": len(findings)},
        "filter_trace": [],
        "aggregates": {
            "consistency": {"ok": True, "failing": []},
            "counts": {"total_reported": len(findings),
                       "sast_records": len(findings),
                       "sca_vulnerable_packages": 0,
                       "grouped_records": len(findings)},
        },
    }
    payload.update(over)
    return payload


_MAKE_DIR_N = [0]


def _make_out_dir(tmp_path: Path, payload: dict) -> Path:
    _MAKE_DIR_N[0] += 1
    out = tmp_path / f"scan_out_{_MAKE_DIR_N[0]}"
    out.mkdir(parents=True)
    (out / "clean_report.json").write_text(
        json.dumps(payload), encoding="utf-8")
    # AUD-005/006 artifacts (>= MIN_ARTIFACT_BYTES); content is not parsed
    for name in ("Security_Report.pdf", "Security_Report.xlsx"):
        (out / name).write_bytes(b"PADDING" * 256)
    return out


def test_full_checks_suite_passes_on_a_consistent_fixture(tmp_path):
    out = _make_out_dir(tmp_path, _payload())
    rc = report_audit.main([str(out)])
    assert rc == 0, "every registered check must pass on a clean fixture"


def test_sast_identity_breaches_fail_closed(tmp_path):
    for breach in (
        {"rule_id": ""},          # empty rule_id
        {"file": ""},             # empty file
        {"line": 0},              # invalid line
    ):
        f = {"rule_id": "R", "severity": "high", "file": "a.py", "line": 1}
        f.update(breach)
        out = _make_out_dir(tmp_path, _payload(findings=[f]))
        rc = report_audit.main([str(out)])
        assert rc == 1, f"breach {breach} must fail the gate"


def test_verdict_vocabulary_breach_fails_closed(tmp_path):
    out = _make_out_dir(tmp_path, _payload(findings=[
        {"rule_id": "R", "severity": "high", "file": "a.py", "line": 1,
         "disposition": "MAGIC_UNICORN"}]))
    assert report_audit.main([str(out)]) == 1


def test_suppressed_without_reason_fails_closed(tmp_path):
    out = _make_out_dir(tmp_path, _payload(findings=[
        {"rule_id": "R", "severity": "high", "file": "a.py", "line": 1,
         "disposition": "NEEDS_REVIEW",
         "accuracy": {"verdict": "SUPPRESSED_USER", "reason": ""}}]))
    assert report_audit.main([str(out)]) == 1


def test_suppressed_with_reason_passes(tmp_path):
    out = _make_out_dir(tmp_path, _payload(findings=[
        {"rule_id": "R", "severity": "high", "file": "a.py", "line": 1,
         "disposition": "NEEDS_REVIEW",
         "accuracy": {"verdict": "SUPPRESSED_USER",
                      "reason": "inline sast-ignore RULE reason"}}]))
    assert report_audit.main([str(out)]) == 0


def test_aggregates_inconsistency_still_fails_closed(tmp_path):
    # The pre-existing AUD-003 invariant must keep failing: regressions in
    # the old checks are caught by this fixture.
    payload = _payload()
    payload["aggregates"]["counts"]["total_reported"] = 99
    out = _make_out_dir(tmp_path, payload)
    assert report_audit.main([str(out)]) == 1


def test_crashing_check_is_a_breach_never_a_pass(tmp_path):
    out = _make_out_dir(tmp_path, _payload())
    idx = next(i for i, (cid, _d, _f) in enumerate(report_audit.CHECKS)
               if cid == "AUD-S01")
    cid, desc, original = report_audit.CHECKS[idx]

    def boom(_out, _payload):
        raise RuntimeError("injected")

    report_audit.CHECKS[idx] = (cid, desc, boom)
    try:
        rc = report_audit.main([str(out)])
    finally:
        report_audit.CHECKS[idx] = (cid, desc, original)
    assert rc == 1, "a crashing check is a breach, never a pass"
