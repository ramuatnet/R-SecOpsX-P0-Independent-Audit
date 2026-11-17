"""B6/E7 (SAST overnight): the scoring service is wired into the payload
and --explain-score explains REAL contributors.

cltask G1.6/DEC-06: wire analysis/scoring/score.py into
payload["scoring"]; expose --explain-score only when it explains actual
score contributors. No third score model: the pipeline's separate
core.risk_scorer per-finding contract is untouched.
"""
from __future__ import annotations

import json

from analysis.scoring.connect import build_explain_scores_document
from analysis.scoring.score import SCHEMA, score_findings


def _payload(**over):
    findings = [
        {"rule_id": "SQL_INJECTION_DEMO", "severity": "critical",
         "file": "app.py", "line": 3},
        {"rule_id": "XSS_DEMO", "severity": "medium",
         "file": "web.js", "line": 8},
        "not-a-dict-row",  # must surface as a machine-readable skip
    ]
    payload = {"findings": findings}
    payload.update(over)
    return payload


def test_score_findings_wired_artifact_shape():
    art = score_findings(_payload(), explain=True)
    assert art["schema"] == SCHEMA == "rsecopsx.score/v1"
    assert art["stats"]["scored"] == 2
    assert art["stats"]["skips"] == 1
    assert art["skips"][0]["reason"] == "finding_rows_not_objects"
    assert len(art["scores"]) == 2
    row = art["scores"][0]
    # the full explain row: real contributors, not placeholders
    assert row["rule_id"] == "SQL_INJECTION_DEMO"
    assert set(row) >= {"rule_id", "score", "band", "base",
                        "contributions", "feedback", "raw", "clamped"}
    assert len(row["contributions"]) == 8
    assert row["base"]["value"] >= 0.0
    assert row["base"].get("source"), "base must disclose its source"


def test_payload_scoring_is_deterministic_for_default_findings():
    # Findings without score_context score deterministically (base from
    # severity, neutral factor deltas). Two calls agree byte-for-byte on
    # the scores list modulo the wall-clock as_of stamp.
    a = score_findings(_payload(), explain=True)
    b = score_findings(_payload(), explain=True)
    assert a["scores"] == b["scores"]
    assert a["stats"] == b["stats"]
    # severity drives the base: critical > medium
    scores = {r["rule_id"]: r["score"] for r in a["scores"]}
    assert scores["SQL_INJECTION_DEMO"] > scores["XSS_DEMO"]


def test_explain_scores_document_reads_real_rows():
    art = score_findings(_payload(), explain=True)
    doc = build_explain_scores_document({"scoring": art})
    assert doc["schema"] == "rsecopsx.explain_scores/v1"
    assert doc["scores"] == art["scores"], "rows must travel verbatim"
    assert doc["as_of"] == art["as_of"]
    assert doc["stats"] == {"scored": 2, "skips": 1}
    assert isinstance(json.dumps(doc), str)


def test_explain_scores_document_discloses_missing_scoring():
    # No placeholders: a payload without scoring discloses the reason.
    doc = build_explain_scores_document({"findings": []})
    assert doc["scores"] == []
    assert doc["stats"] == {"scored": 0, "skips": 1}
    assert doc["skips"][0]["reason"] == "scoring_not_computed"


def test_main_py_wiring_is_present():
    # Source-level pin (mirrors the t1402 workflow pin): the payload wire,
    # the flag and the writer exist in main.py. (Importing main is heavy;
    # the integration behaviour is covered by the two-scan determinism
    # gate which now exercises payload["scoring"] on every run.)
    text = open("main.py", encoding="utf-8").read()
    assert 'dest="explain_score"' in text
    assert "build_explain_scores_document(payload)" in text
    assert "_score_service.score_findings(payload, explain=True)" in text
    assert 'payload["scoring"] = _score_artifact' in text
