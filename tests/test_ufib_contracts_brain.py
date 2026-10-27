# -*- coding: utf-8 -*-
r"""UFIB Phase 12: contract and brain-gate tests.

Every test maps to a mission invariant:
  * contracts are versioned and complete for the measured rule inventory;
  * UNKNOWN mandatory evidence is never satisfied (mission 5 G3);
  * decisive counterevidence blocks CONFIRMED regardless of severity or
    confidence (mission 1's "never overridden" clause);
  * an unmatched category is never silently confirmed (mission 10);
  * detector output is never overwritten (mission 3.1);
  * a brain crash on one finding is ANALYSIS_ERROR for that finding and
    NEEDS_REVIEW at release level -- fail-soft, loud, never confirmed
    (mission 10, safe failure direction);
  * zero silent loss: every finding leaves evaluation with a disposition.
"""
from __future__ import annotations

import pathlib
import sys
import tempfile

import pytest

sys.path.insert(0, r"D:\Data\Code test\R-SecOpsX_V11")

from analysis import ufib_brain as brain
from analysis.ufib_contracts import (
    CONTRACTS,
    DEFAULT_CONTRACT,
    UFIB_CONTRACT_SCHEMA,
    build_claim,
    get_contract,
    resolve_category,
)
from analysis.ufib_release import (
    RELEASE_POLICY_VERSION,
    UFIB_RELEASE_SCHEMA,
    apply_ufib_to_payload,
    build_release_manifest,
    refresh_release_manifest,
)


# ---------------------------------------------------------------------------
# Contracts (Phase 5)
# ---------------------------------------------------------------------------
def test_contracts_are_versioned_and_complete():
    assert CONTRACTS
    for key, c in CONTRACTS.items():
        assert c["schema"] == UFIB_CONTRACT_SCHEMA, key
        assert c["category"] == key
        assert c["claim"] and len(c["claim"]) > 40, key
        assert c["required_evidence"], key
        assert c["confirmation_policy"] in (
            "ALL_MANDATORY_AND_DATAFLOW",
            "MANDATORY_AND_NO_CONTRADICTION",
            "MANUAL_REVIEW_ONLY",
        ), key
        for ce in c["counterevidence"]:
            assert ce["pattern"].search("") is not None or True
            # A pattern that cannot compile raises here:
            ce["pattern"].search("probe")


def test_every_measured_rule_maps_to_a_contract():
    """The 319-rule inventory must resolve: known ids to a real category,
    unknown ids to the DEFAULT manual-review contract -- never silently
    confirmed."""
    from scanner import iac_docker, iac_kubernetes, iac_terraform
    from scanner import llm_security, sast, secret_intelligence, taint_engine
    from scanner.cbom import CRYPTO_RULES

    rules: list[str] = []
    rules += [r["id"] for r in sast.ENTERPRISE_RULES]
    rules += [r["id"] for r in sast.REGEX_RULES]
    rules += [r[0] for r in secret_intelligence.KNOWN_SECRET_RULES]
    rules += [r[0] for r in secret_intelligence.SECRET_RULES]
    rules += [r["rule_id"] for r in iac_terraform.RULES]
    rules += [r["rule_id"] for r in iac_docker.RULES]
    rules += [r["rule_id"] for r in iac_kubernetes.RULES]
    rules += [r["rule_id"] for r in iac_kubernetes.MISSING_RULES]
    rules += [r["rule_id"] for r in llm_security.LLM_RULES]
    rules += [r["component"] for r in CRYPTO_RULES]
    rules += [r["id"] for r in taint_engine.ENTERPRISE_TAINT_RULES]

    assert len(rules) >= 300, "rule inventory unexpectedly small: %d" % len(rules)
    unresolved = []
    for rid in rules:
        cat = resolve_category({"rule_id": rid, "vuln_type": ""})
        contract = get_contract(cat)
        if contract is DEFAULT_CONTRACT:
            unresolved.append(rid)
    from analysis.ufib_contracts import DOCUMENTED_DEFAULT_RULES
    unexpected = [r for r in unresolved if r not in DOCUMENTED_DEFAULT_RULES]
    # An engine's own shipped rules must not fall outside the documented
    # DEFAULT allowlist -- silent category gaps are how claims go unchecked.
    assert not unexpected, (
        "%d engine rules resolved outside the documented DEFAULT allowlist: %s"
        % (len(unexpected), unexpected[:10]))


def test_claim_never_stronger_than_evidence():
    weak = {"rule_id": "CONFIG_CONTEXTUAL_CREDENTIAL",
            "snippet": "password_field = request.form.get('password')"}
    strong = {"rule_id": "TAINT_SQL_INJECTION", "snippet": "cursor.execute(q)",
              "taint_validated": True, "sink_validated": True,
              "evidence_validation_detail": {"taint_validated": True,
                                             "sink_valid": True}}
    _c, w_strength = build_claim("hardcoded_secret", weak)
    _c2, s_strength = build_claim("sql_injection", strong)
    assert w_strength == "WEAK"
    assert s_strength == "STRONG"


# ---------------------------------------------------------------------------
# Gate invariants (Phases 6-7)
# ---------------------------------------------------------------------------
def _mk(**kw):
    base = {"rule_id": "X", "file": "f.py", "line": 1, "snippet": "s()",
            "severity": "Medium", "instances": 1, "group_key": "g"}
    base.update(kw)
    return base


def test_unknown_mandatory_never_satisfied():
    f = _mk(rule_id="TAINT_SSRF_EXPANDED", vuln_type="ssrf",
            snippet='requests.get(url)')
    d = brain.evaluate_finding(f, None)
    assert d == "INSUFFICIENT_EVIDENCE"
    # The sink construct IS observed (G3); what is unknown is the FLOW (G4).
    g4 = [g for g in f["ufib"]["gates"] if g["gate"] == "G4"][0]
    assert g4["result"] == "UNKNOWN"
    assert any(e["state"] == "UNKNOWN" and "never counts as flow"
               in e["detail"] for e in f["ufib"]["evidence"])


def test_decisive_counterevidence_beats_severity_and_confidence():
    f = _mk(rule_id="TAINT_SQL_INJECTION", vuln_type="sql_injection",
            severity="Critical", confidence="HIGH",
            snippet='cursor.execute("SELECT .. WHERE id=%s", (uid,))')
    d = brain.evaluate_finding(f, None)
    assert d == "REJECTED_FALSE_POSITIVE"
    g6 = [g for g in f["ufib"]["gates"] if g["gate"] == "G6"][0]
    assert g6["result"] == "FAIL"
    # The rejection rationale names the counterevidence:
    assert "decisive counterevidence" in g6["reason"]


def test_placeholder_secret_rejected_but_live_validated_secret_survives(tmp_path):
    placeholder = _mk(rule_id="CONFIG_CONTEXTUAL_CREDENTIAL",
                      snippet='password = "EXAMPLE_VALUE_HERE"', line=4)
    assert brain.evaluate_finding(placeholder, None) == "REJECTED_FALSE_POSITIVE"

    # A live-validated secret survives even with a placeholder-looking word,
    # when its file context is verifiable (mission H).
    real_file = tmp_path / "app.properties"
    real_file.write_text('api_key = "live-validated-example-key-9f2c"\n',
                         encoding="utf-8")
    real = _mk(rule_id="CONFIG_CONTEXTUAL_CREDENTIAL", file=str(real_file),
               line=1, validated_live=True)
    d = brain.evaluate_finding(real, str(tmp_path))
    assert d == "CONFIRMED", d
    kinds = [e["kind"] for e in real["ufib"]["evidence"]]
    assert any("live_validated_secret" in k for k in kinds)


def test_unreadable_context_caps_confirmation_at_likely():
    """Mission 5: UNKNOWN context is never satisfied. A hardcoded secret whose
    file cannot be read is released at LIKELY with the cap recorded -- never
    CONFIRMED, never silently accepted as context-clean."""
    f = _mk(rule_id="CONFIG_CONTEXTUAL_CREDENTIAL",
            snippet='password = "Str0ngPr0dVal!"', line=5)
    d = brain.evaluate_finding(f, None)
    assert d == "LIKELY"
    kinds = [e["kind"] for e in f["ufib"]["evidence"]]
    assert any("context_unverifiable" in k for k in kinds)


def test_unmatched_category_never_confirmed():
    f = _mk(rule_id="SOME_FUTURE_RULE_XYZ", snippet="weird_pattern()")
    d = brain.evaluate_finding(f, None)
    assert d == "NEEDS_REVIEW"
    assert f["ufib"]["category"] == "_default"
    assert f["ufib"]["confirmation_policy"] == "MANUAL_REVIEW_ONLY"


def test_detector_output_never_overwritten(tmp_path):
    dao = tmp_path / "dao.py"
    dao.write_text('cursor.execute("SELECT * FROM users WHERE id=" + q)\n',
                   encoding="utf-8")
    original = {
        "rule_id": "TAINT_SQL_INJECTION", "severity": "High",
        "confidence": "MEDIUM", "cve": "", "package": "", "version": "",
        "line": 1, "file": str(dao), "snippet": "cursor.execute(q)",
        "evidence": "cursor.execute(q)",
        "taint_validated": True, "sink_validated": True,
        "evidence_validation_detail": {"taint_validated": True,
                                       "sink_valid": True},
        "instances": 1, "group_key": "g", "vuln_type": "sql_injection",
    }
    snapshot = dict(original)
    d = brain.evaluate_finding(original, str(tmp_path))
    assert d == "CONFIRMED"
    for k, v in snapshot.items():
        assert original[k] == v, "brain overwrote %r" % k
    # And the original snapshot lives INSIDE the audit block:
    assert original["ufib"]["original_detector_fields"]["severity"] == "High"


def test_k8s_pod_level_inheritance_rejects(tmp_path):
    pod = tmp_path / "pod.yaml"
    pod.write_text(
        "apiVersion: v1\n"
        "kind: Pod\n"
        "spec:\n"
        "  securityContext:\n"
        "    runAsNonRoot: true\n"
        "  containers:\n"
        "    - name: agent\n"
        "      image: acme/agent:1.0\n", encoding="utf-8")
    f = _mk(rule_id="K8S_MISSING_RUN_AS_NON_ROOT", file=str(pod), line=7,
            snippet="- name: agent")
    d = brain.evaluate_finding(f, str(tmp_path))
    assert d == "REJECTED_FALSE_POSITIVE"
    kinds = [e["kind"] for e in f["ufib"]["evidence"]]
    assert any("pod_level_inheritance" in k for k in kinds)


def test_k8s_genuinely_missing_nonroot_survives(tmp_path):
    pod = tmp_path / "pod.yaml"
    pod.write_text(
        "apiVersion: v1\n"
        "kind: Pod\n"
        "spec:\n"
        "  containers:\n"
        "    - name: agent\n"
        "      image: acme/agent:1.0\n", encoding="utf-8")
    f = _mk(rule_id="K8S_MISSING_RUN_AS_NON_ROOT", file=str(pod), line=5,
            snippet="- name: agent")
    d = brain.evaluate_finding(f, str(tmp_path))
    assert d == "CONFIRMED"


def test_fail_soft_analysis_error(tmp_path, monkeypatch):
    f = _mk(rule_id="TAINT_SQL_INJECTION", vuln_type="sql_injection",
            snippet="cursor.execute(q)", taint_validated=True,
            sink_validated=True,
            evidence_validation_detail={"taint_validated": True,
                                        "sink_valid": True})
    monkeypatch.setattr(brain, "_g6_contradiction",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    d = brain.evaluate_finding(f, None)
    assert d == "ANALYSIS_ERROR"
    assert "boom" in f["ufib"]["error"]
    assert f["release_eligible"] is False


def test_control_gap_with_present_control_rejected(tmp_path):
    f1 = tmp_path / "login2.js"
    f1.write_text('const limiter = require("express-rate-limit");\n', encoding="utf-8")
    f2 = tmp_path / "login3.js"
    f2.write_text('app.post("/login", handler);\n', encoding="utf-8")
    rejected = _mk(rule_id="MISSING_RATE_LIMIT_ENDPOINT", file=str(f1), line=1,
                   snippet='app.post("/login")')
    assert brain.evaluate_finding(rejected, str(tmp_path)) == "REJECTED_FALSE_POSITIVE"
    held = _mk(rule_id="MISSING_RATE_LIMIT_ENDPOINT", file=str(f2), line=1,
               snippet='app.post("/login")')
    assert brain.evaluate_finding(held, str(tmp_path)) == "NEEDS_REVIEW"
    # The held one says exactly why it stays:
    g5 = [g for g in held["ufib"]["gates"] if g["gate"] == "G5"][0]
    assert g5["result"] == "PASS"


# ---------------------------------------------------------------------------
# Release controller (Phase 11)
# ---------------------------------------------------------------------------
def test_manifest_zero_silent_loss_and_policy_version():
    payload = {"findings": [
        _mk(rule_id="TAINT_SQL_INJECTION", vuln_type="sql_injection",
            snippet="cursor.execute('q')", taint_validated=True,
            sink_validated=True,
            evidence_validation_detail={"taint_validated": True,
                                        "sink_valid": True}),
        _mk(rule_id="TOTALLY_UNKNOWN_RULE", line=2),
    ]}
    payload = apply_ufib_to_payload(payload, None)
    rm = payload["release_manifest"]
    assert rm["schema"] == UFIB_RELEASE_SCHEMA
    assert rm["policy_version"] == RELEASE_POLICY_VERSION
    assert rm["zero_silent_loss"] is True
    assert rm["total_findings"] == 2
    assert sum(rm["by_disposition"].values()) == 2
    assert rm["released_count"] + rm["held_count"] == 2
    assert rm["scan_status"] in ("COMPLETE", "PARTIAL", "INCOMPLETE",
                                 "FAILED", "UNKNOWN")


def test_refresh_preserves_dispositions_and_holds_late_arrivals():
    payload = {"findings": [
        _mk(rule_id="TAINT_SQL_INJECTION", vuln_type="sql_injection",
            snippet="cursor.execute('q')", taint_validated=True,
            sink_validated=True,
            evidence_validation_detail={"taint_validated": True,
                                        "sink_valid": True}),
        _mk(rule_id="TOTALLY_UNKNOWN_RULE", line=2),
    ]}
    payload = apply_ufib_to_payload(payload, None)
    before = [f["disposition"] for f in payload["findings"]]
    # A late pipeline stage adds a finding the brain never saw:
    payload["findings"].append(_mk(rule_id="LATE_ADDITION", line=3))
    refresh_release_manifest(payload)
    after = [f["disposition"] for f in payload["findings"]]
    assert after[:len(before)] == before, "refresh rewrote dispositions"
    assert after[-1] == "NEEDS_REVIEW", "late arrival was released silently"
    assert payload["release_manifest"]["zero_silent_loss"] is True


def test_brain_crash_marks_population_needs_review(monkeypatch):
    import analysis.ufib_release as release

    def boom(finding, target=None):
        raise RuntimeError("brain down")
    monkeypatch.setattr(release, "evaluate_finding", boom)
    payload = {"findings": [_mk(), _mk(line=2)]}
    payload = release.apply_ufib_to_payload(payload, None)
    assert payload["ufib_error"]
    assert payload["release_manifest"]["scan_status"] == "PARTIAL"
    for f in payload["findings"]:
        assert f["disposition"] == "NEEDS_REVIEW"
        assert f["release_eligible"] is False


# ---------------------------------------------------------------------------
# Report-format consistency (Phase 11 / mission 9)
# ---------------------------------------------------------------------------
def test_sarif_carries_the_same_disposition():
    from reporting.sarif_export import _decision_properties

    f = _mk(rule_id="TAINT_SQL_INJECTION", vuln_type="sql_injection",
            snippet="cursor.execute('q')", taint_validated=True,
            sink_validated=True,
            evidence_validation_detail={"taint_validated": True,
                                        "sink_valid": True})
    brain.evaluate_finding(f, None)
    props = _decision_properties(f)
    assert props["ufib_disposition"] == f["disposition"]
    assert props["ufib_release_eligible"] == "true" if f["release_eligible"] \
        else props["ufib_release_eligible"] == "false"
    # Absence-safe: a finding the brain never saw reads NOT_RECORDED.
    bare = _mk()
    assert _decision_properties(bare)["ufib_disposition"] == "NOT_RECORDED"
