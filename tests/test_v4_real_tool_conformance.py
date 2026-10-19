"""V4: real external-tool conformance layer (BLOCKED discipline).

analysis/validation/sbom_conformance.py now runs the real community
tooling (OWASP aibom-generator validator/scorer, cbomkit's
quantum-safe OPA policy, cbomkit-theia) when available, and reports
BLOCKED -- never silent agreement -- when a piece is absent. These
tests pin, hermetically (no docker, no network, no external tools):

  * every check reports BLOCKED with the env cleared and no docker/opa
  * OPA findings parsing: quantum-vulnerable counted, refs collected,
    global status derived, and a "vulnerable" verdict stays PASS (it is
    a true statement about the code, not a document defect)
  * opa/theia/driver execution errors are FAIL, not BLOCKED
  * theia output parsing accepts a CDX 1.6 echo and rejects other docs
  * the aibom-generator driver payload maps to PASS/FAIL + score
  * exit-code discipline: BLOCKED never fails the gate, FAIL does
  * validate_sbom_conformance()'s own result shape is unchanged
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from analysis.validation import sbom_conformance as sc  # noqa: E402


def _clean_env(monkeypatch, tmp_path):
    for var in ("RSX_AIBOM_GENERATOR", "RSX_AIBOM_GENERATOR_PYTHON",
                "RSX_OPA", "RSX_CBOMKIT_REGO", "RSX_CBOMKIT_THEIA_IMAGE"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("PATH", str(tmp_path))  # no opa/docker discoverable


def test_all_checks_blocked_when_tools_absent(monkeypatch, tmp_path):
    _clean_env(monkeypatch, tmp_path)
    results = sc.validate_real_tool_conformance(tmp_path)
    assert set(results) == {"aibom_generator", "cbomkit_quantum_safe",
                            "cbomkit_theia"}
    for name, result in results.items():
        assert result["status"] == "BLOCKED", (name, result)
        assert result["reason"], name
    assert not sc._real_tool_failed(results)


def test_quantum_safe_parses_findings(monkeypatch, tmp_path):
    _clean_env(monkeypatch, tmp_path)
    monkeypatch.setenv("RSX_OPA", "opa-fake")
    rego = tmp_path / "quantum_safe.rego"
    rego.write_text("package policies", encoding="utf-8")
    monkeypatch.setenv("RSX_CBOMKIT_REGO", str(rego))
    (tmp_path / "Security_CBOM.cdx.json").write_text("{}", encoding="utf-8")

    payload = {"result": [{"expressions": [{"value": [
        {"rule": "nist_qs_level", "result": "quantum-vulnerable",
         "bom-ref": "r1"},
        {"rule": "nist_qs_level", "result": "quantum-safe", "bom-ref": "r2"},
        {"rule": "symmetric_na", "result": "NA", "bom-ref": "r1"},
    ]}]}]}
    monkeypatch.setattr(sc, "_shell", lambda cmd, timeout=120: (
        0, json.dumps(payload), ""))

    result = sc._real_cbomkit_quantum_safe_check(tmp_path)
    assert result["status"] == "PASS"
    assert result["findings"] == 3
    assert result["quantum_vulnerable"] == 1
    assert result["global_quantum_safe"] is False
    assert result["vulnerable_refs"] == ["r1"]


def test_quantum_safe_clean_cbom_is_global_safe(monkeypatch, tmp_path):
    _clean_env(monkeypatch, tmp_path)
    monkeypatch.setenv("RSX_OPA", "opa-fake")
    rego = tmp_path / "quantum_safe.rego"
    rego.write_text("package policies", encoding="utf-8")
    monkeypatch.setenv("RSX_CBOMKIT_REGO", str(rego))
    (tmp_path / "Security_CBOM.cdx.json").write_text("{}", encoding="utf-8")
    payload = {"result": [{"expressions": [{"value": [
        {"rule": "symmetric_na", "result": "NA", "bom-ref": "r1"}]}]}]}
    monkeypatch.setattr(sc, "_shell", lambda cmd, timeout=120: (
        0, json.dumps(payload), ""))
    result = sc._real_cbomkit_quantum_safe_check(tmp_path)
    assert result["status"] == "PASS"
    assert result["global_quantum_safe"] is True


def test_opa_error_is_fail_not_blocked(monkeypatch, tmp_path):
    _clean_env(monkeypatch, tmp_path)
    monkeypatch.setenv("RSX_OPA", "opa-fake")
    rego = tmp_path / "quantum_safe.rego"
    rego.write_text("package policies", encoding="utf-8")
    monkeypatch.setenv("RSX_CBOMKIT_REGO", str(rego))
    (tmp_path / "Security_CBOM.cdx.json").write_text("{}", encoding="utf-8")
    monkeypatch.setattr(sc, "_shell", lambda cmd, timeout=120: (
        1, "", "rego compile error"))
    result = sc._real_cbomkit_quantum_safe_check(tmp_path)
    assert result["status"] == "FAIL"
    assert "rego compile error" in result["errors"][0]


def test_theia_accepts_cdx16_echo(monkeypatch, tmp_path):
    _clean_env(monkeypatch, tmp_path)
    (tmp_path / "Security_CBOM.cdx.json").write_text("{}", encoding="utf-8")
    echo = json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6",
                       "components": [{"name": "MD5"}, {"name": "AES"}]})

    def fake_shell(cmd, timeout=120):
        return (0, echo, "") if "run" in cmd else (0, "", "")
    monkeypatch.setattr(sc, "_shell", fake_shell)
    monkeypatch.setattr(sc.shutil, "which", lambda name: "/usr/bin/docker")

    result = sc._real_cbomkit_theia_check(tmp_path)
    assert result == {"status": "PASS", "components": 2}


def test_theia_rejects_wrong_spec(monkeypatch, tmp_path):
    _clean_env(monkeypatch, tmp_path)
    (tmp_path / "Security_CBOM.cdx.json").write_text("{}", encoding="utf-8")
    echo = json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.4",
                       "components": []})

    def fake_shell(cmd, timeout=120):
        return (0, echo, "") if "run" in cmd else (0, "", "")
    monkeypatch.setattr(sc, "_shell", fake_shell)
    monkeypatch.setattr(sc.shutil, "which", lambda name: "/usr/bin/docker")

    result = sc._real_cbomkit_theia_check(tmp_path)
    assert result["status"] == "FAIL"


def test_theia_blocked_when_image_not_pulled(monkeypatch, tmp_path):
    _clean_env(monkeypatch, tmp_path)
    (tmp_path / "Security_CBOM.cdx.json").write_text("{}", encoding="utf-8")
    monkeypatch.setattr(sc, "_shell", lambda cmd, timeout=120: (1, "", "no such image"))
    monkeypatch.setattr(sc.shutil, "which", lambda name: "/usr/bin/docker")
    result = sc._real_cbomkit_theia_check(tmp_path)
    assert result["status"] == "BLOCKED"
    assert "not pulled" in result["reason"]


def test_aibom_generator_driver_payload_maps(monkeypatch, tmp_path):
    _clean_env(monkeypatch, tmp_path)
    tool = tmp_path / "tool"
    tool.mkdir()
    monkeypatch.setenv("RSX_AIBOM_GENERATOR", str(tool))
    monkeypatch.setenv("RSX_AIBOM_GENERATOR_PYTHON", sys.executable)
    (tmp_path / "Security_AIBOM.cdx.json").write_text("{}", encoding="utf-8")

    payload = {"cyclonedx_16_valid": True, "errors": [],
               "completeness_score": {"total_score": 41.0,
                                      "section_scores": {"metadata": 0.0}}}
    monkeypatch.setattr(sc, "_shell", lambda cmd, timeout=120: (
        0, json.dumps(payload), ""))
    result = sc._real_aibom_generator_check(tmp_path)
    assert result["status"] == "PASS"
    assert result["completeness_score"] == 41.0
    assert result["completeness_sections"] == {"metadata": 0.0}

    payload["cyclonedx_16_valid"] = False
    payload["errors"] = ["[root] bad"]
    monkeypatch.setattr(sc, "_shell", lambda cmd, timeout=120: (
        0, json.dumps(payload), ""))
    result = sc._real_aibom_generator_check(tmp_path)
    assert result["status"] == "FAIL"
    assert result["errors"] == ["[root] bad"]


def test_exit_code_discipline(monkeypatch, tmp_path):
    passing_offline = {"cyclonedx": {"valid": True}}
    monkeypatch.setattr(sc, "validate_sbom_conformance",
                        lambda d: passing_offline)

    monkeypatch.setattr(sc, "validate_real_tool_conformance", lambda d: {
        "x": {"status": "BLOCKED", "reason": "absent"}})
    assert sc.main([str(tmp_path)]) == 0

    monkeypatch.setattr(sc, "validate_real_tool_conformance", lambda d: {
        "x": {"status": "FAIL", "errors": ["boom"]}})
    assert sc.main([str(tmp_path)]) == 1

    # --no-real-tools skips the layer entirely
    monkeypatch.setattr(sc, "validate_real_tool_conformance", lambda d: {
        "x": {"status": "FAIL", "errors": ["boom"]}})
    assert sc.main([str(tmp_path), "--no-real-tools"]) == 0


def test_offline_result_shape_unchanged(tmp_path):
    results = sc.validate_sbom_conformance(tmp_path)
    assert set(results) == {"cyclonedx", "spdx", "cbom", "aibom"}
    for result in results.values():
        assert "error" in result  # empty dir: file-not-found per artifact
