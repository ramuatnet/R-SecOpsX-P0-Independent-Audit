"""Phase 0 task 0.5 -- the security gate must be consumable from the artefact.

A CI job should not have to run the tool again, or scrape the console, to
learn whether the scan passed: clean_report.json carries the answer under
metadata.security_gate.
"""
import json
import pathlib
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import main as M  # noqa: E402

GATE_KEYS = {
    "threshold", "security_gate_passed", "blocking_counts", "total_blocking",
    "severity_counts", "unrecognised_severities",
}


def test_it_attaches_the_gate_under_metadata():
    payload = {"metadata": {"tool": "x"}, "findings": [{"severity": "High"}]}
    gate = M._record_security_gate(payload, "high")
    assert payload["metadata"]["security_gate"] is gate
    assert gate["security_gate_passed"] is False


def test_it_does_not_disturb_the_metadata_it_beside():
    payload = {"metadata": {"tool": "x", "risk_score": 50.9,
                            "severity_distribution": {"High": 1}},
               "findings": []}
    M._record_security_gate(payload, "high")
    assert payload["metadata"]["tool"] == "x"
    assert payload["metadata"]["risk_score"] == 50.9
    assert payload["metadata"]["severity_distribution"] == {"High": 1}


def test_it_creates_metadata_when_there_is_none():
    payload = {"findings": [{"severity": "Critical"}]}
    gate = M._record_security_gate(payload, "critical")
    assert payload["metadata"]["security_gate"] is gate
    assert gate["security_gate_passed"] is False


def test_a_payload_with_no_findings_still_records_a_gate():
    payload = {"metadata": {}}
    gate = M._record_security_gate(payload, "high")
    assert gate["threshold"] == "high"
    assert gate["total_blocking"] == 0
    assert gate["security_gate_passed"] is True


def test_every_key_a_ci_job_needs_is_present():
    payload = {"findings": [{"severity": "High"}]}
    gate = M._record_security_gate(payload, "high")
    assert set(gate) == GATE_KEYS


def test_the_persisted_file_carries_the_gate(tmp_path):
    payload = {"metadata": {"tool": "x"},
               "findings": [{"severity": "Critical"}, {"severity": "Low"}]}
    json_path = tmp_path / "clean_report.json"
    gate = M._record_security_gate(payload, "high")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, default=str)

    on_disk = json.loads(json_path.read_text(encoding="utf-8"))
    assert on_disk["metadata"]["security_gate"]["security_gate_passed"] is False
    assert on_disk["metadata"]["security_gate"]["threshold"] == "high"
    assert on_disk["metadata"]["security_gate"]["blocking_counts"] == {"critical": 1}
    assert on_disk["metadata"]["tool"] == "x"


def test_threshold_is_null_so_absence_is_explicit_not_a_missing_key():
    payload = {"findings": [{"severity": "Low"}]}
    gate = M._record_security_gate(payload, None)
    assert "threshold" in gate
    assert gate["threshold"] is None
    assert gate["security_gate_passed"] is True


def test_the_recorded_gate_covers_the_sbom_population():
    # metadata.severity_distribution is scoped SAST + vulnerable packages, so
    # the gate published beside it must cover both or the two disagree.
    payload = {"findings": [{"severity": "Low"}],
               "sbom": [{"vulnerabilities": [{"id": "CVE-1"}],
                         "severity": "Critical"}]}
    gate = M._record_security_gate(payload, "critical")
    assert gate["security_gate_passed"] is False
    assert gate["severity_counts"]["critical"] == 1
    assert payload["metadata"]["security_gate"] is gate
