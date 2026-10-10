"""Phase 0 task 0.4 -- the --fail-on gate.

The gate reads severity and changes nothing else: no finding's severity, risk
score or remediation ranking is touched, and a run without the flag keeps
exiting 0 whatever it finds.
"""
import pathlib
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import main as M  # noqa: E402


def F(*sevs):
    return [{"severity": s} for s in sevs]


def test_no_threshold_means_not_requested_and_a_pass():
    gate = M._security_gate(F("Critical", "High"), None)
    assert gate["threshold"] is None
    assert gate["security_gate_passed"] is True


def test_a_finding_at_or_above_the_rung_fails_the_gate():
    assert M._security_gate(F("Critical"), "critical")["security_gate_passed"] is False
    assert M._security_gate(F("High"), "high")["security_gate_passed"] is False
    assert M._security_gate(F("Medium"), "medium")["security_gate_passed"] is False


def test_a_stricter_rung_ignores_lower_severities():
    assert M._security_gate(F("High"), "critical")["security_gate_passed"] is True
    assert M._security_gate(F("Medium"), "high")["security_gate_passed"] is True
    assert M._security_gate(F("Low", "Info"), "medium")["security_gate_passed"] is True


def test_a_stricter_rung_still_fails_on_the_stricter_severity():
    # --fail-on high must fail on Critical too, not only on High.
    assert M._security_gate(F("Critical"), "high")["security_gate_passed"] is False


def test_blocking_detail_names_the_severities():
    gate = M._security_gate(F("Critical", "High", "High", "Medium"), "high")
    assert gate["blocking_counts"] == {"critical": 1, "high": 2}
    assert gate["total_blocking"] == 3


def test_the_gate_only_reads_severity_it_never_rewrites_it():
    findings = [{"severity": "Critical"}, {"severity": "high"}, {"severity": " CRITICAL "}]
    before = [dict(f) for f in findings]
    M._security_gate(findings, "high")
    assert findings == before


def test_recognition_is_case_insensitive():
    assert M._security_gate(F("CRITICAL"), "critical")["security_gate_passed"] is False


def test_unrecognised_severities_are_reported_not_folded_away():
    gate = M._security_gate(F("Blocker", "", "Critical"), "critical")
    assert gate["unrecognised_severities"] == {"blocker": 1, "(blank)": 1}
    assert gate["severity_counts"]["critical"] == 1
    assert gate["security_gate_passed"] is False


def test_non_dict_and_empty_input_cannot_crash_the_gate():
    assert M._security_gate(None, None)["security_gate_passed"] is True
    assert M._security_gate([1, "x", None], "critical")["security_gate_passed"] is True


def test_an_unknown_threshold_raises_instead_of_passing_by_accident():
    with pytest.raises(ValueError):
        M._security_gate(F("High"), "blocker")


def test_the_cli_rejects_an_unknown_threshold_with_a_usage_error():
    r = subprocess.run(
        [sys.executable, str(ROOT / "main.py"), str(ROOT), "--fail-on", "blocker"],
        capture_output=True, cwd=str(ROOT),
    )
    # 2 is reserved for usage errors, so it cannot be confused with a scan
    # that failed its gate (1).
    assert r.returncode == 2, r.returncode
    assert "invalid choice" in r.stderr.decode("utf-8", "replace")


def test_the_cli_offers_the_three_rungs():
    r = subprocess.run([sys.executable, str(ROOT / "main.py"), "--help"],
                       capture_output=True, cwd=str(ROOT))
    out = r.stdout.decode("utf-8", "replace")
    assert "--fail-on {critical,high,medium}" in out
