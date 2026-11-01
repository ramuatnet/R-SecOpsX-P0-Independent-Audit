"""T-9.15 gate-found defect: wall-clock text in the legacy-protocol context.

The deterministic-output gate observed identical scans flipping
global_legacy_indicators 1 <-> 0 (Telnet CRITICAL): run1's wall clock
hit second/min ":23" inside an ISO timestamp
(2026-11-01T17:37:23.115774Z) in the flattened findings/cbom/apibom
context, and the Telnet port heuristic `:23\b` fired on it; run2's clock
missed.  FTP's `:21\b` has the same hazard.  Machine-generated clock
text is not protocol evidence -- the engine strips timestamp/duration
shapes before pattern matching.  Real evidence (the `telnet` keyword,
host:23 ports) must still be detected.
"""
from __future__ import annotations

import pathlib

REPO = pathlib.Path(__file__).resolve().parents[1]
ENGINE_SRC = REPO / "analysis" / "legacy_protocol_engine.py"


def _global(findings=None, cbom=None, api_bom=None):
    from analysis.legacy_protocol_engine import (
        enrich_legacy_protocol_intelligence,
    )
    _, summary = enrich_legacy_protocol_intelligence(
        [], findings=findings, cbom=cbom, api_bom=api_bom)
    return summary


def _names(summary):
    return {i["indicator"] for i in summary.get("global_indicators") or []}


def test_disclosure_pins_the_fix():
    src = ENGINE_SRC.read_text(encoding="utf-8")
    assert "_MACHINE_CLOCK" in src
    assert "not protocol evidence" in src
    assert 'text = _MACHINE_CLOCK.sub(" ", text)' in src


def test_iso_timestamp_second_23_does_not_fire_telnet():
    # The exact gate failure: scan wall clock inside :23 second.
    summary = _global(findings=[{
        "evidence": "scanned 2026-11-01T17:37:23.115774Z ok",
    }])
    assert "Telnet" not in _names(summary), _names(summary)
    assert summary["global_legacy_indicators"] == 0
    assert (summary["executive_status"]
            == "NO_LEGACY_PROTOCOL_RISK_IDENTIFIED")


def test_bare_clock_and_duration_do_not_fire_port_heuristics():
    # minutes=23 bare clock; duration seconds=21 (FTP :21 heuristic).
    for text in ("start 17:23:45 done", "elapsed 00:21.18 total",
                 "at 09:21:03 finished"):
        summary = _global(findings=[{"evidence": text}])
        assert _names(summary) == set(), (text, _names(summary))
        assert summary["global_legacy_indicators"] == 0, text


def test_real_telnet_keyword_still_detected():
    # Control: the keyword half of the pattern is untouched.
    summary = _global(findings=[{"evidence": "uses telnet for admin"}])
    assert "Telnet" in _names(summary), _names(summary)
    assert summary["global_legacy_indicators"] >= 1
    assert (summary["executive_status"]
            == "LEGACY_PROTOCOL_RISK_IDENTIFIED")


def test_real_port_23_evidence_still_detected():
    # Control: host:23 is one colon -- not a clock shape -- and must
    # survive the strip as genuine port evidence.
    summary = _global(findings=[{"evidence": "connect 10.0.0.5:23 now"}])
    assert "Telnet" in _names(summary), _names(summary)


def test_clock_rotation_yields_identical_summaries():
    # The gate's failure mode at the engine layer: same evidence, two
    # different wall-clock values -> identical indicator sets.
    a = _global(findings=[{"evidence": "log 2026-11-01T17:37:23Z pass"}])
    b = _global(findings=[{"evidence": "log 2026-11-01T17:41:09Z pass"}])
    assert _names(a) == _names(b), (_names(a), _names(b))
    assert (a["global_legacy_indicators"]
            == b["global_legacy_indicators"])
