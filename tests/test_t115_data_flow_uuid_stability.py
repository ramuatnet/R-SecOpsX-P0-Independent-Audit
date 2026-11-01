"""T-9.15 gate-found defect: uuid4 hex in the data-flow engine context.

The deterministic-output gate (analysis/validation/deterministic_output)
observed identical scans producing different data_flow_sensitivity
indicator counts (1 vs 2, HIGH 1 vs 2).  Root cause:
enrich_data_flow_sensitivity regex-scans the flattened
findings/apibom/abom text, and every scan mints fresh uuid4s into the
BOM payloads; uuid hex accidentally satisfies several PII patterns
(measured on 20k random uuids: PASSPORT 1.15%, PHONE/AADHAAR/SWIFT
~0.3%, CREDIT_CARD 0.17%).  Machine identifiers are not PII evidence --
the engine strips uuid-shaped tokens before pattern matching.  Real PII
in the remaining text must still be detected.
"""
from __future__ import annotations

import pathlib

REPO = pathlib.Path(__file__).resolve().parents[1]
ENGINE_SRC = REPO / "analysis" / "data_flow_sensitivity_engine.py"

# Measured collisions: uuid hex that satisfies a PII regex by chance.
PASSPORT_UUID = "a2968778-60e3-43bc-9021-cf75f6bde91b"
AADHAAR_UUID = "d4ddd041-92ce-4d65-ac75-619695604289"
REAL_EMAIL = "alice@example.com"


def _summary(findings):
    from analysis.data_flow_sensitivity_engine import (
        enrich_data_flow_sensitivity,
    )
    return enrich_data_flow_sensitivity(findings)


def _names(summary):
    return {i["indicator"] for i in summary["global_indicators"]}


def test_disclosure_pins_the_fix():
    src = ENGINE_SRC.read_text(encoding="utf-8")
    assert "_MACHINE_UUID" in src
    assert "not PII evidence" in src
    assert 'global_context = _MACHINE_UUID.sub(" ", global_context)' in src


def test_uuid_only_evidence_yields_no_indicators():
    # Pre-fix these uuids fired PASSPORT/AADHAAR (HIGH) -- the exact
    # count flip the gate caught between two identical scans.
    for uuid in (PASSPORT_UUID, AADHAAR_UUID):
        summary = _summary([{"evidence": uuid}])
        assert summary["total_data_flow_sensitivity_indicators"] == 0, (
            uuid, _names(summary))
        assert summary["global_indicators"] == []
        assert (summary["summary_status"]
                == "NO_DATA_FLOW_SENSITIVITY_INDICATORS_IDENTIFIED")


def test_real_pii_still_detected():
    # Control: stripping machine ids must not strip actual PII.
    summary = _summary([{"evidence": "contact " + REAL_EMAIL}])
    names = _names(summary)
    assert "EMAIL_PII_FLOW" in names, names
    assert summary["total_data_flow_sensitivity_indicators"] >= 1


def test_indicator_counts_stable_across_uuid_rotation():
    # Same evidence text, different per-run uuids -> identical summary.
    # This is the gate's failure mode, pinned at the engine layer.
    base = "user " + REAL_EMAIL + " ref "
    a = _summary([{"evidence": base + PASSPORT_UUID}])
    b = _summary([{"evidence": base + AADHAAR_UUID}])
    assert _names(a) == _names(b), (_names(a), _names(b))
    assert (a["total_data_flow_sensitivity_indicators"]
            == b["total_data_flow_sensitivity_indicators"])
    assert (a["high_indicators"] == b["high_indicators"])
    assert (a["executive_relevant_indicators"]
            == b["executive_relevant_indicators"])
    # ...and the real PII is still counted in both.
    assert "EMAIL_PII_FLOW" in _names(a)
