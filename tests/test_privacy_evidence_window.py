"""Evidence must point at the matched PII token, not at the chunk head.

The privacy engine streams a file in fixed windows and used to take
``text[:240]`` as the evidence snippet. For a minified bundle that head is
the import block, so 13.4% of the production report's 268 privacy rows
carried evidence that did not contain the token they claimed (0% for the
two sample chunks). These tests pin the anchored window and, just as
importantly, that detection itself is untouched.
"""
from __future__ import annotations

import pathlib
import tempfile

from analysis.privacy_data_exposure_engine import (
    _pii_evidence_window,
    _redact_pii_evidence,
    enrich_privacy_data_exposure,
)

FILLER = "const cfg={a:1,b:2};"


def test_window_is_centred_on_the_match():
    text = FILLER * 40 + 'label:"PAN",' + FILLER * 10
    window = _pii_evidence_window(text, ["PAN"])
    assert 'label:"PAN"' in window
    assert window.startswith("...")
    # Same order of magnitude as the legacy 240-char slice.
    assert len(window) <= 260


def test_window_keeps_head_when_match_is_already_near_the_start():
    text = 'label:"PAN",' + FILLER * 40
    window = _pii_evidence_window(text, ["PAN"])
    assert 'label:"PAN"' in window
    assert not window.startswith("...")


def test_window_falls_back_to_legacy_slice_without_reported_types():
    text = FILLER * 40 + 'label:"PAN",'
    assert _pii_evidence_window(text, []) == text[:240]
    assert _pii_evidence_window(text, None) == text[:240]


def test_window_falls_back_when_reported_type_does_not_match():
    text = FILLER * 40
    assert _pii_evidence_window(text, ["PAN"]) == text[:240]


def test_window_is_empty_for_non_text_input():
    assert _pii_evidence_window(None, ["PAN"]) == ""
    assert _pii_evidence_window("", ["PAN"]) == ""


def test_window_anchors_on_the_earliest_of_several_types():
    text = (FILLER * 15 + 'email:"ops@example.org",' + FILLER * 30
            + 'label:"PAN",' + FILLER * 5)
    window = _pii_evidence_window(text, ["EMAIL", "PAN"])
    assert "ops@example.org" in window
    assert 'label:"PAN"' not in window


def _scan(tmp_path: pathlib.Path, relative: str, body: str):
    target = tmp_path / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(body, encoding="utf-8")
    return enrich_privacy_data_exposure(
        str(tmp_path / relative.split("/")[0]), findings=[], live_progress=False)


def test_engine_evidence_contains_the_matched_label_on_a_minified_file():
    with tempfile.TemporaryDirectory(prefix="rsx_pii_evidence_") as raw:
        before = dict(
            indicator="PII_PATTERN_OBSERVED",
            risk="LOW",
            pii=["PAN"],
            line=1,
            snippet='label:"PAN"',
        )
        result = _scan(
            pathlib.Path(raw), "src/payments/ui-bundle.js",
            FILLER * 40 + 'label:"PAN",' + FILLER * 10)
        indicators = result["indicators"]
        assert len(indicators) == 1, indicators
        row = indicators[0]
        # Detection outcome is unchanged: same indicator, risk, types, line.
        assert row["indicator"] == before["indicator"]
        assert row["risk_level"] == before["risk"]
        assert row["pii_types"] == before["pii"]
        assert str(row["line"]) == str(before["line"])
        # ... but the evidence now points at the token.
        assert before["snippet"] in row["snippet"]
        assert row["snippet"].startswith("...")


def test_engine_redacts_a_real_value_inside_the_window():
    with tempfile.TemporaryDirectory(prefix="rsx_pii_evidence_redact_") as raw:
        result = _scan(
            pathlib.Path(raw), "src/payments/pan-service.js",
            FILLER * 40 + 'panValue:"ABCDE1234F",' + FILLER * 10)
        indicators = result["indicators"]
        assert len(indicators) == 1, indicators
        snippet = indicators[0]["snippet"]
        assert "[REDACTED_PAN]" in snippet
        assert "ABCDE1234F" not in snippet
        assert _redact_pii_evidence(snippet) == snippet
