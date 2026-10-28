"""The privacy total counts rows, and one of them is not a PII observation.

In the STR delivery the sheet declared 268 "Total Privacy Indicators" while
row #268 was SENSITIVE_DATA_FLOW_CONTEXT (file DATA_FLOW_CORRELATION, line 0,
no PII type). The total is right -- it is a privacy indicator -- but the
split must be visible so 268 is not read as 268 PII findings.
"""
from __future__ import annotations

import pathlib
import tempfile

from openpyxl import Workbook

from analysis.privacy_data_exposure_engine import enrich_privacy_data_exposure
from reporting.excel_report import _privacy_findings

FILLER = "const cfg={a:1,b:2};"


def _enrich(tmp_path: pathlib.Path, flow: int = 0) -> dict:
    target = tmp_path / "src" / "payments" / "ui-bundle.js"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(FILLER * 40 + 'user.email="value@example.com",' + FILLER * 5, encoding="utf-8")
    kwargs = {}
    if flow:
        kwargs["data_flow_summary"] = {"total_data_flow_sensitivity_indicators": flow}
    return enrich_privacy_data_exposure(
        str(tmp_path), findings=[], live_progress=False, **kwargs)


def test_engine_splits_pii_rows_from_context_rows():
    with tempfile.TemporaryDirectory(prefix="rsx_privacy_count_") as raw:
        summary = _enrich(pathlib.Path(raw), flow=2)
    assert summary["total_privacy_indicators"] == 2
    assert summary["pii_data_indicators"] == 1
    assert summary["context_only_indicators"] == 1
    assert (summary["pii_data_indicators"]
            + summary["context_only_indicators"]
            == summary["total_privacy_indicators"])
    assert summary["count_semantics"].startswith("TOTAL_INCLUDES_CONTEXT_ONLY_ROWS")


def test_engine_reports_no_context_rows_when_none_exist():
    with tempfile.TemporaryDirectory(prefix="rsx_privacy_count_plain_") as raw:
        summary = _enrich(pathlib.Path(raw))
    assert summary["total_privacy_indicators"] == 1
    assert summary["pii_data_indicators"] == 1
    assert summary["context_only_indicators"] == 0


def _meta(ws) -> dict:
    out = {}
    for r in range(3, 12):
        key = ws.cell(row=r, column=1).value
        if key:
            out[str(key)] = ws.cell(row=r, column=2).value
    return out


def test_sheet_prefers_stored_counts():
    payload = {"privacy_data_exposure_summary": {
        "summary_status": "X",
        "total_privacy_indicators": 268,
        "pii_data_indicators": 267,
        "context_only_indicators": 1,
        "indicators": [],
    }}
    ws = Workbook().active
    _privacy_findings(ws, payload)
    meta = _meta(ws)
    assert int(meta["Total Privacy Indicators"]) == 268
    assert int(meta["PII Data Indicators"]) == 267
    assert int(meta["Context-Only Indicators"]) == 1


def test_sheet_derives_the_split_for_payloads_without_the_new_keys():
    payload = {"privacy_data_exposure_summary": {
        "summary_status": "X",
        "total_privacy_indicators": 2,
        "indicators": [
            {"risk_level": "LOW", "indicator": "PII_PATTERN_OBSERVED",
             "pii_types": ["PAN"], "file": "a.js", "line": 1},
            {"risk_level": "LOW", "indicator": "SENSITIVE_DATA_FLOW_CONTEXT",
             "pii_types": [], "file": "DATA_FLOW_CORRELATION", "line": 0},
        ],
    }}
    ws = Workbook().active
    _privacy_findings(ws, payload)
    meta = _meta(ws)
    assert int(meta["Total Privacy Indicators"]) == 2
    assert int(meta["PII Data Indicators"]) == 1
    assert int(meta["Context-Only Indicators"]) == 1
