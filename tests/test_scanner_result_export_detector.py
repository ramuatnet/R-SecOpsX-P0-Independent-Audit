# -*- coding: utf-8 -*-
"""Regression tests for the extended scanner-result JSON detector (I19).

The VA production scan proved the original marker set missed the combined
export: RBI7SASTSBOMSCA-result.json carries secret-id=/secret-title= rows
and a scan_date counter instead of total_findings. Both engines' detectors
now accept those alternative signatures; these tests pin the exact shapes
observed in production, plus the benign controls that must keep scanning.
"""
from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from scanner.sast import _is_scanner_result_json as sast_is
from scanner.secret_intelligence import _is_scanner_result_json as sec_is


def _mk(tmp_path, name, body):
    p = tmp_path / name
    p.write_text(body, encoding="utf-8")
    return p


def test_va_combined_export_detected_by_both_engines(tmp_path):
    """The exact shape that leaked 98 rows in the VA/sc scans."""
    body = (
        '{"scan_date": "2026-10-26T10:14:03Z",'
        ' "tool": "R-SecOpsX SAST v2.1",'
        ' "secret-id": "abc123", "secret-title": "DB credential",'
        ' "findings": [{"evidence": "secret-id=[REDACTED]"}]}'
    )
    p = _mk(tmp_path, "RBI7SASTSBOMSCA-result.json", body)
    assert sast_is(p), "SAST detector missed the VA export shape"
    assert sec_is(p), "secrets detector missed the VA export shape"


def test_total_findings_envelope_still_detected(tmp_path):
    body = ('{"metadata": {"tool": "x", "total_findings": 3},'
            ' "findings": [{"rule_id": "A"}]}')
    p = _mk(tmp_path, "legacy-export.json", body)
    assert sast_is(p) and sec_is(p)


def test_benign_application_json_still_scanned(tmp_path):
    # A search response with a findings array but no envelope counters.
    p = _mk(tmp_path, "search.json",
            '{"status": "ok", "findings": ["nodule"], "patient": {"id": 7}}')
    assert not sast_is(p) and not sec_is(p)
    # A scan-timing JSON: has scan_date + tool but no findings/secret-id array.
    p2 = _mk(tmp_path, "timing.json",
             '{"tool": "x", "scan_date": "2026-10-27", "phases": 74}')
    assert not sast_is(p2) and not sec_is(p2)
