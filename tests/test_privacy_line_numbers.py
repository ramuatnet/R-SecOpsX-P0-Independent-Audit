"""Privacy indicators must report a real source line, not the block index.

The engine streams a file in fixed windows; ``line`` used to be the window
counter, so a multi-line file reported 1/2/3 (the STR report shows
220/268 rows on "line 1") and even a single-line bundle could report 2.
These tests pin the line to the matched PII token, across block
boundaries, leading blank lines and minified one-line files.
"""
from __future__ import annotations

import pathlib
import tempfile

from analysis.privacy_data_exposure_engine import (
    _PRIVACY_V5_CHUNK_SIZE,
    enrich_privacy_data_exposure,
)

CHUNK = _PRIVACY_V5_CHUNK_SIZE


def _scan(base: pathlib.Path, relative: str, body: str):
    target = base / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(body, encoding="utf-8")
    result = enrich_privacy_data_exposure(
        str(base), findings=[], live_progress=False)
    return target, result["indicators"]


def test_multiline_file_reports_the_line_holding_the_token():
    with tempfile.TemporaryDirectory(prefix="rsx_privacy_line_") as raw:
        complaint = pathlib.Path(raw)
        lines = ["# field mapping"] + ["# col %d" % i for i in range(39)]
        lines.append('aadhaar_field = "1234 5678 9012"')
        path, indicators = _scan(
            complaint, "src/payments/collect.py", "\n".join(lines) + "\n")
        assert len(indicators) == 1, indicators
        assert indicators[0]["line"] == 41
        source = path.read_text(encoding="utf-8").splitlines()
        assert "1234 5678 9012" in source[indicators[0]["line"] - 1]


def test_line_is_accumulated_across_stream_blocks():
    with tempfile.TemporaryDirectory(prefix="rsx_privacy_line_block_") as raw:
        complaint = pathlib.Path(raw)
        filler = "var a = 1;" + " " * 89          # 99 chars + newline
        # Comfortably past one 128KB window, so the match is in block 2.
        count = (CHUNK * 2) // 100 + 100
        lines = [filler] * count
        match_line = count - 50
        lines[match_line - 1] = 'var panField = "ABCDE1234F";'
        body = "\n".join(lines) + "\n"
        assert len(body) > CHUNK
        path, indicators = _scan(
            complaint, "src/payments/bundle.js", body)
        assert len(indicators) == 1, indicators
        assert indicators[0]["line"] == match_line
        source = path.read_text(encoding="utf-8").splitlines()
        assert "ABCDE1234F" in source[indicators[0]["line"] - 1]


def test_minified_single_line_bundle_reports_line_one():
    with tempfile.TemporaryDirectory(prefix="rsx_privacy_line_min_") as raw:
        complaint = pathlib.Path(raw)
        body = "const cfg={a:1,b:2};" * 500 + 'email:"ops@example.org",' + "const z=1;"
        assert body.count("\n") == 0
        _, indicators = _scan(
            complaint, "src/payments/ui-bundle.js", body)
        assert len(indicators) == 1, indicators
        assert indicators[0]["line"] == 1


def test_leading_blank_lines_do_not_shift_the_line():
    with tempfile.TemporaryDirectory(prefix="rsx_privacy_line_blank_") as raw:
        complaint = pathlib.Path(raw)
        body = "\n" * 5 + 'email:"ops@example.org",\nconst after = 1;\n'
        path, indicators = _scan(
            complaint, "src/payments/form.js", body)
        assert len(indicators) == 1, indicators
        assert indicators[0]["line"] == 6
        source = path.read_text(encoding="utf-8").splitlines()
        assert "ops@example.org" in source[indicators[0]["line"] - 1]


def test_data_flow_context_row_keeps_line_zero():
    with tempfile.TemporaryDirectory(prefix="rsx_privacy_line_ctx_") as raw:
        result = enrich_privacy_data_exposure(
            raw,
            findings=[],
            data_flow_summary={"total_data_flow_sensitivity_indicators": 3},
            live_progress=False,
        )
        rows = [i for i in result["indicators"]
                if i.get("indicator") == "SENSITIVE_DATA_FLOW_CONTEXT"]
        assert rows and rows[0]["line"] == 0
