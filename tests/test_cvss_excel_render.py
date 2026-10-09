"""Excel's three CVSS columns must name the version, and be wide enough to.

Two ways this could still be wrong after the helper exists: a sheet could
pass the wrong field, or the widened string could be written into a column
still sized for a bare number and be clipped. So the rendered cells are read
by header position -- never by searching the sheet for a number -- and the
column widths are asserted directly.

The SAST findings sheet is deliberately NOT converted. Findings come from
static analysis, not from an advisory source: measured on the shipped
payload, 0 of 102 findings carry a CVSS value, a version or a CVE, so there
is no assessment to name there and its cell is left exactly as it was.
"""

import re
from pathlib import Path

from openpyxl import Workbook
from openpyxl.utils import get_column_letter

from reporting.excel_report import _exploitable_cves, _sca_findings, _sbom

EXCEL_SOURCE = Path(__file__).resolve().parents[1] / "reporting" / "excel_report.py"


def _pkg(**kw):
    base = {
        "name": "demo",
        "version": "1.2.3",
        "ecosystem": "npm",
        "purl": "pkg:npm/demo@1.2.3",
        "cve": "CVE-2024-0001",
        "cvss": 9.8,
    }
    base.update(kw)
    return base


def _write(writer, payload):
    wb = Workbook()
    writer(wb.active, payload)
    return wb.active


def _cvss_column(ws, header_row: int = 2) -> list[str]:
    """Every value under the header literally named CVSS, in row order."""
    col = next(
        (c.column for c in ws[header_row] if c.value == "CVSS"),
        None,
    )
    assert col, "no CVSS header on the sheet"
    return [
        str(cell.value)
        for row in ws.iter_rows(min_row=header_row + 1, min_col=col, max_col=col)
        for cell in row
        if cell.value is not None
    ]


def _cvss_width(ws) -> float:
    col = next(c.column for c in ws[2] if c.value == "CVSS")
    return ws.column_dimensions[get_column_letter(col)].width


# ---------------------------------------------------------------- SBOM sheet --
def test_sbom_cell_names_the_version_and_score():
    ws = _write(_sbom, {"sbom": [
        _pkg(cvss_version="4.0", cvss_preferred_score=6.9),
    ]})
    assert _cvss_column(ws) == ["CVSS 4.0 — 6.9"]


def test_sbom_cell_never_prints_the_31_number_for_a_40_primary():
    ws = _write(_sbom, {"sbom": [
        _pkg(cvss_version="4.0", cvss_preferred_score=6.9, cvss=9.8),
    ]})
    cells = _cvss_column(ws)
    assert cells == ["CVSS 4.0 — 6.9"]
    assert not any("9.8" in c for c in cells)


def test_sbom_cell_dashes_a_package_with_no_vulnerability():
    ws = _write(_sbom, {"sbom": [
        _pkg(cve=None, vulnerabilities=[], cvss=None,
             cvss_version=None, cvss_preferred_score=None),
    ]})
    assert _cvss_column(ws) == ["--"]


def test_sbom_cell_never_dashes_a_package_that_has_a_finding():
    ws = _write(_sbom, {"sbom": [
        _pkg(cvss_version="4.0", cvss_preferred_score=None, cvss=None),
    ]})
    cells = _cvss_column(ws)
    assert cells == ["CVSS 4.0 — score unavailable"]
    assert cells != ["--"]


def test_sbom_cell_admits_an_unknown_version_rather_than_guessing():
    """A 7.5 could come from 3.1 or 4.0; only a stated version is printed."""
    ws = _write(_sbom, {"sbom": [
        _pkg(cvss_version=None, cvss_preferred_score=7.5, cvss=7.5),
    ]})
    assert _cvss_column(ws) == ["CVSS version unknown — 7.5"]


def test_sbom_cell_renders_a_legacy_payload_with_no_version_keys():
    ws = _write(_sbom, {"sbom": [
        _pkg(cvss_version=None, cvss_preferred_score=None, cvss=7.7),
    ]})
    assert _cvss_column(ws) == ["CVSS version unknown — 7.7"]


# -------------------------------------------------------- SCA Findings sheet --
def test_sca_findings_cell_names_the_version_and_score():
    ws = _write(_sca_findings, {"sbom": [
        _pkg(cvss_version="4.0", cvss_preferred_score=6.9),
    ]})
    assert _cvss_column(ws) == ["CVSS 4.0 — 6.9"]


def test_sca_findings_cell_keeps_a_31_primary_on_its_own_number():
    ws = _write(_sca_findings, {"sbom": [
        _pkg(cvss_version="3.1", cvss_preferred_score=9.8, cvss=9.8),
    ]})
    assert _cvss_column(ws) == ["CVSS 3.1 — 9.8"]


def test_sca_findings_cell_never_prints_a_bare_number():
    ws = _write(_sca_findings, {"sbom": [
        _pkg(cvss_version="4.0", cvss_preferred_score=6.9, cvss=9.8),
    ]})
    assert _cvss_column(ws) == ["CVSS 4.0 — 6.9"]


# ------------------------------------------------------ Exploitable CVEs sheet --
def test_exploitable_cves_cell_names_the_version_and_score():
    ws = _write(_exploitable_cves, {"sbom": [
        _pkg(cvss_version="4.0", cvss_preferred_score=6.9,
             kev_status="CVE-2024-0001"),
    ]})
    assert _cvss_column(ws) == ["CVSS 4.0 — 6.9"]


def test_exploitable_cves_cell_admits_an_unknown_version():
    ws = _write(_exploitable_cves, {"sbom": [
        _pkg(cvss_version="UNKNOWN", cvss_preferred_score=7.5,
             kev_status="CVE-2024-0001"),
    ]})
    cells = _cvss_column(ws)
    assert cells == ["CVSS version unknown — 7.5"]
    assert not any("UNKNOWN" in c for c in cells)


# ------------------------------------------------------------ column widths --
def test_all_three_cvss_columns_are_wide_enough():
    """Width 8 clipped a bare number; the new text needs room to be read."""
    cases = [
        (_sbom, {"sbom": [_pkg(cvss_version="4.0", cvss_preferred_score=6.9)]}),
        (_sca_findings, {"sbom": [_pkg(cvss_version="4.0",
                                       cvss_preferred_score=6.9)]}),
        (_exploitable_cves, {"sbom": [_pkg(cvss_version="4.0",
                                           cvss_preferred_score=6.9,
                                           kev_status="CVE-2024-0001")]}),
    ]
    for writer, payload in cases:
        assert _cvss_width(_write(writer, payload)) == 26, writer.__name__


def test_source_widened_exactly_the_cvss_column_on_each_sheet():
    """Guards against a future edit widening the wrong index."""
    src = EXCEL_SOURCE.read_text(encoding="utf-8-sig")
    expected = [
        ("SBOM", "28, 16, 48, 12, 18, 30,", 6),
        ("SCA Findings", "4, 26, 16, 46, 16, 52, 32,", 7),
        ("Exploitable CVEs", "4, 24, 14, 16, 30,", 5),
    ]
    for label, signature, index in expected:
        m = re.search(r"widths = \[([^\]]*" + re.escape(signature) + r"[^\]]*)\]",
                      src)
        assert m, f"{label} widths not found"
        values = [int(x.strip()) for x in m.group(1).split(",") if x.strip()]
        assert values[index] == 26, (label, index, values[index])


def test_no_sheet_still_formats_a_bare_cvss_number():
    """_fmt_float collapses the version away; no cell may still use it."""
    src = EXCEL_SOURCE.read_text(encoding="utf-8-sig")
    assert not re.findall(r'_fmt_float\(_first_value\(pkg, "cvss"', src)


# ------------------------------------------------ the deliberate exception --
def test_sast_findings_keep_their_original_cell():
    """Findings are not advisory-sourced: 0/102 carry any CVSS, version or
    CVE, so there is no assessment to name and the cell must not be changed
    by this work. Recorded here so a later refactor cannot 'fix' it silently
    into claiming an absent score for a finding that never had one."""
    src = EXCEL_SOURCE.read_text(encoding="utf-8-sig")
    assert 'f.get("cvss") or "N/A"' in src


def test_excel_keeps_its_utf8_bom():
    assert EXCEL_SOURCE.read_bytes().startswith(b"\xef\xbb\xbf")
