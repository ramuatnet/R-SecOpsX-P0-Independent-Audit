"""The Findings sheet must show the path, not the basename.

Two modules can carry the same file name at the same line (in the STR
delivery, 36 basename groups covered 88 distinct files across rbi-ie,
rbi-import, rbi-export and rbi-interlink). With basenames the rows were
byte-identical apart from '#', which reads as scanner duplication and hides
where the finding actually is. Technical Evidence already prints the path
from the same field; Findings must agree with it.
"""
from __future__ import annotations

from openpyxl import Workbook
from openpyxl.utils import get_column_letter

from reporting.excel_report import _findings, _technical_evidence


def _finding(file_path: str, line: int = 5) -> dict:
    return {
        "rule_id": "JAVA_J2_WEAK_RANDOM",
        "vuln_type": "weak_random",
        "title": "Java insecure random generator",
        "severity": "Medium",
        "file": file_path,
        "affected_files": [file_path],
        "line": line,
        "instances": 1,
    }


def _render(payload: dict):
    wb = Workbook()
    findings_ws = wb.active
    _findings(findings_ws, payload)
    evidence_ws = wb.create_sheet()
    _technical_evidence(evidence_ws, payload)
    return findings_ws, evidence_ws


def _column(ws, name: str) -> list:
    header = [str(c.value) for c in ws[2]]
    col = header.index(name) + 1
    return [ws.cell(row=r, column=col).value
            for r in range(3, ws.max_row + 1)]


def test_same_basename_in_two_modules_renders_two_distinct_paths():
    payload = {"grouped": [
        _finding("mod-b/src/main/java/demo/A.java"),
        _finding("mod-a/src/main/java/demo/A.java"),
    ]}
    findings_ws, evidence_ws = _render(payload)

    findings_files = _column(findings_ws, "File")
    assert findings_files == [
        "mod-b/src/main/java/demo/A.java",
        "mod-a/src/main/java/demo/A.java",
    ]
    assert _column(findings_ws, "Affected Files") == findings_files
    # The two sheets read the same field and must not disagree.
    assert sorted(_column(evidence_ws, "File")) == sorted(findings_files)


def test_windows_separators_are_normalised_for_the_findings_sheet():
    payload = {"grouped": [_finding(r"mod-a\src\main\java\demo\A.java")]}
    findings_ws, _ = _render(payload)
    assert _column(findings_ws, "File") == ["mod-a/src/main/java/demo/A.java"]


def test_bare_file_name_is_unchanged():
    payload = {"grouped": [_finding("A.java")]}
    findings_ws, _ = _render(payload)
    assert _column(findings_ws, "File") == ["A.java"]


def test_file_columns_are_wide_enough_for_a_module_path():
    payload = {"grouped": [_finding("mod-a/src/main/java/demo/A.java")]}
    findings_ws, _ = _render(payload)
    header = [str(c.value) for c in findings_ws[2]]
    for name in ("File", "Affected Files"):
        width = findings_ws.column_dimensions[get_column_letter(
            header.index(name) + 1)].width
        assert width >= 50, (name, width)


def test_missing_file_falls_back_to_empty_string():
    entry = _finding("mod-a/src/main/java/demo/A.java")
    entry.pop("file")
    entry.pop("affected_files")
    findings_ws, evidence_ws = _render({"grouped": [entry]})
    assert _column(findings_ws, "File") == [""]
    assert _column(evidence_ws, "File") == [""]
