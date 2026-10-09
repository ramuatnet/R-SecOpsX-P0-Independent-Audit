"""No table header may be force-split mid-token.

reportlab wraps a Paragraph only at spaces, so a column narrower than its
widest unbreakable token is broken at an arbitrary point. That is invisible
for data -- a long package name wrapping is expected -- but a header is a
label, and "Versio n", "EP SS" and "Reachab le" read as rendering defects in
a report meant to be assessed. The check is therefore per table: a whole-word
match elsewhere in the document proves nothing about the column that broke.

Every width here was derived, not remembered:

    column >= stringWidth(widest header token, that cell's font, size)
              + leftPadding + rightPadding

The padding is read off the table's own cell style rather than assumed,
because the SBOM table was forked to 4pt/side while the others keep
reportlab's 6pt default.

Two of these columns are regression guards. Widening the SBOM CVSS cell to
carry "CVSS 4.0 - 6.9" was funded by shrinking Type 1.0 -> 0.7cm and
Reachable 1.75 -> 1.15cm on the argument that those cells hold a single
letter. The cells do; the headers do not, and both labels broke.
"""

from pathlib import Path

from reportlab.pdfbase.pdfmetrics import stringWidth

from reporting.pdf_report import (
    _sbom_section,
    _sca_remediation_priority_section,
    _ssdf_alignment_section,
)

PDF_SOURCE = Path(__file__).resolve().parents[1] / "reporting" / "pdf_report.py"
PT_PER_CM = 72 / 2.54
FRAME_CM = 17.40

SBOM_PAYLOAD = {"sbom": [{"name": "jsonwebtoken", "version": "0.4.0"}]}
DEPENDENCY_PAYLOAD = {
    "sbom": [{"name": "jsonwebtoken", "version": "0.4.0", "severity": "High",
              "cve": "CVE-2022-23539", "cvss": 7.5}]
}
SSDF_PAYLOAD = {"ssdf_alignment": {"practices": [
    {"practice": "PO.1", "group": "PO", "status": "OBSERVED",
     "evidence": [{"path": "src/app.ts"}]},
]}}


def _table(story):
    for flowable in story:
        if type(flowable).__name__ == "Table":
            return flowable
    raise AssertionError("no Table rendered")


def _text(cell) -> str:
    if isinstance(cell, str):
        return cell
    return getattr(cell, "text", None) or ""


def _pad(table) -> float:
    """Left + right padding in points, from the table's own cell style."""
    style = table._cellStyles[0][0]
    return style.leftPadding + style.rightPadding


def _split_headers(table) -> list[tuple]:
    """Columns whose widest header token does not fit the usable width."""
    cells, widths, pad = table._cellvalues, table._argW, _pad(table)
    bad = []
    for col in range(len(widths)):
        header = cells[0][col]
        style = header.style
        usable = widths[col] - pad
        need = max(stringWidth(token, style.fontName, style.fontSize)
                   for token in _text(header).split())
        if need > usable + 1e-6:
            bad.append((_text(header), need, usable, widths[col] / PT_PER_CM))
    return bad


def _widths_cm(table) -> list[float]:
    return [round(w / PT_PER_CM, 4) for w in table._argW]


# ------------------------------------------------------- headers fit --------
def test_no_sbom_header_is_split():
    assert _split_headers(_table(_sbom_section(SBOM_PAYLOAD))) == []


def test_no_dependency_header_is_split():
    table = _table(_sca_remediation_priority_section(DEPENDENCY_PAYLOAD))
    assert _split_headers(table) == []


def test_no_ssdf_header_is_split():
    assert _split_headers(_table(_ssdf_alignment_section(SSDF_PAYLOAD))) == []


def test_the_two_sbom_columns_shrunk_to_fund_the_wide_cvss_cell_still_hold_their_labels():
    """Regression guard: Type went 1.0 -> 0.7cm and Reachable 1.75 -> 1.15cm
    because their *cells* are one letter and Yes/No. The headers are "Type"
    and "Reachable", which have no space to wrap at."""
    widths = _widths_cm(_table(_sbom_section(SBOM_PAYLOAD)))
    assert widths[2] >= 0.95, f"Type column is {widths[2]}cm"
    assert widths[8] >= 1.70, f"Reachable column is {widths[8]}cm"


def test_the_dependency_labels_that_broke_have_room_now():
    """Version was 1.35cm, EPSS 0.90cm and Reachable 1.65cm."""
    widths = _widths_cm(_table(_sca_remediation_priority_section(DEPENDENCY_PAYLOAD)))
    assert widths[2] >= 1.46, f"Version column is {widths[2]}cm"
    assert widths[5] >= 1.18, f"EPSS column is {widths[5]}cm"
    assert widths[6] >= 1.84, f"Reachable column is {widths[6]}cm"


def test_the_ssdf_findings_label_has_room():
    """It was 1.00cm against a 1.60cm requirement, so "Findings" broke."""
    widths = _widths_cm(_table(_ssdf_alignment_section(SSDF_PAYLOAD)))
    assert widths[4] >= 1.60, f"Findings column is {widths[4]}cm"


# ------------------------------------------------------ frame alignment ------
def test_all_three_tables_still_total_exactly_the_frame():
    """Each of these tables sits inside the same 17.40cm frame; widening one
    column must never push the table past it."""
    tables = [
        ("SBOM", _table(_sbom_section(SBOM_PAYLOAD))),
        ("dependency",
         _table(_sca_remediation_priority_section(DEPENDENCY_PAYLOAD))),
        ("SSDF", _table(_ssdf_alignment_section(SSDF_PAYLOAD))),
    ]
    for name, table in tables:
        total = sum(table._argW) / PT_PER_CM
        assert abs(total - FRAME_CM) < 1e-6, f"{name} table is {total:.4f}cm wide"


def test_no_column_went_negative_or_absurd():
    for name, table in (
        ("SBOM", _table(_sbom_section(SBOM_PAYLOAD))),
        ("dependency",
         _table(_sca_remediation_priority_section(DEPENDENCY_PAYLOAD))),
        ("SSDF", _table(_ssdf_alignment_section(SSDF_PAYLOAD))),
    ):
        for i, width in enumerate(_widths_cm(table)):
            assert width > 0.5, f"{name} column {i} is {width}cm"


# --------------------------------------------------------- the source --------
def test_the_measured_width_vectors_are_the_ones_in_the_source():
    """Pin the vectors so a hand-edit to a single number has to be a
    deliberate change rather than a stray keystroke."""
    src = PDF_SOURCE.read_text(encoding="utf-8-sig")
    assert ("colWidths=[3.10*cm,1.42*cm,0.95*cm,2.99*cm,1.71*cm,"
            "1.04*cm,1.46*cm,1.56*cm,1.70*cm,1.47*cm]") in src
    assert "1.55*cm, 2.75*cm, 1.60*cm, 3.35*cm," in src
    assert "2.0*cm, 1.29*cm, 2.01*cm, 2.85*cm" in src
    assert "colWidths=[4.4 * cm, 1.5 * cm, 5.2 * cm, 4.7 * cm, 1.6 * cm]" in src
    # the widths these replace
    assert "1.55*cm, 2.75*cm, 1.35*cm, 3.35*cm," not in src
    assert "4.4 * cm, 1.5 * cm, 5.6 * cm, 4.7 * cm, 1 * cm" not in src
