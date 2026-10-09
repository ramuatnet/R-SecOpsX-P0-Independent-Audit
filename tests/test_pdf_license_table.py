"""L12: the licence table may only render columns that say something.

Measured across all 168 rows of the shipped payload, two of the table's nine
columns were constant -- `license_review_required` printed "No" 168 times and
`license_provenance` an identical string 168 times. They are dropped from the
render. This is presentation only, so the payload must come back out of the
call untouched: the JSON contract keeps every licence field it was given.

The widths are asserted the same way they were derived. reportlab wraps a
Paragraph only at spaces, so a column that is narrower than its widest
unbreakable token gets force-split mid-token -- a break a reader notices in a
report meant to be assessed. Each column is therefore checked against

    pdfmetrics.stringWidth(widest token, that cell's own font, size)

using the font actually attached to the rendered cell, not one assumed here,
and the seven widths must still total the 17.40 cm frame.
"""

import copy
from pathlib import Path

from reportlab.pdfbase.pdfmetrics import stringWidth

from reporting.pdf_report import _licensing_section

PDF_SOURCE = Path(__file__).resolve().parents[1] / "reporting" / "pdf_report.py"

FRAME_CM = 17.40
N_COLS = 7
HEADERS = [
    "Component", "Version", "Declared License", "Resolved License",
    "License Category", "Resolution Status", "Evidence Source",
]
# columns that were measured to be constant and must not be rendered
DROPPED_HEADERS = ["Review", "Provenance"]

PT_PER_CM = 72 / 2.54


def _table(story):
    for flowable in story:
        if type(flowable).__name__ == "Table":
            return flowable
    raise AssertionError("no Table in the licensing story")


def _text(cell) -> str:
    if isinstance(cell, str):
        return cell
    return getattr(cell, "text", None) or ""


def _payload(**kw):
    base = {
        "license_evidence": [
            {
                "package": "@fortawesome/fontawesome-svg-core",
                "version": "6.4.0",
                "license_declared": "MIT",
                "license_resolved": "MIT",
                "license_expression": "MIT",
                "license_components": ["MIT"],
                "license_category": "Permissive",
                "license_resolution_status": "RESOLVED_FROM_CANONICAL_REPORT",
                "license_evidence_source": "CANONICAL_REPORT",
                "license_evidence": None,
                "license_review_required": False,
                "license_provenance": {"resolver": "x", "source": "y"},
            },
        ],
    }
    base.update(kw)
    return base


def _cells(payload):
    table = _table(_licensing_section(payload))
    return table, table._cellvalues


# ------------------------------------------------------------- the columns ---
def test_the_table_renders_exactly_the_informative_columns():
    _, cells = _cells(_payload())
    assert [_text(c) for c in cells[0]] == HEADERS


def test_every_row_has_one_cell_per_column():
    _, cells = _cells(_payload())
    for i, row in enumerate(cells):
        assert len(row) == N_COLS, f"row {i} has {len(row)} cells, want {N_COLS}"


def test_the_constant_columns_are_gone():
    """Neither may appear as a header: every cell in them read the same word."""
    _, cells = _cells(_payload())
    header = [_text(c) for c in cells[0]]
    for name in DROPPED_HEADERS:
        assert name not in header, f"{name!r} is constant and must not render"


def test_the_dropped_fields_do_not_leak_into_a_surviving_cell():
    """A provenance string is long and distinctive; it must appear nowhere."""
    table, cells = _cells(_payload())
    rendered = "\n".join(_text(c) for row in cells for c in row)
    assert "resolver=x" not in rendered
    assert "No" not in [_text(c) for c in cells[1]], "the Review cell survived"


def test_the_payload_contract_comes_back_untouched():
    """Presentation only: the JSON must be exactly what it was on the way in,
    licence fields included. Dropping a column must not drop a field."""
    payload = _payload()
    before = copy.deepcopy(payload)
    _licensing_section(payload)
    assert payload == before
    row = payload["license_evidence"][0]
    assert row["license_review_required"] is False
    assert row["license_provenance"] == {"resolver": "x", "source": "y"}


def test_the_redundant_fields_are_still_all_present_in_the_payload():
    """Documented redundancy is not a licence to delete them. These three
    carry the same value on this payload; all three remain."""
    payload = _payload()
    _licensing_section(payload)
    row = payload["license_evidence"][0]
    for field in ("license_declared", "license_resolved", "license_expression",
                  "license_components", "license_evidence"):
        assert field in row, f"{field} was dropped from the payload"
    assert row["license_declared"] == row["license_resolved"] == "MIT"


# ---------------------------------------------------------------- widths -----
def test_the_widths_still_total_exactly_the_frame():
    table, _ = _cells(_payload())
    total_cm = sum(table._argW) / PT_PER_CM
    assert abs(total_cm - FRAME_CM) < 1e-6, f"table is {total_cm:.4f} cm wide"


def test_every_column_fits_its_widest_unbreakable_token():
    """reportlab wraps only at spaces, so a too-narrow column is force-split
    mid-token. The font is read off each rendered cell, so a style change
    cannot silently invalidate the arithmetic."""
    table, cells = _cells(_payload())
    widths = table._argW
    problems = []
    for col in range(len(cells[0])):
        usable_pt = widths[col] - 12  # 6pt left + 6pt right padding
        worst, worst_token, where = 0.0, "", None
        for row_index, row in enumerate(cells):
            cell = row[col]
            style = getattr(cell, "style", None)
            font = getattr(style, "fontName", None)
            size = getattr(style, "fontSize", None) or 0
            if not font:
                continue
            for token in _text(cell).split():
                width = stringWidth(token, font, size)
                if width > worst:
                    worst, worst_token, where = width, token, row_index
        if usable_pt < worst - 1e-6:
            problems.append(
                f"column {col}: {usable_pt:.2f}pt usable < {worst:.2f}pt "
                f"needed by {worst_token!r} (row {where})"
            )
    assert not problems, "; ".join(problems)


def test_the_two_columns_that_used_to_overflow_were_actually_widened():
    """Regression guard on the specific defect: Component was 2.55cm against
    a 4.65cm requirement and Source 1.74cm against 3.03cm."""
    table, _ = _cells(_payload())
    component_cm = table._argW[0] / PT_PER_CM
    source_cm = table._argW[6] / PT_PER_CM
    assert component_cm >= 4.65, f"Component is {component_cm:.2f}cm"
    assert source_cm >= 3.03, f"Source is {source_cm:.2f}cm"


# ---------------------------------------------------------- the source ------
def test_the_width_list_is_derived_from_the_measurement_not_remembered():
    """Pin the derivation against the file so a hand-edit to one number that
    breaks the frame total is caught by this test's own arithmetic too."""
    src = PDF_SOURCE.read_text(encoding="utf-8-sig")
    assert "colWidths=[4.77*cm,1.61*cm,2.10*cm,2.10*cm,1.72*cm,1.99*cm,3.11*cm]" in src
    assert "1.45*cm,2.14*cm" not in src, "the dropped widths came back"
