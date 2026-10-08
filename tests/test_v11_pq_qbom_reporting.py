"""The PQ QBOM layer must be REPORTED, not merely emitted as an artifact.

A capability that exists as a JSON file and appears in no human-readable report is
not delivered. Measured before this work: zero occurrences of "qbom" anywhere under
reporting/, so both QBOM layers were invisible in every PDF and every workbook while
the payload and every artifact looked complete. The scan "succeeded" the whole time.

READING THE ARTEFACTS, NOT THE CODE
----------------------------------
The first version of this check failed all 22 of its content assertions while the
sheets were demonstrably correct. Both extractors were wrong: a regex over raw PDF
bytes cannot read compressed content streams, and parsing xl/sharedStrings.xml
misses cells openpyxl writes inline. So this reads the rendered output with the
libraries that produced it -- pypdf for the PDF, openpyxl for the workbooks -- and
asserts on what a reader would actually see.

The three things a reader must be able to tell, which is the substance of the check:

  1. WHICH assets break, and by which quantum mechanism. Shor and Grover are
     different problems with different remedies, and one status label for both
     produces one wrong piece of advice.
  2. WHAT could not be determined. UNKNOWN is printed as its own status with its
     count, and is explicitly marked as not a safe result. "0 assets need
     migration" is meaningless without the number that could not be assessed.
  3. THAT the inventory is aggregated. A real project had 3,111 crypto usage sites
     resolve to 4 distinct assets; if only the 4 appear, the table reads as a
     complete inventory and is not one.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

openpyxl = pytest.importorskip("openpyxl", reason="openpyxl is needed to read the workbooks")
pypdf = pytest.importorskip("pypdf", reason="pypdf is needed to read the rendered PDF")

from openpyxl import load_workbook  # noqa: E402
from pypdf import PdfReader  # noqa: E402

from reporting.excel_report import (  # noqa: E402
    generate_excel_report,
    generate_executive_excel_report,
    generate_technical_excel_report,
)
from reporting.pdf_report import generate_pdf_report  # noqa: E402


def _norm(text) -> str:
    """Collapse whitespace so PDF line wrapping cannot break a substring match.

    ReportLab wraps paragraphs at the frame width, so a sentence a human reads as
    one line is several in the extracted stream. Matching on the raw stream fails
    on correct output.
    """
    return " ".join(str(text).split())


ASSETS = [
    {"qbom_id": "QBOM-a", "algorithm": "RSA", "normalized_algorithm": "rsa",
     "key_size": 2048, "algorithm_provenance": "INFERRED_FROM_DISPLAY_NAME",
     "occurrence_count": 1, "quantum_status": "QUANTUM_VULNERABLE",
     "quantum_risk": "HIGH", "migration_priority": "MEDIUM", "confidence": 0.5,
     "classification_note": None},
    {"qbom_id": "QBOM-b", "algorithm": "DES / 3DES",
     "normalized_algorithm": "3des", "key_size": None,
     "algorithm_provenance": "INFERRED_FROM_DISPLAY_NAME",
     "occurrence_count": 13, "quantum_status": "QUANTUM_MARGIN_CRITICAL",
     "quantum_risk": "HIGH", "migration_priority": "MEDIUM", "confidence": 0.5,
     "classification_note": "64-bit effective key; Grover's algorithm reduces it "
                            "to roughly 32 bits."},
    {"qbom_id": "QBOM-c", "algorithm": "MD5", "normalized_algorithm": "md5",
     "key_size": None, "algorithm_provenance": "INFERRED_FROM_DISPLAY_NAME",
     "occurrence_count": 2, "quantum_status": "UNKNOWN",
     "quantum_risk": "UNKNOWN", "migration_priority": "NONE", "confidence": 0.0,
     "classification_note": None},
]

PAYLOAD = {
    "metadata": {"target": "verify-target", "scan_id": "verify-1",
                 "risk_score": 40.0, "cve_count": 0, "advisory_count": 0},
    "findings": [],
    "sbom": [{"name": "requests", "version": "2.31.0", "ecosystem": "PyPI",
              "direct": True, "license": "Apache-2.0"}],
    "cbom": [{"component": "RSA", "category": "Weak Cryptography",
              "file": "a.py", "line": 3}],
    "qbom_pq": {
        "bom_type": "PQ_QBOM",
        "exposure_summary": {
            "total_usage_sites": 14, "total_assets": 3, "classified": 2,
            "unclassified": 1, "needs_migration": 2,
            "by_quantum_status": {"QUANTUM_VULNERABLE": 1,
                                  "QUANTUM_MARGIN_CRITICAL": 1,
                                  "UNKNOWN": 1},
            "aggregation_note": ("14 CBOM usage sites resolve to 3 distinct "
                                 "cryptographic assets."),
            "coverage_note": "2 of 3 assets could be classified",
        },
        "assets": ASSETS,
    },
    "qbom": {"minimum_elements": {"cryptographic_asset": {
        "value": {"total_usage_sites": 14, "distinct_assets": 3}}}},
}


@pytest.fixture(scope="module")
def pdf_text(tmp_path_factory) -> str:
    out = tmp_path_factory.mktemp("pq_pdf")
    path = Path(generate_pdf_report(PAYLOAD, str(out / "report.pdf")))
    assert path.exists() and path.stat().st_size > 0
    reader = PdfReader(str(path))
    return _norm("".join((p.extract_text() or "") for p in reader.pages))


def _sheet_text(path: Path, title: str) -> tuple[str, int]:
    wb = load_workbook(str(path))
    assert title in wb.sheetnames, f"{title} missing; sheets={wb.sheetnames}"
    ws = wb[title]
    values = [str(v) for row in ws.iter_rows(values_only=True) for v in row
              if v is not None]
    return _norm(" ".join(values)), ws.max_row


# ------------------------------------------------------------------- PDF ----

def test_pdf_has_a_pq_qbom_section(pdf_text):
    assert "Post-Quantum Cryptographic Exposure" in pdf_text


def test_pdf_names_the_exposed_assets(pdf_text):
    assert "RSA" in pdf_text
    assert "DES / 3DES" in pdf_text


def test_pdf_distinguishes_the_two_quantum_mechanisms(pdf_text):
    """Shor and Grover are different problems with different remedies.

    One status label for both would produce one wrong piece of migration advice:
    an asymmetric primitive must be replaced with PQC, a 64-bit symmetric key must
    simply be replaced by one of adequate length.
    """
    assert "QUANTUM_VULNERABLE" in pdf_text
    assert "QUANTUM_MARGIN_CRITICAL" in pdf_text
    assert "Shor" in pdf_text
    assert "Grover" in pdf_text


def test_pdf_discloses_what_it_could_not_determine(pdf_text):
    assert "UNKNOWN" in pdf_text
    assert "could not be classified" in pdf_text


def test_pdf_states_unknown_is_not_a_safe_result(pdf_text):
    """The single most important sentence in the section.

    Without it, '1 of 3 assets could not be classified' reads as a footnote and
    '2 need migration' reads as a complete answer.
    """
    assert "not a safe result" in pdf_text
    assert "must not be read" in pdf_text


def test_pdf_declares_the_aggregation(pdf_text):
    assert "usage sites resolve to" in pdf_text


def test_pdf_records_absent_data_rather_than_inventing_it(pdf_text):
    """DES / 3DES has no key size in the source. Printing 64 or 0 would be a
    fabrication; printing nothing at all would look like an oversight."""
    assert "not recorded" in pdf_text


def test_pdf_carries_per_asset_caveats_and_provenance(pdf_text):
    assert "64-bit effective key" in pdf_text
    assert "INFERRED_FROM_DISPLAY_NAME" in pdf_text


def test_pdf_keeps_the_certin_layer_separate(pdf_text):
    assert "Security_QBOM.qbom.json" in pdf_text


# ------------------------------------------------------------ workbooks -----

@pytest.mark.parametrize(
    ("label", "builder"),
    [
        ("technical", generate_technical_excel_report),
        ("standard", generate_excel_report),
        ("executive", generate_executive_excel_report),
    ],
)
def test_every_workbook_reports_the_pq_qbom_layer(tmp_path, label, builder):
    """All three workbooks, not one.

    The executive workbook omits the other BOM layers by design, so its carrying
    PQ QBOM is a deliberate exception and is asserted explicitly rather than
    inherited.
    """
    path = Path(builder(PAYLOAD, str(tmp_path / f"{label}.xlsx")))
    text, max_row = _sheet_text(path, "PQ QBOM")

    assert max_row > 3, "the PQ QBOM sheet is present but empty"

    assert "RSA" in text
    assert "QUANTUM_VULNERABLE" in text
    assert "QUANTUM_MARGIN_CRITICAL" in text
    assert "NOT classifiable" in text
    assert "usage sites resolve to" in text
    assert "INFERRED_FROM_DISPLAY_NAME" in text
    assert "No external vulnerability or quantum database was consulted" in text


def test_pq_qbom_does_not_absorb_the_other_bom_layers(tmp_path):
    """Separate layers, separately reported.

    CERT-In defines SBOM / QBOM / CBOM / AI-BOM / HBOM as distinct types with
    distinct element tables. A report that merges them makes it impossible to tell
    which table a given field came from.
    """
    path = Path(generate_technical_excel_report(
        PAYLOAD, str(tmp_path / "t.xlsx")))
    sheets = load_workbook(str(path)).sheetnames

    assert "SBOM" in sheets
    assert "CBOM" in sheets
    assert "PQ QBOM" in sheets