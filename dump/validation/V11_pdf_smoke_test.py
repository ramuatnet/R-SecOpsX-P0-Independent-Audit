from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from reporting.pdf_report import generate_pdf_report

payload = {
    "findings": [],
    "summary": {
        "total_findings": 0,
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
    },
}

with tempfile.TemporaryDirectory() as td:
    pdf = Path(td) / "Security_Report.pdf"

    generate_pdf_report(payload, str(pdf))

    assert pdf.exists(), "PDF was not generated"
    assert pdf.stat().st_size > 0, "Generated PDF is empty"

    print("[PASS] PDF generated")
    print(f"[PASS] PDF size: {pdf.stat().st_size} bytes")
    print("[PASS] Canonical JSON -> PDF smoke validation")
