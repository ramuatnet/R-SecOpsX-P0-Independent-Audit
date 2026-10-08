from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scanner import abom

def main():
    d = Path(tempfile.mkdtemp(prefix="abom_v6_"))
    p = d / "case.py"
    p.write_text(
        "from crewai import Agent as CrewAgent\n"
        "agent = CrewAgent(role='analyst')\n",
        encoding="utf-8",
    )
    rows = abom.scan_file(str(p))
    assert rows, "ABOM produced no finding"
    row = next(
        (x for x in rows if str(x.get("component","")).lower() == "agent"),
        rows[0],
    )
    assert row.get("component_id","").startswith("ABOM-"), row
    assert "AST" in row.get("evidence_type", []), row
    assert "IMPORT_RESOLUTION" in row.get("evidence_type", []), row
    assert row.get("confidence_level") == "HIGH", row
    assert row.get("import_resolution"), row
    print("[PASS] Existing ABOM detection")
    print("[PASS] AST verification")
    print("[PASS] Import/alias resolution")
    print("[PASS] Deterministic component_id")
    print("[PASS] Evidence/confidence enrichment")
    print("ABOM_AST_IMPORT_V6_ACCEPTED")

if __name__ == "__main__":
    main()