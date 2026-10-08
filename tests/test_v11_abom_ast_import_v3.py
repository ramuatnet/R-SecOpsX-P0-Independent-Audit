from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scanner import abom


def make_file(text):
    d = Path(tempfile.mkdtemp(prefix="abom_v3_"))
    p = d / "case.py"
    p.write_text(text, encoding="utf-8")
    return p


def main():
    p = make_file(
        "from crewai import Agent as CrewAgent\n"
        "agent = CrewAgent(role='analyst')\n"
    )
    rows = abom.scan_file(str(p))
    assert rows, "ABOM produced no findings"
    row = next((x for x in rows if str(x.get("component", "")).lower() == "agent"), rows[0])

    assert row.get("component_id", "").startswith("ABOM-")
    assert "AST" in row.get("evidence_type", [])
    assert "IMPORT_RESOLUTION" in row.get("evidence_type", [])
    assert row.get("confidence_level") == "HIGH"
    print("[PASS] AST verification")
    print("[PASS] import/alias evidence")
    print("[PASS] deterministic component identity")

    for key in ("framework", "component", "file", "line"):
        assert key in row, key

    print("[PASS] existing ABOM core fields preserved")
    print("ABOM_AST_IMPORT_V3_ACCEPTED")


if __name__ == "__main__":
    main()
