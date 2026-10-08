from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scanner import abom


def main():
    root = Path(tempfile.mkdtemp(prefix="abom_contract_v3_"))
    src = root / "crew.py"

    src.write_text(
        "from crewai import Agent as CrewAgent\n"
        "import crewai\n"
        "a = CrewAgent(role='analyst', goal='analyze')\n"
        "b = crewai.Agent(role='writer', goal='write')\n",
        encoding="utf-8",
    )

    rows = abom.scan_file(str(src))

    print("FINDINGS=", len(rows))

    assert rows, "ABOM produced no findings"

    for row in rows:
        print(row)

        assert row.get("component_id", "").startswith("ABOM-"), row
        assert isinstance(row.get("evidence_type"), list), row
        assert row.get("evidence_type"), row
        assert row.get("confidence_level"), row
        assert row.get("detection_mode"), row

    assert any(
        "AST" in row.get("evidence_type", [])
        for row in rows
    ), rows

    assert any(
        "IMPORT_RESOLUTION" in row.get("evidence_type", [])
        for row in rows
    ), rows

    ids = [row["component_id"] for row in rows]

    assert len(ids) == len(set(ids)), rows

    print("[PASS] ABOM findings")
    print("[PASS] component_id")
    print("[PASS] evidence_type")
    print("[PASS] confidence_level")
    print("[PASS] AST evidence")
    print("[PASS] import-resolution evidence")
    print("[PASS] deterministic component IDs")
    print("ABOM_COMPONENT_CONTRACT_V3_ACCEPTED")


if __name__ == "__main__":
    main()
