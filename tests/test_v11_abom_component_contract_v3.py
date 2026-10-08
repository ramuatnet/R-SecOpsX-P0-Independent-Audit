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
    for row in rows:
        print(row)

    assert rows, "ABOM produced no findings"

    assert all(
        x.get("bom_type") == "ABOM"
        for x in rows
    )

    assert all(
        x.get("framework", "").lower() == "crewai"
        for x in rows
    )

    assert all(
        x.get("component") == "Agent"
        for x in rows
    )

    assert all(
        "AST" in x.get("detection_mode", "")
        for x in rows
    )

    assert any(
        "IMPORT_RESOLUTION" in x.get("detection_mode", "")
        for x in rows
    )

    assert all(
        x.get("confidence") == "HIGH"
        for x in rows
    )

    assert all("file" in x for x in rows)
    assert all("line" in x for x in rows)
    assert all("evidence" in x for x in rows)
    assert all("asset_scope" in x for x in rows)
    assert all("validation_only" in x for x in rows)

    # component_id is intentionally NOT required.
    # Legacy ABOM contract does not require it.

    print("[PASS] ABOM findings")
    print("[PASS] CrewAI framework")
    print("[PASS] Agent component")
    print("[PASS] AST detection")
    print("[PASS] Import resolution")
    print("[PASS] HIGH confidence")
    print("[PASS] Legacy ABOM fields")
    print("[PASS] component_id not required by legacy contract")
    print("ABOM_COMPONENT_CONTRACT_V3_ACCEPTED")


if __name__ == "__main__":
    main()
