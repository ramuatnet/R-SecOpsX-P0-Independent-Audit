from pathlib import Path
import tempfile
from scanner import abom

def case(text):
    d = Path(tempfile.mkdtemp(prefix="abom_v1_"))
    p = d / "case.py"
    p.write_text(text, encoding="utf-8")
    return p

def main():
    p = case("from crewai import Agent as CrewAgent\nagent = CrewAgent(role='analyst')\n")
    rows = abom.scan_file(str(p))
    row = next((x for x in rows if x.get("component") == "Agent"), None)
    assert row is not None, rows
    assert row["component_id"].startswith("ABOM-")
    assert "AST" in row["evidence_type"]
    assert "IMPORT_RESOLUTION" in row["evidence_type"]
    assert row["confidence_level"] == "HIGH"
    print("[PASS] AST verification")
    print("[PASS] import/alias resolution")

    p2 = case("Agent(role='generic')\n")
    rows2 = abom.scan_file(str(p2))
    assert not any(x.get("framework") == "CrewAI" and x.get("confidence_level") == "HIGH" for x in rows2)
    print("[PASS] generic Agent negative/context regression")

    p3 = case("from crewai import Agent as CrewAgent\na=CrewAgent()\nb=CrewAgent()\n")
    rows3 = [x for x in abom.scan_file(str(p3)) if x.get("component") == "Agent"]
    assert rows3 and len({x["component_id"] for x in rows3}) == 1
    print("[PASS] deterministic component_id")

    for key in ("bom_type","framework","component","category","file","line","evidence","tools_detected","memory_detected","human_approval_detected","asset_scope","validation_only","risk","recommendation"):
        assert key in rows3[0], key
    print("[PASS] existing ABOM fields preserved")
    print("ABOM_AST_IMPORT_V1_ACCEPTED")

if __name__ == "__main__":
    main()
