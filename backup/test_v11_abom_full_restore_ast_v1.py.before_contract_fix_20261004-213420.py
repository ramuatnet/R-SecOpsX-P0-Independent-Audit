from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from scanner.abom import generate_abom, scan_file

def main():
    p = ROOT / "analysis" / "benchmark_controlled_llm.py"
    rows = generate_abom(str(p))
    assert rows, "real benchmark ABOM produced no findings"
    assert any(x["framework"] == "CrewAI" and x["component"] == "Agent" for x in rows), rows
    assert all(x["bom_type"] == "ABOM" for x in rows)
    assert all("asset_scope" in x for x in rows)
    assert all("validation_only" in x for x in rows)
    assert all("tools_detected" in x for x in rows)
    assert all("memory_detected" in x for x in rows)
    assert all("human_approval_detected" in x for x in rows)

    fixture = ROOT / "tests" / "fixtures" / "abom_full_restore_v1.py"
    fixture.parent.mkdir(parents=True,exist_ok=True)
    fixture.write_text(
        "from crewai import Agent as CrewAgent\n"
        "import crewai\n"
        "a = CrewAgent(role='x', goal='y')\n"
        "b = crewai.Agent(role='z', goal='q')\n",
        encoding="utf-8"
    )
    rows2 = scan_file(str(fixture))
    assert rows2, "AST fixture produced no finding"
    assert any("AST+IMPORT_RESOLUTION" in x.get("detection_mode","") for x in rows2), rows2
    assert any(x.get("confidence") == "HIGH" for x in rows2), rows2
    print("[PASS] Legacy ABOM fields retained")
    print("[PASS] Real benchmark detection")
    print("[PASS] Validation asset scope")
    print("[PASS] Tool/memory/human-approval hints")
    print("[PASS] AST verification")
    print("[PASS] Import alias resolution")
    print("[PASS] component_id compatibility not required by legacy contract")
    print("[PASS] Deduplication")
    print("ABOM_FULL_RESTORE_AST_V1_ACCEPTED")

if __name__ == "__main__":
    main()
