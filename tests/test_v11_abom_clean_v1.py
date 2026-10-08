from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scanner import abom

def main():
    root = Path(tempfile.mkdtemp(prefix="abom_clean_v1_"))

    src = root / "crew.py"
    src.write_text(
        "from crewai import Agent as CrewAgent\n"
        "import crewai\n"
        "a = CrewAgent(role='analyst', goal='analyze')\n"
        "b = crewai.Agent(role='writer', goal='write')\n",
        encoding="utf-8",
    )

    rows = abom.scan_file(str(src))
    assert rows, "ABOM produced no positive result"

    assert any(
        x.get("framework","").lower() == "crewai" and x["component"] == "Agent"
        for x in rows
    ), rows

    assert all(x.get("component_id","").startswith("ABOM-") for x in rows)
    assert all("AST" in x.get("evidence_type",[]) for x in rows)
    assert any("IMPORT_RESOLUTION" in x.get("evidence_type",[]) for x in rows)
    assert all(x.get("confidence_level") == "HIGH" for x in rows)

    ids = [x["component_id"] for x in rows]
    assert len(ids) == len(set(ids)), rows

    project = root / "project"
    project.mkdir()
    (project / "agent.py").write_text(
        "from crewai import Agent as CrewAgent\n"
        "agent = CrewAgent(role='x', goal='y')\n",
        encoding="utf-8",
    )

    project_rows = abom.generate_abom(str(project))
    assert project_rows, "generate_abom() produced no result"

    print("[PASS] CrewAI context detection")
    print("[PASS] AST verification")
    print("[PASS] Import alias resolution")
    print("[PASS] component_id")
    print("[PASS] confidence/evidence")
    print("[PASS] generate_abom()")
    print("[PASS] deduplication")
    print("ABOM_CLEAN_V1_ACCEPTED")

if __name__ == "__main__":
    main()
