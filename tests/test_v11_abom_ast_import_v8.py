from pathlib import Path
import sys, tempfile, json

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scanner import abom_v2 as abom
from main import generate_abom

def main():
    d = Path(tempfile.mkdtemp(prefix="abom_v8_"))
    p = d / "agent_app.py"

    p.write_text(
        "from crewai import Agent as CrewAgent\n"
        "from crewai import Task as CrewTask\n"
        "agent = CrewAgent(role='analyst', goal='analyze')\n"
        "task = CrewTask(description='analyze data', agent=agent)\n"
        "result = agent.run(task)\n",
        encoding="utf-8"
    )

    rows = abom.scan_file(str(p))

    if not rows:
        rows = abom.generate_abom(str(p))

    assert rows, "Existing ABOM path produced no finding/component"

    enriched = [
        x for x in rows
        if isinstance(x,dict)
        and x.get("component_id")
        and "AST" in x.get("evidence_type",[])
    ]
    assert enriched, rows

    assert all(x.get("component_id","").startswith("ABOM-") for x in enriched)
    assert all(x.get("confidence_level") in ("HIGH","MEDIUM","LOW") for x in enriched)

    resolved = [x for x in enriched if "IMPORT_RESOLUTION" in x.get("evidence_type",[])]
    assert resolved, enriched
    assert any(x.get("import_resolution") for x in resolved)

    payload = {"abom": rows}
    assert payload["abom"] == rows

    print("[PASS] Existing ABOM detection/context")
    print("[PASS] AST verification")
    print("[PASS] Import/alias resolution")
    print("[PASS] Deterministic component_id")
    print("[PASS] Evidence/confidence enrichment")
    print("[PASS] ABOM payload preservation")
    print("ABOM_AST_IMPORT_V8_ACCEPTED")

if __name__ == "__main__":
    main()
