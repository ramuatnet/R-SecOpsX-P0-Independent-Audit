import sys
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scanner import abom
import tempfile
from pathlib import Path

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

assert rows, "No ABOM findings"

for row in rows:
    assert row.get("component_id", "").startswith("ABOM-"), row
    assert row.get("evidence_type"), row
    assert isinstance(row["evidence_type"], list), row
    assert row.get("confidence_level"), row
    assert row.get("detection_mode"), row

assert any("AST" in x["evidence_type"] for x in rows), rows
assert any(
    "IMPORT_RESOLUTION" in x["evidence_type"]
    for x in rows
), rows

ids = [x["component_id"] for x in rows]
assert len(ids) == len(set(ids)), rows

print("ABOM_COMPONENT_CONTRACT_V3_ACCEPTED")

