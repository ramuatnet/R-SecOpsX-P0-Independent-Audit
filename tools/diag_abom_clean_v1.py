from pathlib import Path
import sys
import tempfile

ROOT = Path.cwd()
sys.path.insert(0, str(ROOT))

from scanner import abom

root = Path(tempfile.mkdtemp(prefix="abom_clean_diag_"))
src = root / "crew.py"

src.write_text(
    "from crewai import Agent as CrewAgent\n"
    "import crewai\n"
    "a = CrewAgent(role='analyst', goal='analyze')\n"
    "b = crewai.Agent(role='writer', goal='write')\n",
    encoding="utf-8",
)

print("ROOT =", ROOT)
print("FILE =", src)

rows = abom.scan_file(str(src))

print("COUNT =", len(rows))

for i, row in enumerate(rows, 1):
    print(f"\nROW {i}")
    for key in (
        "framework",
        "component",
        "line",
        "detection_mode",
        "confidence",
        "confidence_level",
        "component_id",
        "evidence_type",
        "import_resolution",
        "evidence",
    ):
        print(f"{key} =", row.get(key))

print("\nFULL ROWS")
for row in rows:
    print(row)
