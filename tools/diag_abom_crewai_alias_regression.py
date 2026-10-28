from pathlib import Path
from tempfile import TemporaryDirectory
from scanner import abom

source = """from crewai import Agent as CrewAgent
import crewai

a = CrewAgent(role='analyst', goal='analyze')
b = crewai.Agent(role='writer', goal='write')
"""

with TemporaryDirectory(prefix="abom_alias_diag_") as td:
    path = Path(td) / "crew.py"
    path.write_text(source, encoding="utf-8")

    rows = abom.scan_file(str(path))

    print("=== CREWAI ALIAS REGRESSION DIAGNOSTIC ===")
    print("COUNT =", len(rows))

    for row in rows:
        print()
        print("framework        =", row.get("framework"))
        print("component        =", row.get("component"))
        print("line             =", row.get("line"))
        print("detection_mode   =", row.get("detection_mode"))
        print("evidence_type    =", row.get("evidence_type"))
        print("import_resolution=", row.get("import_resolution"))
        print("evidence         =", row.get("evidence"))

