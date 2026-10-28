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

    tree = abom.ast.parse(source, filename=str(path))
    imports = abom._python_import_map(tree)

    print("=== IMPORT MAP ===")
    print(imports)

    print()
    print("=== FRAMEWORK RESOLUTION ===")
    for name, module in imports.items():
        print(
            f"{name:15} -> {module:40} -> "
            f"{abom._framework_from_module(module)}"
        )

    print()
    print("=== AST COMPONENT MAPS ===")
    print("crewai      =", abom.AST_COMPONENTS.get("crewai"))
    print("langchain   =", abom.AST_COMPONENTS.get("langchain"))
    print("autogen     =", abom.AST_COMPONENTS.get("autogen"))
    print("llama_index =", abom.AST_COMPONENTS.get("llama_index"))

    print()
    print("=== DIRECT AST FINDINGS ===")
    ast_rows = abom._ast_findings(path, source, "production")

    print("AST COUNT =", len(ast_rows))

    for row in ast_rows:
        print()
        print("framework        =", row.get("framework"))
        print("component        =", row.get("component"))
        print("line             =", row.get("line"))
        print("detection_mode   =", row.get("detection_mode"))
        print("evidence_type    =", row.get("evidence_type"))
        print("import_resolution=", row.get("import_resolution"))
        print("evidence         =", row.get("evidence"))

    print()
    print("=== COMPLETE SCAN ===")
    rows = abom.scan_file(str(path))

    print("SCAN COUNT =", len(rows))

    for row in rows:
        print()
        print("framework        =", row.get("framework"))
        print("component        =", row.get("component"))
        print("line             =", row.get("line"))
        print("detection_mode   =", row.get("detection_mode"))
        print("evidence_type    =", row.get("evidence_type"))
        print("import_resolution=", row.get("import_resolution"))
        print("evidence         =", row.get("evidence"))
