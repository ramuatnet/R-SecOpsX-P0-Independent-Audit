from pathlib import Path
from tempfile import TemporaryDirectory
import scanner.aibom as aibom

SOURCE = """from openai import OpenAI

client = OpenAI()
"""

with TemporaryDirectory(prefix="aibom_p02_diag_") as td:
    path = Path(td) / "case.py"
    path.write_text(SOURCE, encoding="utf-8")

    print("=" * 80)
    print("AI-BOM P0.2 INTERNAL DIAGNOSTIC")
    print("=" * 80)

    print("\n=== RAW AST FINDINGS ===")
    ast_items = aibom._ast_findings(path, SOURCE)

    for i, item in enumerate(ast_items, 1):
        print(f"\nAST ITEM {i}")
        for key in (
            "provider",
            "component",
            "file",
            "line",
            "evidence",
            "component_id",
            "evidence_type",
            "confidence",
            "confidence_score",
            "import_resolution",
            "detection_mode",
        ):
            print(f"{key:20} = {item.get(key)!r}")

    print("\n=== scan_file RESULT ===")
    results = aibom.scan_file(str(path))

    for i, item in enumerate(results, 1):
        print(f"\nSCAN ITEM {i}")
        for key in (
            "provider",
            "component",
            "file",
            "line",
            "evidence",
            "component_id",
            "evidence_type",
            "confidence",
            "confidence_score",
            "import_resolution",
            "detection_mode",
        ):
            print(f"{key:20} = {item.get(key)!r}")

    print("\n=== DEDUP KEY ANALYSIS ===")
    for i, item in enumerate(results, 1):
        key = (
            item.get("provider"),
            item.get("component"),
            item.get("file"),
            item.get("line"),
            item.get("evidence"),
        )
        print(f"ITEM {i} KEY = {key!r}")

    print("\n=== RESULT COUNT ===")
    print("COUNT =", len(results))
