from pathlib import Path
from tempfile import TemporaryDirectory
import sys

ROOT = Path(r"D:\Data\Code test\R-SecOpsX_V11")
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scanner import abom

source = """from llama_index.core.agent import ReActAgent

agent = ReActAgent.from_tools(tools)
"""

with TemporaryDirectory(prefix="abom_llama_ast_") as td:
    path = Path(td) / "llama_react.py"
    path.write_text(source, encoding="utf-8")

    rows = abom.scan_file(str(path))

    print("=== LLAMAINDEX REACT AST VALIDATION ===")
    print(f"COUNT = {len(rows)}")

    for row in rows:
        print()
        print("framework        =", row.get("framework"))
        print("component        =", row.get("component"))
        print("line             =", row.get("line"))
        print("detection_mode   =", row.get("detection_mode"))
        print("evidence_type    =", row.get("evidence_type"))
        print("import_resolution =", row.get("import_resolution"))
        print("component_id     =", row.get("component_id"))

    ast_rows = [
        r for r in rows
        if "AST" in (r.get("evidence_type") or [])
    ]

    if not ast_rows:
        raise SystemExit(
            "[FAIL] LlamaIndex ReActAgent is detected only by regex; "
            "AST/import-resolution coverage is missing."
        )

    if not any(
        r.get("framework") == "LlamaIndex"
        and r.get("component") == "ReAct Agent"
        for r in ast_rows
    ):
        raise SystemExit(
            "[FAIL] AST finding exists, but it is not mapped to "
            "LlamaIndex / ReAct Agent."
        )

    print()
    print("[PASS] LlamaIndex ReActAgent AST/import-resolution coverage")
