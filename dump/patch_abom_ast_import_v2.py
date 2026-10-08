from __future__ import annotations

import ast
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(r"D:\Data\Code test\R-SecOpsX_V11")
PROD = ROOT / "scanner" / "abom.py"
BACKUP_DIR = ROOT / "backup"
TEST = ROOT / "tests" / "test_v11_abom_ast_import_v1.py"

MARKER = "# --- V11 ABOM AST/IMPORT RESOLUTION v1 ---"


def run_checked(cmd):
    print("[INFO]", " ".join(str(x) for x in cmd))
    subprocess.run(cmd, cwd=str(ROOT), check=True)


def main():
    if not PROD.exists():
        raise RuntimeError(f"Production ABOM not found: {PROD}")

    original = PROD.read_text(encoding="utf-8-sig")

    if MARKER in original:
        raise RuntimeError("ABOM AST/import v1 is already installed; refusing duplicate patch.")

    tree = ast.parse(original, filename=str(PROD))
    functions = {
        n.name for n in ast.walk(tree)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    }

    for required in ("_make_item", "scan_file"):
        if required not in functions:
            raise RuntimeError(f"Required function missing: {required}")

    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    backup = BACKUP_DIR / f"abom.py.before_abom_ast_import_v1_{stamp}.py"
    backup.write_text(original, encoding="utf-8")

    # Import additions are intentionally minimal.
    lines = original.splitlines()
    text = "\n".join(lines)
    needed = []
    if "import ast" not in text:
        needed.append("import ast")
    if "import hashlib" not in text:
        needed.append("import hashlib")

    i = 0
    while i < len(lines):
        stripped = lines[i].strip()
        if (
            not stripped
            or stripped.startswith("#")
            or stripped.startswith("import ")
            or stripped.startswith("from ")
        ):
            i += 1
        else:
            break

    if needed:
        lines[i:i] = needed
        i += len(needed)

    helper = r