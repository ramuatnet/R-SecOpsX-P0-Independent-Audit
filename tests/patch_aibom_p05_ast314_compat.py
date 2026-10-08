from pathlib import Path
from datetime import datetime

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "scanner" / "aibom.py"
BACKUP_DIR = ROOT / "backup"

source = TARGET.read_text(encoding="utf-8-sig")

old = '''def _aibom_string_constant(node):
    """Return a literal string value, otherwise None."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value

    if isinstance(node, ast.Str):
        return node.s

    return None
'''

new = '''def _aibom_string_constant(node):
    """Return a literal string value, otherwise None.

    Python 3.14 compatibility:
    string literals are represented through ast.Constant.
    Do not reference ast.Str because it is unavailable in the
    current runtime.
    """
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value

    return None
'''

if old not in source:
    raise SystemExit(
        "[FAIL] Expected _aibom_string_constant() implementation not found."
    )

BACKUP_DIR.mkdir(parents=True, exist_ok=True)

timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
backup = BACKUP_DIR / (
    f"aibom.py.before_p05_ast314_compat_{timestamp}.py"
)

backup.write_text(source, encoding="utf-8")

source = source.replace(old, new, 1)

TARGET.write_text(source, encoding="utf-8")

print("[PASS] Removed ast.Str dependency")
print("[PASS] Python 3.14 AST compatibility applied")
print("[PASS] ast.Constant string handling preserved")
print(f"[BACKUP] {backup}")
