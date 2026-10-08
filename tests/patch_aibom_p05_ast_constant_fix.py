from pathlib import Path
from datetime import datetime

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "scanner" / "aibom.py"
BACKUP_DIR = ROOT / "backup"

BACKUP_DIR.mkdir(parents=True, exist_ok=True)

text = TARGET.read_text(encoding="utf-8-sig")

start_marker = "def _aibom_string_constant("
start = text.find(start_marker)

if start < 0:
    raise SystemExit("[ERROR] _aibom_string_constant() not found.")

next_def = text.find("\ndef ", start + len(start_marker))

if next_def < 0:
    raise SystemExit("[ERROR] Could not locate end of _aibom_string_constant().")

new_function = '''def _aibom_string_constant(node):
    """
    Return a statically resolvable Python string constant.

    Python 3.14 compatibility:
      - Use ast.Constant rather than the removed ast.Str API.
      - Return None for non-string expressions.
      - Do not evaluate arbitrary expressions.
    """
    if isinstance(node, ast.Constant):
        value = node.value
        if isinstance(value, str):
            return value

    return None
'''

updated = text[:start] + new_function + text[next_def:]

if updated == text:
    raise SystemExit("[ERROR] No change produced.")

timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
backup = BACKUP_DIR / f"aibom.py.before_p05_ast_constant_fix_{timestamp}.py"
backup.write_text(text, encoding="utf-8")

TARGET.write_text(updated, encoding="utf-8")

print("[PASS] Replaced obsolete ast.Str usage")
print("[PASS] Python 3.14 AST Constant handling added")
print(f"[BACKUP] {backup}")
