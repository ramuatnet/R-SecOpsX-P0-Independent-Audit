from pathlib import Path
from datetime import datetime
import shutil
import sys

ROOT = Path(r"D:\Data\Code test\R-SecOpsX_V11")
V2 = ROOT / "scanner" / "abom_v2.py"
BACKUP_DIR = ROOT / "backup"

BACKUP_DIR.mkdir(parents=True, exist_ok=True)

source = V2.read_text(encoding="utf-8-sig")

needle = "            for match in re.finditer(pattern, source, re.IGNORECASE):"

if needle not in source:
    print("[FAIL] Regex loop anchor not found.")
    sys.exit(2)

if "if not _regex_match_is_code(source, match.start()):" in source:
    print("[PASS] Guard already present.")
    sys.exit(0)

stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
backup = BACKUP_DIR / f"abom_v2.py.before_regex_guard_{stamp}.py"

shutil.copy2(V2, backup)
print(f"[PASS] Backup: {backup}")

replacement = """            for match in re.finditer(pattern, source, re.IGNORECASE):

                # Regex is supplementary. Never treat Python strings/comments
                # as executable source.
                if path.suffix.lower() == ".py":
                    if not _regex_match_is_code(source, match.start()):
                        continue
"""

updated = source.replace(needle, replacement, 1)

if updated == source:
    shutil.copy2(backup, V2)
    print("[FAIL] No source change produced.")
    sys.exit(3)

V2.write_text(updated, encoding="utf-8")

print("[PASS] Regex code guard inserted")
print("[PASS] V2 written")
