from pathlib import Path
from datetime import datetime
import shutil

root = Path(r"D:\Data\Code test\R-SecOpsX_V11")
src = root / "scanner" / "abom.py"
backup_dir = root / "backup"

backup_dir.mkdir(parents=True, exist_ok=True)

text = src.read_text(encoding="utf-8-sig")

if "def _component_id(" in text:
    print("[INFO] _component_id already exists. No source change made.")
    raise SystemExit(0)

if "import hashlib" not in text:
    marker = "import ast\n"
    if marker not in text:
        raise SystemExit("Could not locate import insertion point. No source change made.")
    text = text.replace(marker, marker + "import hashlib\n", 1)

marker = "def _make_item("
idx = text.find(marker)

if idx < 0:
    raise SystemExit("Could not locate _make_item(). No source change made.")

helper = '''def _component_id(
    framework: str,
    component: str,
    filepath: str,
    line: int,
) -> str:
    raw = f"{framework}|{component}|{filepath}|{line}"
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16].upper()
    return f"ABOM-{digest}"


'''

stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
backup = backup_dir / f"abom.py.before_component_id_{stamp}.py"

shutil.copy2(src, backup)

text = text[:idx] + helper + text[idx:]
src.write_text(text, encoding="utf-8")

print("[PASS] Production _component_id helper added")
print(f"[BACKUP] {backup}")
