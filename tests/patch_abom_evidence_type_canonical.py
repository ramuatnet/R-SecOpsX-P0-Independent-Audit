from pathlib import Path
from datetime import datetime
import shutil

root = Path(r"D:\Data\Code test\R-SecOpsX_V11")
src = root / "scanner" / "abom.py"
backup_dir = root / "backup"

backup_dir.mkdir(parents=True, exist_ok=True)

text = src.read_text(encoding="utf-8-sig")

old = '''    evidence_type = list(evidence_type or [])
'''

new = '''    # V11 canonical provenance contract:
    # derive evidence provenance from detection_mode when callers do not
    # explicitly provide evidence_type.
    if evidence_type:
        evidence_type = list(evidence_type)
    elif detection_mode:
        evidence_type = [
            m.strip()
            for m in detection_mode.split("+")
            if m.strip()
        ]
    else:
        evidence_type = []
'''

if old not in text:
    raise SystemExit(
        "EXPECTED evidence_type assignment not found. "
        "NO SOURCE CHANGE MADE."
    )

stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
backup = backup_dir / f"abom.py.before_evidence_type_canonical_{stamp}.py"

shutil.copy2(src, backup)

text = text.replace(old, new, 1)
src.write_text(text, encoding="utf-8")

print("[PASS] ABOM evidence_type canonical derivation patched")
print(f"[BACKUP] {backup}")
