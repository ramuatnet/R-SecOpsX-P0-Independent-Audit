from pathlib import Path
from datetime import datetime
import shutil

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "scanner" / "aibom.py"
BACKUP_DIR = ROOT / "backup"

source = TARGET.read_text(encoding="utf-8-sig")

stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
BACKUP_DIR.mkdir(parents=True, exist_ok=True)
backup = BACKUP_DIR / f"aibom.py.before_p02_single_identity_{stamp}.py"
shutil.copy2(TARGET, backup)

old = '''    provider = str(rule["provider"])
    component = str(rule["component"])

    # P0.2 canonical semantic identity.
    # Identity MUST NOT depend on file path, line number, alias,
    # evidence text, detection mechanism, or model hint.
    identity_source = f"{provider}|{component}".encode("utf-8")
    component_id = (
        "AIBOM-COMP-"
        + __import__("hashlib").sha256(identity_source)
        .hexdigest()
        .upper()[:20]
    )

    item = {
        "bom_type": "AI-BOM",
        "provider": provider,
        "component": component,
        "component_id": component_id,
'''

new = '''    provider = str(rule["provider"])
    component = str(rule["component"])

    # P0.2:
    # Canonical semantic identity is applied centrally by
    # _aibom_apply_identity_contract().
    #
    # Do not calculate component_id here. Keeping one authoritative
    # identity generator guarantees that regex, AST, import-resolution,
    # alias-resolution, and merged findings use the same identity.

    item = {
        "bom_type": "AI-BOM",
        "provider": provider,
        "component": component,
'''

if old not in source:
    raise SystemExit(
        "ERROR: duplicate component-ID block was not found."
    )

source = source.replace(old, new, 1)

TARGET.write_text(source, encoding="utf-8")

print("[PASS] Removed duplicate component-ID generation")
print("[PASS] _aibom_component_id() remains authoritative")
print("[PASS] _aibom_apply_identity_contract() remains authoritative")
print(f"[BACKUP] {backup}")
