from pathlib import Path
from datetime import datetime
import shutil

root = Path(r"D:\Data\Code test\R-SecOpsX_V11")
src = root / "scanner" / "abom.py"
backup_dir = root / "backup"

backup_dir.mkdir(parents=True, exist_ok=True)

stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
backup = backup_dir / f"abom.py.before_ast_merge_contract_{stamp}.py"

text = src.read_text(encoding="utf-8-sig")

old = '''            if existing:
                modes = set(str(existing.get("detection_mode","")).split("+"))
                modes.update(str(item.get("detection_mode","")).split("+"))
                existing["detection_mode"] = "+".join(sorted(x for x in modes if x))
                if item.get("confidence") == "HIGH":
                    existing["confidence"] = "HIGH"
                if item.get("import_resolution"):
                    existing["import_resolution"] = item["import_resolution"]
'''

new = '''            if existing:
                modes = set(str(existing.get("detection_mode","")).split("+"))
                modes.update(str(item.get("detection_mode","")).split("+"))
                existing["detection_mode"] = "+".join(sorted(x for x in modes if x))

                # V11 canonical evidence enrichment.
                if item.get("confidence") == "HIGH":
                    existing["confidence"] = "HIGH"

                if item.get("import_resolution"):
                    existing["import_resolution"] = item["import_resolution"]

                # Merge provenance from all detection paths.
                existing_types = set(existing.get("evidence_type") or [])
                item_types = set(item.get("evidence_type") or [])
                existing["evidence_type"] = sorted(existing_types | item_types)

                # AST evidence upgrades the canonical confidence contract.
                if item.get("confidence_level") == "HIGH" or item.get("confidence") == "HIGH":
                    existing["confidence_level"] = "HIGH"
                elif not existing.get("confidence_level"):
                    existing["confidence_level"] = (
                        item.get("confidence_level")
                        or item.get("confidence")
                    )

                # Preserve deterministic canonical identity.
                if item.get("component_id"):
                    existing["component_id"] = item["component_id"]
'''

if old not in text:
    raise SystemExit(
        "EXPECTED ABOM MERGE BLOCK NOT FOUND. "
        "NO SOURCE CHANGE MADE."
    )

shutil.copy2(src, backup)

patched = text.replace(old, new, 1)
src.write_text(patched, encoding="utf-8")

print(f"[PASS] ABOM merge contract patched")
print(f"[BACKUP] {backup}")
