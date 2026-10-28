from pathlib import Path
from datetime import datetime
import shutil

root = Path(r"D:\Data\Code test\R-SecOpsX_V11")
src = root / "scanner" / "abom.py"
backup_dir = root / "backup"

backup_dir.mkdir(parents=True, exist_ok=True)

stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
backup = backup_dir / f"abom.py.before_make_item_canonical_contract_{stamp}.py"

text = src.read_text(encoding="utf-8-sig")

old = '''def _make_item(rule, filepath, line, evidence, tools, memory, human_approval, asset_scope,
               detection_mode="REGEX", import_resolution=None, confidence="MEDIUM"):
    item = {
        "bom_type":"ABOM",
        "framework":rule["framework"],
        "component":rule["component"],
        "category":rule["category"],
        "file":filepath,
        "line":line,
        "evidence":evidence.strip(),
        "tools_detected":tools,
        "memory_detected":memory,
        "human_approval_detected":human_approval,
        "asset_scope":asset_scope,
        "validation_only":asset_scope == "validation",
        "risk":rule["risk"],
        "recommendation":"Review agent permissions, tool execution boundaries, memory usage, and human approval controls.",
        "detection_mode":detection_mode,
        "confidence":confidence,
    }
    if import_resolution:
        item["import_resolution"] = import_resolution
    return item
'''

new = '''def _make_item(rule, filepath, line, evidence, tools, memory, human_approval, asset_scope,
               detection_mode="REGEX", import_resolution=None, confidence="MEDIUM",
               evidence_type=None):
    evidence_type = list(evidence_type or [])

    item = {
        "bom_type":"ABOM",
        "framework":rule["framework"],
        "component":rule["component"],
        "category":rule["category"],
        "file":filepath,
        "line":line,
        "evidence":evidence.strip(),
        "tools_detected":tools,
        "memory_detected":memory,
        "human_approval_detected":human_approval,
        "asset_scope":asset_scope,
        "validation_only":asset_scope == "validation",
        "risk":rule["risk"],
        "recommendation":"Review agent permissions, tool execution boundaries, memory usage, and human approval controls.",
        "detection_mode":detection_mode,
        "confidence":confidence,

        # V11 canonical ABOM contract.
        "component_id": _component_id(
            rule["framework"],
            rule["component"],
            filepath,
            line,
        ),
        "evidence_type": sorted(set(evidence_type)),
        "confidence_level": confidence,
    }

    if import_resolution:
        item["import_resolution"] = import_resolution

    return item
'''

if old not in text:
    raise SystemExit(
        "EXPECTED _make_item BLOCK NOT FOUND. "
        "NO SOURCE CHANGE MADE."
    )

shutil.copy2(src, backup)
src.write_text(text.replace(old, new, 1), encoding="utf-8")

print("[PASS] Production _make_item canonical contract patched")
print(f"[BACKUP] {backup}")
