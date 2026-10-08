from pathlib import Path
from datetime import datetime
import shutil
import re

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "scanner" / "abom.py"
BACKUP_DIR = ROOT / "backup"

BACKUP_DIR.mkdir(parents=True, exist_ok=True)

stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
backup = BACKUP_DIR / f"abom.py.before_v2_contract_{stamp}.py"

shutil.copy2(TARGET, backup)
print(f"[PASS] Backup: {backup}")

s = TARGET.read_text(encoding="utf-8-sig")

# ------------------------------------------------------------
# 1. hashlib import
# ------------------------------------------------------------
if "import hashlib" not in s:
    import_marker = "import ast\n"
    if import_marker not in s:
        shutil.copy2(backup, TARGET)
        raise RuntimeError("Could not locate import section.")
    s = s.replace(
        import_marker,
        import_marker + "import hashlib\n",
        1,
    )

# ------------------------------------------------------------
# 2. Canonical component_id helper
# ------------------------------------------------------------
if "def _component_id(" not in s:
    marker = "def _make_item("
    pos = s.find(marker)

    if pos < 0:
        shutil.copy2(backup, TARGET)
        raise RuntimeError("Could not locate _make_item().")

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

    s = s[:pos] + helper + s[pos:]

# ------------------------------------------------------------
# 3. Replace _make_item signature
# ------------------------------------------------------------
old_sig = '''def _make_item(rule, filepath, line, evidence, tools, memory, human_approval, asset_scope,
               detection_mode="REGEX", import_resolution=None, confidence="MEDIUM"):'''

new_sig = '''def _make_item(rule, filepath, line, evidence, tools, memory, human_approval, asset_scope,
               detection_mode="REGEX", import_resolution=None, confidence="MEDIUM",
               evidence_type=None):'''

if old_sig in s:
    s = s.replace(old_sig, new_sig, 1)

elif "def _make_item(rule, filepath, line, evidence, tools, memory, human_approval, asset_scope," not in s:
    shutil.copy2(backup, TARGET)
    raise RuntimeError("Unexpected _make_item() signature; V2 contract patch aborted.")

# ------------------------------------------------------------
# 4. Add canonical enrichment to item
# ------------------------------------------------------------
old_item = '''        "detection_mode":detection_mode,
        "confidence":confidence,
    }'''

new_item = '''        "detection_mode":detection_mode,
        "confidence":confidence,
        "component_id": _component_id(
            rule["framework"],
            rule["component"],
            filepath,
            line,
        ),
        "evidence_type": sorted(
            set(evidence_type or [])
        ),
        "confidence_level": confidence,
    }'''

if old_item in s:
    s = s.replace(old_item, new_item, 1)
elif '"component_id": _component_id(' not in s:
    shutil.copy2(backup, TARGET)
    raise RuntimeError("Could not locate production _make_item() payload.")

# ------------------------------------------------------------
# 5. Regex call: evidence_type=["REGEX"]
# ------------------------------------------------------------
regex_anchor = '''                                           "REGEX","", "HIGH" if rule["framework"] != "CrewAI" else "MEDIUM"))'''

regex_replacement = '''                                           "REGEX","", "HIGH" if rule["framework"] != "CrewAI" else "MEDIUM",
                                           ["REGEX"]))'''

if regex_anchor in s:
    s = s.replace(regex_anchor, regex_replacement, 1)
elif '["REGEX"]))' not in s:
    shutil.copy2(backup, TARGET)
    raise RuntimeError("Could not locate production regex _make_item() call.")

# ------------------------------------------------------------
# 6. AST call: evidence_type=["AST", "IMPORT_RESOLUTION"]
# ------------------------------------------------------------
ast_anchor = '''                                  asset_scope,"AST+IMPORT_RESOLUTION",resolution,"HIGH"))'''

ast_replacement = '''                                  asset_scope,"AST+IMPORT_RESOLUTION",resolution,"HIGH",
                                  ["AST", "IMPORT_RESOLUTION"]))'''

if ast_anchor in s:
    s = s.replace(ast_anchor, ast_replacement, 1)
elif '["AST", "IMPORT_RESOLUTION"]))' not in s:
    shutil.copy2(backup, TARGET)
    raise RuntimeError("Could not locate production AST _make_item() call.")

TARGET.write_text(s, encoding="utf-8")

print("[PASS] Production ABOM V2 contract applied")
print(f"[PASS] Written: {TARGET}")
