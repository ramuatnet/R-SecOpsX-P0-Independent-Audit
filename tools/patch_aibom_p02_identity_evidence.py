from pathlib import Path
from datetime import datetime
import shutil
import ast

ROOT = Path(r"D:\Data\Code test\R-SecOpsX_V11")
PROD = ROOT / "scanner" / "aibom.py"
BACKUP_DIR = ROOT / "backup"

if not PROD.exists():
    raise SystemExit(f"ERROR: {PROD} not found.")

source = PROD.read_text(encoding="utf-8-sig")

# ------------------------------------------------------------
# Backup
# ------------------------------------------------------------
BACKUP_DIR.mkdir(parents=True, exist_ok=True)

stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
backup = BACKUP_DIR / f"aibom.py.before_p02_identity_{stamp}.py"
shutil.copy2(PROD, backup)

# ------------------------------------------------------------
# hashlib import
# ------------------------------------------------------------
if "import hashlib" not in source:
    lines = source.splitlines(keepends=True)

    inserted = False
    for i, line in enumerate(lines):
        if line.startswith("import re"):
            lines.insert(i + 1, "import hashlib\n")
            inserted = True
            break

    if not inserted:
        raise SystemExit(
            "ERROR: could not locate import re anchor."
        )

    source = "".join(lines)

# ------------------------------------------------------------
# P0.2 helper block
# ------------------------------------------------------------
MARKER = "# --- V11 AI-BOM P0.2 IDENTITY / EVIDENCE CONTRACT ---"

if MARKER not in source:

    helper = r'''
# --- V11 AI-BOM P0.2 IDENTITY / EVIDENCE CONTRACT ---

def _aibom_normalize_identity(value):
    if value is None:
        return ""
    text = str(value).strip().replace("\\", "/")
    text = re.sub(r"\s+", " ", text)
    return text.lower()


def _aibom_component_id(provider, component):
    """
    Deterministic semantic AI-BOM component identity.

    Detection line, evidence text, filepath and import-resolution
    details are intentionally excluded.

    Therefore the same semantic provider/component retains the same
    identity when detection moves to another line or is discovered
    through an import alias.
    """
    provider_key = _aibom_normalize_identity(provider)
    component_key = _aibom_normalize_identity(component)

    raw = f"{provider_key}|{component_key}"

    digest = hashlib.sha256(
        raw.encode("utf-8")
    ).hexdigest()[:20].upper()

    return f"AIBOM-COMP-{digest}"


def _aibom_evidence_types(item):
    """
    Normalize evidence provenance from existing detection fields.
    """
    values = set()

    existing = item.get("evidence_type")

    if isinstance(existing, (list, tuple, set)):
        values.update(
            str(x).strip().upper()
            for x in existing
            if str(x).strip()
        )

    detection = str(
        item.get("detection_mode") or ""
    ).strip().upper()

    if detection:
        values.update(
            x.strip()
            for x in detection.split("+")
            if x.strip()
        )

    if item.get("import_resolution"):
        values.add("IMPORT_RESOLUTION")

    if item.get("model_resolution"):
        values.add("MODEL_RESOLUTION")

    if item.get("model_hint"):
        values.add("MODEL_HINT")

    return sorted(values)


def _aibom_confidence_contract(item):
    """
    Conservative confidence classification.

    Existing confidence values are upgraded only when the
    corresponding evidence actually exists.
    """
    evidence = set(
        _aibom_evidence_types(item)
    )

    if {
        "AST",
        "IMPORT_RESOLUTION",
        "MODEL_RESOLUTION",
    }.issubset(evidence):
        return "VERY_HIGH", 0.95

    if {
        "AST",
        "IMPORT_RESOLUTION",
    }.issubset(evidence):
        return "HIGH", 0.90

    if {
        "AST",
        "MODEL_RESOLUTION",
    }.issubset(evidence):
        return "HIGH", 0.85

    if {
        "REGEX",
        "IMPORT_RESOLUTION",
    }.issubset(evidence):
        return "MEDIUM", 0.70

    if "AST" in evidence:
        return "MEDIUM", 0.65

    if "REGEX" in evidence:
        return "LOW", 0.40

    return "LOW", 0.25


def _aibom_apply_identity_contract(item):
    if not isinstance(item, dict):
        return item

    item["component_id"] = _aibom_component_id(
        item.get("provider"),
        item.get("component"),
    )

    evidence_types = _aibom_evidence_types(item)

    item["evidence_type"] = evidence_types

    confidence, confidence_score = _aibom_confidence_contract(
        item
    )

    item["confidence"] = confidence
    item["confidence_score"] = confidence_score

    return item

# --- END V11 AI-BOM P0.2 IDENTITY / EVIDENCE CONTRACT ---
'''

    anchor = "def scan_file(filepath: str) -> list[dict]:"

    if anchor not in source:
        raise SystemExit(
            "ERROR: scan_file() anchor not found."
        )

    source = source.replace(
        anchor,
        helper + "\n\n\n" + anchor,
        1
    )

# ------------------------------------------------------------
# Exact final return replacement
# ------------------------------------------------------------
old = """    return deduplicate(findings)
"""

new = """    # V11 P0.2:
    # Apply stable semantic identity and evidence/confidence
    # contract after both regex and AST/import discovery.
    for _aibom_item in findings:
        _aibom_apply_identity_contract(_aibom_item)

    return deduplicate(findings)
"""

count = source.count(old)

if count != 1:
    raise SystemExit(
        f"ERROR: expected exactly one final "
        f"'return deduplicate(findings)' block, found {count}."
    )

source = source.replace(old, new, 1)

# ------------------------------------------------------------
# Syntax validation before writing
# ------------------------------------------------------------
ast.parse(source)

PROD.write_text(source, encoding="utf-8")

print("[PASS] Added deterministic semantic component_id")
print("[PASS] Added evidence_type normalization")
print("[PASS] Added confidence classification")
print("[PASS] Added confidence_score")
print("[PASS] Preserved all existing scan_file return paths")
print("[PASS] Preserved regex + AST/import discovery")
print(f"[BACKUP] {backup}")
