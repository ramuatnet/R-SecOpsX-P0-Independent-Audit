from pathlib import Path
from datetime import datetime
import re
import shutil

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "scanner" / "aibom.py"
BACKUP_DIR = ROOT / "backup"

source = TARGET.read_text(encoding="utf-8-sig")

if "_aibom_associate_model_calls" in source:
    print("[PASS] Model association helper already exists")
    raise SystemExit(0)

helper = r'''
# ---------------------------------------------------------------------------
# V11 AI-BOM P0.5 — MODEL FINDING ASSOCIATION
# ---------------------------------------------------------------------------

def _aibom_associate_model_calls(source, findings):
    """
    Associate AI component findings with model/deployment calls when the
    finding itself is not located on the model-call line.

    Association order:
      1. Exact finding line.
      2. Same receiver/object when statically identifiable.
      3. Nearest model call within a bounded local region.

    Ambiguous associations are intentionally not forced.
    """
    if not findings:
        return findings

    try:
        model_calls = _aibom_extract_model_calls(source)
    except Exception:
        return findings

    if not model_calls:
        return findings

    lines = source.splitlines()

    # ------------------------------------------------------------------
    # Build receiver -> model-call mapping.
    #
    # Example:
    #   response = client.chat.completions.create(
    #       model="gpt-5"
    #
    # receiver = client
    # ------------------------------------------------------------------
    receiver_calls = {}

    for line_no, resolution in model_calls.items():
        if not (1 <= line_no <= len(lines)):
            continue

        # Search backwards to the call expression.
        start = max(0, line_no - 6)
        context = "\n".join(lines[start:line_no])

        match = re.search(
            r'\b([A-Za-z_][A-Za-z0-9_]*)\s*(?:\.[A-Za-z_][A-Za-z0-9_]*)*\s*\(',
            context,
        )

        if match:
            receiver = match.group(1)
            receiver_calls.setdefault(receiver, []).append(
                (line_no, resolution)
            )

    for item in findings:
        if item.get("model_resolution"):
            continue

        finding_line = item.get("line")
        if not isinstance(finding_line, int):
            continue

        # --------------------------------------------------------------
        # 1. Exact line association.
        # --------------------------------------------------------------
        resolution = model_calls.get(finding_line)

        if resolution:
            item["model_value"] = resolution.get("value")
            item["model_reference"] = resolution.get("reference")
            item["model_resolution"] = resolution.get("resolution")
            item["model_source"] = resolution.get("source")

            if resolution.get("value"):
                item["model_hint"] = resolution["value"]

            continue

        # --------------------------------------------------------------
        # 2. Identify receiver from the finding line.
        #
        # Example:
        #   client = OpenAI()
        #
        # receiver = client
        # --------------------------------------------------------------
        if not (1 <= finding_line <= len(lines)):
            continue

        finding_text = lines[finding_line - 1]

        receiver_match = re.match(
            r'\s*([A-Za-z_][A-Za-z0-9_]*)\s*=',
            finding_text,
        )

        if not receiver_match:
            continue

        receiver = receiver_match.group(1)
        candidates = receiver_calls.get(receiver, [])

        if len(candidates) == 1:
            _, resolution = candidates[0]

            item["model_value"] = resolution.get("value")
            item["model_reference"] = resolution.get("reference")
            item["model_resolution"] = resolution.get("resolution")
            item["model_source"] = resolution.get("source")

            if resolution.get("value"):
                item["model_hint"] = resolution["value"]

            continue

        # --------------------------------------------------------------
        # 3. Controlled nearest-call fallback.
        #
        # Only use this when there is exactly one model call in a small
        # local window. Never guess between multiple model calls.
        # --------------------------------------------------------------
        nearby = []

        for call_line, resolution in model_calls.items():
            distance = abs(call_line - finding_line)

            if distance <= 12:
                nearby.append((distance, call_line, resolution))

        if len(nearby) == 1:
            _, _, resolution = nearby[0]

            item["model_value"] = resolution.get("value")
            item["model_reference"] = resolution.get("reference")
            item["model_resolution"] = resolution.get("resolution")
            item["model_source"] = resolution.get("source")

            if resolution.get("value"):
                item["model_hint"] = resolution["value"]

    return findings


# ---------------------------------------------------------------------------
# END V11 AI-BOM P0.5 MODEL ASSOCIATION
# ---------------------------------------------------------------------------
'''

# Insert helper immediately before _aibom_apply_model_resolution.
marker = "def _aibom_apply_model_resolution(path, source, findings):"

if marker not in source:
    print("[ERROR] Could not locate _aibom_apply_model_resolution().")
    raise SystemExit(1)

backup = BACKUP_DIR / (
    f"aibom.py.before_p05_association_"
    f"{datetime.now().strftime('%Y%m%d-%H%M%S')}.py"
)

BACKUP_DIR.mkdir(parents=True, exist_ok=True)
shutil.copy2(TARGET, backup)

source = source.replace(
    marker,
    helper + "\n\n" + marker,
    1,
)

# Add association immediately after model-resolution processing.
old = """    model_calls = _aibom_extract_model_calls(source)

    if not model_calls:
        return findings
"""

new = """    model_calls = _aibom_extract_model_calls(source)

    if not model_calls:
        return findings

    # P0.5: associate model calls with AI component findings that
    # originate from client construction/import lines.
    findings = _aibom_associate_model_calls(source, findings)
"""

if old not in source:
    print("[ERROR] Could not locate model-call initialization block.")
    raise SystemExit(1)

source = source.replace(old, new, 1)

TARGET.write_text(source, encoding="utf-8")

print("[PASS] Added model-call association helper")
print("[PASS] Exact-line association preserved")
print("[PASS] Receiver-based association added")
print("[PASS] Controlled nearest-call fallback added")
print("[PASS] Association invocation added")
print(f"[BACKUP] {backup}")
