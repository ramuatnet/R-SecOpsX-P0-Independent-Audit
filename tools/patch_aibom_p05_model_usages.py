from pathlib import Path
from datetime import datetime
import ast
import shutil

ROOT = Path(r".")
TARGET = ROOT / "scanner" / "aibom.py"
BACKUP_DIR = ROOT / "backup"

if not TARGET.exists():
    raise SystemExit(f"[ERROR] Missing target: {TARGET}")

source = TARGET.read_text(encoding="utf-8-sig")

timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
BACKUP_DIR.mkdir(parents=True, exist_ok=True)
backup = BACKUP_DIR / f"aibom.py.before_p05_model_usages_{timestamp}.py"
shutil.copy2(TARGET, backup)

# ---------------------------------------------------------------------------
# 1. Replace model-call extractor so each call carries usage classification.
# ---------------------------------------------------------------------------

old = '''            resolution = _aibom_resolve_model_value(
                keyword.value,
                symbols,
            )

            results[node.lineno] = resolution
'''

new = '''            resolution = _aibom_resolve_model_value(
                keyword.value,
                symbols,
            )

            # P0.5: retain the model resolution while classifying the
            # semantic model usage represented by the call.
            usage_type = "MODEL"

            if isinstance(node.func, ast.Attribute):
                call_root = node.func
                attribute_chain = []

                while isinstance(call_root, ast.Attribute):
                    attribute_chain.append(call_root.attr)
                    call_root = call_root.value

                chain = list(reversed(attribute_chain))
                chain_text = ".".join(chain).lower()

                if "embedding" in chain_text:
                    usage_type = "EMBEDDING"
                elif (
                    "chat" in chain_text
                    or "completion" in chain_text
                    or "responses" in chain_text
                ):
                    usage_type = "GENERATION"

            resolution = dict(resolution)
            resolution["usage_type"] = usage_type

            results[node.lineno] = resolution
'''

if old not in source:
    raise SystemExit(
        "[ERROR] Could not locate model extractor resolution block. "
        "No production patch applied."
    )

source = source.replace(old, new, 1)
print("[PASS] Added semantic model usage classification")


# ---------------------------------------------------------------------------
# 2. Replace association helper.
# ---------------------------------------------------------------------------

start_marker = "def _aibom_associate_model_calls(source, findings):"
end_marker = "# END V11 AI-BOM P0.5 MODEL ASSOCIATION"

start = source.find(start_marker)
if start < 0:
    raise SystemExit("[ERROR] Association helper not found.")

end = source.find(end_marker, start)
if end < 0:
    raise SystemExit("[ERROR] Association helper end marker not found.")

# Include the marker line in replacement boundary.
end_line = source.find("\n", end)
if end_line < 0:
    end_line = len(source)
else:
    end_line += 1

helper = r'''def _aibom_associate_model_calls(source, findings):
    """
    Associate AI component findings with one or more model/deployment calls.

    P0.5 contract:

      * Exact model-call line association.
      * Receiver-based association.
      * Multiple model calls are preserved in model_usages.
      * A single model_value remains available for compatibility.
      * Embedding usage is explicitly classified.
      * Ambiguous nearest-call association is not forced.
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

    def _apply_usage(item, resolution):
        if not resolution:
            return

        usage = {
            "value": resolution.get("value"),
            "reference": resolution.get("reference"),
            "resolution": resolution.get("resolution"),
            "source": resolution.get("source"),
            "usage_type": resolution.get("usage_type", "MODEL"),
        }

        existing = item.get("model_usages")

        if not isinstance(existing, list):
            existing = []

        # Deduplicate structurally.
        if usage not in existing:
            existing.append(usage)

        # Stable deterministic ordering.
        existing.sort(
            key=lambda x: (
                str(x.get("usage_type") or ""),
                str(x.get("value") or ""),
                str(x.get("reference") or ""),
            )
        )

        item["model_usages"] = existing

        # Preserve the existing scalar contract.
        #
        # Prefer a resolved concrete model. If multiple concrete models
        # exist, use the first deterministic value while retaining every
        # usage in model_usages.
        concrete = [
            x for x in existing
            if x.get("value") is not None
        ]

        selected = concrete[0] if concrete else existing[0]

        item["model_value"] = selected.get("value")
        item["model_reference"] = selected.get("reference")
        item["model_resolution"] = selected.get("resolution")
        item["model_source"] = selected.get("source")
        item["model_usage_type"] = selected.get("usage_type")

        if selected.get("value"):
            item["model_hint"] = selected["value"]

    # ------------------------------------------------------------------
    # Build receiver -> ALL model calls.
    # ------------------------------------------------------------------
    receiver_calls = {}

    for line_no, resolution in model_calls.items():
        if not (1 <= line_no <= len(lines)):
            continue

        start_line = max(0, line_no - 8)
        context = "\n".join(lines[start_line:line_no])

        match = re.search(
            r'\b([A-Za-z_][A-Za-z0-9_]*)\s*(?:\.[A-Za-z_][A-Za-z0-9_]*)*\s*\(',
            context,
        )

        if match:
            receiver = match.group(1)

            receiver_calls.setdefault(receiver, []).append(
                (line_no, resolution)
            )

    # ------------------------------------------------------------------
    # Associate findings.
    # ------------------------------------------------------------------
    for item in findings:

        finding_line = item.get("line")

        if not isinstance(finding_line, int):
            continue

        # --------------------------------------------------------------
        # 1. Exact-line association.
        # --------------------------------------------------------------
        resolution = model_calls.get(finding_line)

        if resolution:
            _apply_usage(item, resolution)
            continue

        if not (1 <= finding_line <= len(lines)):
            continue

        finding_text = lines[finding_line - 1]

        # --------------------------------------------------------------
        # 2. Receiver association.
        #
        # Example:
        #   client = OpenAI()
        #
        # Multiple calls through the same client are intentionally retained.
        # --------------------------------------------------------------
        receiver_match = re.match(
            r'\s*([A-Za-z_][A-Za-z0-9_]*)\s*=',
            finding_text,
        )

        if receiver_match:
            receiver = receiver_match.group(1)
            candidates = receiver_calls.get(receiver, [])

            if candidates:
                for _, candidate_resolution in candidates:
                    _apply_usage(item, candidate_resolution)

                continue

        # --------------------------------------------------------------
        # 3. Controlled nearest-call fallback.
        #
        # Only associate when exactly one model call is in the bounded
        # local region.
        # --------------------------------------------------------------
        nearby = []

        for call_line, candidate_resolution in model_calls.items():
            distance = abs(call_line - finding_line)

            if distance <= 12:
                nearby.append(
                    (distance, call_line, candidate_resolution)
                )

        if len(nearby) == 1:
            _, _, candidate_resolution = nearby[0]
            _apply_usage(item, candidate_resolution)

    return findings


# ---------------------------------------------------------------------------
# END V11 AI-BOM P0.5 MODEL ASSOCIATION
# ---------------------------------------------------------------------------
'''

source = source[:start] + helper + source[end_line:]

TARGET.write_text(source, encoding="utf-8")

print("[PASS] Replaced P0.5 association helper")
print("[PASS] Multiple model usages preserved")
print("[PASS] Embedding usage classification added")
print(f"[BACKUP] {backup}")
