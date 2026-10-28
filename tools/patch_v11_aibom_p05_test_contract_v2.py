from pathlib import Path

p = Path(r".\tests\test_v11_aibom_p05_end_to_end.py")
lines = p.read_text(encoding="utf-8-sig").splitlines()

def replace_block(lines, marker, replacement):
    start = next(
        (i for i, line in enumerate(lines) if line.strip() == marker),
        None
    )

    if start is None:
        raise RuntimeError(f"Could not find: {marker}")

    end = start + 1

    while end < len(lines):
        stripped = lines[end].strip()

        if stripped.startswith("elif name ==") or stripped.startswith("else:"):
            break

        end += 1

    return lines[:start] + replacement.splitlines() + lines[end:]


# ------------------------------------------------------------------
# ENVIRONMENT
# ------------------------------------------------------------------

lines = replace_block(
    lines,
    'elif name == "environment":',
    '''        elif name == "environment":
            ok = any(
                x.get("model_reference") == "OPENAI_MODEL"
                and x.get("model_value") is None
                and x.get("model_resolution") == "PARTIAL"
                and x.get("model_source") == "ENVIRONMENT_VARIABLE"
                for x in model_items
            )'''
)


# ------------------------------------------------------------------
# MULTIPLE MODELS
# ------------------------------------------------------------------

lines = replace_block(
    lines,
    'elif name == "multiple_models":',
    '''        elif name == "multiple_models":
            usages = []

            for x in findings:
                for usage in (x.get("model_usages") or []):
                    if usage.get("value"):
                        usages.append(usage)

            values = {
                usage.get("value")
                for usage in usages
                if usage.get("value")
            }

            ok = (
                {"gpt-5", "gpt-4.1"}.issubset(values)
                and all(
                    usage.get("resolution") == "RESOLVED"
                    for usage in usages
                    if usage.get("value") in {"gpt-5", "gpt-4.1"}
                )
            )'''
)


# ------------------------------------------------------------------
# EMBEDDING
# ------------------------------------------------------------------

lines = replace_block(
    lines,
    'elif name == "non_model_call":',
    '''        elif name == "non_model_call":
            embedding_usages = []

            for x in findings:
                for usage in (x.get("model_usages") or []):
                    if usage.get("usage_type") == "EMBEDDING":
                        embedding_usages.append(usage)

            ok = any(
                usage.get("value") == "text-embedding-3-small"
                and usage.get("resolution") == "RESOLVED"
                and usage.get("source") == "AST_LITERAL"
                and usage.get("usage_type") == "EMBEDDING"
                for usage in embedding_usages
            )'''
)

p.write_text("\n".join(lines) + "\n", encoding="utf-8")

print("[PASS] Environment assertion updated")
print("[PASS] Multiple-model assertion updated")
print("[PASS] Embedding assertion updated")
print("[PASS] Test contract rewritten structurally")
