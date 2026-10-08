from pathlib import Path

p = Path(r".\tests\test_v11_aibom_p05_end_to_end.py")
s = p.read_text(encoding="utf-8-sig")

old = '''        elif name == "environment":
            ok = any(
                x.get("model_reference") == "MODEL"
                and x.get("model_resolution") == "PARTIAL"
                and x.get("model_source") == "ENVIRONMENT_VARIABLE"
                for x in model_items
            )

        elif name == "unknown":
'''

new = '''        elif name == "environment":
            ok = any(
                x.get("model_reference") == "OPENAI_MODEL"
                and x.get("model_value") is None
                and x.get("model_resolution") == "PARTIAL"
                and x.get("model_source") == "ENVIRONMENT_VARIABLE"
                for x in model_items
            )

        elif name == "unknown":
'''

if old not in s:
    raise SystemExit("[ERROR] Environment assertion block not found.")

s = s.replace(old, new)

old = '''        elif name == "multiple_models":
            values = {
                x.get("model_value")
                for x in model_items
                if x.get("model_value")
            }
            ok = {"gpt-5", "gpt-4.1"}.issubset(values)

        elif name == "non_model_call":
            ok = not any(
                x.get("model_resolution") is not None
                for x in model_items
            )
'''

new = '''        elif name == "multiple_models":
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
            )

        elif name == "non_model_call":
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
            )
'''

if old not in s:
    raise SystemExit("[ERROR] Multiple/non-model assertion block not found.")

s = s.replace(old, new)

p.write_text(s, encoding="utf-8")
print("[PASS] Updated environment assertion")
print("[PASS] Updated multiple-model usage assertion")
print("[PASS] Updated embedding usage assertion")
