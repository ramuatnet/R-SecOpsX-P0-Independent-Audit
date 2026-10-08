from pathlib import Path
import ast

PROJECT_ROOT = Path(__file__).resolve().parents[1]
path = PROJECT_ROOT / "tests" / "test_v11_aibom_abom_correlation_contract.py"

text = path.read_text(encoding="utf-8-sig")
tree = ast.parse(text, filename=str(path))

print("=" * 80)
print("AI-BOM <-> ABOM SEMANTIC LINKAGE INSPECTION")
print("=" * 80)
print(f"FILE: {path}")
print()

keys = set()
dict_keys = set()

for node in ast.walk(tree):

    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        value = node.value

        if any(token in value.lower() for token in (
            "model",
            "agent",
            "component",
            "provider",
            "reference",
            "evidence",
            "usage",
            "abom",
        )):
            keys.add(value)

    if isinstance(node, ast.Dict):
        for key in node.keys:
            if isinstance(key, ast.Constant) and isinstance(key.value, str):
                dict_keys.add(key.value)

print("--- STRING VALUES RELATED TO CORRELATION ---")

for value in sorted(keys):
    print(repr(value))

print()
print("--- DICT KEYS ---")

for key in sorted(dict_keys):
    if any(token in key.lower() for token in (
        "model",
        "agent",
        "component",
        "provider",
        "reference",
        "evidence",
        "usage",
        "abom",
    )):
        print(repr(key))

print()
print("=" * 80)
print("INSPECTION COMPLETE")
print("=" * 80)
