from pathlib import Path

s = Path(r".\scanner\aibom.py").read_text(encoding="utf-8-sig").splitlines()

print("=" * 80)
print("AIBOM MODEL FIELD MUTATIONS")
print("=" * 80)

patterns = (
    "model_usages",
    "model_value",
    "model_reference",
    "model_resolution",
    "model_source",
    "model_hint",
)

for i, x in enumerate(s):
    if any(p in x for p in patterns):
        print(f"{i+1}: {x}")
