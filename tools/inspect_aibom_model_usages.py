from pathlib import Path

s = Path(r".\scanner\aibom.py").read_text(encoding="utf-8-sig").splitlines()

print("=" * 80)
print("MODEL_USAGES REFERENCES")
print("=" * 80)

for i, x in enumerate(s):
    if "model_usages" in x:
        print(f"{i+1}: {x}")
