from pathlib import Path

s = Path(r".\scanner\aibom.py").read_text(encoding="utf-8-sig").splitlines()

print("=" * 80)
print("AIBOM ASSOCIATION CALL SITES")
print("=" * 80)

for i, x in enumerate(s):
    if "_aibom_associate_model_calls(" in x:
        print(f"{i+1}: {x}")
