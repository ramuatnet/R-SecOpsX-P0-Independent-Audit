from pathlib import Path

p = Path(r".\scanner\aibom.py")
s = p.read_text(encoding="utf-8-sig").splitlines()

print("=" * 80)
print("CURRENT RECEIVER ASSOCIATION LOGIC")
print("=" * 80)

start = next(
    i for i, x in enumerate(s)
    if x.startswith("def _aibom_associate_model_calls")
)

end = next(
    (
        i for i in range(start + 1, len(s))
        if s[i].startswith("def ")
    ),
    len(s)
)

for i in range(start, min(end, start + 190)):
    print(f"{i+1}: {s[i]}")
