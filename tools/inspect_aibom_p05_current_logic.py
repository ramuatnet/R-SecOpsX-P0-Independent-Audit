from pathlib import Path

s = Path(r".\scanner\aibom.py").read_text(encoding="utf-8-sig").splitlines()

print("=" * 80)
print("CURRENT AIBOM ASSOCIATION HELPER — FULL")
print("=" * 80)

for start, end in [(1078, 1165), (1257, 1300)]:
    print()
    print(f"--- LINES {start}-{end} ---")
    print()
    for i in range(start - 1, min(end, len(s))):
        print(f"{i+1}: {s[i]}")
