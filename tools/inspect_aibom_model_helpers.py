from pathlib import Path

s = Path(r".\scanner\aibom.py").read_text(encoding="utf-8-sig").splitlines()

for name in [
    "def _aibom_associate_model_calls",
    "def _aibom_classify_model_usage",
    "def _aibom_extract_model_calls",
]:
    print("=" * 80)
    print(name)
    print("=" * 80)

    try:
        start = next(i for i, x in enumerate(s) if x.startswith(name))
    except StopIteration:
        print("NOT FOUND")
        continue

    end = len(s)
    for i in range(start + 1, len(s)):
        if s[i].startswith("def ") and not s[i].startswith(name):
            end = i
            break

    print("\n".join(f"{i+1}: {s[i]}" for i in range(start, end)))
