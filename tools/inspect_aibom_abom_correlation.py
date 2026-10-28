from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
path = PROJECT_ROOT / "scanner" / "aibom_abom_correlation.py"

print("=" * 80)
print("AI-BOM <-> ABOM CORRELATION IMPLEMENTATION INSPECTION")
print("=" * 80)
print(f"FILE: {path}")
print()

if not path.exists():
    raise FileNotFoundError(f"Correlation module not found: {path}")

text = path.read_text(encoding="utf-8")
lines = text.splitlines()

print(f"LINES: {len(lines)}")
print()

keywords = (
    "def ",
    "class ",
    "MODEL",
    "PROVIDER",
    "APPLICATION",
    "AGENT",
    "USES",
    "CORRELATES",
    "relationship",
    "correlation",
    "semantic",
    "confidence",
    "evidence",
    "provenance",
    "dedup",
    "ambig",
)

print("--- RELEVANT IMPLEMENTATION LINES ---")

for line_no, line in enumerate(lines, 1):
    if any(keyword.lower() in line.lower() for keyword in keywords):
        print(f"{line_no:4}: {line}")

print()
print("=" * 80)
print("INSPECTION COMPLETE")
print("=" * 80)
