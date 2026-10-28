from pathlib import Path

path = Path("scanner") / "aibom_abom_correlation.py"

text = path.read_text(encoding="utf-8-sig")

# The semantic-hardening patch will be applied here.
# For now, verify the target file is readable and contains the expected
# AGENT -> MODEL correlation block.

required = [
    "def correlate(",
    "# AGENT -> MODEL",
    "for agent in agents:",
    "model.get(\"model_resolution\")",
    "return _deduplicate(relationships)",
]

missing = [item for item in required if item not in text]

if missing:
    raise SystemExit(
        "[FAIL] Expected correlation implementation markers missing:\n"
        + "\n".join(f"  - {item}" for item in missing)
    )

backup = path.with_name(path.name + ".bak_before_semantic_v3")

if not backup.exists():
    backup.write_text(text, encoding="utf-8")

print("[PASS] Correlation module located")
print(f"[PASS] Backup: {backup}")
print("[PASS] Expected semantic-linkage block verified")
