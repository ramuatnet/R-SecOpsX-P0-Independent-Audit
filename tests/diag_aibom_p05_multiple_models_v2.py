from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scanner.aibom import (
    _aibom_extract_model_calls,
    _aibom_associate_model_calls,
    scan_file,
)

SOURCE = """
from openai import OpenAI

client = OpenAI()

a = client.chat.completions.create(
    model="gpt-5",
    messages=[]
)

b = client.chat.completions.create(
    model="gpt-4.1",
    messages=[]
)
"""

print("=" * 80)
print("P0.5 MULTIPLE MODEL DATA-FLOW DIAGNOSTIC")
print("=" * 80)

print("\n=== EXTRACTOR OUTPUT ===")
calls = _aibom_extract_model_calls(SOURCE)

for line, value in sorted(calls.items()):
    print(
        "line=", line,
        "| value=", repr(value.get("value")),
        "| reference=", repr(value.get("reference")),
        "| resolution=", repr(value.get("resolution")),
        "| source=", repr(value.get("source")),
    )

print("\n=== RAW FINDINGS ===")
raw = scan_file(
    str(
        Path(__file__).resolve().parent / "_p05_tmp_multiple_models.py"
    )
) if False else None

# Reproduce the provider findings through the normal scan path.
tmp = PROJECT_ROOT / "tests" / "_p05_tmp_multiple_models.py"
tmp.write_text(SOURCE, encoding="utf-8")

try:
    # Import internal scanning path indirectly by using scan_file.
    findings = scan_file(str(tmp))

    print("COUNT =", len(findings))

    for i, item in enumerate(findings, 1):
        print(
            f"FINDING {i}:",
            "line=", item.get("line"),
            "| evidence=", repr(item.get("evidence")),
            "| model_hint=", repr(item.get("model_hint")),
            "| model_value=", repr(item.get("model_value")),
            "| model_reference=", repr(item.get("model_reference")),
            "| model_resolution=", repr(item.get("model_resolution")),
            "| model_source=", repr(item.get("model_source")),
            "| model_usages=", repr(item.get("model_usages")),
        )
finally:
    try:
        tmp.unlink()
    except OSError:
        pass

print("\n" + "=" * 80)
print("DIAGNOSTIC COMPLETE")
print("=" * 80)
