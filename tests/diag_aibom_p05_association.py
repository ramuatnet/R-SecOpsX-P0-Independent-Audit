from pathlib import Path
import sys
import tempfile
import ast

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scanner.aibom import (
    _aibom_extract_model_calls,
    scan_file,
)


SOURCE = '''
from openai import OpenAI

client = OpenAI()

response = client.chat.completions.create(
    model="gpt-5",
    messages=[]
)
'''


print("=" * 80)
print("R-SECOPSX V11 AI-BOM P0.5 ASSOCIATION DIAGNOSTIC")
print("=" * 80)

with tempfile.TemporaryDirectory(prefix="aibom_p05_assoc_") as td:
    path = Path(td) / "case.py"
    path.write_text(SOURCE, encoding="utf-8")

    print("\n=== SOURCE ===")
    for i, line in enumerate(SOURCE.splitlines(), 1):
        print(f"{i:02d}: {line}")

    print("\n=== MODEL CALL EXTRACTOR ===")
    model_calls = _aibom_extract_model_calls(SOURCE)

    for line_no, data in model_calls.items():
        print(
            "line=",
            line_no,
            "| value=",
            repr(data.get("value")),
            "| reference=",
            repr(data.get("reference")),
            "| resolution=",
            repr(data.get("resolution")),
            "| source=",
            repr(data.get("source")),
        )

    print("\n=== FINAL SCAN FINDINGS ===")
    findings = scan_file(str(path))

    for item in findings:
        print(
            "line=",
            item.get("line"),
            "| evidence=",
            repr(item.get("evidence")),
            "| model_hint=",
            repr(item.get("model_hint")),
            "| model_value=",
            repr(item.get("model_value")),
            "| model_reference=",
            repr(item.get("model_reference")),
            "| model_resolution=",
            repr(item.get("model_resolution")),
            "| model_source=",
            repr(item.get("model_source")),
        )

print("\n" + "=" * 80)
print("P0.5 ASSOCIATION DIAGNOSTIC COMPLETE")
print("=" * 80)
