from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import tempfile

from scanner.aibom import (
    _aibom_extract_model_calls,
    scan_file,
)

source = """from openai import OpenAI

client = OpenAI()

response1 = client.chat.completions.create(
    model="gpt-5",
    messages=[]
)

response2 = client.chat.completions.create(
    model="gpt-4.1",
    messages=[]
)
"""

print("=" * 80)
print("P0.5 MULTIPLE-MODEL ASSOCIATION DIAGNOSTIC")
print("=" * 80)

print("\n=== MODEL CALL EXTRACTION ===")
calls = _aibom_extract_model_calls(source)

for line, value in sorted(calls.items()):
    print(
        f"line={line} | "
        f"value={value.get('value')!r} | "
        f"reference={value.get('reference')!r} | "
        f"resolution={value.get('resolution')!r} | "
        f"source={value.get('source')!r}"
    )

with tempfile.TemporaryDirectory(prefix="aibom_p05_multi_") as td:
    path = Path(td) / "case.py"
    path.write_text(source, encoding="utf-8")

    print("\n=== FINAL FINDINGS ===")
    findings = scan_file(str(path))

    for i, item in enumerate(findings, 1):
        print(
            f"FINDING {i}: "
            f"line={item.get('line')} | "
            f"evidence={item.get('evidence')!r} | "
            f"model_hint={item.get('model_hint')!r} | "
            f"model_value={item.get('model_value')!r} | "
            f"model_reference={item.get('model_reference')!r} | "
            f"model_resolution={item.get('model_resolution')!r} | "
            f"model_source={item.get('model_source')!r} | "
            f"model_usages={item.get('model_usages')!r}"
        )

print("\n" + "=" * 80)
print("MULTIPLE-MODEL DIAGNOSTIC COMPLETE")
print("=" * 80)
