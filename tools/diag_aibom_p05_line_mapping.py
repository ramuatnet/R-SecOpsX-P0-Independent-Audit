from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scanner.aibom import (
    _aibom_extract_model_calls,
    scan_file,
)

CASES = {
    "literal_model": '''
from openai import OpenAI

client = OpenAI()
response = client.responses.create(
    model="gpt-5",
    input="hello",
)
''',

    "constant_model": '''
from openai import OpenAI

MODEL = "gpt-5"
client = OpenAI()
response = client.responses.create(
    model=MODEL,
    input="hello",
)
''',

    "variable_model": '''
from openai import OpenAI

MODEL = "gpt-5"
client = OpenAI()
response = client.responses.create(
    model=MODEL,
)
''',

    "environment_model": '''
import os
from openai import OpenAI

MODEL = os.getenv("OPENAI_MODEL")
client = OpenAI()
response = client.responses.create(
    model=MODEL,
)
''',
}

print("=" * 80)
print("R-SECOPSX V11 AI-BOM P0.5 LINE-MAPPING DIAGNOSTIC")
print("=" * 80)

for name, source in CASES.items():
    print("\n" + "=" * 80)
    print(name)
    print("=" * 80)

    print("\n--- SOURCE ---")
    for i, line in enumerate(source.splitlines(), 1):
        print(f"{i:3}: {line}")

    print("\n--- MODEL CALLS ---")
    model_calls = _aibom_extract_model_calls(source)

    for line, data in sorted(model_calls.items()):
        print(
            f"MODEL CALL LINE={line} | "
            f"value={data.get('value')!r} | "
            f"reference={data.get('reference')!r} | "
            f"resolution={data.get('resolution')!r} | "
            f"source={data.get('source')!r}"
        )

    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "case.py"
        path.write_text(source, encoding="utf-8")

        findings = scan_file(str(path))

        print("\n--- FINDINGS ---")
        for item in findings:
            print(
                f"FINDING LINE={item.get('line')} | "
                f"provider={item.get('provider')} | "
                f"component={item.get('component')} | "
                f"evidence={item.get('evidence')!r} | "
                f"model_hint={item.get('model_hint')!r} | "
                f"model_value={item.get('model_value')!r} | "
                f"model_reference={item.get('model_reference')!r} | "
                f"model_resolution={item.get('model_resolution')!r} | "
                f"model_source={item.get('model_source')!r}"
            )

        print("\n--- LINE MATCH ANALYSIS ---")
        for item in findings:
            line = item.get("line")
            if line in model_calls:
                print(
                    f"LINE {line}: EXACT MATCH -> "
                    f"{model_calls[line]}"
                )
            else:
                print(
                    f"LINE {line}: NO EXACT MATCH | "
                    f"available model lines={sorted(model_calls)}"
                )

print("\n" + "=" * 80)
print("P0.5 LINE-MAPPING DIAGNOSTIC COMPLETE")
print("=" * 80)
