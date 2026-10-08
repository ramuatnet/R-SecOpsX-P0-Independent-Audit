from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
from pathlib import Path
import tempfile
from scanner.aibom import _aibom_extract_model_calls

CASES = {
    "literal_model": '''
from openai import OpenAI
client = OpenAI()
response = client.responses.create(model="gpt-5", input="hello")
''',

    "constant_model": '''
from openai import OpenAI
MODEL = "gpt-5"
client = OpenAI()
response = client.responses.create(model=MODEL, input="hello")
''',

    "variable_model": '''
from openai import OpenAI
MODEL_NAME = "gpt-5"
MODEL = MODEL_NAME
client = OpenAI()
response = client.responses.create(model=MODEL, input="hello")
''',

    "deployment_literal": '''
from openai import OpenAI
from openai import AzureOpenAI
client = OpenAI()
response = client.responses.create(model="my-gpt-deployment", input="hello")
azure = AzureOpenAI()
response2 = azure.chat.completions.create(
    model="my-gpt-deployment",
    messages=[]
)
''',

    "environment_model": '''
import os
from openai import OpenAI
MODEL = os.getenv("OPENAI_MODEL")
client = OpenAI()
response = client.responses.create(model=MODEL, input="hello")
''',

    "unknown_model_variable": '''
from openai import OpenAI
MODEL = get_model()
client = OpenAI()
response = client.responses.create(model=MODEL, input="hello")
''',

    "multiple_models": '''
from openai import OpenAI
MODEL_A = "gpt-5"
MODEL_B = "gpt-4.1"
client = OpenAI()
response1 = client.responses.create(model=MODEL_A, input="hello")
response2 = client.responses.create(model=MODEL_B, input="hello")
''',
}

print("=" * 80)
print("R-SECOPSX V11 AI-BOM P0.5 MODEL-CALL INTERNAL DIAGNOSTIC")
print("=" * 80)

for name, source in CASES.items():
    print("\n" + "=" * 80)
    print(name)

    results = _aibom_extract_model_calls(source)

    print("MODEL CALLS =", results)

    if not results:
        print("[FAIL] No model calls extracted")
        continue

    for line, resolution in sorted(results.items()):
        print(
            f"line={line} | "
            f"value={resolution.get('value')!r} | "
            f"reference={resolution.get('reference')!r} | "
            f"resolution={resolution.get('resolution')!r} | "
            f"source={resolution.get('source')!r}"
        )

print("\n" + "=" * 80)
print("P0.5 INTERNAL DIAGNOSTIC COMPLETE")
print("=" * 80)

