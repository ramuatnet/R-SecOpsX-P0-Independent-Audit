from pathlib import Path
from tempfile import TemporaryDirectory
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scanner.aibom import scan_file


def scan(source: str):
    with TemporaryDirectory() as td:
        path = Path(td) / "model_resolution_case.py"
        path.write_text(source, encoding="utf-8")
        return scan_file(str(path))


def show(name, findings):
    print()
    print("=" * 80)
    print(name)
    print("=" * 80)

    print(f"COUNT = {len(findings)}")

    for item in findings:
        print(
            f"provider={item.get('provider')} | "
            f"component={item.get('component')} | "
            f"line={item.get('line')} | "
            f"model_hint={item.get('model_hint')!r} | "
            f"model_resolution={item.get('model_resolution')!r} | "
            f"model_source={item.get('model_source')!r}"
        )


CASES = {
    "literal_model": """
from openai import OpenAI
client = OpenAI()
client.chat.completions.create(model="gpt-5")
""",

    "constant_model": """
from openai import OpenAI
MODEL = "gpt-5"
client = OpenAI()
client.chat.completions.create(model=MODEL)
""",

    "variable_model": """
from openai import OpenAI
model_name = "gpt-5"
client = OpenAI()
client.chat.completions.create(model=model_name)
""",

    "deployment_literal": """
from openai import AzureOpenAI
client = AzureOpenAI()
client.chat.completions.create(model="my-gpt-deployment")
""",

    "environment_model": """
import os
from openai import OpenAI

MODEL = os.getenv("OPENAI_MODEL")
client = OpenAI()
client.chat.completions.create(model=MODEL)
""",

    "unrelated_model_variable": """
model = "this_is_not_an_ai_call"
value = model
print(value)
""",

    "unknown_model_variable": """
from openai import OpenAI

model_name = get_model_name()
client = OpenAI()
client.chat.completions.create(model=model_name)
""",

    "multiple_models": """
from openai import OpenAI

MODEL_A = "gpt-5"
MODEL_B = "gpt-4.1"

client = OpenAI()
client.chat.completions.create(model=MODEL_A)
client.chat.completions.create(model=MODEL_B)
""",
}


def main():
    print("=" * 80)
    print("R-SECOPSX V11 AI-BOM P0.5 REAL MODEL EXTRACTION MATRIX")
    print("=" * 80)

    for name, source in CASES.items():
        findings = scan(source)
        show(name, findings)

    print()
    print("=" * 80)
    print("P0.5 DIAGNOSTIC COMPLETE")
    print("=" * 80)


if __name__ == "__main__":
    main()
