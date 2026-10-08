from pathlib import Path
import sys
import tempfile

# Ensure project root is importable when this test is executed directly.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scanner.aibom import scan_file


def scan(source):
    with tempfile.TemporaryDirectory(prefix="aibom_p05_e2e_") as td:
        path = Path(td) / "case.py"
        path.write_text(source, encoding="utf-8")
        return scan_file(str(path))


CASES = {
    "literal": '''
from openai import OpenAI

client = OpenAI()
response = client.chat.completions.create(
    model="gpt-5",
    messages=[]
)
''',

    "constant": '''
from openai import OpenAI

MODEL = "gpt-5"
client = OpenAI()
response = client.chat.completions.create(
    model=MODEL,
    messages=[]
)
''',

    "variable": '''
from openai import OpenAI

MODEL = "gpt-5"
selected_model = MODEL

client = OpenAI()
response = client.chat.completions.create(
    model=selected_model,
    messages=[]
)
''',

    "environment": '''
import os
from openai import OpenAI

MODEL = os.getenv("OPENAI_MODEL")
client = OpenAI()
response = client.chat.completions.create(
    model=MODEL,
    messages=[]
)
''',

    "unknown": '''
from openai import OpenAI

MODEL = get_model_from_runtime()

client = OpenAI()
response = client.chat.completions.create(
    model=MODEL,
    messages=[]
)
''',

    "multiple_models": '''
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
''',

    "non_model_call": '''
from openai import OpenAI

client = OpenAI()
client.embeddings.create(
    input="hello",
    model="text-embedding-3-small"
)
''',
}


def main():
    print("=" * 80)
    print("R-SECOPSX V11 AI-BOM P0.5 END-TO-END MODEL RESOLUTION CONTRACT")
    print("=" * 80)

    failures = 0

    for name, source in CASES.items():
        print("\n" + "=" * 80)
        print(name)
        print("=" * 80)

        findings = scan(source)

        print("COUNT =", len(findings))

        for item in findings:
            print(
                "line=", item.get("line"),
                "| component=", item.get("component"),
                "| model_hint=", repr(item.get("model_hint")),
                "| model_value=", repr(item.get("model_value")),
                "| model_reference=", repr(item.get("model_reference")),
                "| model_resolution=", repr(item.get("model_resolution")),
                "| model_source=", repr(item.get("model_source")),
                "| evidence_type=", item.get("evidence_type"),
                "| confidence=", item.get("confidence"),
                "| confidence_score=", item.get("confidence_score"),
                "| detection_mode=", item.get("detection_mode"),
            )

        model_items = [
            x for x in findings
            if x.get("model_resolution") is not None
        ]

        if name == "literal":
            ok = any(
                x.get("model_value") == "gpt-5"
                and x.get("model_resolution") == "RESOLVED"
                and x.get("model_source") in ("AST_LITERAL", "AST_CONSTANT")
                for x in model_items
            )

        elif name == "constant":
            ok = any(
                x.get("model_value") == "gpt-5"
                and x.get("model_resolution") == "RESOLVED"
                for x in model_items
            )

        elif name == "variable":
            ok = any(
                x.get("model_value") == "gpt-5"
                and x.get("model_reference") == "selected_model"
                and x.get("model_resolution") == "RESOLVED"
                for x in model_items
            )

        elif name == "environment":
            ok = any(
                x.get("model_reference") == "OPENAI_MODEL"
                and x.get("model_value") is None
                and x.get("model_resolution") == "PARTIAL"
                and x.get("model_source") == "ENVIRONMENT_VARIABLE"
                for x in model_items
            )
        elif name == "unknown":
            ok = any(
                x.get("model_resolution") == "UNKNOWN"
                for x in model_items
            )

        elif name == "multiple_models":
            usages = []

            for x in findings:
                for usage in (x.get("model_usages") or []):
                    if usage.get("value"):
                        usages.append(usage)

            values = {
                usage.get("value")
                for usage in usages
                if usage.get("value")
            }

            ok = (
                {"gpt-5", "gpt-4.1"}.issubset(values)
                and all(
                    usage.get("resolution") == "RESOLVED"
                    for usage in usages
                    if usage.get("value") in {"gpt-5", "gpt-4.1"}
                )
            )
        elif name == "non_model_call":
            embedding_usages = []

            for x in findings:
                for usage in (x.get("model_usages") or []):
                    if usage.get("usage_type") == "EMBEDDING":
                        embedding_usages.append(usage)

            ok = any(
                usage.get("value") == "text-embedding-3-small"
                and usage.get("resolution") == "RESOLVED"
                and usage.get("source") == "AST_LITERAL"
                and usage.get("usage_type") == "EMBEDDING"
                for usage in embedding_usages
            )
        else:
            ok = False

        print("[PASS]" if ok else "[FAIL]", name)

        if not ok:
            failures += 1

    print("\n" + "=" * 80)

    if failures:
        print(f"P0.5 END-TO-END FAILED: {failures} case(s)")
        raise SystemExit(1)

    print("AIBOM_P0_5_END_TO_END_ACCEPTED")
    print("=" * 80)


if __name__ == "__main__":
    main()
