from pathlib import Path
import ast
import re

source = """
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

tree = ast.parse(source)
lines = source.splitlines()

print("=" * 80)
print("P0.5 RECEIVER / MULTIPLE-MODEL ASSOCIATION DIAGNOSTIC")
print("=" * 80)

print("\n=== CALL NODES ===")

for node in ast.walk(tree):
    if not isinstance(node, ast.Call):
        continue

    model_kw = next(
        (kw for kw in node.keywords if kw.arg == "model"),
        None
    )

    if model_kw is None:
        continue

    print(
        "model_line=", node.lineno,
        "| model=",
        ast.literal_eval(model_kw.value)
        if isinstance(model_kw.value, ast.Constant)
        else ast.dump(model_kw.value)
    )

    start = max(0, node.lineno - 6)
    context = "\n".join(lines[start:node.lineno])

    match = re.search(
        r'\b([A-Za-z_][A-Za-z0-9_]*)\s*(?:\.[A-Za-z_][A-Za-z0-9_]*)*\s*\(',
        context,
    )

    print(
        "receiver_match=",
        repr(match.group(1) if match else None)
    )
    print("context:")
    print(context)
    print("-" * 80)

print("\n=== EXPECTED CONTRACT ===")
print("receiver = client")
print("model usages = gpt-5 + gpt-4.1")
print("=" * 80)
