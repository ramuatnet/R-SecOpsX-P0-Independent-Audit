import ast

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

print("=" * 80)
print("P0.5 AST RECEIVER DIAGNOSTIC")
print("=" * 80)

for node in ast.walk(tree):
    if not isinstance(node, ast.Call):
        continue

    model_kw = next(
        (kw for kw in node.keywords if kw.arg == "model"),
        None,
    )

    if model_kw is None:
        continue

    print()
    print("MODEL CALL LINE:", node.lineno)
    print("MODEL:", ast.literal_eval(model_kw.value))

    print("\nCALL FUNC AST:")
    print(ast.dump(node.func, indent=2))

    root = node.func
    while isinstance(root, ast.Attribute):
        root = root.value

    print("\nROOT NODE:")
    print(ast.dump(root, indent=2))

    if isinstance(root, ast.Name):
        print("AST RECEIVER:", root.id)
    else:
        print("AST RECEIVER: <not statically identifiable>")

print()
print("=" * 80)
print("EXPECTED")
print("=" * 80)
print("gpt-5   -> client")
print("gpt-4.1 -> client")
