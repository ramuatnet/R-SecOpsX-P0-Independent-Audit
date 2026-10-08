from pathlib import Path
from datetime import datetime

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "scanner" / "aibom.py"
BACKUP_DIR = ROOT / "backup"

def fail(msg):
    print(f"[ERROR] {msg}")
    raise SystemExit(1)

text = TARGET.read_text(encoding="utf-8-sig")

if "_aibom_associate_model_calls" in text:
    fail("Association helper already exists; refusing duplicate patch.")

lines = text.splitlines(keepends=True)

# ------------------------------------------------------------------
# Locate _aibom_apply_model_resolution()
# ------------------------------------------------------------------

start = None
end = None

for i, line in enumerate(lines):
    if line.startswith("def _aibom_apply_model_resolution"):
        start = i
        break

if start is None:
    fail("Could not locate _aibom_apply_model_resolution().")

for i in range(start + 1, len(lines)):
    if lines[i].startswith("def "):
        end = i
        break

if end is None:
    end = len(lines)

function_text = "".join(lines[start:end])

if "    return findings" not in function_text:
    fail("Could not locate return findings inside _aibom_apply_model_resolution().")

# ------------------------------------------------------------------
# Create backup BEFORE modification
# ------------------------------------------------------------------

BACKUP_DIR.mkdir(parents=True, exist_ok=True)

stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
backup = BACKUP_DIR / f"aibom.py.before_p05_association_{stamp}.py"
backup.write_text(text, encoding="utf-8")

# ------------------------------------------------------------------
# Insert association invocation into existing function
# ------------------------------------------------------------------

old_return = "    return findings\n"

new_return = """    # P0.5 association layer:
    # Constructor findings may occur before the actual model-bearing call.
    # Associate them through AST client-variable flow.
    findings = _aibom_associate_model_calls(source, findings)

    return findings
"""

if function_text.count(old_return) != 1:
    fail(
        "Expected exactly one return findings statement inside "
        "_aibom_apply_model_resolution()."
    )

function_text = function_text.replace(
    old_return,
    new_return,
    1,
)

# ------------------------------------------------------------------
# Insert helper immediately before _aibom_apply_model_resolution()
# ------------------------------------------------------------------

helper = r'''
# ---------------------------------------------------------------------------
# V11 AI-BOM P0.5 CLIENT -> MODEL CALL ASSOCIATION
# ---------------------------------------------------------------------------

_AIBOM_MODEL_BEARING_METHODS = {
    "create",
    "generate",
    "generate_content",
    "invoke",
}


def _aibom_call_root_name(node):
    """
    Resolve the root variable of an attribute call.

        client.chat.completions.create(...)
            -> client

        client.responses.create(...)
            -> client
    """
    current = node

    while isinstance(current, ast.Attribute):
        current = current.value

    if isinstance(current, ast.Call):
        current = current.func

        while isinstance(current, ast.Attribute):
            current = current.value

    if isinstance(current, ast.Name):
        return current.id

    return None


def _aibom_is_model_bearing_call(node):
    """
    Identify calls that explicitly contain a model/deployment argument.

    This prevents arbitrary proximity-based association.
    """
    if not isinstance(node, ast.Call):
        return False

    func = node.func

    if not isinstance(func, ast.Attribute):
        return False

    if func.attr not in _AIBOM_MODEL_BEARING_METHODS:
        return False

    for keyword in node.keywords:
        if keyword.arg in {
            "model",
            "deployment",
            "deployment_name",
            "model_name",
        }:
            return True

    return False


def _aibom_constructor_root(node):
    """
    Resolve:

        client = OpenAI()
        client = AzureOpenAI()

    into:

        ("client", "OpenAI")
        ("client", "AzureOpenAI")
    """
    if not isinstance(node, ast.Assign):
        return None, None

    if not isinstance(node.value, ast.Call):
        return None, None

    constructor = node.value.func

    if not isinstance(constructor, ast.Name):
        return None, None

    ai_constructors = {
        "OpenAI",
        "AzureOpenAI",
        "AsyncOpenAI",
        "AsyncAzureOpenAI",
        "Anthropic",
        "ChatOpenAI",
        "AzureChatOpenAI",
        "GenerativeModel",
        "VertexAI",
        "Bedrock",
    }

    if constructor.id not in ai_constructors:
        return None, None

    for target in node.targets:
        if isinstance(target, ast.Name):
            return target.id, constructor.id

    return None, None


def _aibom_associate_model_calls(source, findings):
    """
    Associate an AI client constructor finding with model-bearing calls
    performed through the same client variable.

    Example:

        client = OpenAI()

        response = client.chat.completions.create(
            model="gpt-5"
        )

    The AI-BOM constructor finding remains at line 2, but receives
    model evidence from the associated call.
    """
    if not findings:
        return findings

    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, TypeError):
        return findings

    constructors = {}

    for node in ast.walk(tree):
        variable, constructor = _aibom_constructor_root(node)

        if variable and constructor:
            constructors[variable] = {
                "line": getattr(node, "lineno", 0),
                "constructor": constructor,
            }

    if not constructors:
        return findings

    model_calls = {}

    # Reuse the already validated model-call extractor.
    extracted = _aibom_extract_model_calls(source)

    for node in ast.walk(tree):
        if not _aibom_is_model_bearing_call(node):
            continue

        root = _aibom_call_root_name(node)

        if root not in constructors:
            continue

        line_no = getattr(node, "lineno", 0)

        resolution = extracted.get(line_no)

        if not resolution:
            continue

        model_calls.setdefault(root, []).append(
            {
                "line": line_no,
                "resolution": resolution,
            }
        )

    if not model_calls:
        return findings

    for item in findings:
        finding_line = item.get("line")

        if not finding_line:
            continue

        root = None

        for variable, constructor_info in constructors.items():
            if constructor_info["line"] == finding_line:
                root = variable
                break

        if root is None:
            continue

        calls = model_calls.get(root, [])

        if len(calls) == 1:
            resolution = calls[0]["resolution"]

            item["model_value"] = resolution.get("value")
            item["model_reference"] = resolution.get("reference")
            item["model_resolution"] = resolution.get("resolution")
            item["model_source"] = resolution.get("source")

            if resolution.get("value"):
                item["model_hint"] = resolution["value"]

            item["model_association"] = "AST_CLIENT_FLOW"
            item["model_call_line"] = calls[0]["line"]

        elif len(calls) > 1:
            # Never arbitrarily select one model.
            item["model_value"] = None
            item["model_reference"] = None
            item["model_resolution"] = "MULTIPLE"
            item["model_source"] = "AST_CLIENT_FLOW"
            item["model_association"] = "AST_CLIENT_FLOW"
            item["model_call_line"] = None

    return findings


# ---------------------------------------------------------------------------
# END V11 AI-BOM P0.5 CLIENT -> MODEL CALL ASSOCIATION
# ---------------------------------------------------------------------------

'''

# Insert helper before the function.
lines[start:start] = [helper]

# Function start shifted by helper insertion.
new_start = start + helper.count("\n")

# Re-find function after insertion.
for i, line in enumerate(lines):
    if line.startswith("def _aibom_apply_model_resolution"):
        function_start = i
        break
else:
    fail("Function disappeared after helper insertion.")

for i in range(function_start + 1, len(lines)):
    if lines[i].startswith("def "):
        function_end = i
        break
else:
    function_end = len(lines)

current_function = "".join(lines[function_start:function_end])

if "findings = _aibom_associate_model_calls(source, findings)" in current_function:
    fail("Association invocation unexpectedly already exists.")

if current_function.count("    return findings\n") != 1:
    fail("Expected exactly one return findings in target function.")

current_function = current_function.replace(
    "    return findings\n",
    new_return,
    1,
)

lines[function_start:function_end] = [current_function]

TARGET.write_text("".join(lines), encoding="utf-8")

print("[PASS] P0.5 AST client -> model association added")
print("[PASS] Constructor-to-model flow association added")
print("[PASS] Same-line model resolution preserved")
print("[PASS] Multiple model calls protected from arbitrary selection")
print(f"[BACKUP] {backup}")
