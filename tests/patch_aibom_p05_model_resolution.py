from pathlib import Path
from datetime import datetime

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "scanner" / "aibom.py"
BACKUP_DIR = ROOT / "backup"

source = TARGET.read_text(encoding="utf-8-sig")

if "_aibom_resolve_model_value" in source:
    raise SystemExit("[FAIL] P0.5 model resolver already exists. Do not apply twice.")

BACKUP_DIR.mkdir(parents=True, exist_ok=True)

timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
backup = BACKUP_DIR / f"aibom.py.before_p05_model_resolution_{timestamp}.py"
backup.write_text(source, encoding="utf-8")

HELPER = r'''

# ---------------------------------------------------------------------------
# V11 AI-BOM P0.5 — AST MODEL RESOLUTION
# ---------------------------------------------------------------------------

_AIBOM_MODEL_KEYWORDS = {
    "model",
    "deployment",
    "model_name",
    "model_id",
    "engine",
}


def _aibom_string_constant(node):
    """Return a literal string value, otherwise None."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value

    if isinstance(node, ast.Str):
        return node.s

    return None


def _aibom_getenv_reference(node):
    """
    Resolve:
        os.getenv("OPENAI_MODEL")
        os.environ.get("OPENAI_MODEL")
    """
    if not isinstance(node, ast.Call):
        return None

    func = node.func

    if isinstance(func, ast.Attribute):
        if (
            func.attr == "getenv"
            and isinstance(func.value, ast.Name)
            and func.value.id == "os"
        ):
            if node.args:
                return _aibom_string_constant(node.args[0])

        if (
            func.attr == "get"
            and isinstance(func.value, ast.Attribute)
            and func.value.attr == "environ"
            and isinstance(func.value.value, ast.Name)
            and func.value.value.id == "os"
        ):
            if node.args:
                return _aibom_string_constant(node.args[0])

    return None


def _aibom_build_model_symbols(tree):
    """
    Build a conservative Python symbol table for model values.

    Supported:
      MODEL = "gpt-5"
      MODEL = OTHER_MODEL
      MODEL = os.getenv("OPENAI_MODEL")

    Deliberately unsupported:
      MODEL = get_model()
      MODEL = foo.bar()
      arbitrary inter-procedural execution
    """
    symbols = {}

    for node in ast.walk(tree):

        if isinstance(node, ast.Assign):
            targets = node.targets

        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]

        else:
            continue

        value = node.value

        for target in targets:
            if not isinstance(target, ast.Name):
                continue

            name = target.id

            literal = _aibom_string_constant(value)

            if literal is not None:
                symbols[name] = {
                    "value": literal,
                    "reference": None,
                    "resolution": "RESOLVED",
                    "source": "AST_CONSTANT",
                }
                continue

            env_reference = _aibom_getenv_reference(value)

            if env_reference:
                symbols[name] = {
                    "value": None,
                    "reference": env_reference,
                    "resolution": "PARTIAL",
                    "source": "ENVIRONMENT_VARIABLE",
                }
                continue

            if isinstance(value, ast.Name):
                symbols[name] = {
                    "value": None,
                    "reference": value.id,
                    "resolution": "SYMBOL_REFERENCE",
                    "source": "AST_VARIABLE",
                }
                continue

            symbols[name] = {
                "value": None,
                "reference": None,
                "resolution": "UNKNOWN",
                "source": "DYNAMIC_EXPRESSION",
            }

    return symbols


def _aibom_resolve_model_value(node, symbols, seen=None):
    """
    Resolve an AST expression to a model descriptor.

    Returns:
        value
        reference
        resolution
        source
    """
    if seen is None:
        seen = set()

    literal = _aibom_string_constant(node)

    if literal is not None:
        return {
            "value": literal,
            "reference": None,
            "resolution": "RESOLVED",
            "source": "AST_LITERAL",
        }

    env_reference = _aibom_getenv_reference(node)

    if env_reference:
        return {
            "value": None,
            "reference": env_reference,
            "resolution": "PARTIAL",
            "source": "ENVIRONMENT_VARIABLE",
        }

    if isinstance(node, ast.Name):
        name = node.id

        if name in seen:
            return {
                "value": None,
                "reference": name,
                "resolution": "UNKNOWN",
                "source": "CYCLIC_REFERENCE",
            }

        entry = symbols.get(name)

        if not entry:
            return {
                "value": None,
                "reference": name,
                "resolution": "UNKNOWN",
                "source": "UNRESOLVED_VARIABLE",
            }

        if entry.get("resolution") == "SYMBOL_REFERENCE":
            seen.add(name)

            target = entry.get("reference")

            target_node = None

            for symbol_name, symbol_entry in symbols.items():
                if symbol_name == target:
                    target_node = symbol_name
                    break

            if target_node:
                resolved = symbols[target_node]

                if resolved.get("resolution") == "RESOLVED":
                    return {
                        "value": resolved.get("value"),
                        "reference": name,
                        "resolution": "RESOLVED",
                        "source": "AST_VARIABLE",
                    }

                if resolved.get("resolution") == "PARTIAL":
                    return {
                        "value": None,
                        "reference": resolved.get("reference") or name,
                        "resolution": "PARTIAL",
                        "source": resolved.get("source"),
                    }

            return {
                "value": None,
                "reference": name,
                "resolution": "UNKNOWN",
                "source": "AST_VARIABLE",
            }

        return dict(entry)

    if isinstance(node, ast.JoinedStr):
        parts = []

        for value_node in node.values:
            if isinstance(value_node, ast.Constant):
                if isinstance(value_node.value, str):
                    parts.append(value_node.value)
                    continue

            return {
                "value": None,
                "reference": None,
                "resolution": "UNKNOWN",
                "source": "DYNAMIC_EXPRESSION",
            }

        return {
            "value": "".join(parts),
            "reference": None,
            "resolution": "RESOLVED",
            "source": "AST_LITERAL",
        }

    return {
        "value": None,
        "reference": None,
        "resolution": "UNKNOWN",
        "source": "DYNAMIC_EXPRESSION",
    }


def _aibom_extract_model_calls(source):
    """
    Extract model/deployment expressions from Python Call nodes.

    This operates independently of provider detection. The existing
    provider/AI-component detection remains unchanged.
    """
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, TypeError):
        return {}

    symbols = _aibom_build_model_symbols(tree)
    results = {}

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        for keyword in node.keywords:
            if keyword.arg not in _AIBOM_MODEL_KEYWORDS:
                continue

            resolution = _aibom_resolve_model_value(
                keyword.value,
                symbols,
            )

            results[node.lineno] = resolution

    return results


def _aibom_apply_model_resolution(path, source, findings):
    """
    Attach structured model resolution only to findings located on an
    actual model/deployment call.

    Existing model_hint behavior is retained for compatibility.
    """
    if path.suffix.lower() != ".py":
        return findings

    model_calls = _aibom_extract_model_calls(source)

    if not model_calls:
        return findings

    for item in findings:
        line_no = item.get("line")

        resolution = model_calls.get(line_no)

        if not resolution:
            continue

        item["model_value"] = resolution.get("value")
        item["model_reference"] = resolution.get("reference")
        item["model_resolution"] = resolution.get("resolution")
        item["model_source"] = resolution.get("source")

        if resolution.get("value"):
            item["model_hint"] = resolution["value"]

    return findings

# ---------------------------------------------------------------------------
# END V11 AI-BOM P0.5
# ---------------------------------------------------------------------------
'''

scan_marker = "\ndef scan_file(filepath: str) -> list[dict]:"

if scan_marker not in source:
    raise SystemExit("[FAIL] scan_file() marker not found.")

source = source.replace(
    scan_marker,
    HELPER + scan_marker,
    1,
)

old_return = "    return deduplicate(findings)\n"

if old_return not in source:
    raise SystemExit("[FAIL] scan_file() return marker not found.")

source = source.replace(
    old_return,
    "    findings = _aibom_apply_model_resolution(path, source, findings)\n\n"
    "    return deduplicate(findings)\n",
    1,
)

TARGET.write_text(source, encoding="utf-8")

print("[PASS] Added AST model-value resolution")
print("[PASS] Added constant resolution")
print("[PASS] Added variable resolution")
print("[PASS] Added environment-variable resolution")
print("[PASS] Added explicit UNKNOWN state")
print("[PASS] Preserved existing model_hint fallback")
print("[PASS] Applied resolution only to model/deployment call lines")
print(f"[BACKUP] {backup}")
