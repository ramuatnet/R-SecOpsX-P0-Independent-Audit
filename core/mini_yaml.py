"""Strict subset YAML for the declarative rule files (T-0.6).

Scan mode is offline/airgap by invariant: PyYAML is an optional extra,
so the rule loader must parse the rule files without it.  This module
implements exactly the normalized subset that ``tools/emit_rule_yaml.py``
writes -- and nothing else:

  * a top-level mapping with scalar keys;
  * one nested block list (``rules:``) of block mappings;
  * single-quoted strings ('' escapes a quote), ints, ``true``/``false``,
    ``null``;
  * flow lists of those scalars (``langs: ['php', 'java']``);
  * full-line ``#`` comments and blank lines.

Every emitted file is also valid YAML for ``yaml.safe_load`` (the loader
prefers PyYAML when installed and falls back here); the test suite
asserts both paths produce equal structures, so the two parsers cannot
drift.  Anything outside the subset raises MiniYamlError -- a rule file
the tool cannot fully understand must never half-load.
"""
from __future__ import annotations

import re

__all__ = ["MiniYamlError", "dump", "loads"]

_SCALAR_RE = re.compile(
    r"^'((?:[^']|'')*)'$|^(true|false|null|-?\d+)$")


class MiniYamlError(ValueError):
    """Raised for any construct outside the normalized subset."""


def _parse_scalar(raw: str):
    m = _SCALAR_RE.match(raw)
    if not m:
        raise MiniYamlError(f"unsupported scalar: {raw!r}")
    if m.group(1) is not None:
        return m.group(1).replace("''", "'")
    tok = m.group(2)
    if tok == "true":
        return True
    if tok == "false":
        return False
    if tok == "null":
        return None
    return int(tok)


def _parse_flow_list(raw: str):
    inner = raw[1:-1].strip()
    if not inner:
        return []
    # Split on commas that are OUTSIDE single quotes; a quoted scalar may
    # contain commas, and '' is the escape for a quote inside it.
    parts: list[str] = []
    buf: list[str] = []
    in_quote = False
    i = 0
    while i < len(inner):
        ch = inner[i]
        if in_quote:
            if ch == "'":
                if i + 1 < len(inner) and inner[i + 1] == "'":
                    buf.append("''")
                    i += 2
                    continue
                in_quote = False
            buf.append(ch)
        else:
            if ch == "'":
                in_quote = True
                buf.append(ch)
            elif ch == ",":
                parts.append("".join(buf).strip())
                buf = []
            else:
                buf.append(ch)
        i += 1
    if in_quote:
        raise MiniYamlError(f"unterminated quote in flow list: {raw!r}")
    parts.append("".join(buf).strip())
    return [_parse_scalar(part) for part in parts]


def _split_key_value(line: str, lineno: int) -> tuple[str, str]:
    if ":" not in line:
        raise MiniYamlError(f"line {lineno}: expected 'key: value', got {line!r}")
    key, _, value = line.partition(":")
    key = key.strip()
    if not key or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
        raise MiniYamlError(f"line {lineno}: bad key {key!r}")
    return key, value.strip()


def loads(text: str) -> dict:
    """Parse a normalized rule document into {schema, rules}."""
    root: dict = {}
    rules: list | None = None
    current: dict | None = None
    lines = text.splitlines()
    i = 0
    n = len(lines)
    while i < n:
        raw = lines[i]
        i += 1
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        if indent % 2 != 0:
            raise MiniYamlError(f"line {i}: odd indentation ({indent})")
        if indent == 0:
            key, value = _split_key_value(stripped, i)
            if value:
                if key in root:
                    raise MiniYamlError(f"line {i}: duplicate key {key!r}")
                root[key] = _parse_scalar(value)
                rules = None
                current = None
            else:
                if key != "rules":
                    raise MiniYamlError(
                        f"line {i}: only 'rules' may be a block list")
                rules = []
                root["rules"] = rules
        elif indent == 2:
            if rules is None:
                raise MiniYamlError(f"line {i}: list item outside 'rules'")
            if stripped.startswith("- "):
                current = {}
                rules.append(current)
                key, value = _split_key_value(stripped[2:].strip(), i)
            elif stripped == "-":
                current = {}
                rules.append(current)
                continue
            else:
                if current is None:
                    raise MiniYamlError(f"line {i}: mapping key with no item")
                key, value = _split_key_value(stripped, i)
            if current is None or key in current:
                raise MiniYamlError(f"line {i}: duplicate/bad key {key!r}")
            if not value:
                raise MiniYamlError(
                    f"line {i}: nested blocks are not supported "
                    "(only flat rule mappings)")
            if value.startswith("[") and value.endswith("]"):
                current[key] = _parse_flow_list(value)
            else:
                current[key] = _parse_scalar(value)
        elif indent == 4:
            # Continuation key of the current rule item (the emitter writes
            # the first key on the "- " line and the rest at indent 4).
            if current is None:
                raise MiniYamlError(f"line {i}: continuation with no item")
            key, value = _split_key_value(stripped, i)
            if key in current:
                raise MiniYamlError(f"line {i}: duplicate key {key!r}")
            if not value:
                raise MiniYamlError(
                    f"line {i}: nested blocks are not supported "
                    "(only flat rule mappings)")
            if value.startswith("[") and value.endswith("]"):
                current[key] = _parse_flow_list(value)
            else:
                current[key] = _parse_scalar(value)
        else:
            raise MiniYamlError(f"line {i}: unsupported indentation")
    if "rules" not in root or not isinstance(root["rules"], list):
        raise MiniYamlError("document has no 'rules' list")
    return root


def _dump_scalar(value) -> str:
    if value is True:
        return "true"
    if value is False:
        return "false"
    if value is None:
        return "null"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return "'" + value.replace("'", "''") + "'"
    raise MiniYamlError(f"cannot dump {type(value).__name__}")


def _dump_flow_list(values) -> str:
    return "[" + ", ".join(_dump_scalar(v) for v in values) + "]"


def dump(doc: dict) -> str:
    """Emit the normalized form consumed by loads() (and yaml.safe_load)."""
    if not isinstance(doc, dict) or not isinstance(doc.get("rules"), list):
        raise MiniYamlError("document must be {schema, rules: [...]}")
    out: list[str] = []
    schema = doc.get("schema")
    if schema is not None:
        out.append(f"schema: {_dump_scalar(schema)}")
    out.append("rules:")
    for rule in doc["rules"]:
        if not isinstance(rule, dict) or not rule:
            raise MiniYamlError("every rule must be a non-empty mapping")
        first = True
        for key, value in rule.items():
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", str(key)):
                raise MiniYamlError(f"bad key {key!r}")
            if isinstance(value, list):
                rendered = _dump_flow_list(value)
            else:
                rendered = _dump_scalar(value)
            prefix = "  - " if first else "    "
            out.append(f"{prefix}{key}: {rendered}")
            first = False
    return "\n".join(out) + "\n"
