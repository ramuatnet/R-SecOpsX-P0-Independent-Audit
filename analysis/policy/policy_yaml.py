"""Policy-document YAML subset parser (T-8.3, airgap fallback).

core/mini_yaml cannot serve policy documents: it is hardwired to the
{schema, rules} rule-document shape (only 'rules' may be a block list;
root values are scalars only -- no top-level flow lists). Policy files
need a different shape, so this module implements the canonical subset
directly:

* top-level ``key: scalar`` and top-level ``key: [flow, list]``;
* exactly ONE block list, ``exclusions:``, of flat mappings at indent 2
  (``- key: value`` items plus ``key: value`` continuation lines);
* full-line comments, blank lines, 2-space indent;
* scalars: single-quoted ('' escapes the quote), integers, true/false/
  null, bare strings.

PyYAML (when importable) is the preferred loader -- model.parse_policy
uses it if present; both paths MUST produce equal structures for the
canonical document (pinned by test_both_yaml_paths_produce_equal_
structures). This parser is what keeps the gate runnable with zero
third-party dependencies.
"""


class PolicyYamlError(Exception):
    """Raised for any input outside the documented subset."""


def loads(text):
    """Parse *text* in the policy subset; return the raw dict structure."""
    root = {}
    exclusions = None     # active block list, if the cursor is inside one
    current_item = None   # active exclusion mapping, if any
    for lineno, raw in enumerate(text.splitlines(), 1):
        if not raw.strip() or raw.lstrip(" ").startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        line = raw.strip()
        if indent % 2 != 0:
            raise PolicyYamlError(
                f"line {lineno}: indent must be a multiple of 2")
        if indent == 0:
            exclusions = None
            current_item = None
            if ":" not in line:
                raise PolicyYamlError(f"line {lineno}: expected 'key: value'")
            key, _, value = line.partition(":")
            key = key.strip()
            value = value.strip()
            if not value:
                if key != "exclusions":
                    raise PolicyYamlError(
                        f"line {lineno}: block lists are only allowed for "
                        f"'exclusions', got {key!r}")
                if key in root:
                    raise PolicyYamlError(
                        f"line {lineno}: duplicate key {key!r}")
                root[key] = []
                exclusions = root[key]
            else:
                if key in root:
                    raise PolicyYamlError(
                        f"line {lineno}: duplicate key {key!r}")
                root[key] = _parse_value(value, lineno)
        elif indent == 2:
            if exclusions is None:
                raise PolicyYamlError(
                    f"line {lineno}: indented line outside a block list")
            if line.startswith("- "):
                current_item = {}
                exclusions.append(current_item)
                rest = line[2:].strip()
                if ":" not in rest:
                    raise PolicyYamlError(
                        f"line {lineno}: expected 'key: value' after '-'")
                key, _, value = rest.partition(":")
                _put_item(current_item, key.strip(), value.strip(), lineno)
            else:
                if current_item is None:
                    raise PolicyYamlError(
                        f"line {lineno}: continuation without an item")
                key, _, value = line.partition(":")
                _put_item(current_item, key.strip(), value.strip(), lineno)
        elif indent == 4 and current_item is not None:
            # continuation keys of a block-list item live at indent 4
            # ('- rule: x' at 2, 'file: y' at 4) -- the canonical shape
            if line.startswith("- "):
                raise PolicyYamlError(
                    f"line {lineno}: nested lists are not part of the "
                    f"policy subset")
            key, _, value = line.partition(":")
            _put_item(current_item, key.strip(), value.strip(), lineno)
        else:
            raise PolicyYamlError(
                f"line {lineno}: unsupported indent {indent} "
                f"(top level or indent 2 only)")
    return root


def _put_item(item, key, value, lineno):
    if not key:
        raise PolicyYamlError(f"line {lineno}: empty key")
    if key in item:
        raise PolicyYamlError(f"line {lineno}: duplicate key {key!r}")
    if not value:
        raise PolicyYamlError(
            f"line {lineno}: block-list items are flat scalars "
            f"(no nested blocks); key {key!r} has no value")
    item[key] = _parse_value(value, lineno)


def _parse_value(value, lineno):
    if value.startswith("["):
        if not value.endswith("]"):
            raise PolicyYamlError(f"line {lineno}: unterminated flow list")
        return [_parse_scalar(p.strip(), lineno)
                for p in _split_flow(value[1:-1], lineno)]
    return _parse_scalar(value, lineno)


def _split_flow(inner, lineno):
    items = []
    buf = []
    in_quote = False
    for ch in inner:
        if in_quote:
            buf.append(ch)
            if ch == "'":
                in_quote = False
        elif ch == "'":
            in_quote = True
            buf.append(ch)
        elif ch == ",":
            items.append("".join(buf).strip())
            buf = []
        else:
            buf.append(ch)
    if in_quote:
        raise PolicyYamlError(f"line {lineno}: unterminated quote")
    tail = "".join(buf).strip()
    if tail or items:
        items.append(tail)
    return [i for i in items if i != ""]


def _parse_scalar(value, lineno):
    if value.startswith("'"):
        if len(value) < 2 or not value.endswith("'"):
            raise PolicyYamlError(f"line {lineno}: unterminated quote")
        return value[1:-1].replace("''", "'")
    if value in ("true", "True"):
        return True
    if value in ("false", "False"):
        return False
    if value in ("null", "Null", "~"):
        return None
    try:
        return int(value)
    except ValueError:
        return value
