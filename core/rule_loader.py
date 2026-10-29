"""Declarative rule loader (T-0.6): YAML is the source of truth.

``rules/enterprise_v1.yaml`` and ``rules/regex_v1.yaml`` hold every
inline sast rule; this module validates them against
``rules/schema_v1.json`` and adapts them to the legacy table shapes
scanner.sast still consumes (ENTERPRISE_RULES: ``pat`` + string fields;
REGEX_RULES: ``name``/``severity``/``vuln_type`` + *compiled* patterns,
since core.regex_budget.timed_finditer takes a re.Pattern).

Offline invariant: PyYAML is an optional extra.  The loader prefers it
when importable and falls back to core.mini_yaml, which parses exactly
the normalized subset the emitter writes; tests assert both paths agree,
so the parsers cannot drift.

Validation is schema + compile: a rule file the tool cannot fully
understand raises at import rather than half-loading -- a silent
half-load would be the "silent drops" failure class T-0.1 exists to
kill, applied to the rule base itself.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from core import mini_yaml

_RULES_DIR = Path(__file__).resolve().parents[1] / "rules"
_SCHEMA_PATH = _RULES_DIR / "schema_v1.json"
_ENTERPRISE_PATH = _RULES_DIR / "enterprise_v1.yaml"
_REGEX_PATH = _RULES_DIR / "regex_v1.yaml"

# scanner.sast's compile flags (re.IGNORECASE | re.MULTILINE | re.DOTALL);
# duplicated as literals to keep this module free of scanner imports.
_FLAG_LETTERS = {"i": re.IGNORECASE, "m": re.MULTILINE, "s": re.DOTALL}
_DEFAULT_FLAGS = "ims"

_SCHEMA: dict | None = None


class RuleFormatError(ValueError):
    """A rule file outside the v1 schema (or unparseable pattern)."""


def _schema() -> dict:
    global _SCHEMA
    if _SCHEMA is None:
        _SCHEMA = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
    return _SCHEMA


def _load_doc(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    try:
        import yaml  # type: ignore
        return yaml.safe_load(text)
    except ImportError:
        return mini_yaml.loads(text)


# ---------------------------------------------------------------------------
# Schema validation (the subset of JSON Schema the rule schema uses)
# ---------------------------------------------------------------------------
def _check(value, spec: dict, where: str, root: dict):
    if "enum" in spec:
        if value not in spec["enum"]:
            raise RuleFormatError(
                f"{where}: {value!r} not in enum {spec['enum']}")
        return
    if "const" in spec:
        if value != spec["const"]:
            raise RuleFormatError(f"{where}: expected {spec['const']!r}")
        return
    typ = spec.get("type")
    if typ == "string" and not isinstance(value, str):
        raise RuleFormatError(f"{where}: expected string, got {type(value).__name__}")
    if typ == "boolean" and not isinstance(value, bool):
        raise RuleFormatError(f"{where}: expected boolean")
    if typ == "integer" and not isinstance(value, int):
        raise RuleFormatError(f"{where}: expected integer")
    if typ == "array":
        if not isinstance(value, list):
            raise RuleFormatError(f"{where}: expected array")
        if "minItems" in spec and len(value) < spec["minItems"]:
            raise RuleFormatError(f"{where}: fewer than {spec['minItems']} items")
        if spec.get("uniqueItems") and len(set(map(str, value))) != len(value):
            raise RuleFormatError(f"{where}: duplicate items")
        items = spec.get("items")
        if items:
            resolved = _resolve(items, root)
            for i, item in enumerate(value):
                _check(item, resolved, f"{where}[{i}]", root)
        return
    if typ == "object":
        if not isinstance(value, dict):
            raise RuleFormatError(f"{where}: expected object")
        props = spec.get("properties", {})
        for req in spec.get("required", ()):
            if req not in value:
                raise RuleFormatError(f"{where}: missing required field {req!r}")
        if spec.get("additionalProperties") is False:
            extra = set(value) - set(props)
            if extra:
                raise RuleFormatError(f"{where}: unknown fields {sorted(extra)}")
        for key, sub in props.items():
            if key in value:
                _check(value[key], _resolve(sub, root), f"{where}.{key}", root)
        return
    if "pattern" in spec and isinstance(value, str):
        if not re.search(spec["pattern"], value):
            raise RuleFormatError(
                f"{where}: {value!r} does not match {spec['pattern']!r}")
    if "minLength" in spec and isinstance(value, str):
        if len(value) < spec["minLength"]:
            raise RuleFormatError(f"{where}: shorter than {spec['minLength']}")


def _resolve(spec: dict, root: dict) -> dict:
    ref = spec.get("$ref")
    if not ref:
        return spec
    node = root
    for part in ref.lstrip("#/").split("/"):
        node = node[part]
    return node


def validate_doc(doc: dict, *, source: str = "<rule file>") -> None:
    schema = _schema()
    _check(doc, {k: v for k, v in schema.items()
                 if k in ("type", "required", "additionalProperties", "properties")},
           source, schema)
    for i, rule in enumerate(doc.get("rules") or []):
        where = f"{source}:rules[{i}]({rule.get('id', '?')})" if isinstance(rule, dict) else f"{source}:rules[{i}]"
        _check(rule, _resolve(schema["definitions"]["rule"], schema), where, schema)
        if isinstance(rule, dict) and "pattern" in rule:
            flags = _compile_flags(rule.get("flags", _DEFAULT_FLAGS))
            try:
                re.compile(rule["pattern"], flags)
            except re.error as exc:
                raise RuleFormatError(f"{where}: pattern does not compile: {exc}") from exc
        if isinstance(rule, dict) and "barriers" in rule:
            # T-2.3: barrier patterns are compiled here so a bad regex
            # fails at load (the "silent half-load" law), matching the
            # main-pattern discipline above.
            flags = _compile_flags(rule.get("flags", _DEFAULT_FLAGS))
            for i, b in enumerate(rule["barriers"]):
                try:
                    re.compile(b, flags)
                except re.error as exc:
                    raise RuleFormatError(
                        f"{where}.barriers[{i}]: does not compile: {exc}") from exc


def _compile_flags(letters: str) -> int:
    flags = 0
    for ch in letters:
        flags |= _FLAG_LETTERS[ch]
    return flags


# ---------------------------------------------------------------------------
# Legacy-shape adapters (the back-compat shim)
# ---------------------------------------------------------------------------
def load_enterprise_rules() -> list[dict]:
    """ENTERPRISE_RULES shape: pat + title/vuln/sev/langs/cwe/owasp."""
    doc = _load_doc(_ENTERPRISE_PATH)
    validate_doc(doc, source="rules/enterprise_v1.yaml")
    out = []
    for r in doc["rules"]:
        row = {
            "id": r["id"],
            "title": r["title"],
            "vuln": r["vuln"],
            "sev": r["sev"],
            "langs": list(r["langs"]),
            "cwe": r["cwe"],
            "owasp": r["owasp"],
            "pat": r["pattern"],
        }
        if r.get("evidence_pat"):
            row["evidence_pat"] = r["evidence_pat"]
        if r.get("remediation"):
            row["remediation"] = list(r["remediation"])
        # The legacy shape is kept EXACT (extra v1 keys would leak into
        # every consumer that iterates the dict); sink_category and
        # contract_ref are served by the dedicated accessors below.
        out.append(row)
    return out


def load_regex_rules() -> list[dict]:
    """REGEX_RULES shape: name/severity/vuln_type + compiled patterns."""
    doc = _load_doc(_REGEX_PATH)
    validate_doc(doc, source="rules/regex_v1.yaml")
    out = []
    for r in doc["rules"]:
        row = {
            "id": r["id"],
            "name": r["title"],
            "pattern": re.compile(r["pattern"],
                                  _compile_flags(r.get("flags", _DEFAULT_FLAGS))),
            "vuln_type": r["vuln"],
            "note": r.get("note", ""),
            "severity": r["sev"],
            "cwe": r["cwe"],
            "owasp": r["owasp"],
        }
        if r.get("langs"):
            # Legacy REGEX_RULES stores languages as a set; keep the shape.
            row["languages"] = set(r["langs"])
        out.append(row)
    return out


def load_disabled_ids() -> frozenset:
    doc = _load_doc(_ENTERPRISE_PATH)
    return frozenset(r["id"] for r in doc["rules"] if r.get("disabled"))


def load_sink_categories() -> dict:
    doc = _load_doc(_ENTERPRISE_PATH)
    return {r["id"]: r["sink_category"] for r in doc["rules"]
            if r.get("sink_category")}


def load_contract_refs() -> dict:
    """rule id -> ufib family contract key (the rule's contract_ref)."""
    out = {}
    for name in ("enterprise_v1.yaml", "regex_v1.yaml"):
        doc = _load_doc(_RULES_DIR / name)
        out.update({r["id"]: r["contract_ref"] for r in doc["rules"]
                    if r.get("contract_ref")})
    return out


def load_sanitizer_overrides() -> dict:
    """T-2.3: rule id -> {vuln, sanitizers} for rules declaring sanitizers.

    Declarative data with a dedicated accessor (like contract_ref /
    sink_category); never leaked into the legacy table shapes.  Empty for
    a pack that declares none -- the taint engine then sees only its
    built-in per-class table, keeping every oracle byte-identical.
    """
    out = {}
    for name in ("enterprise_v1.yaml", "regex_v1.yaml"):
        doc = _load_doc(_RULES_DIR / name)
        for r in doc["rules"]:
            s = r.get("sanitizers")
            if s:
                out[r["id"]] = {"vuln": r["vuln"], "sanitizers": list(s)}
    return out


def load_barrier_overrides() -> dict:
    """T-2.3: rule id -> barrier regex patterns (raw strings).

    Compiled by the consumer (ufib_brain) with the same default flags the
    main pattern uses; validate_doc already proved each compiles.  Empty
    for a pack that declares none -> G6 sees only its contract
    counterevidence, keeping every oracle byte-identical.
    """
    out = {}
    for name in ("enterprise_v1.yaml", "regex_v1.yaml"):
        doc = _load_doc(_RULES_DIR / name)
        for r in doc["rules"]:
            b = r.get("barriers")
            if b:
                out[r["id"]] = list(b)
    return out
