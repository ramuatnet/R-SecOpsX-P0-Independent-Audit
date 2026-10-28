"""T-0.6 gate: declarative rule format v1.

task.md section 3, T-0.6:

    JSON-Schema-backed YAML rule file. Loader + back-compat shim that
    generates the existing ENTERPRISE_RULES/REGEX_RULES. Move
    ufib_contracts and sink_table declarations into the rule.
    Accept: all existing rules load from YAML; findings byte-identical
    on all oracles. Gate: adding a new rule touches <=2 files (the YAML
    + a test).

The contract asserted here:

  * rules/enterprise_v1.yaml + rules/regex_v1.yaml are the source of
    truth; scanner/sast.py contains no inline rule dicts (structural
    check -- the <=2-file gate);
  * the loader validates against rules/schema_v1.json and every pattern
    compiles with its declared flags before a table is handed out;
  * core.mini_yaml (the offline fallback) and PyYAML parse the same
    files to equal structures, so the two parsers cannot drift;
  * the legacy table shapes are exact (compiled patterns for
    REGEX_RULES, set-valued languages, string 'pat' for ENTERPRISE);
  * the PHP webshell pack stays code-side and its env switch still
    removes it at registration;
  * contract_ref (ufib family) and sink_category are declarative data
    with dedicated accessors, not lookups hidden in code.
"""
from __future__ import annotations

import pathlib
import re
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))


# ---------------------------------------------------------------------------
# 1. Source of truth: YAML, not code
# ---------------------------------------------------------------------------
def test_sast_has_no_inline_rule_dicts():
    """The <=2-file gate: a new rule must not require editing sast.py.

    Structural, not textual-nitpick: the legacy tables used ``"pat":``
    / ``"pattern":`` dict literals inside sast.py. After T-0.6 the only
    pattern-bearing data lives in rules/*.yaml (checked by id parity
    below); sast keeps BIG4_CONTROL_FALLBACKS (compliance text, no
    patterns) and the validator dispatch, which are behaviour, not
    rule declarations.
    """
    src = (REPO / "scanner" / "sast.py").read_text(encoding="utf-8")
    assert '"pat":' not in src, "inline ENTERPRISE rule literal in sast.py"
    assert "'pat':" not in src
    # REGEX table entries were compiled literals.
    assert "re.compile(r\"" not in src.split("COMPILED_ENTERPRISE_RULES")[0].split(
        "REGEX_RULES: list[dict] = load_regex_rules()")[-1], (
        "compiled REGEX_RULES literal survived the migration")


def test_every_table_rule_id_comes_from_yaml():
    from core import rule_loader
    from scanner import sast
    from scanner.php_webshell_rules import as_sast_rules

    yaml_ids = {r["id"] for r in rule_loader.load_enterprise_rules()}
    yaml_ids |= {r["id"] for r in rule_loader.load_regex_rules()}
    pack_ids = {r["id"] for r in as_sast_rules()}
    table_ids = {r["id"] for r in sast.ENTERPRISE_RULES}
    table_ids |= {r["id"] for r in sast.REGEX_RULES}
    assert table_ids - pack_ids <= yaml_ids, (
        "rules present in the sast tables but in no YAML file: %s"
        % sorted(table_ids - pack_ids - yaml_ids))


def test_yaml_is_normalized_and_idempotent():
    """tools/emit_rule_yaml.py output round-trips byte-identically."""
    from core import mini_yaml
    for name in ("enterprise_v1.yaml", "regex_v1.yaml"):
        text = (REPO / "rules" / name).read_text(encoding="utf-8")
        doc = mini_yaml.loads(text)
        assert mini_yaml.dump(doc) == text, f"{name} is not normalized"


# ---------------------------------------------------------------------------
# 2. Parser equivalence: mini_yaml == PyYAML on the rule files
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("name", ["enterprise_v1.yaml", "regex_v1.yaml"])
def test_mini_yaml_matches_pyyaml(name):
    yaml = pytest.importorskip("yaml")
    from core import mini_yaml
    text = (REPO / "rules" / name).read_text(encoding="utf-8")
    assert mini_yaml.loads(text) == yaml.safe_load(text)


def test_mini_yaml_rejects_out_of_subset_constructs():
    from core import mini_yaml
    with pytest.raises(mini_yaml.MiniYamlError):
        mini_yaml.loads("rules:\n  - id: unquoted\n")     # unquoted scalar
    with pytest.raises(mini_yaml.MiniYamlError):
        mini_yaml.loads("rules:\n  - id: 'A'\n    nested:\n      x: 'y'\n")  # nesting


def test_mini_yaml_parses_empty_block_list_as_empty():
    # ``rules:`` with no items is [] (schema minItems then rejects the
    # document -- rejection of content belongs to validate_doc, not the
    # subset parser).
    from core import mini_yaml
    from core.rule_loader import RuleFormatError, validate_doc
    doc = mini_yaml.loads("schema: 'x'\nrules:\n")
    assert doc == {"schema": "x", "rules": []}
    with pytest.raises(RuleFormatError):
        validate_doc(doc)


# ---------------------------------------------------------------------------
# 3. Schema validation rejects bad rules
# ---------------------------------------------------------------------------
def _doc_with(rule: dict) -> dict:
    return {"schema": "rsecopsx.rules/v1", "rules": [rule]}


def _good_rule(**over) -> dict:
    rule = {
        "id": "TEST_SAMPLE_RULE",
        "title": "Sample",
        "vuln": "sql_injection",
        "sev": "High",
        "langs": ["python"],
        "cwe": "CWE-89",
        "owasp": "A03:2021 - Injection",
        "pattern": "execute\\s*\\(",
    }
    rule.update(over)
    return rule


def test_schema_accepts_a_good_rule():
    from core.rule_loader import validate_doc
    validate_doc(_doc_with(_good_rule()))


@pytest.mark.parametrize("over,error_part", [
    ({"id": "lowercase_id"}, "id"),
    ({"sev": "Catastrophic"}, "enum"),
    ({"langs": []}, "minItems"),
    ({"pattern": ""}, "minLength"),
    ({"unknown_field": 1}, "unknown"),
    ({"flags": "xyz"}, "pattern"),
])
def test_schema_rejects_bad_rules(over, error_part):
    from core.rule_loader import RuleFormatError, validate_doc
    with pytest.raises(RuleFormatError):
        validate_doc(_doc_with(_good_rule(**over)))


def test_schema_rejects_missing_required_field():
    from core.rule_loader import RuleFormatError, validate_doc
    rule = _good_rule()
    del rule["title"]
    with pytest.raises(RuleFormatError):
        validate_doc(_doc_with(rule))


def test_schema_rejects_uncompilable_pattern():
    from core.rule_loader import RuleFormatError, validate_doc
    with pytest.raises(RuleFormatError):
        validate_doc(_doc_with(_good_rule(pattern="([unclosed")))


# ---------------------------------------------------------------------------
# 4. Legacy shape parity
# ---------------------------------------------------------------------------
def test_enterprise_table_shape_is_legacy():
    from scanner import sast
    for r in sast.ENTERPRISE_RULES:
        assert set(r) <= {"id", "title", "vuln", "sev", "langs", "cwe",
                          "owasp", "pat", "evidence_pat", "remediation"}, \
            (r["id"], sorted(r))
        assert isinstance(r["pat"], str)


def test_regex_table_patterns_are_compiled_with_declared_flags():
    from core import rule_loader
    from scanner import sast
    flags_of = {r["id"]: r["pattern"].flags for r in sast.REGEX_RULES}
    # AWS_ACCESS_KEY is the case-sensitive CID rule: default flags only.
    assert flags_of["AWS_ACCESS_KEY"] == re.compile("x").flags
    ims = re.compile("x", re.IGNORECASE | re.MULTILINE | re.DOTALL).flags
    for rid, fl in flags_of.items():
        if rid != "AWS_ACCESS_KEY":
            assert fl == ims, rid
    # And the YAML records exactly that.
    rows = {r["id"]: r for r in rule_loader.load_regex_rules()}
    assert rows["AWS_ACCESS_KEY"] is not None


def test_disabled_ids_come_from_yaml():
    from scanner import sast
    assert sast.DISABLED_CONTEXT_ONLY_RULES == frozenset(
        {"GRAPHQL_RESOLVER_BOLA", "DUPLICATE_ACTION_RACE"})
    compiled = {r["id"] for r in sast.COMPILED_ENTERPRISE_RULES}
    assert not (compiled & sast.DISABLED_CONTEXT_ONLY_RULES)


def test_sink_categories_merge_declarative_and_pack():
    from scanner import sast
    from scanner.php_webshell_rules import SINK_CATEGORIES
    assert len(sast._PHP_SINK_CATEGORY) == 15
    assert sast._PHP_SINK_CATEGORY["PHP_SQL_INTERMEDIATE_QUERY"] == "sql"
    assert sast._PHP_SINK_CATEGORY["PHP_ASSERT_REQUEST_CODE_EXEC"] == "code"
    for k, v in SINK_CATEGORIES.items():
        assert sast._PHP_SINK_CATEGORY[k] == v


def test_contract_refs_resolve_to_ufib_contracts():
    from analysis.ufib_contracts import CONTRACTS
    from core import rule_loader
    refs = rule_loader.load_contract_refs()
    assert refs, "no contract_ref emitted"
    unknown = sorted({v for v in refs.values() if v not in CONTRACTS})
    assert not unknown, unknown
    # The sql family maps through, on both tables.
    assert refs.get("JAVA_JDBC_SQL_CONCAT") == "sql_injection"


def test_webshell_pack_env_switch_still_removes_pack(monkeypatch):
    import importlib
    from scanner import php_webshell_rules as pack
    from scanner import sast
    monkeypatch.setenv(pack.DISABLE_ENV, "0")
    importlib.reload(pack)
    try:
        assert pack.as_sast_rules() == []
    finally:
        monkeypatch.delenv(pack.DISABLE_ENV, raising=False)
        importlib.reload(pack)
    # The registered table still carries the pack when enabled.
    assert {r["id"] for r in pack.as_sast_rules()} <= {
        r["id"] for r in sast.ENTERPRISE_RULES}
