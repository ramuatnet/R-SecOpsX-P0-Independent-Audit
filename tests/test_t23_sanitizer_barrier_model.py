"""T-2.3: formal sanitizer + barrier declarations in rules, contract-driven
suppression.

task.md section 3, T-2.3:

    Formal `sanitizer` + `barrier` declarations in rules; contract-driven
    suppression. Uploads must NOT reuse `_PATH_SAFE` (basename strips
    traversal, not extension) -- keep that distinction. Gate: BenchmarkJava
    recall >= parity, FP delta <= 1%, golden-corpus precision >= 75.7%.

The contract asserted here:

  * the rule schema (rules/schema_v1.json) gains two OPTIONAL fields --
    `sanitizers` (dotted-name taint purifiers) and `barriers` (regex
    counterevidence) -- so every pre-existing rule still validates
    byte-identically (back-compat; task.md:374 risk table);
  * core.rule_loader exposes dedicated accessors
    (load_sanitizer_overrides / load_barrier_overrides); neither is leaked
    into the legacy ENTERPRISE_RULES / REGEX_RULES shapes;
  * the declarations are CONSUMED, not decorative:
      - barriers feed UFIB G6 as additive decisive counterevidence
        (contract-driven suppression);
      - sanitizers extend the taint engine's per-vuln-class SANITIZERS
        table (xss / command_injection / ssrf only -- new classes are
        refused so frozenset(SANITIZERS) and sanitized_for stay stable);
  * uploads keep their own counterevidence library (_UPLOAD_SAFE) and
    never reuse _PATH_SAFE (basename is a path defence, not an upload
    defence) -- locked here so a refactor cannot silently merge them;
  * with no rule declaring either field (the current production pack),
    every consumer sees the built-in tables unchanged -> oracles
    byte-identical.
"""
from __future__ import annotations

import pathlib
import re
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))


def _doc_with(rule: dict) -> dict:
    return {"schema": "rsecopsx.rules/v1", "rules": [rule]}


def _good_rule(**over) -> dict:
    rule = {
        "id": "TEST_T23_RULE",
        "title": "Sample",
        "vuln": "xss",
        "sev": "High",
        "langs": ["python"],
        "cwe": "CWE-79",
        "owasp": "A03:2021 - Injection",
        "pattern": "render_template\\s*\\(",
    }
    rule.update(over)
    return rule


# ---------------------------------------------------------------------------
# 1. Schema: the two new fields are optional and validated
# ---------------------------------------------------------------------------
def test_schema_accepts_sanitizers_and_barriers():
    from core.rule_loader import validate_doc
    validate_doc(_doc_with(_good_rule(
        sanitizers=["mycorp.escape_html"],
        barriers=[r"allowed_hosts\.append"],
    )))


def test_schema_still_accepts_rules_without_the_new_fields():
    # Back-compat: the entire existing pack declares neither field.
    from core.rule_loader import validate_doc
    validate_doc(_doc_with(_good_rule()))


@pytest.mark.parametrize("over,error_part", [
    ({"sanitizers": []}, "fewer than"),
    ({"sanitizers": ["ok", "ok"]}, "duplicate"),
    ({"sanitizers": [1]}, "string"),
    ({"barriers": []}, "fewer than"),
    ({"barriers": ["ok", "ok"]}, "duplicate"),
    ({"barriers": [None]}, "string"),
])
def test_schema_rejects_bad_sanitizer_barrier_shapes(over, error_part):
    from core.rule_loader import RuleFormatError, validate_doc
    with pytest.raises(RuleFormatError) as ei:
        validate_doc(_doc_with(_good_rule(**over)))
    assert error_part in str(ei.value)


def test_schema_rejects_uncompilable_barrier():
    from core.rule_loader import RuleFormatError, validate_doc
    with pytest.raises(RuleFormatError) as ei:
        validate_doc(_doc_with(_good_rule(barriers=["([unclosed"])))
    assert "barriers" in str(ei.value)


# ---------------------------------------------------------------------------
# 2. Loader accessors
# ---------------------------------------------------------------------------
def test_loader_accessors_surface_declarations(tmp_path, monkeypatch):
    from core import rule_loader
    import core.mini_yaml as mini_yaml
    # The accessors read _RULES_DIR / <name>; point that at a temp dir.
    monkeypatch.setattr(rule_loader, "_RULES_DIR", tmp_path)
    (tmp_path / "enterprise_v1.yaml").write_text(mini_yaml.dump(
        _doc_with(_good_rule(
            id="T23_SANITIZED_RULE",
            sanitizers=["mycorp.escape_html", "bleach.clean"],
            barriers=[r"ALLOWLIST\s*="],
        ))), encoding="utf-8")
    (tmp_path / "regex_v1.yaml").write_text(mini_yaml.dump(
        {"schema": "rsecopsx.rules/v1", "rules": [_good_rule(
            id="T23_BARRIER_ONLY", vuln="sql_injection",
            pattern="execute\\s*\\(",
            barriers=[r"params\s*=\s*\["],
        )]}), encoding="utf-8")

    sani = rule_loader.load_sanitizer_overrides()
    assert sani["T23_SANITIZED_RULE"] == {
        "vuln": "xss",
        "sanitizers": ["mycorp.escape_html", "bleach.clean"],
    }
    assert "T23_BARRIER_ONLY" not in sani

    barriers = rule_loader.load_barrier_overrides()
    assert barriers["T23_SANITIZED_RULE"] == [r"ALLOWLIST\s*="]
    assert barriers["T23_BARRIER_ONLY"] == [r"params\s*=\s*\["]


def test_production_pack_declares_no_sanitizers_or_barriers():
    # Parity guard: the shipped pack must not declare either field, so
    # every consumer keeps seeing the built-in tables unchanged.
    from core import rule_loader
    assert rule_loader.load_sanitizer_overrides() == {}
    assert rule_loader.load_barrier_overrides() == {}


def test_accessors_do_not_leak_into_legacy_shapes():
    from core import rule_loader
    from scanner import sast
    for r in sast.ENTERPRISE_RULES:
        assert "sanitizers" not in r and "barriers" not in r
    for r in sast.REGEX_RULES:
        assert "sanitizers" not in r and "barriers" not in r
    # And the accessors still resolve for the real pack (no crash).
    assert isinstance(rule_loader.load_sanitizer_overrides(), dict)
    assert isinstance(rule_loader.load_barrier_overrides(), dict)


# ---------------------------------------------------------------------------
# 3. Barriers are CONSUMED by UFIB G6 (contract-driven suppression)
# ---------------------------------------------------------------------------
def _ufib_finding(rule_id="T23_BARRIER_RULE", file_text="ALLOWLIST = {'a'}\n"):
    return {
        "rule_id": rule_id,
        "vuln_type": "xss",
        "severity": "High",
        "file": "app.py",
        "line": 3,
        "evidence": "render_template(request.args.get('q'))",
    }


def test_barrier_suppresses_finding_through_g6(monkeypatch, tmp_path):
    from analysis import ufib_brain
    from analysis import ufib_contracts as uc
    pat = re.compile(r"ALLOWLIST\s*=", re.I | re.M | re.S)
    monkeypatch.setattr(ufib_brain, "_RULE_BARRIERS",
                        {"T23_BARRIER_RULE": (pat,)}, raising=False)
    # G6 needs the file text; stub the reader to return the barrier source.
    monkeypatch.setattr(ufib_brain, "read_source",
                        lambda f, t=None: "ALLOWLIST = {'a'}\n")
    ev: list[dict] = []
    finding = _ufib_finding()
    contract = uc.get_contract("xss")
    result, reason = ufib_brain._g6_contradiction(finding, contract, None, ev)
    assert result == "FAIL", reason
    assert any(e["kind"].startswith("counterevidence:rule_barrier")
               for e in ev)


def test_barrier_absent_leaves_g6_unchanged(monkeypatch):
    from analysis import ufib_brain
    from analysis import ufib_contracts as uc
    pat = re.compile(r"NEVER_PRESENT_TOKEN_XYZ", re.I | re.M | re.S)
    monkeypatch.setattr(ufib_brain, "_RULE_BARRIERS",
                        {"T23_BARRIER_RULE": (pat,)}, raising=False)
    monkeypatch.setattr(ufib_brain, "read_source",
                        lambda f, t=None: "ALLOWLIST = {'a'}\n")
    ev: list[dict] = []
    result, _ = ufib_brain._g6_contradiction(
        _ufib_finding(), uc.get_contract("xss"), None, ev)
    assert result in {"PASS", "UNKNOWN"}
    assert not any(e["kind"].startswith("counterevidence:rule_barrier")
                   for e in ev)


def test_no_rule_barriers_is_a_noop_on_g6(monkeypatch):
    from analysis import ufib_brain
    from analysis import ufib_contracts as uc
    monkeypatch.setattr(ufib_brain, "_RULE_BARRIERS", {}, raising=False)
    monkeypatch.setattr(ufib_brain, "read_source",
                        lambda f, t=None: "x = 1\n")
    ev: list[dict] = []
    result, _ = ufib_brain._g6_contradiction(
        _ufib_finding(), uc.get_contract("xss"), None, ev)
    assert not any(e["kind"].startswith("counterevidence:rule_barrier")
                   for e in ev)


def test_barrier_loader_compiles_patterns(monkeypatch, tmp_path):
    from analysis import ufib_brain
    import core.mini_yaml as mini_yaml
    from core import rule_loader
    monkeypatch.setattr(rule_loader, "_RULES_DIR", tmp_path)
    (tmp_path / "enterprise_v1.yaml").write_text(mini_yaml.dump(
        _doc_with(_good_rule(
            id="T23_COMPILE_RULE",
            barriers=[r"FOO\s*=\s*1", r"BAR\s*=\s*2"]))), encoding="utf-8")
    (tmp_path / "regex_v1.yaml").write_text(mini_yaml.dump(
        {"schema": "rsecopsx.rules/v1",
         "rules": [_good_rule(id="T23_EMPTY")]}), encoding="utf-8")
    barriers = ufib_brain._load_rule_barriers()
    assert "T23_COMPILE_RULE" in barriers
    assert all(isinstance(p, re.Pattern) for p in barriers["T23_COMPILE_RULE"])
    assert len(barriers["T23_COMPILE_RULE"]) == 2


# ---------------------------------------------------------------------------
# 4. Sanitizers are CONSUMED by the taint engine (per-class extension)
# ---------------------------------------------------------------------------
def test_rule_sanitizer_extends_xss_class(monkeypatch):
    from scanner import taint_engine as te
    monkeypatch.setattr(te, "_RULE_SANITIZERS",
                        {"xss": frozenset({"mycorp.escape_html"})},
                        raising=False)
    monkeypatch.setattr(te, "_EFFECTIVE", None, raising=False)
    is_san = te.TaintVisitor._is_sanitizer_call
    # The injected rule sanitizer is now recognised for xss (exact).
    assert is_san("mycorp.escape_html", "xss")
    # ...and by suffix: a longer call path ending in the sanitizer matches.
    assert is_san("pkg.utils.mycorp.escape_html", "xss")
    # ...and for no other class (class-correct, like the built-ins).
    assert not is_san("mycorp.escape_html", "command_injection")
    assert not is_san("mycorp.escape_html", "ssrf")
    # Built-ins still work.
    assert is_san("html.escape", "xss")
    assert is_san("shlex.quote", "command_injection")
    # The effective table carries the union for xss only.
    eff = te._effective_sanitizers()
    assert "mycorp.escape_html" in eff["xss"]
    assert "html.escape" in eff["xss"]
    assert eff["command_injection"] == te.SANITIZERS["command_injection"]


def test_rule_sanitizer_refuses_new_vuln_class(monkeypatch):
    # A rule declaring a sanitizer for a class the engine does not model
    # must NOT create that class (frozenset(SANITIZERS) / sanitized_for
    # stay stable); the loader keeps it, the engine drops it.
    from scanner import taint_engine as te
    monkeypatch.setattr(te, "_RULE_SANITIZERS",
                        {"path_traversal": frozenset({"mycorp.safe_path"})},
                        raising=False)
    monkeypatch.setattr(te, "_EFFECTIVE", None, raising=False)
    eff = te._effective_sanitizers()
    assert "path_traversal" not in eff
    assert set(eff) == set(te.SANITIZERS)


def test_no_rule_sanitizers_is_identity(monkeypatch):
    from scanner import taint_engine as te
    monkeypatch.setattr(te, "_RULE_SANITIZERS", {}, raising=False)
    monkeypatch.setattr(te, "_EFFECTIVE", None, raising=False)
    # With no declarations the effective table IS the built-in object.
    assert te._effective_sanitizers() is te.SANITIZERS


def test_rule_sanitizer_load_filters_to_known_classes(monkeypatch, tmp_path):
    from scanner import taint_engine as te
    import core.mini_yaml as mini_yaml
    from core import rule_loader
    monkeypatch.setattr(rule_loader, "_RULES_DIR", tmp_path)
    (tmp_path / "enterprise_v1.yaml").write_text(mini_yaml.dump(
        {"schema": "rsecopsx.rules/v1", "rules": [
            _good_rule(id="T23_XSS_SAN", vuln="xss",
                       sanitizers=["mycorp.escape_html"]),
            _good_rule(id="T23_CMD_SAN", vuln="command_injection",
                       pattern="subprocess", sanitizers=["mycorp.quote_arg"]),
            _good_rule(id="T23_UNKNOWN_SAN", vuln="prototype_pollution",
                       pattern="__proto__", sanitizers=["mycorp.freeze"]),
        ]}), encoding="utf-8")
    (tmp_path / "regex_v1.yaml").write_text(mini_yaml.dump(
        {"schema": "rsecopsx.rules/v1",
         "rules": [_good_rule(id="T23_NONE")]}), encoding="utf-8")
    loaded = te._load_rule_sanitizers()
    assert loaded == {
        "xss": frozenset({"mycorp.escape_html"}),
        "command_injection": frozenset({"mycorp.quote_arg"}),
        # prototype_pollution dropped: not a modelled sanitizer class.
    }


# ---------------------------------------------------------------------------
# 5. Uploads keep their own counterevidence (never reuse _PATH_SAFE)
# ---------------------------------------------------------------------------
def test_upload_counterevidence_does_not_reuse_path_safe():
    from analysis import ufib_contracts as uc
    path_kinds = {ce["kind"] for ce in uc._PATH_SAFE}
    upload_kinds = {ce["kind"] for ce in uc._UPLOAD_SAFE}
    # Path defences: canonicalization + containment (incl. basename).
    assert "canonicalization" in path_kinds
    assert "containment_check" in path_kinds
    # Upload defences: extension allowlist + generated destination name.
    assert "extension_allowlist" in upload_kinds
    assert "generated_destination_name" in upload_kinds
    # The two libraries are disjoint -- no shared kind.
    assert not (path_kinds & upload_kinds)
    # basename is a PATH defence; it must never be an UPLOAD defence.
    path_pats = " ".join(ce["pattern"].pattern for ce in uc._PATH_SAFE)
    upload_pats = " ".join(ce["pattern"].pattern for ce in uc._UPLOAD_SAFE)
    assert "basename" in path_pats
    assert "basename" not in upload_pats


def test_contracts_bind_distinct_upload_vs_path_libraries():
    from analysis import ufib_contracts as uc
    upload = uc.get_contract("unrestricted_upload")
    path = uc.get_contract("path_traversal")
    assert upload["counterevidence"] is uc._UPLOAD_SAFE
    assert path["counterevidence"] is uc._PATH_SAFE
    assert upload["counterevidence"] is not path["counterevidence"]


# ---------------------------------------------------------------------------
# 6. Round-trip: emitter preserves the new fields
# ---------------------------------------------------------------------------
def test_emitter_field_order_includes_new_fields():
    src = (REPO / "tools" / "emit_rule_yaml.py").read_text(encoding="utf-8")
    assert '"sanitizers"' in src and '"barriers"' in src
