"""Phase 3.3: fix snippets — recipe-style before/after templates on findings.

WHAT THIS DELIVERS
------------------
Gap-plan row 3.3 ("map top rules to OpenRewrite-style fix templates",
verify: findings include fix_snippet). scanner/fix_patch_intelligence.py
already emitted remediation blueprints, but two things were wrong:

* `fix_snippet` did not exist at all — a human had to re-derive the fix
  from the blueprint prose;
* the lookup ran against `rule_id` alone. SAST findings carry the engine's
  identifier there (JAVA_JDBC_SQL_CONCAT) while the semantic class lives in
  `vuln_type` (sql_injection), so even the blueprint resolved to the
  review placeholder instead of real advice.

WHAT THESE TESTS PIN
--------------------
* the finding itself carries fix_snippet, and the blueprint row mirrors it;
* candidate resolution: rule_id first, then vuln_type and friends, exact
  key beats substring coincidence;
* language resolution: declared language, then file extension, exact then
  curated `generic` fallback — and honest None where there is no idiom;
* the template never claims application: template=True, applied=False,
  human_review_required=True, patches_generated=0;
* the deepcopy contract: the caller's original findings are untouched.
"""
from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scanner.fix_patch_intelligence import (  # noqa: E402
    FIX_SNIPPET_MAP,
    _get_fix_snippet,
    _get_blueprint_from_finding,
    _finding_language,
    _rule_candidates,
    enrich_fix_patch_intelligence,
)

TOP_RULES = (
    "sql_injection", "command_injection", "xss", "path_traversal",
    "ssrf", "hardcoded_secret", "weak_crypto",
)
LANGUAGES = ("python", "java", "javascript")


def _finding(rule_id="RULE_X", vuln_type=None, file="app.py", language=None,
             finding_id=None):
    finding = {"rule_id": rule_id, "file": file}
    if vuln_type is not None:
        finding["vuln_type"] = vuln_type
    if language is not None:
        finding["language"] = language
    if finding_id is not None:
        finding["finding_id"] = finding_id
    return finding


def _enrich(*findings):
    payload = {"findings": [copy.deepcopy(f) for f in findings]}
    originals = copy.deepcopy(payload)
    enriched = enrich_fix_patch_intelligence(payload)
    return payload, originals, enriched


# ---------------------------------------------------------------------------
# Snippet coverage: top rules x benchmark languages, real idioms.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("rule", TOP_RULES)
@pytest.mark.parametrize("language", LANGUAGES)
def test_top_rules_have_snippets_in_all_three_languages(rule, language):
    snippet = _get_fix_snippet(rule, language)
    assert snippet is not None, (rule, language)
    assert snippet["language"] == language
    assert snippet["kind"]
    assert snippet["before"] and snippet["after"]
    assert snippet["before"] != snippet["after"], (rule, language)
    assert isinstance(snippet["placeholders"], list)


def test_snippet_map_is_json_serializable():
    for entry in FIX_SNIPPET_MAP.values():
        for lang_snippet in entry.values():
            assert json.loads(json.dumps(lang_snippet)) == lang_snippet


def test_snippet_lookup_still_works_for_a_plain_rule_string():
    assert _get_fix_snippet("CWE-89", "python")["kind"] == "parameterized_query"


def test_engine_vocabulary_is_the_canonical_key():
    """The engine emits vuln_type "weak_crypto" (verified against a real
    scan finding); the map must be keyed on that spelling. The OWASP-style
    "weak_cryptography" must resolve too."""
    engine_form = _get_fix_snippet("weak_crypto", "python")
    owasp_form = _get_fix_snippet("weak_cryptography", "python")
    assert engine_form is not None and owasp_form is not None
    assert engine_form["after"] == owasp_form["after"]


# ---------------------------------------------------------------------------
# Language resolution: declared, extension, generic fallback, honest None.
# ---------------------------------------------------------------------------

def test_declared_language_wins_over_extension():
    # Declared TypeScript against a .py file -> javascript snippet.
    assert _finding_language(_finding(file="app.py", language="TypeScript")) \
        == "javascript"


def test_extension_fallback_when_language_not_declared():
    assert _finding_language(_finding(file="svc/App.java")) == "java"
    assert _finding_language(_finding(file="src/x.js")) == "javascript"
    assert _finding_language(_finding(file="deploy.yml")) == "yaml"


def test_unknown_language_yields_no_language_not_a_guess():
    assert _finding_language(_finding(file="app.rb")) == ""


def test_language_neutral_transforms_resolve_without_a_language():
    snippet = _get_fix_snippet("vulnerable_dependency", "")
    assert snippet is not None
    assert snippet["language"] == "generic"
    assert snippet["kind"] == "version_bump"


def test_no_snippet_without_a_curated_idiom_is_an_absent_key_not_a_fabrication():
    # XSS has no ruby snippet and no generic entry: the answer is None.
    assert _get_fix_snippet("xss", "ruby") is None
    # An unresolvable rule likewise.
    assert _get_fix_snippet("custom_obscure_rule", "python") is None


# ---------------------------------------------------------------------------
# Candidate resolution: vuln_type carries the semantic class.
# ---------------------------------------------------------------------------

def test_candidates_collect_every_rule_bearing_field_strongest_first():
    finding = _finding(rule_id="JAVA_JDBC_SQL_CONCAT",
                       vuln_type="sql_injection", file="svc.java")
    candidates = _rule_candidates(finding)
    assert candidates[0] == "JAVA_JDBC_SQL_CONCAT"
    assert "sql_injection" in candidates


def test_engine_style_finding_resolves_through_vuln_type():
    """The real-world shape: rule_id says nothing, vuln_type says the class."""
    finding = _finding(rule_id="JAVA_JDBC_SQL_CONCAT",
                       vuln_type="sql_injection", file="svc.java")
    assert _get_blueprint_from_finding(finding).startswith(
        "Use parameterized queries")


def test_exact_semantic_key_beats_rule_id_substring_coincidence():
    # rule_id contains "x" fragments but vuln_type must decide: path_traversal
    # beats a rule_id that happens to contain "path".
    finding = _finding(rule_id="UNRELATED_PATH_PATHNAME",
                       vuln_type="path_traversal", file="io.py")
    assert _get_blueprint_from_finding(finding).startswith(
        "Validate and canonicalize")


def test_blueprint_falls_back_to_placeholder_when_nothing_resolves():
    finding = _finding(rule_id="TOTALLY_CUSTOM", file="weird.brainfuck")
    assert _get_blueprint_from_finding(finding) == \
        "REVIEW_FINDING_AND_APPLY_CONTEXT_APPROPRIATE_FIX"


# ---------------------------------------------------------------------------
# Enrichment integration: findings carry the snippet, rows mirror it.
# ---------------------------------------------------------------------------

def test_findings_carry_fix_snippet_and_rows_mirror_it():
    _, _, enriched = _enrich(_finding(rule_id="JAVA_JDBC_SQL_CONCAT",
                                      vuln_type="sql_injection",
                                      file="svc.java",
                                      finding_id="FINDING_STABLE_TEST_ID"))
    rows = enriched["fix_patch_intelligence"]["remediation_blueprints"]
    assert len(rows) == 1
    finding = enriched["findings"][0]
    assert finding["fix_snippet"]["kind"] == "parameterized_query"
    assert finding["fix_snippet"]["language"] == "java"
    assert rows[0]["fix_snippet"] == finding["fix_snippet"]
    # The row's finding_id is the deterministic identity (rule+file+line+
    # message), preserved verbatim when the finding already carries one.
    assert rows[0]["finding_id"] == "FINDING_STABLE_TEST_ID"
    assert rows[0]["rule"] == finding["rule_id"]


def test_snippet_never_claims_it_was_applied():
    _, _, enriched = _enrich(_finding(vuln_type="xss", file="page.js"))
    block = enriched["fix_patch_intelligence"]
    snippet = enriched["findings"][0]["fix_snippet"]
    assert snippet["template"] is True
    assert snippet["applied"] is False
    assert snippet["human_review_required"] is True
    assert block["summary"]["snippets_available"] == 1
    assert block["summary"]["patches_generated"] == 0
    assert block["read_only"] is True
    assert block["automatic_source_modification"] is False


def test_unmapped_finding_gets_no_snippet_key_and_none_in_the_row():
    _, _, enriched = _enrich(_finding(rule_id="TOTALLY_CUSTOM",
                                      file="weird.brainfuck"))
    finding = enriched["findings"][0]
    assert "fix_snippet" not in finding
    row = enriched["fix_patch_intelligence"]["remediation_blueprints"][0]
    assert row["fix_snippet"] is None
    assert enriched["fix_patch_intelligence"]["summary"][
        "snippets_available"] == 0


def test_original_payload_is_never_mutated():
    payload, originals, _ = _enrich(_finding(vuln_type="sqli", file="q.py"))
    assert payload == originals


def test_enrichment_is_deterministic():
    payload = {"findings": [_finding(vuln_type="ssrf", file="net.py")]}
    a = enrich_fix_patch_intelligence(copy.deepcopy(payload))
    b = enrich_fix_patch_intelligence(copy.deepcopy(payload))
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


def test_non_dict_findings_are_still_skipped():
    _, _, enriched = _enrich("not-a-finding", _finding(vuln_type="idor"))
    block = enriched["fix_patch_intelligence"]
    assert block["summary"]["findings"] == 1
    # idor is generic-only and language resolves to python via app.py:
    # exact "python" entry does not exist, generic does -> materializes.
    assert enriched["findings"][1]["fix_snippet"]["language"] == "generic"


def test_mixed_findings_get_independent_snippets():
    _, _, enriched = _enrich(
        _finding(vuln_type="sql_injection", file="a.py"),
        _finding(vuln_type="command_injection", file="b.java"),
        _finding(vuln_type="xss", file="c.rb"),  # no idiom -> absent
    )
    by_file = {f["file"]: f for f in enriched["findings"]}
    assert by_file["a.py"]["fix_snippet"]["language"] == "python"
    assert by_file["b.java"]["fix_snippet"]["language"] == "java"
    assert "fix_snippet" not in by_file["c.rb"]
    assert enriched["fix_patch_intelligence"]["summary"][
        "snippets_available"] == 2
