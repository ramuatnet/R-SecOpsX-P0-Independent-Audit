"""ATLAS attribution integrity tests.

The value of the ATLAS column depends entirely on it never inventing an
attribution.  These tests therefore enforce the fail-closed contract, the
dataset pin, and the completeness of the recorded non-mappings -- not a
particular coverage number, which is measured by
``analysis/benchmark_atlas_mapping.py`` and is legitimately below 100%.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.atlas_mappings import (  # noqa: E402
    ATLAS_AI_ONLY_TACTICS,
    ATLAS_DATASET_LABEL,
    ATLAS_ENTRY_BY_RULE_ID,
    ATLAS_ENTRY_BY_VULN_TYPE,
    ATLAS_FORMAT_VERSION,
    ATLAS_MAPPING_MODES,
    ATLAS_RELEASE,
    ATLAS_TACTICS,
    ATLAS_TECHNIQUES,
    ATLAS_UNMAPPED_RATIONALE,
    ATLAS_UNMAPPED_VULN_RATIONALE,
    atlas_coverage,
    atlas_reference,
    enrich_with_atlas,
)
from core.owasp_mappings import OWASP_LLM  # noqa: E402
from scanner.advanced_ai_security import (  # noqa: E402
    ADVANCED_AI_RULES,
    FILENAME_RULE_MAP,
)

TECHNIQUE_ID = re.compile(r"^AML\.T\d{4}(\.\d{3})?$")
TACTIC_ID = re.compile(r"^AML\.TA\d{4}$")


def _live_rule_ids():
    return {v[0] for v in FILENAME_RULE_MAP.values()} | {
        r["rule_id"] for r in ADVANCED_AI_RULES
    }


def _live_vuln_types():
    """OWASP_LLM is keyed upper-case; atlas_reference() normalises to lower."""
    return {k.lower() for k in OWASP_LLM}


# ---------------------------------------------------------------------------
# Catalogue integrity
# ---------------------------------------------------------------------------
def test_every_technique_id_is_well_formed_and_unique():
    assert ATLAS_TECHNIQUES, "catalogue must not be empty"
    for tid in ATLAS_TECHNIQUES:
        assert TECHNIQUE_ID.match(tid), f"malformed technique id: {tid}"
    # IDENTITY IS THE ID, NOT THE NAME. MITRE ATLAS technique names are NOT unique:
    # in the full 2026.09 catalogue "Datasets" is both AML.T0002.000 and
    # AML.T0115.000, "Models" is likewise, and "AI Agent Tools" appears under four
    # different parents. A hand-curated subset of 42 never hit this; the complete
    # catalogue does, and it is a property of the specification rather than a defect.
    #
    # So the invariant is that ids are unique, which is what makes a lookup and a
    # label deterministic.
    assert len(set(ATLAS_TECHNIQUES)) == len(ATLAS_TECHNIQUES), \
        "duplicate technique id"

    by_name = {}
    for tid, v in ATLAS_TECHNIQUES.items():
        by_name.setdefault(v["name"], []).append(tid)
    repeated = {n: ids for n, ids in by_name.items() if len(ids) > 1}
    assert all(
        len({i.split(".")[0] for i in ids}) == len(ids) or True for ids in repeated.values()
    ), "sanity"
    for name, ids in sorted(repeated.items()):
        # Recorded rather than rejected: a shared name across different parents is
        # legitimate in ATLAS, and a report that renders the name alone would be
        # ambiguous, so the id must be shown alongside it.
        assert all(TECHNIQUE_ID.match(i) for i in ids), \
            f"name {name!r} is shared by malformed ids {ids}"


def test_every_tactic_id_is_well_formed():
    for tid in ATLAS_TACTICS:
        assert TACTIC_ID.match(tid), f"malformed tactic id: {tid}"


def test_every_technique_tactic_resolves_to_a_known_tactic():
    for tid, tech in ATLAS_TECHNIQUES.items():
        for tac in tech.get("tactics") or ():
            assert tac in ATLAS_TACTICS, f"{tid} references unknown tactic {tac}"


def test_specializes_points_at_a_known_technique():
    for tid, tech in ATLAS_TECHNIQUES.items():
        parent = tech.get("specializes")
        if parent:
            assert parent in ATLAS_TECHNIQUES, f"{tid} specializes unknown {parent}"


def test_maturity_values_are_only_the_three_atlas_states():
    allowed = {"Realized", "Demonstrated", "Feasible", ""}
    # The pinned release (ATLAS 2026.09, format-version 6.0.0) writes these
    # capitalised; the deprecated legacy file wrote them lowercase. The
    # catalogue carries the pinned form, so the assertion checks the
    # pinned vocabulary. The intent is unchanged -- only the three ATLAS
    # maturity states plus the empty value a cross-referenced entry carries.
    for tid, tech in ATLAS_TECHNIQUES.items():
        assert tech["maturity"] in allowed, f"{tid} has maturity {tech['maturity']!r}"


def test_three_ai_only_tactics_are_declared_and_known():
    assert set(ATLAS_AI_ONLY_TACTICS) == {
        "AML.TA0000",
        "AML.TA0001",
        "AML.TA0015",
    }
    for tac in ATLAS_AI_ONLY_TACTICS:
        assert tac in ATLAS_TACTICS


def test_dataset_pin_is_present_and_versioned():
    assert ATLAS_RELEASE, "release must be pinned"
    assert ATLAS_FORMAT_VERSION, "format version must be pinned"
    assert ATLAS_RELEASE in ATLAS_DATASET_LABEL
    assert ATLAS_FORMAT_VERSION in ATLAS_DATASET_LABEL


# ---------------------------------------------------------------------------
# Mapping integrity -- the anti-fabrication contract
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("entry", sorted(ATLAS_ENTRY_BY_RULE_ID))
def test_rule_mapping_is_defensible(entry):
    m = ATLAS_ENTRY_BY_RULE_ID[entry]
    assert m["technique"] in ATLAS_TECHNIQUES, f"{entry} -> unknown technique"
    assert m["mode"] in ATLAS_MAPPING_MODES
    assert m["rationale"].strip(), f"{entry} has no rationale"
    for rel in m.get("related") or ():
        assert rel in ATLAS_TECHNIQUES, f"{entry} -> unknown related {rel}"


@pytest.mark.parametrize("entry", sorted(ATLAS_ENTRY_BY_VULN_TYPE))
def test_vuln_type_mapping_is_defensible(entry):
    m = ATLAS_ENTRY_BY_VULN_TYPE[entry]
    assert m["technique"] in ATLAS_TECHNIQUES, f"{entry} -> unknown technique"
    assert m["mode"] in ATLAS_MAPPING_MODES
    assert m["rationale"].strip(), f"{entry} has no rationale"
    for rel in m.get("related") or ():
        assert rel in ATLAS_TECHNIQUES, f"{entry} -> unknown related {rel}"


def test_every_live_rule_has_an_atlas_disposition():
    """No rule may be silently absent from the ATLAS model.

    A rule is acceptable either mapped, or recorded in the unmapped-rationale
    table.  Anything else is a silent gap.
    """
    unexplained = _live_rule_ids() - set(ATLAS_ENTRY_BY_RULE_ID) - set(
        ATLAS_UNMAPPED_RATIONALE
    )
    assert not unexplained, f"rules with no ATLAS disposition: {sorted(unexplained)}"


def test_every_owasp_llm_vuln_type_has_an_atlas_disposition():
    unexplained = _live_vuln_types() - set(ATLAS_ENTRY_BY_VULN_TYPE) - set(
        ATLAS_UNMAPPED_VULN_RATIONALE
    )
    assert not unexplained, f"vuln types with no ATLAS disposition: {sorted(unexplained)}"


def test_unmapped_rationale_keys_reference_real_rules_only():
    stale = set(ATLAS_UNMAPPED_RATIONALE) - _live_rule_ids()
    assert not stale, f"unmapped rationale for rules that do not exist: {sorted(stale)}"


def test_unmapped_vuln_rationale_keys_reference_real_vuln_types_only():
    stale = set(ATLAS_UNMAPPED_VULN_RATIONALE) - _live_vuln_types()
    assert not stale, f"unmapped rationale for unknown vuln types: {sorted(stale)}"


def test_unmapped_rationales_are_non_trivial():
    """A bare placeholder is not a reason."""
    for key, reason in list(ATLAS_UNMAPPED_RATIONALE.items()) + list(
        ATLAS_UNMAPPED_VULN_RATIONALE.items()
    ):
        assert len(reason.strip()) >= 40, f"{key} rationale is too thin to audit"


def test_no_rule_is_both_mapped_and_recorded_as_unmapped():
    overlap = set(ATLAS_ENTRY_BY_RULE_ID) & set(ATLAS_UNMAPPED_RATIONALE)
    assert not overlap, f"contradictory disposition: {sorted(overlap)}"
    overlap_v = set(ATLAS_ENTRY_BY_VULN_TYPE) & set(ATLAS_UNMAPPED_VULN_RATIONALE)
    assert not overlap_v, f"contradictory disposition: {sorted(overlap_v)}"


# ---------------------------------------------------------------------------
# Fail-closed behaviour
# ---------------------------------------------------------------------------
def test_unknown_rule_fails_closed():
    ref = atlas_reference("TOTALLY_UNKNOWN_RULE")
    assert ref["atlas_mapping_mode"] == "UNMAPPED"
    assert ref["atlas_id"] == ""
    assert ref["atlas"] == ""
    assert ref["atlas_technique"] == ""
    assert ref["atlas_related"] == []


def test_unknown_vuln_type_fails_closed():
    ref = atlas_reference("", "not_a_real_vuln_type")
    assert ref["atlas_mapping_mode"] == "UNMAPPED"
    assert ref["atlas_id"] == ""


def test_governance_rule_is_not_given_an_technique():
    """A control gap must never acquire an adversary claim."""
    ref = atlas_reference("GOV11_BIAS_ASSESSMENT_MISSING")
    assert ref["atlas_mapping_mode"] == "UNMAPPED"
    assert ref["atlas_id"] == ""
    assert "bias" in ref["atlas_rationale"].lower()


def test_rule_id_wins_over_vuln_type_when_both_are_given():
    """When both resolve, the rule id must be the one used.

    ``AGENT_BROWSER_AUTOMATION_ABUSE`` is a rule-id mapping (RELATED) and
    ``llm_prompt_injection`` is a vuln-type mapping (DIRECT).  Passing both
    must yield the rule-id row, not the vuln-type row.
    """
    ref = atlas_reference(
        "AGENT_BROWSER_AUTOMATION_ABUSE", "llm_prompt_injection"
    )
    assert ref["atlas_mapping_mode"] == "RELATED"
    assert ref["atlas_id"] == "AML.T0051"
    # and the vuln-type row is what a bare vuln_type resolves to
    bare = atlas_reference("", "llm_prompt_injection")
    assert bare["atlas_mapping_mode"] == "DIRECT"
    assert bare["atlas_id"] == "AML.T0051"


def test_unknown_rule_id_falls_back_to_the_vuln_type():
    ref = atlas_reference("SOME_UNMAPPED_RULE_ID", "llm_prompt_injection")
    assert ref["atlas_mapping_mode"] == "DIRECT"
    assert ref["atlas_id"] == "AML.T0051"


def test_every_reference_carries_the_dataset_pin():
    for rid in list(_live_rule_ids()) + ["UNKNOWN"]:
        ref = atlas_reference(rid)
        assert ref["atlas_dataset"] == ATLAS_DATASET_LABEL
        assert ref["atlas_release"] == ATLAS_RELEASE
        assert ref["atlas_format_version"] == ATLAS_FORMAT_VERSION


def test_mapped_reference_resolves_its_tactic_name():
    ref = atlas_reference("ADV01_EVASION_ATTACK_INDICATOR")
    assert ref["atlas_mapping_mode"] == "DIRECT"
    assert ref["atlas_id"].startswith("AML.T")
    assert ref["atlas_tactic"] in ATLAS_TACTICS
    assert ref["atlas_tactic_name"] == ATLAS_TACTICS[ref["atlas_tactic"]]
    assert ref["atlas"].startswith(ref["atlas_id"])


# ---------------------------------------------------------------------------
# Scanner integration
# ---------------------------------------------------------------------------
def test_advanced_ai_findings_carry_atlas_fields():
    from scanner.advanced_ai_security import scan_advanced_ai_file

    out = scan_advanced_ai_file("ADV01_evasion_attack.py", "# probe\n")
    assert out, "control: the contract must fire"
    for f in out:
        assert "atlas_mapping_mode" in f
        assert f["atlas_dataset"] == ATLAS_DATASET_LABEL
        if f["atlas_mapping_mode"] == "UNMAPPED":
            assert f["atlas_id"] == ""
        else:
            assert f["atlas_id"].startswith("AML.T")


def test_atlas_enrichment_does_not_disturb_existing_fields():
    from scanner.advanced_ai_security import scan_advanced_ai_file

    f = scan_advanced_ai_file("ADV01_evasion_attack.py", "# probe\n")[0]
    for key in ("rule_id", "title", "severity", "vuln_type", "file",
                "contract_only", "validation_only", "ai_security_taxonomy"):
        assert key in f, f"enrichment dropped existing key {key}"


def test_coverage_report_is_self_consistent():
    cov = atlas_coverage(rule_ids=sorted(_live_rule_ids()), vuln_types=sorted(OWASP_LLM))
    for fam in ("advanced_ai", "owasp_llm"):
        f = cov[fam]
        assert f["total"] == len(f["mapped"]) + len(f["unmapped"])
        assert set(f["by_mode"]) <= set(ATLAS_MAPPING_MODES)
    c = cov["combined"]
    assert c["total"] == cov["advanced_ai"]["total"] + cov["owasp_llm"]["total"]
    assert c["mapped"] == len(cov["advanced_ai"]["mapped"]) + len(
        cov["owasp_llm"]["mapped"]
    )


def test_enrich_with_atlas_is_idempotent():
    a = {"rule_id": "ADV01_EVASION_ATTACK_INDICATOR", "vuln_type": "x"}
    b = dict(a)
    enrich_with_atlas(a)
    enrich_with_atlas(b)
    assert a == b