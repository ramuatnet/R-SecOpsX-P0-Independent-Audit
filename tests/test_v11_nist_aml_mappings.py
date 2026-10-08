"""Tests for the NIST AI 100-2e2025 (AML) taxonomy mapping.

Same anti-fabrication contract as the ATLAS mapping: a technique is claimed only
where the rule's own detection subject is that attack class, and every claim
carries a rationale.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core.nist_aml_mappings import (  # noqa: E402
    DIRECT,
    NISTAML_ATTACKS,
    NISTAML_DATASET_LABEL,
    NISTAML_DETECTION_GAPS,
    NISTAML_DOCUMENT,
    NISTAML_ENTRY_BY_RULE_ID,
    NISTAML_ENTRY_BY_VULN_TYPE,
    NISTAML_MAPPING_MODES,
    NISTAML_OBJECTIVES,
    NISTAML_PUBLISHED,
    NISTAML_UNCONFIRMED_TERMS,
    NISTAML_UNMAPPED_RATIONALE,
    RELATED,
    UNMAPPED,
    enrich_with_nistaml,
    nistaml_coverage,
    nistaml_reference,
)
from core.owasp_mappings import OWASP_LLM  # noqa: E402
from scanner.advanced_ai_security import (  # noqa: E402
    ADVANCED_AI_RULES,
    FILENAME_RULE_MAP,
)

ATTACK_ID = re.compile(r"^NISTAML\.\d{3}$")
OBJECTIVE_ID = re.compile(r"^NISTAML\.\d{2}$")


def _live_rule_ids():
    return {v[0] for v in FILENAME_RULE_MAP.values()} | {
        r["rule_id"] for r in ADVANCED_AI_RULES
    }


def _live_vuln_types():
    return {
        str(r.get("vuln_type") or "").strip().lower()
        for r in __import__("scanner.llm_security", fromlist=["LLM_RULES"]).LLM_RULES
    } - {""}


# ---------------------------------------------------------------------------
# Catalogue integrity
# ---------------------------------------------------------------------------
def test_document_is_pinned():
    assert NISTAML_DOCUMENT == "NIST AI 100-2e2025"
    assert NISTAML_PUBLISHED == "2025-03-24"
    assert NISTAML_PUBLISHED in NISTAML_DATASET_LABEL


def test_attack_ids_well_formed_and_objectives_resolve():
    for aid, spec in NISTAML_ATTACKS.items():
        assert ATTACK_ID.match(aid), f"malformed attack id {aid}"
        assert spec["objective"] in NISTAML_OBJECTIVES, f"{aid} unknown objective"
        assert spec["systems"], f"{aid} records no taxonomy membership"
        assert set(spec["systems"]) <= {"PredAI", "GenAI"}, aid


def test_objective_ids_are_well_formed():
    for oid in NISTAML_OBJECTIVES:
        assert OBJECTIVE_ID.match(oid), oid


def test_shared_identifier_is_declared_in_both_taxonomies():
    """Data Poisoning appears in both PredAI and GenAI; the catalogue must say so."""
    dp = NISTAML_ATTACKS["NISTAML.013"]
    assert set(dp["systems"]) == {"PredAI", "GenAI"}


def test_misuse_objective_is_not_invented():
    """Misuse is a real GenAI objective but its id was NOT confirmed."""
    assert "MISUSE" in NISTAML_UNCONFIRMED_TERMS
    assert not any(
        spec["objective"] == "NISTAML.04" for spec in NISTAML_ATTACKS.values()
    ), "an unconfirmed Misuse identifier must not be used"


def test_unconfirmed_terms_are_documented_not_silent():
    for term, note in NISTAML_UNCONFIRMED_TERMS.items():
        assert note.strip(), term


# ---------------------------------------------------------------------------
# Mapping integrity
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("entry", sorted(NISTAML_ENTRY_BY_RULE_ID))
def test_rule_mapping_is_defensible(entry):
    m = NISTAML_ENTRY_BY_RULE_ID[entry]
    assert m["attack"] in NISTAML_ATTACKS, f"{entry} -> unknown attack"
    assert m["mode"] in NISTAML_MAPPING_MODES
    assert len(m["rationale"].strip()) >= 40, f"{entry} rationale too thin"
    for rel in m.get("related") or ():
        assert rel in NISTAML_ATTACKS, f"{entry} -> unknown related {rel}"


@pytest.mark.parametrize("entry", sorted(NISTAML_ENTRY_BY_VULN_TYPE))
def test_vuln_type_mapping_is_defensible(entry):
    m = NISTAML_ENTRY_BY_VULN_TYPE[entry]
    assert m["attack"] in NISTAML_ATTACKS, f"{entry} -> unknown attack"
    assert m["mode"] in NISTAML_MAPPING_MODES
    assert len(m["rationale"].strip()) >= 40, f"{entry} rationale too thin"


def test_mapped_rules_exist_in_the_live_population():
    """No mapping may reference a rule id the scanner cannot emit."""
    stale = set(NISTAML_ENTRY_BY_RULE_ID) - _live_rule_ids()
    assert not stale, f"mapped rules that do not exist: {sorted(stale)}"


def test_mapped_vuln_types_are_real_catalogue_entries():
    stale = set(NISTAML_ENTRY_BY_VULN_TYPE) - {k.lower() for k in OWASP_LLM}
    assert not stale, f"mapped vuln types not in the OWASP catalogue: {sorted(stale)}"


def test_no_contradictory_disposition():
    assert not (set(NISTAML_ENTRY_BY_RULE_ID) & set(NISTAML_ENTRY_BY_VULN_TYPE))


def test_detection_gaps_reference_real_attack_ids():
    for aid, note in NISTAML_DETECTION_GAPS.items():
        assert aid in NISTAML_ATTACKS, f"{aid} is not in the catalogue"
        assert "detection gap" in note.lower(), aid


# ---------------------------------------------------------------------------
# Fail-closed behaviour
# ---------------------------------------------------------------------------
def test_unknown_rule_fails_closed():
    ref = nistaml_reference("NO_SUCH_RULE")
    assert ref["nistaml_mapping_mode"] == UNMAPPED
    assert ref["nistaml_id"] == ""
    assert ref["nistaml"] == ""
    assert ref["nistaml_objective"] == ""


def test_governance_rule_never_gets_an_attack_class():
    ref = nistaml_reference("GOV11_BIAS_ASSESSMENT_MISSING")
    assert ref["nistaml_mapping_mode"] == UNMAPPED
    assert ref["nistaml_id"] == ""
    assert "control" in ref["nistaml_rationale"].lower()


def test_membership_inference_is_direct():
    ref = nistaml_reference("ADV04_MEMBERSHIP_INFERENCE")
    assert ref["nistaml_id"] == "NISTAML.033"
    assert ref["nistaml_mapping_mode"] == DIRECT
    assert ref["nistaml_objective"] == "NISTAML.03"
    assert ref["nistaml_objective_name"] == "Privacy Compromises"


def test_prompt_injection_names_both_direct_and_indirect():
    ref = nistaml_reference("", "llm_prompt_injection")
    assert ref["nistaml_id"] == "NISTAML.018"
    assert "NISTAML.015" in ref["nistaml_related"]
    assert "neither is claimed alone" in ref["nistaml_rationale"]


def test_every_reference_carries_the_document_pin():
    for rid in list(_live_rule_ids()) + ["UNKNOWN"]:
        ref = nistaml_reference(rid)
        assert ref["nistaml_document"] == NISTAML_DOCUMENT
        assert ref["nistaml_published"] == NISTAML_PUBLISHED
        assert ref["nistaml_dataset"] == NISTAML_DATASET_LABEL


def test_enrich_is_idempotent():
    a = {"rule_id": "ADV04_MEMBERSHIP_INFERENCE", "vuln_type": "x"}
    b = dict(a)
    enrich_with_nistaml(a)
    enrich_with_nistaml(b)
    assert a == b


def test_enrich_does_not_drop_existing_fields():
    from scanner.advanced_ai_security import scan_advanced_ai_file

    f = scan_advanced_ai_file("ADV04_membership_inference.py", "# probe\n")[0]
    for key in ("rule_id", "title", "severity", "contract_only", "atlas_id",
                "atlas_mapping_mode"):
        assert key in f, f"NISTAML enrichment dropped existing key {key}"


def test_coverage_report_is_consistent():
    cov = nistaml_coverage(
        rule_ids=sorted(_live_rule_ids()), vuln_types=sorted(_live_vuln_types())
    )
    for fam in ("advanced_ai", "owasp_llm"):
        f = cov[fam]
        assert f["total"] == len(f["mapped"]) + len(f["unmapped"])
        assert set(f["by_mode"]) <= set(NISTAML_MAPPING_MODES)
    c = cov["combined"]
    assert c["total"] == cov["advanced_ai"]["total"] + cov["owasp_llm"]["total"]
    for aid in cov["attacks_referenced"]:
        assert aid in NISTAML_ATTACKS


def test_default_unmapped_rationale_is_substantive():
    assert len(NISTAML_UNMAPPED_RATIONALE) >= 80
    assert "adversary technique against a trained model" in NISTAML_UNMAPPED_RATIONALE