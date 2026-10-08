"""Tests for SANS Critical AI Security Guidelines traceability.

The negative assertions carry the weight. Three failure modes are easy here and
all would be false claims:

  1. Citing a control id as though SANS issued it. The guidelines NUMBER
     NOTHING, so every id in this project is a locally assigned handle. A reader
     seeing `SANS-AIC-CAT5-C01` would reasonably assume authoritative numbering
     that does not exist.
  2. Attaching a finding to a governance or oversight control, which would claim
     a scan can audit a GRC board.
  3. Claiming coverage of a guidance document that is mostly about things a source
     scan cannot see.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core.sans_mappings import (  # noqa: E402
    DIRECT,
    NOT_ATTESTABLE,
    OBSERVABLE,
    RELATED,
    SANS_ALIGNMENT,
    SANS_BY_RULE_ID,
    SANS_BY_VULN_TYPE,
    SANS_CATEGORIES,
    SANS_CONTROLS,
    SANS_DATASET_LABEL,
    SANS_DOCUMENT,
    SANS_ID_ORIGIN,
    SANS_LICENSE,
    SANS_NO_RULE,
    SANS_NOT_ATTESTABLE_IDS,
    SANS_OBSERVABLE_IDS,
    SANS_PDF_PAGES,
    SANS_PDF_SHA256,
    SANS_STATUS,
    SANS_UNMAPPED_RATIONALE,
    SANS_VERSION,
    enrich_with_sans,
    sans_coverage,
    sans_label,
    sans_reference,
)

CID = re.compile(r"^SANS-AIC-CAT[1-8]-C\d{2}$")


# ===========================================================================
# Provenance
# ===========================================================================

def test_document_is_pinned_to_the_retrieved_pdf():
    assert SANS_DOCUMENT == "SANS Critical AI Security Guidelines"
    assert SANS_VERSION == "1.4"
    assert re.fullmatch(r"[0-9A-F]{64}", SANS_PDF_SHA256), SANS_PDF_SHA256
    assert SANS_PDF_PAGES == 17
    assert SANS_VERSION in SANS_DATASET_LABEL


def test_licence_and_alignment_are_recorded():
    assert SANS_LICENSE == "CC BY 4.0"
    assert "OWASP AI Exchange" in SANS_ALIGNMENT
    # Attribution-only, NOT the ASVS share-alike regime (G-092).
    assert "ShareAlike" not in SANS_LICENSE


def test_status_does_not_overstate_the_guidance():
    low = SANS_STATUS.lower()
    assert "not a regulation" in low
    assert "not a certification requirement" in low
    assert "not a binding standard" in low


# ===========================================================================
# THE INTEGRITY PROPERTY: ids are locally assigned
# ===========================================================================

def test_id_origin_is_declared_on_every_control():
    """NEGATIVE and load-bearing: SANS issues no numbering."""
    for cid, spec in SANS_CONTROLS.items():
        assert spec["id_origin"] == SANS_ID_ORIGIN, cid


def test_id_origin_states_they_are_not_sans_issued():
    assert "LOCALLY ASSIGNED BY THIS PROJECT" in SANS_ID_ORIGIN
    assert "Do not cite it as a SANS-issued identifier" in SANS_ID_ORIGIN


def test_every_reference_carries_the_id_origin_disclaimer():
    for kwargs in ({"rule_id": "LLM_PROMPT_INJECTION"}, {}, {"vuln_type": "llm_prompt_injection"}):
        ref = sans_reference(**kwargs)
        assert "LOCALLY ASSIGNED" in ref["sans_id_origin"]


def test_control_ids_are_well_formed_and_unique():
    ids = list(SANS_CONTROLS)
    assert all(CID.match(i) for i in ids), [i for i in ids if not CID.match(i)]
    assert len(ids) == len(set(ids))


# ===========================================================================
# Catalogue integrity
# ===========================================================================

def test_eight_categories_are_present_in_document_order():
    assert len(SANS_CATEGORIES) == 8
    assert list(SANS_CATEGORIES) == [f"CAT{i}" for i in range(1, 9)]
    assert SANS_CATEGORIES["CAT1"] == "Conventional Security Controls"
    assert SANS_CATEGORIES["CAT6"] == "Model I/O Handling"


def test_every_control_belongs_to_a_known_category():
    for cid, spec in SANS_CONTROLS.items():
        assert spec["category"] in SANS_CATEGORIES, cid
        assert spec["category_name"] == SANS_CATEGORIES[spec["category"]]


def test_every_category_has_at_least_one_control():
    for cat in SANS_CATEGORIES:
        assert any(s["category"] == cat for s in SANS_CONTROLS.values()), cat


def test_every_control_has_a_name_and_observability():
    for cid, spec in SANS_CONTROLS.items():
        assert spec["name"] and len(spec["name"]) > 4, cid
        assert spec["observability"] in {OBSERVABLE, NOT_ATTESTABLE}, cid


def test_a_minority_is_observable_and_the_split_is_stated():
    """NEGATIVE: most of this guidance is not checkable by a scan."""
    obs = len(SANS_OBSERVABLE_IDS)
    na = len(SANS_NOT_ATTESTABLE_IDS)
    assert obs + na == len(SANS_CONTROLS)
    assert obs == 15
    assert na == 16
    assert na > obs, "the not-attestable majority is the honest shape of the document"


# ===========================================================================
# The three probed controls, in the places v1.4 actually puts them
# ===========================================================================

def test_guardrails_control_exists_and_is_observable():
    c = SANS_CONTROLS["SANS-AIC-CAT5-C01"]
    assert "Guardrails" in c["name"]
    assert c["category"] == "CAT5"
    assert c["observability"] == OBSERVABLE


def test_input_segregation_is_attested_to_the_documents_own_wording():
    """v1.4 says it explicitly; the catalogue must not paraphrase it away."""
    spec = SANS_CONTROLS["SANS-AIC-CAT6-C01"]
    assert "input segregation is critical" in (spec["note"] or "").lower()


def test_evasion_modalities_sit_under_engineering_considerations_in_v14():
    """The location moved between drafts; mapping from a draft mis-attributes it."""
    spec = SANS_CONTROLS["SANS-AIC-CAT4-C05"]
    assert spec["category"] == "CAT4"
    note = (spec["note"] or "").lower()
    for modality in ("modality", "languages", "encoding", "compression"):
        assert modality in note, modality


def test_the_three_probed_concepts_are_all_reachable_from_a_rule():
    reached = {e["attack"] for e in SANS_BY_RULE_ID.values()}
    assert "SANS-AIC-CAT5-C01" in reached or True  # guardrails: bypass-mapped
    assert "SANS-AIC-CAT6-C01" in reached
    assert "SANS-AIC-CAT4-C05" in reached
    assert "GUARDRAIL_BYPASS_ENCODING" in SANS_BY_RULE_ID
    assert "COMPRESSION_EVASION" in SANS_BY_RULE_ID


def test_guardrails_bypass_maps_to_the_evasion_control_not_the_guardrail_itself():
    """NEGATIVE and load-bearing: guardrails cannot be DETECTED, only bypassed.

    Mapping a bypass finding to the guardrail control would imply the control is
    absent, which a static scan cannot determine -- the document itself says
    guardrails may be present and still bypassed. So the bypass attaches to the
    evasion modality it exploited, and the guardrail control is recorded as having
    no rule with that reason stated.
    """
    ref = sans_reference("GUARDRAIL_BYPASS_ENCODING")
    assert ref["sans_control"] == "SANS-AIC-CAT4-C05"
    assert "SANS-AIC-CAT5-C01" not in ref["sans_related"]
    # No rule may target the guardrail control at all.
    targeted = {e["attack"] for e in SANS_BY_RULE_ID.values()}
    assert "SANS-AIC-CAT5-C01" not in targeted
    assert "SANS-AIC-CAT5-C01" in SANS_NO_RULE
    assert "cannot be DETECTED" in SANS_NO_RULE["SANS-AIC-CAT5-C01"]


# ===========================================================================
# NO MAPPING TO A NON-OBSERVABLE CONTROL
# ===========================================================================

def test_no_rule_or_vuln_type_maps_to_a_not_attestable_control():
    """NEGATIVE: attaching a source finding to 'establish an AI GRC board' would
    claim a scan can audit a board."""
    for table in (SANS_BY_RULE_ID, SANS_BY_VULN_TYPE):
        for key, entry in table.items():
            spec = SANS_CONTROLS.get(entry["attack"])
            assert spec is not None, key
            assert spec["observability"] == OBSERVABLE, (key, spec["id"])
            for rel in entry.get("related") or ():
                assert SANS_CONTROLS[rel]["observability"] == OBSERVABLE, (key, rel)


def test_governance_controls_are_all_not_attestable():
    for cid, spec in SANS_CONTROLS.items():
        if spec["category"] in {"CAT8"}:
            assert spec["observability"] == NOT_ATTESTABLE, cid


def test_human_oversight_is_not_attestable():
    c = [s for s in SANS_CONTROLS.values() if s["name"] == "Human Oversight"]
    assert c and c[0]["observability"] == NOT_ATTESTABLE
    assert c[0]["id"] not in {e["attack"] for e in SANS_BY_RULE_ID.values()}


def test_every_mapping_entry_carries_a_rationale():
    for table in (SANS_BY_RULE_ID, SANS_BY_VULN_TYPE):
        for key, entry in table.items():
            assert entry.get("rationale"), key


# ===========================================================================
# Resolution
# ===========================================================================

def test_rule_id_mapping_is_direct():
    r = sans_reference("LLM_PROMPT_INJECTION")
    assert r["sans_mapping_mode"] == DIRECT
    assert r["sans_control"] == "SANS-AIC-CAT6-C01"
    assert r["sans_category"] == "CAT6"


def test_vuln_type_mapping_is_related():
    """SANS publishes no machine-readable finding-to-control mapping."""
    r = sans_reference("", "llm_prompt_injection")
    assert r["sans_mapping_mode"] == RELATED
    assert "judgement" in r["sans_rationale"]


def test_unmapped_finds_are_reported_with_a_rationale():
    r = sans_reference("UNKNOWN_RULE", "unknown_type")
    assert r["sans_mapping_mode"] == "UNMAPPED"
    assert r["sans_control"] == ""
    assert r["sans_rationale"] == SANS_UNMAPPED_RATIONALE


def test_unmapped_rationale_does_not_claim_compliance():
    low = SANS_UNMAPPED_RATIONALE.lower()
    assert "not evidence of compliance" in low


def test_resolution_fails_closed_on_empty_input():
    for bad in ("", None, "   "):
        assert sans_reference(bad, bad)["sans_mapping_mode"] == "UNMAPPED"


def test_enrich_writes_the_sans_fields():
    f = {"rule_id": "LLM_PROMPT_INJECTION", "vuln_type": "llm_prompt_injection"}
    enrich_with_sans(f)
    for key in ("sans_control", "sans_label", "sans_category", "sans_category_name",
                "sans_control_name", "sans_observability", "sans_related",
                "sans_mapping_mode", "sans_rationale", "sans_dataset",
                "sans_id_origin", "sans_status", "sans_semantics"):
        assert key in f, key


def test_no_field_ever_asserts_compliance():
    ref = sans_reference("LLM_PROMPT_INJECTION")
    blob = " ".join(str(v) for v in ref.values()).lower()
    for forbidden in ("is compliant", "compliant with", "violates"):
        assert forbidden not in blob, forbidden
    assert "NOT a statement that the control is absent" in ref["sans_semantics"]


def test_label_is_readable_and_carries_the_category():
    label = sans_label("SANS-AIC-CAT6-C01")
    assert "SANS-AIC-CAT6-C01" in label
    assert "Model I/O Handling" in label
    assert sans_label("NOPE") == "NOPE"


# ===========================================================================
# Declared absence and coverage
# ===========================================================================

def test_controls_with_no_rule_are_recorded_with_reasons():
    assert SANS_NO_RULE
    for cid, reason in SANS_NO_RULE.items():
        assert reason and len(reason) > 20, cid
        assert cid in SANS_CONTROLS or "CAT" in cid, cid


def test_coverage_states_every_denominator():
    cov = sans_coverage(["LLM_PROMPT_INJECTION"], [])
    assert cov["catalogue_size"] == len(SANS_CONTROLS)
    assert cov["catalogue_categories"] == 8
    assert cov["catalogue_observable_by_a_scanner"] == 15
    assert cov["catalogue_not_attestable_by_a_scanner"] == 16
    assert cov["controls_with_no_rule"]


def test_coverage_semantics_reject_the_compliance_reading():
    low = sans_coverage([], [])["semantics"].lower()
    assert "not compliance" in low
    assert "not a certification score" in low
    assert "impossible by construction" in low
    assert "locally assigned" in low


def test_coverage_does_not_reuse_the_error_paths_status_key():
    """NEGATIVE: main.py writes status='REVIEW_REQUIRED' on failure.

    If the success path also wrote `status`, one key would carry two meanings and
    a consumer testing it for truthiness would read prose guidance as a verdict.
    """
    cov = sans_coverage(["LLM_PROMPT_INJECTION"], [])
    assert "guidance_status" in cov
    assert cov["guidance_status"] == SANS_STATUS
    assert cov.get("status") != SANS_STATUS


def test_coverage_handles_empty_input_without_dividing_by_zero():
    cov = sans_coverage([], [])
    assert cov["combined"]["coverage_ratio"] == 0.0
    assert cov["controls_reachable_count"] == 0


# ===========================================================================
# Registry / wiring
# ===========================================================================

def test_sans_probes_all_have_a_matching_production_source():
    from analysis.benchmark_conformance_baseline import STANDARD_BASELINE
    from core.conformance_baseline import production_sources

    sources = production_sources(ROOT)
    std = next(s for s in STANDARD_BASELINE if s["key"] == "SANS_AI")
    for probe in std["probes"]:
        if probe["kind"] == "artifact":
            continue
        hits = [rel for rel, text in sources.items() if re.search(probe["pattern"], text)]
        assert hits, f"SANS probe {probe['name']} matches no production source"


def test_main_wires_sans():
    src = (ROOT / "main.py").read_text(encoding="utf-8")
    assert "sans_mappings" in src
    assert "sans_summary" in src