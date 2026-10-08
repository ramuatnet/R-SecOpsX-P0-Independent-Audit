"""Tests for RBI FREE-AI traceability.

The negative assertions carry the weight here. FREE-AI is a committee report
addressed to Indian financial-sector regulated entities, so the three easy ways
to be wrong are:

  1. presenting it as a binding regulatory obligation,
  2. implying it applies to whatever codebase happened to be scanned,
  3. counting its 16 organisational recommendations as "covered" by a source scan.

Each is pinned below.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core.free_ai_mappings import (  # noqa: E402
    DIRECT,
    FREE_AI_APPLICABILITY,
    FREE_AI_BY_RULE_ID,
    FREE_AI_BY_VULN_TYPE,
    FREE_AI_LEGAL_STATUS,
    FREE_AI_NO_RULE,
    FREE_AI_NOT_ATTESTABLE_IDS,
    FREE_AI_OBSERVABLE_IDS,
    FREE_AI_PUBLISHED,
    FREE_AI_PILLARS,
    FREE_AI_RECOMMENDATIONS,
    FREE_AI_SOURCE_URL,
    FREE_AI_SUTRAS,
    FREE_AI_UNMAPPED_RATIONALE,
    NOT_ATTESTABLE,
    OBSERVABLE,
    RELATED,
    UNMAPPED,
    enrich_with_free_ai,
    free_ai_coverage,
    free_ai_label,
    free_ai_reference,
)

REC_ID = re.compile(r"^FREE_AI_REC_(\d{1,2})$")


# ===========================================================================
# Catalogue provenance
# ===========================================================================

def test_publication_is_pinned_to_the_committee_report():
    assert FREE_AI_PUBLISHED == "2025-08-13"
    assert "PublicationReportDetails.aspx?ID=1306" in FREE_AI_SOURCE_URL


def test_all_twenty_six_recommendations_are_catalogued():
    assert len(FREE_AI_RECOMMENDATIONS) == 26
    numbers = sorted(r["number"] for r in FREE_AI_RECOMMENDATIONS.values())
    assert numbers == list(range(1, 27)), numbers


def test_all_seven_sutras_are_catalogued():
    assert len(FREE_AI_SUTRAS) == 7
    assert set(FREE_AI_SUTRAS) == {f"SUTRA_{n}" for n in range(1, 8)}


def test_sutra_titles_are_the_reports_own():
    titles = {s["title"] for s in FREE_AI_SUTRAS.values()}
    assert titles == {
        "Trust is the Foundation",
        "People First",
        "Innovation over Restraint",
        "Fairness and Equity",
        "Accountability",
        "Understandable by Design",
        "Safety, Resilience, and Sustainability",
    }


def test_six_pillars_partition_the_recommendations_exactly_once():
    seen = []
    for pillar in FREE_AI_PILLARS.values():
        seen.extend(pillar["recs"])
    assert sorted(seen) == list(range(1, 27)), sorted(seen)
    assert len(FREE_AI_PILLARS) == 6


def test_every_recommendation_belongs_to_a_known_pillar():
    for rec in FREE_AI_RECOMMENDATIONS.values():
        assert rec["pillar"] in FREE_AI_PILLARS, rec["id"]
        assert FREE_AI_PILLARS[rec["pillar"]]["recs"], rec["id"]
        assert rec["number"] in FREE_AI_PILLARS[rec["pillar"]]["recs"]


def test_every_recommendation_has_a_title():
    for rec in FREE_AI_RECOMMENDATIONS.values():
        assert rec["title"] and len(rec["title"]) > 4, rec["id"]


def test_uncaptured_actor_tags_are_empty_not_guessed():
    """16 of 26 actor tags were recoverable from the source. The other 10 must be
    empty; filling them with a plausible guess is the failure this guards."""
    captured = [r for r in FREE_AI_RECOMMENDATIONS.values() if r["actors"]]
    assert len(captured) == 16, len(captured)
    for rec in FREE_AI_RECOMMENDATIONS.values():
        if not rec["actors"]:
            assert rec["actors"] == ""


# ===========================================================================
# LEGAL STATUS -- the first negative
# ===========================================================================

def test_legal_status_says_it_is_not_binding():
    assert "NOT a binding RBI direction" in FREE_AI_LEGAL_STATUS
    assert "Master Direction" in FREE_AI_LEGAL_STATUS


def test_every_reference_carries_the_legal_status_and_applicability():
    """NEGATIVE: an attribution without the legal status reads as an obligation."""
    for kwargs in (
        {"rule_id": "VDB_VECTOR_DB_EXPOSURE"},
        {"vuln_type": "vector_database_exposure"},
        {},
    ):
        ref = free_ai_reference(**kwargs)
        assert "NOT a binding RBI direction" in ref["free_ai_legal_status"]
        assert "regulated entities" in ref["free_ai_applicability"]


def test_applicability_to_the_corpus_is_never_asserted():
    """NEGATIVE and load-bearing: this tool scans arbitrary codebases. It must
    never claim the corpus is in scope of an RBI committee report."""
    for kwargs in ({"rule_id": "VDB_VECTOR_DB_EXPOSURE"}, {"vuln_type": "llm_prompt_injection"}):
        assert free_ai_reference(**kwargs)["free_ai_applicable_to_corpus"] is False


def test_no_compliance_verdict_is_ever_emitted():
    """NEGATIVE: no field may say met, unmet, compliant or non-compliant."""
    ref = free_ai_reference("VDB_VECTOR_DB_EXPOSURE")
    blob = " ".join(str(v) for v in ref.values()).lower()
    for forbidden in ("compliant", "non-compliant", "is met", "is unmet", "violation"):
        assert forbidden not in blob, f"{forbidden!r} appears in a FREE-AI reference"


# ===========================================================================
# OBSERVABILITY -- the second negative
# ===========================================================================

def test_organisational_recommendations_are_not_attestable():
    """NEGATIVE: 19 of 26 ask an institution to do something source code cannot show. Counting them as covered would be a fabricated coverage claim."""
    not_attestable = [r for r in FREE_AI_RECOMMENDATIONS.values()
                      if r["observability"] == NOT_ATTESTABLE]
    assert len(not_attestable) == 19, len(not_attestable)
    assert len(FREE_AI_NOT_ATTESTABLE_IDS) == 19
    assert len(FREE_AI_OBSERVABLE_IDS) == 7


def test_board_audit_and_institutional_acts_are_not_attestable():
    for rid in ("FREE_AI_REC_9", "FREE_AI_REC_24", "FREE_AI_REC_25",
                "FREE_AI_REC_21", "FREE_AI_REC_22", "FREE_AI_REC_11"):
        assert FREE_AI_RECOMMENDATIONS[rid]["observability"] == NOT_ATTESTABLE, rid


def test_coverage_surfaces_the_not_attestable_denominator():
    cov = free_ai_coverage(["VDB_VECTOR_DB_EXPOSURE"], [])
    assert cov["catalogue_size"] == 26
    assert cov["catalogue_not_attestable_by_a_scanner"] == 19
    assert cov["catalogue_observable_by_a_scanner"] == 7
    assert cov["catalogue_not_attestable_by_a_scanner"] + \
        cov["catalogue_observable_by_a_scanner"] == cov["catalogue_size"]


def test_coverage_semantics_reject_the_compliance_reading():
    cov = free_ai_coverage(["VDB_VECTOR_DB_EXPOSURE"], [])
    low = cov["semantics"].lower()
    assert "not compliance" in low
    assert "impossible by construction" in low
    assert "not established" in low or "never established" in low


def test_no_rule_targets_a_not_attestable_recommendation():
    """NEGATIVE: attaching a source finding to 'form an AI standing committee'
    would be an unevidenced organisational claim."""
    for table in (FREE_AI_BY_RULE_ID, FREE_AI_BY_VULN_TYPE):
        for key, entry in table.items():
            rec = FREE_AI_RECOMMENDATIONS[entry["attack"]]
            assert rec["observability"] == OBSERVABLE, (key, rec["id"])
            for rel in entry.get("related") or ():
                assert FREE_AI_RECOMMENDATIONS[rel]["observability"] == OBSERVABLE, (key, rel)


def test_every_mapping_entry_carries_a_rationale():
    for table in (FREE_AI_BY_RULE_ID, FREE_AI_BY_VULN_TYPE):
        for key, entry in table.items():
            assert entry.get("rationale"), key
            assert entry["attack"] in FREE_AI_RECOMMENDATIONS, key


def test_every_mapping_target_is_an_observable_recommendation():
    targets = {e["attack"] for e in FREE_AI_BY_RULE_ID.values()}
    targets |= {e["attack"] for e in FREE_AI_BY_VULN_TYPE.values()}
    assert targets
    for tid in targets:
        assert FREE_AI_RECOMMENDATIONS[tid]["observability"] == OBSERVABLE, tid


# ===========================================================================
# Resolution
# ===========================================================================

def test_rule_id_mapping_is_direct():
    r = free_ai_reference("VDB_VECTOR_DB_EXPOSURE")
    assert r["free_ai_mapping_mode"] == DIRECT
    assert r["free_ai_rec"] == "FREE_AI_REC_19"
    assert r["free_ai_rec_number"] == 19


def test_vuln_type_mapping_is_related_never_direct():
    """NEGATIVE: FREE-AI publishes no machine-readable finding-to-recommendation
    mapping, so any linkage is this project's judgement."""
    r = free_ai_reference("", "vector_database_exposure")
    assert r["free_ai_mapping_mode"] == RELATED
    assert "judgement" in r["free_ai_rationale"]


def test_rule_id_outranks_vuln_type():
    r = free_ai_reference("COMP_AI_POLICY_MISSING", "ai_policy_compliance_missing")
    assert r["free_ai_mapping_mode"] == DIRECT
    assert r["free_ai_rec"] == "FREE_AI_REC_14"


def test_unmapped_finds_are_reported_with_a_rationale():
    r = free_ai_reference("SOME_UNRELATED_RULE", "some_unrelated_type")
    assert r["free_ai_mapping_mode"] == UNMAPPED
    assert r["free_ai_rec"] == ""
    assert r["free_ai_rationale"] == FREE_AI_UNMAPPED_RATIONALE


def test_unmapped_rationale_does_not_imply_compliance():
    low = FREE_AI_UNMAPPED_RATIONALE.lower()
    assert "not evidence that the corpus complies" in low
    assert "never established" in low


def test_resolution_fails_closed_on_empty_input():
    for bad in ("", None, "   "):
        assert free_ai_reference(bad, bad)["free_ai_mapping_mode"] == UNMAPPED


def test_enrich_writes_the_free_ai_fields():
    f = {"rule_id": "VDB_VECTOR_DB_EXPOSURE", "vuln_type": "vector_database_exposure"}
    enrich_with_free_ai(f)
    for key in ("free_ai_rec", "free_ai_label", "free_ai_pillar", "free_ai_framework",
                "free_ai_observability", "free_ai_related", "free_ai_sutras",
                "free_ai_mapping_mode", "free_ai_rationale", "free_ai_dataset",
                "free_ai_legal_status", "free_ai_applicable_to_corpus"):
        assert key in f, key
    assert f["free_ai_applicable_to_corpus"] is False


def test_rec_to_sutra_links_point_at_real_sutras():
    from core.free_ai_mappings import FREE_AI_REC_TO_SUTRA

    for rec_id, sutras in FREE_AI_REC_TO_SUTRA.items():
        assert rec_id in FREE_AI_RECOMMENDATIONS, rec_id
        for sid in sutras:
            assert sid in FREE_AI_SUTRAS, sid


def test_label_names_the_framework_not_just_the_number():
    label = free_ai_label("FREE_AI_REC_19")
    assert "FREE_AI_REC_19" in label
    assert "Risk Mitigation Framework" in label
    assert "Cybersecurity Measures" in label


# ===========================================================================
# Declared absence
# ===========================================================================

def test_recommendations_with_no_rule_are_recorded():
    assert FREE_AI_NO_RULE
    for rid, reason in FREE_AI_NO_RULE.items():
        assert reason and len(reason) > 20, rid


def test_g077_named_rec_17_and_24_are_in_the_no_rule_set():
    for rid in ("FREE_AI_REC_17", "FREE_AI_REC_24", "FREE_AI_REC_21"):
        assert rid in FREE_AI_NO_RULE, rid


# ===========================================================================
# Coverage
# ===========================================================================

def test_coverage_counts_mapped_and_unmapped_separately():
    cov = free_ai_coverage(["VDB_VECTOR_DB_EXPOSURE", "NOT_A_RULE"],
                           ["vector_database_exposure"])
    assert cov["rule_id"]["total"] == 2
    assert cov["rule_id"]["unmapped"] == ["NOT_A_RULE"]
    assert cov["combined"]["mapped"] == 2


def test_coverage_handles_empty_input_without_dividing_by_zero():
    cov = free_ai_coverage([], [])
    assert cov["combined"]["coverage_ratio"] == 0.0
    assert cov["recommendations_reachable_count"] == 0


def test_coverage_reachability_is_a_minority_of_the_catalogue():
    cov = free_ai_coverage(["VDB_VECTOR_DB_EXPOSURE"], [])
    assert cov["recommendations_reachable_count"] == 1
    assert cov["recommendations_reachable_count"] < cov["catalogue_size"]


# ===========================================================================
# Registry / wiring
# ===========================================================================

def test_freeai_probes_all_have_a_matching_production_source():
    from analysis.benchmark_conformance_baseline import STANDARD_BASELINE
    from core.conformance_baseline import production_sources

    sources = production_sources(ROOT)
    std = next(s for s in STANDARD_BASELINE if s["key"] == "RBI_FREE_AI")
    for probe in std["probes"]:
        if probe["kind"] != "code":
            continue
        hits = [rel for rel, text in sources.items() if re.search(probe["pattern"], text)]
        assert hits, f"FREE-AI probe {probe['name']} matches no production source"


def test_main_wires_free_ai():
    main_src = (ROOT / "main.py").read_text(encoding="utf-8")
    assert "free_ai_mappings" in main_src
    assert "free_ai_summary" in main_src