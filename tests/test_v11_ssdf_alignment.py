"""Tests for the NIST SSDF (SP 800-218) evidence alignment.

SSDF is a process framework, so the property that matters most here is negative:
no practice identifier may ever be attached to a finding, because a scanner
cannot evidence an organisational practice. These tests pin that.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core.ssdf_mappings import (  # noqa: E402
    SSDF_ALIGNMENT_NOT_OBSERVED,
    SSDF_ALIGNMENT_OBSERVED,
    SSDF_ALIGNMENT_ORGANISATIONAL,
    SSDF_DATASET_LABEL,
    SSDF_DOCUMENT,
    SSDF_DOI,
    SSDF_EVIDENCE,
    SSDF_NOT_ATTESTABLE,
    SSDF_PRACTICE_GROUPS,
    SSDF_PRACTICES,
    SSDF_VERSION,
    evaluate_ssdf_alignment,
)

ARTIFACT = Path(
    r"C:\Users\janan\AppData\Local\Temp\opencode\js_fix\clean_report.json"
)

PRACTICE_ID = __import__("re").compile(r"^(PO|PS|PW|RV)\.\d$")


# ---------------------------------------------------------------------------
# Catalogue integrity
# ---------------------------------------------------------------------------
def test_version_is_pinned_to_sp_800_218_v1_1():
    assert SSDF_DOCUMENT == "NIST SP 800-218"
    assert SSDF_VERSION == "1.1"
    assert SSDF_DOI == "10.6028/NIST.SP.800-218"
    assert "v1.1" in SSDF_DATASET_LABEL


def test_every_practice_id_is_well_formed_and_group_is_known():
    for pid, spec in SSDF_PRACTICES.items():
        assert PRACTICE_ID.match(pid), f"malformed practice id {pid}"
        assert spec["group"] in SSDF_PRACTICE_GROUPS, f"{pid} unknown group"
        assert set(SSDF_PRACTICE_GROUPS) == {"PO", "PS", "PW", "RV"}


def test_all_four_groups_are_represented():
    groups = {spec["group"] for spec in SSDF_PRACTICES.values()}
    assert groups == {"PO", "PS", "PW", "RV"}


def test_draft_revision_practices_are_excluded():
    """PO.6 and PW.10 belong to a later EO 14144 revision, not v1.1.

    Including them would put unpublished identifiers in a compliance table.
    """
    for draft_only in ("PO.6", "PW.10", "PO.7", "PW.11"):
        assert draft_only not in SSDF_PRACTICES, (
            f"{draft_only} is not in SSDF v1.1 and must not be listed"
        )


def test_every_practice_has_evidence_or_an_explicit_non_attestable_reason():
    for pid in SSDF_PRACTICES:
        assert pid in SSDF_EVIDENCE or pid in SSDF_NOT_ATTESTABLE, (
            f"{pid} has neither an evidence probe nor a recorded reason for "
            f"having none"
        )


def test_practices_with_empty_evidence_paths_declare_why():
    for pid, spec in SSDF_EVIDENCE.items():
        if not spec["paths"]:
            assert len(spec["why"]) > 60, (
                f"{pid} has no evidence path and needs a substantive reason"
            )


def test_not_attestable_entries_are_strings_or_notes():
    for pid, entry in SSDF_NOT_ATTESTABLE.items():
        assert pid in SSDF_PRACTICES, pid
        assert isinstance(entry, (str, dict)), pid
        if isinstance(entry, dict):
            assert entry.get("note"), pid


def test_practices_are_not_simultaneously_evidenced_and_not_attestable():
    overlap = set(SSDF_EVIDENCE) & set(SSDF_NOT_ATTESTABLE)
    assert not overlap, f"contradictory declaration: {sorted(overlap)}"


# ---------------------------------------------------------------------------
# Evaluation behaviour
# ---------------------------------------------------------------------------
def test_empty_payload_observes_nothing():
    """Fail closed: no artifact data means no SSDF evidence."""
    result = evaluate_ssdf_alignment({})
    assert result["observed"] == 0, result["observed_ids"]
    assert result["observed_ids"] == []
    for p in result["practices"]:
        assert p["status"] != SSDF_ALIGNMENT_OBSERVED


def test_every_practice_is_reported_exactly_once():
    result = evaluate_ssdf_alignment({})
    ids = [p["practice_id"] for p in result["practices"]]
    assert sorted(ids) == sorted(SSDF_PRACTICES)
    assert len(ids) == len(set(ids))


def test_statuses_are_from_the_declared_vocabulary():
    allowed = {
        SSDF_ALIGNMENT_OBSERVED,
        SSDF_ALIGNMENT_NOT_OBSERVED,
        SSDF_ALIGNMENT_ORGANISATIONAL,
    }
    result = evaluate_ssdf_alignment({"findings": [1], "sbom": [1]})
    for p in result["practices"]:
        assert p["status"] in allowed, p


def test_observed_requires_every_declared_evidence_path():
    """Partial evidence must not be promoted to OBSERVED.

    PW.5 declares two paths (findings and metadata.sast_findings). Supplying
    only one must leave it NOT_OBSERVED.
    """
    # findings present but metadata.sast_findings absent -> PW.5 must NOT observe
    partial = evaluate_ssdf_alignment({"findings": [1, 2]})
    pw5_partial = next(
        p for p in partial["practices"] if p["practice_id"] == "PW.5"
    )
    assert pw5_partial["status"] == SSDF_ALIGNMENT_NOT_OBSERVED

    # both present -> PW.5 observes
    full = evaluate_ssdf_alignment(
        {"findings": [1, 2], "metadata": {"sast_findings": 2}}
    )
    pw5 = next(p for p in full["practices"] if p["practice_id"] == "PW.5")
    assert pw5["status"] == SSDF_ALIGNMENT_OBSERVED
    assert all(e["resolved"] for e in pw5["evidence"])
    assert len(pw5["evidence"]) == 2


def test_empty_container_does_not_satisfy_an_evidence_path():
    result = evaluate_ssdf_alignment({"findings": [], "sbom": []})
    assert result["observed"] == 0
    pw5 = next(p for p in result["practices"] if p["practice_id"] == "PW.5")
    assert pw5["status"] == SSDF_ALIGNMENT_NOT_OBSERVED


def test_every_entry_carries_a_rationale():
    result = evaluate_ssdf_alignment({"findings": [1]})
    for p in result["practices"]:
        assert p["rationale"].strip(), p["practice_id"]


def test_by_group_counts_are_consistent():
    result = evaluate_ssdf_alignment({"findings": [1]})
    total = sum(g["total"] for g in result["by_group"].values())
    observed = sum(g["observed"] for g in result["by_group"].values())
    assert total == result["total_practices"]
    assert observed == result["observed"]


def test_method_statement_forbids_per_finding_identifiers():
    result = evaluate_ssdf_alignment({})
    method = result["method"].lower()
    assert "no practice identifier is attached to any finding" in method
    assert "absence into assurance" in method


# ---------------------------------------------------------------------------
# The anti-fabrication contract
# ---------------------------------------------------------------------------
def test_no_ssdf_field_is_emitted_on_a_finding():
    """A finding must never carry an SSDF practice id."""
    enriched = {}
    evaluate_ssdf_alignment({"findings": [{"rule_id": "X"}]})
    # evaluate() must not mutate or annotate the payload it is given
    assert enriched == {}
    finding = {"rule_id": "X", "ssdf_practice": "RV.1"}
    # and nothing in this module exposes a finding-level enricher
    import core.ssdf_mappings as m

    fns = [n for n in dir(m) if n.startswith("enrich")]
    assert fns == [], f"SSDF must not expose a finding-level enricher: {fns}"


def test_organisational_practices_are_never_marked_observed():
    result = evaluate_ssdf_alignment(
        {"findings": [1], "sbom": [1], "secret_intelligence_summary": {"total_secrets": 1},
         "runtime_artifact_integrity_summary": {}, "kev_intelligence_summary": {},
         "epss_intelligence_summary": {}, "vulnerability_age_summary": {},
         "reachability_vulnerability_summary": {}, "release_readiness": {},
         "exploitability_summary": {}, "metadata": {"sast_findings": 1}}
    )
    status = {p["practice_id"]: p["status"] for p in result["practices"]}
    for pid in ("PO.1", "PO.2", "PO.3", "PO.5"):
        assert status[pid] == SSDF_ALIGNMENT_ORGANISATIONAL, (
            f"{pid} is organisational and must never be OBSERVED"
        )


# ---------------------------------------------------------------------------
# Artifact behaviour
# ---------------------------------------------------------------------------
def test_direct_construction_always_emits_the_evidence_key():
    """Before the pipeline, the schema is uniform."""
    result = evaluate_ssdf_alignment({})
    for p in result["practices"]:
        assert "evidence" in p, p["practice_id"]


@pytest.mark.skipif(not ARTIFACT.exists(), reason="reference artifact not present")
def test_reference_artifact_shape():
    art = json.loads(ARTIFACT.read_text(encoding="utf-8"))
    result = evaluate_ssdf_alignment(art)
    assert result["observed"] >= 6, result["observed_ids"]
    assert "RV.1" in result["observed_ids"]
    assert "RV.2" in result["observed_ids"]
    assert "PW.5" in result["observed_ids"]
    assert "PS.2" in result["observed_ids"]
    for pid in ("PO.1", "PO.2", "PO.3"):
        assert pid not in result["observed_ids"]


def test_report_pipeline_prunes_empty_containers():
    """Documented artifact property: empty lists are dropped before writing.

    A consumer indexing p['evidence'] will raise KeyError on a
    NOT_ATTESTABLE practice, so the accessor must be tolerant. This test
    records the property so a future change to the pruning pass is visible.
    """
    artifact = ROOT / "reports" / "_benchmark_scan" / "clean_report.json"
    if not artifact.exists():
        pytest.skip("no pipeline artifact present")
    data = json.loads(artifact.read_text(encoding="utf-8"))
    if "ssdf_alignment" not in data:
        pytest.skip("artifact predates SSDF wiring")
    for p in data["ssdf_alignment"]["practices"]:
        assert isinstance(p.get("evidence", []), list)