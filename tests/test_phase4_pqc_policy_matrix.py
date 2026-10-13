"""Phase 4.5: PQC policy packs -- multi-jurisdiction verdict matrix on the QBOM.

WHAT THIS DELIVERS
------------------
The gap plan's Phase 4.5 row: "PQC policy packs: BSI/ANSSI/NIST-IR-8547/CNSA
verdicts on QBOM", acceptance "QBOM emits multi-jurisdiction verdicts". Four
authorities were transcribed from their primary documents (each pack carries
document, status, date and URL) and applied to this scan's own quantum
classification:

* NIST IR 8547 (US, initial public draft 2024-11-12) -- calendar dates,
  deprecate 2030 / disallow 2035, symmetric >=128-bit stays approved;
* NSA CNSA 2.0 (US National Security Systems) -- per-category timetable,
  closed suite (AES-256, SHA-384/512, ML-KEM-1024, ML-DSA-87, LMS/XMSS)
  that excludes SLH-DSA;
* BSI TR-02102-1 (Germany, version 2026-01) -- solo classical key
  establishment recommended only until end of 2031, hybrid the expected
  mode, 120-bit security level;
* ANSSI (France, 2022 avis + 2023 follow-up) -- hybridation pushed hard,
  no closed algorithm list, symmetric target >= AES-256 / >= SHA2-384.

WHAT THESE TESTS PIN BEYOND THE HAPPY PATH
------------------------------------------
* the four packs must genuinely DIFFER (four different notes for
  QUANTUM_VULNERABLE, four different treatments of AES-128) -- a matrix
  whose rows collapsed to one generic verdict would pass a naive
  "is it emitted" test while carrying no jurisdiction information;
* REVIEW is never a pass: UNKNOWN lands on REVIEW in every pack;
* the override layer that prevents false passes (SHA-1 classifies
  QUANTUM_IMPACT_ASSESSED yet must be REPLACE everywhere; CNSA's suite
  is AES-256, not "AES");
* no key material can leak: the matrix copies identity fields only and
  PEM-redacts the algorithm strings on the way in;
* the CERT-In Table 8 document does NOT grow the key -- its conformance
  element list is fixed by spec, the matrix is the PQ document's.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.qbom_mappings import (  # noqa: E402
    PQC_POLICY_PACKS,
    PQC_VERDICT_VOCABULARY,
    build_qbom,
)
from scanner.crypto_quantum_analyzer import (  # noqa: E402
    build_pqc_verdict_matrix,
    correlate_cbom_to_qbom,
    verdict_for_asset,
)

PACK_IDS = ["nist-ir-8547", "nsa-cnsa-2-0", "bsi-tr-02102",
            "anssi-pqc-transition"]
PACK_BY_ID = {p["id"]: p for p in PQC_POLICY_PACKS}


def _asset(algorithm: str) -> dict:
    """One correlated QBOM asset from a one-line CBOM entry."""
    correlated = correlate_cbom_to_qbom([{"algorithm": algorithm}])
    assert correlated, f"correlator dropped {algorithm!r}"
    return correlated[0]


def _verdict(algorithm: str, pack_id: str) -> dict:
    return verdict_for_asset(_asset(algorithm), PACK_BY_ID[pack_id])


# ---------------------------------------------------------------------------
# Pack registry: identity, citations, vocabulary coverage.
# ---------------------------------------------------------------------------

def test_pack_set_is_the_four_cited_jurisdictions():
    assert [p["id"] for p in PQC_POLICY_PACKS] == PACK_IDS
    assert {p["authority"] for p in PQC_POLICY_PACKS} == {
        "NIST", "NSA", "BSI", "ANSSI",
    }


def test_every_pack_cites_a_primary_source():
    """A pack without a citable source is an unsourced claim wearing a
    jurisdiction's name -- the exact failure mode this matrix exists to
    avoid."""
    for pack in PQC_POLICY_PACKS:
        assert pack["document"], pack["id"]
        assert pack["document_status"], pack["id"]
        assert pack["published"][:2] == "20", pack["id"]
        assert pack["source_url"].startswith("https://"), pack["id"]
        assert pack["scope"].strip(), pack["id"]
        assert pack["hybrid_position"].strip(), pack["id"]
        assert isinstance(pack["key_dates"], dict), pack["id"]
        assert pack["approved_pqc"], pack["id"]


def test_status_grid_covers_every_status_for_every_pack():
    matrix = build_pqc_verdict_matrix([])
    for pack_id, grid in matrix["status_grid"].items():
        assert sorted(grid) == sorted(
            ["QUANTUM_VULNERABLE", "QUANTUM_MARGIN_CRITICAL", "PQC",
             "QUANTUM_IMPACT_ASSESSED", "UNKNOWN"]
        ), pack_id
        for status, cell in grid.items():
            assert cell["verdict"] in PQC_VERDICT_VOCABULARY, (
                pack_id, status, cell["verdict"])
            assert cell["note"].strip(), (pack_id, status)


def test_every_emitted_cell_uses_the_shipped_vocabulary():
    probes = ["RSA", "3DES", "ML-KEM-768", "AES-128", "SHA-1", "LMS",
              "Kyber768", "FrodoKEM-1344", "SHA-256"]
    matrix = build_pqc_verdict_matrix(
        correlate_cbom_to_qbom([{"algorithm": a} for a in probes]))
    for row in matrix["assets"]:
        for pack_id, cell in row["verdicts"].items():
            assert cell["verdict"] in PQC_VERDICT_VOCABULARY, (
                pack_id, row["algorithm"], cell["verdict"])
            assert cell["note"].strip(), (pack_id, row["algorithm"])


# ---------------------------------------------------------------------------
# The four packs must actually differ: this is a matrix, not one verdict.
# ---------------------------------------------------------------------------

def test_quantum_vulnerable_deadlines_differ_per_jurisdiction():
    notes = {}
    for pack_id in PACK_IDS:
        cell = PACK_BY_ID[pack_id]["position_by_status"][
            "QUANTUM_VULNERABLE"]
        assert cell["verdict"] == "MIGRATE", pack_id
        notes[pack_id] = cell["note"]

    # Four authorities, four distinct positions -- pairwise distinct notes.
    assert len(set(notes.values())) == 4

    assert "2030" in notes["nist-ir-8547"] and "2035" in notes[
        "nist-ir-8547"]
    assert "2030" in notes["nsa-cnsa-2-0"] and "2033" in notes[
        "nsa-cnsa-2-0"] and "NSS" in notes["nsa-cnsa-2-0"]
    assert "2031" in notes["bsi-tr-02102"]
    assert "hybridation" in notes["anssi-pqc-transition"]


def test_aes128_splits_the_jurisdictions_the_way_the_policies_do():
    """The whole point of the cross-product: one asset, four verdicts that
    follow the documents, not a single generic row.

    NIST keeps >=128-bit symmetric approved; BSI's level is 120 bits;
    ANSSI encourages at least AES-256 for block ciphers; CNSA's suite is
    AES-256 specifically.
    """
    assert _verdict("AES-128", "nist-ir-8547")["verdict"] == "ACCEPTABLE"
    assert _verdict("AES-128", "bsi-tr-02102")["verdict"] == "ACCEPTABLE"
    assert _verdict("AES-128", "anssi-pqc-transition")["verdict"] == "REVIEW"
    assert _verdict("AES-128", "nsa-cnsa-2-0")["verdict"] == "REVIEW"


def test_cnsa_splits_symmetric_by_suite_parameters():
    assert _verdict("AES-256", "nsa-cnsa-2-0")["verdict"] == "ACCEPTABLE"
    assert _verdict("SHA-512", "nsa-cnsa-2-0")["verdict"] == "ACCEPTABLE"
    assert _verdict("AES-128", "nsa-cnsa-2-0")["verdict"] == "REVIEW"
    assert _verdict("SHA-256", "nsa-cnsa-2-0")["verdict"] == "REVIEW"
    # Bare family: parameter unrecorded, so it cannot be confirmed against
    # the suite -- REVIEW, not a pass.
    assert _verdict("AES", "nsa-cnsa-2-0")["verdict"] == "REVIEW"
    # ...but bare AES is safe under NIST: every AES variant is >=128-bit.
    assert _verdict("AES", "nist-ir-8547")["verdict"] == "ACCEPTABLE"


def test_override_layer_beats_a_naive_status_mapping():
    """SHA-1 classifies QUANTUM_IMPACT_ASSESSED, whose status default is
    ACCEPTABLE under NIST. A status-only matrix would pass a broken hash;
    the override layer must say REPLACE in every pack."""
    correlated = correlate_cbom_to_qbom([{"algorithm": "SHA-1"}])
    assert correlated[0]["quantum_status"] == "QUANTUM_IMPACT_ASSESSED"
    for pack_id in PACK_IDS:
        cell = verdict_for_asset(correlated[0], PACK_BY_ID[pack_id])
        assert cell["verdict"] == "REPLACE", pack_id
        assert cell["rule"] == "algorithm", pack_id


def test_rule_layers_are_reported_so_a_reader_can_audit_the_cell():
    rsa = verdict_for_asset(_asset("RSA"), PACK_BY_ID["nist-ir-8547"])
    assert rsa["rule"] == "status" and rsa["verdict"] == "MIGRATE"

    sha = verdict_for_asset(_asset("SHA-1"), PACK_BY_ID["nist-ir-8547"])
    assert sha["rule"] == "algorithm" and sha["matched"] == "sha-1"


# ---------------------------------------------------------------------------
# PQC family verdicts: standardised vs pre-standard, suite membership.
# ---------------------------------------------------------------------------

def test_standardised_pqc_aligned_prestandard_review():
    # NIST: FIPS 203 family vs its research-stage spelling.
    assert _verdict("ML-KEM-768", "nist-ir-8547")["verdict"] == "ALIGNED"
    assert _verdict("Kyber768", "nist-ir-8547")["verdict"] == "REVIEW"
    # CNSA: suite member vs SLH-DSA, which NSA left out of CNSA 2.0.
    assert _verdict("ML-DSA-65", "nsa-cnsa-2-0")["verdict"] == "ALIGNED"
    assert _verdict("SLH-DSA-SHA2-128s", "nsa-cnsa-2-0")["verdict"] == "REVIEW"
    assert _verdict("Falcon-512", "nsa-cnsa-2-0")["verdict"] == "REVIEW"
    # BSI/ANSSI publish no closed suite: recognised PQC families are
    # direction-consistent (ALIGNED) with the caveat carried in the note.
    assert _verdict("ML-KEM-768", "bsi-tr-02102")["verdict"] == "ALIGNED"
    assert _verdict("Kyber768", "anssi-pqc-transition")["verdict"] == "ALIGNED"
    assert "no closed algorithm list" in _verdict(
        "ML-KEM-768", "anssi-pqc-transition")["note"]


def test_prestandard_spellings_review_under_bsi():
    assert _verdict("Kyber768", "bsi-tr-02102")["verdict"] == "REVIEW"
    assert _verdict("Dilithium3", "bsi-tr-02102")["verdict"] == "REVIEW"


def test_stateful_hash_signatures_map_per_pack_despite_unknown_status():
    """LMS classifies UNKNOWN (the quantum classifier's set does not carry
    it), yet the override layer -- which runs BEFORE the status grid --
    still reaches the pack positions."""
    lms = _asset("LMS")
    assert lms["quantum_status"] == "UNKNOWN"
    assert _verdict("LMS", "nist-ir-8547")["verdict"] == "ALIGNED"
    assert _verdict("LMS", "bsi-tr-02102")["verdict"] == "ALIGNED"
    # CNSA 2.0 names LMS/XMSS for software and firmware signing.
    assert _verdict("LMS", "nsa-cnsa-2-0")["verdict"] == "ALIGNED"
    # ANSSI publishes no position this pack can cite for LMS from its two
    # documents: REVIEW stands -- and REVIEW is not a pass.
    assert _verdict("LMS", "anssi-pqc-transition")["verdict"] == "REVIEW"


# ---------------------------------------------------------------------------
# Honest failure modes: UNKNOWN never becomes a pass.
# ---------------------------------------------------------------------------

def test_unknown_status_is_review_in_every_pack():
    matrix = build_pqc_verdict_matrix([])
    for pack_id, grid in matrix["status_grid"].items():
        assert grid["UNKNOWN"]["verdict"] == "REVIEW", pack_id

    # RC4 classifies UNKNOWN (deliberately: no quantum-relevant claim).
    rc4 = _asset("RC4")
    assert rc4["quantum_status"] == "UNKNOWN"
    for pack_id in PACK_IDS:
        cell = verdict_for_asset(rc4, PACK_BY_ID[pack_id])
        assert cell["verdict"] == "REVIEW", pack_id
        assert "NOT a pass" in cell["note"]


def test_margin_critical_is_replace_everywhere_not_a_pqc_question():
    for pack_id in PACK_IDS:
        assert _verdict("3DES", pack_id)["verdict"] == "REPLACE", pack_id


# ---------------------------------------------------------------------------
# Matrix shape: determinism, empty inventory, rollup, PEM safety.
# ---------------------------------------------------------------------------

def test_matrix_is_deterministic():
    assets = correlate_cbom_to_qbom(
        [{"algorithm": a} for a in
         ("RSA", "AES-128", "3DES", "ML-KEM-768", "SHA-1")])
    a = build_pqc_verdict_matrix(assets)
    b = build_pqc_verdict_matrix(assets)
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


def test_empty_inventory_still_ships_packs_grid_and_vocabulary():
    matrix = build_pqc_verdict_matrix([])
    assert matrix["assets"] == []
    assert matrix["totals"] == {"assets": 0, "verdict_cells": 0,
                                "jurisdictions": 4}
    assert [p["id"] for p in matrix["packs"]] == PACK_IDS
    assert matrix["vocabulary"] == PQC_VERDICT_VOCABULARY
    assert len(matrix["status_grid"]) == 4
    for pack_id in PACK_IDS:
        assert sum(matrix["rollup"][pack_id].values()) == 0
    assert matrix["limits"]


def test_rollup_counts_match_the_asset_rows():
    assets = correlate_cbom_to_qbom(
        [{"algorithm": a} for a in ("RSA", "RSA-2048", "SHA-1", "LMS")])
    # Key size is identity, so RSA and RSA-2048 stay distinct assets.
    assert len(assets) == 4
    matrix = build_pqc_verdict_matrix(assets)
    assert matrix["totals"]["assets"] == len(matrix["assets"]) == 4
    assert matrix["totals"]["verdict_cells"] == 4 * 4
    for pack_id in PACK_IDS:
        assert (sum(matrix["rollup"][pack_id].values())
                == len(matrix["assets"]))
    for row in matrix["assets"]:
        for pack_id, cell in row["verdicts"].items():
            assert matrix["rollup"][pack_id][cell["verdict"]] >= 1


def test_asset_rows_carry_identity_fields_and_no_evidence():
    cbom = [{
        "algorithm": "RSA",
        "key_size": 2048,
        "evidence": [
            {"detail": "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAK\n"
                       "-----END RSA PRIVATE KEY-----"}
        ],
    }]
    assets = correlate_cbom_to_qbom(cbom)
    matrix = build_pqc_verdict_matrix(assets)
    dumped = json.dumps(matrix)
    assert "PRIVATE KEY" not in dumped
    assert "BEGIN" not in dumped
    row = matrix["assets"][0]
    assert row["key_size"] == 2048
    assert "evidence" not in row and "occurrences" not in row
    assert row["occurrence_count"] == 1


def test_algorithm_strings_are_pem_redacted_even_if_placed_there_directly():
    """Defense in depth: the builder redacts on the way in, so no caller
    path can smuggle key material through the algorithm field."""
    matrix = build_pqc_verdict_matrix([{
        "qbom_id": "QBOM-x",
        "algorithm": "-----BEGIN PRIVATE KEY-----\nMIIE\n"
                     "-----END PRIVATE KEY-----",
        "normalized_algorithm": "-----BEGIN PRIVATE KEY-----\nMIIE\n"
                                "-----END PRIVATE KEY-----",
        "quantum_status": "UNKNOWN",
        "occurrence_count": 1,
    }])
    dumped = json.dumps(matrix)
    assert "PRIVATE KEY" not in dumped
    assert "MIIE" not in dumped


def test_certin_table8_document_does_not_grow_the_key():
    """The CERT-In document models a fixed 11-element list; jurisdiction
    policy is a migration projection and lives in the PQ document."""
    doc = build_qbom({"sbom": [], "findings": []})
    assert "pqc_policy_matrix" not in doc
    assert len(doc["minimum_elements"]) == 11


def test_matrix_limits_state_the_derivation_and_the_draft_status():
    limits = " ".join(build_pqc_verdict_matrix([])["limits"])
    assert "not a compliance certification" in limits
    assert "INITIAL PUBLIC DRAFT" in limits
    assert "National Security Systems" in limits
    assert "REVIEW is never a pass" in limits
