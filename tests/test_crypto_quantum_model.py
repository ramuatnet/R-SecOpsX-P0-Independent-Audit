"""Tests for the PQ crypto models: scanner/{cbom,qbom}_model + crypto_quantum_analyzer.

Written against the assertions the model is supposed to guarantee, then checked
against the measured behaviour of the prodtest corpus. Three of these encode
defects that were found by validating the modules against 3,191 real CBOM entries
rather than against hand-made fixtures, so they are kept as regression guards:

  * key_size is part of a cryptographic asset's identity. RSA-2048 and RSA-4096
    at the same call site previously shared one id (CBOM-4075ef5a41e50a0c for
    both), which means the inventory could not say which strength was deployed.
  * an algorithm we cannot classify is UNKNOWN, never LOW. `quantum_risk` used
    to be "HIGH if QUANTUM_VULNERABLE else LOW", so an algorithm this tool has
    never heard of was reported as low risk. Absence is not reassurance.
  * classification is by family, and the family rule must never strip a
    meaningful key length. Two earlier attempts stripped a trailing numeric
    group and regressed AES-256 and SHA-512 to UNKNOWN.

The symmetric-asymmetric separation is asserted explicitly: AES is
impact-assessed rather than vulnerable because Grover halves the key, while
ed25519 IS vulnerable because Shor breaks it precisely by being strong. A
key-size-based oracle gets both backwards.
"""
from __future__ import annotations

import pytest

from scanner.cbom_model import create_cbom_asset
from scanner.crypto_quantum_analyzer import correlate_cbom_to_qbom
from scanner.qbom_model import (
    classify_quantum_status,
    create_qbom_asset,
    normalize_algorithm,
    stable_qbom_id,
)


# ---------------------------------------------------------------- identity --

def test_cbom_has_stable_identity():
    asset = create_cbom_asset(
        algorithm="RSA",
        key_size=2048,
        library="OpenSSL",
    )

    assert asset.asset_id.startswith("CBOM-")


def test_asset_id_is_deterministic():
    a = create_cbom_asset(algorithm="RSA", key_size=2048, library="OpenSSL")
    b = create_cbom_asset(algorithm="RSA", key_size=2048, library="OpenSSL")

    assert a.asset_id == b.asset_id


def test_key_size_is_part_of_the_asset_identity():
    """RSA-2048 and RSA-4096 are different cryptographic assets.

    They used to collapse onto one id because key_size was not in the digest, so
    an inventory could not record which key strength was actually deployed.
    """
    weak = create_cbom_asset(
        algorithm="RSA",
        key_size=2048,
        library="OpenSSL",
        application="Payment API",
        source_file="crypto.py",
    )
    strong = create_cbom_asset(
        algorithm="RSA",
        key_size=4096,
        library="OpenSSL",
        application="Payment API",
        source_file="crypto.py",
    )

    assert weak.asset_id != strong.asset_id
    assert weak.key_size == 2048
    assert strong.key_size == 4096


def test_qbom_id_is_keyed_on_key_size_too():
    assert stable_qbom_id("RSA", "app", "CBOM-1", 2048) != stable_qbom_id(
        "RSA", "app", "CBOM-1", 4096
    )


# -------------------------------------------------- quantum classification --

def test_rsa_is_quantum_vulnerable():
    assert classify_quantum_status("RSA") == "QUANTUM_VULNERABLE"


def test_ecdsa_is_quantum_vulnerable():
    assert classify_quantum_status("ECDSA") == "QUANTUM_VULNERABLE"


def test_ed25519_is_quantum_vulnerable_because_it_is_strong():
    """Shor's attack breaks ed25519 precisely because the curve is hard.

    This is the case a key-size oracle gets backwards: ed25519 has a small,
    uniform key size and is still Shor-broken.
    """
    assert classify_quantum_status("ed25519") == "QUANTUM_VULNERABLE"


def test_ml_kem_is_pqc():
    assert classify_quantum_status("ML-KEM") == "PQC"


def test_ml_dsa_is_pqc():
    assert classify_quantum_status("ML-DSA") == "PQC"


@pytest.mark.parametrize(
    "name",
    [
        "ml-kem-768",
        "ML-KEM-1024",
        "ML-DSA-65",
        "SLH-DSA-SHA2-128s",
        "Kyber768",
        "Dilithium3",
    ],
)
def test_pqc_parameter_sets_resolve_to_their_family(name):
    """A NIST parameter set is a parameter set of a family, not a new algorithm.

    These all classified UNKNOWN before family-prefix matching existed, because
    the name carried a size suffix the classifier did not recognise.
    """
    assert classify_quantum_status(name) == "PQC"


def test_aes_is_not_public_key_quantum_vulnerable():
    assert classify_quantum_status("AES-256") == "QUANTUM_IMPACT_ASSESSED"


@pytest.mark.parametrize("name", ["AES-128", "AES-192", "AES-256"])
def test_aes_key_length_is_preserved(name):
    """Grover's advantage scales with key length, so the length is the fact.

    An earlier suffix-stripping attempt turned AES-256 into "aes" and lost the
    classification entirely. For a symmetric primitive the size must survive
    normalisation.
    """
    assert normalize_algorithm(name) == name.lower()
    assert classify_quantum_status(name) == "QUANTUM_IMPACT_ASSESSED"


@pytest.mark.parametrize(
    "name", ["SHA-1", "SHA-256", "SHA-384", "SHA-512", "SHA1"]
)
def test_hashes_are_impact_assessed_not_vulnerable(name):
    assert classify_quantum_status(name) == "QUANTUM_IMPACT_ASSESSED"


def test_unrelated_unknown_algorithm_not_marked_vulnerable():
    assert classify_quantum_status("UNKNOWN-ALGORITHM") == "UNKNOWN"


# -------------------------------------- the corpus's bare symmetric families --

def test_bare_aes_is_classified_without_a_key_size():
    """The broken-or-not axis is answerable from the family alone.

    Grover-reducible is knowable without a key size; only the magnitude needs it.
    Classifying bare "AES" -- 93 real occurrences in the corpus -- as UNKNOWN
    asserted we cannot place it on that axis at all, which is false.
    """
    asset = create_qbom_asset(algorithm="AES")

    assert asset.quantum_status == "QUANTUM_IMPACT_ASSESSED"


def test_bare_aes_states_that_the_margin_is_unquantifiable():
    """A verdict without its caveat overstates it.

    The caveat travels on the asset rather than being left for the reader to
    infer, because "not broken" and "not broken by enough" are different claims.
    """
    asset = create_qbom_asset(algorithm="AES")

    assert asset.classification_note, "the missing key size is not disclosed"
    assert "key size" in asset.classification_note


def test_parameterised_aes_needs_no_caveat():
    """AES-256 already encodes its size, so there is nothing left unstated."""
    assert create_qbom_asset(algorithm="AES-256").classification_note is None


def test_des_is_margin_critical_not_shor_broken():
    """64-bit key -> about 32 bits under Grover. Separate from Shor.

    Overloading one label with both mechanisms produces one piece of advice for
    two different problems: an asymmetric primitive must be replaced, a 64-bit
    symmetric key must simply be replaced by one of adequate length.
    """
    asset = create_qbom_asset(algorithm="DES")

    assert asset.quantum_status == "QUANTUM_MARGIN_CRITICAL"
    assert asset.quantum_risk == "HIGH"


def test_the_corpus_largest_class_is_no_longer_unknown():
    """"DES / 3DES" is 3,011 of 3,191 real CBOM entries.

    It normalised to "3des", which matched nothing, so the single largest class in
    the corpus was classified UNKNOWN -- reported as unassessable rather than as
    the obsolete primitive it is.
    """
    assert classify_quantum_status("DES / 3DES") == "QUANTUM_MARGIN_CRITICAL"


def test_margin_critical_assets_reach_the_migration_queue():
    """A Grover-destroyed primitive must not be silently dropped from the queue.

    The queue previously selected on QUANTUM_VULNERABLE alone, so adding the
    status without adding it here would have produced a status that existed and
    then did nothing.
    """
    result = correlate_cbom_to_qbom([{"component": "DES"}])[0]

    assert result["migration_priority"] in {"CRITICAL", "HIGH", "MEDIUM"}
    assert result["classification_note"]


@pytest.mark.parametrize("label", ["TLS / SSL", "MD5", "RC4"])
def test_non_primitives_are_left_unclassified(label):
    """No quantum status is invented for things that have none.

    TLS/SSL is a protocol whose quantum impact comes from its key exchange; MD5
    and RC4 have no quantum-relevant role. Assigning them a status would be a
    claim the evidence cannot support, so they stay UNKNOWN and are reported as
    such rather than being quietly absorbed.
    """
    assert classify_quantum_status(label) == "UNKNOWN"


def test_status_values_are_all_strings():
    """A regression guard for a real defect.

    `resolve_symmetric_family` returned the SET `QUANTUM_IMPACT_ASSESSED` -- the
    same name as the status string, a different thing -- so classify_quantum_status
    returned a set, which failed two frames later as an unhashable dict key at the
    risk-mapping lookup, nowhere near the cause. Every status must be a string.
    """
    for algorithm in ("AES", "DES", "RSA", "ML-KEM", "MD5", "TLS / SSL", "3DES"):
        status = classify_quantum_status(algorithm)
        assert isinstance(status, str), f"{algorithm!r} -> {status!r}"
        assert status in {
            "QUANTUM_VULNERABLE", "PQC", "QUANTUM_IMPACT_ASSESSED",
            "QUANTUM_MARGIN_CRITICAL", "UNKNOWN",
        }


def test_empty_algorithm_is_unknown():
    assert classify_quantum_status("") == "UNKNOWN"


# --------------------------------------- absence must not become reassurance --

def test_unknown_algorithm_does_not_get_a_low_risk_rating():
    asset = create_qbom_asset(algorithm="TotallyUnknownCipher")

    assert asset.quantum_status == "UNKNOWN"
    assert asset.quantum_risk == "UNKNOWN"


def test_quantum_risk_mirrors_the_status():
    vulnerable = create_qbom_asset(algorithm="RSA")
    safe = create_qbom_asset(algorithm="AES-256")
    pqc = create_qbom_asset(algorithm="ML-KEM")

    assert vulnerable.quantum_risk == "HIGH"
    assert safe.quantum_risk == "LOW"
    assert pqc.quantum_risk == "LOW"


def test_unknown_status_gets_no_migration_priority():
    """Priority means 'do this migration', which cannot be asserted for an
    algorithm we cannot identify."""
    asset = create_qbom_asset(algorithm="TotallyUnknownCipher")

    assert asset.migration_priority == "NONE"


# ------------------------------------------------- display-name resolution --

@pytest.mark.parametrize(
    ("emitted", "expected"),
    [
        # These are the strings the corpus actually emits, measured over 3,191
        # real CBOM entries. Before normalisation was added, seven of eight
        # distinct component values in the corpus classified as UNKNOWN.
        ("SHA1", "sha-1"),
        ("SHA-256", "sha-256"),
        ("DES / 3DES", "3des"),
        ("tripledes", "3des"),
        ("RSA_2048", "rsa-2048"),
        ("RSA 2048", "rsa-2048"),
    ],
)
def test_display_names_normalise(emitted, expected):
    assert normalize_algorithm(emitted) == expected


def test_compound_display_name_takes_the_specific_algorithm():
    """"DES / 3DES" is a weak-family / specific-algorithm pair; the specific
    one is the last token."""
    assert normalize_algorithm("DES / 3DES") == "3des"


# --------------------------------------------------------- migration order --

def test_rsa_critical_migration_priority():
    asset = create_qbom_asset(
        algorithm="RSA",
        key_size=2048,
        application="Payment API",
        business_criticality="CRITICAL",
        internet_exposed=True,
        protected_data="Sensitive customer data",
    )

    assert asset.quantum_status == "QUANTUM_VULNERABLE"
    assert asset.migration_priority == "CRITICAL"


def test_internal_only_vulnerable_asset_is_lower_priority():
    asset = create_qbom_asset(algorithm="RSA", key_size=2048)

    assert asset.quantum_status == "QUANTUM_VULNERABLE"
    assert asset.migration_priority == "MEDIUM"


def test_pqc_asset_needs_no_migration():
    asset = create_qbom_asset(algorithm="ML-KEM-768", business_criticality="CRITICAL")

    assert asset.migration_priority == "NONE"


def test_invalid_migration_status_is_rejected():
    with pytest.raises(ValueError):
        create_qbom_asset(algorithm="RSA", migration_status="MADE_UP")


# ----------------------------------------------------------- correlation --

def test_cbom_qbom_correlation():
    cbom = [
        create_cbom_asset(
            algorithm="RSA",
            key_size=2048,
            library="OpenSSL",
            application="Payment API",
            confidence=0.95,
        ).to_dict()
    ]

    results = correlate_cbom_to_qbom(cbom)

    assert len(results) == 1
    assert results[0]["relationship"]["type"] == "CBOM_CORRELATES_WITH_QBOM"
    assert results[0]["quantum_status"] == "QUANTUM_VULNERABLE"
    assert results[0]["relationship"]["source"] == cbom[0]["asset_id"]


def test_correlation_preserves_key_size_and_confidence():
    cbom = [
        create_cbom_asset(
            algorithm="RSA",
            key_size=4096,
            library="OpenSSL",
            application="Payment API",
            confidence=0.9,
        ).to_dict()
    ]

    result = correlate_cbom_to_qbom(cbom)[0]

    assert result["key_size"] == 4096
    assert result["confidence"] == 0.9


def test_correlation_deduplicates_identical_assets():
    cbom = [
        create_cbom_asset(algorithm="RSA", key_size=2048, library="OpenSSL").to_dict()
        for _ in range(3)
    ]

    assert len(correlate_cbom_to_qbom(cbom)) == 1


def test_correlation_keeps_distinct_key_sizes_separate():
    cbom = [
        create_cbom_asset(
            algorithm="RSA", key_size=2048, library="OpenSSL"
        ).to_dict(),
        create_cbom_asset(
            algorithm="RSA", key_size=4096, library="OpenSSL"
        ).to_dict(),
    ]

    assert len(correlate_cbom_to_qbom(cbom)) == 2


# ---------------------------------------------------- the real-schema gap --

def test_analyzer_consumes_this_products_real_cbom_shape():
    """The corpus emits `component`, not `algorithm`.

    `correlate_cbom_to_qbom` read `asset.get("algorithm")` and skipped anything
    without it. Against 200 real entries that produced zero QBOM assets: the
    function was written against a schema this product does not produce. The
    derivation below is what makes the entry observable, and it is marked as
    inferred rather than asserted.
    """
    real_entry = {
        "bom_type": "CBOM",
        "component": "RSA",
        "category": "Weak Cryptography",
        "file": "app/crypto.py",
        "line": 41,
        "evidence": "RSA.generate(...)",
        "risk": "HIGH",
    }

    results = correlate_cbom_to_qbom([real_entry])

    assert len(results) == 1, (
        "an entry using the corpus's real shape produced no QBOM asset"
    )
    assert results[0]["quantum_status"] == "QUANTUM_VULNERABLE"


def test_inferred_algorithm_is_marked_as_derived():
    """An algorithm read off a display string is an inference, not an assertion.

    Consumers must be able to tell the two apart, so the provenance travels with
    the asset rather than being implied.
    """
    from_display = correlate_cbom_to_qbom([{"component": "RSA"}])[0]
    from_explicit = correlate_cbom_to_qbom([{"algorithm": "RSA"}])[0]

    assert from_display["algorithm_provenance"] == "INFERRED_FROM_DISPLAY_NAME"
    assert from_explicit["algorithm_provenance"] == "EXPLICIT"