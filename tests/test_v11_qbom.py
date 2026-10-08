"""Tests for the CERT-In Quantum Bill of Materials layer.

FIRST: A CORRECTION THAT WAS WRONG AND IS RETRACTED
---------------------------------------------------
An earlier note in this session asserted that CERT-In's QBOM meant "Quality Bill
of Materials". That was wrong. CERT-In Technical Guidelines v2.0 Chapter 8 is
titled "Quantum BOM (QBOM) & Cryptographic BOM (CBOM)", and 8.1 defines QBOM as
focused on "components related to quantum computing and quantum-safe
cryptography". The wrong expansion survived my own scrutiny because it sounded
plausible and because the acronym soup (SBOM/QBOM/CBOM/AIBOM/HBOM) invites it.
The definition is therefore quoted from the pinned PDF in the module and asserted
below, so the error cannot come back as an unexamined assumption.

THE PROPERTY THAT MATTERS MOST
------------------------------
Nothing is invented. Most codebases have no quantum dependency at all, so the
honest output is an EMPTY inventory that says it is empty. A QBOM that always
contained an entry would be fabrication, and these tests assert emptiness as
strongly as they assert detection works -- otherwise "empty" would pass trivially
because detection is broken.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import re
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core.qbom_mappings import (  # noqa: E402
    CERTIN_PDF_SHA256,
    CERTIN_VERSION,
    NOT_OBSERVABLE,
    OBSERVABLE,
    QBOM_MINIMUM_ELEMENTS,
    QBOM_NOT_OBSERVABLE_ELEMENTS,
    QBOM_OBSERVABLE_ELEMENTS,
    build_qbom,
    detect_quantum_components,
)

Q = pathlib.Path(
    r"D:\Data\Code test\prodtest\reports\ai_benchmarks\babyagi-main"
    r"\Security_QBOM.qbom.json")

PAYLOAD = {
    "sbom": [
        {"name": "requests", "version": "2.31.0", "ecosystem": "PyPI",
         "license": "Apache-2.0", "direct": True, "manifest_file": "r.txt"},
        {"name": "flask", "version": "3.0.0", "ecosystem": "PyPI",
         "license": "BSD-3-Clause", "direct": True, "manifest_file": "r.txt"},
    ],
    "findings": [
        {"rule_id": "SQLI_1", "severity": "HIGH", "vuln_type": "sql_injection"},
        {"rule_id": "XSS_1", "severity": "MEDIUM", "vuln_type": "xss"},
    ],
}


# ===========================================================================
# Identity and provenance
# ===========================================================================

def test_qbom_is_the_QUANTUM_bill_of_materials():
    """Retraction guard: not the "Quality" BOM."""
    from core.qbom_mappings import QBOM_DEFINITION
    assert "quantum-safe cryptography" in QBOM_DEFINITION
    assert "Quality" not in QBOM_DEFINITION
    doc = build_qbom(PAYLOAD)
    assert doc["bom_type_expansion"] == "Quantum Bill of Materials"


def test_guideline_is_pinned_by_digest():
    assert re.fullmatch(r"[0-9A-F]{64}", CERTIN_PDF_SHA256), CERTIN_PDF_SHA256
    assert CERTIN_VERSION == "v2.0"
    assert build_qbom(PAYLOAD)["specification"]["pdf_sha256"] == CERTIN_PDF_SHA256


# ===========================================================================
# Table 8: all 11 minimum elements
# ===========================================================================

def test_all_eleven_table8_elements_are_present():
    assert len(QBOM_MINIMUM_ELEMENTS) == 11
    names = {v["name"] for v in QBOM_MINIMUM_ELEMENTS.values()}
    # Transcribed from the pinned PDF; a typo here would be a compliance claim.
    assert names == {
        "Model Name", "Version", "Vendor & Origin Information",
        "License Information", "Cryptographic Asset", "Communication Protocol",
        "Hardware", "Software Dependencies", "Environmental Impact",
        "Vulnerabilities Information", "Attestations",
    }


def test_every_element_has_a_description_table_and_reason():
    for key, spec in QBOM_MINIMUM_ELEMENTS.items():
        assert spec["description"], key
        assert spec["table"].startswith("Table 8"), key
        assert len(spec["reason"]) > 30, key


def test_coverage_split_is_declared():
    doc = build_qbom(PAYLOAD)
    cov = doc["element_coverage"]
    assert cov["minimum_elements"] == 11
    assert cov["observable_from_source"] == len(QBOM_OBSERVABLE_ELEMENTS) == 5
    assert cov["not_observable_from_source"] == len(QBOM_NOT_OBSERVABLE_ELEMENTS) == 6
    assert cov["observable_from_source"] + cov["not_observable_from_source"] == 11


def test_hardware_describing_elements_are_not_observable_from_source():
    """NEGATIVE and load-bearing.

    Six elements describe a physical quantum device. A source analyser cannot see
    one, so claiming coverage would be a lie and emitting invented values would
    be worse.
    """
    for key in ("model_name", "version", "vendor_origin",
                "communication_protocol", "hardware", "environmental_impact"):
        assert key in QBOM_NOT_OBSERVABLE_ELEMENTS, key
        assert not QBOM_MINIMUM_ELEMENTS[key]["observable"], key
        doc = build_qbom(PAYLOAD)
        assert doc["minimum_elements"][key]["element_status"] == NOT_OBSERVABLE
        assert doc["minimum_elements"][key]["value"] is None, key


def test_observable_elements_actually_carry_values():
    doc = build_qbom(PAYLOAD)
    for key in QBOM_OBSERVABLE_ELEMENTS:
        if key == "attestations":
            continue
        assert doc["minimum_elements"][key]["value"] not in (None, [], {}), key


# ===========================================================================
# THE property that matters most: nothing is invented
# ===========================================================================

def test_a_codebase_with_no_quantum_dependency_yields_an_empty_inventory():
    quantum, pqc = detect_quantum_components(PAYLOAD["sbom"])
    assert quantum == []
    assert pqc == []
    doc = build_qbom(PAYLOAD)
    assert doc["quantum_components_detected"] is False
    assert doc["quantum_components"] == []


def test_detection_flag_always_agrees_with_the_list():
    for sbom in ([], PAYLOAD["sbom"],
                 [{"name": "qiskit", "version": "1.0"}],
                 [{"name": "liboqs-python"}]):
        doc = build_qbom({"sbom": sbom, "findings": []})
        assert doc["quantum_components_detected"] == bool(doc["quantum_components"])


def test_detection_works_on_a_real_quantum_sdk():
    """So that the empty-inventory tests above are not vacuous."""
    quantum, _ = detect_quantum_components([{"name": "qiskit", "version": "1.2.0"}])
    assert len(quantum) == 1
    assert quantum[0]["name"] == "qiskit"
    assert quantum[0]["version"] == "1.2.0"


def test_detection_recognises_post_quantum_libraries():
    _, pqc = detect_quantum_components([{"name": "liboqs-python", "version": "0.10"}])
    assert len(pqc) == 1


def test_detection_ignores_ordinary_packages():
    quantum, pqc = detect_quantum_components(
        [{"name": "requests"}, {"name": "numpy"}, {"name": "flask"}])
    assert quantum == [] and pqc == []


def test_the_artifact_states_it_invents_nothing():
    doc = build_qbom(PAYLOAD)
    assert any("synthesised" in l for l in doc["limits"])
    assert any("Hardware Bill of Materials" in l for l in doc["limits"])


# ===========================================================================
# Attestations: a content digest, not a signature
# ===========================================================================

def test_attestation_is_not_claimed_as_a_digital_signature():
    att = build_qbom(PAYLOAD)["minimum_elements"]["attestations"]["value"]
    assert att["is_digital_signature"] is False
    assert "not a signature" in att["note"].lower()
    assert "authenticity" in att["note"].lower()


def test_attestation_covers_the_element_values():
    """THE FIX. An earlier version stripped `value` from every element before
    hashing, so the digest covered only names and statuses: every inventory value
    could be altered and the attestation would not move. Caught by asserting the
    digest changes when the findings change."""
    att = build_qbom(PAYLOAD)["minimum_elements"]["attestations"]["value"]
    assert "complete value of all 10 other minimum elements" in att["covers"]


def test_attestation_digest_changes_when_the_data_changes():
    a = build_qbom(PAYLOAD)
    b = build_qbom({**PAYLOAD, "findings": []})
    assert (a["minimum_elements"]["attestations"]["value"]["digest"]
            != b["minimum_elements"]["attestations"]["value"]["digest"])


def test_attestation_digest_changes_when_a_dependency_changes():
    a = build_qbom(PAYLOAD)
    b = build_qbom({**PAYLOAD,
                    "sbom": PAYLOAD["sbom"] + [{"name": "evil", "version": "1"}]})
    assert (a["minimum_elements"]["attestations"]["value"]["digest"]
            != b["minimum_elements"]["attestations"]["value"]["digest"])


def test_attestation_digest_is_a_real_sha256():
    att = build_qbom(PAYLOAD)["minimum_elements"]["attestations"]["value"]
    assert att["algorithm"] == "SHA-256"
    assert len(att["digest"]) == 64
    assert re.fullmatch(r"[0-9a-f]{64}", att["digest"]), att["digest"]


def test_build_is_deterministic():
    a = json.dumps(build_qbom(PAYLOAD), sort_keys=True)
    b = json.dumps(build_qbom(PAYLOAD), sort_keys=True)
    assert a == b


# ===========================================================================
# Wiring and the deferred HBOM
# ===========================================================================

def test_main_publishes_payload_qbom():
    """The artifact probe resolves payload["qbom"], and the PQ handoff names the
    same key independently. Two routes agreeing is reassuring, not coincidental."""
    src = (ROOT / "main.py").read_text(encoding="utf-8")
    assert 'payload["qbom"]' in src
    assert 'payload["qbom_summary"]' in src
    assert "Security_QBOM.qbom.json" in src


def test_qbom_is_a_separate_artifact():
    src = (ROOT / "main.py").read_text(encoding="utf-8")
    assert 'Security_QBOM.qbom.json' in src
    # Separate from the SBOM: CERT-In defines SBOM/QBOM/CBOM/AIBOM/HBOM as
    # distinct types, so folding QBOM into the SBOM would erase that.
    assert 'Security_SBOM' not in src.split('Security_QBOM.qbom.json')[0][-400:]


def test_the_new_artifact_is_excluded_from_self_scan():
    """The PQ handoff names this exact hazard: a new artifact filename must be
    added to EXCLUDED_FILES or the scanner reads its own output back as input.

    The whole set literal is read, not just its first line. A single-line read
    passed only while the set happened to be written on one line, and would have
    gone on passing the moment it was wrapped -- which is exactly how a real
    exclusion can be added and still be reported missing, or present and be
    reported absent.
    """
    sast = (ROOT / "scanner" / "sast.py").read_text(encoding="utf-8")
    block = sast.split("EXCLUDED_FILES = {", 1)[1].split("}", 1)[0]
    assert '"qbom.json"' in block, block
    assert '"security_qbom.pq.json"' in block, block


def test_hbom_is_still_reported_as_not_implemented():
    src = (ROOT / "core" / "qbom_mappings.py").read_text(encoding="utf-8")
    assert "NOT_IMPLEMENTED" in src
    doc = build_qbom(PAYLOAD)
    assert doc["minimum_elements"]["hardware"]["value"] is None
    assert any("NOT implemented" in l for l in doc["limits"])


def test_hbom_probe_is_left_failing_and_says_why():
    """NEGATIVE: a deferred item must keep the baseline honest. Relaxing the probe
    would make CERT_IN verify while a required BOM type is absent."""
    import re as _re

    from core.conformance_baseline import STANDARD_BASELINE

    std = next(s for s in STANDARD_BASELINE if s["key"] == "CERT_IN")
    probe = next(p for p in std["probes"] if p["name"] == "hbom_emitted")
    assert "DELIBERATELY STILL FAILING" in probe["description"]
    assert "deferred" in probe["description"].lower()


def test_qbom_probes_pass_against_a_real_artifact():
    # Guard on the FILE, not the directory. Q is the corpus target directory, which
    # survives having its clean_report.json deleted -- and corpus artifacts are
    # deleted and regenerated as a matter of course when the corpus is rescanned.
    # Checking the directory meant this test raised FileNotFoundError from inside the
    # test body during a rescan, which reads as a code defect and is not one.
    _art = Q.parent / "clean_report.json"
    if not _art.exists():
        pytest.skip(f"babyagi artifact not present: {_art}")
    payload = json.loads(
        _art.read_text(encoding="utf-8", errors="replace"))
    doc = build_qbom(payload)
    assert doc["element_coverage"]["minimum_elements"] == 11
    assert doc["quantum_components"] == [], (
        "babyagi is a plain Python task-runner; any quantum component here "
        "would be invented")


def test_empty_payload_is_safe():
    doc = build_qbom({})
    assert len(doc["minimum_elements"]) == 11
    assert doc["quantum_components_detected"] is False
    att = doc["minimum_elements"]["attestations"]["value"]
    assert len(att["digest"]) == 64


def test_element_count_is_invariant_regardless_of_payload():
    for payload in ({}, {"sbom": []}, {"findings": []}, PAYLOAD):
        assert len(build_qbom(payload)["minimum_elements"]) == 11


def test_attestation_matches_a_hand_computed_digest():
    """Independently recompute the digest so the value is not self-confirming."""
    doc = build_qbom(PAYLOAD)
    body = {k: v for k, v in doc.items() if k != "minimum_elements"}
    body["minimum_elements"] = {
        k: ({kk: vv for kk, vv in v.items() if kk != "value"}
            if k == "attestations" else v)
        for k, v in doc["minimum_elements"].items()
    }
    canon = json.dumps(body, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=False, default=str)
    expected = hashlib.sha256(canon.encode("utf-8")).hexdigest()
    assert doc["minimum_elements"]["attestations"]["value"]["digest"] == expected