"""Phase 4: CBOM/AI-BOM CycloneDX 1.6 conformance and secret non-republication.

Two claims are under test:

1. Conformance. reporting/cyclonedx_bom_export.py emits the crypto and AI
   inventories as CycloneDX 1.6 documents whose cryptographic-asset
   components carry the cryptoProperties block the spec defines, and
   analysis/validation/sbom_conformance.py checks the structure a CBOM
   consumer (cbomkit) actually parses -- assetType enum, the
   asset-specific sub-object, unique bom-refs.

2. Non-republication. The CBOM private-key rule's evidence field IS the
   PEM block. Every serialization path that copied that field verbatim
   republished the secret the scan found (probe_leak_audit caught three
   such paths: the main SBOM's rsecopsx:raw, the 1.6 CBOM's evidence
   property, and Security_QBOM.pq.json). These tests pin each path so a
   fourth cannot appear quietly.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from analysis.validation.sbom_conformance import (  # noqa: E402
    _aibom_schema_check,
    _cbomkit_parse_check,
    _result_valid,
)
from core.redaction import PEM_PLACEHOLDER, redact_pem, redact_pem_deep  # noqa: E402
from reporting.cyclonedx_bom_export import (  # noqa: E402
    build_cyclonedx_aibom,
    build_cyclonedx_cbom,
)

FIXTURE_PEM = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEpAIBAAKCAQEAyMockKeyMaterialNotReal000000000000000000000000000\n"
    "0000000000000000000000000000000000000000000000000000000000000000000\n"
    "-----END RSA PRIVATE KEY-----"
)


def _item(component: str, evidence: str = "", **over) -> dict:
    item = {
        "bom_type": "CBOM",
        "component": component,
        "category": "test",
        "file": "src/app.py",
        "line": 10,
        "evidence": evidence,
        "risk": "HIGH",
        "recommendation": "fix",
    }
    item.update(over)
    return item


# --------------------------------------------------------------------------
# Document identity and shape
# --------------------------------------------------------------------------

def test_document_is_cyclonedx_16_with_required_top_level_fields():
    doc = build_cyclonedx_cbom([_item("MD5", "hashlib.md5(x)")], "t", "1.0")
    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] == "1.6"          # cryptographic-asset is 1.6+;
    assert doc["version"] == 1                  # 1.5 has no cryptoProperties
    assert doc["serialNumber"].startswith("urn:uuid:")
    assert doc["metadata"]["tools"]["components"][0]["name"] == "t"


def test_empty_inventory_is_still_a_well_formed_document():
    # Most scan targets contain no crypto code at all, and the artifact is
    # written unconditionally -- so the empty shape must be as valid as the
    # populated one, or every clean-target run emits a malformed BOM.
    for doc in (build_cyclonedx_cbom([], "t", "1"),
                build_cyclonedx_aibom([], "t", "1")):
        assert doc["components"] == []
        assert doc["bomFormat"] == "CycloneDX"
        json.dumps(doc)  # must round-trip


# --------------------------------------------------------------------------
# cryptoProperties mapping per asset type (CDX 1.6 schema)
# --------------------------------------------------------------------------

def test_algorithm_assets_carry_algorithm_properties():
    doc = build_cyclonedx_cbom([
        _item("MD5", "hashlib.md5(data)"),
        _item("AES", "AES.new(key, AES.MODE_GCM, nonce=n)"),
        _item("RSA", "RSA.generate(2048)"),
    ], "t", "1")
    by_name = {c["name"]: c for c in doc["components"]}
    assert by_name["MD5"]["type"] == "cryptographic-asset"
    props = by_name["MD5"]["cryptoProperties"]
    assert props["assetType"] == "algorithm"
    assert props["algorithmProperties"]["primitive"] == "hash"
    assert props["algorithmProperties"]["executionEnvironment"] == "software-plain-ram"
    # Quantum figures: MD5 is classical-only, AES-128 meets NIST category 1.
    assert props["algorithmProperties"]["nistQuantumSecurityLevel"] == 0
    assert by_name["AES"]["cryptoProperties"]["algorithmProperties"][
        "nistQuantumSecurityLevel"] == 1
    # Mode is only claimed when the evidence names it.
    assert by_name["AES"]["cryptoProperties"]["algorithmProperties"]["mode"] == "gcm"
    assert by_name["RSA"]["cryptoProperties"]["algorithmProperties"]["primitive"] == "pke"


def test_protocol_asset_uses_protocol_properties():
    doc = build_cyclonedx_cbom(
        [_item("TLS / SSL", "ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)")], "t", "1")
    comp = doc["components"][0]
    props = comp["cryptoProperties"]
    assert props["assetType"] == "protocol"
    assert props["protocolProperties"]["type"] == "tls"
    # No version claimed: the rule matches the call shape, not a negotiation.
    assert "version" not in props["protocolProperties"]


def test_key_material_asset_declares_compromised_state_without_value():
    doc = build_cyclonedx_cbom(
        [_item("Hardcoded Private Key", FIXTURE_PEM)], "t", "1")
    comp = doc["components"][0]
    props = comp["cryptoProperties"]
    assert props["assetType"] == "related-crypto-material"
    rcm = props["relatedCryptoMaterialProperties"]
    assert rcm["type"] == "private-key"
    assert rcm["state"] == "compromised"     # checked-in material is exposed
    assert "value" not in rcm                # and never republished


def test_certificate_asset_declares_certificate_properties():
    doc = build_cyclonedx_cbom(
        [_item("Hardcoded Certificate", "-----BEGIN CERTIFICATE-----")], "t", "1")
    props = doc["components"][0]["cryptoProperties"]
    assert props["assetType"] == "certificate"
    assert props["certificateProperties"]["certificateFormat"] == "PEM"


def test_unknown_component_exports_as_bare_algorithm_rather_than_dropping():
    # Dropping an unrecognised crypto observation to keep the document tidy
    # is the wrong trade for an inventory.
    doc = build_cyclonedx_cbom([_item("Some Future Cipher", "use()")], "t", "1")
    assert len(doc["components"]) == 1
    assert doc["components"][0]["cryptoProperties"]["assetType"] == "algorithm"


# --------------------------------------------------------------------------
# Non-republication: no serialization path may emit the PEM body
# --------------------------------------------------------------------------

def test_cbom_evidence_property_never_contains_pem_body():
    doc = build_cyclonedx_cbom(
        [_item("Hardcoded Private Key", FIXTURE_PEM)], "t", "1")
    dumped = json.dumps(doc)
    assert "MIIEpAIBAAKCAQEA" not in dumped
    assert "BEGIN RSA PRIVATE KEY" not in dumped


def test_evidence_property_redacts_pem_from_other_assets():
    # The regression this pins: the TLS rule's context window crossed the
    # fixture's PEM between its BEGIN and END lines, so evidence from a
    # *protocol* asset still carried key material. Redaction happens before
    # the 500-char slice; slicing first cuts the block in half and the
    # END line the pattern needs never lands in the window.
    crossing = "ctx = ssl.SSLContext(...)\n" + FIXTURE_PEM + "\nmore context"
    doc = build_cyclonedx_cbom([_item("TLS / SSL", crossing)], "t", "1")
    dumped = json.dumps(doc)
    assert "MIIEpAIBAAKCAQEA" not in dumped
    assert PEM_PLACEHOLDER in dumped


def test_redact_pem_handles_unterminated_block():
    # Window that stops mid-block: BEGIN present, END sliced away.
    window = "prefix\n-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEAtruncated"
    out = redact_pem(window)
    assert "MIIEpAIBAAKCAQEA" not in out
    assert PEM_PLACEHOLDER in out


def test_redact_pem_deep_walks_nested_records():
    record = {"evidence": [{"detail": FIXTURE_PEM}], "line": 5, "nested": {"v": FIXTURE_PEM}}
    out = redact_pem_deep(record)
    dumped = json.dumps(out)
    assert "MIIEpAIBAAKCAQEA" not in dumped
    assert out["line"] == 5  # non-strings untouched


def test_main_sbom_raw_property_redacts_key_material():
    # The main SBOM predates 1.6 and embeds CBOM items as opaque data
    # components -- rsecopsx:raw reproduces the item dict, evidence and all.
    from reporting.cyclonedx_export import _bom_asset_components

    payload = {"cbom": [_item("Hardcoded Private Key", FIXTURE_PEM)]}
    dumped = json.dumps(_bom_asset_components(payload))
    assert "MIIEpAIBAAKCAQEA" not in dumped
    assert "rsecopsx:raw" in dumped


def test_pq_qbom_evidence_normalization_redacts_key_material():
    # Security_QBOM.pq.json is built from CBOM evidence via this function;
    # the artifact-wide leak audit found the PEM in that document.
    from scanner.crypto_quantum_analyzer import _normalize_evidence

    out = _normalize_evidence(FIXTURE_PEM)
    assert out == [{"detail": PEM_PLACEHOLDER}]

    out_list = _normalize_evidence([{"detail": FIXTURE_PEM}, "plain"])
    dumped = json.dumps(out_list)
    assert "MIIEpAIBAAKCAQEA" not in dumped


# --------------------------------------------------------------------------
# Conformance checker: rejects the structural defects cbomkit trips on
# --------------------------------------------------------------------------

def _crypto_comp(**over):
    comp = {
        "type": "cryptographic-asset",
        "bom-ref": "ref-1",
        "name": "MD5",
        "cryptoProperties": {
            "assetType": "algorithm",
            "algorithmProperties": {"primitive": "hash"},
        },
    }
    comp.update(over)
    return comp


def test_cbomkit_check_accepts_well_formed_document():
    doc = {"components": [_crypto_comp()]}
    res = _cbomkit_parse_check(doc)
    assert res == {"valid": True, "errors": [], "crypto_components": 1}


def test_cbomkit_check_rejects_crypto_asset_without_crypto_properties():
    doc = {"components": [_crypto_comp()]}
    del doc["components"][0]["cryptoProperties"]
    res = _cbomkit_parse_check(doc)
    assert not res["valid"]
    assert any("missing cryptoProperties" in e for e in res["errors"])


def test_cbomkit_check_rejects_invalid_asset_type():
    doc = {"components": [_crypto_comp()]}
    doc["components"][0]["cryptoProperties"]["assetType"] = "algorithmm"
    res = _cbomkit_parse_check(doc)
    assert not res["valid"]
    assert any("invalid assetType" in e for e in res["errors"])


def test_cbomkit_check_rejects_asset_type_missing_its_sub_object():
    # Schema-valid (assetType alone satisfies the 1.6 required list) but
    # unparsable: algorithmProperties is where the algorithm lives.
    doc = {"components": [_crypto_comp()]}
    del doc["components"][0]["cryptoProperties"]["algorithmProperties"]
    res = _cbomkit_parse_check(doc)
    assert not res["valid"]
    assert any("missing algorithmProperties" in e for e in res["errors"])


def test_cbomkit_check_rejects_duplicate_bom_ref():
    second = _crypto_comp()
    second["bom-ref"] = "ref-1"
    doc = {"components": [_crypto_comp(), second]}
    res = _cbomkit_parse_check(doc)
    assert not res["valid"]
    assert any("duplicate bom-ref" in e for e in res["errors"])


def test_cbomkit_check_requires_crypto_components_to_exist():
    res = _cbomkit_parse_check({"components": [{"type": "data", "name": "x"}]})
    assert not res["valid"]
    assert res["errors"] == ["no cryptographic-asset components"]


def test_aibom_check_requires_provider_provenance():
    comp = {"type": "machine-learning-model", "bom-ref": "r", "name": "openai",
            "properties": []}
    res = _aibom_schema_check({"components": [comp]})
    assert not res["valid"]
    assert any("rsecopsx:provider" in e for e in res["errors"])


def test_aibom_document_carries_provider_confidence_and_model_hint():
    items = [{
        "bom_type": "AI-BOM", "provider": "OpenAI", "component": "openai",
        "model_hint": "gpt-4o", "file": "app.py", "line": 3, "evidence": "import openai",
        "risk": "LOW", "recommendation": "review", "confidence": "HIGH",
        "confidence_score": 0.9, "detection_mode": "regex",
        "evidence_type": ["import"],
    }]
    doc = build_cyclonedx_aibom(items, "t", "1")
    assert doc["components"][0]["type"] == "machine-learning-model"
    res = _aibom_schema_check(doc)
    assert res["valid"], res["errors"]
    names = {p["name"]: p["value"] for p in doc["components"][0]["properties"]}
    assert names["rsecopsx:provider"] == "OpenAI"
    assert names["rsecopsx:confidence"] == "HIGH"
    assert names["rsecopsx:model_hint"] == "gpt-4o"


def test_duplicate_bom_refs_are_disambiguated():
    # Two detections of the same provider must not violate bom-ref uniqueness.
    item = {"provider": "OpenAI", "component": "openai", "file": "a.py", "line": 1,
            "confidence": "HIGH"}
    doc = build_cyclonedx_aibom([item, dict(item)], "t", "1")
    refs = [c["bom-ref"] for c in doc["components"]]
    assert len(refs) == len(set(refs))


# --------------------------------------------------------------------------
# Scanner duplicate suppression
# --------------------------------------------------------------------------

def test_cbom_scanner_reports_one_observation_per_component_line():
    # ssl.PROTOCOL_TLS_CLIENT satisfies several alternatives of one rule's
    # pattern; three copies of one observation overstate inventory size.
    from scanner.cbom import generate_cbom

    items = generate_cbom(str(ROOT / "tests" / "e2e_targets" / "crypto_ai"))
    keys = [(i.get("component"), i.get("file"), i.get("line")) for i in items]
    assert len(keys) == len(set(keys))
    assert any(i.get("component") == "Hardcoded Private Key" for i in items)


# --------------------------------------------------------------------------
# Verdict aggregation (text output + exit code)
# --------------------------------------------------------------------------

def test_result_valid_unnests_per_version_results():
    # cyclonedx results are {"1.5": {...}, "1.7": {...}} with no top-level
    # "valid"; reading it directly reported FAIL and exited 1 while both
    # versions actually passed.
    assert _result_valid({"1.5": {"valid": True}, "1.7": {"valid": True},
                          "quality_score": 10.0}) is True
    assert _result_valid({"1.5": {"valid": True}, "1.7": {"valid": False}}) is False
    assert _result_valid({"valid": True}) is True
    assert _result_valid({"valid": False, "errors": ["x"]}) is False
    assert _result_valid({"error": "file not found"}) is False


# --------------------------------------------------------------------------
# Official-schema validation (network; skipped when unavailable)
# --------------------------------------------------------------------------

def test_documents_validate_against_official_cyclonedx_16_schema():
    from analysis.validation.sbom_conformance import _cyclonedx_schema_check

    cbom = build_cyclonedx_cbom([
        _item("MD5", "hashlib.md5(x)"),
        _item("TLS / SSL", "ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)"),
        _item("Hardcoded Private Key", FIXTURE_PEM),
    ], "t", "1")
    aibom = build_cyclonedx_aibom(
        [{"provider": "OpenAI", "component": "openai", "file": "a.py", "line": 1}],
        "t", "1")

    for label, doc in (("cbom", cbom), ("aibom", aibom)):
        entry = _cyclonedx_schema_check(doc, target_versions=("1.6",)).get("1.6", {})
        if "valid" not in entry:
            pytest.skip("official schema unavailable: %s" % entry)
        assert entry["valid"], "%s failed official 1.6 schema: %s" % (
            label, entry.get("errors"))
