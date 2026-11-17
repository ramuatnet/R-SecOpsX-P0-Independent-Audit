"""Phase 4.1/4.2: CBOM cryptoFunctions purpose model, padding, detection
context, and uses-dependencies.

WHAT WAS BROKEN
---------------
cbomctl (lvlrSajjad/cbomctl, one of the 240 CBOM-ecosystem tools in
cyclonedx_github_repositories.csv) yields INDET on any algorithm asset
with no cryptoFunctions list. Two shapes produced those: ECC (one rule
matches ECDSA, ECDH and bare curve usage alike, so no function set could
be named statically) and any future rule outside the exporter's map (the
fallback branch emitted primitive "unknown" and no functions).

These tests pin the fix and the Phase 4.1 schema-carried fields:

* purpose model -- scanner/cbom.py::_detect_purpose disambiguates the
  concrete algorithm and function set from the call site, family
  capability set otherwise, purpose_source saying which;
* padding -- evidence-derived, 1.6 enum values only;
* detectionContext -- the IBM extension field has no core-schema slot
  (verified against official 1.6 AND 1.7: cryptoProperties is
  additionalProperties false), so it rides on the core-native
  component.evidence.occurrences[] {location, line, additionalContext},
  the same block the official CBOM examples emit;
* dependencyType uses|implements -- likewise absent from core schemas
  (dependency is {ref, dependsOn, provides}, additionalProperties false);
  uses rides on dependsOn from metadata.component to every crypto asset.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from reporting.cyclonedx_bom_export import (  # noqa: E402
    build_cyclonedx_cbom,
)
from scanner.cbom import (  # noqa: E402
    _detect_purpose,
    _make_cbom_item,
    CRYPTO_RULES,
    generate_cbom,
)

FIXTURE_PEM = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF6PZF1pG+nF+vJ9qVqYk9yGqZ\n"
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


def _props_by_name(doc: dict) -> dict:
    return {c["name"]: c for c in doc["components"]}


# --------------------------------------------------------------------------
# Purpose model: call-site disambiguation (the INDET fix)
# --------------------------------------------------------------------------

def test_ecc_signature_call_site_yields_determinate_purpose():
    out = _detect_purpose("ECC", "crypto.createSign('ecdsa')")
    assert out["algorithm"] == "ECDSA"
    assert out["primitive"] == "signature"
    assert out["crypto_functions"] == ["sign", "verify"]
    assert out["purpose"] == "signature"
    assert out["purpose_source"] == "call-site"
    assert out["confidence"] == 3
    assert "ecdsa" in out["detection_keywords"]


def test_ecc_key_agreement_call_site_yields_determinate_purpose():
    out = _detect_purpose(
        "ECC", "KeyAgreement.getInstance('ECDH').doFinal(shared)")
    assert out["algorithm"] == "ECDH"
    assert out["primitive"] == "key-agree"
    assert out["crypto_functions"] == ["keyderive", "keygen"]
    assert out["purpose"] == "key-agreement"
    assert out["purpose_source"] == "call-site"


def test_ecc_family_fallback_is_still_non_empty_and_tagged():
    # Bare curve usage: the call site says nothing about sign vs agree.
    # The union of the family's capabilities, explicitly tagged as a
    # family-scope answer, is the determinate shape cbomctl can score.
    out = _detect_purpose("ECC", "p256 = elliptic.curve.p256()")
    assert out["primitive"] == "unknown"          # honest: purpose unknown
    assert out["crypto_functions"]                # but never empty (INDET)
    assert set(out["crypto_functions"]) >= {"sign", "keyderive"}
    assert out["purpose_source"] == "family"
    assert out["confidence"] == 2
    assert out["detection_keywords"] == []


def test_rsa_signature_and_encryption_call_sites_split():
    sig = _detect_purpose("RSA", "Signature.getInstance('SHA256withRSA')")
    assert sig["primitive"] == "signature"
    assert sig["crypto_functions"] == ["sign", "verify"]
    assert sig["purpose_source"] == "call-site"

    enc = _detect_purpose(
        "RSA", "Cipher.getInstance('RSA/ECB/OAEPWithSHA-1AndMGF1Padding')")
    assert enc["primitive"] == "pke"
    assert enc["crypto_functions"] == ["encrypt", "decrypt"]
    assert enc["purpose"] == "encryption"

    bare = _detect_purpose("RSA", "RSA.generate(2048)")
    assert bare["crypto_functions"] == ["encrypt", "decrypt", "sign", "verify"]
    assert bare["purpose_source"] == "family"


def test_hash_and_cipher_families_are_purpose_determinate_by_family():
    # A hash is always a hash: no call-site reclassification, but the
    # fields must exist so the exporter has something to emit.
    for component, want_primitive in (("MD5", "hash"), ("SHA1", "hash"),
                                      ("AES", "block-cipher"),
                                      ("RC4", "stream-cipher"),
                                      ("DES / 3DES", "block-cipher")):
        out = _detect_purpose(component, "some call")
        assert out["primitive"] == want_primitive
        assert out["crypto_functions"]
        assert out["purpose_source"] == "family"


def test_non_algorithm_components_have_no_purpose_model():
    for component in ("TLS / SSL", "Hardcoded Private Key",
                      "Hardcoded Certificate"):
        assert _detect_purpose(component, "x") is None


def test_scanner_items_carry_purpose_fields_end_to_end():
    rule = next(r for r in CRYPTO_RULES if r["component"] == "ECC")
    item = _make_cbom_item(rule, "src/ecc.py", 7,
                           "sig = crypto.createSign('ecdsa')")
    assert item["primitive"] == "signature"
    assert item["crypto_functions"] == ["sign", "verify"]
    assert item["purpose_source"] == "call-site"


# --------------------------------------------------------------------------
# Exporter: no algorithm asset may leave without cryptoFunctions
# --------------------------------------------------------------------------

def test_every_algorithm_asset_exports_non_empty_crypto_functions():
    # The cbomctl gate: INDET comes from a MISSING cryptoFunctions list.
    doc = build_cyclonedx_cbom([
        _item("MD5", "hashlib.md5(x)"),
        _item("SHA1", "hashlib.sha1(x)"),
        _item("DES / 3DES", "DES.new(k, DES.MODE_CBC)"),
        _item("RC4", "ARC4.new(k)"),
        _item("AES", "AES.new(k, AES.MODE_GCM)"),
        _item("RSA", "RSA.generate(2048)"),
        _item("ECC", "ec.generate_private_key(ec.SECP256R1())"),
        _item("Some Future Cipher", "use()"),
    ], "t", "1")
    for comp in doc["components"]:
        cprops = comp["cryptoProperties"]
        if cprops["assetType"] != "algorithm":
            continue
        assert cprops["algorithmProperties"]["cryptoFunctions"], comp["name"]


def test_real_scanner_path_also_exports_non_empty_functions(tmp_path):
    # Same gate through the actual scanner -> exporter pipeline on real
    # evidence, not fixture dicts: any algorithm family rule with no
    # call-site signal must still produce a function list.
    src = tmp_path / "crypto_usage.py"
    src.write_text(
        "import hashlib\n"
        "from Crypto.Cipher import AES, ARC4\n"
        "from Crypto.PublicKey import RSA\n"
        "h = hashlib.md5(b'x')\n"
        "c = AES.new(key, AES.MODE_GCM, nonce=n)\n"
        "r = RSA.generate(2048)\n"
        "p = elliptic.curve.p256()\n",
        encoding="utf-8")
    items = generate_cbom(str(src))
    assert items, "fixture must produce findings"
    for item in items:
        assert item.get("crypto_functions"), item.get("component")

    doc = build_cyclonedx_cbom(items, "t", "1")
    for comp in doc["components"]:
        cprops = comp["cryptoProperties"]
        if cprops["assetType"] == "algorithm":
            assert cprops["algorithmProperties"]["cryptoFunctions"]


def test_aead_mode_appends_tag_function():
    doc = build_cyclonedx_cbom(
        [_item("AES", "Cipher.getInstance(\"AES/GCM/NoPadding\")")], "t", "1")
    alg = doc["components"][0]["cryptoProperties"]["algorithmProperties"]
    assert alg["mode"] == "gcm"
    assert "tag" in alg["cryptoFunctions"]


# --------------------------------------------------------------------------
# Padding (4.1): evidence-derived, enum values only
# --------------------------------------------------------------------------

def test_padding_inferred_from_evidence():
    doc = build_cyclonedx_cbom([
        _item("AES", "Cipher.getInstance(\"AES/CBC/PKCS7Padding\")"),
        _item("RSA", "Cipher.getInstance(\"RSA/ECB/OAEPWithSHA-1AndMGF1Padding\")"),
        _item("AES", "Cipher.getInstance(\"AES/CTR/NoPadding\")"),
        _item("RSA", "Signature.getInstance(\"SHA256withRSAandMGF1\")"),
        _item("AES", "AES.new(key, AES.MODE_GCM, nonce=n)"),  # silent: no field
    ], "t", "1")
    algs = [c["cryptoProperties"]["algorithmProperties"]
            for c in doc["components"]]
    assert algs[0]["padding"] == "pkcs7"
    assert algs[1]["padding"] == "oaep"
    assert algs[2]["padding"] == "raw"
    assert algs[3]["padding"] == "other"      # PSS/MGF1 has no enum value
    assert "padding" not in algs[4]           # never invented from silence


def test_padding_never_applies_to_hash_assets():
    # A 2000-char evidence window can mention a padding name without the
    # asset being a cipher; hash primitives must not grow a padding field.
    doc = build_cyclonedx_cbom(
        [_item("MD5", "# then we call CBC/PKCS7Padding in the other module\n"
                      "hashlib.md5(data)")], "t", "1")
    alg = doc["components"][0]["cryptoProperties"]["algorithmProperties"]
    assert "padding" not in alg


# --------------------------------------------------------------------------
# detectionContext via core-native evidence.occurrences
# --------------------------------------------------------------------------

def test_occurrences_carry_location_line_and_context():
    doc = build_cyclonedx_cbom(
        [_item("MD5", "hashlib.md5(data)", file="src/h.py", line=42)],
        "t", "1")
    comp = doc["components"][0]
    occ = comp["evidence"]["occurrences"][0]
    assert occ["location"] == "src/h.py"
    assert occ["line"] == 42
    assert "hashlib.md5" in occ["additionalContext"]
    # Same redaction + cap as the rsecopsx:evidence property.
    prop = {p["name"]: p["value"] for p in comp["properties"]}
    assert occ["additionalContext"] == prop["rsecopsx:evidence"]


def test_private_key_asset_gets_no_occurrences_and_no_pem():
    doc = build_cyclonedx_cbom(
        [_item("Hardcoded Private Key", FIXTURE_PEM)], "t", "1")
    comp = doc["components"][0]
    assert "evidence" not in comp            # no occurrences carrier either
    dumped = json.dumps(doc)
    assert "MIIEpAIBAAKCAQEA" not in dumped
    assert "BEGIN RSA PRIVATE KEY" not in dumped


def test_purpose_provenance_properties_surface_in_export():
    # Real scanner path (fixture dicts predate the purpose model and carry
    # no purpose fields; _make_cbom_item is where detection happens).
    rule = next(r for r in CRYPTO_RULES if r["component"] == "ECC")
    item = _make_cbom_item(rule, "src/ecc.py", 7,
                           "crypto.createSign('ecdsa')")
    doc = build_cyclonedx_cbom([item], "t", "1")
    comp = doc["components"][0]
    assert comp["name"] == "ECC"             # family name kept as identity
    props = {p["name"]: p["value"] for p in comp["properties"]}
    assert props["rsecopsx:purpose"] == "signature"
    assert props["rsecopsx:purpose_source"] == "call-site"
    assert props["rsecopsx:confidence"] == "3"
    assert "ecdsa" in props["rsecopsx:detection-keywords"]
    alg = comp["cryptoProperties"]["algorithmProperties"]
    assert alg["primitive"] == "signature"
    assert alg["cryptoFunctions"] == ["sign", "verify"]


# --------------------------------------------------------------------------
# dependencyType uses|implements via core dependsOn/provides
# --------------------------------------------------------------------------

def test_application_uses_all_crypto_assets_via_depends_on():
    doc = build_cyclonedx_cbom(
        [_item("MD5", "hashlib.md5(x)"), _item("AES", "AES.new(k)")],
        "t", "1", target_name="demo-app")
    meta_comp = doc["metadata"]["component"]
    assert meta_comp["type"] == "application"
    assert meta_comp["name"] == "demo-app"
    deps = doc["dependencies"]
    assert len(deps) == 1
    assert deps[0]["ref"] == meta_comp["bom-ref"]
    assert sorted(deps[0]["dependsOn"]) == sorted(
        c["bom-ref"] for c in doc["components"])


def test_no_dependencies_without_target_name():
    doc = build_cyclonedx_cbom([_item("MD5", "hashlib.md5(x)")], "t", "1")
    assert "dependencies" not in doc
    assert "component" not in doc["metadata"]


def test_empty_inventory_gets_no_application_component():
    doc = build_cyclonedx_cbom([], "t", "1", target_name="demo-app")
    assert "dependencies" not in doc
    assert "component" not in doc["metadata"]


# --------------------------------------------------------------------------
# Official schema validation (CycloneDX 1.6 schema vendored offline; no network)
# --------------------------------------------------------------------------

def test_new_fields_validate_against_official_cyclonedx_16_schema():
    from analysis.validation.sbom_conformance import _cyclonedx_schema_check

    ecc_rule = next(r for r in CRYPTO_RULES if r["component"] == "ECC")
    doc = build_cyclonedx_cbom([
        # Scanner-path item: carries purpose/confidence/keywords properties.
        _make_cbom_item(ecc_rule, "src/ecc.py", 7,
                        "crypto.createSign('ecdsa')"),
        _item("AES", "Cipher.getInstance(\"AES/GCM/NoPadding\")"),
        _item("RSA", "Signature.getInstance(\"SHA256withRSAandMGF1\")"),
        _item("Hardcoded Private Key", FIXTURE_PEM),
        _item("TLS / SSL", "ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)"),
    ], "t", "1", target_name="demo-app")

    entry = _cyclonedx_schema_check(doc, target_versions=("1.6",)).get("1.6", {})
    if "valid" not in entry:
        pytest.skip("official schema unavailable: %s" % entry)
    assert entry["valid"], "purpose/padding/occurrences/dependencies doc " \
                           "failed official 1.6 schema: %s" % entry.get("errors")
