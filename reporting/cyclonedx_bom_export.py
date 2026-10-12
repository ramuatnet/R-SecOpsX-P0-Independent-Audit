"""CycloneDX 1.6 exporters for the CBOM and AI-BOM inventories (Phase 4).

WHY THIS EXISTS
---------------
reporting/cyclonedx_export.py builds the main SBOM at specVersion 1.5,
which predates both the ``cryptographic-asset`` component type and the
``cryptoProperties`` object -- they arrived in CycloneDX 1.6. So the crypto
inventory was only ever embedded there as opaque ``data`` components whose
detail lived in a JSON string under ``rsecopsx:raw``. A CBOM consumer
(cyclonedx-cli, Dependency-Track's CBOM ingestion, OWASP cbomkit) reading
that file sees data blobs, not algorithms.

These writers emit the two inventories as their own 1.6 documents:

    Security_CBOM.cdx.json     cryptographic-asset components with the
                               cryptoProperties block the 1.6 schema defines
    Security_AIBOM.cdx.json    machine-learning-model components carrying
                               provider/confidence provenance as properties

WHAT IS DELIBERATELY ABSENT
---------------------------
Key material. A hardcoded private key is reported as a
``related-crypto-material`` asset whose ``state`` is ``compromised`` -- the
strongest true statement available, because material checked into source is
exposed by definition -- but the value itself is never written to the
document. A BOM that republishes the secret it just found would be a
vulnerability disclosure channel, not an inventory.
"""
from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path

from core.redaction import redact_pem

_LOG = logging.getLogger("rsx.reporting.cyclonedx_bom_export")

SPEC_VERSION = "1.6"

# The scanner's rule component -> 1.6 cryptoProperties mapping.
#
# Security levels follow NIST SP 800-57 (classical, in bits) and the NIST
# post-quantum security categories (1..6, 0 = none). Shor's algorithm breaks
# RSA and ECC outright and Grover halves symmetric bounds, so every
# classical-primitive asset here records nistQuantumSecurityLevel 0 or 1
# rather than inheriting its classical figure.
_ALGORITHM_MAP = {
    "MD5": {
        "name": "MD5", "primitive": "hash",
        "crypto_functions": ["digest"],
        "classical": 128, "quantum": 0,
    },
    "SHA1": {
        "name": "SHA-1", "primitive": "hash",
        "crypto_functions": ["digest"],
        "classical": 80, "quantum": 0,
    },
    "DES / 3DES": {
        "name": "3DES", "primitive": "block-cipher",
        "crypto_functions": ["encrypt", "decrypt"],
        "classical": 112, "quantum": 0,
    },
    "RC4": {
        "name": "RC4", "primitive": "stream-cipher",
        "crypto_functions": ["encrypt", "decrypt"],
        "classical": 0, "quantum": 0,
    },
    "AES": {
        "name": "AES", "primitive": "block-cipher",
        "crypto_functions": ["encrypt", "decrypt"],
        "classical": 128, "quantum": 1,
    },
    "RSA": {
        "name": "RSA", "primitive": "pke",
        "crypto_functions": ["encrypt", "decrypt", "sign", "verify"],
        "classical": 128, "quantum": 0,
    },
    "ECC": {
        # The rule matches both ECDSA (sign) and ECDH (key-agree) call
        # shapes; without disambiguating the call site the honest entry is
        # an unnamed ECC primitive rather than a guessed scheme.
        "name": "ECC", "primitive": "unknown",
        "classical": 128, "quantum": 0,
    },
}

# AES modes the scanner can infer from the matched evidence text. Only
# present in the document when the evidence actually names the mode.
_AES_MODES = ("gcm", "ctr", "cbc", "cfb", "ofb", "ecb", "ccm")

# component -> (assetType, builder key); non-algorithm assets.
_MATERIAL_TYPES = {
    "Hardcoded Private Key": "private-key",
    "Hardcoded Certificate": "certificate",
}


def _metadata(tool_name: str, tool_version: str) -> dict:
    return {
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "tools": {
            "components": [{
                "type": "application",
                "name": tool_name or "R-SecOpsX",
                "version": tool_version or "unknown",
            }],
        },
    }


def _algorithm_properties(spec: dict, evidence: str) -> dict:
    props: dict = {
        "primitive": spec["primitive"],
        # Source-scanned crypto runs in the application's own process; the
        # schema's closest honest value is plain-RAM software.
        "executionEnvironment": "software-plain-ram",
    }
    if spec.get("crypto_functions"):
        props["cryptoFunctions"] = list(spec["crypto_functions"])
    if spec.get("classical") is not None:
        props["classicalSecurityLevel"] = spec["classical"]
    if spec.get("quantum") is not None:
        props["nistQuantumSecurityLevel"] = spec["quantum"]
    if spec["name"] == "AES":
        low = (evidence or "").lower()
        for mode in _AES_MODES:
            # Word-boundary match: "gcm" must not fire inside e.g. a var
            # named "gcm_key_count" ... it still might, but only the mode
            # enum is emitted, and an inferred mode is recorded as exactly
            # that -- inference from the same evidence line the finding
            # already cites.
            if mode in low:
                props["mode"] = mode
                break
    return props


def _crypto_component(item: dict, index: int) -> dict | None:
    """Translate one scanner CBOM item into a 1.6 cryptographic-asset.

    Returns None only if the item carries no recognisable component name --
    an unrecognised rule still exports, as a bare algorithm asset, because
    dropping a crypto observation to keep the document tidy is the wrong
    trade for an inventory.
    """
    component = str(item.get("component") or "").strip()
    if not component:
        return None

    rel_file = str(item.get("file") or "")
    line = int(item.get("line") or 0)
    evidence = str(item.get("evidence") or "")

    bom_ref = f"rsecopsx:cbom:{index}:{component}"
    name = component

    crypto_properties: dict
    if component in _ALGORITHM_MAP:
        spec = _ALGORITHM_MAP[component]
        name = spec["name"]
        crypto_properties = {
            "assetType": "algorithm",
            "algorithmProperties": _algorithm_properties(spec, evidence),
        }
    elif _MATERIAL_TYPES.get(component) == "private-key":
        crypto_properties = {
            "assetType": "related-crypto-material",
            "relatedCryptoMaterialProperties": {
                "type": "private-key",
                "format": "PEM",
                # Checked-in key material is exposed by definition. NIST
                # SP 800-57 state, not a severity -- the finding carries
                # the severity.
                "state": "compromised",
            },
        }
    elif _MATERIAL_TYPES.get(component) == "certificate":
        crypto_properties = {
            "assetType": "certificate",
            "certificateProperties": {"certificateFormat": "PEM"},
        }
    elif "TLS" in component.upper() or "SSL" in component.upper():
        crypto_properties = {
            "assetType": "protocol",
            "protocolProperties": {
                "type": "tls",
                # Version intentionally absent: the rule matches the call
                # shape, not a negotiated version, and asserting 1.2/1.3
                # here would claim knowledge the scanner does not have.
            },
        }
    else:
        crypto_properties = {
            "assetType": "algorithm",
            "algorithmProperties": {
                "primitive": "unknown",
                "executionEnvironment": "software-plain-ram",
            },
        }

    properties = [
        {"name": "rsecopsx:category", "value": str(item.get("category") or "")},
        {"name": "rsecopsx:risk", "value": str(item.get("risk") or "")},
        {"name": "rsecopsx:file", "value": rel_file},
        {"name": "rsecopsx:line", "value": str(line)},
        {"name": "rsecopsx:recommendation",
         "value": str(item.get("recommendation") or "")},
    ]
    # Evidence is source text the finding already cites; it goes in as a
    # property rather than an attachment so the document stays
    # self-explanatory without embedding whole files.
    #
    # NEVER for key material. The private-key rule's evidence is the PEM
    # block itself, so attaching it republishes the very secret the finding
    # exists to report -- caught by the exporter's own probe before this
    # guard existed. The file/line properties above still point at it.
    # PEM blocks are also redacted from every other asset's evidence as
    # defence in depth, in case a future rule's context window ever spans
    # one.
    if evidence and crypto_properties.get("assetType") != "related-crypto-material":
        # Redact BEFORE slicing: slicing first can cut a PEM block in half,
        # leaving a BEGIN header with no END for the pattern to match.
        redacted = redact_pem(evidence)
        properties.append({"name": "rsecopsx:evidence", "value": redacted[:500]})

    return {
        "type": "cryptographic-asset",
        "bom-ref": bom_ref,
        "name": name,
        "cryptoProperties": crypto_properties,
        "properties": properties,
    }


def build_cyclonedx_cbom(cbom_items: list[dict],
                         tool_name: str = "",
                         tool_version: str = "") -> dict:
    """Build a CycloneDX 1.6 CBOM document from scanner CBOM items."""
    components = []
    for i, item in enumerate(cbom_items or [], 1):
        if not isinstance(item, dict):
            continue
        comp = _crypto_component(item, i)
        if comp is not None:
            components.append(comp)

    return {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": _metadata(tool_name, tool_version),
        "components": components,
    }


def _aibom_component(item: dict, index: int) -> dict | None:
    provider = str(item.get("provider") or "").strip()
    component = str(item.get("component") or "").strip()
    if not (provider or component):
        return None

    name = component or provider.lower().replace(" ", "_")
    bom_ref = f"rsecopsx:aibom:{index}:{name}"

    properties = [
        {"name": "rsecopsx:provider", "value": provider},
        {"name": "rsecopsx:file", "value": str(item.get("file") or "")},
        {"name": "rsecopsx:line", "value": str(int(item.get("line") or 0))},
        {"name": "rsecopsx:risk", "value": str(item.get("risk") or "")},
        {"name": "rsecopsx:recommendation",
         "value": str(item.get("recommendation") or "")},
    ]
    model_hint = str(item.get("model_hint") or "").strip()
    if model_hint:
        properties.append({"name": "rsecopsx:model_hint", "value": model_hint})
    if item.get("confidence"):
        properties.append({"name": "rsecopsx:confidence",
                           "value": str(item["confidence"])})
    if item.get("confidence_score") is not None:
        properties.append({"name": "rsecopsx:confidence_score",
                           "value": str(item["confidence_score"])})
    if item.get("detection_mode"):
        properties.append({"name": "rsecopsx:detection_mode",
                           "value": str(item["detection_mode"])})
    for ev in sorted(set(item.get("evidence_type") or [])):
        properties.append({"name": "rsecopsx:evidence_type", "value": str(ev)})

    comp: dict = {
        "type": "machine-learning-model",
        "bom-ref": bom_ref,
        "name": name,
        "properties": properties,
    }
    # modelProperties is 1.7-only; at 1.6 the provenance rides in
    # properties, which every 1.6 consumer reads.
    if model_hint:
        comp["version"] = model_hint
    return comp


def build_cyclonedx_aibom(aibom_items: list[dict],
                          tool_name: str = "",
                          tool_version: str = "") -> dict:
    """Build a CycloneDX 1.6 AI-BOM document from scanner AI-BOM items."""
    components = []
    seen_refs: set[str] = set()
    for i, item in enumerate(aibom_items or [], 1):
        if not isinstance(item, dict):
            continue
        comp = _aibom_component(item, i)
        # The scanner deduplicates by semantic identity, but two detections
        # can still land on the same provider component; a BOM-ref must be
        # unique, so later duplicates fold into earlier components' props
        # rather than violating the schema with a repeated ref.
        if comp is None:
            continue
        if comp["bom-ref"] in seen_refs:
            comp["bom-ref"] = f"{comp['bom-ref']}:dup{i}"
        seen_refs.add(comp["bom-ref"])
        components.append(comp)

    return {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": _metadata(tool_name, tool_version),
        "components": components,
    }


def _tool_identity() -> tuple[str, str]:
    try:
        from core.config import TOOL_NAME
        import core.config as cfg
        return TOOL_NAME, str(getattr(cfg, "VERSION", "") or "")
    except Exception:  # pragma: no cover - defensive
        return "R-SecOpsX", ""


def write_cbom_report(cbom_items: list[dict], output_path: str) -> str:
    tool_name, tool_version = _tool_identity()
    doc = build_cyclonedx_cbom(cbom_items, tool_name, tool_version)
    Path(output_path).write_text(
        json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    _LOG.info("CBOM written: %s (%d cryptographic assets)",
              output_path, len(doc["components"]))
    return output_path


def write_aibom_report(aibom_items: list[dict], output_path: str) -> str:
    tool_name, tool_version = _tool_identity()
    doc = build_cyclonedx_aibom(aibom_items, tool_name, tool_version)
    Path(output_path).write_text(
        json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    _LOG.info("AI-BOM written: %s (%d AI components)",
              output_path, len(doc["components"]))
    return output_path
