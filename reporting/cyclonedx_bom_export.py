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
import re
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


# Padding signals in evidence text, keyed by the 1.6 schema enum and
# scoped to the primitives the padding can actually apply to. Scope
# matters: the evidence window is up to 2000 chars of surrounding code,
# so an RSA/PKCS1 mention nearby must never label a block cipher
# "pkcs1v15" -- observed in the first real artifact before scoping.
#   * PKCS#5/#7 paddings belong to block ciphers;
#   * OAEP/PKCS#1 v1.5 belong to RSA (pke/signature) shapes;
#   * PSS is a signature scheme with no enum value of its own, so it
#     (and MGF1 outside an OAEP context) lands in "other";
#   * NoPadding/ZeroPadding map to raw, the enum's no-padding value.
_PADDING_SIGNALS = {
    "block-cipher": (
        ("pkcs7", ("pkcs7", "pkcs#7")),
        ("pkcs5", ("pkcs5", "pkcs#5")),
        ("raw", ("nopadding", "no padding", "zeropadding")),
    ),
    "ae": (
        ("pkcs7", ("pkcs7", "pkcs#7")),
        ("pkcs5", ("pkcs5", "pkcs#5")),
        ("raw", ("nopadding", "no padding", "zeropadding")),
    ),
    "stream-cipher": (
        ("raw", ("nopadding", "no padding", "zeropadding")),
    ),
    "pke": (
        ("oaep", ("oaep",)),
        ("pkcs1v15", ("pkcs1v15", "pkcs1", "pkcs#1")),
        ("raw", ("nopadding", "no padding", "zeropadding")),
        ("other", ("pss", "mgf1")),
    ),
    "signature": (
        ("other", ("pss", "mgf1")),
        ("pkcs1v15", ("pkcs1v15", "pkcs1", "pkcs#1")),
    ),
}


def _infer_padding(evidence: str, primitive: str) -> str | None:
    """Map evidence text to the 1.6 padding enum for this primitive.

    Returns None when the evidence is silent OR when the only padding
    names in the window belong to a different primitive family.
    """
    signals = _PADDING_SIGNALS.get(primitive)
    if not signals:
        return None
    low = (evidence or "").lower()
    if not low:
        return None
    for value, tokens in signals:
        if any(token in low for token in tokens):
            return value
    return None


def _algorithm_properties(item: dict, spec: dict, evidence: str) -> dict:
    """cryptoProperties.algorithmProperties for one detected asset.

    The scanner's purpose model (scanner/cbom.py::_detect_purpose) is
    authoritative when present on the item: it disambiguates the concrete
    algorithm, primitive and function set from the call site. The static
    _ALGORITHM_MAP entry in ``spec`` is the family fallback for fixture
    dicts. cbomctl yields INDET on any algorithm asset without a
    cryptoFunctions list, so every branch here emits one.
    """
    props: dict = {
        "primitive": item.get("primitive") or spec.get("primitive") or "unknown",
        # Source-scanned crypto runs in the application's own process; the
        # schema's closest honest value is plain-RAM software.
        "executionEnvironment": "software-plain-ram",
    }
    functions = (item.get("crypto_functions")
                 or spec.get("crypto_functions") or ["unknown"])
    props["cryptoFunctions"] = list(functions)
    if spec.get("classical") is not None:
        props["classicalSecurityLevel"] = spec["classical"]
    if spec.get("quantum") is not None:
        props["nistQuantumSecurityLevel"] = spec["quantum"]
    if spec.get("name") == "AES":
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
        if props.get("mode") in ("gcm", "ccm") and "tag" not in props["cryptoFunctions"]:
            # AEAD: GCM/CCM authenticate their ciphertext. The official
            # CycloneDX AES-128-GCM example lists "tag" for the same reason.
            props["cryptoFunctions"].append("tag")
    padding = _infer_padding(evidence, props["primitive"])
    if padding:
        props["padding"] = padding
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
            "algorithmProperties": _algorithm_properties(item, spec, evidence),
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
        # Unrecognised algorithm rule. Routed through the same builder so
        # the INDET fix covers it too: the purpose model's fields (if the
        # scanner attached any) or a present ["unknown"] function list
        # replace the old empty-functions export.
        crypto_properties = {
            "assetType": "algorithm",
            "algorithmProperties": _algorithm_properties(item, {}, evidence),
        }

    properties = [
        {"name": "rsecopsx:category", "value": str(item.get("category") or "")},
        {"name": "rsecopsx:risk", "value": str(item.get("risk") or "")},
        {"name": "rsecopsx:file", "value": rel_file},
        {"name": "rsecopsx:line", "value": str(line)},
        {"name": "rsecopsx:recommendation",
         "value": str(item.get("recommendation") or "")},
    ]
    # Purpose model provenance (Phase 4.2). purpose/purpose_source say what
    # the algorithm is used for and whether the call site said so or the
    # family default applied; confidence is the IBM CBOM 0..3 detection
    # confidence (3 = call-site tokens found, 2 = family scope); the
    # keywords are the exact evidence tokens that produced the purpose.
    if item.get("purpose"):
        properties.append({"name": "rsecopsx:purpose",
                           "value": str(item["purpose"])})
    if item.get("purpose_source"):
        properties.append({"name": "rsecopsx:purpose_source",
                           "value": str(item["purpose_source"])})
    if item.get("confidence") is not None:
        properties.append({"name": "rsecopsx:confidence",
                           "value": str(int(item["confidence"]))})
    if item.get("detection_keywords"):
        properties.append({
            "name": "rsecopsx:detection-keywords",
            "value": ",".join(sorted({str(k) for k in item["detection_keywords"]})),
        })
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
    redacted = ""
    if evidence and crypto_properties.get("assetType") != "related-crypto-material":
        # Redact BEFORE slicing: slicing first can cut a PEM block in half,
        # leaving a BEGIN header with no END for the pattern to match.
        redacted = redact_pem(evidence)[:500]
        properties.append({"name": "rsecopsx:evidence", "value": redacted})

    out = {
        "type": "cryptographic-asset",
        "bom-ref": bom_ref,
        "name": name,
        "cryptoProperties": crypto_properties,
        "properties": properties,
    }
    # detectionContext (IBM CBOM extension) has no core-schema field, but
    # CDX 1.6's own component.evidence.occurrences[] -- {location, line,
    # additionalContext} -- is exactly the per-finding detection context,
    # and is what the official CBOM examples emit. Same redaction and cap
    # as the property above: one guard, two carriers.
    if redacted:
        out["evidence"] = {
            "occurrences": [{
                "location": rel_file or "unknown",
                "line": line,
                "additionalContext": redacted,
            }],
        }
    return out


def build_cyclonedx_cbom(cbom_items: list[dict],
                         tool_name: str = "",
                         tool_version: str = "",
                         target_name: str = "") -> dict:
    """Build a CycloneDX 1.6 CBOM document from scanner CBOM items.

    ``target_name``, when given, becomes metadata.component and the
    subject of one dependency edge: the application dependsOn every crypto
    asset found in its source. dependsOn is the core-schema "uses"
    relationship (the CBOM guide: "an application depends on the algorithm
    that it uses"); the IBM extension's dependencyType field does not
    exist in core 1.6 or 1.7 (verified against both official schemas:
    dependency is {ref, dependsOn, provides} with additionalProperties
    false), so uses rides on dependsOn. "implements" edges have no
    derivable instances here: they require an implementing library
    component, and the CBOM source-scope filter deliberately excludes
    third-party dependency trees -- that is SBOM territory.
    """
    components = []
    asset_refs = []
    for i, item in enumerate(cbom_items or [], 1):
        if not isinstance(item, dict):
            continue
        comp = _crypto_component(item, i)
        if comp is not None:
            components.append(comp)
            asset_refs.append(comp["bom-ref"])

    metadata = _metadata(tool_name, tool_version)
    doc = {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": metadata,
        "components": components,
    }
    if components and target_name:
        app_ref = f"rsecopsx:application:{target_name}"
        metadata["component"] = {
            "type": "application",
            "name": target_name,
            "bom-ref": app_ref,
        }
        doc["dependencies"] = [{
            "ref": app_ref,
            "dependsOn": sorted(asset_refs),
        }]
    return doc


# Truthful identity enrichment for detected AI SDK/framework components,
# keyed by the exact component string in scanner/aibom.py's AI_RULES.
#
# WHY: the OWASP AIBOM Generator's completeness profile (and real BOM
# consumers generally) score and act on package identity -- a purl to
# match advisories, a license to gate on, a homepage to audit. Detection
# supplies provider identity only, so these facts are curated here, in
# the REPORTING layer, where presentation lives; detection is untouched.
#
# SOURCING RULE (verified 2026-10-19 against each distribution's own
# PyPI metadata and the upstream GitHub repository API; do not extend by
# guesswork):
#   purl      the canonical PyPI distribution the rule's import patterns
#             bind to (e.g. `import openai` -> pkg:pypi/openai)
#   license   SPDX id taken from that distribution's PyPI metadata and
#             cross-checked against the upstream repository's SPDX
#             license; legacy strings such as "Apache 2.0" are
#             normalized only when both sources agree
#   homepage  the canonical upstream repository URL
# Components whose package identity is ambiguous emit no purl and no
# license (Ollama: PyPI client vs local runtime; DeepSeek: no canonical
# SDK distribution) -- a BOM must not guess identity, and honest absence
# beats a wrong match. Version is likewise omitted for import-only
# detections: an `import` statement proves usage, never which version.
_AI_ENRICHMENT: dict[str, dict[str, str]] = {
    "OpenAI SDK / API": {
        "purl": "pkg:pypi/openai",
        "license": "Apache-2.0",
        "homepage": "https://github.com/openai/openai-python",
        "description": "Official OpenAI Python SDK for the OpenAI API.",
    },
    "Azure OpenAI": {
        "purl": "pkg:pypi/azure-ai-openai",
        "license": "MIT",
        "homepage": "https://github.com/Azure/azure-sdk-for-python/tree/main/sdk/openai",
        "description": "Azure OpenAI client from the Azure SDK for Python.",
    },
    "Anthropic Claude SDK / API": {
        "purl": "pkg:pypi/anthropic",
        "license": "MIT",
        "homepage": "https://github.com/anthropics/anthropic-sdk-python",
        "description": "Official Anthropic Python SDK for the Claude API.",
    },
    "Google Gemini / Generative AI": {
        "purl": "pkg:pypi/google-generativeai",
        "license": "Apache-2.0",
        "homepage": "https://github.com/google-gemini/deprecated-generative-ai-python",
        "description": "Google Gemini generative AI Python SDK.",
    },
    "HuggingFace Transformers": {
        "purl": "pkg:pypi/transformers",
        "license": "Apache-2.0",
        "homepage": "https://github.com/huggingface/transformers",
        "description": "HuggingFace Transformers model library.",
    },
    "LangChain Framework": {
        "purl": "pkg:pypi/langchain",
        "license": "MIT",
        "homepage": "https://github.com/langchain-ai/langchain",
        "description": "LangChain LLM application framework.",
    },
    "LlamaIndex Framework": {
        "purl": "pkg:pypi/llama-index",
        "license": "MIT",
        "homepage": "https://github.com/run-llama/llama_index",
        "description": "LlamaIndex data framework for LLM applications.",
    },
    "Ollama Local LLM": {
        "license": "MIT",
        "homepage": "https://github.com/ollama/ollama",
        "description": "Ollama local LLM runtime.",
    },
    "Mistral AI": {
        "purl": "pkg:pypi/mistralai",
        "license": "Apache-2.0",
        "homepage": "https://github.com/mistralai/client-python",
        "description": "Official Mistral AI Python client.",
    },
    "Cohere AI": {
        "purl": "pkg:pypi/cohere",
        "license": "MIT",
        "homepage": "https://github.com/cohere-ai/cohere-python",
        "description": "Official Cohere Python SDK.",
    },
    "DeepSeek AI": {
        "homepage": "https://api.deepseek.com",
        "description": "DeepSeek LLM API.",
    },
    "CrewAI Agent Framework": {
        "purl": "pkg:pypi/crewai",
        "license": "MIT",
        "homepage": "https://github.com/crewAIInc/crewAI",
        "description": "CrewAI multi-agent orchestration framework.",
    },
    "Microsoft AutoGen Agent Framework": {
        "purl": "pkg:pypi/autogen",
        "license": "Apache-2.0",
        "homepage": "https://github.com/microsoft/autogen",
        "description": "Microsoft AutoGen multi-agent conversation framework.",
    },
}

# Shape of an SPDX license identifier; anything else rides as a name.
_SPDX_ID_RE = re.compile(r"^[A-Za-z0-9-.+]+$")


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
    # Phase 4.3: NTIA/G7 minimum-elements completeness (per model
    # component) and any HuggingFace hub enrichment that refined it.
    completeness = item.get("completeness")
    if isinstance(completeness, dict):
        properties.append(
            {"name": "rsecopsx:completeness_score",
             "value": str(completeness.get("score"))})
        for key, prop in (
            ("elements_present", "rsecopsx:completeness_elements"),
            ("elements_missing", "rsecopsx:missing_elements"),
            ("not_computable_from_source", "rsecopsx:not_computable_from_source"),
        ):
            values = completeness.get(key) or []
            if values:
                properties.append(
                    {"name": prop,
                     "value": ",".join(sorted(str(v) for v in values))})
    hf = item.get("hf_enrichment")
    if isinstance(hf, dict):
        properties.append(
            {"name": "rsecopsx:hf_status", "value": str(hf.get("status") or "")})
        for key, prop in (("license", "rsecopsx:hf_license"),
                          ("pipeline_tag", "rsecopsx:hf_pipeline_tag"),
                          ("created_at", "rsecopsx:hf_created_at")):
            if hf.get(key):
                properties.append({"name": prop, "value": str(hf[key])})

    comp: dict = {
        "type": "machine-learning-model",
        "bom-ref": bom_ref,
        "name": name,
        "properties": properties,
    }
    # Curated package identity for known SDK/framework components (see
    # _AI_ENRICHMENT): purl, description, license and homepage, each a
    # sourced fact. A key absent from the entry means "not truthfully
    # knowable", never "fill with a plausible value".
    ident = _AI_ENRICHMENT.get(component)
    if ident:
        if ident.get("description"):
            comp["description"] = ident["description"]
        if ident.get("purl"):
            comp["purl"] = ident["purl"]
        if ident.get("license"):
            comp["licenses"] = [{"license": {"id": ident["license"]}}]
        if ident.get("homepage"):
            comp["externalReferences"] = [
                {"type": "website", "url": ident["homepage"]}]
    # Model detections can carry a HuggingFace-stated license; reuse it
    # as a CycloneDX license. HF strings are not always SPDX ids, so
    # only shape-matching values become ids.
    hf_license = str(hf.get("license") or "").strip() if isinstance(hf, dict) else ""
    if hf_license and "licenses" not in comp:
        if _SPDX_ID_RE.fullmatch(hf_license):
            comp["licenses"] = [{"license": {"id": hf_license}}]
        else:
            comp["licenses"] = [{"license": {"name": hf_license}}]
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


def write_cbom_report(cbom_items: list[dict], output_path: str,
                      target_name: str = "") -> str:
    tool_name, tool_version = _tool_identity()
    doc = build_cyclonedx_cbom(cbom_items, tool_name, tool_version,
                               target_name=target_name)
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
