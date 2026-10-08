"""SANS Critical AI Security Guidelines traceability.

What this framework is
----------------------
"Critical AI Security Guidelines, v1.4", SANS Institute, last updated March 2026,
developed in alignment with the OWASP AI Exchange. Eight control categories, with
named controls inside each. It is guidance, not a binding standard or a
regulation.

Source and provenance
---------------------
PDF retrieved this session:
https://assets.contentstack.io/v3/assets/bltabe50a4554f8e97f/blte964a6eef293d57e/whitepaper-critical-ai-security-guidelines
SHA-256 6D32F6F7B7F95E94CC72F0FD0740F00264B8A07CA72BEB96911ACCB54D3588C5, 17 pages,
declared licence CC BY 4.0.

This resolves the sourcing block recorded in G-084, which previously said the
document "could not be retrieved by the tooling available in this session, so no
control is claimed". It has now been read, so controls ARE claimed -- from the
document, not from memory.

Identifiers are ours, not SANS's -- read this before citing one
--------------------------------------------------------------
The guidelines number nothing. Controls are named prose headings inside eight
categories. So the ids here (`SANS-AIC-CAT5-C01` style) are LOCALLY ASSIGNED by
this project for referential integrity, and `id_origin` records that fact on
every control. Anyone citing an id from a report must cite it as
"SANS Critical AI Security Guidelines v1.4, control under category N" -- not as a
SANS-issued identifier, because SANS issues none. Inventing plausible-looking
`SANS-CTL-0042` ids that a reader would assume are authoritative is precisely the
fabrication this project forbids, and it is why the scheme is visibly local.

Observability, and why most of this is not checkable by a scanner
-----------------------------------------------------------------
The 8 categories split sharply. A source or asset scan can speak to a minority:
whether an AI endpoint requires authentication, whether model I/O is filtered,
whether an AIBOM exists, whether guardrails are declared in code. It cannot speak
to the majority: whether a GRC board was established, whether human oversight is
real, whether data was minimised in a process sense, whether models are hosted
locally. Those are classified NOT_ATTESTABLE_BY_A_SCANNER and reported as such, in
the same spirit as core/ssdf_mappings.py and core/free_ai_mappings.py.

Three controls the conformance baseline probes for, and where they actually live
in v1.4 (this changed between drafts and was verified in the document, not assumed):

  guardrails          CAT5 "Establish AI Guardrails"
  input segregation   CAT6 "Sanitize, Validate, and Filter Inputs/Prompts"
  evasion modalities  CAT4 "Engineering Considerations" -- Modality, Languages and
                      character sets, Encoding/decoding (Base64, Hex, Morse) and
                      Compression/decompression

Note the third one: earlier drafts placed the evasion-modality material under the
behaviour-limiting material. In v1.4 it sits under engineering considerations, and
mapping it from a draft would have mis-attributed it.
"""
from __future__ import annotations

SANS_DOCUMENT = "SANS Critical AI Security Guidelines"
SANS_VERSION = "1.4"
SANS_PUBLISHED = "2026-03"
SANS_LICENSE = "CC BY 4.0"
SANS_SOURCE_URL = (
    "https://assets.contentstack.io/v3/assets/bltabe50a4554f8e97f/"
    "blte964a6eef293d57e/whitepaper-critical-ai-security-guidelines"
)
SANS_PDF_SHA256 = "6D32F6F7B7F95E94CC72F0FD0740F00264B8A07CA72BEB96911ACCB54D3588C5"
SANS_PDF_PAGES = 17
SANS_DATASET_LABEL = f"{SANS_DOCUMENT} v{SANS_VERSION} ({SANS_PUBLISHED})"
SANS_ALIGNMENT = "Aligned with the OWASP AI Exchange"
SANS_STATUS = (
    "Guidance from a training vendor. NOT a regulation, not a certification "
    "requirement, and not a binding standard."
)
SANS_ID_ORIGIN = (
    "LOCALLY ASSIGNED BY THIS PROJECT. The guidelines number their controls, so "
    "every id here is a convenience handle for referring to a named control inside "
    "a category. Do not cite it as a SANS-issued identifier."
)

DIRECT = "DIRECT"
RELATED = "RELATED"
UNMAPPED = "UNMAPPED"
SANS_MAPPING_MODES = (DIRECT, RELATED, UNMAPPED)

OBSERVABLE = "SCANNER_OBSERVABLE"
NOT_ATTESTABLE = "NOT_ATTESTABLE_BY_A_SCANNER"

# ---------------------------------------------------------------------------
# The 8 control categories, in the document's own order.
# ---------------------------------------------------------------------------
SANS_CATEGORIES = {
    "CAT1": "Conventional Security Controls",
    "CAT2": "Data Minimization and Obfuscation",
    "CAT3": "AI Supply Chain Management",
    "CAT4": "Data/Model Engineering Controls",
    "CAT5": "Limit Model Behavior",
    "CAT6": "Model I/O Handling",
    "CAT7": "Monitoring",
    "CAT8": "Governance, Risk, Compliance (GRC)",
}


def _c(cat, n, name, observable, note=""):
    return {
        "id": f"SANS-AIC-{cat}-C{n:02d}",
        "category": cat,
        "category_name": SANS_CATEGORIES[cat],
        "index": n,
        "name": name,
        "observability": OBSERVABLE if observable else NOT_ATTESTABLE,
        "note": note,
        "id_origin": SANS_ID_ORIGIN,
    }


# Controls as named in v1.4. `observable` is True only where a source or asset
# inventory can say something true or false about the control's subject.
SANS_CONTROLS = {}
for _row in [
    # ---- CAT1 Conventional Security Controls ----------------------------
    _c("CAT1", 1, "Control access to interaction/inference", True,
       "Authentication on an AI or model endpoint is directly observable in code, "
       "route configuration and access-control declarations."),
    _c("CAT1", 2, "Protect Your Model Parameters", True,
       "Model artefacts left in the repository, or loaded from an unprotected path, "
       "are observable."),
    _c("CAT1", 3, "Protecting Augmentation Data", True,
       "RAG/augmentation sources and how retrieved content is delimited from "
       "system instructions are observable in source."),
    _c("CAT1", 4, "Defend Training Data", False,
       "Defending training data is a data-governance and pipeline-integrity matter; "
       "a repository scan sees the pipeline only in part."),
    _c("CAT1", 5, "Avoid Data Commingling", False,
       "Whether sensitive data was commingled during training is not a property of "
       "the shipped artifact."),
    # ---- CAT2 Data Minimization and Obfuscation ------------------------
    _c("CAT2", 1, "Minimize Data Exposure", False,
       "Data minimisation is a lifecycle decision about what is collected and fed "
       "to a model, not a property of the code alone."),
    _c("CAT2", 2, "Limit Sensitive Prompt Content", True,
       "Sensitive values embedded in a system prompt ARE readable in source, so a "
       "scan can evidence this one."),
    _c("CAT2", 3, "Leverage AI-Specific Obfuscation Techniques", False,
       "A recommendation to obfuscate; its absence is not a defect."),
    _c("CAT2", 4, "Context Window Management", False,
       "Context-window sizing is a design and cost decision."),
    # ---- CAT3 AI Supply Chain Management -------------------------------
    _c("CAT3", 1, "Assess Model Hosting Options: Local vs. SaaS Models", False,
       "Hosting location is an architectural decision. Some proxies are visible "
       "(a call to a model provider), but the decision itself is not."),
    _c("CAT3", 2, "Be Cautious Using Public Models", True,
       "Pulling a model or dataset from a public registry at build or run time is "
       "observable in dependency manifests and source."),
    _c("CAT3", 3, "Critical Models and Transfer Attacks", False,
       "Whether an equivalent public model makes a domain model critical is a risk "
       "judgement."),
    _c("CAT3", 4, "AI Bill of Materials (AIBOM)", True,
       "An AIBOM is an artifact: its ABSENCE from a repository is observable."),
    # ---- CAT4 Data/Model Engineering Controls ---------------------------
    _c("CAT4", 1, "Adversarial Training and Robustness", False,
       "Robustness is a training outcome; a source scan cannot measure it."),
    _c("CAT4", 2, "Model Alignment and Fine-Tuning", False),
    _c("CAT4", 3, "Data Quality Controls", False),
    _c("CAT4", 4, "Architectural Considerations", False,
       "Modality, language coverage and encryption choices are design decisions. "
       "The document lists these under this control; the SCAN-relevant consequence "
       "is that multimodal and multilingual systems have a wider attack surface, "
       "which is why the evasion-modality rules map to inference handling too."),
    _c("CAT4", 5, "Engineering Considerations", True,
       "Where the guidelines enumerate the evasion modalities -- Modality, Languages "
       "and character sets, Encoding/decoding (Base64, Hex, Morse) and "
       "Compression/decompression -- a scan can detect whether a codebase handles "
       "any of those, and can therefore evidence the absence of handling."),
    # ---- CAT5 Limit Model Behavior --------------------------------------
    _c("CAT5", 1, "Establish AI Guardrails", True,
       "Guardrails declared in code or configuration ARE observable. Whether they "
       "are sufficient is not -- the document itself warns they cannot be relied on "
       "to be infallible."),
    _c("CAT5", 2, "Implement Access Controls Outside of the Model", True,
       "Whether retrieval or tool access is enforced by ACLs outside the model is a "
       "source property."),
    _c("CAT5", 3, "Employ the Principle of Focused Functionality", True,
       "The tools, interpreters and network egress a model is granted are declared "
       "in source."),
    _c("CAT5", 4, "Human Oversight", False,
       "Human oversight is an organisational arrangement. Asserting its absence "
       "from a repository would be asserting something a scan cannot see."),
    # ---- CAT6 Model I/O Handling ----------------------------------------
    _c("CAT6", 1, "Sanitize, Validate, and Filter Inputs/Prompts", True,
       "Input filtering is source. The document makes input segregation explicit: "
       "'In multiuser environments or applications where prompts are composed from "
       "multiple sources, input segregation is critical.'"),
    _c("CAT6", 2, "Sanitize, Validate, and Filter AI Outputs/Responses", True,
       "Output filtering and postprocessing are source."),
    _c("CAT6", 3, "Minimize attacker information in output", True,
       "Whether model internals, system prompts or credentials are echoed into "
       "responses is observable in output-handling code."),
    _c("CAT6", 4, "Implement Multilayered Protection/Detection", True,
       "A single-layer mitigation -- typically an overridable system prompt -- is "
       "detectable, and the document is explicit that system prompts are tactical."),
    # ---- CAT7 Monitoring ------------------------------------------------
    _c("CAT7", 1, "Monitor Interaction/Inference", True,
       "Whether inference endpoints are audited and rate-limited is observable in "
       "middleware and route configuration."),
    _c("CAT7", 2, "Drift Monitoring", False,
       "Drift is a runtime observation."),
    _c("CAT7", 3, "Output Monitoring", False,
       "Output monitoring is a runtime capability."),
    # ---- CAT8 GRC -------------------------------------------------------
    _c("CAT8", 1, "Establish an AI GRC board or equivalent", False,
       "A governance board is an organisational act. Claiming to check it from a "
       "repository would be claiming to audit."),
    _c("CAT8", 2, "Regularly Test and Tune AI Applications/Models", False,
       "A testing cadence is a process."),
]:
    SANS_CONTROLS[_row["id"]] = _row

SANS_OBSERVABLE_IDS = [k for k, v in SANS_CONTROLS.items() if v["observability"] == OBSERVABLE]
SANS_NOT_ATTESTABLE_IDS = [k for k, v in SANS_CONTROLS.items()
                           if v["observability"] == NOT_ATTESTABLE]

# ---------------------------------------------------------------------------
# V11 rule id -> SANS control.
#
# Only OBSERVABLE controls may receive a finding. Each entry carries why the rule
# is relevant, so the mapping can be audited rather than trusted.
# ---------------------------------------------------------------------------
SANS_BY_RULE_ID = {
    "LLM_PROMPT_INJECTION": {
        "attack": "SANS-AIC-CAT6-C01",
        "related": ("SANS-AIC-CAT6-C04",),
        "rationale": "Unfiltered prompt input is the absence of the input "
                     "sanitisation/validation/filtering the control requires.",
    },
    "LLM_INDIRECT_PROMPT_INJECTION": {
        "attack": "SANS-AIC-CAT6-C01",
        "related": ("SANS-AIC-CAT1-C03",),
        "rationale": "Untrusted retrieved content reaching the prompt without "
                     "delimiting is exactly the augmentation-data and input-segregation "
                     "gap.",
    },
    "LLM_SYSTEM_PROMPT_LEAK": {
        "attack": "SANS-AIC-CAT6-C03",
        "rationale": "Echoing system prompts or model internals to the caller is the "
                     "attacker-information disclosure this control names.",
    },
    "LLM_NO_OUTPUT_FILTERING": {
        "attack": "SANS-AIC-CAT6-C02",
        "rationale": "Absent output postprocessing is the absence of the output "
                     "filtering this control requires.",
    },
    "SYSTEM_PROMPT_ONLY_MITIGATION": {
        "attack": "SANS-AIC-CAT6-C04",
        "rationale": "Relying on an overridable system prompt is the single-layer "
                     "mitigation this control warns against.",
    },
    "PROMPT_RESPONSE_LOGGING_SENSITIVE_DATA": {
        "attack": "SANS-AIC-CAT6-C03",
        "rationale": "Logging prompts and responses verbatim can persist sensitive "
                     "content outside the model's control.",
    },
    "LLM06_SENSITIVE_INFORMATION_DISCLOSURE": {
        "attack": "SANS-AIC-CAT6-C03",
        "rationale": "Sensitive data in model responses is the disclosure this "
                     "control targets.",
    },
    "LLM_UNAUTHENTICATED_INFERENCE_ENDPOINT": {
        "attack": "SANS-AIC-CAT1-C01",
        "rationale": "An unauthenticated inference endpoint is the absence of "
                     "access control on interaction/inference.",
    },
    "LLM_API_KEY_HARDCODED": {
        "attack": "SANS-AIC-CAT1-C01",
        "rationale": "Hardcoded API keys to a model provider are exactly the "
                     "access-control gap this control names.",
    },
    "LLM_MODEL_ENDPOINT_NO_RATE_LIMIT": {
        "attack": "SANS-AIC-CAT7-C01",
        "rationale": "An unlimited inference endpoint is unmonitored interaction; the "
                     "document pairs usage monitoring with rate limiting.",
    },
    "PUBLIC_MODEL_REGISTRY_PULL": {
        "attack": "SANS-AIC-CAT3-C02",
        "rationale": "Pulling a model from a public registry at run time is the "
                     "exposure this control warns about.",
    },
    "REG01_PUBLIC_MODEL_REGISTRY_PULL": {
        "attack": "SANS-AIC-CAT3-C02",
        "rationale": "Pulling a model from a public registry is the exposure this "
                     "control warns about.",
    },
    "MODEL_WEIGHTS_IN_REPOSITORY": {
        "attack": "SANS-AIC-CAT1-C02",
        "rationale": "Model parameters committed to the repository are unprotected "
                     "model artefacts.",
    },
    "AIBOM_MISSING": {
        "attack": "SANS-AIC-CAT3-C04",
        "rationale": "No AI Bill of Materials in the repository is the observable "
                     "absence of this control's artifact.",
    },
    "GUARDRAIL_BYPASS_ENCODING": {
        "attack": "SANS-AIC-CAT4-C05",
        "related": ("SANS-AIC-CAT6-C01",),
        "rationale": "Guardrails bypassed via encoded input are the encoding/decoding "
                     "evasion the guidelines enumerate.",
    },
    "COMPRESSION_EVASION": {
        "attack": "SANS-AIC-CAT4-C05",
        "related": ("SANS-AIC-CAT6-C01",),
        "rationale": "Compression-based input obfuscation is one of the evasion "
                     "modalities the guidelines enumerate.",
    },
    "MULTILINGUAL_GUARDRAIL_GAP": {
        "attack": "SANS-AIC-CAT4-C05",
        "rationale": "Guardrails only effective in the primary training language is "
                     "the language/character-set evasion the guidelines enumerate.",
    },
    "MULTIMODAL_INPUT_UNVALIDATED": {
        "attack": "SANS-AIC-CAT4-C05",
        "rationale": "Unvalidated non-text input widens attack surface in the way the "
                     "guidelines' Modality consideration describes.",
    },
    "AGENT_UNRESTRICTED_TOOL_ACCESS": {
        "attack": "SANS-AIC-CAT5-C03",
        "rationale": "An agent granted broad tools or interpreters violates focused "
                     "functionality.",
    },
    "RAG_NO_ACCESS_CONTROL": {
        "attack": "SANS-AIC-CAT5-C02",
        "rationale": "Retrieval without ACLs is the 'access controls outside of the "
                     "model' gap.",
    },
}

SANS_BY_VULN_TYPE = {
    "llm_prompt_injection": {
        "attack": "SANS-AIC-CAT6-C01",
        "rationale": "Unfiltered prompt input is an absence of input filtering.",
    },
    "adversarial_prompt_injection": {
        "attack": "SANS-AIC-CAT6-C01",
        "rationale": "Unfiltered prompt input is an absence of input filtering.",
    },
    "indirect_prompt_injection": {
        "attack": "SANS-AIC-CAT6-C01",
        "rationale": "Untrusted content reaching the prompt unfiltered.",
    },
    "sensitive_information_disclosure": {
        "attack": "SANS-AIC-CAT6-C03",
        "rationale": "Sensitive data disclosed in model output.",
    },
    "model_poisoning": {
        "attack": "SANS-AIC-CAT3-C02",
        "rationale": "Poisoning risk from externally sourced model artefacts.",
    },
    "data_poisoning": {
        "attack": "SANS-AIC-CAT3-C02",
        "rationale": "Untrusted training or retrieval data source.",
    },
}

# Observable controls with no rule in this release. Recorded so a coverage figure
# cannot improve silently by them being left out.
SANS_NO_RULE = {
    "SANS-AIC-CAT2-C02": (
        "Limit Sensitive Prompt Content - no rule. Detecting sensitive values inside a "
        "system prompt needs semantic judgement this rule set does not attempt."
    ),
    "SANS-AIC-CAT7-C01": (
        "Monitor Interaction/Inference - partially covered: MISSING_RATE_LIMIT_ENDPOINT "
        "covers unauthenticated or unlimited API endpoints generally, not AI inference "
        "specifically. No AI-specific rule exists."
    ),
    "SANS-AIC-CAT5-C01": (
        "Establish AI Guardrails - no rule. Guardrails cannot be DETECTED, only their "
        "bypass can. This control is evidence-bearing rather than defect-bearing: a "
        "bypass finding is mapped to the evasion modalities it exploits, not to the "
        "guardrail's presence."
    ),
    "SANS-AIC-CAT1-C04": (
        "Defend Training Data - no rule, and NOT_ATTESTABLE by a source scan."
    ),
    "SANS-AIC-CAT2-C01": (
        "Minimize Data Exposure - no rule, and NOT_ATTESTABLE."
    ),
}

SANS_UNMAPPED_RATIONALE = (
    "No SANS control was attributed to this finding. SANS guidance is organised as 8 "
    "control categories containing named controls, of which a minority concern "
    "anything a source or asset scan can observe; the rest are governance, hosting "
    "and oversight matters. Absence of a mapping is therefore usually a statement "
    "about the guideline's subject rather than about this finding, and is not "
    "evidence of compliance with the guidelines."
)

SANS_EDGE_RATIONALE = (
    "Linked through this project's vuln_type table. SANS publishes no "
    "machine-readable finding-to-control mapping, so this linkage is judgement and "
    "is reported as RELATED rather than DIRECT."
)


def sans_label(cid: str) -> str:
    spec = SANS_CONTROLS.get(str(cid or "").strip()) or {}
    bits = [spec.get("id", cid)]
    if spec.get("name"):
        bits.append(spec["name"])
    if spec.get("category_name"):
        bits.append(f"({spec['category_name']})")
    return " - ".join(bits)


def sans_reference(rule_id: str = "", vuln_type: str = "") -> dict:
    """Pinned SANS Critical AI Security Guidelines attribution. Fails closed."""
    rid = str(rule_id or "").strip().upper()
    vtype = str(vuln_type or "").strip().lower()

    base = {
        "sans_control": "",
        "sans_label": "",
        "sans_category": "",
        "sans_category_name": "",
        "sans_control_name": "",
        "sans_observability": "",
        "sans_related": [],
        "sans_mapping_mode": UNMAPPED,
        "sans_rationale": "",
        "sans_dataset": SANS_DATASET_LABEL,
        "sans_version": SANS_VERSION,
        "sans_license": SANS_LICENSE,
        "sans_status": SANS_STATUS,
        "sans_id_origin": SANS_ID_ORIGIN,
        "sans_source_url": SANS_SOURCE_URL,
        "sans_semantics": (
            "Evidence relevant to this SANS control. NOT a statement that the "
            "control is absent, and NOT a SANS certification claim."
        ),
    }

    entry = SANS_BY_RULE_ID.get(rid)
    mode = DIRECT
    if entry is None:
        entry = SANS_BY_VULN_TYPE.get(vtype)
        mode = RELATED if entry is not None else None

    if entry is None:
        base["sans_rationale"] = SANS_UNMAPPED_RATIONALE
        return base

    cid = entry["attack"]
    spec = SANS_CONTROLS.get(cid) or {}
    base["sans_control"] = cid
    base["sans_label"] = sans_label(cid)
    base["sans_category"] = spec.get("category", "")
    base["sans_category_name"] = spec.get("category_name", "")
    base["sans_control_name"] = spec.get("name", "")
    base["sans_observability"] = spec.get("observability", "")
    base["sans_related"] = list(entry.get("related") or ())
    base["sans_mapping_mode"] = mode
    base["sans_rationale"] = (
        (entry.get("rationale", "") + " " + (spec.get("note") or "")).strip())
    if mode == RELATED:
        base["sans_rationale"] += " " + SANS_EDGE_RATIONALE
    return base


def enrich_with_sans(finding: dict) -> dict:
    finding.update(sans_reference(
        finding.get("rule_id", ""), finding.get("vuln_type", "")))
    return finding


def sans_coverage(rule_ids=(), vuln_types=()) -> dict:
    """Reachability summary with every denominator stated."""
    from collections import Counter

    def tally(keys, resolve):
        counts = Counter()
        mapped, unmapped = [], []
        keys = list(keys)
        for k in keys:
            m = resolve(k)["sans_mapping_mode"]
            counts[m] += 1
            (mapped if m != UNMAPPED else unmapped).append(k)
        return {
            "total": len(keys),
            "by_mode": dict(counts),
            "mapped": sorted(mapped),
            "unmapped": sorted(unmapped),
            "coverage_ratio": (len(mapped) / len(keys)) if keys else 0.0,
        }

    families = {
        "rule_id": tally(rule_ids, lambda k: sans_reference(k, "")),
        "vuln_type": tally(vuln_types, lambda k: sans_reference("", k)),
    }
    total = sum(f["total"] for f in families.values())
    mapped = sum(len(f["mapped"]) for f in families.values())
    families["combined"] = {
        "total": total, "mapped": mapped, "unmapped": total - mapped,
        "coverage_ratio": (mapped / total) if total else 0.0,
    }

    reached = sorted({
        ref["sans_control"]
        for keys, is_rule in ((rule_ids, True), (vuln_types, False))
        for k in keys
        for ref in [sans_reference(k, "") if is_rule else sans_reference("", k)]
        if ref["sans_control"]
    })
    families["controls_reachable"] = reached
    families["controls_reachable_count"] = len(reached)
    families["catalogue_size"] = len(SANS_CONTROLS)
    families["catalogue_categories"] = len(SANS_CATEGORIES)
    families["catalogue_observable_by_a_scanner"] = len(SANS_OBSERVABLE_IDS)
    families["catalogue_not_attestable_by_a_scanner"] = len(SANS_NOT_ATTESTABLE_IDS)
    families["controls_with_no_rule"] = sorted(SANS_NO_RULE)
    families["dataset"] = SANS_DATASET_LABEL
    families["alignment"] = SANS_ALIGNMENT
    # Deliberately NOT named "status". main.py's error path writes
    # payload["sans_summary"]["status"] = "REVIEW_REQUIRED", so reusing "status"
    # here would put two different meanings in one key and a consumer checking it
    # for truthiness would be misled on the success path.
    families["guidance_status"] = SANS_STATUS
    families["semantics"] = (
        "Ratios describe reachability into SANS guidance. They are NOT compliance and "
        "NOT a certification score. Control identifiers are locally assigned by this "
        "project because the guidelines number nothing; see id_origin. A majority of "
        "the controls concern governance, hosting and oversight that a source scan "
        "cannot observe, so full coverage is impossible by construction."
    )
    return families