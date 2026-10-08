"""NIST AI 100-2e2025 (Adversarial Machine Learning) taxonomy mapping for V11.

Why this is mandatory rather than nice-to-have
---------------------------------------------
V11's ``scanner/advanced_ai_security.py`` already carries 81 rules whose entire
purpose is detecting adversarial manipulation of AI systems, and
``scanner/llm_security.py`` carries the OWASP LLM Top 10. Neither emitted a
standard identifier, so an AI finding could not be aggregated across scans,
compared against a peer tool, or answered against a NIST reference. NIST AI
100-2 is the taxonomy for exactly that attack class, and its 2025 edition added
an Index whose stated purpose is to let industry build compliance-checking
products against it.

Source
------
NIST Trustworthy and Responsible AI Report, *Adversarial Machine Learning: A
Taxonomy and Terminology of Attacks and Mitigations*, **NIST AI 100-2e2025**,
published 2025-03-24. Maintained annually (e2023 -> e2025).
https://csrc.nist.gov/pubs/ai/100/2/e2025/final

Taxonomy shape
--------------
Attacks are classified against the attacker's objective (top level) and are
split into a Predictive-AI (PredAI) taxonomy and a Generative-AI (GenAI)
taxonomy, which reuse some identifiers because the same attack applies to both
(Data Poisoning is ``NISTAML.013`` in each).

Only identifiers confirmed from the published taxonomy appear here. The
GenAI taxonomy's *Misuse* objective and the PredAI Supply Chain sub-identifiers
beyond ``NISTAML.051`` were not confirmed in this session, so they are absent
rather than reconstructed.

``mapping_mode`` values
-----------------------
``DIRECT``          the rule detects the AML attack itself
``RELATED``         the rule detects a precondition the attack requires
``UNMAPPED``        nothing defensible was established
"""
from __future__ import annotations

NISTAML_DOCUMENT = "NIST AI 100-2e2025"
NISTAML_TITLE = (
    "Adversarial Machine Learning: A Taxonomy and Terminology of Attacks and "
    "Mitigations"
)
NISTAML_PUBLISHED = "2025-03-24"
NISTAML_SOURCE_URL = "https://csrc.nist.gov/pubs/ai/100/2/e2025/final"
NISTAML_DATASET_LABEL = f"{NISTAML_DOCUMENT} ({NISTAML_PUBLISHED})"

DIRECT = "DIRECT"
RELATED = "RELATED"
UNMAPPED = "UNMAPPED"
NISTAML_MAPPING_MODES = (DIRECT, RELATED, UNMAPPED)

# ---------------------------------------------------------------------------
# Top-level attacker objectives.
# ---------------------------------------------------------------------------
NISTAML_OBJECTIVES = {
    "NISTAML.01": "Availability Violations",
    "NISTAML.02": "Integrity Violations",
    "NISTAML.03": "Privacy Compromises",
    "NISTAML.05": "Supply Chain Attacks",
}

# ---------------------------------------------------------------------------
# Attack classes.
#
# `systems` records which taxonomy(ies) the identifier appears under, because
# several identifiers are shared between the PredAI and GenAI taxonomies.
# `name` is left empty where the term was seen but the exact identifier-to-term
# binding was not confirmed, rather than being reconstructed.
# ---------------------------------------------------------------------------
NISTAML_ATTACKS = {
    "NISTAML.011": {"name": "Model Poisoning", "objective": "NISTAML.01", "systems": ("PredAI",)},
    "NISTAML.012": {"name": "Clean-label Poisoning", "objective": "NISTAML.01", "systems": ("PredAI",), "also_under": "NISTAML.02"},
    "NISTAML.013": {"name": "Data Poisoning", "objective": "NISTAML.01", "systems": ("PredAI", "GenAI")},
    "NISTAML.014": {"name": "Energy-latency", "objective": "NISTAML.01", "systems": ("PredAI",)},
    "NISTAML.015": {"name": "Indirect Prompt Injection", "objective": "NISTAML.01", "systems": ("GenAI",)},
    "NISTAML.018": {"name": "Prompt Injection", "objective": "NISTAML.01", "systems": ("GenAI",)},
    "NISTAML.021": {"name": "Clean-label Backdoor", "objective": "NISTAML.02", "systems": ("PredAI",)},
    "NISTAML.022": {"name": "Evasion", "objective": "NISTAML.02", "systems": ("PredAI",)},
    "NISTAML.023": {"name": "Backdoor Poisoning", "objective": "NISTAML.02", "systems": ("PredAI",)},
    "NISTAML.024": {"name": "Targeted Poisoning", "objective": "NISTAML.02", "systems": ("PredAI",)},
    "NISTAML.025": {"name": "Black-box Evasion", "objective": "NISTAML.02", "systems": ("PredAI",)},
    "NISTAML.026": {"name": "Model Poisoning", "objective": "NISTAML.02", "systems": ("PredAI",)},
    "NISTAML.031": {"name": "Model Extraction", "objective": "NISTAML.03", "systems": ("PredAI",)},
    "NISTAML.032": {"name": "Reconstruction", "objective": "NISTAML.03", "systems": ("PredAI",)},
    "NISTAML.033": {"name": "Membership Inference", "objective": "NISTAML.03", "systems": ("PredAI",)},
    "NISTAML.034": {"name": "Property Inference", "objective": "NISTAML.03", "systems": ("PredAI",)},
    "NISTAML.051": {"name": "Model Poisoning", "objective": "NISTAML.05", "systems": ("PredAI",)},
}

# Terms named in the report's privacy-compromise discussion whose identifiers
# were NOT confirmed in this session. Recorded so the omission is auditable.
NISTAML_UNCONFIRMED_TERMS = {
    "DATA RECONSTRUCTION": "Privacy-compromise data attack; identifier not confirmed.",
    "TRAINING DATA EXTRACTION": "Privacy-compromise data attack; identifier not confirmed.",
    "ATTRIBUTE INFERENCE ATTACK": "Privacy-compromise data attack; identifier not confirmed.",
    "MODEL EXTRACTION": "Modelled as NISTAML.031; the term also appears standalone in the privacy discussion.",
    "MISUSE": "GenAI top-level objective; identifier not confirmed, so no attack carries it.",
}


def _label(attack_id: str) -> str:
    name = (NISTAML_ATTACKS.get(attack_id) or {}).get("name") or ""
    return f"{attack_id}: {name}" if name else attack_id


# ---------------------------------------------------------------------------
# V11 rule id -> NISTAML attribution.
#
# The ADV* adversarial-ML rules and the LLM injection rules are the natural fit;
# DATA* poisoning-adjacent rules map as preconditions. Everything else is
# deliberately unmapped and the reason recorded.
# ---------------------------------------------------------------------------
NISTAML_ENTRY_BY_RULE_ID = {
    "ADV01_EVASION_ATTACK_INDICATOR": {
        "attack": "NISTAML.022",
        "related": ("NISTAML.025",),
        "mode": DIRECT,
        "rationale": (
            "Indicators of input crafted to make a model misclassify content "
            "are an Evasion attack; where the attacker only has query access "
            "the black-box variant applies."
        ),
    },
    "ADV02_GRADIENT_EXTRACTION": {
        "attack": "NISTAML.031",
        "related": ("NISTAML.032",),
        "mode": RELATED,
        "rationale": (
            "Recovering model gradients is the standard route to extracting "
            "model information, which is a Model Extraction privacy attack and "
            "also enables Reconstruction."
        ),
    },
    "ADV03_MODEL_INVERSION": {
        "attack": "NISTAML.032",
        "related": ("NISTAML.031",),
        "mode": DIRECT,
        "rationale": (
            "Model inversion recovers representations of training inputs from "
            "model behaviour, which is a Reconstruction privacy attack."
        ),
    },
    "ADV04_MEMBERSHIP_INFERENCE": {
        "attack": "NISTAML.033",
        "related": (),
        "mode": DIRECT,
        "rationale": (
            "Establishing whether a record was in the training set is a "
            "Membership Inference privacy attack."
        ),
    },
    "ADV05_ADVERSARIAL_TESTING_MISSING": {
        "attack": "NISTAML.022",
        "related": ("NISTAML.025",),
        "mode": RELATED,
        "rationale": (
            "Absence of adversarial testing removes the control that detects "
            "Evasion and Black-box Evasion inputs."
        ),
    },
    "ADV_ADVERSARIAL_INPUT_UNTESTED": {
        "attack": "NISTAML.022",
        "related": ("NISTAML.025",),
        "mode": RELATED,
        "rationale": (
            "Content-rule form of ADV05: untested adversarial input leaves "
            "Evasion unmitigated."
        ),
    },
    "ADV_MODEL_EVASION_UNMITIGATED": {
        "attack": "NISTAML.022",
        "related": ("NISTAML.025",),
        "mode": DIRECT,
        "rationale": (
            "Content-rule form of ADV01: model-evasion mitigation explicitly "
            "disabled is an Evasion attack."
        ),
    },
    "DATA05_UNTRUSTED_TRAINING_UPLOAD": {
        "attack": "NISTAML.013",
        "related": ("NISTAML.051",),
        "mode": RELATED,
        "rationale": (
            "An untrusted upload path into a training set is the delivery "
            "channel for Data Poisoning."
        ),
    },
    "DATA_UNTRUSTED_TRAINING_UPLOAD": {
        "attack": "NISTAML.013",
        "related": ("NISTAML.051",),
        "mode": RELATED,
        "rationale": (
            "Content-rule form of DATA05: untrusted training upload is the "
            "Data Poisoning delivery channel."
        ),
    },
    "DATA_TRAINING_DATA_LINEAGE_MISSING": {
        "attack": "NISTAML.013",
        "related": (),
        "mode": RELATED,
        "rationale": (
            "Without training-data lineage there is no way to establish that "
            "poisoned records were not introduced."
        ),
    },
    "DATA01_TRAINING_SOURCE_UNKNOWN": {
        "attack": "NISTAML.013",
        "related": (),
        "mode": RELATED,
        "rationale": (
            "An unrecorded training source removes the provenance check that "
            "distinguishes legitimate data from poisoned data."
        ),
    },
    "REG01_PUBLIC_MODEL_REGISTRY_PULL": {
        "attack": "NISTAML.051",
        "related": ("NISTAML.013",),
        "mode": RELATED,
        "rationale": (
            "Acquiring a model artefact from a public registry without trust "
            "establishment is the supply-chain route by which a poisoned model "
            "reaches a system."
        ),
    },
    "REG_UNTRUSTED_MODEL_REGISTRY": {
        "attack": "NISTAML.051",
        "related": ("NISTAML.013",),
        "mode": RELATED,
        "rationale": (
            "Content-rule form of REG01: loading from an untrusted registry is "
            "the AI supply-chain attack surface."
        ),
    },
    "REG02_MODEL_CHECKSUM_MISSING": {
        "attack": "NISTAML.051",
        "related": (),
        "mode": RELATED,
        "rationale": (
            "Absent integrity verification on model load is the precondition "
            "for a supply-chain model substitution."
        ),
    },
    "REG_MODEL_CHECKSUM_MISSING": {
        "attack": "NISTAML.051",
        "related": (),
        "mode": RELATED,
        "rationale": (
            "Content-rule form of REG02: skipped checksum verification removes "
            "model artefact integrity."
        ),
    },
    "REG05_MODEL_SIGNATURE_MISSING": {
        "attack": "NISTAML.051",
        "related": (),
        "mode": RELATED,
        "rationale": (
            "An unsigned model artefact carries no provenance, so substitution "
            "is undetectable."
        ),
    },
    "REG_MODEL_SIGNATURE_MISSING": {
        "attack": "NISTAML.051",
        "related": (),
        "mode": RELATED,
        "rationale": (
            "Content-rule form of REG05: signature verification disabled "
            "removes model artefact provenance."
        ),
    },
}

NISTAML_ENTRY_BY_VULN_TYPE = {
    "llm_prompt_injection": {
        "attack": "NISTAML.018",
        "related": ("NISTAML.015",),
        "mode": DIRECT,
        "rationale": (
            "Prompt content crafted to override the model's original "
            "instructions is a Prompt Injection attack. Where the payload "
            "arrives through retrieved or third-party content the Indirect "
            "variant applies, so both are named and neither is claimed alone."
        ),
    },
    "rag_untrusted_retrieval": {
        "attack": "NISTAML.015",
        "related": ("NISTAML.018",),
        "mode": RELATED,
        "rationale": (
            "Untrusted content entering a RAG pipeline reaches the model from "
            "a source it did not author, which is the Indirect Prompt "
            "Injection delivery channel."
        ),
    },
    "rag_poisoning": {
        "attack": "NISTAML.015",
        "related": ("NISTAML.013",),
        "mode": RELATED,
        "rationale": (
            "Poisoning a retrieval index plants attacker content that later "
            "reaches the model as indirect input, and is also a data-poisoning "
            "surface."
        ),
    },
    "llm_data_poisoning": {
        "attack": "NISTAML.013",
        "related": (),
        "mode": DIRECT,
        "rationale": (
            "Contamination of pre-training or fine-tuning data is Data "
            "Poisoning."
        ),
    },
    "ai_data_lineage_risk": {
        "attack": "NISTAML.013",
        "related": (),
        "mode": RELATED,
        "rationale": (
            "Absent data lineage removes the provenance check that "
            "distinguishes legitimate training records from poisoned ones."
        ),
    },
    "llm_insecure_output": {
        "attack": "NISTAML.015",
        "related": ("NISTAML.018",),
        "mode": RELATED,
        "rationale": (
            "Failing to validate model output before it drives downstream "
            "action lets an injected instruction take effect, which is the "
            "Impact of Indirect Prompt Injection."
        ),
    },
    "llm_supply_chain": {
        "attack": "NISTAML.051",
        "related": ("NISTAML.013",),
        "mode": RELATED,
        "rationale": (
            "Trust failure in a third-party model or artefact is an AI supply "
            "chain attack."
        ),
    },
    "unsigned_or_untrusted_model_loading": {
        "attack": "NISTAML.051",
        "related": (),
        "mode": RELATED,
        "rationale": (
            "Loading an unsigned or untrusted model is the delivery path for a "
            "compromised model artefact."
        ),
    },
    "untrusted_model_loading": {
        "attack": "NISTAML.051",
        "related": (),
        "mode": RELATED,
        "rationale": (
            "Content-rule form of unsigned_or_untrusted_model_loading."
        ),
    },
    "model_registry_integrity_risk": {
        "attack": "NISTAML.051",
        "related": (),
        "mode": RELATED,
        "rationale": (
            "A registry without integrity guarantees allows the served artefact "
            "to differ from the intended one."
        ),
    },
}

# Default reason attached to any rule with no AML attribution. A single string
# rather than a per-rule table, because the reason is uniform: AML attack
# classes describe adversary techniques against trained models, while most
# advanced-AI rules in V11 detect a control, governance or supply-chain
# condition. Attributing an attack class to those would manufacture an adversary
# technique that no evidence supports.


NISTAML_UNMAPPED_RATIONALE = (
    "No NISTAML attack class claimed: this rule detects a control, governance or "
    "supply-chain condition rather than an adversary technique against a "
    "trained model."
)

# AML attack classes with no corresponding V11 rule. These are DETECTION gaps,
# not mapping gaps, and are recorded so the distinction is not lost.
NISTAML_DETECTION_GAPS = {
    "NISTAML.012": (
        "Clean-label Poisoning - no V11 rule. A detection gap; the identifier is "
        "carried in the catalogue but unmapped."
    ),
    "NISTAML.021": "Clean-label Backdoor - no V11 rule. A detection gap.",
    "NISTAML.014": (
        "Energy-latency - no V11 rule. A detection gap. V11 measures economic "
        "cost amplification (RUN03) but not a latency-based availability attack."
    ),
    "NISTAML.034": (
        "Property Inference - no V11 rule. A detection gap; ADV04 covers "
        "membership inference only."
    ),
    "NISTAML.023": "Backdoor Poisoning - no V11 rule. A detection gap.",
    "NISTAML.024": "Targeted Poisoning - no V11 rule. A detection gap.",
    "NISTAML.026": (
        "Model Poisoning under the Integrity objective - no V11 rule distinct "
        "from the evasion rules. A detection gap."
    ),
}


def nistaml_reference(rule_id: str = "", vuln_type: str = "") -> dict:
    """Pinned NISTAML attribution for a V11 rule. Fails closed."""
    rid = str(rule_id or "").strip().upper()
    vid = str(vuln_type or "").strip().lower()

    entry = NISTAML_ENTRY_BY_RULE_ID.get(rid)
    if entry is None and vid:
        entry = NISTAML_ENTRY_BY_VULN_TYPE.get(vid)

    base = {
        "nistaml": "",
        "nistaml_id": "",
        "nistaml_attack": "",
        "nistaml_objective": "",
        "nistaml_objective_name": "",
        "nistaml_related": [],
        "nistaml_mapping_mode": UNMAPPED,
        "nistaml_rationale": "",
        "nistaml_dataset": NISTAML_DATASET_LABEL,
        "nistaml_document": NISTAML_DOCUMENT,
        "nistaml_published": NISTAML_PUBLISHED,
        "nistaml_source": NISTAML_SOURCE_URL,
    }

    if not entry:
        base["nistaml_rationale"] = NISTAML_UNMAPPED_RATIONALE
        return base

    attack_id = entry["attack"]
    attack = NISTAML_ATTACKS.get(attack_id) or {}
    objective = attack.get("objective") or ""

    base.update({
        "nistaml": _label(attack_id),
        "nistaml_id": attack_id,
        "nistaml_attack": attack.get("name") or "",
        "nistaml_objective": objective,
        "nistaml_objective_name": NISTAML_OBJECTIVES.get(objective, ""),
        "nistaml_related": list(entry.get("related") or ()),
        "nistaml_mapping_mode": entry["mode"],
        "nistaml_rationale": entry["rationale"],
    })
    return base


def enrich_with_nistaml(finding: dict) -> dict:
    finding.update(nistaml_reference(
        finding.get("rule_id", ""), finding.get("vuln_type", "")
    ))
    return finding


def nistaml_coverage(rule_ids=(), vuln_types=()) -> dict:
    from collections import Counter

    def tally(keys, resolve):
        counts = Counter()
        mapped, unmapped = [], []
        keys = list(keys)
        for k in keys:
            mode = resolve(k)["nistaml_mapping_mode"]
            counts[mode] += 1
            (mapped if mode != UNMAPPED else unmapped).append(k)
        return {
            "total": len(keys),
            "by_mode": dict(counts),
            "mapped": sorted(mapped),
            "unmapped": sorted(unmapped),
            "coverage_ratio": (len(mapped) / len(keys)) if keys else 0.0,
        }

    families = {
        "advanced_ai": tally(rule_ids, lambda k: nistaml_reference(k)),
        "owasp_llm": tally(vuln_types, lambda k: nistaml_reference("", k)),
    }
    total = sum(f["total"] for f in families.values())
    mapped = sum(len(f["mapped"]) for f in families.values())
    families["combined"] = {
        "total": total,
        "mapped": mapped,
        "unmapped": total - mapped,
        "coverage_ratio": (mapped / total) if total else 0.0,
    }
    families["attacks_referenced"] = sorted({
        r["attack"] for r in NISTAML_ENTRY_BY_RULE_ID.values()
    } | {r["attack"] for r in NISTAML_ENTRY_BY_VULN_TYPE.values()})
    families["dataset"] = NISTAML_DATASET_LABEL
    return families