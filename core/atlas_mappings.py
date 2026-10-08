"""MITRE ATLAS (AI adversary behaviour) mapping metadata for V11.

This module is the single source of truth for every ATLAS label V11 emits.
``scanner/advanced_ai_security.py`` imports from here rather than keeping a
second copy, mirroring the arrangement used for the OWASP GenAI catalogues in
``core/owasp_mappings.py``.

Why this exists
---------------
ATLAS is a knowledge base of **adversary behaviour against AI systems**.  It is
not a vulnerability taxonomy.  V11 already detects AI weaknesses; what it could
not do is say *which adversary technique* a finding corresponds to.  Adding that
attribution is metadata, not new detection -- no rule's behaviour changes.

Dataset provenance
------------------
  ATLAS  mitre-atlas/atlas-data, ``dist/manifest.yaml``
         release ``2026.09`` (release-date 2026-09-15), format-version ``6.0.0``

  The manifest's ``dist/ATLAS.yaml`` is version 5.6.0 and its own first line
  declares it deprecated.  The live content is under ``dist/v6/``.  Pinning the
  obvious path would silently select a deprecated file, so the release and the
  format version are both recorded here and carried on every finding.

  OWASP Top 10 for LLM Applications 2026 (released 2026-08-04), Appendix A,
  independently cites ``MITRE ATLAS -- content v2026.06 (format-version
  6.0.0)``.  V11 pins a later content release of the same format version.

Per-technique ``provenance`` is recorded because not every entry below was read
from the dataset definition:

  ``atlas_definition``  the technique's own definition block was read
  ``atlas_crossref``    the id and name were confirmed from an ATLAS-internal
                        link in a definition that was read; the definition
                        block itself was not
  ``owasp_llm01``       the id and name were confirmed from OWASP's own
                        LLM01:2025 entry, which cites the ATLAS ids

Fail-closed by construction
---------------------------
:func:`atlas_reference` returns ``mapping_mode="UNMAPPED"`` with an empty
technique list for any rule id that is not in :data:`ATLAS_ENTRY_BY_RULE_ID`.
A rule is never assigned an ATLAS technique by inference, similarity or
plausibility: every mapped row carries a non-empty ``rationale`` explaining why
that specific technique applies, and ``tests/test_v11_atlas_mappings.py`` fails
the build if a rationale is missing or a referenced technique is not in
:data:`ATLAS_TECHNIQUES`.

``mapping_mode`` values
-----------------------
  ``DIRECT``    the rule detects the ATLAS technique itself
  ``RELATED``   the rule detects a condition that technique depends on
  ``UNMAPPED``  nothing defensible was established
"""
from __future__ import annotations

# ---------------------------------------------------------------------------
# CATALOGUE -- GENERATED, do not hand-edit.
#
# The tables below used to be maintained by hand in this file while the module
# declared ATLAS_FORMAT_VERSION = "6.0.0". MITRE's v6 document is a mapping keyed by
# id, capitalises maturity, and expresses tactic membership as an `achieves`
# relationship in a separate `relationships:` block -- so a hand copy could never be
# regenerated from the pinned source and could drift from its own stated pin
# silently. It did: twelve entries were transcribed from `dist/ATLAS.yaml`, which
# carries a deprecation header and declares 5.6.0, and two of their maturity values
# were wrong for a full release before anything noticed.
#
# core/atlas_catalogue.py is rendered from the pinned release by
# analysis/render_atlas_catalogue.py, which compiles and re-imports its own output
# before claiming success. Re-exported here under the original names so every
# consumer is unaffected by where the data now lives.
# ---------------------------------------------------------------------------
from core.atlas_catalogue import (  # noqa: E402
    ATLAS_AI_ONLY_TACTICS,
    ATLAS_FORMAT_VERSION,
    ATLAS_MATRIX,
    ATLAS_RELEASE,
    ATLAS_RELEASE_DATE,
    ATLAS_SOURCE_SHA256,
    ATLAS_SOURCE_URL,
    ATLAS_SUB_TECHNIQUE_COUNT,
    ATLAS_TACTIC_COUNT,
    ATLAS_TACTICS,
    ATLAS_TECHNIQUE_COUNT,
    ATLAS_TECHNIQUES,
    ATLAS_TECHNIQUES_WITH_TACTICS,
    ATLAS_TOP_LEVEL_TECHNIQUE_COUNT,
)


ATLAS_DATASET_LABEL = f"MITRE ATLAS {ATLAS_RELEASE} (format-version {ATLAS_FORMAT_VERSION})"

ATLAS_MAPPING_MODE_DIRECT = "DIRECT"
ATLAS_MAPPING_MODE_RELATED = "RELATED"
ATLAS_MAPPING_MODE_UNMAPPED = "UNMAPPED"

ATLAS_MAPPING_MODES = (
    ATLAS_MAPPING_MODE_DIRECT,
    ATLAS_MAPPING_MODE_RELATED,
    ATLAS_MAPPING_MODE_UNMAPPED,
)

ATLAS_UNMAPPED_LABEL = "ATLAS technique not established"


# ---------------------------------------------------------------------------
# Tactics -- AML.TA0000 .. AML.TA0015 (16).
#
# Three are AI-only and carry no ATT&CK equivalence:
#   AML.TA0000 AI Model Access
#   AML.TA0001 AI Attack Staging
#   AML.TA0015 Lateral Movement
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Techniques.
#
# `maturity` is an ATLAS-specific field (realized / demonstrated / feasible)
# that ATT&CK Enterprise does not carry.  Empty string means the value was not
# established from a read definition -- it is never guessed.
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# V11 rule id -> ATLAS attribution.
#
# A technique is assigned only where the rule's own detection subject is that
# technique (DIRECT) or is a precondition the technique requires (RELATED).
# Everything else is deliberately UNMAPPED -- governance, compliance and
# lifecycle rules describe a control obligation, not adversary behaviour, and
# forcing them onto a technique would manufacture adversary claims that no
# evidence supports.
# ---------------------------------------------------------------------------
ATLAS_ENTRY_BY_RULE_ID = {
    # -- Model registry / AI supply chain -----------------------------------
    "REG01_PUBLIC_MODEL_REGISTRY_PULL": {
        "technique": "AML.T0002",
        "related": ("AML.T0010",),
        "mode": "DIRECT",
        "rationale": (
            "The rule fires on pulling a model artefact from a public registry, "
            "which is ATLAS Acquire Public AI Artifacts (Resource Development)."
        ),
    },
    "REG02_MODEL_CHECKSUM_MISSING": {
        "technique": "AML.T0010",
        "related": (),
        "mode": "RELATED",
        "rationale": (
            "Absent checksum verification on model load is the integrity check "
            "that AI Supply Chain Compromise (Initial Access) depends on."
        ),
    },
    "REG03_MODEL_REGISTRY_ACL_MISSING": {
        "technique": "AML.T0010",
        "related": ("AML.T0012",),
        "mode": "RELATED",
        "rationale": (
            "A registry without access control lets an unauthorised party replace "
            "the artefact an AI system loads, which is the AI Supply Chain "
            "Compromise precondition."
        ),
    },
    "REG04_MODEL_VERSION_DRIFT": {
        "technique": "AML.T0018",
        "related": ("AML.T0031",),
        "mode": "RELATED",
        "rationale": (
            "A deployed model that differs from the registered model is evidence "
            "the model was changed outside the change path, which is Manipulate "
            "AI Model / Erode AI Model Integrity."
        ),
    },
    "REG05_MODEL_SIGNATURE_MISSING": {
        "technique": "AML.T0010",
        "related": (),
        "mode": "RELATED",
        "rationale": (
            "An unsigned model artefact carries no provenance, so a substituted "
            "artefact is indistinguishable from the intended one; this is the "
            "AI Supply Chain Compromise precondition."
        ),
    },
    "REG_MODEL_CHECKSUM_MISSING": {
        "technique": "AML.T0010",
        "related": (),
        "mode": "RELATED",
        "rationale": (
            "Content-rule form of REG02: skipping checksum verification removes "
            "the integrity check AI Supply Chain Compromise depends on."
        ),
    },
    "REG_MODEL_SIGNATURE_MISSING": {
        "technique": "AML.T0010",
        "related": (),
        "mode": "RELATED",
        "rationale": (
            "Content-rule form of REG05: signature verification disabled removes "
            "artefact provenance."
        ),
    },
    "REG_UNTRUSTED_MODEL_REGISTRY": {
        "technique": "AML.T0010",
        "related": ("AML.T0002",),
        "mode": "RELATED",
        "rationale": (
            "Loading models from an untrusted or plaintext-HTTP registry is the "
            "delivery path for AI Supply Chain Compromise."
        ),
    },
    # -- Prompt artefacts ----------------------------------------------------
    "PSC01_EXTERNAL_PROMPT_TEMPLATE_PULL": {
        "technique": "AML.T0051.001",
        "related": (),
        "mode": "RELATED",
        "rationale": (
            "Retrieving a prompt template from an external source places "
            "attacker-controllable content into the assembled context, which is "
            "the Indirect LLM Prompt Injection delivery channel."
        ),
    },
    "PSC02_PROMPT_MARKETPLACE_IMPORT": {
        "technique": "AML.T0051.001",
        "related": (),
        "mode": "RELATED",
        "rationale": (
            "Importing a prompt from a public marketplace imports untrusted "
            "instructions into the context window (Indirect LLM Prompt "
            "Injection)."
        ),
    },
    "PSC04_PROMPT_CACHE_POISONING": {
        "technique": "AML.T0051.001",
        "related": (),
        "mode": "RELATED",
        "rationale": (
            "A poisoned prompt cache lets one injected payload recur in later "
            "requests, giving Indirect LLM Prompt Injection persistence beyond "
            "the originating turn."
        ),
    },
    "PSC_UNTRUSTED_PROMPT_TEMPLATE": {
        "technique": "AML.T0051.001",
        "related": (),
        "mode": "RELATED",
        "rationale": (
            "Content-rule form of PSC01/PSC02: loading a prompt template from a "
            "remote source is the Indirect injection channel."
        ),
    },
    # -- Agents --------------------------------------------------------------
    "AGENT11_BROWSER_AUTOMATION_ABUSE": {
        "technique": "AML.T0051",
        "related": ("AML.T0054",),
        "mode": "RELATED",
        "rationale": (
            "Browser automation driven by model output converts an injected "
            "instruction into a real user action, which is what LLM Prompt "
            "Injection is escalated through when it succeeds."
        ),
    },
    "AGENT_BROWSER_AUTOMATION_ABUSE": {
        "technique": "AML.T0051",
        "related": ("AML.T0054",),
        "mode": "RELATED",
        "rationale": (
            "Content-rule form of AGENT11: the injection reaches a privileged "
            "action surface through automated browsing."
        ),
    },
    "AGENT13_DATABASE_DESTRUCTIVE_ACTION": {
        "technique": "AML.T0011",
        "related": ("AML.T0051",),
        "mode": "RELATED",
        "rationale": (
            "A destructive database action driven by an agent is an availability "
            "and integrity impact, which is the ATLAS Impact tactic."
        ),
    },
    "AGENT_DATABASE_TOOL_ABUSE": {
        "technique": "AML.T0011",
        "related": ("AML.T0051",),
        "mode": "RELATED",
        "rationale": (
            "Content-rule form of AGENT13: a database tool executing "
            "attacker-influenced input lands in the Impact tactic."
        ),
    },
    "AGENT_FILESYSTEM_ABUSE": {
        "technique": "AML.T0011",
        "related": ("AML.T0051",),
        "mode": "RELATED",
        "rationale": (
            "Agent filesystem read/write/delete on attacker-influenced paths is "
            "an impact action in the Impact tactic."
        ),
    },
    "AI_PROVIDER_SECRET_EXPOSURE": {
        "technique": "AML.T0012",
        "related": (),
        "mode": "RELATED",
        "rationale": (
            "A provider API key committed to source is a credential an adversary "
            "uses as a Valid Account against the inference API."
        ),
    },
    # -- Vector / RAG --------------------------------------------------------
    "VDB01_PUBLIC_VECTOR_DB": {
        "technique": "AML.T0064",
        "related": ("AML.T0024",),
        "mode": "RELATED",
        "rationale": (
            "A publicly reachable vector store is the indexed target an "
            "adversary gathers before targeting the RAG pipeline."
        ),
    },
    "VDB02_VECTOR_ACL_MISSING": {
        "technique": "AML.T0064",
        "related": (),
        "mode": "RELATED",
        "rationale": (
            "A vector index without access control is gatherable by any party, "
            "which is Gather RAG-Indexed Targets."
        ),
    },
    "VDB03_EMBEDDING_CROSS_TENANT_ACCESS": {
        "technique": "AML.T0024",
        "related": ("AML.T0064",),
        "mode": "RELATED",
        "rationale": (
            "Cross-tenant retrieval through the embedding layer reconstructs "
            "another principal's data, which is Exfiltration via AI Inference "
            "API."
        ),
    },
    "VDB04_UNENCRYPTED_EMBEDDINGS": {
        "technique": "AML.T0024",
        "related": (),
        "mode": "RELATED",
        "rationale": (
            "Stored embeddings readable by other principals are recoverable "
            "through the inference path."
        ),
    },
    "VDB05_SENSITIVE_DOCUMENT_INDEXING": {
        "technique": "AML.T0024",
        "related": (),
        "mode": "RELATED",
        "rationale": (
            "Indexing sensitive documents makes them retrievable through the "
            "inference API to anyone who can query it."
        ),
    },
    "VDB_VECTOR_DB_EXPOSURE": {
        "technique": "AML.T0064",
        "related": ("AML.T0024",),
        "mode": "RELATED",
        "rationale": (
            "Content-rule form of VDB01: an exposed vector database is a "
            "gatherable RAG target."
        ),
    },
    "VDB_RAG_INDEX_PUBLIC": {
        "technique": "AML.T0064",
        "related": (),
        "mode": "RELATED",
        "rationale": (
            "Content-rule form of VDB02: a public RAG index is gatherable by "
            "any party."
        ),
    },
    "VDB_EMBEDDING_EXPORT": {
        "technique": "AML.T0024",
        "related": (),
        "mode": "RELATED",
        "rationale": (
            "Exporting or persisting the embedding store moves reconstructed "
            "model-adjacent data out through the inference path."
        ),
    },
    # -- Training data -------------------------------------------------------
    "DATA05_UNTRUSTED_TRAINING_UPLOAD": {
        "technique": "AML.T0020",
    # NOTE: the related technique was AML.T0019 "Publish Poisoned
    # Datasets", which MITRE withdrew; ATLAS 2026.09 supersedes it with
    # AML.T0115 "Publish Poisoned AI Artifacts". The old id was cited
    # here while the hand-maintained catalogue still held it, so nothing
    # could detect that the pinned release no longer publishes it.
        "related": ("AML.T0115",),
        "mode": "RELATED",
        "rationale": (
            "An untrusted upload path into the training set is the delivery "
            "channel for Poison Training Data."
        ),
    },
    "DATA_UNTRUSTED_TRAINING_UPLOAD": {
        "technique": "AML.T0020",
        "related": ("AML.T0115",),
        "mode": "RELATED",
        "rationale": (
            "Content-rule form of DATA05: untrusted training upload is the "
            "Poison Training Data delivery channel."
        ),
    },
    "DATA_TRAINING_DATA_LINEAGE_MISSING": {
        "technique": "AML.T0020",
        "related": (),
        "mode": "RELATED",
        "rationale": (
            "Without training-data lineage there is no way to establish that "
            "poisoned records were not introduced, which Poison Training Data "
            "requires."
        ),
    },
    "DATA01_TRAINING_SOURCE_UNKNOWN": {
        "technique": "AML.T0020",
        "related": (),
        "mode": "RELATED",
        "rationale": (
            "An unrecorded training source removes the provenance check that "
            "distinguishes legitimate data from Poison Training Data."
        ),
    },
    # -- Adversarial ML ------------------------------------------------------
    "ADV01_EVASION_ATTACK_INDICATOR": {
        "technique": "AML.T0015",
        "related": (),
        "mode": "DIRECT",
        "rationale": (
            "Indicators of input crafted to make the model misclassify content "
            "are Evade AI Model."
        ),
    },
    "ADV02_GRADIENT_EXTRACTION": {
        "technique": "AML.T0005",
        "related": ("AML.T0024.001",),
        "mode": "RELATED",
        "rationale": (
            "Recovering model gradients is the standard route to reconstructing "
            "a target model, which is Create Proxy AI Model and feeds Invert AI "
            "Model."
        ),
    },
    "ADV03_MODEL_INVERSION": {
        "technique": "AML.T0024.001",
        "related": (),
        "mode": "DIRECT",
        "rationale": (
            "Model inversion recovers training-data representatives from model "
            "output, which is Invert AI Model."
        ),
    },
    "ADV04_MEMBERSHIP_INFERENCE": {
        "technique": "AML.T0024.000",
        "related": (),
        "mode": "DIRECT",
        "rationale": (
            "Membership inference establishes whether a record was in the "
            "training set, which is Infer Training Data Membership."
        ),
    },
    "ADV05_ADVERSARIAL_TESTING_MISSING": {
        "technique": "AML.T0015",
        "related": (),
        "mode": "RELATED",
        "rationale": (
            "Absence of adversarial testing removes the control that detects "
            "Evade AI Model inputs."
        ),
    },
    "ADV_ADVERSARIAL_INPUT_UNTESTED": {
        "technique": "AML.T0015",
        "related": (),
        "mode": "RELATED",
        "rationale": (
            "Content-rule form of ADV05: untested adversarial input leaves "
            "Evade AI Model unmitigated."
        ),
    },
    "ADV_MODEL_EVASION_UNMITIGATED": {
        "technique": "AML.T0015",
        "related": (),
        "mode": "DIRECT",
        "rationale": (
            "Content-rule form of ADV01: model-evasion mitigation explicitly "
            "disabled is Evade AI Model."
        ),
    },
    # -- Explainability ------------------------------------------------------
    "COMP06_AI_EXPLAINABILITY_MISSING": {
        "technique": "AML.T0056",
        "related": ("AML.T0054",),
        "mode": "RELATED",
        "rationale": (
            "Where behaviour is undocumented and unexplained, system-prompt and "
            "hidden-context recovery is easier, which is the precondition for "
            "Extract LLM System Prompt."
        ),
    },
}


# ---------------------------------------------------------------------------
# Explicit non-mappings.  Recording the reason keeps the gap auditable and
# stops a future edit from "fixing" it by guessing.
# ---------------------------------------------------------------------------
ATLAS_UNMAPPED_RATIONALE = {
    "AGENT12_EMAIL_EXFILTRATION": (
        "Generic agent exfiltration channel. ATLAS has no verified generic "
        "exfiltration-technique id pinned in this module, so none is claimed."
    ),
    "AGENT14_RECURSIVE_SELF_INVOCATION": (
        "Resource-exhaustion recursion is a runtime failure mode, not an ATLAS "
        "adversary technique."
    ),
    "AGENT15_SELF_MODIFYING_AGENT": (
        "Agent self-modification is an agentic risk; ATLAS 2026 defers agentic "
        "amplifications to the OWASP Top 10 for Agentic Applications."
    ),
    "AGENT16_MULTI_AGENT_ESCALATION": (
        "Multi-agent privilege amplification is an ASI-domain concern; ATLAS "
        "2026 defers it to the Agentic Top 10."
    ),
    "AGENT_EMAIL_EXFILTRATION": (
        "Content-rule form of AGENT12; same absence of a pinned ATLAS id."
    ),
    "RUN01_UNLIMITED_TOOL_RECURSION": (
        "Unbounded tool recursion is a cost/availability control gap, not an "
        "adversary technique."
    ),
    "RUN02_TOKEN_BUDGET_BYPASS": (
        "Token-budget bypass is an economic control gap, not an adversary "
        "technique."
    ),
    "RUN03_COST_AMPLIFICATION": (
        "Cost amplification is an economic control gap; ATLAS Spamming AI "
        "System with Chaff Data is the nearest candidate but its definition was "
        "not read, so it is not claimed."
    ),
    "RUN04_CONTEXT_STUFFING": (
        "Context stuffing is an input-construction weakness; the nearest ATLAS "
        "candidate was not read, so no attribution is made."
    ),
    "RUN05_AI_RATE_LIMIT_MISSING": (
        "Missing rate limiting is a control gap, not an adversary technique."
    ),
    "RUN_UNSAFE_RUNTIME_TOOL": (
        "Unsafe runtime tool wiring is a control gap; the escalation path is "
        "agentic and deferred by ATLAS 2026 to ASI."
    ),
    "RUN_CODE_INTERPRETER_UNRESTRICTED": (
        "Unrestricted code execution in the agent runtime is a control gap."
    ),
    "RUN_SANDBOX_DISABLED": (
        "A disabled sandbox is a control gap, not an adversary technique."
    ),
    "PSC03_UNSIGNED_PROMPT_PACKAGE": (
        "Prompt-artefact signing has no ATLAS technique; the technique set "
        "covers adversary behaviour, not package integrity."
    ),
    "PSC05_PROMPT_REPLAY_RISK": (
        "Prompt replay has no ATLAS technique in the pinned content."
    ),
    "PSC06_PROMPT_SIGNING_MISSING": (
        "Prompt signing has no ATLAS technique in the pinned content."
    ),
    "PSC_PROMPT_SIGNING_MISSING": (
        "Content-rule form of PSC06; no ATLAS technique."
    ),
    "PSC_PROMPT_TEMPLATE_INTEGRITY_MISSING": (
        "Prompt-template integrity has no ATLAS technique in the pinned content."
    ),
    "VDB06_CITATION_SUPPRESSION": (
        "Citation suppression is an output-grounding weakness; the nearest "
        "ATLAS candidate was not read, so no attribution is made."
    ),
    "DATA02_DATASET_LICENSE_UNKNOWN": (
        "Dataset licensing is a legal/compliance obligation, not adversary "
        "behaviour."
    ),
    "DATA03_DATASET_PII_INGESTION": (
        "PII ingestion is a privacy obligation, not adversary behaviour."
    ),
    "DATA04_TRAINING_DATA_RETENTION_MISSING": (
        "Retention is a data-governance obligation, not adversary behaviour."
    ),
    "DATA_PERSONAL_DATA_IN_TRAINING": (
        "Personal data in a training set is a privacy obligation; the inference "
        "route is Exfiltration via AI Inference API but the rule detects the "
        "data condition, not the retrieval."
    ),
    "GOV11_BIAS_ASSESSMENT_MISSING": (
        "Fairness is an ethical obligation. ATLAS models adversary behaviour "
        "and has no bias technique."
    ),
    "GOV12_FAIRNESS_TESTING_MISSING": (
        "Fairness testing is an ethical obligation with no ATLAS technique."
    ),
    "GOV13_AI_RED_TEAM_EVIDENCE_MISSING": (
        "Red-team evidence is an assurance obligation, not an adversary "
        "technique."
    ),
    "GOV14_HUMAN_FALLBACK_MISSING": (
        "Human fallback is an availability/assurance control; ATLAS has no "
        "human-oversight technique."
    ),
    "GOV15_AI_INCIDENT_PLAYBOOK_MISSING": (
        "An incident playbook is an operational readiness obligation."
    ),
    "GOV16_AI_KILL_SWITCH_MISSING": (
        "A kill switch is an operational control, not an adversary technique."
    ),
    "GOV17_MODEL_DECOMMISSION_MISSING": (
        "Decommissioning is a lifecycle obligation; Erode AI Model Integrity "
        "describes adversary-driven degradation, not orderly retirement."
    ),
    "GOV_MODEL_APPROVAL_MISSING": (
        "Model approval is a governance obligation, not adversary behaviour."
    ),
    "GOV_MODEL_CARD_MISSING": (
        "A model card is a documentation obligation, not adversary behaviour."
    ),
    "GOV_MODEL_OWNER_MISSING": (
        "Named model ownership is an accountability obligation."
    ),
    "GOV_HUMAN_REVIEW_MISSING": (
        "Human review is a control; ATLAS has no human-oversight technique."
    ),
    "COMP01_EU_AI_ACT_RISK_CLASS_MISSING": (
        "EU AI Act risk classification is a regulatory obligation."
    ),
    "COMP02_AI_DATA_RESIDENCY_UNDEFINED": (
        "Data residency is a regulatory obligation."
    ),
    "COMP03_CROSS_BORDER_AI_INFERENCE": (
        "Cross-border inference is a data-handling obligation; the nearest "
        "ATLAS candidate was not read, so no attribution is made."
    ),
    "COMP04_AI_PROCESSOR_DISCLOSURE_MISSING": (
        "Processor disclosure is a contractual obligation."
    ),
    "COMP05_AI_RETENTION_UNDEFINED": (
        "Retention is a data-governance obligation."
    ),
    "COMP_AI_POLICY_MISSING": (
        "An AI policy is a governance obligation, not adversary behaviour."
    ),
    "COMP_AI_RISK_ASSESSMENT_MISSING": (
        "Risk assessment is a governance obligation, not adversary behaviour."
    ),
    "COMP_AI_AUDIT_LOGGING_MISSING": (
        "Audit logging is an accountability obligation; ATLAS has no "
        "logging technique."
    ),
}


# ---------------------------------------------------------------------------
# V11 vulnerability type -> ATLAS attribution.
#
# The OWASP-catalogue LLM rule family keys on vuln_type rather than rule_id.
# Same three disciplines apply: a technique only where the rule's own
# detection subject is that technique (DIRECT) or is a precondition it
# requires (RELATED), and UNMAPPED everywhere else.
#
# Two candidates were deliberately NOT claimed even though they look plausible:
# "Excessive Agency"-style rules could point at a privilege-escalation-via-
# prompt-injection technique, and grounding rules could point at a hallucination-
# discovery technique; neither id was read from the pinned content, so neither is
# asserted.
# ---------------------------------------------------------------------------
ATLAS_ENTRY_BY_VULN_TYPE = {
    "llm_prompt_injection": {
        "technique": "AML.T0051",
        "related": ("AML.T0054",),
        "mode": "DIRECT",
        "rationale": (
            "The rule matches prompt content intended to override the model's "
            "original instructions, which is LLM Prompt Injection. The Direct / "
            "Indirect sub-technique is not claimed because the rule does not "
            "establish the delivery channel."
        ),
    },
    "rag_untrusted_retrieval": {
        "technique": "AML.T0051.001",
        "related": (),
        "mode": "RELATED",
        "rationale": (
            "Untrusted content entering a RAG pipeline is placed into the "
            "assembled context from a source the model did not author, which is "
            "the Indirect LLM Prompt Injection channel."
        ),
    },
    "rag_poisoning": {
        "technique": "AML.T0051.001",
        "related": ("AML.T0020",),
        "mode": "RELATED",
        "rationale": (
            "Poisoning a retrieval index plants attacker content that later "
            "reaches the model as indirect input."
        ),
    },
    "llm_data_poisoning": {
        "technique": "AML.T0020",
        "related": (),
        "mode": "DIRECT",
        "rationale": (
            "Contamination of pre-training or fine-tuning data is Poison "
            "Training Data."
        ),
    },
    "ai_data_lineage_risk": {
        "technique": "AML.T0020",
        "related": (),
        "mode": "RELATED",
        "rationale": (
            "Absent data lineage removes the provenance check that distinguishes "
            "legitimate training records from poisoned ones."
        ),
    },
    "system_prompt_exposure": {
        "technique": "AML.T0056",
        "related": ("AML.T0054",),
        "mode": "DIRECT",
        "rationale": (
            "Code that returns or logs the system prompt is the delivery side of "
            "Extract LLM System Prompt."
        ),
    },
    "llm_sensitive_disclosure": {
        "technique": "AML.T0057",
        "related": ("AML.T0024",),
        "mode": "RELATED",
        "rationale": (
            "Disclosure of sensitive data through model output or retrieval is "
            "LLM Data Leakage, reached through the inference API."
        ),
    },
    "prompt_response_logging_sensitive_data": {
        "technique": "AML.T0057",
        "related": (),
        "mode": "RELATED",
        "rationale": (
            "Writing prompts and responses containing sensitive data to a log "
            "creates a durable leakage channel for the same material LLM Data "
            "Leakage exposes through inference."
        ),
    },
    "embedding_data_exposure": {
        "technique": "AML.T0024",
        "related": ("AML.T0064",),
        "mode": "RELATED",
        "rationale": (
            "Exposed embedding data is retrievable through the inference path, "
            "which is Exfiltration via AI Inference API."
        ),
    },
    "vector_database_exposure": {
        "technique": "AML.T0064",
        "related": ("AML.T0024",),
        "mode": "RELATED",
        "rationale": (
            "An exposed vector database is the gatherable RAG target an "
            "adversary enumerates before targeting the pipeline."
        ),
    },
    "llm_supply_chain": {
        "technique": "AML.T0010",
        "related": ("AML.T0002",),
        "mode": "RELATED",
        "rationale": (
            "Trust failure in a model or artefact acquired from a third party is "
            "AI Supply Chain Compromise."
        ),
    },
    "unsigned_or_untrusted_model_loading": {
        "technique": "AML.T0010",
        "related": (),
        "mode": "RELATED",
        "rationale": (
            "Loading an unsigned or untrusted model removes artefact provenance, "
            "the precondition for AI Supply Chain Compromise."
        ),
    },
    "untrusted_model_loading": {
        "technique": "AML.T0010",
        "related": (),
        "mode": "RELATED",
        "rationale": (
            "Loading from an untrusted source is the delivery path for a "
            "compromised model artefact."
        ),
    },
    "model_registry_integrity_risk": {
        "technique": "AML.T0010",
        "related": ("AML.T0018",),
        "mode": "RELATED",
        "rationale": (
            "A registry without integrity guarantees allows the served artefact "
            "to differ from the intended one."
        ),
    },
    "ai_provider_secret_exposure": {
        "technique": "AML.T0012",
        "related": (),
        "mode": "RELATED",
        "rationale": (
            "A committed provider key is a credential usable as a Valid Account "
            "against the inference API."
        ),
    },
    "agent_browser_automation_abuse": {
        "technique": "AML.T0051",
        "related": ("AML.T0054",),
        "mode": "RELATED",
        "rationale": (
            "Browser automation driven by model output turns an injected "
            "instruction into an authenticated action."
        ),
    },
    "prompt_injection": {
        "technique": "AML.T0051",
        "related": ("AML.T0054",),
        "mode": "DIRECT",
        "rationale": (
            "Catalogue alias of llm_prompt_injection; no rule currently emits "
            "this vuln_type, so it does not contribute to measured coverage. "
            "Mapped so the alias cannot silently lose its attribution if a rule "
            "adopts it."
        ),
    },
}


# Vulnerability types in the OWASP-catalogue LLM family with no defensible
# ATLAS attribution.  Recorded so the gap is auditable rather than silent.
ATLAS_UNMAPPED_VULN_RATIONALE = {
    "llm_insecure_output": (
        "Improper output handling is an application-security concern inherited "
        "from LLM integration; ATLAS models adversary behaviour."
    ),
    "llm_excessive_agency": (
        "Excessive agency is an OWASP risk, not an ATLAS technique. The nearest "
        "ATLAS candidate was not read from the pinned content, so none is "
        "claimed."
    ),
    "ai_tool_approval_bypass": (
        "Approval bypass is an agentic control gap; ATLAS 2026 defers "
        "agentic amplifications to the OWASP Top 10 for Agentic Applications."
    ),
    "ai_autonomous_tool_execution": (
        "Autonomous tool execution is an agentic control gap, deferred to ASI."
    ),
    "unsafe_function_calling": (
        "Unsafe function calling is an agentic control gap, deferred to ASI."
    ),
    "unsafe_autonomous_decision": (
        "Unsupervised autonomous decisions are a governance and assurance gap."
    ),
    "no_human_review": (
        "Human review is a control; ATLAS has no human-oversight technique."
    ),
    "unsafe_runtime_tool_execution": (
        "Runtime tool execution safety is an agentic control gap, deferred to "
        "ASI."
    ),
    "ai_memory_persistence": (
        "Persistent agent memory is an ASI06 Memory and Context Poisoning "
        "concern; ATLAS 2026 defers it to the Agentic Top 10."
    ),
    "ai_memory_cross_tenant_leakage": (
        "Cross-tenant agent memory is an agentic isolation concern, deferred to "
        "ASI."
    ),
    "agent_email_exfiltration": (
        "Generic agent exfiltration channel with no pinned ATLAS id."
    ),
    "llm_overreliance": (
        "Over-reliance is an OWASP Misinformation risk; the nearest ATLAS "
        "candidate was not read, so none is claimed."
    ),
    "rag_no_source_grounding": (
        "Missing source grounding is an output-grounding weakness, not an "
        "adversary technique."
    ),
    "source_grounding_missing": (
        "Missing source grounding is an output-grounding weakness, not an "
        "adversary technique."
    ),
    "llm_model_dos": (
        "Resource exhaustion is an economic control gap; the nearest ATLAS "
        "candidate was not read, so none is claimed."
    ),
    "llm_insecure_plugin": (
        "Retired from the OWASP Top 10 in 2025; the nearest ATLAS candidate was "
        "not read from the pinned content."
    ),
    "llm_model_theft": (
        "Retired from the OWASP Top 10 in 2025; the nearest ATLAS candidate was "
        "not read from the pinned content."
    ),
    "prompt_template_secret_exposure": (
        "A secret embedded in a prompt template is a credential-hygiene finding; "
        "it is not system-prompt recovery, so Extract LLM System Prompt is not "
        "claimed."
    ),
    "prompt_supply_chain_signing_missing": (
        "Prompt-artefact signing has no ATLAS technique in the pinned content."
    ),
    "model_governance_missing_owner": (
        "Named ownership is an accountability obligation, not adversary "
        "behaviour."
    ),
    "model_governance_missing_model_card": (
        "A model card is a documentation obligation, not adversary behaviour."
    ),
    "model_governance_incomplete": (
        "Governance documentation completeness is an obligation, not adversary "
        "behaviour."
    ),
    "model_approval_missing": (
        "Model approval is a governance obligation, not adversary behaviour."
    ),
    "ai_policy_compliance_missing": (
        "An AI policy is a governance obligation, not adversary behaviour."
    ),
}


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------
def _technique_label(technique_id: str) -> str:
    entry = ATLAS_TECHNIQUES.get(technique_id) or {}
    name = entry.get("name") or ""
    return f"{technique_id}: {name}" if name else technique_id


def atlas_reference(rule_id: str, vuln_type: str = "") -> dict:
    """Edition- and release-pinned ATLAS attribution for a V11 rule.

    Resolution order is rule id first, then vulnerability type: the
    ``advanced_ai_security`` rules key on rule id, the OWASP-catalogue LLM
    family keys on vuln_type.  Rule id wins when both are present.

    Fails closed: an unknown rule, or one with no defensible technique,
    returns ``mapping_mode="UNMAPPED"`` with empty technique fields.  Absence is
    never rendered as a technique.
    """
    rid = str(rule_id or "").strip().upper()
    vid = str(vuln_type or "").strip().lower()

    entry = ATLAS_ENTRY_BY_RULE_ID.get(rid)
    if entry is None and vid:
        entry = ATLAS_ENTRY_BY_VULN_TYPE.get(vid)

    if not entry:
        reason = ATLAS_UNMAPPED_RATIONALE.get(rid)
        if reason is None and vid:
            reason = ATLAS_UNMAPPED_VULN_RATIONALE.get(vid)
        return {
            "atlas": "",
            "atlas_id": "",
            "atlas_technique": "",
            "atlas_tactic": "",
            "atlas_tactic_name": "",
            "atlas_related": [],
            "atlas_maturity": "",
            "atlas_provenance": "",
            "atlas_mapping_mode": ATLAS_MAPPING_MODE_UNMAPPED,
            "atlas_rationale": reason
            or "No ATLAS attribution established for this rule.",
            "atlas_dataset": ATLAS_DATASET_LABEL,
            "atlas_release": ATLAS_RELEASE,
            "atlas_format_version": ATLAS_FORMAT_VERSION,
            "atlas_source": ATLAS_SOURCE_URL,
        }

    technique_id = entry["technique"]
    technique = ATLAS_TECHNIQUES.get(technique_id) or {}
    tactics = tuple(technique.get("tactics") or ())
    primary_tactic = tactics[0] if tactics else ""

    return {
        "atlas": _technique_label(technique_id),
        "atlas_id": technique_id,
        "atlas_technique": technique.get("name") or "",
        "atlas_tactic": primary_tactic,
        "atlas_tactic_name": ATLAS_TACTICS.get(primary_tactic, ""),
        "atlas_related": list(entry.get("related") or ()),
        "atlas_maturity": technique.get("maturity") or "",
        "atlas_provenance": technique.get("provenance") or "",
        "atlas_mapping_mode": entry["mode"],
        "atlas_rationale": entry["rationale"],
        "atlas_dataset": ATLAS_DATASET_LABEL,
        "atlas_release": ATLAS_RELEASE,
        "atlas_format_version": ATLAS_FORMAT_VERSION,
        "atlas_source": ATLAS_SOURCE_URL,
    }


def enrich_with_atlas(finding: dict) -> dict:
    """Attach ATLAS attribution to one finding, in place, and return it."""
    ref = atlas_reference(
        finding.get("rule_id", ""), finding.get("vuln_type", "")
    )
    finding.update(ref)
    return finding


def atlas_coverage(rule_ids=(), vuln_types=()) -> dict:
    """Mapping coverage over a rule/vuln-type population, by mode.

    ``rule_ids`` is the ``advanced_ai_security`` population; ``vuln_types`` is
    the OWASP-catalogue LLM population.  Both are reported separately because
    they are different rule families, then combined.
    """
    from collections import Counter

    def tally(keys, resolve):
        counts = Counter()
        mapped, unmapped = [], []
        keys = list(keys)
        for k in keys:
            mode = resolve(k)["atlas_mapping_mode"]
            counts[mode] += 1
            (mapped if mode != ATLAS_MAPPING_MODE_UNMAPPED else unmapped).append(k)
        return {
            "total": len(keys),
            "by_mode": dict(counts),
            "mapped": sorted(mapped),
            "unmapped": sorted(unmapped),
            "coverage_ratio": (len(mapped) / len(keys)) if keys else 0.0,
        }

    families = {
        "advanced_ai": tally(rule_ids, lambda k: atlas_reference(k)),
        "owasp_llm": tally(
            vuln_types, lambda k: atlas_reference("", k)
        ),
    }
    total = sum(f["total"] for f in families.values())
    mapped = sum(len(f["mapped"]) for f in families.values())
    families["combined"] = {
        "total": total,
        "mapped": mapped,
        "unmapped": total - mapped,
        "coverage_ratio": (mapped / total) if total else 0.0,
    }
    families.update(
        {
            "dataset": ATLAS_DATASET_LABEL,
            "release": ATLAS_RELEASE,
            "format_version": ATLAS_FORMAT_VERSION,
        }
    )
    return families