"""Verified OWASP GenAI/Agentic mapping metadata for V11.

Mapping identifiers are metadata, not detector names. Tool-poisoning is
conditional: ASI02 for misuse/exploitation; ASI04 where evidence establishes
agentic supply-chain compromise.

OWASP GenAI entry catalogues
----------------------------
This module is the single source of truth for every OWASP label V11 emits;
``scanner/llm_security.py`` imports from here rather than keeping a second
copy.  The catalogues are transcribed from two primary sources and are never
inferred:

  2025  https://genai.owasp.org/llm-top-10/  -- the edition OWASP serves
  2026  OWASP GenAI Crosswalk, ``data/entries/LLM01..LLM10.json``,
        ``source_list == "LLM-Top10-2026"``, crosswalk version 4.0.0 /
        2026-Q3 (``data/stats.json``)

Both editions travel together because eight of the ten entries changed number
between them (Crosswalk ``MIGRATION.md``), so an edition-less ID is ambiguous
and a one-pass substitution corrupts it.  A subject that an edition does not
enumerate gets an empty entry id -- it is never re-pointed at a live risk it
does not describe.

``mapping_mode`` values emitted by :func:`map_technique`:

  ``DIRECT``          enumerated in the current edition
  ``RETIRED_2023``    left the Top 10 when the 2025 list published
  ``NOT_ENUMERATED``  a governance/control gap, not a Top 10 risk
  ``CONDITIONAL``     Agentic Top 10, depends on misuse/supply-chain evidence
  ``UNMAPPED``        fail-closed default: nothing was established
"""
from __future__ import annotations

OWASP_LLM_EDITION_PRIMARY = "2025"
OWASP_LLM_EDITION_FORWARD = "2026"

OWASP_LLM_TOP10_2025 = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain",
    "LLM04": "Data and Model Poisoning",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector and Embedding Weaknesses",
    "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
}

OWASP_LLM_TOP10_2026 = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Excessive Agency",
    "LLM04": "Supply Chain",
    "LLM05": "Data and Model Poisoning",
    "LLM06": "Unbounded Consumption",
    "LLM07": "Misinformation",
    "LLM08": "Hidden Context Exposure",
    "LLM09": "Vector and Embedding Weaknesses",
    "LLM10": "Improper Output Handling",
}

OWASP_LLM_TOP10_2023_RETIRED = {
    "LLM07": "Insecure Plugin Design",
    "LLM10": "Model Theft",
}

OWASP_LLM_GOVERNANCE_LABEL = "AI Governance Control Gap"
OWASP_LLM_UNCLASSIFIED_LABEL = "OWASP LLM / Agentic AI Security"

# V11 vulnerability type -> (2025 entry id, 2026 entry id).  An empty string
# means the subject is not enumerated in that edition.
OWASP_LLM_ENTRY_BY_VULN_TYPE = {
    "llm_prompt_injection": ("LLM01", "LLM01"),
    "llm_insecure_output": ("LLM05", "LLM10"),
    "llm_data_poisoning": ("LLM04", "LLM05"),
    "llm_model_dos": ("LLM10", "LLM06"),
    "llm_supply_chain": ("LLM03", "LLM04"),
    "llm_sensitive_disclosure": ("LLM02", "LLM02"),
    "llm_insecure_plugin": ("", ""),
    "llm_excessive_agency": ("LLM06", "LLM03"),
    "llm_overreliance": ("LLM09", "LLM07"),
    "llm_model_theft": ("", ""),
    "rag_untrusted_retrieval": ("LLM01", "LLM01"),
    "rag_no_source_grounding": ("LLM09", "LLM07"),
    "rag_poisoning": ("LLM04", "LLM05"),
    "source_grounding_missing": ("LLM09", "LLM07"),
    "ai_memory_persistence": ("LLM02", "LLM02"),
    "ai_memory_cross_tenant_leakage": ("LLM02", "LLM02"),
    "ai_tool_approval_bypass": ("LLM06", "LLM03"),
    "ai_autonomous_tool_execution": ("LLM06", "LLM03"),
    "unsafe_function_calling": ("LLM06", "LLM03"),
    "unsafe_autonomous_decision": ("LLM06", "LLM03"),
    "no_human_review": ("LLM06", "LLM03"),
    "unsafe_runtime_tool_execution": ("LLM06", "LLM03"),
    "agent_browser_automation_abuse": ("LLM06", "LLM03"),
    "embedding_data_exposure": ("LLM08", "LLM09"),
    "vector_database_exposure": ("LLM08", "LLM09"),
    "system_prompt_exposure": ("LLM07", "LLM08"),
    "prompt_template_secret_exposure": ("LLM02", "LLM02"),
    "prompt_response_logging_sensitive_data": ("LLM02", "LLM02"),
    "agent_email_exfiltration": ("LLM02", "LLM02"),
    "ai_provider_secret_exposure": ("LLM02", "LLM02"),
    "unsigned_or_untrusted_model_loading": ("LLM03", "LLM04"),
    "untrusted_model_loading": ("LLM03", "LLM04"),
    "model_registry_integrity_risk": ("LLM03", "LLM04"),
    "prompt_supply_chain_signing_missing": ("LLM03", "LLM04"),
    "ai_data_lineage_risk": ("LLM04", "LLM05"),
    # Governance/control gaps: not an enumerated risk in either edition.
    "model_governance_missing_owner": ("", ""),
    "model_governance_missing_model_card": ("", ""),
    "model_governance_incomplete": ("", ""),
    "model_approval_missing": ("", ""),
    "ai_policy_compliance_missing": ("", ""),
}

OWASP_LLM_RETIRED_BY_VULN_TYPE = {
    "llm_insecure_plugin": "LLM07",
    "llm_model_theft": "LLM10",
}

OWASP_LLM_GOVERNANCE_VULN_TYPES = frozenset({
    "model_governance_missing_owner",
    "model_governance_missing_model_card",
    "model_governance_incomplete",
    "model_approval_missing",
    "ai_policy_compliance_missing",
})

# ``map_technique`` is also called with a raw V11 rule id.  Those ids embed a
# *V11* sequence number that is unrelated to the OWASP number, so resolution
# is by the name portion only -- matching the Crosswalk guidance to "map by
# entry name rather than by ID".
OWASP_LLM_RULE_NAME_ALIASES = {
    "PROMPT_INJECTION": "llm_prompt_injection",
    "INSECURE_OUTPUT_HANDLING": "llm_insecure_output",
    "TRAINING_DATA_POISONING": "llm_data_poisoning",
    "MODEL_DENIAL_OF_SERVICE": "llm_model_dos",
    "SUPPLY_CHAIN_VULNERABILITY": "llm_supply_chain",
    "SENSITIVE_INFORMATION_DISCLOSURE": "llm_sensitive_disclosure",
    "INSECURE_PLUGIN_DESIGN": "llm_insecure_plugin",
    "EXCESSIVE_AGENCY": "llm_excessive_agency",
    "OVERRELIANCE": "llm_overreliance",
    "MODEL_THEFT": "llm_model_theft",
}


def _entry_for(vuln_type: str) -> dict:
    key = str(vuln_type or "").strip().lower()
    id_2025, id_2026 = OWASP_LLM_ENTRY_BY_VULN_TYPE.get(key, ("", ""))

    if key in OWASP_LLM_RETIRED_BY_VULN_TYPE:
        entry_id = OWASP_LLM_RETIRED_BY_VULN_TYPE[key]
        return {
            "namespace": f"{entry_id}:2023",
            "title": f"{OWASP_LLM_TOP10_2023_RETIRED[entry_id]} (retired from the Top 10 in 2025)",
            "namespace_2026": "",
            "title_2026": "",
            "owasp": [entry_id],
            "mapping_mode": "RETIRED_2023",
        }

    if key in OWASP_LLM_GOVERNANCE_VULN_TYPES:
        return {
            "namespace": "",
            "title": OWASP_LLM_GOVERNANCE_LABEL,
            "namespace_2026": "",
            "title_2026": "",
            "owasp": [],
            "mapping_mode": "NOT_ENUMERATED",
        }

    if not id_2025 and not id_2026:
        return {
            "namespace": "",
            "title": OWASP_LLM_UNCLASSIFIED_LABEL,
            "namespace_2026": "",
            "title_2026": "",
            "owasp": [],
            "mapping_mode": "UNMAPPED",
        }

    return {
        "namespace": f"{id_2025}:{OWASP_LLM_EDITION_PRIMARY}" if id_2025 else "",
        "title": OWASP_LLM_TOP10_2025.get(id_2025, ""),
        "namespace_2026": f"{id_2026}:{OWASP_LLM_EDITION_FORWARD}" if id_2026 else "",
        "title_2026": OWASP_LLM_TOP10_2026.get(id_2026, ""),
        "owasp": [id_2025] if id_2025 else [],
        "mapping_mode": "DIRECT",
    }


def _build_owasp_llm_catalog() -> dict:
    catalog = {
        vuln_type.upper(): _entry_for(vuln_type)
        for vuln_type in OWASP_LLM_ENTRY_BY_VULN_TYPE
    }
    # Legacy technique token kept so historical callers and the pinned
    # contract ``map_technique("PROMPT_INJECTION")`` keep resolving.
    catalog["PROMPT_INJECTION"] = dict(catalog["LLM_PROMPT_INJECTION"])
    return catalog


OWASP_LLM = _build_owasp_llm_catalog()


def owasp_llm_reference(vuln_type: str) -> dict:
    """Edition-tagged OWASP GenAI reference for a V11 vulnerability type.

    Returns plain strings ready to drop into a finding.  ``owasp``,
    ``owasp_id`` and ``owasp_edition`` describe the primary (2025) namespace;
    the ``*_2026`` members carry the renumbered entry from the following
    edition; ``owasp_llm_enumerated`` is ``False`` when the subject is not an
    enumerated risk in the current edition, which is what stops a retired or
    governance-only rule from being reported as a live Top 10 hit.
    """
    entry = OWASP_LLM.get(str(vuln_type or "").strip().upper()) or {
        "namespace": "",
        "title": OWASP_LLM_UNCLASSIFIED_LABEL,
        "namespace_2026": "",
        "title_2026": "",
        "owasp": [],
        "mapping_mode": "UNMAPPED",
    }

    namespace = entry.get("namespace") or ""
    namespace_2026 = entry.get("namespace_2026") or ""
    label = f"{namespace} - {entry['title']}" if namespace else (entry.get("title") or "")
    label_2026 = f"{namespace_2026} - {entry['title_2026']}" if namespace_2026 else ""

    if ":" in namespace:
        entry_id, edition = namespace.split(":", 1)
    else:
        entry_id, edition = "", ""
    entry_id_2026 = namespace_2026.split(":", 1)[0] if ":" in namespace_2026 else ""

    return {
        "owasp": label,
        "owasp_id": entry_id,
        "owasp_edition": edition,
        "owasp_llm_top10": label,
        "owasp_llm_top10_2026": label_2026,
        "owasp_id_2026": entry_id_2026,
        "owasp_llm_enumerated": entry.get("mapping_mode") == "DIRECT",
        "mapping_mode": entry.get("mapping_mode", "UNMAPPED"),
    }


OWASP_ASI = {
    "ASI01":{"title":"Agent Goal Hijack"},
    "ASI02":{"title":"Tool Misuse and Exploitation"},
    "ASI03":{"title":"Identity & Privilege Abuse"},
    "ASI04":{"title":"Agentic Supply Chain Vulnerabilities"},
    "ASI05":{"title":"Unexpected Code Execution"},
    "ASI06":{"title":"Memory & Context Poisoning"},
    "ASI07":{"title":"Insecure Inter-Agent Communication"},
    "ASI08":{"title":"Cascading Failures"},
    "ASI09":{"title":"Human-Agent Trust Exploitation"},
    "ASI10":{"title":"Rogue Agents"},
}


def _direct(vuln_type: str) -> dict | None:
    entry = OWASP_LLM.get(vuln_type)
    if entry is None:
        return None
    return dict(entry)


def map_technique(technique, *, supply_chain=False, misuse=False):
    """Map a V11 technique/rule token to its OWASP GenAI reference.

    Fail-closed: anything that does not resolve to a catalogued entry returns
    ``mapping_mode="UNMAPPED"`` with an empty ``owasp`` list.  An unmapped
    technique is never upgraded to a mapped one.
    """
    t = (technique or "").strip().upper()

    direct = _direct(t)
    if direct is not None:
        return {**direct, "technique": t}

    # Raw V11 rule ids ("LLM05_SUPPLY_CHAIN_VULNERABILITY") resolve by their
    # name portion only: the numeric prefix is V11's own sequence, not an
    # OWASP entry number.
    if "_" in t:
        name = t.split("_", 1)[1]
        direct = _direct(name)
        if direct is not None:
            return {**direct, "technique": t}

        alias = OWASP_LLM_RULE_NAME_ALIASES.get(name)
        if alias is not None:
            direct = _direct(alias.upper())
            if direct is not None:
                return {**direct, "technique": t}

    if t in {"TOOL_POISONING", "MCP_TOOL_POISONING"}:
        ids = []
        if misuse:
            ids.append("ASI02")
        if supply_chain:
            ids.append("ASI04")
        return {"technique": "TOOL_POISONING", "owasp": ids, "mapping_mode": "CONDITIONAL"}

    if t in OWASP_ASI:
        return {"technique": t, "owasp": [t], "mapping_mode": "DIRECT"}

    return {"technique": t, "owasp": [], "mapping_mode": "UNMAPPED"}


__all__ = [
    "OWASP_LLM",
    "OWASP_ASI",
    "OWASP_LLM_TOP10_2025",
    "OWASP_LLM_TOP10_2026",
    "OWASP_LLM_TOP10_2023_RETIRED",
    "OWASP_LLM_ENTRY_BY_VULN_TYPE",
    "OWASP_LLM_RETIRED_BY_VULN_TYPE",
    "OWASP_LLM_GOVERNANCE_VULN_TYPES",
    "OWASP_LLM_GOVERNANCE_LABEL",
    "OWASP_LLM_UNCLASSIFIED_LABEL",
    "OWASP_LLM_EDITION_PRIMARY",
    "OWASP_LLM_EDITION_FORWARD",
    "owasp_llm_reference",
    "map_technique",
]
