"""RBI FREE-AI framework (Responsible and Ethical Enablement of AI) traceability.

What this framework is, precisely
---------------------------------
A Committee report of the Reserve Bank of India, published 13 August 2025:
"Report of the Committee to develop a Framework for Responsible and Ethical
Enablement of Artificial Intelligence (FREE-AI) in the Financial Sector",
chair Puneet Pancholy, committee set up 26 December 2024. It contains 7 Sutras
(guiding principles) and 26 recommendations across 6 pillars.

It is NOT a binding RBI direction, a Master Direction, or a regulation. The
conformance baseline records that distinction and so does this module, because
presenting a committee report as a regulatory obligation would overstate it.

Source and provenance
---------------------
Catalogue transcribed from the RBI's own publication page, ID 1306
(https://www.rbi.org.in/Scripts/PublicationReportDetails.aspx?ID=1306), cross
checked against the KPMG India summary of the same report. All 26
recommendation titles were extracted mechanically from the RBI page and appear
below in the report's own numbering; the cross-check agreed on all 26.

Recommendation actors/horizons are recorded for 16 of the 26, the ones whose
bracketed actor tag was recoverable from the source text. The remaining 10 carry
`actors=""`. That is a transcription limit, not an absence in the report: an empty
field means "not captured here", and the module never fills it with a guess.

Applicability -- the reason this module is careful
--------------------------------------------------
FREE-AI addresses **regulated entities in the Indian financial sector**. R-SecOpsX
scans arbitrary codebases. Attaching a FREE-AI recommendation to a finding in a
non-financial codebase would imply the corpus is in scope of an RBI committee
report, which it is not. So:

  * a mapping states that the finding is evidence relevant to that recommendation
    *if the framework applied*, and carries `applicable_to_corpus` so a report can
    say plainly that applicability was never established;
  * no recommendation is ever reported as met, unmet or compliant.

Observability, which is where most of the value is
--------------------------------------------------
Nineteen of the 26 recommendations ask an institution to do something a source
scan cannot observe: approve a board policy, build an audit framework, build
capacity, form an institutional committee, share best practices, maintain a
sector-wide incident framework. Those are organisational acts, classified
NOT_ATTESTABLE_BY_A_SCANNER and reported as such, in the same spirit as
core/ssdf_mappings.py. A scanner that claimed to check "Board Approved AI Policy"
against source code would be claiming to audit a board.

Seven have a subject that a source or asset inventory can actually say something
about, and those are the only ones a finding may attach to:
REC 14 (policy file absent), 15 (data lifecycle traces), 16 (model lifecycle
controls), 17 (AI approval gate), 19 (AI-specific attack surface), 20 (red
teaming absent) and 23 (AI inventory completeness).

That 7-of-26 split is the honest headline for this framework, and it is why
`free_ai_coverage` publishes both denominators: a scanner cannot "cover" FREE-AI,
and a coverage ratio that concealed that would be misleading.

Not implemented, and recorded as such
------------------------------------
G-077 also notes that four recommendations have no implementation at all. The
rule inventory this module maps against does not detect them, so they appear in
FREE_AI_NO_RULE with the reason, rather than being quietly absent from a ratio.
"""
from __future__ import annotations

FREE_AI_DOCUMENT = "RBI FREE-AI Committee Report"
FREE_AI_TITLE = (
    "Report of the Committee to develop a Framework for Responsible and Ethical "
    "Enablement of Artificial Intelligence (FREE-AI) in the Financial Sector"
)
FREE_AI_PUBLISHED = "2025-08-13"
FREE_AI_SOURCE_URL = (
    "https://www.rbi.org.in/Scripts/PublicationReportDetails.aspx?ID=1306"
)
FREE_AI_CROSSCHECK_URL = (
    "https://assets.kpmg.com/content/dam/kpmgsites/in/pdf/2025/09/"
    "rbis-free-ai-committee-report-in-the-financial-sector.pdf"
)
FREE_AI_DATASET_LABEL = f"{FREE_AI_DOCUMENT} ({FREE_AI_PUBLISHED})"

# A committee report, not a binding direction. Stated here because the whole
# point of the module is traceability, and traceability to the wrong legal
# status is worse than none.
FREE_AI_LEGAL_STATUS = (
    "Committee report. NOT a binding RBI direction, Master Direction or "
    "regulation. Presenting it as an obligation would overstate it."
)
FREE_AI_APPLICABILITY = (
    "Addresses regulated entities in the Indian financial sector. R-SecOpsX scans "
    "arbitrary codebases, so applicability to a given corpus is NEVER established "
    "by this tool and must be asserted by the reader."
)

DIRECT = "DIRECT"
RELATED = "RELATED"
UNMAPPED = "UNMAPPED"
FREE_AI_MAPPING_MODES = (DIRECT, RELATED, UNMAPPED)

# Observability classes.
OBSERVABLE = "SCANNER_OBSERVABLE"
NOT_ATTESTABLE = "NOT_ATTESTABLE_BY_A_SCANNER"

# ---------------------------------------------------------------------------
# The 7 Sutras. Title and subtitle transcribed from section 4.3 of the report.
# ---------------------------------------------------------------------------
FREE_AI_SUTRAS = {
    "SUTRA_1": {
        "title": "Trust is the Foundation",
        "subtitle": "Trust is non-negotiable and should remain uncompromised",
    },
    "SUTRA_2": {
        "title": "People First",
        "subtitle": (
            "AI should augment human decision-making but defer to human judgment "
            "and citizen interest"
        ),
    },
    "SUTRA_3": {
        "title": "Innovation over Restraint",
        "subtitle": "Foster responsible innovation with purpose",
    },
    "SUTRA_4": {
        "title": "Fairness and Equity",
        "subtitle": "AI outcomes should be fair and non-discriminatory",
    },
    "SUTRA_5": {
        "title": "Accountability",
        "subtitle": "Accountability rests with the entities deploying AI",
    },
    "SUTRA_6": {
        "title": "Understandable by Design",
        "subtitle": "Ensure explainability for trust",
    },
    "SUTRA_7": {
        "title": "Safety, Resilience, and Sustainability",
        "subtitle": "AI systems should be secure, resilient and energy efficient",
    },
}

# ---------------------------------------------------------------------------
# The 6 pillars, in the report's two sub-framework groupings.
# ---------------------------------------------------------------------------
FREE_AI_FRAMEWORKS = {
    "INNOVATION_ENABLEMENT": "Innovation Enablement Framework",
    "RISK_MITIGATION": "Risk Mitigation Framework",
}

FREE_AI_PILLARS = {
    "INFRASTRUCTURE": {"framework": "INNOVATION_ENABLEMENT", "recs": (1, 2, 3, 4, 5)},
    "POLICY": {"framework": "INNOVATION_ENABLEMENT", "recs": (6, 7, 8, 9)},
    "CAPACITY": {"framework": "INNOVATION_ENABLEMENT", "recs": (10, 11, 12, 13)},
    "GOVERNANCE": {"framework": "RISK_MITIGATION", "recs": (14, 15, 16, 17)},
    "PROTECTION": {"framework": "RISK_MITIGATION", "recs": (18, 19, 20, 21, 22)},
    "ASSURANCE": {"framework": "RISK_MITIGATION", "recs": (23, 24, 25, 26)},
}


def _rec(n, pillar, title, observable, actors="", note=""):
    return {
        "id": f"FREE_AI_REC_{n}",
        "number": n,
        "pillar": pillar,
        "title": title,
        "observability": OBSERVABLE if observable else NOT_ATTESTABLE,
        "actors": actors,
        "note": note,
    }


# The 26 recommendations, in the report's own numbering and order.
# `observable=True` only where a source or asset inventory can say something
# true or false about the recommendation's subject.
FREE_AI_RECOMMENDATIONS = {
    r["id"]: r for r in [
        # ---- Infrastructure ------------------------------------------------
        _rec(1, "INFRASTRUCTURE", "Financial Sector Data Infrastructure", False,
             "Regulators and Government, Short term"),
        _rec(2, "INFRASTRUCTURE", "AI Innovation Sandbox", False,
             "Regulators, RBI, MeitY, FSRs, Short term"),
        _rec(3, "INFRASTRUCTURE", "Incentives and Funding Support", False),
        _rec(4, "INFRASTRUCTURE", "Indigenous Financial Sector Specific AI Models",
             False, "Regulators, SROs and Industry, Medium term"),
        _rec(5, "INFRASTRUCTURE", "Integrating AI with DPI", False,
             "Regulators, Medium term"),
        # ---- Policy --------------------------------------------------------
        _rec(6, "POLICY", "Adaptive and Enabling Policies", False),
        _rec(7, "POLICY", "Enabling AI-Based Affirmative Action", False,
             "Regulators, Medium term"),
        _rec(8, "POLICY", "AI Liability Framework", False),
        _rec(9, "POLICY", "AI Institutional Framework", False,
             note="Form a standing committee. An institutional act; a source scan "
                  "cannot observe that a committee exists, let alone that it met."),
        # ---- Capacity ------------------------------------------------------
        _rec(10, "CAPACITY", "Capacity Building within REs", False,
             "REs, Medium term"),
        _rec(11, "CAPACITY", "Capacity Building for Regulators and Supervisors", False),
        _rec(12, "CAPACITY", "Framework for Sharing Best Practices", False,
             "Industry Association / SRO, Medium term"),
        _rec(13, "CAPACITY", "Recognise and Reward Responsible AI Innovation", False,
             "Regulators and Industry, Medium term"),
        # ---- Governance ----------------------------------------------------
        _rec(14, "GOVERNANCE", "Board-Approved AI Policy", True,
             note="A policy document is a file, so its ABSENCE is observable when "
                  "the repository is the whole submission. Its adequacy is not: "
                  "reviewing policy content is a governance act, not a scan."),
        _rec(15, "GOVERNANCE", "Data Lifecycle Governance", True,
             "REs, Medium term",
             note="Provenance, training-source and consent handling appear in code "
                  "and configuration, so parts are observable."),
        _rec(16, "GOVERNANCE", "AI System Governance Framework", True,
             note="Model lifecycle controls (registration, versioning, approval "
                  "gates) leave traces in repositories and registries."),
        _rec(17, "GOVERNANCE", "Product Approval Process", True,
             "REs, Medium term",
             note="An AI-specific approval step is visible as a required gate in a "
                  "delivery pipeline or its absence from one."),
        # ---- Protection ----------------------------------------------------
        _rec(18, "PROTECTION", "Consumer Protection", False,
             "REs, Medium term",
             note="Transparency, fairness and grievance redressal are largely "
                  "process. The transparency and fairness obligations may be coded, "
                  "but the framework's subject is the consumer process."),
        _rec(19, "PROTECTION", "Cybersecurity Measures", True,
             "REs, Medium term",
             note="The most directly observable recommendation in the set: "
                  "AI-specific attack surface is exactly what this tool detects."),
        _rec(20, "PROTECTION", "Red Teaming", True,
             note="The ABSENCE of adversarial tests is observable in the test tree."),
        _rec(21, "PROTECTION", "Business Continuity Plan for AI Systems", False,
             "REs, Medium term",
             note="A fallback plan is a document and a drill, not source code."),
        _rec(22, "PROTECTION",
             "AI Incident Reporting and Sectoral Risk Intelligence Framework", False,
             "REs, Regulators Medium term",
             note="A sector-wide reporting framework is a supervisory arrangement."),
        # ---- Assurance -----------------------------------------------------
        _rec(23, "ASSURANCE", "AI Inventory within REs and Sector-Wide Repository", True,
             note="An AI asset inventory is the closest thing in the whole framework "
                  "to what this product already produces."),
        _rec(24, "ASSURANCE", "AI Audit Framework", False,
             note="An audit framework is an assurance engagement. Claiming to check "
                  "it from source code would be claiming to audit."),
        _rec(25, "ASSURANCE", "Disclosures by REs", False,
             "REs, Regulators, Short term",
             note="Annual-report disclosure is outside any artifact a scan produces."),
        _rec(26, "ASSURANCE", "AI Toolkit", False,
             "Regulators and Industry, Medium term"),
    ]
}

FREE_AI_OBSERVABLE_IDS = [
    rid for rid, r in FREE_AI_RECOMMENDATIONS.items()
    if r["observability"] == OBSERVABLE
]
FREE_AI_NOT_ATTESTABLE_IDS = [
    rid for rid, r in FREE_AI_RECOMMENDATIONS.items()
    if r["observability"] == NOT_ATTESTABLE
]

# Which Sutras a recommendation serves, where the report's own grouping makes
# the link explicit. Recorded per recommendation rather than inferred, and only
# where the recommendation's subject plainly sits under a named Sutra.
FREE_AI_REC_TO_SUTRA = {
    "FREE_AI_REC_14": ("SUTRA_5",),   # Accountability
    "FREE_AI_REC_15": ("SUTRA_5",),   # Accountability
    "FREE_AI_REC_16": ("SUTRA_5", "SUTRA_6"),
    "FREE_AI_REC_19": ("SUTRA_7",),   # Safety, Resilience, Sustainability
    "FREE_AI_REC_20": ("SUTRA_7",),
    "FREE_AI_REC_23": ("SUTRA_5",),   # Accountability / inventory
    "FREE_AI_REC_24": ("SUTRA_1", "SUTRA_5"),
}

# ---------------------------------------------------------------------------
# V11 rule id -> FREE-AI recommendation.
#
# Every entry is an observable recommendation, because attaching a finding to an
# organisational act would be an unevidenced claim. Each carries the reason the
# rule is relevant, so the mapping can be audited rather than trusted.
# ---------------------------------------------------------------------------
FREE_AI_BY_RULE_ID = {
    "VDB_VECTOR_DB_EXPOSURE": {
        "attack": "FREE_AI_REC_19",
        "related": ("FREE_AI_REC_23",),
        "rationale": "An exposed vector store is an AI-specific attack surface: the "
                     "recommendation asks an RE to identify and harden security "
                     "risks arising from its use of AI.",
    },
    "VDB01_PUBLIC_VECTOR_DB": {
        "attack": "FREE_AI_REC_19",
        "related": ("FREE_AI_REC_23",),
        "rationale": "A publicly reachable vector database holding embeddings is "
                     "exactly the AI-specific exposure REC 19 asks to be found.",
    },
    "VDB_RAG_INDEX_PUBLIC": {
        "attack": "FREE_AI_REC_19",
        "related": ("FREE_AI_REC_23",),
        "rationale": "A public RAG index exposes retrieved model context; REC 19 "
                     "covers AI-specific attack surface.",
    },
    "COMP_AI_POLICY_MISSING": {
        "attack": "FREE_AI_REC_14",
        "rationale": "The rule fires when no AI policy document is found in the "
                     "repository. REC 14 asks for a board-approved AI policy; the "
                     "absence of such a file is the observable part.",
    },
    "ADV_ADVERSARIAL_INPUT_UNTESTED": {
        "attack": "FREE_AI_REC_20",
        "rationale": "The rule fires when AI inputs are not adversarially tested. "
                     "REC 20 asks REs to establish red-teaming across the AI "
                     "lifecycle; missing adversarial tests is its absence.",
    },
    "GOV11_BIAS_ASSESSMENT_MISSING": {
        "attack": "FREE_AI_REC_16",
        "related": ("FREE_AI_REC_14",),
        "rationale": "No bias assessment in the AI lifecycle points at REC 16's "
                     "model-lifecycle governance subject. Note this does NOT map "
                     "to Sutra 4 (Fairness and Equity) as a compliance statement: "
                     "Sutra 4 is a principle, and a missing assessment is evidence "
                     "about governance, not a finding of discrimination.",
    },
    "REG01_PUBLIC_MODEL_REGISTRY_PULL": {
        "attack": "FREE_AI_REC_23",
        "rationale": "A model pulled from a public registry rather than an approved "
                     "internal one bears on REC 23's AI inventory subject: an "
                     "inventory that does not account for externally sourced models "
                     "is incomplete.",
    },
}

FREE_AI_BY_VULN_TYPE = {
    "vector_database_exposure": {
        "attack": "FREE_AI_REC_19",
        "rationale": "Vector store exposure is AI-specific attack surface.",
    },
    "public_vector_database": {
        "attack": "FREE_AI_REC_19",
        "rationale": "Vector store exposure is AI-specific attack surface.",
    },
    "public_rag_index_exposure": {
        "attack": "FREE_AI_REC_19",
        "rationale": "RAG index exposure is AI-specific attack surface.",
    },
    "ai_policy_compliance_missing": {
        "attack": "FREE_AI_REC_14",
        "rationale": "Absent AI policy document is the observable part of REC 14.",
    },
    "adversarial_input_testing_missing": {
        "attack": "FREE_AI_REC_20",
        "rationale": "Absent adversarial testing is the observable part of REC 20.",
    },
    "bias_assessment_missing": {
        "attack": "FREE_AI_REC_16",
        "rationale": "Absent bias assessment bears on AI lifecycle governance.",
    },
    "public_model_registry_pull": {
        "attack": "FREE_AI_REC_23",
        "rationale": "Untracked external model bears on AI inventory completeness.",
    },
    # Adversarial-ML classes also speak to REC 19 (attack surface) and REC 20
    # (red teaming). Mapped RELATED so a red-team gap is never presented as the
    # same thing as a detected attack.
    "adversarial_evasion": {
        "attack": "FREE_AI_REC_19",
        "related": ("FREE_AI_REC_20",),
        "rationale": "Adversarial evasion is AI-specific attack surface (REC 19).",
    },
    "model_extraction": {
        "attack": "FREE_AI_REC_19",
        "related": ("FREE_AI_REC_20",),
        "rationale": "Model extraction is AI-specific attack surface (REC 19).",
    },
    "model_inversion": {
        "attack": "FREE_AI_REC_19",
        "related": ("FREE_AI_REC_20",),
        "rationale": "Model inversion is AI-specific attack surface (REC 19).",
    },
    "membership_inference": {
        "attack": "FREE_AI_REC_19",
        "related": ("FREE_AI_REC_20",),
        "rationale": "Membership inference is AI-specific attack surface (REC 19).",
    },
    "llm_prompt_injection": {
        "attack": "FREE_AI_REC_19",
        "related": ("FREE_AI_REC_20",),
        "rationale": "Prompt injection is AI-specific attack surface (REC 19).",
    },
    "adversarial_prompt_injection": {
        "attack": "FREE_AI_REC_19",
        "related": ("FREE_AI_REC_20",),
        "rationale": "Prompt injection is AI-specific attack surface (REC 19).",
    },
    "indirect_prompt_injection": {
        "attack": "FREE_AI_REC_19",
        "related": ("FREE_AI_REC_20",),
        "rationale": "Indirect prompt injection is AI-specific attack surface (REC 19).",
    },
}

# Recommendations with no rule at all in this release. Recorded so they appear in
# a coverage statement instead of silently improving a ratio. These are the four
# G-077 already named, plus the two observability-relevant ones with no rule.
FREE_AI_NO_RULE = {
    "FREE_AI_REC_17": (
        "Product Approval Process - no V11 rule. An AI-specific approval gate in a "
        "delivery pipeline is detectable in principle; no rule implements it."
    ),
    "FREE_AI_REC_21": (
        "Business Continuity Plan for AI Systems - no V11 rule, and classified "
        "NOT_ATTESTABLE: a fallback plan and drill are not source artefacts."
    ),
    "FREE_AI_REC_24": (
        "AI Audit Framework - no V11 rule, and classified NOT_ATTESTABLE: an audit "
        "engagement cannot be evidenced by a source scan."
    ),
    "FREE_AI_REC_14_NOTE": (
        "REC 14 is mapped from COMP_AI_POLICY_MISSING, which detects only the "
        "ABSENCE of a policy file. Whether a present policy is adequate, board "
        "approved or even current is not determinable from a repository."
    ),
}

FREE_AI_UNMAPPED_RATIONALE = (
    "No FREE-AI recommendation was attributed to this finding. FREE-AI's 26 "
    "recommendations are mostly addressed to regulated entities and 16 of them "
    "ask for organisational acts a source scan cannot observe, so the absence of "
    "a mapping is usually a statement about the framework's subject rather than "
    "about this finding. It is not evidence that the corpus complies with FREE-AI, "
    "and FREE-AI applicability to any given corpus is never established here."
)

FREE_AI_EDGE_RATIONALE = (
    "Linked through this project's vuln_type table. The linkage is judgement, so "
    "it is reported as RELATED rather than as a framework cross-reference. FREE-AI "
    "publishes no machine-readable finding-to-recommendation mapping."
)


def free_ai_label(rec_id: str) -> str:
    rec = FREE_AI_RECOMMENDATIONS.get(str(rec_id or "").strip()) or {}
    pillar = FREE_AI_PILLARS.get(rec.get("pillar") or "", {}).get("framework", "")
    fw_name = FREE_AI_FRAMEWORKS.get(pillar, "")
    bits = [f"{rec.get('id', rec_id)}"]
    if rec.get("title"):
        bits.append(rec["title"])
    if fw_name:
        bits.append(f"({fw_name})")
    return " - ".join(bits)


def _sutra_labels(rec_id: str) -> list[str]:
    out = []
    for sid in FREE_AI_REC_TO_SUTRA.get(str(rec_id or "").strip(), ()):  # noqa: B007
        sutra = FREE_AI_SUTRAS.get(sid) or {}
        out.append(f"{sid}: {sutra.get('title', '')}")
    return out


def free_ai_reference(rule_id: str = "", vuln_type: str = "") -> dict:
    """Pinned FREE-AI attribution for one finding. Fails closed."""
    rid = str(rule_id or "").strip().upper()
    vtype = str(vuln_type or "").strip().lower()

    base = {
        "free_ai_rec": "",
        "free_ai_rec_number": "",
        "free_ai_label": "",
        "free_ai_pillar": "",
        "free_ai_framework": "",
        "free_ai_title": "",
        "free_ai_observability": "",
        "free_ai_related": [],
        "free_ai_sutras": [],
        "free_ai_mapping_mode": UNMAPPED,
        "free_ai_rationale": "",
        "free_ai_dataset": FREE_AI_DATASET_LABEL,
        "free_ai_legal_status": FREE_AI_LEGAL_STATUS,
        "free_ai_applicability": FREE_AI_APPLICABILITY,
        "free_ai_applicable_to_corpus": False,
        "free_ai_source_url": FREE_AI_SOURCE_URL,
    }

    entry = FREE_AI_BY_RULE_ID.get(rid)
    mode = DIRECT
    if entry is None:
        entry = FREE_AI_BY_VULN_TYPE.get(vtype)
        mode = RELATED if entry is not None else None

    if entry is None:
        base["free_ai_rationale"] = FREE_AI_UNMAPPED_RATIONALE
        return base

    rec_id = entry["attack"]
    rec = FREE_AI_RECOMMENDATIONS.get(rec_id) or {}
    pillar = rec.get("pillar") or ""
    base["free_ai_rec"] = rec_id
    base["free_ai_rec_number"] = rec.get("number", "")
    base["free_ai_label"] = free_ai_label(rec_id)
    base["free_ai_pillar"] = pillar
    base["free_ai_framework"] = FREE_AI_PILLARS.get(pillar, {}).get("framework", "")
    base["free_ai_title"] = rec.get("title", "")
    base["free_ai_observability"] = rec.get("observability", "")
    base["free_ai_related"] = list(entry.get("related") or ())
    base["free_ai_sutras"] = _sutra_labels(rec_id)
    base["free_ai_mapping_mode"] = mode
    base["free_ai_rationale"] = (
        entry.get("rationale", "")
        + (" " + rec.get("note") if rec.get("note") else "")
    ).strip()
    if mode == RELATED:
        base["free_ai_rationale"] += " " + FREE_AI_EDGE_RATIONALE
    return base


def enrich_with_free_ai(finding: dict) -> dict:
    finding.update(free_ai_reference(
        finding.get("rule_id", ""), finding.get("vuln_type", "")
    ))
    return finding


def free_ai_coverage(rule_ids=(), vuln_types=()) -> dict:
    """Reachability summary with every denominator stated.

    `catalogue_not_attestable_by_a_scanner` is deliberately surfaced: 16 of 26
    recommendations are organisational acts, so no scanner can ever cover the
    framework, and a coverage ratio that hid that would be misleading.
    """
    from collections import Counter

    def tally(keys, resolve):
        counts = Counter()
        mapped, unmapped = [], []
        keys = list(keys)
        for k in keys:
            m = resolve(k)["free_ai_mapping_mode"]
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
        "rule_id": tally(rule_ids, lambda k: free_ai_reference(k, "")),
        "vuln_type": tally(vuln_types, lambda k: free_ai_reference("", k)),
    }
    total = sum(f["total"] for f in families.values())
    mapped = sum(len(f["mapped"]) for f in families.values())
    families["combined"] = {
        "total": total,
        "mapped": mapped,
        "unmapped": total - mapped,
        "coverage_ratio": (mapped / total) if total else 0.0,
    }

    reached = sorted({
        ref["free_ai_rec"]
        for keys, is_rule in ((rule_ids, True), (vuln_types, False))
        for k in keys
        for ref in [free_ai_reference(k, "") if is_rule else free_ai_reference("", k)]
        if ref["free_ai_rec"]
    })

    families["recommendations_reachable"] = reached
    families["recommendations_reachable_count"] = len(reached)
    families["catalogue_size"] = len(FREE_AI_RECOMMENDATIONS)
    families["catalogue_observable_by_a_scanner"] = len(FREE_AI_OBSERVABLE_IDS)
    families["catalogue_not_attestable_by_a_scanner"] = len(FREE_AI_NOT_ATTESTABLE_IDS)
    families["sutra_count"] = len(FREE_AI_SUTRAS)
    families["dataset"] = FREE_AI_DATASET_LABEL
    families["legal_status"] = FREE_AI_LEGAL_STATUS
    families["semantics"] = (
        "Ratios describe reachability into a committee report addressed to Indian "
        "financial-sector regulated entities. They are NOT compliance, NOT a "
        "regulatory obligation, and NOT a statement that the framework applies to "
        "this corpus: applicability to a given codebase is never established by "
        "this tool. 19 of 26 recommendations ask for organisational acts that no "
        "source scan can observe, so full coverage is impossible by construction."
    )
    return families