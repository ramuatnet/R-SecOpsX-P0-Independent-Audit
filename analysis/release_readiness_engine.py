from __future__ import annotations
from typing import Any, Dict, List


DECISION_RANK = {
    "RELEASE_READY": 0,
    "CONDITIONAL_RELEASE": 1,
    "SECURITY_REVIEW_REQUIRED": 2,
    "REMEDIATE_BEFORE_RELEASE": 3,
    "DO_NOT_RELEASE": 4,
}


def _get(payload: Dict[str, Any], path: str, default=None):
    current = payload
    for part in path.split("."):
        if not isinstance(current, dict):
            return default
        current = current.get(part)
    return default if current is None else current


def _add_gate(
    gates: List[Dict[str, Any]],
    gate_id: str,
    decision: str,
    priority: str,
    reason: str,
    evidence: Dict[str, Any],
    severity: str = "HIGH",
    executive_relevant: bool | None = None,
):
    gates.append({
        "gate_id": gate_id,
        "decision": decision,
        "priority": priority,
        "severity": severity,
        "reason": reason,
        "evidence": evidence or {},
        "executive_relevant": (
            executive_relevant
            if executive_relevant is not None
            else decision in {"DO_NOT_RELEASE", "REMEDIATE_BEFORE_RELEASE", "SECURITY_REVIEW_REQUIRED"}
        ),
    })


def _highest_decision(gates: List[Dict[str, Any]]) -> str:
    if not gates:
        return "RELEASE_READY"
    return max(
        gates,
        key=lambda g: DECISION_RANK.get(g.get("decision", "RELEASE_READY"), 0),
    ).get("decision", "RELEASE_READY")


def _priority_for(decision: str) -> str:
    return {
        "DO_NOT_RELEASE": "P0",
        "REMEDIATE_BEFORE_RELEASE": "P1",
        "SECURITY_REVIEW_REQUIRED": "P2",
        "CONDITIONAL_RELEASE": "P3",
        "RELEASE_READY": "P4",
    }.get(decision, "P3")


def _confidence_for(decision: str, gates: List[Dict[str, Any]]) -> float:
    executive_gates = sum(1 for g in gates if g.get("executive_relevant"))

    if decision == "DO_NOT_RELEASE":
        return 0.95
    if decision == "REMEDIATE_BEFORE_RELEASE":
        return 0.90 if executive_gates >= 2 else 0.85
    if decision == "SECURITY_REVIEW_REQUIRED":
        return 0.80
    if decision == "CONDITIONAL_RELEASE":
        return 0.70
    return 0.65


def _deployment_recommendation(decision: str) -> str:
    return {
        "DO_NOT_RELEASE": "Release should be blocked until P0 blockers are remediated and revalidated.",
        "REMEDIATE_BEFORE_RELEASE": "Release should wait until high-risk remediation is completed or formally risk-accepted.",
        "SECURITY_REVIEW_REQUIRED": "Release requires security/governance review before approval.",
        "CONDITIONAL_RELEASE": "Release may proceed only with documented conditions, owner approval, and follow-up actions.",
        "RELEASE_READY": "No release-blocking static intelligence gates were triggered.",
    }.get(decision, "Release requires review.")


def derive_release_readiness(payload: Dict[str, Any]) -> Dict[str, Any]:
    gates: List[Dict[str, Any]] = []

    # KEV / Exploitability / Reachability
    reachable_kev = _get(payload, "kev_intelligence_summary.reachable_kev_packages", 0)
    ransomware_kev = _get(payload, "kev_intelligence_summary.ransomware_linked_packages", 0)
    immediate_remediate = _get(payload, "exploitability_summary.immediate_remediate", 0)
    p0_epss = _get(payload, "epss_intelligence_summary.p0_immediate_packages", 0)

    if reachable_kev > 0:
        _add_gate(
            gates, "REACHABLE_KEV", "DO_NOT_RELEASE", "P0",
            "Reachable known-exploited vulnerability observed.",
            {"reachable_kev_packages": reachable_kev, "ransomware_linked_packages": ransomware_kev},
            "CRITICAL",
        )

    if ransomware_kev > 0:
        _add_gate(
            gates, "RANSOMWARE_LINKED_KEV", "DO_NOT_RELEASE", "P0",
            "Ransomware-linked known exploited vulnerability observed.",
            {"ransomware_linked_packages": ransomware_kev},
            "CRITICAL",
        )

    if immediate_remediate > 0 or p0_epss > 0:
        _add_gate(
            gates, "EXPLOITABILITY_P0", "DO_NOT_RELEASE", "P0",
            "Immediate exploitability remediation signal observed.",
            {"immediate_remediate": immediate_remediate, "p0_immediate_packages": p0_epss},
            "CRITICAL",
        )

    # Secrets / Blast Radius
    # Offline secret severity is a detection signal, not proof of active provider
    # compromise. Only confirmed/live validation may create a critical SBR gate.
    secret_live_validated = _get(payload, "secret_live_validation_summary.live_valid", 0)
    secret_critical = _get(payload, "secret_intelligence_summary.critical_blast_radius", 0) if secret_live_validated else 0
    secret_high = _get(payload, "secret_intelligence_summary.high_blast_radius", 0)

    sbr_critical = _get(payload, "secret_blast_radius_correlation_summary.critical_unique_secret_blast_radius", 0)
    sbr_high = _get(payload, "secret_blast_radius_correlation_summary.high_unique_secret_blast_radius", 0)
    sbr_total = _get(payload, "secret_blast_radius_correlation_summary.total_secret_blast_radius_correlations", 0)

    confirmed_sbr_critical = 0
    for corr in (_get(payload, "secret_blast_radius_correlation_summary.correlations", []) or []):
        if corr.get("blast_radius_risk") == "CRITICAL" and corr.get("secret_confirmed") is True and corr.get("provider_scope_confirmed") is True:
            confirmed_sbr_critical += 1

    if secret_critical > 0 or confirmed_sbr_critical > 0:
        _add_gate(
            gates, "CRITICAL_SECRET_EXPOSURE", "DO_NOT_RELEASE", "P0",
            "Critical secret or provider blast-radius exposure observed.",
            {
                "secret_critical_blast_radius": secret_critical,
                "critical_unique_secret_blast_radius": confirmed_sbr_critical,
                "total_secret_blast_radius_correlations": sbr_total,
            },
            "CRITICAL",
        )
    elif secret_high > 0 and sbr_high > 0:
        _add_gate(
            gates, "HIGH_SECRET_EXPOSURE", "REMEDIATE_BEFORE_RELEASE", "P1",
            "High-impact secret exposure requires rotation and scope validation.",
            {
                "secret_high_blast_radius": secret_high,
                "high_unique_secret_blast_radius": sbr_high,
                "total_secret_blast_radius_correlations": sbr_total,
            },
            "HIGH",
        )

    # Crypto Misuse
    crypto_critical = _get(payload, "crypto_misuse_summary.critical_crypto_misuse_indicators", 0)
    crypto_high = _get(payload, "crypto_misuse_summary.high_crypto_misuse_indicators", 0)
    crypto_confirmed = bool(_get(payload, "crypto_misuse_summary.crypto_confirmed", False))

    # Static crypto heuristics remain reviewable evidence, but do not create a
    # release gate until independently confirmed.
    if not crypto_confirmed:
        crypto_critical = 0
        crypto_high = 0

    if crypto_critical > 0:
        _add_gate(
            gates, "CRITICAL_CRYPTO_MISUSE", "REMEDIATE_BEFORE_RELEASE", "P1",
            "Critical cryptographic misuse indicators observed.",
            {"critical_crypto_misuse_indicators": crypto_critical, "high_crypto_misuse_indicators": crypto_high},
            "CRITICAL",
        )
    elif crypto_high > 0:
        _add_gate(
            gates, "HIGH_CRYPTO_MISUSE", "SECURITY_REVIEW_REQUIRED", "P2",
            "High cryptographic misuse indicators require review before release.",
            {"high_crypto_misuse_indicators": crypto_high},
            "HIGH",
        )

    # API Abuse / Business Logic / Identity
    api_critical = _get(payload, "api_abuse_risk_summary.critical_api_abuse_indicators", 0)
    api_high = _get(payload, "api_abuse_risk_summary.high_api_abuse_indicators", 0)
    api_unique = _get(payload, "api_abuse_risk_summary.total_unique_api_abuse_indicators", 0)

    business_critical = _get(payload, "business_logic_risk_summary.critical_business_logic_indicators", 0)
    business_high = _get(payload, "business_logic_risk_summary.high_business_logic_indicators", 0)

    identity_critical = _get(payload, "identity_access_risk_summary.critical_identity_access_indicators", 0)
    identity_high = _get(payload, "identity_access_risk_summary.high_identity_access_indicators", 0)

    if api_critical > 0 or business_critical > 0 or identity_critical > 0:
        _add_gate(
            gates, "CRITICAL_ACCESS_OR_BUSINESS_ABUSE", "DO_NOT_RELEASE", "P0",
            "Critical API, identity, or business-logic abuse indicator observed.",
            {
                "api_critical": api_critical,
                "business_critical": business_critical,
                "identity_critical": identity_critical,
                "unique_api_abuse_indicators": api_unique,
            },
            "CRITICAL",
        )
    elif api_high > 0 or business_high > 0 or identity_high > 0:
        _add_gate(
            gates, "HIGH_ACCESS_OR_BUSINESS_ABUSE", "REMEDIATE_BEFORE_RELEASE", "P1",
            "High API, identity, or business-logic abuse indicators require remediation.",
            {
                "api_high": api_high,
                "business_high": business_high,
                "identity_high": identity_high,
                "unique_api_abuse_indicators": api_unique,
            },
            "HIGH",
            False,
        )

    # AI Model / Agent Risk
    ai_critical = _get(payload, "ai_model_risk_summary.critical_ai_model_risk_indicators", 0)
    ai_high = _get(payload, "ai_model_risk_summary.high_ai_model_risk_indicators", 0)

    ai_exec_confirmed = _get(payload, "ai_model_risk_summary.confirmed_executive_risk_indicators", 0)
    # A7: bind the priority to the SAME indicator. The old pair -- "some
    # critical exists" AND "some confirmed exists" -- let 216 unconfirmed
    # UNSAFE_CODE_INTERPRETER_TOOL criticals ride a confirmed neighbour into
    # a P0. Score the confirmed set itself: P0 needs a confirmed CRITICAL
    # indicator, P1 a confirmed HIGH one.
    ai_indicators = _get(payload, "ai_model_risk_summary.global_indicators", []) or []
    confirmed_critical = sum(
        1 for i in ai_indicators
        if isinstance(i, dict)
        and i.get("confirmed_executive_risk")
        and str(i.get("risk_level", "")).upper() == "CRITICAL"
    )
    confirmed_high = sum(
        1 for i in ai_indicators
        if isinstance(i, dict)
        and i.get("confirmed_executive_risk")
        and str(i.get("risk_level", "")).upper() == "HIGH"
    )
    if not ai_indicators:
        # Scalar-only payload (older reports did not expand the indicator
        # list): preserve the legacy count-based gate rather than going
        # silent on evidence the summariser already counted.
        confirmed_critical = ai_critical if (ai_critical > 0 and ai_exec_confirmed > 0) else 0
        confirmed_high = ai_high if (ai_high > 0 and ai_exec_confirmed > 0) else 0
    if confirmed_critical > 0:
        _add_gate(
            gates, "CRITICAL_AI_MODEL_RISK", "DO_NOT_RELEASE", "P0",
            "Critical AI model or agent execution risk observed.",
            {
                "critical_ai_model_risk_indicators": ai_critical,
                "confirmed_critical_ai_model_risk_indicators": confirmed_critical,
                "confirmed_executive_risk_indicators": ai_exec_confirmed,
            },
            "CRITICAL",
        )
    elif confirmed_high > 0:
        _add_gate(
            gates, "HIGH_AI_MODEL_RISK", "REMEDIATE_BEFORE_RELEASE", "P1",
            "High AI model, prompt, retrieval, or tool-execution risk with confirmed executive evidence.",
            {
                "high_ai_model_risk_indicators": ai_high,
                "confirmed_high_ai_model_risk_indicators": confirmed_high,
                "confirmed_executive_risk_indicators": ai_exec_confirmed,
            },
            "HIGH",
        )

    # Supply Chain / Artifact Integrity
    supply_critical = _get(payload, "supply_chain_trust_summary.critical_affected_components", 0)
    supply_high = _get(payload, "supply_chain_trust_summary.high_affected_components", 0)
    artifact_status = _get(payload, "runtime_artifact_integrity_summary.summary_status", "")
    artifact_global_integrity = _get(payload, "runtime_artifact_integrity_summary.global_artifact_integrity_indicators", 0)
    artifact_component_integrity = _get(payload, "runtime_artifact_integrity_summary.total_artifact_integrity_indicators", 0)

    if supply_critical > 0:
        _add_gate(
            gates, "CRITICAL_SUPPLY_CHAIN_TRUST_RISK", "DO_NOT_RELEASE", "P0",
            "Critical supply-chain trust risk observed.",
            {"critical_affected_components": supply_critical, "high_affected_components": supply_high},
            "CRITICAL",
        )
    elif supply_high > 0:
        _add_gate(
            gates, "SUPPLY_CHAIN_TRUST_RISK", "SECURITY_REVIEW_REQUIRED", "P2",
            "Supply-chain trust indicators observed.",
            {"high_affected_components": supply_high},
            "HIGH",
        )

    if artifact_status == "ARTIFACT_INTEGRITY_RISK_IDENTIFIED":
        # Component-level/static observations such as an unpinned Docker reference
        # are not proof that a deployed artifact is affected. Only confirmed
        # global artifact evidence can block release; component observations
        # remain review/remediation signals.
        if artifact_global_integrity > 0:
            artifact_decision = "REMEDIATE_BEFORE_RELEASE"
            artifact_priority = "P1"
        elif artifact_component_integrity > 0:
            artifact_decision = "SECURITY_REVIEW_REQUIRED"
            artifact_priority = "P2"
        else:
            artifact_decision = "SECURITY_REVIEW_REQUIRED"
            artifact_priority = "P2"

        _add_gate(
            gates, "ARTIFACT_INTEGRITY_RISK", artifact_decision, artifact_priority,
            "Runtime artifact integrity risk observed.",
            {
                "artifact_status": artifact_status,
                "global_artifact_integrity_indicators": artifact_global_integrity,
                "component_artifact_integrity_indicators": artifact_component_integrity,
                "artifact_presence_confirmed": artifact_global_integrity > 0,
            },
            "HIGH",
            artifact_global_integrity > 0,
        )

    # License / Governance / Control Coverage
    legal_review = _get(payload, "license_policy_summary.legal_review_required_components", 0)
    unknown_license = _get(payload, "license_policy_summary.unknown_license_components", 0)

    if legal_review > 0:
        _add_gate(
            gates, "LICENSE_LEGAL_REVIEW", "SECURITY_REVIEW_REQUIRED", "P2",
            "License legal review required before release.",
            {"legal_review_required_components": legal_review},
            "HIGH",
        )
    elif unknown_license > 0:
        _add_gate(
            gates, "UNKNOWN_LICENSES", "CONDITIONAL_RELEASE", "P3",
            "Unknown licenses observed; release may require governance review.",
            {"unknown_license_components": unknown_license},
            "MEDIUM",
        )

    control_status = _get(payload, "security_control_coverage_summary.defense_in_depth_status", "NOT_AVAILABLE")
    executive_control_gaps = _get(payload, "security_control_coverage_summary.executive_relevant_gaps", 0)
    coverage_ratio = _get(payload, "security_control_coverage_summary.coverage_ratio", 0)

    # Static "not observed" controls are not proof of absence. Keep these as
    # review signals and never make them release blockers without concrete
    # absence evidence.
    if coverage_ratio < 0.60 and executive_control_gaps > 0:
        _add_gate(
            gates, "CONTROL_COVERAGE_GAPS", "SECURITY_REVIEW_REQUIRED", "P2",
            "Defense-in-depth controls were not observed in static evidence; this does not prove the controls are absent.",
            {
                "coverage_ratio": coverage_ratio,
                "control_status": control_status,
                "executive_relevant_gaps": executive_control_gaps,
                "evidence_status": "NOT_OBSERVED_NOT_PROOF_OF_ABSENCE",
            },
            "MEDIUM",
            False,
        )

    # Data Flow Correlation
    correlated_critical = _get(payload, "data_flow_correlation_summary.critical_correlated_flows", 0)
    correlated_high = _get(payload, "data_flow_correlation_summary.high_correlated_flows", 0)

    # Critical/High data-flow correlations are release blockers only when the
    # correlation engine explicitly confirms the flow. Heuristic/contextual
    # correlations remain review signals.
    df_correlations = _get(payload, "data_flow_correlation_summary.correlations", []) or []
    confirmed_critical = sum(
        1 for c in df_correlations
        if str(c.get("severity", "")).lower() == "critical"
        and c.get("confirmed") is True
        and c.get("evidence_status") == "CONFIRMED"
    )
    confirmed_high = sum(
        1 for c in df_correlations
        if str(c.get("severity", "")).lower() == "high"
        and c.get("confirmed") is True
        and c.get("evidence_status") == "CONFIRMED"
    )

    if confirmed_critical > 0:
        _add_gate(
            gates, "CRITICAL_DATA_FLOW_CORRELATION", "DO_NOT_RELEASE", "P0",
            "Confirmed critical sensitive source-to-sink correlation observed.",
            {"critical_correlated_flows": confirmed_critical},
            "CRITICAL",
        )
    elif confirmed_high > 0:
        _add_gate(
            gates, "HIGH_DATA_FLOW_CORRELATION", "REMEDIATE_BEFORE_RELEASE", "P1",
            "High sensitive source-to-sink correlation observed.",
            {"high_correlated_flows": confirmed_high},
            "HIGH",
        )

    if not gates:
        gates.append({
            "gate_id": "NO_BLOCKING_GATES",
            "decision": "RELEASE_READY",
            "priority": "P4",
            "severity": "INFO",
            "reason": "No blocking release-readiness gate was triggered from available static intelligence.",
            "evidence": {},
            "executive_relevant": False,
        })

    final_decision = _highest_decision(gates)
    final_priority = _priority_for(final_decision)

    blocking_gates = [
        g for g in gates
        if g.get("decision") in {"DO_NOT_RELEASE", "REMEDIATE_BEFORE_RELEASE"}
    ]
    review_gates = [
        g for g in gates
        if g.get("decision") in {"SECURITY_REVIEW_REQUIRED", "CONDITIONAL_RELEASE"}
    ]

    critical_blockers = sum(1 for g in blocking_gates if g.get("severity") == "CRITICAL")
    high_blockers = sum(1 for g in blocking_gates if g.get("severity") == "HIGH")
    medium_review_gates = sum(1 for g in review_gates if g.get("severity") == "MEDIUM")

    return {
        "release_decision": final_decision,
        "release_priority": final_priority,
        "release_confidence": _confidence_for(final_decision, gates),
        "deployment_recommendation": _deployment_recommendation(final_decision),
        "release_rationale": [g.get("reason") for g in gates],
        "blocking_gates": blocking_gates,
        "review_gates": review_gates,
        "all_gates": gates,
        "blocking_gate_count": len(blocking_gates),
        "review_gate_count": len(review_gates),
        "critical_blockers": critical_blockers,
        "high_blockers": high_blockers,
        "medium_review_gates": medium_review_gates,
        "engine_mode": "STATIC_RELEASE_READINESS_GOVERNANCE_V2",
        "summary_status": "RELEASE_READINESS_EVALUATED",
    }