from __future__ import annotations


DECISION_CATALOG = {
    "ACCEPTABLE_FOR_RELEASE": {
        "priority": "P4",
        "base_confidence": 0.70,
    },
    "SECURITY_REVIEW_REQUIRED": {
        "priority": "P3",
        "base_confidence": 0.78,
    },
    "REMEDIATE_BEFORE_RELEASE": {
        "priority": "P2",
        "base_confidence": 0.86,
    },
    "MANAGEMENT_RISK_ACCEPTANCE_REQUIRED": {
        "priority": "P1",
        "base_confidence": 0.90,
    },
    "DO_NOT_RELEASE": {
        "priority": "P0",
        "base_confidence": 0.95,
    },
}


BLOCKING_SIGNALS = {
    "SECRET_MANAGEMENT_WEAKNESS",
    "CLOUD_GOVERNANCE_WEAKNESS",
    "CONTAINER_GOVERNANCE_WEAKNESS",
}

HIGH_GOVERNANCE_SIGNALS = {
    "PATCH_GOVERNANCE_WEAKNESS",
    "SUPPLY_CHAIN_GOVERNANCE_WEAKNESS",
    "LICENSE_GOVERNANCE_RISK",
}

REVIEW_SIGNALS = {
    "API_GOVERNANCE_WEAKNESS",
    "CRYPTOGRAPHIC_GOVERNANCE_WEAKNESS",
}


def _signal_ids(governance_result: dict) -> set[str]:
    return {
        str(s.get("signal_id"))
        for s in governance_result.get("governance_signals", []) or []
        if s.get("signal_id")
    }


def _signals_by_severity(governance_result: dict, severity: str) -> list[dict]:
    return [
        s for s in governance_result.get("governance_signals", []) or []
        if s.get("severity") == severity
    ]


def _max_confidence(governance_result: dict) -> float:
    values = [
        float(s.get("confidence") or 0.0)
        for s in governance_result.get("governance_signals", []) or []
    ]
    return max(values) if values else 0.0


def _decision_metadata(
    decision: str,
    confidence: float,
    drivers: list[str],
    rationale: list[str]
) -> dict:
    meta = DECISION_CATALOG.get(
        decision,
        DECISION_CATALOG["SECURITY_REVIEW_REQUIRED"]
    )

    return {
        "executive_decision": decision,
        "decision_priority": meta.get("priority", "P3"),
        "decision_confidence": round(
            max(confidence, meta.get("base_confidence", 0.75)), 2
        ),
        "decision_drivers": drivers,
        "decision_rationale": rationale,
        "decision_model": "rule_based_governance_signal_v1",
        "decision_scope": "advisory_governance_decision",
    }


def derive_executive_decision(
    governance_result: dict,
    release_readiness: dict | None = None
) -> dict:

    # Hard precedence enforcement
    release_readiness = release_readiness or {}
    release_decision = (
        release_readiness.get("release_decision")
        or release_readiness.get("decision")
    )

    if release_decision == "DO_NOT_RELEASE":
        return {
            "executive_decision": "DO_NOT_RELEASE",
            "decision_priority": "P0",
            "decision_confidence": 0.95,
            "decision_drivers": ["RELEASE_READINESS_DO_NOT_RELEASE"],
            "decision_rationale": [
                "Release readiness gate returned DO_NOT_RELEASE.",
                "Executive decision locked by release-readiness precedence.",
            ],
            "decision_model": "release_readiness_precedence_v1",
            "decision_scope": "terminal_release_governance_decision",
            "summary_status": "EXECUTIVE_DECISION_LOCKED_BY_RELEASE_GATE",
        }

    # Release-readiness is the canonical decision when it has been evaluated.
    # If there are no blocking gates, governance heuristics must not independently
    # escalate the executive decision to P0/P1.
    if release_decision and int(release_readiness.get("blocking_gate_count", 0) or 0) == 0:
        rr_map = {
            "SECURITY_REVIEW_REQUIRED": "SECURITY_REVIEW_REQUIRED",
            "CONDITIONAL_RELEASE": "ACCEPTABLE_FOR_RELEASE",
            "RELEASE_READY": "ACCEPTABLE_FOR_RELEASE",
            "REMEDIATE_BEFORE_RELEASE": "REMEDIATE_BEFORE_RELEASE",
        }
        canonical = rr_map.get(release_decision)
        if canonical:
            confidence = min(float(release_readiness.get("release_confidence") or 0.8), 0.90)
            drivers = [
                str(g.get("gate_id"))
                for g in (release_readiness.get("review_gates", []) or [])
                if g.get("gate_id") and g.get("gate_id") != "NO_BLOCKING_GATES"
            ]
            return _decision_metadata(
                canonical,
                confidence,
                drivers,
                [
                    "Executive decision aligned with release-readiness evaluation.",
                    "No blocking release-readiness gates were identified; review signals are not treated as P0/P1 blockers.",
                ],
            )

    signals = governance_result.get("governance_signals", []) or []
    summary = governance_result.get("governance_signal_summary", {}) or {}

    ids = _signal_ids(governance_result)
    high_signals = _signals_by_severity(governance_result, "HIGH")
    medium_signals = _signals_by_severity(governance_result, "MEDIUM")
    max_conf = _max_confidence(governance_result)

    if not signals:
        return _decision_metadata(
            "ACCEPTABLE_FOR_RELEASE",
            0.70,
            [],
            ["No governance signals were identified from the available evidence."]
        )

    blocking_present = sorted(ids.intersection(BLOCKING_SIGNALS))
    high_governance_present = sorted(ids.intersection(HIGH_GOVERNANCE_SIGNALS))
    review_present = sorted(ids.intersection(REVIEW_SIGNALS))

    if (
        len(blocking_present) >= 2
        and summary.get("high_signals", 0) >= 3
    ):
        return _decision_metadata(
            "DO_NOT_RELEASE",
            max_conf,
            blocking_present + high_governance_present,
            [
                "Multiple blocking governance weaknesses were identified.",
                f"{summary.get('high_signals', 0)} high-severity governance signals are present.",
                "Release should be blocked until remediation or formal executive exception is completed.",
            ]
        )

    if blocking_present and high_governance_present:
        return _decision_metadata(
            "MANAGEMENT_RISK_ACCEPTANCE_REQUIRED",
            max_conf,
            blocking_present + high_governance_present,
            [
                "At least one blocking governance weakness is present alongside high governance risk indicators.",
                "Management risk acceptance is required if remediation cannot be completed before release.",
            ]
        )

    if blocking_present:
        return _decision_metadata(
            "REMEDIATE_BEFORE_RELEASE",
            max_conf,
            blocking_present,
            [
                "Blocking governance weakness identified.",
                "Remediation is recommended before release.",
            ]
        )

    if high_governance_present or len(high_signals) >= 2:
        return _decision_metadata(
            "REMEDIATE_BEFORE_RELEASE",
            max_conf,
            high_governance_present,
            [
                "High governance risk indicators were identified.",
                "Remediation should be completed before release where feasible.",
            ]
        )

    if review_present or medium_signals:
        return _decision_metadata(
            "SECURITY_REVIEW_REQUIRED",
            max_conf,
            review_present,
            [
                "Medium governance risk indicators were identified.",
                "Security review is recommended before release approval.",
            ]
        )

    return _decision_metadata(
        "ACCEPTABLE_FOR_RELEASE",
        max_conf,
        list(ids),
        ["Only low governance indicators were identified."]
    )


if __name__ == "__main__":
    sample_governance_result = {
        "governance_signals": [
            {
                "signal_id": "SECRET_MANAGEMENT_WEAKNESS",
                "severity": "HIGH",
                "confidence": 0.95,
            }
        ],
        "governance_signal_summary": {
            "total_signals": 1,
            "high_signals": 1,
        },
    }

    import json

    print(
        json.dumps(
            derive_executive_decision(sample_governance_result),
            indent=2
        )
    )