from __future__ import annotations

from collections import Counter


ENGINE_MODE = "STATIC_BUSINESS_LOGIC_CORRELATION_V1"


def _norm(value) -> str:
    return str(value or "").replace("\\", "/").lower()


def _text(value) -> str:
    if value is None:
        return ""
    return str(value).lower()


def _file_of(item: dict) -> str:
    return _norm(item.get("file") or item.get("file_path") or item.get("full_path"))


def _route_of(item: dict) -> str:
    return str(item.get("route") or item.get("path") or item.get("endpoint") or "")


def _make(
    rule_id: str,
    title: str,
    severity: str,
    confidence: str,
    sources: list[dict],
    evidence: str,
    remediation: str,
) -> dict:
    files = sorted({_file_of(s) for s in sources if _file_of(s)})
    routes = sorted({_route_of(s) for s in sources if _route_of(s)})

    return {
        "rule_id": rule_id,
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "source_count": len(sources),
        "files": files,
        "routes": routes,
        "evidence": evidence,
        "remediation": remediation,
        "executive_relevant": severity in {"Critical", "High"},
        "correlation_mode": ENGINE_MODE,
        "source_indicators": sources,
    }


def _collect_items(summary: dict | None, keys: tuple[str, ...]) -> list[dict]:
    summary = summary or {}
    out = []
    for key in keys:
        value = summary.get(key, [])
        if isinstance(value, list):
            out.extend([x for x in value if isinstance(x, dict)])
    return out


def enrich_business_logic_correlation(
    business_logic_summary: dict | None,
    api_abuse_summary: dict | None = None,
    api_bom: list[dict] | None = None,
) -> dict:
    business_logic_summary = business_logic_summary or {}
    api_abuse_summary = api_abuse_summary or {}
    api_bom = api_bom or []

    business_items = _collect_items(
        business_logic_summary,
        (
            "global_indicators",
            "indicators",
            "findings",
            "business_logic_indicators",
            "correlations",
        ),
    )

    api_abuse_items = _collect_items(
        api_abuse_summary,
        (
            "indicators",
            "findings",
            "api_abuse_indicators",
            "unique_indicators",
        ),
    )

    correlations = []
    seen = set()

    def add(corr: dict) -> None:
        key = (
            corr.get("rule_id"),
            "|".join(corr.get("files", [])),
            "|".join(corr.get("routes", [])),
        )
        if key in seen:
            return
        seen.add(key)
        correlations.append(corr)

    combined = business_items + api_abuse_items

    def matching(keywords: tuple[str, ...]) -> list[dict]:
        hits = []
        for item in combined:
            text = " ".join([
                _text(item.get("rule_id")),
                _text(item.get("indicator")),
                _text(item.get("context_id")),
                _text(item.get("title")),
                _text(item.get("description")),
                _text(item.get("evidence_match")),
                _text(item.get("evidence")),
                _text(item.get("snippet")),
                _text(item.get("business_impact")),
                _text(item.get("route")),
                _text(item.get("file")),
            ])
            if any(k in text for k in keywords):
                hits.append(item)
        return hits

    approval = matching(("approval", "four_eyes", "dual_control", "maker_checker"))
    privilege = matching(("admin", "privilege", "role", "permission", "authorization"))
    payment = matching(("price", "payment", "discount", "coupon", "amount", "cart"))
    ownership = matching(("owner", "ownership", "tenant", "idor", "bola"))
    # Generic JS/TS tokens such as "object", "state", and "step" are not
    # standalone business-logic evidence. Require stronger anchors.
    ownership_object = [x for x in combined if "object" in _text(x.get("title")) + " " + _text(x.get("description")) and any(t in _text(x.get("title")) + " " + _text(x.get("description")) for t in ("owner", "ownership", "object id", "object_id", "objectid", "tenant"))]
    ownership.extend(ownership_object)
    workflow = matching(("workflow", "transition", "skip"))
    workflow.extend([x for x in combined if any(t in _text(x.get(k)) for k in ("title", "description", "evidence", "snippet") for t in ("state transition", "workflow state", "state machine", "approval state", "step transition"))])
    audit = matching(("audit", "logging", "security_event", "trace"))
    rate_limit = matching(("rate", "throttle", "abuse", "automation"))
    replay = matching(("replay", "nonce", "idempotency", "duplicate"))

    privileged_routes = []
    for route in api_bom:
        route_text = _text(route)
        if any(x in route_text for x in ("/admin", "/internal", "/delete", "/approve", "/role", "/permission")):
            privileged_routes.append(route)

    # 1. Privileged action without approval / governance chain
    if privilege and approval:
        add(_make(
            "BL_PRIVILEGED_APPROVAL_GOVERNANCE_CHAIN",
            "Privileged action and approval-control weakness appear together",
            "High",
            "Medium",
            privilege + approval,
            "Privilege-sensitive logic appears near approval or dual-control weakness indicators.",
            "Require approval workflow, maker-checker control, RBAC enforcement, and audit logging for privileged actions.",
        ))

    # 2. Payment/price abuse chain
    if payment and (workflow or ownership):
        add(_make(
            "BL_PAYMENT_TAMPERING_CHAIN",
            "Payment or price manipulation risk correlated with workflow or ownership weakness",
            "High",
            "Medium",
            payment + workflow + ownership,
            "Payment/price indicators appear with workflow bypass or ownership-control weakness.",
            "Recalculate prices server-side, enforce object ownership, validate state transitions, and audit payment changes.",
        ))

    # 3. Account/tenant takeover chain
    if ownership and privilege:
        add(_make(
            "BL_TENANT_PRIVILEGE_ESCALATION_CHAIN",
            "Ownership or tenant weakness correlated with privileged authorization weakness",
            "Critical",
            "Medium",
            ownership + privilege,
            "Object/tenant ownership weakness appears with privileged access or authorization indicators.",
            "Apply object-level authorization, tenant scoping, deny-by-default RBAC, and privilege boundary tests.",
        ))

    # 4. Workflow bypass without audit trail
    if workflow and not audit:
        add(_make(
            "BL_WORKFLOW_BYPASS_AUDIT_GAP",
            "Workflow/state-transition risk without audit evidence",
            "High",
            "Low",
            workflow,
            "Workflow or state-transition bypass indicators exist, but audit evidence is not observed in the same signal set.",
            "Add state-machine enforcement and audit events for all sensitive workflow transitions.",
        ))

    # 5. Automation/replay abuse around sensitive business routes
    if (rate_limit or replay) and privileged_routes:
        add(_make(
            "BL_SENSITIVE_ROUTE_ABUSE_CHAIN",
            "Sensitive business route exposed to automation or replay abuse",
            "High",
            "Medium",
            rate_limit + replay + privileged_routes,
            "Abuse-prevention weakness appears alongside privileged or sensitive API routes.",
            "Add rate limits, replay protection, idempotency controls, and authorization on sensitive routes.",
        ))

    # 6. Broad cluster
    distinct_classes = sum(bool(x) for x in [approval, privilege, payment, ownership, workflow, rate_limit, replay])
    if distinct_classes >= 4:
        add(_make(
            "BL_MULTI_VECTOR_BUSINESS_LOGIC_CLUSTER",
            "Multiple business-logic weakness classes observed",
            "High",
            "Medium",
            combined[:50],
            "Four or more business-logic weakness classes are present across the scan.",
            "Perform focused business-logic abuse testing for authorization, workflow, payment, replay, and tenant boundaries.",
        ))

    # Heuristic business-logic correlations require workflow confirmation
    # before being promoted to High/Critical executive risk.
    workflow_confirmed = bool(
        business_logic_summary.get("workflow_confirmed") is True
        or business_logic_summary.get("confirmed_workflow") is True
    )
    if not workflow_confirmed:
        for corr in correlations:
            if corr.get("severity") in {"Critical", "High"}:
                corr["severity"] = "Medium"
                corr["confidence"] = "Low"
                corr["executive_relevant"] = False
                corr["requires_manual_verification"] = True
                corr["evidence_status"] = "POTENTIAL_REVIEW_ONLY"
                corr["governance_note"] = (
                    "Business-logic correlation was not promoted because workflow "
                    "confirmation was not established."
                )

    severity_counts = Counter(c.get("severity", "Medium") for c in correlations)
    type_counts = Counter(c.get("rule_id", "UNKNOWN") for c in correlations)

    # Executive relevance requires confirmed workflow evidence and high-confidence
    # correlation evidence. Severity alone is not sufficient for executive escalation.
    for corr in correlations:
        corr["executive_relevant"] = bool(
            workflow_confirmed
            and str(corr.get("confidence", "")).title() == "High"
            and corr.get("evidence_status") != "POTENTIAL_REVIEW_ONLY"
        )

    return {
        "workflow_confirmed": workflow_confirmed,
        "total_business_logic_correlations": len(correlations),
        "critical_business_logic_correlations": severity_counts.get("Critical", 0),
        "high_business_logic_correlations": severity_counts.get("High", 0),
        "medium_business_logic_correlations": severity_counts.get("Medium", 0),
        "executive_relevant_correlations": sum(
            1 for c in correlations if c.get("executive_relevant") is True
        ),
        "by_type": dict(type_counts),
        "correlation_mode": ENGINE_MODE,
        "summary_status": (
            "BUSINESS_LOGIC_CORRELATION_CONFIRMED"
            if workflow_confirmed and any(
                str(c.get("confidence", "")).title() == "High"
                and c.get("evidence_status") != "POTENTIAL_REVIEW_ONLY"
                for c in correlations
            )
            else "BUSINESS_LOGIC_CORRELATION_REQUIRES_VALIDATION"
            if correlations
            else "NO_BUSINESS_LOGIC_CORRELATION_RISK_IDENTIFIED"
        ),
        "correlations": correlations,
    }