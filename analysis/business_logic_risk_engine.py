import re
from collections import defaultdict
from typing import Any, Dict, List


BUSINESS_LOGIC_PATTERNS = [
    # Rate limit / abuse
    ("MISSING_RATE_LIMIT", r"\brate_limit\s*=\s*False\b|\brateLimit\s*:\s*false\b|\bno_rate_limit\b|\bunlimited_requests\b", "HIGH"),
    ("WEAK_RATE_LIMIT", r"\brate_limit\s*=\s*(0|None)\b|\bmax_requests\s*=\s*(0|None)\b", "HIGH"),
    ("UNBOUNDED_RETRY_LOOP", r"\bwhile\s+True\b|\bfor\s+.*range\s*\(\s*999999", "MEDIUM"),

    # Approval / workflow bypass
    ("APPROVAL_BYPASS", r"\bapproved\s*=\s*True\b|\bauto_approve\b|\bskip_approval\b|\bapproval_required\s*=\s*False\b", "HIGH"),
    ("WORKFLOW_GUARD_DISABLED", r"\bworkflow_guard\s*=\s*False\b|\bskip_workflow\b|\bdisable_workflow_check\b", "HIGH"),
    ("REFUND_WITHOUT_APPROVAL", r"\brefund\b.*\bapproved\s*=\s*True\b|\brefund\b.*\bskip_approval\b|\bauto_refund\b", "CRITICAL"),
    ("REFUND_WITHOUT_THRESHOLD", r"\brefund\b.*\b(no_threshold|threshold\s*=\s*(0|None)|without_approval)\b", "HIGH"),
    ("HIGH_VALUE_ACTION_NO_REVIEW", r"\bamount\s*>\s*\d+\b.*\bapproved\s*=\s*True\b|\bhigh_value\b.*\bskip_review\b", "HIGH"),

    # Payment / transaction manipulation
    ("PAYMENT_BYPASS", r"\bpayment_required\s*=\s*False\b|\bskip_payment\b|\bpaid\s*=\s*True\b|\bamount\s*=\s*0\b", "CRITICAL"),
    ("MISSING_BALANCE_CHECK", r"\b(balance|wallet|account_balance)\b.*\b(skip|no_check|unchecked)\b|\bdebit\b.*\bwithout_balance_check\b", "CRITICAL"),
    ("NEGATIVE_BALANCE_ALLOWED", r"\ballow[_-]?negative[_-]?balance\b|\bnegative_balance_allowed\s*=\s*True\b|\boverdraft_allowed\s*=\s*True\b", "HIGH"),
    ("TRANSACTION_STATE_TRUSTED_FROM_CLIENT", r"\bstatus\s*=\s*request\b|\bstate\s*=\s*request\b|\btransaction_status\s*=\s*request\b", "HIGH"),
    ("IDEMPOTENCY_MISSING", r"\bidempotency_key\s*=\s*None\b|\bmissing_idempotency\b|\bno_idempotency\b", "HIGH"),
    ("REPLAY_PROTECTION_MISSING", r"\breplay_protection\s*=\s*False\b|\bnonce_required\s*=\s*False\b|\bno_nonce\b", "HIGH"),

    # Coupon / pricing abuse
    ("UNLIMITED_COUPON_USE", r"\bunlimited_coupon\b|\bcoupon_limit\s*=\s*(0|None)\b|\bmax_redemptions\s*=\s*(0|None)\b", "HIGH"),
    ("COUPON_REUSE_ALLOWED", r"\bcoupon\b.*\b(reuse|multi_use|unlimited)\b|\bone_time_use\s*=\s*False\b", "HIGH"),
    ("CLIENT_CONTROLLED_DISCOUNT", r"\bdiscount\s*=\s*request\b|\bdiscount_percent\s*=\s*request\b|\bcoupon_value\s*=\s*request\b", "HIGH"),
    ("NEGATIVE_PRICE_ALLOWED", r"\bprice\s*<\s*0\b|\ballow_negative_price\b|\bdiscount\s*>\s*price\b", "HIGH"),
    ("NEGATIVE_QUANTITY_ALLOWED", r"\ballow[_-]?negative[_-]?quantity\b|\bnegative_quantity_allowed\s*=\s*True\b", "HIGH"),
    ("EXCESSIVE_DISCOUNT_ALLOWED", r"\bdiscount\s*>=\s*100\b|\bdiscount_percent\s*=\s*100\b|\bfree_checkout\b", "HIGH"),

    # Object ownership / IDOR
    ("MISSING_OBJECT_OWNERSHIP_CHECK", r"\buser_id\s*=\s*request\b|\baccount_id\s*=\s*request\b|\border_id\s*=\s*request\b", "HIGH"),
    ("DIRECT_OBJECT_ACCESS", r"\bget_object_or_404\s*\([^)]*id\b|\bfind_by_id\s*\(|\.get\s*\(\s*id\s*\)", "HIGH"),
    ("IDOR_LIKE_ACCESS_PATTERN", r"\brequest\.args\.get\s*\(['\"]id['\"]\)|\breq\.params\.id\b|\bparams\[['\"]id['\"]\]", "HIGH"),

    # Role / authorization
    ("ROLE_BYPASS_LOGIC", r"\bis_admin\s*=\s*True\b|\brole\s*=\s*['\"]admin['\"]|\bskip_authz\b|\bbypass_authorization\b", "CRITICAL"),
    ("AUTHORIZATION_DISABLED", r"\bauthorization_required\s*=\s*False\b|\bauthz\s*=\s*False\b|\bdisable_authorization\b", "CRITICAL"),
    ("CLIENT_CONTROLLED_ROLE", r"\brole\s*=\s*request\b|\bis_admin\s*=\s*request\b|\bpermissions\s*=\s*request\b", "CRITICAL"),

    # Account recovery / fraud
    ("ACCOUNT_ENUMERATION_RISK", r"\buser_exists\b|\bemail_exists\b|\baccount_exists\b", "MEDIUM"),
    ("PASSWORD_RESET_TOKEN_WEAKNESS", r"\breset_token\s*=\s*['\"]\d+['\"]|\breset_token\s*=\s*random\.randint\b", "HIGH"),
    ("OTP_BRUTE_FORCE_RISK", r"\botp\b.*\b(no_rate_limit|unlimited|retry)\b|\bverify_otp\b", "MEDIUM"),
]


RISK_RANK = {
    "NONE": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def _collect_text(obj: Any) -> str:
    if obj is None:
        return ""
    if isinstance(obj, str):
        return obj
    if isinstance(obj, dict):
        return " ".join(_collect_text(v) for v in obj.values() if v is not None)
    if isinstance(obj, list):
        return " ".join(_collect_text(x) for x in obj)
    return str(obj)


def _highest_risk(indicators: List[Dict[str, Any]]) -> str:
    if not indicators:
        return "NONE"
    return max(
        indicators,
        key=lambda x: RISK_RANK.get(x.get("risk_level", "NONE"), 0),
    ).get("risk_level", "NONE")


def _impact_for(risk: str) -> str:
    if risk == "CRITICAL":
        return "Business logic weakness may enable payment bypass, privilege abuse, authorization bypass, refund fraud, or transaction manipulation."
    if risk == "HIGH":
        return "Business logic indicator may enable abuse of workflow, object access, rate limits, discounts, coupons, or transaction state."
    if risk == "MEDIUM":
        return "Business abuse indicator observed and should be reviewed for workflow or fraud impact."
    return "No material business logic risk indicator identified."


def _action_for(risk: str) -> str:
    if risk == "CRITICAL":
        return "Immediately validate authorization, payment, approval, refund, balance, and transaction-state controls before release."
    if risk == "HIGH":
        return "Review workflow guards, ownership checks, coupon controls, rate limits, and abuse-prevention controls."
    if risk == "MEDIUM":
        return "Validate whether the indicator is exploitable in the application workflow."
    return "No action required."


def _finding_text(finding: Dict[str, Any]) -> str:
    return " ".join([
        str(finding.get("title", "")),
        str(finding.get("description", "")),
        str(finding.get("snippet", "")),
        str(finding.get("evidence", "")),
        str(finding.get("file", "")),
        str(finding.get("file_path", "")),
        _collect_text(finding.get("occurrences", [])),
    ])


def _function_name(finding: Dict[str, Any]) -> str:
    return str(
        finding.get("function_name")
        or finding.get("function")
        or finding.get("method")
        or finding.get("method_name")
        or ""
    ).strip()


def _detect_indicators(
    text: str,
    context_type: str,
    context_id: str,
    evidence: Dict[str, Any],
) -> List[Dict[str, Any]]:
    detected = []

    for name, pattern, risk in BUSINESS_LOGIC_PATTERNS:
        match = re.search(pattern, text or "", flags=re.IGNORECASE | re.DOTALL)
        if not match:
            continue

        detected.append({
            "indicator": name,
            "risk_level": risk,
            "evidence_match": match.group(0)[:200],
            "executive_relevant": risk in {"CRITICAL", "HIGH"},
            "business_logic_risk": True,
            "workflow_confirmed": False,
            "context_type": context_type,
            "context_id": context_id,
            "evidence": evidence or {},
        })

    return detected


def _dedupe_indicators(indicators: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    deduped = {}

    for item in indicators:
        evidence = item.get("evidence", {}) or {}
        key = (
            item.get("indicator"),
            evidence.get("file") or evidence.get("route") or evidence.get("agent") or "",
            item.get("evidence_match") or "",
        )

        existing = deduped.get(key)
        if existing is None:
            deduped[key] = item
            continue

        old_rank = RISK_RANK.get(existing.get("risk_level", "NONE"), 0)
        new_rank = RISK_RANK.get(item.get("risk_level", "NONE"), 0)

        if new_rank > old_rank:
            deduped[key] = item

    return list(deduped.values())


def enrich_business_logic_risk(
    findings: List[Dict[str, Any]],
    api_bom: List[Dict[str, Any]] = None,
    abom: List[Dict[str, Any]] = None,
) -> Dict[str, Any]:

    findings = findings or []
    api_bom = api_bom or []
    abom = abom or []

    indicators = []
    file_groups = defaultdict(list)
    function_groups = defaultdict(list)

    for finding in findings:
        file_key = finding.get("file") or finding.get("file_path") or ""
        fn = _function_name(finding)
        context_id = str(
            finding.get("id")
            or finding.get("rule_id")
            or finding.get("title")
            or file_key
            or "finding"
        )

        indicators.extend(
            _detect_indicators(
                _finding_text(finding),
                "FINDING",
                context_id,
                {
                    "file": finding.get("file"),
                    "line": finding.get("line"),
                    "rule_id": finding.get("rule_id"),
                    "title": finding.get("title"),
                    "function": fn or None,
                },
            )
        )

        if file_key:
            file_groups[str(file_key)].append(finding)

        if file_key and fn:
            function_groups[(str(file_key), fn)].append(finding)

    for file_key, grouped_findings in file_groups.items():
        indicators.extend(
            _detect_indicators(
                " ".join(_finding_text(f) for f in grouped_findings),
                "FILE",
                file_key,
                {
                    "file": file_key,
                    "finding_count": len(grouped_findings),
                },
            )
        )

    for (file_key, fn), grouped_findings in function_groups.items():
        indicators.extend(
            _detect_indicators(
                " ".join(_finding_text(f) for f in grouped_findings),
                "FUNCTION",
                f"{file_key}::{fn}",
                {
                    "file": file_key,
                    "function": fn,
                    "finding_count": len(grouped_findings),
                },
            )
        )

    for route in api_bom:
        route_id = str(
            route.get("route")
            or route.get("path")
            or route.get("endpoint")
            or "api_route"
        )

        indicators.extend(
            _detect_indicators(
                _collect_text(route),
                "API_ROUTE",
                route_id,
                {
                    "route": route.get("route") or route.get("path") or route.get("endpoint"),
                    "method": route.get("method"),
                },
            )
        )

    for agent in abom:
        agent_id = str(agent.get("name") or agent.get("agent") or "ai_agent")

        indicators.extend(
            _detect_indicators(
                _collect_text(agent),
                "AI_AGENT",
                agent_id,
                {
                    "agent": agent.get("name") or agent.get("agent"),
                    "type": agent.get("type"),
                },
            )
        )

    indicators = _dedupe_indicators(indicators)
    highest_risk = _highest_risk(indicators)

    critical = sum(1 for i in indicators if i.get("risk_level") == "CRITICAL")
    high = sum(1 for i in indicators if i.get("risk_level") == "HIGH")
    medium = sum(1 for i in indicators if i.get("risk_level") == "MEDIUM")
    executive_relevant = sum(1 for i in indicators if i.get("executive_relevant") is True)

    by_context = {
        "finding": sum(1 for i in indicators if i.get("context_type") == "FINDING"),
        "file": sum(1 for i in indicators if i.get("context_type") == "FILE"),
        "function": sum(1 for i in indicators if i.get("context_type") == "FUNCTION"),
        "api_route": sum(1 for i in indicators if i.get("context_type") == "API_ROUTE"),
        "ai_agent": sum(1 for i in indicators if i.get("context_type") == "AI_AGENT"),
    }

    unique_indicator_types = sorted({
        i.get("indicator")
        for i in indicators
        if i.get("indicator")
    })

    return {
        "total_business_logic_indicators": len(indicators),
        "critical_business_logic_indicators": critical,
        "high_business_logic_indicators": high,
        "medium_business_logic_indicators": medium,
        "executive_relevant_indicators": executive_relevant,
        "highest_risk_indicator": highest_risk,
        "unique_indicator_types": unique_indicator_types,
        "unique_indicator_type_count": len(unique_indicator_types),
        "by_context": by_context,
        "global_indicators": indicators,
        "workflow_confirmed": False,
        "enterprise_impact": _impact_for(highest_risk),
        "recommended_action": _action_for(highest_risk),
        "engine_mode": "OFFLINE_RULE_BASED_BUSINESS_LOGIC_CONTEXT_V2",
        "summary_status": (
            "BUSINESS_LOGIC_RISK_IDENTIFIED"
            if executive_relevant > 0
            else "NO_BUSINESS_LOGIC_RISK_IDENTIFIED"
        ),
    }
