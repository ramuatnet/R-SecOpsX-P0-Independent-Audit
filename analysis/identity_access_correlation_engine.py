from __future__ import annotations

from collections import Counter


ENGINE_MODE = "STATIC_IDENTITY_ACCESS_CORRELATION_V2_HARDENED"


PRIVILEGED_ROUTE_KEYWORDS = (
    "/admin",
    "/internal",
    "/debug",
    "/impersonate",
    "/users/delete",
    "/user/delete",
    "/delete-user",
    "/role",
    "/roles",
    "/permissions",
    "/privilege",
    "/superuser",
)

PRIVILEGED_TOKEN_KEYWORDS = (
    "aws_access_key",
    "aws_secret",
    "github_token",
    "gitlab_token",
    "jwt_secret",
    "service_account",
    "service_account_key",
    "private_key",
    "api_key",
    "bearer",
    "oauth_token",
)

RBAC_KEYWORDS = (
    "is_admin",
    "admin",
    "superuser",
    "role ==",
    "role=",
    "roles",
    "permission",
    "permissions",
    "authorize",
    "authorization",
    "rbac",
)

MISSING_AUTH_KEYWORDS = (
    "missing auth",
    "missing authorization",
    "no authorization",
    "no auth",
    "auth bypass",
    "authorization bypass",
    "unauthenticated",
    "insecure direct object reference",
    "idor",
)

JWT_BYPASS_KEYWORDS = (
    "verify=false",
    "verify_signature=false",
    "algorithms=['none']",
    'algorithms=["none"]',
    "algorithm none",
    "jwt decode without verification",
    "jwt validation bypass",
)

SESSION_FIXATION_KEYWORDS = (
    "session fixation",
    "session_id",
    "request.session",
    "session[",
    "set_cookie",
    "login",
    "regenerate",
    "rotate",
)


def _text(value) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list, tuple, set)):
        return str(value).lower()
    return str(value).lower()


def _finding_text(finding: dict) -> str:
    parts = [
        finding.get("rule_id"),
        finding.get("title"),
        finding.get("vuln_type"),
        finding.get("description"),
        finding.get("snippet"),
        finding.get("evidence"),
        finding.get("file"),
        finding.get("file_path"),
        finding.get("issue_type"),
        finding.get("business_impact"),
    ]
    return " | ".join(_text(p) for p in parts if p is not None)


def _route_text(route: dict) -> str:
    parts = [
        route.get("route"),
        route.get("path"),
        route.get("endpoint"),
        route.get("method"),
        route.get("file"),
        route.get("file_path"),
        route.get("handler"),
        route.get("function"),
        route.get("auth"),
        route.get("authentication"),
        route.get("authorization"),
    ]
    return " | ".join(_text(p) for p in parts if p is not None)


def _file_of(item: dict) -> str:
    return str(
        item.get("file")
        or item.get("file_path")
        or item.get("full_path")
        or ""
    ).replace("\\", "/").lower()


def _line_of(item: dict):
    return item.get("line") or item.get("line_number") or item.get("start_line")


def _severity_rank(sev: str) -> int:
    ranks = {
        "critical": 4,
        "high": 3,
        "medium": 2,
        "low": 1,
        "info": 0,
    }
    return ranks.get(str(sev).lower(), 0)


def _max_severity(*values: str) -> str:
    best = "Medium"
    for value in values:
        if _severity_rank(value) > _severity_rank(best):
            best = value
    return best


def _has_any(text: str, keywords: tuple[str, ...]) -> bool:
    return any(k in text for k in keywords)
    

def _secret_category(text: str) -> str:
    text = _text(text)

    if "aws_access_key" in text or "aws_secret" in text or "aws_access_key_id" in text:
        return "aws_credential"

    if "github_token" in text or "gitlab_token" in text:
        return "scm_token"

    if "jwt_secret" in text or "jwt" in text:
        return "jwt_secret"

    if "service_account" in text or "service_account_key" in text:
        return "service_account"

    if "private_key" in text or "private key" in text:
        return "private_key"

    if "api_key" in text or "api key" in text:
        return "api_key"

    if "bearer" in text or "oauth_token" in text or "oauth" in text:
        return "oauth_token"

    return "generic_identity_secret"


def _is_privileged_route(route: dict) -> bool:
    text = _route_text(route)
    return _has_any(text, PRIVILEGED_ROUTE_KEYWORDS)


def _route_has_auth(route: dict) -> bool:
    text = _route_text(route)
    positive = (
        "auth=true",
        "authenticated",
        "requires_auth",
        "login_required",
        "jwt_required",
        "permission_required",
        "authorize",
        "authorization",
        "rbac",
        "iam",
    )
    negative = (
        "auth=false",
        "no auth",
        "unauthenticated",
        "public",
        "anonymous",
    )

    if any(x in text for x in negative):
        return False

    return any(x in text for x in positive)


def _make_correlation(
    *,
    correlation_id: str,
    correlation_type: str,
    title: str,
    severity: str,
    confidence: str,
    file_path: str = "",
    line=None,
    evidence: str = "",
    source_rule_id: str = "",
    route: str = "",
    business_impact: str = "",
    remediation: str = "",
) -> dict:
    return {
        "correlation_id": correlation_id,
        "rule_id": correlation_type,
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "file": file_path,
        "line": line,
        "route": route,
        "evidence": evidence,
        "source_rule_id": source_rule_id,
        "business_impact": business_impact,
        "remediation": remediation,
        "correlation_mode": ENGINE_MODE,
        "executive_relevant": severity in {"Critical", "High"},
    }


def enrich_identity_access_correlation(
    findings: list[dict] | None,
    api_bom: list[dict] | None = None,
    abom: list[dict] | None = None,
) -> dict:
    findings = findings or []
    api_bom = api_bom or []
    abom = abom or []

    correlations: list[dict] = []
    seen = set()

    privileged_routes = [r for r in api_bom if _is_privileged_route(r)]
    # Absence of auth metadata is not proof of unauthenticated exposure.
    # Only correlate when the API inventory explicitly says auth is missing/false/public.
    unauth_privileged_routes = [
        r for r in privileged_routes
        if any(k in _route_text(r) for k in (
            "auth=false", "no auth", "unauthenticated", "anonymous",
            "authorization bypass", "missing authorization", "missing auth"
        ))
    ]

     
    def add(corr: dict) -> None:
        text_for_category = " | ".join([
            str(corr.get("evidence") or ""),
            str(corr.get("source_rule_id") or ""),
            str(corr.get("title") or ""),
        ])

        key = (
            corr.get("rule_id"),
            str(corr.get("file") or "").replace("\\", "/").lower(),
            str(corr.get("route") or "").lower(),
            _secret_category(text_for_category),
        )

        if key in seen:
            return

        seen.add(key)
        correlations.append(corr)
    
     

    # 1. Hardcoded privileged identity/token correlation
    for finding in findings:
        text = _finding_text(finding)
        file_path = _file_of(finding)

        source_rule = str(finding.get("rule_id") or "").lower()
        evidence_text = " ".join([
            str(finding.get("snippet") or ""),
            str(finding.get("evidence") or ""),
            str(finding.get("title") or ""),
        ]).lower()
        secret_rule = any(k in source_rule for k in (
            "secret", "credential", "token", "private_key", "api_key",
            "oauth", "password", "jwt", "connection_string"
        ))
        explicit_secret_evidence = bool(_has_any(evidence_text, PRIVILEGED_TOKEN_KEYWORDS)) or bool(
            _has_any(evidence_text, ("hardcoded secret", "hardcoded credential", "private key", "api key", "access token"))
        )
        is_secret = secret_rule or explicit_secret_evidence

        if not is_secret:
            continue

        related_privileged_routes = [
            r for r in privileged_routes
            if _file_of(r) and (_file_of(r) == file_path or _file_of(r) in file_path or file_path in _file_of(r))
        ]

        # A privileged route alone is not evidence that the finding contains
        # privileged identity material. Require explicit identity/credential
        # evidence in the finding itself before creating a Critical correlation.
        privileged_identity_evidence = _has_any(text, (
            "admin password", "admin_password", "adminpassword",
            "root password", "root_password", "service_account",
            "aws_access_key", "aws_secret", "api_key", "private_key",
            "bearer token", "oauth_token", "jwt_secret", "credential",
        )) or secret_rule

        if related_privileged_routes and privileged_identity_evidence:
            for route in related_privileged_routes:
                add(_make_correlation(
                    correlation_id="IACORR_HARDCODED_PRIVILEGED_IDENTITY",
                    correlation_type="HARDCODED_PRIVILEGED_IDENTITY",
                    title="Hardcoded privileged identity material near privileged API surface",
                    severity="Critical",
                    confidence="High",
                    file_path=finding.get("file") or finding.get("file_path") or "",
                    line=_line_of(finding),
                    route=route.get("route") or route.get("path") or route.get("endpoint") or "",
                    source_rule_id=finding.get("rule_id", ""),
                    evidence=finding.get("snippet") or finding.get("evidence") or finding.get("title") or "",
                    business_impact=(
                        "Hardcoded identity material appears connected to privileged functionality. "
                        "This may enable administrative access, lateral movement, or privilege escalation."
                    ),
                    remediation=(
                        "Remove hardcoded credentials, rotate exposed secrets, enforce least privilege, "
                        "and require authenticated authorization on privileged endpoints."
                    ),
                ))
        elif _has_any(text, PRIVILEGED_TOKEN_KEYWORDS):
            add(_make_correlation(
                correlation_id="IACORR_PRIVILEGED_TOKEN_EXPOSURE",
                correlation_type="PRIVILEGED_TOKEN_EXPOSURE",
                title="Privileged token or service identity exposure",
                severity=_max_severity(finding.get("severity", "High"), "High"),
                confidence="Medium",
                file_path=finding.get("file") or finding.get("file_path") or "",
                line=_line_of(finding),
                source_rule_id=finding.get("rule_id", ""),
                evidence=finding.get("snippet") or finding.get("evidence") or finding.get("title") or "",
                business_impact=(
                    "Privileged token material may grant access to source control, cloud APIs, "
                    "service accounts, or administrative automation."
                ),
                remediation="Move secrets to a vault, rotate tokens, and constrain identity privileges.",
            ))

    # 2. RBAC bypass / missing authorization correlation
    for finding in findings:
        text = _finding_text(finding)

        if _has_any(text, RBAC_KEYWORDS) and _has_any(text, MISSING_AUTH_KEYWORDS):
            add(_make_correlation(
                correlation_id="IACORR_RBAC_BYPASS_RISK",
                correlation_type="RBAC_BYPASS_RISK",
                title="Potential RBAC or authorization bypass",
                severity="High",
                confidence="Medium",
                file_path=finding.get("file") or finding.get("file_path") or "",
                line=_line_of(finding),
                source_rule_id=finding.get("rule_id", ""),
                evidence=finding.get("snippet") or finding.get("evidence") or finding.get("title") or "",
                business_impact=(
                    "Authorization logic appears weak or bypassable. Users may access privileged "
                    "actions outside their assigned role."
                ),
                remediation=(
                    "Centralize authorization checks, enforce deny-by-default RBAC, and add tests "
                    "for admin/user privilege boundaries."
                ),
            ))

    # 3. Weak JWT handling
    for finding in findings:
        text = _finding_text(finding)

        if "jwt" in text and _has_any(text, JWT_BYPASS_KEYWORDS):
            add(_make_correlation(
                correlation_id="IACORR_JWT_VALIDATION_BYPASS",
                correlation_type="JWT_VALIDATION_BYPASS",
                title="JWT validation bypass or weak JWT verification",
                severity="Critical",
                confidence="High",
                file_path=finding.get("file") or finding.get("file_path") or "",
                line=_line_of(finding),
                source_rule_id=finding.get("rule_id", ""),
                evidence=finding.get("snippet") or finding.get("evidence") or finding.get("title") or "",
                business_impact=(
                    "Weak JWT validation may allow forged tokens, account takeover, or privilege escalation."
                ),
                remediation=(
                    "Require signature verification, reject 'none' algorithms, enforce issuer/audience/expiry, "
                    "and use a fixed allowlist of signing algorithms."
                ),
            ))

    # 4. Privileged API route exposure
    for route in unauth_privileged_routes:
        add(_make_correlation(
            correlation_id="IACORR_PRIVILEGED_ROUTE_EXPOSURE",
            correlation_type="PRIVILEGED_ROUTE_EXPOSURE",
            title="Privileged API route appears exposed without strong auth evidence",
            severity="High",
            confidence="Medium",
            file_path=route.get("file") or route.get("file_path") or "",
            line=_line_of(route),
            route=route.get("route") or route.get("path") or route.get("endpoint") or "",
            evidence=_route_text(route),
            business_impact=(
                "Privileged endpoint exposure can permit unauthorized administrative actions, "
                "debug access, user impersonation, or account manipulation."
            ),
            remediation=(
                "Require authentication and authorization decorators/middleware on all privileged routes."
            ),
        ))

    # 5. Session fixation risk
    for finding in findings:
        text = _finding_text(finding)

        has_session = _has_any(text, SESSION_FIXATION_KEYWORDS)
        has_regen = "regenerate" in text or "rotate" in text or "new session" in text

        # Session fixation requires actual session-state handling plus evidence
        # that the same/pre-auth identifier can survive authentication. A
        # login route or a test password alone is not sufficient.
        session_state = _has_any(text, (
            "request.session", "req.session", "session[", "session_id",
            "sessionid", "set_cookie", "cookie(", "session.save",
        ))
        fixation_evidence = _has_any(text, (
            "session fixation", "pre-auth session", "session id reused",
            "session identifier reused", "reuse session", "same session",
        ))
        if (
            has_session
            and "login" in text
            and not has_regen
            and session_state
            and fixation_evidence
        ):
            add(_make_correlation(
                correlation_id="IACORR_SESSION_FIXATION_RISK",
                correlation_type="SESSION_FIXATION_RISK",
                title="Potential session fixation risk",
                severity="High",
                confidence="Low",
                file_path=finding.get("file") or finding.get("file_path") or "",
                line=_line_of(finding),
                source_rule_id=finding.get("rule_id", ""),
                evidence=finding.get("snippet") or finding.get("evidence") or finding.get("title") or "",
                business_impact=(
                    "Session identifiers may persist across authentication boundaries, enabling account takeover "
                    "if an attacker can pre-set or reuse a victim session."
                ),
                remediation="Regenerate session identifiers after login and privilege changes.",
            ))

    # 6. Agent/tool identity exposure correlation
    for agent in abom:
        text = _text(agent)

        explicit_elevation = _has_any(text, (
            "admin", "root", "superuser", "privileged", "elevated",
            "service_account", "aws_access_key", "private_key", "api_key",
            "bearer", "oauth_token"
        ))
        no_approval = _has_any(text, ("human_approval_detected': false", '"human_approval_detected": false', "approval_required': false", '"approval_required": false'))
        if explicit_elevation and no_approval:
            add(_make_correlation(
                correlation_id="IACORR_AGENT_IDENTITY_RISK",
                correlation_type="AGENT_IDENTITY_RISK",
                title="Agent or tool identity may operate with elevated privileges",
                severity="High",
                confidence="Low",
                file_path=agent.get("file") or agent.get("file_path") or "",
                line=_line_of(agent),
                evidence=text[:500],
                business_impact=(
                    "Autonomous agent/tool identity may execute privileged operations without clear "
                    "approval or least-privilege boundaries."
                ),
                remediation=(
                    "Constrain agent tool permissions, require approval for privileged actions, "
                    "and isolate credentials per tool scope."
                ),
            ))

    severity_counts = Counter(c.get("severity", "Medium") for c in correlations)
    type_counts = Counter(c.get("rule_id", "UNKNOWN") for c in correlations)

    critical = severity_counts.get("Critical", 0)
    high = severity_counts.get("High", 0)
    medium = severity_counts.get("Medium", 0)

    return {
        "total_identity_access_correlations": len(correlations),
        "critical_identity_access_correlations": critical,
        "high_identity_access_correlations": high,
        "medium_identity_access_correlations": medium,
        "executive_relevant_correlations": sum(
            1 for c in correlations
            if c.get("executive_relevant") is True
        ),
        "by_type": dict(type_counts),
        "privileged_routes_observed": len(privileged_routes),
        "unauthenticated_privileged_routes": len(unauth_privileged_routes),
        "correlation_mode": ENGINE_MODE,
        "summary_status": (
            "IDENTITY_ACCESS_CORRELATION_RISK_IDENTIFIED"
            if correlations
            else "NO_IDENTITY_ACCESS_CORRELATION_RISK_IDENTIFIED"
        ),
        "correlations": correlations,
    }