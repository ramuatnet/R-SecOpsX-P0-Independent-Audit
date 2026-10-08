import logging
import re
import time
from collections import defaultdict
from typing import Any, Dict, List

_LOGGER = logging.getLogger(__name__)


CONTROL_PATTERNS = [
    ("AUTHENTICATION_CONTROL", r"\blogin_required\b|\bauthentication_required\b|\bauthenticate\s*\(|\bverify_token\b|\bjwt\.decode\b", "AUTHENTICATION", "OWASP_ASVS_V2"),
    ("MFA_CONTROL", r"\bmfa\b|\btotp\b|\bMultiFactorAuth\b|\btwo_factor\b", "AUTHENTICATION", "OWASP_ASVS_V2"),
    ("AUTHORIZATION_CONTROL", r"\bauthorize\s*\(|\bpermission_required\b|\brole_required\b|\bhas_permission\b|\bcheck_permission\b", "AUTHORIZATION", "OWASP_ASVS_V4"),
    ("RBAC_CONTROL", r"\brbac\b|\bRoleBinding\b|\bClusterRole\b|\bpolicy_document\b", "AUTHORIZATION", "OWASP_ASVS_V4"),
    ("OWNERSHIP_CHECK", r"\bowner_id\b|\bbelongs_to_user\b|\bcheck_owner\b|\bownership_check\b", "AUTHORIZATION", "OWASP_API1_BOLA"),
    ("INPUT_VALIDATION_CONTROL", r"\bvalidate_[a-zA-Z0-9_]+\b|\bschema\.validate\b|\bpydantic\b|\bmarshmallow\b|\bjoi\.validate\b", "INPUT_VALIDATION", "OWASP_ASVS_V5"),
    ("SANITIZATION_CONTROL", r"\bsanitize\b|\bhtmlspecialchars\b|\bbleach\.clean\b", "INPUT_VALIDATION", "OWASP_ASVS_V5"),
    ("OUTPUT_ENCODING_CONTROL", r"\bhtml\.escape\b|\bmarkupsafe\b|\bencodeURIComponent\b", "OUTPUT_PROTECTION", "OWASP_ASVS_V5"),
    ("RESPONSE_FILTERING_CONTROL", r"\bresponse_model\b|\bserializer\b|\bexclude\s*=\b|\bfields\s*=\s*\[", "OUTPUT_PROTECTION", "OWASP_API3"),
    ("RATE_LIMIT_CONTROL", r"\brate_limit\b|\bLimiter\b|\bthrottle\b|\bslow_down\b|\bmax_requests\b", "ABUSE_PREVENTION", "OWASP_API4"),
    ("IDEMPOTENCY_CONTROL", r"\bidempotency_key\b|\bIdempotency-Key\b", "ABUSE_PREVENTION", "OWASP_API6"),
    ("REPLAY_PROTECTION_CONTROL", r"\breplay_protection\b|\btimestamp_validation\b|\bnonce_required\s*=\s*True\b", "ABUSE_PREVENTION", "OWASP_API6"),
    ("CSRF_CONTROL", r"\bcsrf\b|\bCSRFProtect\b|\bcsrf_token\b", "WEB_SECURITY", "OWASP_ASVS_V4"),
    ("CORS_RESTRICTION_CONTROL", r"\ballowed_origins\b|\bCORS\(.*origins\s*=\s*\[|\bAccess-Control-Allow-Origin\b.*https?://", "WEB_SECURITY", "OWASP_API8"),
    ("SECURITY_HEADERS_CONTROL", r"\bContent-Security-Policy\b|\bX-Frame-Options\b|\bStrict-Transport-Security\b|\bX-Content-Type-Options\b", "WEB_SECURITY", "OWASP_ASVS_V14"),
    ("ENCRYPTION_CONTROL", r"\bencrypt\b|\bAES\b|\bChaCha20\b|\bFernet\b|\bTLS\b|\bssl_context\b", "CRYPTO", "OWASP_ASVS_V6"),
    ("PASSWORD_HASHING_CONTROL", r"\bbcrypt\b|\bargon2\b|\bpbkdf2\b|\bscrypt\b|\bhash_password\b", "CRYPTO", "OWASP_ASVS_V6"),
    ("CERT_VALIDATION_CONTROL", r"\bverify\s*=\s*True\b|\bcheck_hostname\s*=\s*True\b", "CRYPTO", "OWASP_ASVS_V6"),
    ("SECRETS_MANAGER_CONTROL", r"\bSecretsManager\b|\bsecretmanager\b|\bKeyVault\b|\bVault\b|\bget_secret_value\b", "SECRETS", "OWASP_ASVS_V6"),
    ("ENV_SECRET_CONTROL", r"\bos\.environ\b|\bgetenv\s*\(", "SECRETS", "OWASP_ASVS_V6"),
    ("AUDIT_LOGGING_CONTROL", r"\baudit_log\b|\bsecurity_event\b|\bSIEM\b|\blogger\.(info|warning|error|critical)\b", "MONITORING", "OWASP_ASVS_V7"),
    ("ERROR_HANDLING_CONTROL", r"\berror_handler\b|\bhandle_exception\b|\bexcept\s+[A-Za-z0-9_]+Error\b|\bcatch\s*\([^)]*Error", "RESILIENCE", "OWASP_ASVS_V7"),
	("CAPTCHA_CONTROL", r"\brecaptcha\b|\bhcaptcha\b|\bturnstile\b|\bcaptcha\b|\bverify_captcha\b", "ABUSE_PREVENTION", "OWASP_ASVS_V2"),

	("ACCOUNT_LOCKOUT_CONTROL", r"\baccount_lockout\b|\block_after\b|\bfailed_login_attempts\b|\bmax_login_attempts\b", "ABUSE_PREVENTION", "OWASP_ASVS_V2"),

	("BREACHED_PASSWORD_CHECK", r"\bhaveibeenpwned\b|\bpwned_password\b|\bbreached_password\b|\bpassword_blacklist\b", "AUTHENTICATION", "OWASP_ASVS_V2"),

	("SESSION_TIMEOUT_CONTROL", r"\bsession_timeout\b|\bexpires_in\b|\bmax_age\b|\bidle_timeout\b", "AUTHENTICATION", "OWASP_ASVS_V3"),

	("SECURE_COOKIE_CONTROL", r"\bsecure\s*=\s*True\b|\bhttponly\s*=\s*True\b|\bSameSite\b", "WEB_SECURITY", "OWASP_ASVS_V3"),

	("WEBHOOK_SIGNATURE_VALIDATION", r"\bverify_signature\b|\bX-Hub-Signature\b|\bstripe-signature\b|\bwebhook_secret\b", "API_SECURITY", "OWASP_API10"),

	("TENANT_ISOLATION_CONTROL", r"\btenant_id\b|\borg_id\b|\bworkspace_id\b|\brow_level_security\b", "AUTHORIZATION", "OWASP_API1"),

	("SECURE_FILE_UPLOAD_CONTROL", r"\ballowed_extensions\b|\bmax_file_size\b|\bvirus_scan\b|\bcontent_type_validation\b", "INPUT_VALIDATION", "OWASP_ASVS_V12"),

	("RISK_BASED_AUTH_CONTROL", r"\brisk_score\b|\bdevice_trust\b|\bnew_device\b|\bimpossible_travel\b", "AUTHENTICATION", "OWASP_ASVS_V2"),

	("STEP_UP_AUTH_CONTROL", r"\bstep_up\b|\bre_authenticate\b|\brequire_mfa\b", "AUTHENTICATION", "OWASP_ASVS_V2"),
]


REQUIRED_CONTROL_DOMAINS = [
    "AUTHENTICATION",
    "AUTHORIZATION",
    "INPUT_VALIDATION",
    "OUTPUT_PROTECTION",
    "ABUSE_PREVENTION",
    "WEB_SECURITY",
    "CRYPTO",
    "SECRETS",
    "MONITORING",
    "RESILIENCE",
]


DOMAIN_RECOMMENDATIONS = {
    "AUTHENTICATION": "Review whether authentication enforcement is consistently applied to protected routes and services.",
    "AUTHORIZATION": "Review object-level, role-level, and permission-level authorization controls.",
    "INPUT_VALIDATION": "Review schema validation, input normalization, and sanitization coverage.",
    "OUTPUT_PROTECTION": "Review response filtering and output encoding for sensitive or user-controlled data.",
    "ABUSE_PREVENTION": "Review rate limits, replay protection, and idempotency controls for abuse-prone flows.",
    "WEB_SECURITY": "Review CSRF protection, CORS restrictions, and browser security headers.",
    "CRYPTO": "Review encryption, password hashing, TLS, and certificate-validation controls.",
    "SECRETS": "Review use of secrets managers, environment isolation, and runtime secret handling.",
    "MONITORING": "Review audit logging, security event logging, and SIEM integration.",
    "RESILIENCE": "Review structured error handling and safe exception disclosure.",
}


def _collect_text(
    obj: Any,
    *,
    max_chars: int = 200_000,
    _seen: set[int] | None = None,
) -> str:
    """
    Convert structured evidence to searchable text without allowing a
    pathological/repeated nested object to create multi-megabyte regex input.

    The limit is applied only to the text representation used by this
    coverage engine. It does not delete, mutate, or suppress source findings.
    """
    if obj is None or max_chars <= 0:
        return ""

    if _seen is None:
        _seen = set()

    # Guard against recursive/self-referential structures.
    if isinstance(obj, (dict, list, tuple, set)):
        oid = id(obj)
        if oid in _seen:
            return ""
        _seen.add(oid)

    if isinstance(obj, str):
        return obj[:max_chars]

    if isinstance(obj, dict):
        parts = []
        remaining = max_chars
        for key, value in obj.items():
            if value is None or remaining <= 0:
                break
            piece = _collect_text(
                f"{key}: {_collect_text(value, max_chars=remaining, _seen=_seen)}",
                max_chars=remaining,
                _seen=_seen,
            )
            if piece:
                parts.append(piece)
                remaining -= len(piece) + 1
        return " ".join(parts)[:max_chars]

    if isinstance(obj, (list, tuple, set)):
        parts = []
        remaining = max_chars
        for item in obj:
            if remaining <= 0:
                break
            piece = _collect_text(item, max_chars=remaining, _seen=_seen)
            if piece:
                parts.append(piece)
                remaining -= len(piece) + 1
        return " ".join(parts)[:max_chars]

    return str(obj)[:max_chars]


def _function_name(item: Dict[str, Any]) -> str:
    return str(
        item.get("function_name")
        or item.get("function")
        or item.get("method")
        or item.get("method_name")
        or ""
    ).strip()


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


def _coverage_grade(ratio: float) -> str:
    if ratio >= 0.85:
        return "STRONG"
    if ratio >= 0.60:
        return "MODERATE"
    if ratio > 0:
        return "LIMITED"
    return "NOT_OBSERVED"


def _defense_status(ratio: float, missing_count: int) -> str:
    if ratio >= 0.85 and missing_count == 0:
        return "DEFENSE_IN_DEPTH_CONTROLS_OBSERVED"
    if ratio >= 0.60:
        return "PARTIAL_DEFENSE_IN_DEPTH_CONTROLS_OBSERVED"
    return "CONTROL_COVERAGE_GAPS_IDENTIFIED"


def _risk_for_domain(domain: str) -> str:
    if domain in {"AUTHENTICATION", "AUTHORIZATION", "SECRETS", "CRYPTO"}:
        return "HIGH"
    if domain in {"ABUSE_PREVENTION", "WEB_SECURITY", "INPUT_VALIDATION", "OUTPUT_PROTECTION"}:
        return "MEDIUM"
    return "LOW"


def _detect_controls(
    context_id: str,
    context_type: str,
    text: str,
    evidence: Dict[str, Any],
    allowed_domains: set[str] | None = None,
) -> List[Dict[str, Any]]:
    controls = []

    scan_text = text or ""

    for control, pattern, domain, framework in CONTROL_PATTERNS:
        if allowed_domains is not None and domain not in allowed_domains:
            continue

        match = re.search(
            pattern,
            scan_text,
            flags=re.IGNORECASE | re.DOTALL,
        )
        if not match:
            continue

        controls.append({
            "context_id": context_id,
            "context_type": context_type,
            "control": control,
            "domain": domain,
            "status": "OBSERVED",
            "risk_level": "INFO",
            "coverage_observed": True,
            "confidence": "Medium",
            "evidence_match": match.group(0)[:160],
            "evidence": evidence or {},
            "mapped_frameworks": [framework],
            "recommended_action": "Validate whether this control is consistently enforced across applicable routes, functions, and deployment paths.",
        })

    return controls


def _missing_control_findings(domains_observed: List[str]) -> List[Dict[str, Any]]:
    missing = []

    for domain in REQUIRED_CONTROL_DOMAINS:
        if domain in domains_observed:
            continue

        risk = _risk_for_domain(domain)

        missing.append({
            "context_id": domain,
            "context_type": "DOMAIN_COVERAGE",
            "control": f"{domain}_CONTROL_NOT_OBSERVED",
            "domain": domain,
            "status": "NOT_OBSERVED",
            "risk_level": risk,
            "coverage_observed": False,
            "confidence": "Low",
            "evidence_match": None,
            "evidence": {
                "note": "Control was not observed in available static evidence. This is not proof the control is absent.",
            },
            "mapped_frameworks": [],
            "recommended_action": DOMAIN_RECOMMENDATIONS.get(domain, "Review control coverage."),
        })

    return missing


def _dedupe(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    deduped = {}

    for item in items:
        key = (
            item.get("context_type"),
            item.get("context_id"),
            item.get("control"),
            item.get("domain"),
        )

        if key not in deduped:
            deduped[key] = item

    return list(deduped.values())


def enrich_security_control_coverage(
    findings: List[Dict[str, Any]],
    api_bom: List[Dict[str, Any]] = None,
    cbom: List[Dict[str, Any]] = None,
    abom: List[Dict[str, Any]] = None,
    console_writer=None,
) -> Dict[str, Any]:

    findings = findings or []
    api_bom = api_bom or []
    cbom = cbom or []
    abom = abom or []
    write_console = console_writer or _LOGGER.info

    control_findings = []
    file_groups = defaultdict(list)

    if cbom:
        sample_lengths = []
        sample_count = min(len(cbom), 25)
        for sample in cbom[:sample_count]:
            sample_lengths.append(len(_collect_text(sample, max_chars=200_000)))
        write_console(
            f"[SC-ENGINE] CBOM count={len(cbom)} "
            f"sample_text_len_min={min(sample_lengths) if sample_lengths else 0} "
            f"sample_text_len_max={max(sample_lengths) if sample_lengths else 0}"
        )
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

        control_findings.extend(_detect_controls(
            context_id=context_id,
            context_type="FINDING",
            text=_finding_text(finding),
            evidence={
                "file": file_key,
                "line": finding.get("line"),
                "rule_id": finding.get("rule_id"),
                "title": finding.get("title"),
                "function": fn or None,
            },
        ))

        if file_key:
            file_groups[str(file_key)].append(finding)
        if file_key and fn:
            function_groups[(str(file_key), fn)].append(finding)

    for file_key, grouped in file_groups.items():
        control_findings.extend(_detect_controls(
            context_id=file_key,
            context_type="FILE_CONTEXT",
            text=" ".join(_finding_text(x) for x in grouped),
            evidence={
                "file": file_key,
                "finding_count": len(grouped),
            },
        ))

    for (file_key, fn), grouped in function_groups.items():
        control_findings.extend(_detect_controls(
            context_id=f"{file_key}::{fn}",
            context_type="FUNCTION_CONTEXT",
            text=" ".join(_finding_text(x) for x in grouped),
            evidence={
                "file": file_key,
                "function": fn,
                "finding_count": len(grouped),
            },
        ))

    for route in api_bom:
        route_id = str(route.get("route") or route.get("path") or route.get("endpoint") or "api_route")
        method = route.get("method")

        control_findings.extend(_detect_controls(
            context_id=f"{method or ''} {route_id}".strip(),
            context_type="API_ROUTE",
            text=_collect_text(route),
            evidence={
                "route": route.get("route") or route.get("path") or route.get("endpoint"),
                "method": method,
            },
        ))

    for index, component in enumerate(cbom):
        cid = str(
            component.get("algorithm")
            or component.get("primitive")
            or component.get("name")
            or f"cbom_component_{index}"
        )

        cbom_text = _collect_text(component, max_chars=200_000)

        control_findings.extend(_detect_controls(
            context_id=cid,
            context_type="CBOM_COMPONENT",
            text=cbom_text,
            evidence={
                "algorithm": component.get("algorithm") or component.get("primitive"),
                "file": component.get("file"),
                "line": component.get("line"),
            },
            # CBOM evidence is cryptographic by definition; evaluate only the
            # CRYPTO control domain here. Other contexts retain full coverage.
            allowed_domains={"CRYPTO"},
        ))

    for agent in abom:
        aid = str(agent.get("name") or agent.get("agent") or "ai_agent")

        control_findings.extend(_detect_controls(
            context_id=aid,
            context_type="AI_AGENT",
            text=_collect_text(agent),
            evidence={
                "agent": agent.get("name") or agent.get("agent"),
                "type": agent.get("type"),
            },
        ))

    control_findings = _dedupe(control_findings)

    domains_observed = sorted({
        c.get("domain")
        for c in control_findings
        if c.get("status") == "OBSERVED" and c.get("domain")
    })

    missing_findings = _missing_control_findings(domains_observed)
    all_control_findings = control_findings + missing_findings

    observed_count = len([c for c in all_control_findings if c.get("status") == "OBSERVED"])
    not_observed_count = len([c for c in all_control_findings if c.get("status") == "NOT_OBSERVED"])

    coverage_ratio = round(
        len(domains_observed) / max(len(REQUIRED_CONTROL_DOMAINS), 1),
        2
    )

    by_domain = {}
    for domain in REQUIRED_CONTROL_DOMAINS:
        domain_items = [c for c in all_control_findings if c.get("domain") == domain]
        observed = [c for c in domain_items if c.get("status") == "OBSERVED"]
        not_observed = [c for c in domain_items if c.get("status") == "NOT_OBSERVED"]

        by_domain[domain] = {
            "status": "OBSERVED" if observed else "NOT_OBSERVED",
            "observed_controls": len(observed),
            "not_observed_controls": len(not_observed),
            "risk_level": "INFO" if observed else _risk_for_domain(domain),
        }

    by_context = {
        "finding_context": sum(1 for c in all_control_findings if c.get("context_type") == "FINDING"),
        "file_context": sum(1 for c in all_control_findings if c.get("context_type") == "FILE_CONTEXT"),
        "function_context": sum(1 for c in all_control_findings if c.get("context_type") == "FUNCTION_CONTEXT"),
        "api_route_context": sum(1 for c in all_control_findings if c.get("context_type") == "API_ROUTE"),
        "cbom_component_context": sum(1 for c in all_control_findings if c.get("context_type") == "CBOM_COMPONENT"),
        "ai_agent_context": sum(1 for c in all_control_findings if c.get("context_type") == "AI_AGENT"),
        "domain_coverage_context": sum(1 for c in all_control_findings if c.get("context_type") == "DOMAIN_COVERAGE"),
    }

    executive_relevant_gaps = sum(
        1 for c in all_control_findings
        if c.get("status") == "NOT_OBSERVED" and c.get("risk_level") in {"HIGH", "MEDIUM"}
    )

    write_console(
        f"[SC-ENGINE] END control_findings={len(all_control_findings)} "
        f"domains_observed={len(domains_observed)}"
    )

    return {
        # Rule-level control metrics and domain-level coverage are distinct.
        "total_controls_evaluated": len(CONTROL_PATTERNS),
        "controls_observed": len({
            c.get("control")
            for c in all_control_findings
            if c.get("status") == "OBSERVED" and c.get("control")
        }),
        "controls_not_observed": max(
            len(CONTROL_PATTERNS) - len({
                c.get("control")
                for c in all_control_findings
                if c.get("status") == "OBSERVED" and c.get("control")
            }),
            0,
        ),
        "control_coverage_ratio": round(
            len({
                c.get("control")
                for c in all_control_findings
                if c.get("status") == "OBSERVED" and c.get("control")
            }) / max(len(CONTROL_PATTERNS), 1),
            2,
        ),
        "static_evidence_control_coverage_ratio": round(
            len({
                c.get("control")
                for c in all_control_findings
                if c.get("status") == "OBSERVED" and c.get("control")
            }) / max(len(CONTROL_PATTERNS), 1),
            2,
        ),
        "domains_evaluated": len(REQUIRED_CONTROL_DOMAINS),
        "domains_observed_count": len(domains_observed),
        "domains_not_observed_count": len(REQUIRED_CONTROL_DOMAINS) - len(domains_observed),
        # coverage_ratio remains the established DOMAIN coverage ratio so the
        # existing grade/status decision model does not change.
        "coverage_ratio": coverage_ratio,
        "domain_coverage_ratio": coverage_ratio,
        "coverage_ratio_semantics": "STATIC_EVIDENCE_ONLY_NOT_CONTROL_EFFECTIVENESS",
        "control_coverage_semantics": "UNIQUE_OBSERVED_CONTROL_RULES_DIVIDED_BY_DEFINED_CONTROL_RULES",
        "domain_coverage_semantics": "OBSERVED_DOMAINS_DIVIDED_BY_REQUIRED_DOMAINS",
        "coverage_grade": _coverage_grade(coverage_ratio),
        "defense_in_depth_status": _defense_status(coverage_ratio, len(REQUIRED_CONTROL_DOMAINS) - len(domains_observed)),
        "executive_relevant_gaps": executive_relevant_gaps,
        "domains_observed": domains_observed,
        "domains_not_observed": [d for d in REQUIRED_CONTROL_DOMAINS if d not in domains_observed],
        "by_domain": by_domain,
        "by_context": by_context,
        "control_findings": all_control_findings,
        "engine_mode": "STATIC_SECURITY_CONTROL_COVERAGE_V2_SEMANTICALLY_ALIGNED",
    }