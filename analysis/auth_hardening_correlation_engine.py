from __future__ import annotations

from collections import Counter


ENGINE_MODE = "STATIC_AUTH_HARDENING_CORRELATION_V1"


def _norm(value) -> str:
    return str(value or "").replace("\\", "/").lower()


def _rule_set(indicators: list[dict]) -> set[str]:
    return {str(i.get("rule_id") or "") for i in indicators}


def _file_of(item: dict) -> str:
    return _norm(item.get("file") or item.get("file_path"))


def _make(
    rule_id: str,
    title: str,
    severity: str,
    confidence: str,
    indicators: list[dict],
    evidence: str,
    remediation: str,
) -> dict:
    files = sorted({_file_of(i) for i in indicators if _file_of(i)})

    return {
        "rule_id": rule_id,
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "correlated_indicator_count": len(indicators),
        "files": files,
        "evidence": evidence,
        "remediation": remediation,
        "executive_relevant": severity in {"Critical", "High"},
        "correlation_mode": ENGINE_MODE,
        "source_indicators": indicators,
    }


def enrich_auth_hardening_correlation(
    auth_hardening_summary: dict | None,
    api_bom: list[dict] | None = None,
) -> dict:
    auth_hardening_summary = auth_hardening_summary or {}
    api_bom = api_bom or []

    indicators = auth_hardening_summary.get("indicators", []) or []
    rules = _rule_set(indicators)

    correlations: list[dict] = []
    seen = set()

    def add(corr: dict) -> None:
        key = (
            corr.get("rule_id"),
            "|".join(corr.get("files", [])),
            corr.get("severity"),
        )
        if key in seen:
            return
        seen.add(key)
        correlations.append(corr)

    def by_rule(rule_id: str) -> list[dict]:
        return [i for i in indicators if i.get("rule_id") == rule_id]

    weak_passwords = by_rule("WEAK_PASSWORD_LITERAL")
    weak_policy = by_rule("WEAK_PASSWORD_POLICY")
    captcha_bypass = by_rule("CAPTCHA_BYPASSABLE_FLOW")
    captcha_unverified = by_rule("CAPTCHA_TOKEN_NOT_VERIFIED")
    no_rate_limit = by_rule("NO_LOGIN_RATE_LIMIT")
    no_lockout = by_rule("NO_ACCOUNT_LOCKOUT")
    weak_reset = by_rule("WEAK_PASSWORD_RESET_TOKEN")
    no_session_rotation = by_rule("SESSION_NOT_ROTATED_AFTER_LOGIN")

    # 1. Credential stuffing / brute force chain
    if weak_passwords and (no_rate_limit or no_lockout):
        add(_make(
            "AUTH_CREDENTIAL_STUFFING_CHAIN",
            "Weak password exposure combined with missing brute-force resistance",
            "Critical",
            "High" if no_rate_limit and no_lockout else "Medium",
            weak_passwords + no_rate_limit + no_lockout,
            "Weak/default password evidence appears alongside missing rate-limit or account-lockout controls.",
            "Remove weak/default passwords, enforce strong password policy, enable login throttling, and configure account lockout.",
        ))

    # 2. Weak password policy + no lockout
    if weak_policy and no_lockout:
        add(_make(
            "AUTH_WEAK_POLICY_LOCKOUT_GAP",
            "Weak password policy combined with missing account lockout",
            "High",
            "Medium",
            weak_policy + no_lockout,
            "Password policy weakness appears with no account-lockout control evidence.",
            "Enforce minimum length, complexity/breach checks, and lock accounts or step-up authentication after repeated failures.",
        ))

    # 3. Automated abuse / CAPTCHA bypass chain
    if (captcha_bypass or captcha_unverified) and (no_rate_limit or no_lockout):
        add(_make(
            "AUTH_AUTOMATION_ABUSE_CHAIN",
            "CAPTCHA weakness combined with missing abuse throttling",
            "High",
            "Medium",
            captcha_bypass + captcha_unverified + no_rate_limit + no_lockout,
            "CAPTCHA weakness appears alongside missing login throttling or lockout control evidence.",
            "Verify CAPTCHA server-side, apply rate limits, add bot detection, and monitor failed login spikes.",
        ))

    # 4. Password reset takeover chain
    if weak_reset and no_session_rotation:
        add(_make(
            "AUTH_PASSWORD_RESET_TAKEOVER_CHAIN",
            "Weak password reset token combined with missing session rotation",
            "High",
            "Medium",
            weak_reset + no_session_rotation,
            "Weak reset-token generation appears with no session rotation evidence.",
            "Use cryptographically secure reset tokens, short expiry, one-time use, and rotate sessions after password reset/login.",
        ))

    # 5. General high-risk auth hardening cluster
    high_value_rules = {
        "WEAK_PASSWORD_LITERAL",
        "CAPTCHA_BYPASSABLE_FLOW",
        "WEAK_PASSWORD_RESET_TOKEN",
        "NO_LOGIN_RATE_LIMIT",
        "NO_ACCOUNT_LOCKOUT",
        "SESSION_NOT_ROTATED_AFTER_LOGIN",
    }

    cluster = [i for i in indicators if i.get("rule_id") in high_value_rules]
    if len({i.get("rule_id") for i in cluster}) >= 3:
        add(_make(
            "AUTH_HARDENING_CLUSTER_RISK",
            "Multiple authentication hardening gaps observed",
            "High",
            "Medium",
            cluster,
            "Three or more authentication hardening weakness classes are present.",
            "Perform auth-flow hardening review across login, reset, CAPTCHA, session lifecycle, and brute-force controls.",
        ))

    severity_counts = Counter(c.get("severity", "Medium") for c in correlations)
    type_counts = Counter(c.get("rule_id", "UNKNOWN") for c in correlations)

    return {
        "total_auth_hardening_correlations": len(correlations),
        "critical_auth_hardening_correlations": severity_counts.get("Critical", 0),
        "high_auth_hardening_correlations": severity_counts.get("High", 0),
        "medium_auth_hardening_correlations": severity_counts.get("Medium", 0),
        "executive_relevant_correlations": sum(
            1 for c in correlations if c.get("executive_relevant") is True
        ),
        "by_type": dict(type_counts),
        "correlation_mode": ENGINE_MODE,
        "summary_status": (
            "AUTH_HARDENING_CORRELATION_RISK_IDENTIFIED"
            if correlations
            else "NO_AUTH_HARDENING_CORRELATION_RISK_IDENTIFIED"
        ),
        "correlations": correlations,
    }