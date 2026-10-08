"""analysis/api_abuse_risk_engine.py
Backward-compatible API abuse risk enrichment.

Fixes:
- Works even when API-BOM is empty by inspecting route-like snippets already present
  in SAST/API findings.
- Adds OTP, reset, coupon, token refresh, invite and payment abuse categories.
"""
from __future__ import annotations
import re
from collections import Counter

ABUSE_RULES = [
    ("LOGIN", "login", ["login", "signin", "auth", "session", "authenticate"]),
    ("OTP", "otp", ["otp", "mfa", "2fa", "verify-otp", "one-time"]),
    ("PASSWORD_RESET", "password_reset", ["reset", "forgot", "password-reset", "reset-password", "forgot-password"]),
    ("INVITE", "invite", ["invite", "invitation", "refer"]),
    ("COUPON", "coupon", ["coupon", "promo", "redeem", "discount", "voucher"]),
    ("TOKEN_REFRESH", "token_refresh", ["refresh", "refresh-token", "token/refresh", "renew"]),
    ("PAYMENT", "payment", ["payment", "checkout", "transfer", "withdraw", "pay"]),
]
SAFE = re.compile(r"rateLimit|throttle|limiter|Bucket4j|RateLimiter|limit_req|slow_down|idempotency|Idempotency-Key|lockout|backoff", re.I)
ROUTE_RE = re.compile(r"(?:app|router)\.(?:get|post|put|patch|delete)\s*\(\s*[\"']([^\"']+)|@(PostMapping|GetMapping|PutMapping|PatchMapping|DeleteMapping)\s*\(\s*[\"']([^\"']+)|\[Http(?:Post|Get|Put|Patch|Delete)\s*\(\s*[\"']([^\"']+)", re.I)

def _priority(sev: str) -> str:
    return {"Critical":"P1","High":"P2","Medium":"P3","Low":"P4"}.get(sev,"P3")

def _normalize_route_path(path: str) -> str:
    """Normalize route identity for deterministic API-abuse grouping."""
    text = str(path or "").strip().replace("\\", "/")
    if not text:
        return ""
    if not text.startswith("/"):
        text = "/" + text
    text = re.sub(r"/{2,}", "/", text)
    if len(text) > 1:
        text = text.rstrip("/")
    return text


def _classify_path(path: str):
    p = _normalize_route_path(path).lower()
    for suffix, abuse_type, tokens in ABUSE_RULES:
        if any(t in p for t in tokens):
            return suffix, abuse_type
    return None, None

def _mk(suffix: str, abuse_type: str, method: str, path: str, file="api_bom", line=0, snippet="") -> dict:
    title_map = {
        "login":"Login Brute Force Missing Rate Limit",
        "otp":"OTP Brute Force Missing Rate Limit",
        "password_reset":"Password Reset Abuse Missing Rate Limit",
        "invite":"Invite Abuse Missing Rate Limit",
        "coupon":"Coupon Replay / Redemption Abuse",
        "token_refresh":"Token Refresh Abuse Missing Rate Limit",
        "payment":"Payment Duplicate Action / Missing Idempotency",
    }
    return {
        "rule_id": f"API_ABUSE_{suffix}",
        "title": title_map.get(abuse_type, f"Missing Rate Limit on Abuse-Prone Endpoint - {abuse_type}"),
        "vuln_type": "api_rate_limit",
        "finding_class": "control_gap",
        "severity": "High",
        "priority": "P2",
        "confidence": "Medium",
        "language": "api",
        "file": file or "api_bom",
        "line": line or 0,
        "snippet": snippet or f"{method} {path}".strip(),
        "description": "Abuse-prone endpoint lacks clear rate-limit, replay, lockout, or idempotency controls.",
        "business_impact": "Attackers can automate brute-force, replay, duplicate transaction, coupon, OTP, or reset workflows leading to account takeover, fraud, and service abuse.",
        "remediation": [
            "Add per-user/IP/tenant rate limits.",
            "Add lockout/backoff for login, OTP and reset workflows.",
            "Use idempotency keys for payment and state-changing actions.",
            "Monitor and alert on abuse patterns.",
        ],
        "owasp": "API4:2023 - Unrestricted Resource Consumption",
        "cwe": "CWE-770",
        "pci_dss": "Req 6.2.4 / Req 8 - Abuse prevention and authentication controls",
        "nist": "AC-7 / SC-5 / SI-10",
        "nist_800_53": "AC-7 / SC-5 / SI-10",
        "iso27001": "A.8.16 / A.8.20",
        "iso_27001": "A.8.16 / A.8.20",
        "soc2": "CC7.2 / CC6.6",
        "evidence": f"{method} {path}".strip(),
        "detection": "API Abuse Heuristic",
        "engine": "analysis.api_abuse_risk_engine",
        "api_abuse_type": abuse_type,
        "group_key": f"API_ABUSE_{suffix}|{method}|{_normalize_route_path(path)}",
        "evidence_type": "route_definition_without_detected_control",
        "requires_manual_verification": True,
        "control_gap_basis": (
            "A server-side API route matched an abuse-prone category and no "
            "matching rate-limit, lockout, replay-protection, throttle, or "
            "idempotency control was detected in the inspected route context. "
            "Static analysis does not establish exploitability or runtime absence "
            "of controls outside the inspected evidence."
        ),
        "enterprise_control": True,
    }

def _is_client_side_api_reference(finding: dict) -> bool:
    """
    Return True when a finding represents a client-side API reference rather
    than a server-side endpoint definition.

    API rate-limit/abuse controls must be evaluated at the server endpoint.
    Client-side Axios interceptors, React components, and browser-side API
    calls do not prove that a backend endpoint lacks rate limiting.
    """
    path = str(
        finding.get("file")
        or finding.get("full_path")
        or finding.get("file_path")
        or ""
    ).replace("\\", "/").lower()

    return (
        path.endswith((".jsx", ".tsx", ".vue"))
        or "/frontend/" in path
        or "/src/api/" in path
        or path.endswith(("/axios.js", "/axios.ts"))
    )


def enrich_api_abuse_risk(findings: list[dict] | None = None, api_bom=None) -> dict:
    indicators = []
    # ------------------------------------------------------------
    # Canonical API-abuse identity / duplicate suppression
    # ------------------------------------------------------------
    # Multiple evidence sources can describe the same semantic route issue.
    # A method-less representation must not become a second vulnerability
    # when an explicit HTTP-method representation exists for the same
    # rule + route.
    def _api_abuse_identity(item):
        rule = str(item.get("rule_id") or item.get("rule") or "").strip().upper()

        path = str(
            item.get("path")
            or item.get("route")
            or item.get("endpoint")
            or ""
        ).strip().replace("\\", "/")

        if not path:
            group = str(item.get("group_key") or "")
            if "|" in group:
                path = group.rsplit("|", 1)[-1].strip()

        if path and not path.startswith("/"):
            path = "/" + path
        path = re.sub(r"/{2,}", "/", path)
        if len(path) > 1:
            path = path.rstrip("/")

        method = str(
            item.get("method")
            or item.get("http_method")
            or ""
        ).strip().upper()

        if not method:
            group = str(item.get("group_key") or "")
            parts = group.split("|")
            if len(parts) >= 3:
                method = parts[-2].strip().upper()

        return (rule, method, path)

    def _dedupe_api_abuse_indicators(items):
        selected = {}
        for item in items or []:
            key = _api_abuse_identity(item)
            if key not in selected:
                selected[key] = item

        # Prefer explicit HTTP-method evidence over a method-less duplicate.
        explicit = set()
        for item in selected.values():
            rule, method, path = _api_abuse_identity(item)
            if method:
                explicit.add((rule, path))

        final = []
        emitted = set()
        for item in selected.values():
            rule, method, path = _api_abuse_identity(item)

            if not method and (rule, path) in explicit:
                continue

            key = (rule, method, path)
            if key in emitted:
                continue

            emitted.add(key)
            final.append(item)

        return final
    seen = set()
    api_bom = api_bom or []
    findings = findings or []

    # Primary source: API-BOM routes
    for route in api_bom:
        path = str(route.get("path") or route.get("route") or route.get("endpoint") or "")
        method = str(route.get("method") or "").upper()
        suffix, abuse_type = _classify_path(path)
        if not abuse_type:
            continue
        if SAFE.search(" ".join(str(route.get(k, "")) for k in route.keys())):
            continue
        item = _mk(suffix, abuse_type, method, path, route.get("file", "api_bom"), route.get("line", 0), f"{method} {path}".strip())
        if item["group_key"] not in seen:
            seen.add(item["group_key"]); indicators.append(item)

    # Fallback: route-like snippets already emitted by scanners/framework engines.
    #
    # IMPORTANT: only server-side route context can establish a missing
    # rate-limit/API-abuse control. Client-side Axios interceptors, React
    # components, and browser-side API references are not endpoint definitions.
    for f in findings:
        if _is_client_side_api_reference(f):
            continue

        text = " ".join(str(f.get(k, "")) for k in ("snippet", "title", "description", "file"))
        if SAFE.search(text):
            continue
        candidates = []
        for m in ROUTE_RE.finditer(text):
            route = next((g for g in m.groups() if g), "")
            if route:
                candidates.append(route)
        # Also catch plain endpoint snippets like POST /otp/verify
        candidates += re.findall(r"\b(?:GET|POST|PUT|PATCH|DELETE)\s+(/[^\s'\"]+)", text, flags=re.I)
        for path in candidates:
            suffix, abuse_type = _classify_path(path)
            if not abuse_type:
                continue
            item = _mk(suffix, abuse_type, "", path, f.get("file", "api_findings"), f.get("line", 0), f.get("snippet", path))
            if item["group_key"] not in seen:
                seen.add(item["group_key"]); indicators.append(item)

    # ------------------------------------------------------------
    # FINAL CANONICAL API-ABUSE IDENTITY
    # ------------------------------------------------------------
    # Canonicalize only after API-BOM and fallback producers have
    # populated the complete indicator collection.
    indicators = _dedupe_api_abuse_indicators(indicators)
    high = sum(1 for i in indicators if i.get("severity") == "High")
    return {
        "total_api_abuse_indicators": len(indicators),
        "total_unique_api_abuse_indicators": len({i.get("group_key") for i in indicators}),
        "critical_api_abuse_indicators": 0,
        "high_api_abuse_indicators": high,
        "executive_relevant_indicators": high,
        "by_context": {"api_route_context": len(indicators)},
        "by_type": dict(Counter(i.get("api_abuse_type", "unknown") for i in indicators)),
        "indicators": indicators,
        "summary_status": "API_ABUSE_RISK_IDENTIFIED" if indicators else "NO_API_ABUSE_RISK_IDENTIFIED",
    }
