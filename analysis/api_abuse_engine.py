"""analysis/api_abuse_engine.py
Enterprise API abuse indicator engine. Backward-compatible aliases included.

Purpose:
- Detect abuse-prone API routes that appear without nearby rate-limit,
  replay, lockout, or idempotency controls.
- Offline static analysis only.
- Backward-compatible public APIs:
  scan_file(filepath) -> list[dict]
  analyze_api_abuse(target_path) -> dict
  analyze_api_abuse_risk(target_path) -> dict
  scan_api_abuse(target_path) -> dict
  summarize_api_abuse(findings) -> dict
"""
from __future__ import annotations
try:
    from analysis.spans import WINDOW_1, WINDOW_800
except ImportError:  # FND-03: standalone, repo root not on path
    import sys as _fnd03_sys
    from pathlib import Path as _fnd03_path
    _fnd03_sys.path.insert(0, str(_fnd03_path(__file__).resolve().parents[1]))
    from analysis.spans import WINDOW_1, WINDOW_800

import re
from pathlib import Path
from collections import Counter


RULES = [
    (
        "API_LOGIN_BRUTE_FORCE",
        "Login Brute Force Rate Limit Missing",
        "login",
        r"/(?:login|signin|sign-in|auth|session|authenticate)",
    ),
    (
        "API_OTP_BRUTE_FORCE",
        "OTP Brute Force Rate Limit Missing",
        "otp",
        r"/(?:otp|verify-otp|mfa|2fa|verify|one-time|one_time)",
    ),
    (
        "API_PASSWORD_RESET_ABUSE",
        "Password Reset Abuse Rate Limit Missing",
        "password_reset",
        r"/(?:password-reset|reset-password|forgot-password|forgot_password|reset|forgot)",
    ),
    (
        "API_INVITE_ABUSE",
        "Invite Abuse Rate Limit Missing",
        "invite",
        r"/(?:invite|invitation|refer|referral)",
    ),
    (
        "API_COUPON_REPLAY",
        "Coupon Replay / Redemption Abuse",
        "coupon",
        r"/(?:coupon|promo|redeem|redemption|discount|voucher)",
    ),
    (
        "API_TOKEN_REFRESH_ABUSE",
        "Token Refresh Abuse",
        "token_refresh",
        r"/(?:refresh|token/refresh|refresh-token|refresh_token|renew|token)",
    ),
    (
        "API_PAYMENT_DUPLICATE_ACTION",
        "Payment Duplicate Action / Missing Idempotency",
        "payment",
        r"/(?:pay|payment|checkout|transfer|withdraw|deposit)",
    ),
]

SAFE = re.compile(
    r"rateLimit|rate_limit|throttle|limiter|Bucket4j|RateLimiter|limit_req|"
    r"slow_down|slowDown|idempotency|Idempotency-Key|OncePer|lockout|"
    r"backoff|captcha|recaptcha|antiReplay|anti_replay|replay_protection",
    re.I,
)

# Supports:
# - Express / Node: app.post("/login"), router.post("/otp")
# - Spring: @PostMapping("/reset-password")
# - ASP.NET: [HttpPost("/payment")]  # sast-ignore API_PAYMENT_DUPLICATE_ACTION documentation example, not a live route
# - Go: http.HandleFunc("/login", handler)
# - PHP Slim/Lumen: $app->post("/login")
# - Laravel: Route::post("/login")
# - Flask/FastAPI: @app.post("/login"), @router.post("/login"), @app.route("/login")
ROUTE = re.compile(
    r'''(?:path|re_path|url)\s*\(\s*["']([^"']+)'''
    r"|(?:app|router)\.(?:get|post|put|patch|delete)\s*\(\s*[\"']([^\"']+)"
    r"|@(PostMapping|GetMapping|PutMapping|PatchMapping|DeleteMapping)\s*\(\s*[\"']([^\"']+)"
    r"|\[Http(?:Post|Get|Put|Patch|Delete)\s*\(\s*[\"']([^\"']+)"
    r"|http\.HandleFunc\s*\(\s*[\"']([^\"']+)"
    r"|\$app->(?:get|post|put|patch|delete)\s*\(\s*[\"']([^\"']+)"
    r"|Route::(?:get|post|put|patch|delete)\s*\(\s*[\"']([^\"']+)"
    r"|@app\.(?:route|get|post|patch|put|delete)\s*\(\s*[\"']([^\"']+)"
    r"|@router\.(?:route|get|post|patch|put|delete)\s*\(\s*[\"']([^\"']+)",
    re.I,
)

SCANNABLE_EXTENSIONS = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".java",
    ".cs",
    ".go",
    ".php",
    ".rb",
    ".kt",
    ".scala",
    ".yml",
    ".yaml",
    ".json",
}

SKIP_DIRS = {
    ".git",
    ".svn",
    "node_modules",
    "__pycache__",
    ".tox",
    "venv",
    ".venv",
    "dist",
    "build",
    "vendor",
    "third_party",
}


def _remediation_for_abuse_type(abuse_type: str) -> list[str]:
    if abuse_type == "login":
        return [
            "Apply server-side rate limits per account and source IP; scope limits by tenant where applicable.",
            "Use progressive backoff or bounded temporary blocking after repeated failures and return HTTP 429 when throttled.",
            "Do not reveal whether an account exists in authentication error responses.",
            "Add tests for burst, distributed, and repeated login attempts plus recovery behavior.",
        ]
    if abuse_type == "coupon":
        return [
            "Enforce one-time redemption server-side with an atomic transaction or unique redemption constraint.",
            "Bind redemption to the authenticated account/order/tenant and validate eligibility on the server.",
            "Use an idempotency or unique redemption key for retries and reject reuse with conflicting request data.",
            "Add tests for replay, concurrency, cross-account use, and repeated redemption attempts.",
        ]
    if abuse_type == "payment":
        return [
            "Require an idempotency key for retryable payment or checkout requests.",
            "Enforce idempotency atomically inside the server-side transaction so concurrent retries cannot create duplicate charges.",
            "Bind the idempotency record to the authenticated account and operation parameters; reject key reuse with a different payload.",
            "Add tests for retries, concurrent submissions, timeout replay, and mismatched idempotency keys.",
        ]
    if abuse_type == "otp":
        return [
            "Limit OTP verification attempts per account/session and source IP with progressive backoff.",
            "Expire OTPs quickly, invalidate challenge state after completion, and enforce a maximum attempt count.",
            "Return HTTP 429 when throttled and monitor repeated verification failures.",
            "Add tests for guessing, replay, expiry, distributed attempts, and lockout behavior.",
        ]
    if abuse_type == "password_reset":
        return [
            "Rate-limit password-reset requests per account and source IP without exposing account existence.",
            "Use short-lived, single-use reset tokens and invalidate them after successful password change.",
            "Add abuse monitoring for reset floods and token-spray patterns.",
            "Test repeated requests, token replay, expiry, and enumeration resistance.",
        ]
    if abuse_type == "invite":
        return [
            "Rate-limit invitations per authenticated account, tenant, destination, and source IP as appropriate.",
            "Enforce server-side authorization for who may invite users and restrict destinations to approved tenants/domains.",
            "Make invitation tokens short-lived and single-use and return HTTP 429 on abuse.",
            "Add tests for bulk invites, cross-tenant invites, replay, and enumeration.",
        ]
    return [
        "Apply endpoint-appropriate server-side throttling using account, IP, tenant, and operation dimensions.",
        "Use replay protection or idempotency for state-changing operations where duplicate execution matters.",
        "Return HTTP 429 with bounded retry behavior and emit abuse telemetry.",
        "Add automated burst, replay, concurrency, and authorization tests for the affected endpoint.",
    ]

def _priority(severity: str) -> str:
    return {
        "Critical": "P1",
        "High": "P2",
        "Medium": "P3",
        "Low": "P4",
        "Info": "P4",
    }.get(severity, "P3")


def _lang(path: Path) -> str:
    return {
        ".py": "python",
        ".js": "javascript",
        ".jsx": "javascript",
        ".ts": "typescript",
        ".tsx": "typescript",
        ".java": "java",
        ".cs": "csharp",
        ".go": "go",
        ".php": "php",
        ".rb": "ruby",
        ".kt": "kotlin",
        ".scala": "scala",
        ".yml": "yaml",
        ".yaml": "yaml",
        ".json": "json",
    }.get(path.suffix.lower(), "unknown")


def _extract_route(match: re.Match) -> str:
    return next((group for group in match.groups() if group), "") or ""


def _make_finding(
    *,
    rule_id: str,
    title: str,
    abuse_type: str,
    path: Path,
    line: int,
    snippet: str,
    route: str,
    method: str = "",
) -> dict:
    return {
        "rule_id": rule_id,
        "title": title,
        "vuln_type": "api_abuse_missing_rate_limit",
        "finding_class": "control_gap",
        "severity": "Medium",
        "priority": _priority("Medium"),
        "confidence": "Medium",
        "language": _lang(path),
        "file": str(path),
        "line": line,
        "snippet": snippet.strip(),
        "description": (
            f"Abuse-prone {abuse_type} endpoint appears without nearby "
            "rate-limit, replay, lockout, or idempotency controls."
        ),
        "remediation": _remediation_for_abuse_type(abuse_type),
        "owasp": "API4:2023 - Unrestricted Resource Consumption",
        "cwe": "CWE-770",
        "pci_dss": "Req 6.2.4 / Req 8 - Abuse prevention and authentication controls",
        "nist": "AC-7 / SC-5 / SI-10",
        "nist_800_53": "AC-7 / SC-5 / SI-10",
        "iso27001": "A.8.16 / A.8.20",
        "iso_27001": "A.8.16 / A.8.20",
        "soc2": "CC7.2 / CC6.6",
        "evidence": f"{path}:{line}: {snippet.strip()}",
        "evidence_type": "route_definition_without_detected_control",
        "control_gap_basis": "Concrete server-side route definition was identified; no matching rate-limit, throttle, lockout, replay-protection, or idempotency control was detected in the route declaration or applicable nearby middleware context.",
        "requires_manual_verification": True,
        "detection": "API Abuse Heuristic",
        "engine": "analysis.api_abuse_engine",
        "api_abuse_type": abuse_type,
        "route": route,
        "http_method": method.upper() if method else "UNKNOWN",
        "group_key": f"{rule_id}|{path}|{route}",
        "enterprise_control": True,
    }



def _is_frontend_client_file(path: Path) -> bool:
    """Client-side code is not a server API route definition."""
    normalized = str(path).replace("\\", "/").lower()
    markers = (
        "/frontend/", "/src/context/", "/src/hooks/", "/src/pages/",
        "/src/components/", "/src/api/", "/client/", "/web/"
    )
    return any(marker in normalized for marker in markers)


def _route_has_protection(text: str, route: str, start: int, window: str) -> bool:
    """Check route-specific and file-level abuse controls."""
    route_norm = route.rstrip('/') or '/'
    route_escaped = re.escape(route_norm)
    quote = r"[\"']"
    prefix = text[:start]
    middleware = r"(?:rateLimit|rate_limit|throttle|limiter|Bucket4j|RateLimiter|limit_req|slow_down|slowDown|lockout|backoff)"
    route_use = rf"(?:app|router)\.use\s*\(\s*{quote}{route_escaped}/?{quote}\s*,"
    if re.search(route_use + r"(?:(?!\n\n).)*?" + middleware, prefix, re.I | re.S):
        return True
    route_decl = rf"(?:app|router)\.(?:get|post|put|patch|delete)\s*\(\s*{quote}{route_escaped}/?{quote}\s*,"
    if re.search(route_decl + r"[^\n]*" + middleware, text[start:start + 1200], re.I):
        return True
    # Only inspect the current route declaration (up to the next route), not
    # a broad character window that can accidentally inherit middleware from
    # the preceding endpoint.
    tail = text[start:]
    next_route = re.search(r"\n\s*(?:app|router)\.(?:get|post|put|patch|delete)\s*\(", tail[WINDOW_1:], re.I)
    declaration = tail if not next_route else tail[: next_route.start() + 1]
    return bool(SAFE.search(declaration[:WINDOW_800]))

def scan_file(filepath: str) -> list[dict]:
    path = Path(filepath)

    # A client-side file may contain API paths such as "/refresh" or
    # "/login", but it does not define the server endpoint and therefore
    # cannot establish a missing server-side rate limit.
    if _is_frontend_client_file(path):
        return []

    from core import file_index
    try:
        text = file_index.read_source(path)
    except OSError:
        return []
    if text is None:
        return []

    lines = text.splitlines()
    findings: list[dict] = []
    seen: set[str] = set()

    for match in ROUTE.finditer(text):
        route = _extract_route(match)
        if not route:
            continue

        start = match.start()
        line_no = text[:start].count("\n") + 1
        window = text[max(0, start - 300): min(len(text), start + 500)]

        # Normalize framework route syntax before applying abuse rules.
        # Django commonly emits "login/" while other frameworks emit "/login".
        route_for_matching = route.strip()
        if route_for_matching and not route_for_matching.startswith("/"):
            route_for_matching = "/" + route_for_matching

        # A Django include()/mount prefix is a routing container, not the
        # concrete authentication operation. Report the resolved child route
        # (e.g. login/) instead of duplicating the parent /api/auth/ finding.
        route_line_start = text.rfind("\n", 0, start) + 1
        route_line_end = text.find("\n", match.end())
        if route_line_end == -1:
            route_line_end = len(text)
        route_line = text[route_line_start:route_line_end]
        if re.search(r"\binclude\s*\(", route_line, re.I):
            continue

        # Recover the HTTP verb from the concrete route declaration. A route
        # name alone is not enough to establish an abuse-control gap.
        decl = match.group(0)
        method_match = re.search(r"\.(get|post|put|patch|delete)\s*\(|@(?:PostMapping|GetMapping|PutMapping|PatchMapping|DeleteMapping)|\[Http(Post|Get|Put|Patch|Delete)", decl, re.I)
        method = ""
        if method_match:
            token = next((g for g in method_match.groups() if g), "")
            if token:
                method = token.replace("Mapping", "").replace("Http", "").upper()
            else:
                tokenized = re.search(r"(?:PostMapping|GetMapping|PutMapping|PatchMapping|DeleteMapping|HttpPost|HttpGet|HttpPut|HttpPatch|HttpDelete)", decl, re.I)
                method = re.sub(r"Mapping$", "", tokenized.group(0), flags=re.I).replace("Http", "").upper() if tokenized else ""

        for rule_id, title, abuse_type, pattern in RULES:
            if not re.search(pattern, route_for_matching, re.I):
                continue

            # Payment duplicate-action and coupon replay controls concern
            # state-changing operations. GET endpoints such as wallet balance,
            # promotion videos, or intentionally hidden pages are not payment
            # replay controls merely because their path contains a keyword.
            if abuse_type in {"payment", "coupon"} and method == "GET":
                continue
            if abuse_type in {"login", "otp", "password_reset", "invite", "token_refresh"} and method == "GET":
                continue

            if _route_has_protection(text, route_for_matching, start, window):
                break

            snippet = lines[line_no - 1] if 0 < line_no <= len(lines) else route
            key = f"{rule_id}|{path}|{route}"
            if key in seen:
                break

            finding = _make_finding(
                    rule_id=rule_id,
                    title=title,
                    abuse_type=abuse_type,
                    path=path,
                    line=line_no,
                    snippet=snippet,
                    route=route,
                    method=method,
                )
            # A state-changing abuse category without a resolved HTTP method
            # is weaker evidence; keep it for review but do not over-promote it.
            if abuse_type in {"payment", "coupon", "login", "otp", "password_reset", "invite", "token_refresh"} and not method:
                finding["severity"] = "Medium"
                finding["confidence"] = "Low"
                finding["executive_relevant"] = False
                finding["evidence_status"] = "ROUTE_HEURISTIC_REVIEW_ONLY"
                finding["requires_manual_verification"] = True
            findings.append(finding)
            seen.add(key)
            break

    return findings


def analyze_api_abuse(target_path: str) -> dict:
    target = Path(target_path)
    findings: list[dict] = []

    # FND-02: single-file targets are yielded unconditionally; directory
    # targets are the one index query (ext allow-list = walk policy).
    if target.is_file():
        _api_files: list[Path] = [target]
    else:
        from core import file_index
        _api_files = file_index.index_for(target).files(
            exts={e.lower() for e in SCANNABLE_EXTENSIONS})
    for file_path in _api_files:
        findings.extend(scan_file(str(file_path)))

    return {
        "api_abuse_findings": findings,
        "api_abuse_summary": summarize_api_abuse(findings),
    }


def analyze_api_abuse_risk(target_path: str) -> dict:
    return analyze_api_abuse(target_path)


def scan_api_abuse(target_path: str) -> dict:
    return analyze_api_abuse(target_path)


def summarize_api_abuse(findings: list[dict]) -> dict:
    unique = {finding.get("group_key") for finding in findings if finding.get("group_key")}
    high = sum(1 for finding in findings if finding.get("severity") == "High")
    critical = sum(1 for finding in findings if finding.get("severity") == "Critical")

    return {
        "total_api_abuse_findings": len(findings),
        "unique_api_abuse_findings": len(unique),
        "critical_api_abuse_findings": critical,
        "high_api_abuse_findings": high,
        "by_type": dict(Counter(finding.get("api_abuse_type", "unknown") for finding in findings)),
        "by_severity": dict(Counter(finding.get("severity", "Unknown") for finding in findings)),
        "summary_status": "API_ABUSE_RISK_IDENTIFIED" if findings else "NO_API_ABUSE_RISK_IDENTIFIED",
    }


if __name__ == "__main__":
    import json
    import sys

    target_arg = sys.argv[1] if len(sys.argv) > 1 else "."
    print(json.dumps(analyze_api_abuse(target_arg), indent=2))
