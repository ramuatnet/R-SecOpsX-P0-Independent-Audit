
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
        r"/(?:pay|payment|checkout|transfer|withdraw|wallet|deposit)",
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
# - ASP.NET: [HttpPost("/payment")]
# - Go: http.HandleFunc("/login", handler)
# - PHP Slim/Lumen: $app->post("/login")
# - Laravel: Route::post("/login")
# - Flask/FastAPI: @app.post("/login"), @router.post("/login"), @app.route("/login")
ROUTE = re.compile(
    r"(?:app|router)\.(?:get|post|put|patch|delete)\s*\(\s*[\"']([^\"']+)"
    r"|@(PostMapping|GetMapping|PutMapping|PatchMapping|DeleteMapping)\s*\(\s*[\"']([^\"']+)"
    r"|\[Http(?:Post|Get|Put|Patch|Delete)\s*\(\s*[\"']([^\"']+)"
    r"|http\.HandleFunc\s*\(\s*[\"']([^\"']+)"
    r"|\$app->(?:get|post|put|patch|delete)\s*\(\s*[\"']([^\"']+)"
    r"|Route::(?:get|post|put|patch|delete)\s*\(\s*[\"']([^\"']+)"
    r"|@app\.(?:route|get|post|put|patch|delete)\s*\(\s*[\"']([^\"']+)"
    r"|@router\.(?:route|get|post|put|patch|delete)\s*\(\s*[\"']([^\"']+)"
    # Django URLconf:
    #   path("login/", LoginView.as_view(), name="login")
    #   re_path(r"^refresh/$", RefreshTokenView.as_view(), name="refresh")
    #   url(r"^login/$", LoginView.as_view(), name="login")
    r"|(?:^|\n)\s*(?:path|re_path|url)\s*\(\s*[rRuUbBfF]*[\"']([^\"']+)",
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


def _iter_files(target: Path) -> list[Path]:
    if target.is_file():
        return [target]

    files: list[Path] = []
    for path in target.rglob("*"):
        if not path.is_file():
            continue
        parts = {part.lower() for part in path.parts}
        if parts.intersection(SKIP_DIRS):
            continue
        if path.suffix.lower() not in SCANNABLE_EXTENSIONS:
            continue
        files.append(path)
    return files


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
) -> dict:
    return {
        "rule_id": rule_id,
        "title": title,
        "vuln_type": "api_abuse_missing_rate_limit",
        "severity": "High",
        "priority": _priority("High"),
        "confidence": "Medium",
        "language": _lang(path),
        "file": str(path),
        "line": line,
        "snippet": snippet.strip(),
        "description": (
            f"Abuse-prone {abuse_type} endpoint appears without nearby "
            "rate-limit, replay, lockout, or idempotency controls."
        ),
        "remediation": [
            "Add per-user, per-IP, and per-tenant rate limits.",
            "Add lockout/backoff for brute-force workflows such as login, OTP, MFA, and password reset.",
            "Use idempotency keys for payment or state-changing actions.",
            "Add replay protection and server-side nonce validation where applicable.",
            "Monitor abuse metrics and alert on anomalous request velocity or repeated failures.",
        ],
        "owasp": "API4:2023 - Unrestricted Resource Consumption",
        "cwe": "CWE-770",
        "pci_dss": "Req 6.2.4 / Req 8 - Abuse prevention and authentication controls",
        "nist": "AC-7 / SC-5 / SI-10",
        "nist_800_53": "AC-7 / SC-5 / SI-10",
        "iso27001": "A.8.16 / A.8.20",
        "iso_27001": "A.8.16 / A.8.20",
        "soc2": "CC7.2 / CC6.6",
        "evidence": f"{path}:{line}: {snippet.strip()}",
        "detection": "API Abuse Heuristic",
        "engine": "analysis.api_abuse_engine",
        "api_abuse_type": abuse_type,
        "route": route,
        "group_key": f"{rule_id}|{path}|{route}",
        "enterprise_control": True,
    }


def scan_file(filepath: str) -> list[dict]:
    path = Path(filepath)
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    lines = text.splitlines()
    findings: list[dict] = []
    seen: set[str] = set()


    for match in ROUTE.finditer(text):
        route = _extract_route(match)
        if not route:
            continue

        start = match.start()
        line = text[:start].count("\n") + 1
        window = text[max(0, start - 300): min(len(text), start + 500)]

        for rule_id, title, abuse_type, pattern in RULES:
            if not re.search(pattern, route, re.I):
                continue

            if SAFE.search(window):
                break

            snippet = lines[line - 1] if 0 < line <= len(lines) else route
            key = f"{rule_id}|{path}|{route}"
            if key in seen:
                break

            findings.append(
                _make_finding(
                    rule_id=rule_id,
                    title=title,
                    abuse_type=abuse_type,
                    path=path,
                    line=line,
                    snippet=snippet,
                    route=route,
                )
            )
            seen.add(key)
            break

    return findings


def analyze_api_abuse(target_path: str) -> dict:
    target = Path(target_path)
    findings: list[dict] = []

    for file_path in _iter_files(target):
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
