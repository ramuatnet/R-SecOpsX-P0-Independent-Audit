from __future__ import annotations
try:
    from analysis.spans import WINDOW_SNIPPET
except ImportError:  # FND-03: standalone, repo root not on path
    import sys as _fnd03_sys
    from pathlib import Path as _fnd03_path
    _fnd03_sys.path.insert(0, str(_fnd03_path(__file__).resolve().parents[1]))
    from analysis.spans import WINDOW_SNIPPET

import re
from collections import Counter
from pathlib import Path


ENGINE_MODE = "STATIC_AUTH_HARDENING_RISK_V2_TARGET_SCAN"


WEAK_PASSWORD_PATTERNS = [
    r'password\s*=\s*["\'](123456|password|admin|root|qwerty|welcome|letmein)["\']',
    r'passwd\s*=\s*["\'](123456|password|admin|root|qwerty|welcome|letmein)["\']',
    r'pwd\s*=\s*["\'](123456|password|admin|root|qwerty|welcome|letmein)["\']',
    r'default_password\s*=\s*["\'][^"\']+["\']',
    r'hardcoded_password\s*=\s*["\'][^"\']+["\']',
]

WEAK_POLICY_PATTERNS = [
    r'min_length\s*[<:=]\s*[1-7]\b',
    r'password_length\s*[<:=]\s*[1-7]\b',
    r'allow_weak_password\s*=\s*True',
    r'password_complexity\s*=\s*False',
    r'require_special\s*=\s*False',
    r'require_digit\s*=\s*False',
    r'require_uppercase\s*=\s*False',
]

CAPTCHA_BYPASS_PATTERNS = [
    r'captcha_disabled\s*=\s*True',
    r'skip_captcha\s*=\s*True',
    r'bypass_captcha',
    r'recaptcha_enabled\s*=\s*False',
    r'hcaptcha_enabled\s*=\s*False',
]

CAPTCHA_VERIFY_PATTERNS = [
    r'verify_captcha',
    r'captcha_verify',
    r'captcha_validate',
    r'recaptcha/api/siteverify',
    r'hcaptcha.com/siteverify',
    r'turnstile/v0/siteverify',
]

LOGIN_ROUTE_PATTERNS = [
    # Authentication-attempt endpoints only. Do not classify informational
    # routes such as /authentication-details as login endpoints.
    r'@app\.route\(["\'][^"\']*/(?:login|signin|sign-in|authenticate|authentication)["\']',
    r'router\.post\(["\'][^"\']*/(?:login|signin|sign-in|authenticate|authentication)["\']',
    r'path\(["\'][^"\']*/(?:login|signin|sign-in|authenticate|authentication)["\']',
    r'\bPOST\s+/[^\s\'"]*(?:login|signin|sign-in|authenticate|authentication)(?:[/\?\s\'"]|$)',
]

RATE_LIMIT_PATTERNS = [
    r'rate_limit',
    r'limiter',
    r'throttle',
    r'login_throttle',
    r'max_requests',
]

ACCOUNT_LOCKOUT_PATTERNS = [
    r'failed_attempts',
    r'failed_login_attempts',
    r'account_lockout',
    r'lock_after',
    r'max_login_attempts',
]

WEAK_RESET_TOKEN_PATTERNS = [
    r'password_reset.*md5',
    r'password_reset.*sha1',
    r'reset_token.*md5',
    r'reset_token.*sha1',
    r'reset_token\s*=\s*random\.randint',
    r'reset_token\s*=\s*random\.choice',
    r'token\s*=\s*random\.randint',
    r'token\s*=\s*random\.choice',
]

SESSION_LOGIN_PATTERNS = [
    r'login',
    r'authenticate',
    r'signin',
]

SESSION_ROTATION_PATTERNS = [
    r'regenerate_session',
    r'rotate_session',
    r'session\.regenerate',
    r'cycle_key',
    r'renew_session',
]

SCAN_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx",
    ".java", ".go", ".php", ".rb", ".cs",
    ".env", ".txt", ".json", ".yml", ".yaml",
    ".properties", ".ini", ".conf", ".cfg",
}

SPECIAL_FILENAMES = {
    ".env",
    "dockerfile",
}


def _text(obj) -> str:
    if obj is None:
        return ""
    if isinstance(obj, (dict, list, tuple, set)):
        return str(obj).lower()
    return str(obj).lower()


def _finding_text(finding: dict) -> str:
    return " ".join([
        _text(finding.get("title")),
        _text(finding.get("description")),
        _text(finding.get("snippet")),
        _text(finding.get("evidence")),
        _text(finding.get("file")),
        _text(finding.get("file_path")),
    ])


def _matches_any(text: str, patterns: list[str]) -> bool:
    return any(re.search(pattern, text, re.IGNORECASE) for pattern in patterns)


def _make(
    rule_id: str,
    title: str,
    severity: str,
    confidence: str,
    file_path: str,
    line,
    evidence: str,
):
    return {
        "rule_id": rule_id,
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "file": file_path,
        "line": line,
        "evidence": evidence,
        "engine_mode": ENGINE_MODE,
        "executive_relevant": severity in {"Critical", "High"},
    }


# Directories that are not useful for authentication-hardening source
# analysis and can contain very large generated/third-party trees.
# Skipping them is both a performance optimization and a precision
# improvement: third-party implementation details should not be treated
# as application authentication controls.
AUTH_SCAN_SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "vendor",
    "bower_components",
    "dist",
    "build",
    "coverage",
    ".next",
    ".nuxt",
    ".angular",
    "out",
    "target",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".tox",
    "venv",
    ".venv",
    "env",
    ".env",
}

# Cheap lexical gate used before the comparatively expensive regex rules.
# A line that contains none of these tokens cannot match any auth rule.
AUTH_SCAN_TOKENS = (
    "password",
    "passwd",
    "pwd",
    "captcha",
    "recaptcha",
    "hcaptcha",
    "turnstile",
    "login",
    "signin",
    "sign-in",
    "authenticate",
    "authentication",
    "auth",
    "rate_limit",
    "ratelimit",
    "limiter",
    "throttle",
    "lockout",
    "lock_after",
    "failed_attempt",
    "max_login",
    "reset_token",
    "password_reset",
    "session",
    "rotate_session",
    "regenerate_session",
    "cycle_key",
    "renew_session",
    "random.randint",
    "random.choice",
)


def _iter_auth_scan_files(root: Path):
    """
    Yield candidate application source files without walking excluded
    dependency/generated directories.

    os.scandir-style recursion is materially cheaper than Path.rglob on
    large Windows trees and allows directory pruning before descending.
    """
    # T-0.2 (task.md): the one walk's index; AUTH_SCAN_SKIP_DIRS is walk
    # policy now (part of the shared union). The old iterdir recursion
    # returned empty for a file target (PermissionError/OSError path) --
    # preserve that: this engine only scans directories.
    if not root.is_dir():
        return
    from core import file_index
    for entry in file_index.index_for(root).files():
        suffix = entry.suffix.lower()
        name = entry.name.lower()
        if suffix in SCAN_EXTENSIONS or name in SPECIAL_FILENAMES:
            yield entry


def _target_findings(target: str | None) -> list[dict]:
    """
    Scan only application-relevant authentication source evidence.

    Performance safeguards:
    - prunes node_modules/vendor/build/dist/.git and other generated trees;
    - uses a cheap lexical token gate before regex evaluation;
    - compiles regexes once;
    - does not create findings for unrelated source lines.
    """
    if not target:
        return []

    root = Path(target)
    if not root.exists():
        return []

    if root.is_file():
        candidate_files = [root]
    else:
        candidate_files = _iter_auth_scan_files(root)

    relevant_patterns = [
        re.compile(pattern, re.IGNORECASE)
        for pattern_group in (
            WEAK_PASSWORD_PATTERNS,
            WEAK_POLICY_PATTERNS,
            CAPTCHA_BYPASS_PATTERNS,
            CAPTCHA_VERIFY_PATTERNS,
            LOGIN_ROUTE_PATTERNS,
            RATE_LIMIT_PATTERNS,
            ACCOUNT_LOCKOUT_PATTERNS,
            WEAK_RESET_TOKEN_PATTERNS,
            SESSION_ROTATION_PATTERNS,
        )
        for pattern in pattern_group
    ]

    generated = []

    for path in candidate_files:
        try:
            with path.open(
                "r",
                encoding="utf-8",
                errors="ignore",
            ) as handle:
                for idx, line in enumerate(handle, start=1):
                    clean = line.strip()

                    if not clean:
                        continue

                    lowered = clean.lower()

                    # Cheap substring gate. Most source lines fail here,
                    # avoiding dozens of regex searches per line.
                    if not any(token in lowered for token in AUTH_SCAN_TOKENS):
                        continue

                    if not any(
                        pattern.search(clean)
                        for pattern in relevant_patterns
                    ):
                        continue

                    generated.append({
                        "file": str(path),
                        "line": idx,
                        "title": "Auth hardening source scan",
                        "snippet": clean,
                        "evidence": clean,
                    })

        except (OSError, UnicodeError, PermissionError):
            continue

    return generated


def _has_login_surface(findings: list[dict], api_bom: list[dict]) -> bool:
    """
    Check for a login/authentication surface using already materialized text.
    """
    corpus = " ".join(_finding_text(f) for f in findings)
    if api_bom:
        corpus += " " + _text(api_bom)
    return _matches_any(corpus, LOGIN_ROUTE_PATTERNS)


CAPTCHA_TOKEN_EVIDENCE_PATTERNS = [
    r'\bcaptcha[_\- ]?(?:token|response|value)\b',
    r'\b(?:recaptcha|hcaptcha)[_\- ]?(?:token|response)\b',
    r'g-recaptcha-response',
    r'cf-turnstile-response',
    r'\b(?:captcha|recaptcha|hcaptcha|turnstile)[^\n]{0,80}\btoken\b',
]


def _has_captcha_token_without_verification(
    findings: list[dict],
    finding_texts: list[str] | None = None,
) -> list[dict]:
    """
    Identify an observed CAPTCHA token/response that lacks verification.

    Merely mentioning CAPTCHA (for example in an ``eval captcha`` finding) is
    insufficient evidence. A concrete token/response signal must be present
    before creating a CAPTCHA_TOKEN_NOT_VERIFIED indicator.
    """
    suspicious = []

    if finding_texts is None:
        finding_texts = [_finding_text(f) for f in findings]

    for finding, text in zip(findings, finding_texts):
        if "captcha" not in text and "recaptcha" not in text and "hcaptcha" not in text and "turnstile" not in text:
            continue

        if not _matches_any(text, CAPTCHA_TOKEN_EVIDENCE_PATTERNS):
            continue

        if _matches_any(text, CAPTCHA_VERIFY_PATTERNS):
            continue

        if _matches_any(text, CAPTCHA_BYPASS_PATTERNS):
            continue

        suspicious.append(finding)

    return suspicious


def enrich_auth_hardening_risk(
    findings: list[dict] | None,
    api_bom: list[dict] | None = None,
    target: str | None = None,
):
    """
    Authentication hardening analysis.

    V2 target scanning is retained, but only authentication-relevant source
    lines are materialized. This prevents dependency/source trees such as
    node_modules from turning every source line into a synthetic finding.

    The function also reuses precomputed text/corpora so large finding sets
    are not repeatedly converted to strings.
    """
    findings = list(findings or [])
    api_bom = list(api_bom or [])

    # Direct target scan allows this engine to operate even when SAST raw
    # findings are zero. _target_findings now returns only relevant lines.
    target_findings = _target_findings(target)
    if target_findings:
        findings.extend(target_findings)

    # Precompute finding text exactly once.
    finding_texts = [_finding_text(f) for f in findings]

    # Precompute API route text exactly once.
    api_texts = [_text(route) for route in api_bom]

    finding_corpus = " ".join(
        text for text in finding_texts if text
    )
    api_corpus = " ".join(
        text for text in api_texts if text
    )

    combined_corpus = finding_corpus
    if api_corpus:
        combined_corpus += " " + api_corpus

    indicators = []
    seen = set()

    def add(ind):
        key = (
            ind.get("rule_id"),
            str(ind.get("file") or "").replace("\\", "/").lower(),
            str(ind.get("line")),
            str(ind.get("evidence") or "")[:WINDOW_SNIPPET].lower(),
        )

        if key in seen:
            return

        seen.add(key)
        indicators.append(ind)

    # --------------------------------------------------
    # Finding-level authentication controls
    # --------------------------------------------------
    for finding, text in zip(findings, finding_texts):
        file_path = finding.get("file", "")
        line = finding.get("line")
        evidence = (
            finding.get("snippet")
            or finding.get("evidence", "")
        )

        if _matches_any(text, WEAK_PASSWORD_PATTERNS):
            add(_make(
                "WEAK_PASSWORD_LITERAL",
                "Weak or default password detected",
                "Critical",
                "High",
                file_path,
                line,
                evidence,
            ))

        if _matches_any(text, WEAK_POLICY_PATTERNS):
            add(_make(
                "WEAK_PASSWORD_POLICY",
                "Weak password policy detected",
                "High",
                "Medium",
                file_path,
                line,
                evidence,
            ))

        if _matches_any(text, CAPTCHA_BYPASS_PATTERNS):
            add(_make(
                "CAPTCHA_BYPASSABLE_FLOW",
                "Captcha disabled or bypassable",
                "High",
                "Medium",
                file_path,
                line,
                evidence,
            ))

        if _matches_any(text, WEAK_RESET_TOKEN_PATTERNS):
            add(_make(
                "WEAK_PASSWORD_RESET_TOKEN",
                "Weak password reset token generation",
                "High",
                "Medium",
                file_path,
                line,
                evidence,
            ))

    # --------------------------------------------------
    # CAPTCHA token without verification
    # --------------------------------------------------
    for finding in _has_captcha_token_without_verification(
        findings,
        finding_texts,
    ):
        add(_make(
            "CAPTCHA_TOKEN_NOT_VERIFIED",
            "Captcha token observed without verification evidence",
            "Medium",
            "Low",
            finding.get("file", ""),
            finding.get("line"),
            finding.get("snippet")
            or finding.get("evidence", ""),
        ))

    # --------------------------------------------------
    # API login routes without visible rate limiting
    # --------------------------------------------------
    for route, route_text in zip(api_bom, api_texts):
        if not _matches_any(route_text, LOGIN_ROUTE_PATTERNS):
            continue

        if _matches_any(route_text, RATE_LIMIT_PATTERNS):
            continue

        add(_make(
            "NO_LOGIN_RATE_LIMIT",
            "Login endpoint without visible rate limiting",
            "High",
            "Low",
            route.get("file", ""),
            route.get("line"),
            route_text,
        ))

    # --------------------------------------------------
    # Global missing controls
    # --------------------------------------------------
    if (
        _matches_any(finding_corpus, LOGIN_ROUTE_PATTERNS)
        or _matches_any(api_corpus, LOGIN_ROUTE_PATTERNS)
    ):
        if not _matches_any(
            combined_corpus,
            ACCOUNT_LOCKOUT_PATTERNS,
        ):
            add(_make(
                "NO_ACCOUNT_LOCKOUT",
                "No account lockout controls observed",
                "Medium",
                "Low",
                "",
                None,
                "Login/auth surface observed, but no account "
                "lockout patterns observed",
            ))

        if not _matches_any(
            combined_corpus,
            SESSION_ROTATION_PATTERNS,
        ):
            add(_make(
                "SESSION_NOT_ROTATED_AFTER_LOGIN",
                "Session rotation after login not observed",
                "Medium",
                "Low",
                "",
                None,
                "Login/auth surface observed, but no session "
                "rotation patterns observed",
            ))

    counts = Counter(
        x.get("severity")
        for x in indicators
    )

    return {
        "total_auth_hardening_indicators": len(indicators),
        "critical_auth_hardening_indicators":
            counts.get("Critical", 0),
        "high_auth_hardening_indicators":
            counts.get("High", 0),
        "medium_auth_hardening_indicators":
            counts.get("Medium", 0),
        "executive_relevant_indicators": sum(
            1
            for x in indicators
            if x.get("executive_relevant")
        ),
        "summary_status": (
            "AUTH_HARDENING_RISK_IDENTIFIED"
            if indicators
            else "NO_AUTH_HARDENING_RISK_IDENTIFIED"
        ),
        "indicators": indicators,
        "engine_mode": ENGINE_MODE,
    }
