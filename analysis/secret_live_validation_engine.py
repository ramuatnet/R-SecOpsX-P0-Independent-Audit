"""
analysis/secret_live_validation_engine.py

R-SecOpsX V4 Phase 1: Optional Secret Live Validation.

Design goals:
- V3 baseline is unchanged unless --live-secrets is enabled.
- Never leak full secrets into reports.
- Use Python standard library only.
- Validate only with low-impact authentication/profile endpoints.
- Fail closed to inconclusive/error without breaking the scan.
"""
from __future__ import annotations
from concurrent.futures import ThreadPoolExecutor, as_completed

import base64
import re
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple


DEFAULT_TIMEOUT_SECONDS = 6
DEFAULT_MAX_VALIDATIONS = 50

_SECRET_ASSIGNMENT_RE = re.compile(
    r"""(?ix)
    (?:secret|token|api[_-]?key|client[_-]?secret|password|passwd|pwd|credential|key)
    \s*[:=]\s*
    ["']?
    (?P<value>[^"'\s#;,]+)
    """
)

_URI_CREDENTIAL_RE = re.compile(
    r"""(?ix)
    (?P<uri>
        (?:postgres(?:ql)?|mysql|mongodb|redis|sqlserver|amqps?|jdbc:[^\s"']+)
        ://[^\s"']+
    )
    """
)


@dataclass
class LiveValidationResult:
    provider: str
    validation_status: str
    confidence: str
    evidence: str
    risk_upgrade: bool = False
    http_status: Optional[int] = None


def _mask_secret(value: str) -> str:
    value = str(value or "").strip()
    if not value:
        return ""
    if len(value) <= 8:
        return "***"
    return f"{value[:4]}...{value[-4:]}"


def _candidate_values_from_text(text: str) -> List[str]:
    text = str(text or "").strip()
    values: List[str] = []

    if not text:
        return values

    for match in _SECRET_ASSIGNMENT_RE.finditer(text):
        val = match.group("value").strip().strip('"').strip("'")
        if val:
            values.append(val)

    for match in _URI_CREDENTIAL_RE.finditer(text):
        val = match.group("uri").strip().strip('"').strip("'")
        if val:
            values.append(val)

    # Provider-native token patterns.
    provider_patterns = [
        r"github_pat_[A-Za-z0-9_]{20,}",
        r"gh[pousr]_[A-Za-z0-9_]{20,}",
        r"glpat-[A-Za-z0-9_\-]{20,}",
        r"sk-ant-[A-Za-z0-9_\-]{20,}",
        r"sk-[A-Za-z0-9_\-]{20,}",
        r"(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}",
        r"xox[baprs]-[A-Za-z0-9\-]{20,}",
        r"SG\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}",
        r"AIza[0-9A-Za-z_\-]{20,}",
    ]

    for pattern in provider_patterns:
        for match in re.finditer(pattern, text):
            values.append(match.group(0).strip())

    if not values and len(text) >= 12 and not any(ch.isspace() for ch in text):
        values.append(text)

    # Preserve order and de-duplicate.
    deduped: List[str] = []
    seen = set()
    for value in values:
        if value not in seen:
            seen.add(value)
            deduped.append(value)

    return deduped


def _extract_secret_value(finding: Dict[str, Any]) -> str:
    explicit_keys = (
        "secret_value",
        "secret",
        "value",
        "match",
        "matched_value",
        "raw_secret",
        "token",
        "credential",
    )

    for key in explicit_keys:
        val = finding.get(key)
        if isinstance(val, str) and val.strip():
            candidates = _candidate_values_from_text(val)
            return candidates[0] if candidates else val.strip()

    for key in ("snippet", "evidence", "description"):
        val = finding.get(key)
        if isinstance(val, str) and val.strip():
            candidates = _candidate_values_from_text(val)
            if candidates:
                return candidates[0]

    return ""


def _detect_provider(finding: Dict[str, Any], secret_value: str) -> str:
    text = " ".join(
        str(finding.get(k, ""))
        for k in ("rule_id", "title", "type", "secret_type", "description", "provider", "snippet")
    ).lower()

    value = str(secret_value or "").strip()

    if value.startswith("sk-ant-") or "anthropic" in text:
        return "anthropic"
    if "github" in text or value.startswith(("ghp_", "github_pat_", "gho_", "ghu_", "ghs_", "ghr_")):
        return "github"
    if "gitlab" in text or value.startswith(("glpat-", "gloas-", "glcbt-")):
        return "gitlab"
    if "openai" in text or value.startswith("sk-"):
        return "openai"
    if "stripe" in text or value.startswith(("sk_live_", "rk_live_", "sk_test_", "rk_test_")):
        return "stripe"
    if "slack" in text or value.startswith(("xoxb-", "xoxp-", "xoxa-", "xoxr-", "xoxs-")):
        return "slack"
    if "sendgrid" in text or value.startswith("SG."):
        return "sendgrid"
    if "gemini" in text or "google api" in text or value.startswith("AIza"):
        return "google_api_key"
    if "aws" in text or value.startswith(("AKIA", "ASIA")):
        return "aws_access_key"

    return "unknown"


def _http_request(
    url: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    data: Optional[bytes] = None,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
) -> Tuple[int, str]:
    request = urllib.request.Request(
        url=url,
        method=method,
        headers=headers or {},
        data=data,
    )

    context = ssl.create_default_context()

    try:
        with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
            body = response.read(2048).decode("utf-8", errors="replace")
            return int(response.status), body
    except urllib.error.HTTPError as exc:
        body = exc.read(2048).decode("utf-8", errors="replace")
        return int(exc.code), body
    except (urllib.error.URLError, socket.timeout, TimeoutError, OSError):
        return 0, ""


def _validate_github(token: str, timeout: int) -> LiveValidationResult:
    status, _ = _http_request(
        "https://api.github.com/user",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "User-Agent": "R-SecOpsX-Secret-Live-Validation",
        },
        timeout=timeout,
    )
    if status == 200:
        return LiveValidationResult("github", "LIVE_VALID", "High", "GitHub API authenticated successfully", True, status)
    if status in (401, 403):
        return LiveValidationResult("github", "NOT_VALID_OR_REVOKED", "Medium", "GitHub API rejected token", False, status)
    return LiveValidationResult("github", "VALIDATION_INCONCLUSIVE", "Low", "GitHub validation inconclusive", False, status)


def _validate_gitlab(token: str, timeout: int) -> LiveValidationResult:
    status, _ = _http_request(
        "https://gitlab.com/api/v4/user",
        headers={"PRIVATE-TOKEN": token, "User-Agent": "R-SecOpsX-Secret-Live-Validation"},
        timeout=timeout,
    )
    if status == 200:
        return LiveValidationResult("gitlab", "LIVE_VALID", "High", "GitLab API authenticated successfully", True, status)
    if status in (401, 403):
        return LiveValidationResult("gitlab", "NOT_VALID_OR_REVOKED", "Medium", "GitLab API rejected token", False, status)
    return LiveValidationResult("gitlab", "VALIDATION_INCONCLUSIVE", "Low", "GitLab validation inconclusive", False, status)


def _validate_openai(token: str, timeout: int) -> LiveValidationResult:
    status, _ = _http_request(
        "https://api.openai.com/v1/models",
        headers={"Authorization": f"Bearer {token}"},
        timeout=timeout,
    )
    if status == 200:
        return LiveValidationResult("openai", "LIVE_VALID", "High", "OpenAI API authenticated successfully", True, status)
    if status in (401, 403):
        return LiveValidationResult("openai", "NOT_VALID_OR_REVOKED", "Medium", "OpenAI API rejected token", False, status)
    return LiveValidationResult("openai", "VALIDATION_INCONCLUSIVE", "Low", "OpenAI validation inconclusive", False, status)


def _validate_anthropic(token: str, timeout: int) -> LiveValidationResult:
    status, _ = _http_request(
        "https://api.anthropic.com/v1/models",
        headers={"x-api-key": token, "anthropic-version": "2023-06-01"},
        timeout=timeout,
    )
    if status == 200:
        return LiveValidationResult("anthropic", "LIVE_VALID", "High", "Anthropic API authenticated successfully", True, status)
    if status in (401, 403):
        return LiveValidationResult("anthropic", "NOT_VALID_OR_REVOKED", "Medium", "Anthropic API rejected token", False, status)
    return LiveValidationResult("anthropic", "VALIDATION_INCONCLUSIVE", "Low", "Anthropic validation inconclusive", False, status)


def _validate_stripe(token: str, timeout: int) -> LiveValidationResult:
    encoded = base64.b64encode(f"{token}:".encode("utf-8")).decode("ascii")
    status, _ = _http_request(
        "https://api.stripe.com/v1/account",
        headers={"Authorization": f"Basic {encoded}"},
        timeout=timeout,
    )
    if status == 200:
        return LiveValidationResult("stripe", "LIVE_VALID", "High", "Stripe API authenticated successfully", True, status)
    if status in (401, 403):
        return LiveValidationResult("stripe", "NOT_VALID_OR_REVOKED", "Medium", "Stripe API rejected key", False, status)
    return LiveValidationResult("stripe", "VALIDATION_INCONCLUSIVE", "Low", "Stripe validation inconclusive", False, status)


def _validate_slack(token: str, timeout: int) -> LiveValidationResult:
    status, body = _http_request(
        "https://slack.com/api/auth.test",
        headers={"Authorization": f"Bearer {token}"},
        timeout=timeout,
    )
    compact = body.replace(" ", "").lower()
    if status == 200 and '"ok":true' in compact:
        return LiveValidationResult("slack", "LIVE_VALID", "High", "Slack auth.test succeeded", True, status)
    if status in (200, 401, 403):
        return LiveValidationResult("slack", "NOT_VALID_OR_REVOKED", "Medium", "Slack rejected token", False, status)
    return LiveValidationResult("slack", "VALIDATION_INCONCLUSIVE", "Low", "Slack validation inconclusive", False, status)


def _validate_sendgrid(token: str, timeout: int) -> LiveValidationResult:
    status, _ = _http_request(
        "https://api.sendgrid.com/v3/user/profile",
        headers={"Authorization": f"Bearer {token}"},
        timeout=timeout,
    )
    if status == 200:
        return LiveValidationResult("sendgrid", "LIVE_VALID", "High", "SendGrid API authenticated successfully", True, status)
    if status in (401, 403):
        return LiveValidationResult("sendgrid", "NOT_VALID_OR_REVOKED", "Medium", "SendGrid rejected token", False, status)
    return LiveValidationResult("sendgrid", "VALIDATION_INCONCLUSIVE", "Low", "SendGrid validation inconclusive", False, status)


def _validate_google_api_key(token: str, timeout: int) -> LiveValidationResult:
    encoded_key = urllib.parse.quote(token, safe="")
    status, _ = _http_request(
        f"https://www.googleapis.com/discovery/v1/apis?key={encoded_key}",
        timeout=timeout,
    )
    if status == 200:
        return LiveValidationResult("google_api_key", "LIVE_VALID", "High", "Google API key accepted by discovery API", True, status)
    if status in (400, 401, 403):
        return LiveValidationResult("google_api_key", "NOT_VALID_OR_REVOKED", "Medium", "Google rejected API key", False, status)
    return LiveValidationResult("google_api_key", "VALIDATION_INCONCLUSIVE", "Low", "Google API key validation inconclusive", False, status)


def _unsupported(provider: str) -> LiveValidationResult:
    return LiveValidationResult(
        provider=provider,
        validation_status="VALIDATION_NOT_SUPPORTED",
        confidence="Low",
        evidence="No safe standard-library live validator available for this secret type",
        risk_upgrade=False,
        http_status=None,
    )


VALIDATORS: Dict[str, Callable[[str, int], LiveValidationResult]] = {
    "github": _validate_github,
    "gitlab": _validate_gitlab,
    "openai": _validate_openai,
    "anthropic": _validate_anthropic,
    "stripe": _validate_stripe,
    "slack": _validate_slack,
    "sendgrid": _validate_sendgrid,
    "google_api_key": _validate_google_api_key,
}


def validate_secret_finding_live(
    finding: Dict[str, Any],
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
) -> Dict[str, Any]:
    if not isinstance(finding, dict):
        return {
            "provider": "unknown",
            "validation_status": "INVALID_FINDING_STRUCTURE",
            "confidence": "Low",
            "evidence": "Non-dict finding supplied",
            "risk_upgrade": False,
            "http_status": None,
            "secret_fingerprint": "",
            "validated_at_epoch": int(time.time()),
            "mode": "LIVE_NETWORK_VALIDATION",
        }

    try:
        secret_value = _extract_secret_value(finding)
    except KeyError:
        secret_value = ""

    provider = _detect_provider(finding, secret_value)

    if not secret_value:
        result = LiveValidationResult(
            provider=provider,
            validation_status="NO_SECRET_VALUE_AVAILABLE",
            confidence="Low",
            evidence="Finding does not expose raw secret value to validator",
            risk_upgrade=False,
        )
    elif provider not in VALIDATORS:
        result = _unsupported(provider)
    else:
        result = VALIDATORS[provider](secret_value, timeout)

    return {
        "provider": result.provider,
        "validation_status": result.validation_status,
        "confidence": result.confidence,
        "evidence": result.evidence,
        "risk_upgrade": result.risk_upgrade,
        "http_status": result.http_status,
        "secret_fingerprint": _mask_secret(secret_value),
        "validated_at_epoch": int(time.time()),
        "mode": "LIVE_NETWORK_VALIDATION",
    }


def enrich_findings_with_live_secret_validation(
    findings: List[Dict[str, Any]],
    enabled: bool = False,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
    max_validations: int = DEFAULT_MAX_VALIDATIONS,
) -> Dict[str, Any]:
    findings = findings or []

    if not enabled:
        return {
            "enabled": False,
            "mode": "OFFLINE_ONLY_NOT_VALIDATED",
            "total_secret_findings": len(findings),
            "validated": 0,
            "live_valid": 0,
            "not_valid_or_revoked": 0,
            "inconclusive": 0,
            "unsupported": 0,
            "no_secret_value": 0,
            "errors": 0,
            "max_validations": max_validations,
            "timeout_seconds": timeout,
            "status": "SECRET_LIVE_VALIDATION_DISABLED",
        }

    summary = {
        "enabled": True,
        "mode": "LIVE_NETWORK_VALIDATION",
        "total_secret_findings": len(findings),
        "validated": 0,
        "live_valid": 0,
        "not_valid_or_revoked": 0,
        "inconclusive": 0,
        "unsupported": 0,
        "no_secret_value": 0,
        "errors": 0,
        "max_validations": max_validations,
        "timeout_seconds": timeout,
        "status": "SECRET_LIVE_VALIDATION_COMPLETED",
    }

    target_findings = findings[: max(0, max_validations)]

    # B2-I4: bounded concurrency prevents serial network waits while
    # preserving the existing per-finding validation and status logic.
    worker_count = min(8, max(1, len(target_findings)))

    def _apply_validation_result(finding, validation):
        finding["live_validation"] = validation

        summary["validated"] += 1
        status = validation.get("validation_status")

        if status == "LIVE_VALID":
            summary["live_valid"] += 1
            finding["secret_live_status"] = "LIVE_VALID"
            finding["validated_live"] = True
            finding["validated_active_secret"] = True
            finding["offline_only"] = False
            finding["priority"] = "P0"

            if str(finding.get("severity", "")).lower() not in {"critical"}:
                finding["severity"] = "High"

        elif status == "NOT_VALID_OR_REVOKED":
            summary["not_valid_or_revoked"] += 1
            finding["secret_live_status"] = "NOT_VALID_OR_REVOKED"
            finding["validated_active_secret"] = False

        elif status == "NO_SECRET_VALUE_AVAILABLE":
            summary["no_secret_value"] += 1
            finding["secret_live_status"] = "NO_SECRET_VALUE_AVAILABLE"

        elif status == "VALIDATION_NOT_SUPPORTED":
            summary["unsupported"] += 1
            finding["secret_live_status"] = "VALIDATION_NOT_SUPPORTED"

        else:
            summary["inconclusive"] += 1
            finding["secret_live_status"] = status or "VALIDATION_INCONCLUSIVE"

    def _apply_validation_error(finding, exc):
        finding["live_validation"] = {
            "provider": "unknown",
            "validation_status": "VALIDATION_ERROR",
            "confidence": "Low",
            "evidence": type(exc).__name__,
            "risk_upgrade": False,
            "http_status": None,
            "secret_fingerprint": "",
            "validated_at_epoch": int(time.time()),
            "mode": "LIVE_NETWORK_VALIDATION",
        }
        finding["secret_live_status"] = "VALIDATION_ERROR"
        summary["errors"] += 1

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        future_to_finding = {
            executor.submit(
                validate_secret_finding_live,
                finding,
                max(1, timeout),
            ): finding
            for finding in target_findings
        }

        for future in as_completed(future_to_finding):
            finding = future_to_finding[future]
            try:
                validation = future.result()
                _apply_validation_result(finding, validation)
            except Exception as exc:
                _apply_validation_error(finding, exc)

    if summary["live_valid"] > 0:
        summary["status"] = "LIVE_SECRETS_CONFIRMED"

    return summary


if __name__ == "__main__":
    sample = {
        "rule_id": "TEST_OPENAI_SECRET",
        "title": "OpenAI API key",
        "snippet": "OPENAI_API_KEY=sk-testinvalidplaceholder",
    }
    import json

    print(json.dumps(validate_secret_finding_live(sample, timeout=2), indent=2))
