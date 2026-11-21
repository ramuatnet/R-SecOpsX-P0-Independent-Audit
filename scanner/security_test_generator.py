"""
Feature 9 - Security Test Generation Intelligence.

Generates deterministic security-test blueprints from existing findings.
It does not execute tests, alter source, or claim exploitability.
"""

from __future__ import annotations

from copy import deepcopy
import re
from typing import Any, Dict, Tuple


def _normalize_path(path: str) -> str:
    """Normalize file paths across Windows/Linux representations."""
    text = str(path or "").replace("\\", "/").strip()
    while text.startswith("./"):
        text = text[2:]
    return text


def _get_framework_harness(path: str) -> str:
    """Infer a reasonable test harness from the target file extension."""
    ext = path.rsplit(".", 1)[-1].lower() if "." in path else ""
    harness_map = {
        "py": "pytest",
        "js": "jest / mocha",
        "jsx": "jest / mocha",
        "ts": "jest / vitest",
        "tsx": "jest / vitest",
        "go": "go test",
        "java": "junit",
        "cs": "nunit / xunit",
        "rb": "rspec",
        "php": "phpunit",
    }
    return harness_map.get(ext, "generic_unit_test")


def _has_cwe(cwe: str, number: str) -> bool:
    value = str(cwe or "").upper()
    return bool(re.search(rf"\bCWE[-_: ]?{re.escape(number)}\b", value))


def _derive_blueprint_strategy(rule: str, cwe: str) -> Tuple[str, str, str]:
    """
    Derive a conservative test strategy from rule/CWE evidence.

    This creates a blueprint only. It does not prove exploitability,
    remediation, or execution.
    """
    rule_upper = str(rule or "").upper()

    if "SECRET" in rule_upper or _has_cwe(cwe, "798"):
        return (
            "SECRET_REMOVAL_VALIDATION",
            "Assert target file contains no hardcoded credential or secret strings",
            "Replace secret with dynamic configuration or environment-variable lookup before testing",
        )

    if "SQL" in rule_upper or _has_cwe(cwe, "89"):
        return (
            "SQL_INJECTION_PREVENTION",
            "Assert SQL query parameters are bound safely using parameterized placeholders or ORM",
            "Mock database connections and verify raw string concatenation is not performed",
        )

    if "XSS" in rule_upper or _has_cwe(cwe, "79"):
        return (
            "XSS_OUTPUT_ENCODING",
            "Assert untrusted input is context-encoded or sanitized before rendering",
            "Supply a controlled HTML/script payload and verify the resulting output is safely encoded",
        )

    if "PATH" in rule_upper or _has_cwe(cwe, "22"):
        return (
            "PATH_TRAVERSAL_PREVENTION",
            "Assert relative path traversal sequences are rejected or canonicalized",
            "Supply controlled traversal input and verify sandbox-directory confinement",
        )

    return (
        "GENERIC_SECURITY_REGRESSION",
        "Finding condition should remain detectable or explicitly be remediated",
        "Verify input sanitization, safe API usage, and non-vulnerable output handling",
    )


def generate_security_test_blueprints(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generate deterministic blueprints without mutating the caller's payload.

    Contract:
      - read-only with respect to source files
      - no test execution
      - no exploitability claim
      - one blueprint per valid finding
      - deterministic ordering
    """
    result = deepcopy(payload)
    findings = result.get("findings", []) or []
    rows = []

    for i, finding in enumerate(findings):
        if not isinstance(finding, dict):
            continue

        finding_id = str(
            finding.get("finding_uid")  # B3-ID Phase B Wave 2 prepend (contract §6.2 #3)
            or finding.get("finding_id")
            or finding.get("id")
            or f"FINDING_{i + 1:06d}"  # positional fallback retained for legacy inputs
        )

        rule = str(
            finding.get("rule_id")
            or finding.get("rule")
            or finding.get("category")
            or "SECURITY_FINDING"
        )

        cwe = str(finding.get("cwe") or finding.get("cwe_id") or "")

        target_file = _normalize_path(
            finding.get("file")
            or finding.get("path")
            or finding.get("source_file")
            or ""
        )

        strategy, assertion, setup_guidance = _derive_blueprint_strategy(
            rule,
            cwe,
        )

        rows.append(
            {
                "finding_id": finding_id,
                "test_id": f"SEC-TEST-{finding_id}",
                "rule": rule,
                "cwe": cwe,
                "target_file": target_file,
                "test_type": "REGRESSION_SECURITY_TEST_BLUEPRINT",
                "test_strategy": strategy,
                "suggested_harness": _get_framework_harness(target_file),
                "assertion": assertion,
                "setup_guidance": setup_guidance,
                "execution_performed": False,
                "synthetic_test_created": False,
            }
        )

    rows.sort(key=lambda row: row["test_id"])

    result["security_test_generation"] = {
        "status": "AVAILABLE" if rows else "UNAVAILABLE",
        "blueprints": rows,
        "summary": {"blueprints": len(rows)},
        "execution_performed": False,
        "source_modified": False,
        "read_only": True,
    }

    return result
