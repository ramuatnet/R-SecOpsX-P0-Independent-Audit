"""
Feature 12 — Fix/Patch Generation Intelligence.

Produces remediation guidance and patch blueprints.
Does NOT automatically modify source code.

Design principles:
- Read-only
- Deep-copy input protection
- Deterministic finding identity
- Rule/category normalization
- Granular remediation blueprints
- Human review required
- No automatic source modification
"""

from __future__ import annotations

import hashlib
import re
from copy import deepcopy
from typing import Any, Dict, List


BLUEPRINT_MAP = {
    "sql_injection": (
        "Use parameterized queries or prepared statements "
        "(for example ORM query parameters or PreparedStatement) "
        "instead of raw SQL string concatenation."
    ),
    "hardcoded_secret": (
        "Extract credentials, API keys, tokens, and other secrets "
        "into an approved secrets manager or protected environment configuration."
    ),
    "command_injection": (
        "Avoid shell execution with untrusted input. "
        "Use safe process invocation APIs with explicit argument lists "
        "and validate allowed input values."
    ),
    "ssrf": (
        "Validate outbound URLs using strict allowlists and block "
        "loopback, link-local, RFC1918/private, and other internal destinations."
    ),
    "xss": (
        "Apply context-aware output encoding before rendering untrusted data. "
        "Use framework-native escaping and avoid unsafe HTML/script sinks."
    ),
    "vulnerable_dependency": (
        "Upgrade the vulnerable dependency to a safe version identified "
        "by the applicable vendor advisory or validated remediation source."
    ),
    "insecure_configuration": (
        "Replace insecure configuration with secure defaults, "
        "restrict exposed services and permissions, and enforce the applicable "
        "security baseline."
    ),
    "path_traversal": (
        "Validate and canonicalize user-controlled paths and ensure resolved "
        "paths remain within the intended application directory."
    ),
    "idor": (
        "Enforce server-side authorization checks against the authenticated "
        "user or service identity before accessing the requested object."
    ),
    "weak_cryptography": (
        "Replace deprecated or weak cryptographic algorithms with approved "
        "modern algorithms and secure key-management practices."
    ),
}


RULE_ALIASES = {
    "sqli": "sql_injection",
    "sqlinjection": "sql_injection",
    "sql_injection": "sql_injection",
    "sql-injection": "sql_injection",
    "cwe89": "sql_injection",
    "cwe-89": "sql_injection",

    "hardcodedsecret": "hardcoded_secret",
    "hardcoded_secret": "hardcoded_secret",
    "hardcoded-secret": "hardcoded_secret",
    "hardcoded_credentials": "hardcoded_secret",
    "secret_detection": "hardcoded_secret",
    "secret": "hardcoded_secret",

    "commandinjection": "command_injection",
    "command_injection": "command_injection",
    "command-injection": "command_injection",
    "cwe78": "command_injection",
    "cwe-78": "command_injection",

    "ssrf": "ssrf",
    "server_side_request_forgery": "ssrf",
    "server-side-request-forgery": "ssrf",

    "xss": "xss",
    "cross_site_scripting": "xss",
    "cross-site-scripting": "xss",
    "cwe79": "xss",
    "cwe-79": "xss",

    "vulnerabledependency": "vulnerable_dependency",
    "vulnerable_dependency": "vulnerable_dependency",
    "vulnerable-dependency": "vulnerable_dependency",
    "dependency_vulnerability": "vulnerable_dependency",
    "dependency-vulnerability": "vulnerable_dependency",

    "insecureconfiguration": "insecure_configuration",
    "insecure_configuration": "insecure_configuration",
    "insecure-configuration": "insecure_configuration",

    "pathtraversal": "path_traversal",
    "path_traversal": "path_traversal",
    "path-traversal": "path_traversal",
    "cwe22": "path_traversal",
    "cwe-22": "path_traversal",

    "idor": "idor",
    "insecure_direct_object_reference": "idor",

    "weakcryptography": "weak_cryptography",
    "weak_cryptography": "weak_cryptography",
    "weak-cryptography": "weak_cryptography",
}


def _normalize_rule(rule: Any) -> str:
    """
    Normalize scanner rule/category identifiers into a stable lookup key.
    """
    if not rule:
        return ""

    value = str(rule).strip().lower()

    value = value.replace("/", "_")
    value = value.replace(" ", "_")
    value = value.replace(".", "_")

    value = re.sub(r"[^a-z0-9_-]", "_", value)
    value = re.sub(r"_+", "_", value)
    value = value.strip("_")

    return RULE_ALIASES.get(value, value)


def _get_blueprint(rule: Any) -> str:
    """
    Return the most specific remediation blueprint available.
    """
    normalized = _normalize_rule(rule)

    if normalized in BLUEPRINT_MAP:
        return BLUEPRINT_MAP[normalized]

    for key, blueprint in BLUEPRINT_MAP.items():
        if key in normalized:
            return blueprint

    return "REVIEW_FINDING_AND_APPLY_CONTEXT_APPROPRIATE_FIX"


def _target_file(finding: Dict[str, Any]) -> str:
    """
    Resolve the most useful source-file identifier.
    """
    value = (
        finding.get("file")
        or finding.get("path")
        or finding.get("source_file")
        or finding.get("filename")
        or ""
    )

    return str(value).replace("\\", "/").strip()


def _finding_rule(finding: Dict[str, Any]) -> str:
    """
    Resolve the strongest available rule/category identifier.
    """
    return str(
        finding.get("rule_id")
        or finding.get("rule")
        or finding.get("category")
        or finding.get("vulnerability_type")
        or "SECURITY_FINDING"
    ).strip()


def _finding_location(finding: Dict[str, Any]) -> str:
    """
    Produce a stable location component for deterministic identity.
    """
    for key in ("line", "start_line", "line_number"):
        value = finding.get(key)

        if value is not None:
            text = str(value).strip()

            if text:
                return text

    return ""


def _deterministic_finding_id(finding: Dict[str, Any]) -> str:
    """
    Preserve an existing finding ID when available.

    Otherwise derive a stable ID from rule + target file + location +
    message/description. This avoids positional IDs that change when
    finding ordering changes.
    """
    existing = str(
        finding.get("finding_id")
        or finding.get("id")
        or ""
    ).strip()

    if existing:
        return existing

    rule = _finding_rule(finding)
    target_file = _target_file(finding)
    location = _finding_location(finding)

    message = str(
        finding.get("message")
        or finding.get("description")
        or finding.get("title")
        or ""
    ).strip()

    identity_material = "|".join(
        [
            rule,
            target_file,
            location,
            message,
        ]
    )

    if not identity_material.strip("|"):
        return "FINDING_UNKNOWN"

    digest = hashlib.sha256(
        identity_material.encode("utf-8")
    ).hexdigest()[:12].upper()

    return f"FINDING_{digest}"


def enrich_fix_patch_intelligence(
    payload: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Enrich a report payload with remediation intelligence.

    The original payload is never modified.
    """
    if not isinstance(payload, dict):
        return payload

    result = deepcopy(payload)

    findings = result.get("findings", [])

    if not isinstance(findings, list):
        findings = []

    rows: List[Dict[str, Any]] = []

    for finding in findings:
        if not isinstance(finding, dict):
            continue

        fid = _deterministic_finding_id(finding)
        rule = _finding_rule(finding)
        target_file = _target_file(finding)

        normalized_rule = _normalize_rule(rule)

        rows.append(
            {
                "finding_id": fid,
                "rule": rule,
                "normalized_rule": normalized_rule,
                "target_file": target_file,
                "remediation_blueprint": _get_blueprint(rule),
                "patch_generated": False,
                "source_modified": False,
                "human_review_required": True,
            }
        )

    rows.sort(
        key=lambda x: (
            x["target_file"],
            x["normalized_rule"],
            x["finding_id"],
        )
    )

    result["fix_patch_intelligence"] = {
        "status": "AVAILABLE",
        "remediation_blueprints": rows,
        "summary": {
            "findings": len(rows),
            "patches_generated": 0,
        },
        "read_only": True,
        "automatic_source_modification": False,
    }

    return result
