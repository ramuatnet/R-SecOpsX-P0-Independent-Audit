from __future__ import annotations

from typing import Any

CONTRACT_VERSION = "1.0"

RULE_MODES = {
    "SEARCH",
    "STRUCTURAL",
    "DATAFLOW",
    "TAINT",
    "SECRET",
    "CORRELATION",
    "POLICY",
}

QUALITY_CLASSIFICATIONS = {
    "UNCLASSIFIED",
    "TRUE_POSITIVE",
    "FALSE_POSITIVE",
    "INTENTIONAL",
    "UNCONFIRMED",
}

CONTRACT_GROUPS = {
    "core": (
        "rule_id",
        "rule_version",
        "title",
        "description",
        "mode",
        "languages",
        "paths",
    ),
    "security": (
        "severity",
        "confidence",
        "cwe",
        "owasp",
        "mitre",
        "remediation",
        "references",
    ),
    "evidence": (
        "evidence_requirements",
        "required_evidence",
        "evidence_types",
        "provenance",
    ),
    "quality": (
        "fp_indicators",
        "noise_categories",
        "suppression_policy",
    ),
    "dataflow": (
        "sources",
        "propagators",
        "sanitizers",
        "sinks",
    ),
}


def empty_contract() -> dict[str, Any]:
    return {
        "contract_version": CONTRACT_VERSION,
        "rule": {},
        "security": {},
        "evidence": {},
        "quality": {},
        "dataflow": {},
    }
