from __future__ import annotations

from typing import Any

from .rule_contract import (
    CONTRACT_VERSION,
    QUALITY_CLASSIFICATIONS,
    RULE_MODES,
)

_ENGINE_MODE = {
    "scanner.sast": "SEARCH",
    "scanner.taint_engine": "TAINT",
    "scanner.secret_intelligence": "SECRET",
    "analysis.api_abuse_engine": "POLICY",
    "analysis.data_flow_correlation_engine": "CORRELATION",
}


def _text(value: Any) -> str:
    return str(value).strip() if value is not None else ""


def _list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return [value]


def _language(finding: dict[str, Any]) -> list[str]:
    value = finding.get("languages")

    if value:
        return [str(x) for x in _list(value) if str(x).strip()]

    value = finding.get("language")

    if value:
        return [str(value)]

    return []


def _mode(finding: dict[str, Any]) -> str:
    explicit = _text(finding.get("mode")).upper()

    if explicit in RULE_MODES:
        return explicit

    engine = _text(finding.get("engine")).lower()

    if engine in _ENGINE_MODE:
        return _ENGINE_MODE[engine]

    detection = _text(finding.get("detection")).lower()

    if "taint" in detection:
        return "TAINT"

    if "secret" in detection:
        return "SECRET"

    if "correlation" in detection:
        return "CORRELATION"

    if "api abuse" in detection or "policy" in detection:
        return "POLICY"

    return "SEARCH"


def _paths(finding: dict[str, Any]) -> list[str]:
    value = finding.get("paths")

    if value:
        return [str(x) for x in _list(value) if str(x).strip()]

    file_value = _text(finding.get("file"))

    if file_value:
        return [file_value]

    return []


def _evidence_types(finding: dict[str, Any]) -> list[str]:
    explicit = finding.get("evidence_types")

    if explicit:
        return [str(x) for x in _list(explicit) if str(x).strip()]

    types = []

    if finding.get("evidence"):
        types.append("CODE_EVIDENCE")

    if finding.get("taint_path"):
        types.append("TAINT_PATH")

    if finding.get("source") or finding.get("source_expr"):
        types.append("SOURCE")

    if finding.get("sink") or finding.get("sink_call"):
        types.append("SINK")

    if finding.get("route"):
        types.append("ROUTE_CONTEXT")

    if finding.get("evidence_valid") is not None:
        types.append("EVIDENCE_VALIDATION")

    return sorted(set(types))


def _provenance(finding: dict[str, Any]) -> dict[str, Any]:
    existing = finding.get("provenance")

    if isinstance(existing, dict):
        return dict(existing)

    result = {}

    for key in (
        "engine",
        "detection",
        "source_type",
        "scanner",
        "evidence_source",
    ):
        value = finding.get(key)

        if value not in (None, ""):
            result[key] = value

    return result


def _dataflow(finding: dict[str, Any]) -> dict[str, Any]:
    result = {}

    for key in (
        "sources",
        "propagators",
        "sanitizers",
        "sinks",
    ):
        if key in finding and finding[key] is not None:
            result[key] = _list(finding[key])

    if not result.get("sources"):
        source = finding.get("source") or finding.get("source_expr")

        if source:
            result["sources"] = [source]

    if not result.get("sinks"):
        sink = finding.get("sink") or finding.get("sink_call")

        if sink:
            result["sinks"] = [sink]

    return result


def adapt_finding(finding: dict[str, Any]) -> dict[str, Any]:
    """
    V10 -> V11 Unified Rule Contract adapter.

    Non-authoritative adapter:
      - preserves existing finding values
      - does not change severity
      - does not manufacture security evidence
      - does not classify TP/FP
      - does not promote confidence
      - does not make RCMSP decisions
    """

    if not isinstance(finding, dict):
        return finding

    f = dict(finding)

    rule_id = _text(f.get("rule_id"))

    if not rule_id:
        vuln = _text(f.get("vuln_type")).lower()
        rule_id = (
            vuln.upper().replace("-", "_").replace(" ", "_")
            or "UNKNOWN"
        )

    title = _text(f.get("title")) or rule_id
    description = _text(f.get("description"))
    mode = _mode(f)
    languages = _language(f)
    paths = _paths(f)

    rule = {
        "rule_id": rule_id,
        "rule_version": _text(f.get("rule_version")) or "V10_ADAPTER",
        "title": title,
        "description": description,
        "mode": mode,
        "languages": languages,
        "paths": paths,
    }

    security = {
        "severity": f.get("severity"),
        "confidence": f.get("confidence"),
        "cwe": f.get("cwe"),
        "owasp": f.get("owasp"),
        "mitre": f.get("mitre"),
        "remediation": f.get("remediation"),
        "references": f.get("references"),
    }

    evidence = {
        "evidence_requirements": f.get("evidence_requirements"),
        "required_evidence": f.get("required_evidence"),
        "evidence_types": _evidence_types(f),
        "provenance": _provenance(f),
    }

    quality = {
        "fp_indicators": _list(f.get("fp_indicators")),
        "noise_categories": _list(f.get("noise_categories")),
        "suppression_policy": f.get("suppression_policy"),
    }

    dataflow = _dataflow(f)

    f["rule_contract_version"] = CONTRACT_VERSION
    f["rule_contract"] = rule
    f["rule_security"] = security
    f["rule_evidence"] = evidence
    f["rule_quality"] = quality
    f["rule_dataflow"] = dataflow

    quality_state = f.get("quality_state")

    if not isinstance(quality_state, dict):
        quality_state = {}

    quality_state.setdefault("classification", "UNCLASSIFIED")
    quality_state.setdefault("fp_status", "NOT_ASSESSED")
    quality_state.setdefault("noise_status", "NOT_ASSESSED")
    quality_state.setdefault("suppression_status", "NOT_SUPPRESSED")
    quality_state.setdefault("benchmark_status", "NOT_ADJUDICATED")

    if quality_state["classification"] not in QUALITY_CLASSIFICATIONS:
        quality_state["classification"] = "UNCLASSIFIED"

    f["quality_state"] = quality_state

    return f


def adapt_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        adapt_finding(f)
        for f in findings
        if isinstance(f, dict)
    ]
