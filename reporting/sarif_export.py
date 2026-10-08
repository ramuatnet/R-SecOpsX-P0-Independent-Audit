from __future__ import annotations

import json
from pathlib import Path
from typing import Any

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

SUMMARY_KEYS = [
    "reachability_summary", "kev_intelligence_summary", "epss_intelligence_summary",
    "exploitability_decision_summary", "license_policy_summary",
    "copyright_ip_compliance_summary", "supply_chain_trust_summary",
    "runtime_artifact_integrity_summary", "data_flow_sensitivity_summary",
    "data_flow_correlation_summary", "identity_access_risk_summary",
    "identity_access_correlation_summary", "auth_hardening_risk_summary",
    "auth_hardening_correlation_summary", "ai_model_risk_summary",
    "business_logic_risk_summary", "business_logic_correlation_summary",
    "api_abuse_risk_summary", "security_control_coverage_summary",
    "crypto_misuse_summary", "secret_intelligence_summary",
    "secret_blast_radius_correlation_summary", "framework_enrichment_summary",
    "governance_signal_summary", "release_readiness_summary", "executive_decision_summary",
]

def _clean(v: Any) -> Any:
    if isinstance(v, (str, int, float, bool)) or v is None:
        return v
    return json.loads(json.dumps(v, default=str))

def _level(severity: str) -> str:
    sev = str(severity or "").lower()
    if sev in {"critical", "high"}: return "error"
    if sev == "medium": return "warning"
    if sev == "low": return "note"
    return "none"

def _security_severity(finding: dict) -> str:
    if finding.get("cvss") not in (None, "", "N/A", "--"):
        try: return f"{float(finding.get('cvss')):.1f}"
        except Exception: pass
    mapping = {"critical": "9.5", "high": "8.0", "medium": "5.0", "low": "2.0", "info": "0.0"}
    return mapping.get(str(finding.get("severity") or "").lower(), "0.0")

def _rank(severity: str) -> float:
    return {"critical": 95.0, "high": 80.0, "medium": 50.0, "low": 20.0}.get(str(severity or "").lower(), 0.0)

def _rule_id(finding: dict) -> str:
    return str(finding.get("rule_id") or finding.get("vuln_type") or finding.get("title") or "UNKNOWN_RULE").replace(" ", "_").upper()

def _rule_name(finding: dict) -> str:
    return str(finding.get("title") or _rule_id(finding))

def _description(finding: dict) -> str:
    return str(finding.get("description") or finding.get("business_impact") or finding.get("vuln_type") or "")

def _help_text(finding: dict) -> str:
    remediation = finding.get("remediation", "")
    if isinstance(remediation, list): remediation = "\n".join(f"- {x}" for x in remediation)
    parts = []
    for label, key in [("CWE", "cwe"), ("OWASP", "owasp"), ("MITRE", "mitre"), ("PCI DSS", "pci_dss"), ("NIST", "nist"), ("ISO 27001", "iso27001"), ("SOC2", "soc2")]:
        if finding.get(key): parts.append(f"{label}: {finding.get(key)}")
    if finding.get("taint_path"): parts.append(f"Taint path: {finding.get('taint_path')}")
    if finding.get("blast_radius"): parts.append(f"Blast radius: {finding.get('blast_radius')}")
    if remediation: parts.append(f"Remediation:\n{remediation}")
    return "\n\n".join(parts)

def _artifact_uri(finding: dict) -> str:
    return str(finding.get("file") or finding.get("file_path") or finding.get("full_path") or "unknown").replace("\\", "/")

def _line(finding: dict) -> int:
    try: return max(int(finding.get("line") or 1), 1)
    except Exception: return 1

def _message(finding: dict) -> str:
    title = finding.get("title") or _rule_id(finding)
    snippet = finding.get("snippet") or finding.get("evidence") or ""
    return f"{title}: {snippet}" if snippet else str(title)

def _tags(finding: dict) -> list[str]:
    tags = []
    for key in ("cwe", "owasp", "mitre", "vuln_type", "secret_category", "secret_provider"):
        val = finding.get(key)
        if val: tags.append(str(val))
    return tags

# The pipeline's own disposition for a finding. These were computed for every
# finding and previously surfaced in no machine-readable artifact at all.
#
# The absence rule matters more here than in the PDF: SARIF consumers are
# automation. A `false` for "not reportable" would let a CI gate silently drop a
# finding the pipeline never triaged, and an absent value emitted as `true`
# would assert evidence that was never recorded. So an absent value is emitted
# as the string "NOT_RECORDED", never as a boolean.
_NOT_RECORDED = "NOT_RECORDED"

def _decision_properties(finding: dict) -> dict:
    """decision_state / reportable_finding / evidence_valid, absence-safe.

    Returns SARIF `result.properties` entries. Values are stringified so the
    three states (verdict / negative / not recorded) stay distinguishable --
    a boolean here could only ever express two of them.
    """
    out = {
        "decision_state": str(finding.get("decision_state") or _NOT_RECORDED),
        "reportable_finding": (
            str(bool(finding.get("reportable_finding"))).lower()
            if isinstance(finding.get("reportable_finding"), bool)
            else _NOT_RECORDED
        ),
        "evidence_valid": (
            str(bool(finding.get("evidence_valid"))).lower()
            if isinstance(finding.get("evidence_valid"), bool)
            else _NOT_RECORDED
        ),
    }
    for key in ("evidence_state", "evidence_reason", "quality_state", "is_synthetic"):
        val = finding.get(key)
        if val not in (None, "", [], {}):
            out[key] = _clean(val) if not isinstance(val, (str, int, float, bool)) else val
    return out

def _build_rules(findings: list[dict]) -> list[dict]:
    seen, rules = {}, []
    for finding in findings:
        rid = _rule_id(finding)
        if rid in seen: continue
        seen[rid] = True
        rules.append({
            "id": rid,
            "name": _rule_name(finding),
            "shortDescription": {"text": _rule_name(finding)},
            "fullDescription": {"text": _description(finding)},
            "help": {"text": _help_text(finding), "markdown": _help_text(finding)},
            "defaultConfiguration": {"level": _level(finding.get("severity")), "rank": _rank(finding.get("severity"))},
            "properties": {
                "precision": finding.get("confidence") or finding.get("confidence_label") or "medium",
                "problem.severity": finding.get("severity"),
                "security-severity": _security_severity(finding),
                "priority": finding.get("priority"),
                "confidence": finding.get("confidence"),
                "vuln_type": finding.get("vuln_type"),
                "cwe": finding.get("cwe"), "owasp": finding.get("owasp"), "mitre": finding.get("mitre"),
                "tags": _tags(finding),
            },
        })
    return rules

def _related_locations(finding: dict) -> list[dict]:
    locs = []
    for fp in finding.get("affected_files", []) or []:
        locs.append({"physicalLocation": {"artifactLocation": {"uri": str(fp).replace("\\", "/")}}})
    return locs

def _build_results(findings: list[dict]) -> list[dict]:
    results = []
    for finding in findings:
        res = {
            "ruleId": _rule_id(finding),
            "level": _level(finding.get("severity")),
            "message": {"text": _message(finding)},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": _artifact_uri(finding)}, "region": {"startLine": _line(finding)}}}],
            "partialFingerprints": {
                "primaryLocationLineHash": f"{_artifact_uri(finding)}:{_line(finding)}:{_rule_id(finding)}",
            },
            "properties": {
                "severity": finding.get("severity"), "priority": finding.get("priority"),
                "risk_score": finding.get("risk_score"), "confidence": finding.get("confidence"),
                "vuln_type": finding.get("vuln_type"), "issue_group": finding.get("issue_group"),
                "taint_path": finding.get("taint_path"), "framework_mappings": finding.get("framework_mappings"),
                "secret_category": finding.get("secret_category"), "secret_provider": finding.get("secret_provider"),
                "blast_radius": finding.get("blast_radius"), "correlation_evidence": finding.get("correlation_evidence"),
                "reachability_status": finding.get("reachability_status"), "kev_status": finding.get("kev_status"),
                "epss_score": finding.get("epss_score"), "release_gate": finding.get("release_gate"),
            },
        }
        # Disposition, merged in so it cannot be silently omitted by a later
        # edit to the literal above.
        res["properties"].update(_decision_properties(finding))
        related = _related_locations(finding)
        if related: res["relatedLocations"] = related
        results.append(res)
    return results

def _run_properties(payload: dict) -> dict:
    props = {"tool": "R-SecOpsX", "report_type": "SARIF", "schema_maturity": "SARIF_HARDENED_PHASE6"}
    rr = payload.get("release_readiness", {}) or {}
    ed = payload.get("executive_decision", {}) or {}
    md = payload.get("metadata", {}) or {}
    props["release_decision"] = rr.get("release_decision") or md.get("release_decision") or "UNKNOWN"
    props["executive_decision"] = ed.get("executive_decision") or md.get("executive_decision") or "UNKNOWN"
    for key in SUMMARY_KEYS:
        if payload.get(key) not in (None, {}, [], ""):
            props[key] = _clean(payload.get(key))
    return props

def build_sarif(payload: dict) -> dict:
    findings = payload.get("findings") or payload.get("grouped") or []
    metadata = payload.get("metadata", {}) or {}
    release_readiness = payload.get("release_readiness", {}) or {}
    executive_decision_obj = payload.get("executive_decision", {}) or {}
    canonical_release_decision = (release_readiness.get("release_decision") or metadata.get("release_decision") or "UNKNOWN")
    canonical_executive_decision = (executive_decision_obj.get("executive_decision") or metadata.get("executive_decision") or "UNKNOWN")
    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {"driver": {"name": "R-SecOpsX", "informationUri": "https://r-secopsx.local", "semanticVersion": "2.0.0", "rules": _build_rules(findings)}},
            "automationDetails": {"id": "rsecopsx-sast-scan"},
            "invocations": [{"executionSuccessful": True, "properties": {"total_findings": metadata.get("total_findings"), "risk_score": metadata.get("risk_score"), "executive_decision": canonical_executive_decision, "release_decision": canonical_release_decision, "framework_mapping_status": metadata.get("framework_mapping_status")}}],
            "results": _build_results(findings),
            "properties": _run_properties(payload),
        }],
    }

def write_sarif_report(payload: dict, output_path: str) -> str:
    sarif = build_sarif(payload)
    out = Path(output_path); out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as f: json.dump(sarif, f, indent=2, default=str)
    return str(out)
