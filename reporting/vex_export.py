from __future__ import annotations

import json
import uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from analysis.intelligence_provenance import NOT_AVAILABLE, STATIC_REFERENCE

VEX_VERSION = "1.1"

def _component_ref(pkg: dict) -> str:
    name = str(pkg.get("name") or "unknown")
    version = str(pkg.get("version") or "unknown")
    ecosystem = str(pkg.get("ecosystem") or "unknown").lower()
    return (pkg.get("purl") or f"pkg:{ecosystem}/{name}@{version}").replace(" ", "_")

def _vulnerability_id(pkg: dict) -> str | None:
    return pkg.get("cve") or pkg.get("primary_vulnerability_id") or pkg.get("advisory_id")

def _source(vuln_id: str) -> str:
    return "NVD" if vuln_id.startswith("CVE-") else "GitHub Advisory" if vuln_id.startswith("GHSA-") else "R-SecOpsX"

def _norm(value) -> str:
    return str(value or "").strip().upper()

def _reachability_status(pkg: dict) -> str:
    return str(pkg.get("reachability_priority") or pkg.get("reachability_status") or "UNKNOWN")

def _vex_status(pkg: dict) -> str:
    explicit = _norm(pkg.get("vex_status") or pkg.get("status"))
    if explicit in {"AFFECTED", "NOT_AFFECTED", "UNDER_INVESTIGATION", "FIXED"}:
        return explicit.lower()
    if _norm(pkg.get("accepted_risk")) in {"TRUE", "YES", "ACCEPTED"}:
        return "affected"
    if _norm(pkg.get("mitigation_status")) in {"MITIGATED", "COMPENSATING_CONTROL"}:
        return "affected"
    priority = _norm(pkg.get("reachability_priority")); reachable = _norm(pkg.get("reachability_status"))
    kev = bool(pkg.get("kev_status")); epss_priority = _norm(pkg.get("epss_priority"))
    if priority in {"REACHABLE_VULNERABLE", "P0_REACHABLE"} or reachable == "REACHABLE": return "affected"
    if priority == "NOT_OBSERVED_VULNERABLE": return "under_investigation"
    if kev or epss_priority == "P0_IMMEDIATE": return "under_investigation"
    return "not_affected"

def _justification(pkg: dict) -> str:
    if pkg.get("fixed_in") and _vex_status(pkg) == "fixed": return "component_fixed"
    st = _vex_status(pkg)
    if st == "affected":
        if _norm(pkg.get("mitigation_status")) in {"MITIGATED", "COMPENSATING_CONTROL"}: return "protected_by_mitigating_control"
        if _norm(pkg.get("accepted_risk")) in {"TRUE", "YES", "ACCEPTED"}: return "risk_accepted"
        return "reachable_code"
    if st == "under_investigation": return "insufficient_runtime_evidence"
    return "vulnerable_code_not_in_execute_path"

def _impact_statement(pkg: dict) -> str:
    st = _vex_status(pkg)
    if st == "fixed": return "R-SecOpsX marks this vulnerability as fixed based on fixed_in or explicit VEX status evidence."
    if st == "affected": return "R-SecOpsX determined this vulnerable component is reachable, exploitable, mitigated, or formally accepted and requires tracked remediation or exception handling."
    if st == "under_investigation": return "R-SecOpsX found vulnerability evidence, but reachability or exploitability could not be conclusively established."
    return "R-SecOpsX did not observe reachable usage evidence for this vulnerable component in the current scan context."

def _action_statement(pkg: dict) -> str:
    if _vex_status(pkg) == "fixed": return "Verify fixed version in build artifact and close exception after re-scan."
    if _norm(pkg.get("patch_urgency")) == "IMMEDIATE" or _norm(pkg.get("epss_priority")) == "P0_IMMEDIATE": return "Apply patch immediately or obtain formal executive exception."
    if _vex_status(pkg) == "affected": return "Prioritize remediation according to severity, reachability, KEV, EPSS, and release gate decision."
    if _vex_status(pkg) == "under_investigation": return "Review component usage, exposure, and exploitability evidence before approving release."
    return "No immediate action required unless deployment context changes."

def _statement(pkg: dict) -> dict | None:
    vuln_id = _vulnerability_id(pkg)
    if not vuln_id: return None
    status = _vex_status(pkg)
    return {
        "vulnerability": {"id": str(vuln_id), "source": _source(str(vuln_id))},
        "product": {"component": str(pkg.get("name") or "unknown"), "version": str(pkg.get("version") or "unknown"), "ecosystem": str(pkg.get("ecosystem") or "unknown"), "bom_ref": _component_ref(pkg), "purl": pkg.get("purl")},
        "status": status,
        "justification": _justification(pkg),
        "impact_statement": _impact_statement(pkg),
        "action_statement": _action_statement(pkg),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "properties": {
            "reachability_status": _reachability_status(pkg), "reachability_confidence": pkg.get("reachability_confidence"),
            "kev_status": pkg.get("kev_status"), "actively_exploited": pkg.get("actively_exploited"), "outbreak_status": pkg.get("outbreak_status"),
            "patch_urgency": pkg.get("patch_urgency"), "epss_score": pkg.get("epss_score") or pkg.get("epss"), "epss_bucket": pkg.get("epss_bucket"), "epss_priority": pkg.get("epss_priority"),
            # G-003: VEX consumers are integrations; they must be able to tell an
            # offline STATIC_REFERENCE snapshot from a live feed without parsing
            # the free-text summary_status.
            "epss_provenance": pkg.get("epss_provenance") or NOT_AVAILABLE,
            "kev_provenance": pkg.get("kev_provenance") or STATIC_REFERENCE,
            "severity": pkg.get("severity"), "cvss": pkg.get("cvss"), "advisory_id": pkg.get("advisory_id"), "cve": pkg.get("cve"),
            # Which standard produced a score, carried alongside the legacy
            # scalar rather than merged into it: `cvss` ships byte-for-byte
            # as before, so a consumer reading only that key sees exactly
            # what it saw before. These three identify the preferred
            # assessment -- the one PDF, Excel and CycloneDX show -- so no
            # surface can be reading a different assessment from another.
            "cvss_version": pkg.get("cvss_version"), "cvss_vector": pkg.get("cvss_vector"), "cvss_preferred_score": pkg.get("cvss_preferred_score"),
            "fixed_in": pkg.get("fixed_in"), "accepted_risk": pkg.get("accepted_risk"), "mitigation_status": pkg.get("mitigation_status"),
            "release_gate": pkg.get("release_gate"), "exploitability_decision": pkg.get("exploitability_decision"),
        },
    }

def build_vex(payload: dict) -> dict:
    sbom = payload.get("sbom", []) or []
    metadata = payload.get("metadata", {}) or {}
    statements = [stmt for stmt in (_statement(pkg) for pkg in sbom) if stmt]
    counts = Counter(stmt["status"] for stmt in statements)
    return {
        "document": {"type": "R-SecOpsX VEX", "version": VEX_VERSION, "id": f"urn:uuid:{uuid.uuid4()}", "created": datetime.now(timezone.utc).isoformat(), "author": "R-SecOpsX", "profile": "RSECOpsX_VEX_REACHABILITY_KEV_EPSS_RELEASE_GATE"},
        "metadata": {
            "total_statements": len(statements), "status_counts": dict(counts),
            "risk_score": metadata.get("risk_score"), "executive_decision": metadata.get("executive_decision"),
            "release_decision": (metadata.get("release_decision") or metadata.get("canonical_release_decision") or metadata.get("release_readiness_decision") or metadata.get("executive_decision")), "reachability_summary": payload.get("reachability_summary"),
            "vulnerability_age_summary": payload.get("vulnerability_age_summary"), "epss_intelligence_summary": payload.get("epss_intelligence_summary"),
            "kev_intelligence_summary": payload.get("kev_intelligence_summary"), "exploitability_decision_summary": payload.get("exploitability_decision_summary"),
            "release_readiness_summary": payload.get("release_readiness_summary"),
        },
        "statements": statements,
    }

def write_vex_report(payload: dict, output_path: str) -> str:
    vex = build_vex(payload)
    out = Path(output_path); out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as f: json.dump(vex, f, indent=2, default=str)
    return str(out)
