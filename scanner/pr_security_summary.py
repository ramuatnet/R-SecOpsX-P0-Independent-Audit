"""
Feature 8 — PR Security Summary.
Aggregates existing evidence without inventing risk or lifecycle conclusions.
"""
from __future__ import annotations
from typing import Any, Dict

def enrich_pr_security_summary(payload: Dict[str, Any]) -> Dict[str, Any]:
    ci=payload.get("change_intelligence") or {}
    cl=payload.get("changed_line_security") or {}
    li=payload.get("finding_lifecycle") or {}
    impact=payload.get("change_impact") or {}
    cov=payload.get("security_test_coverage") or {}
    payload["pr_security_summary"]={
        "status":"AVAILABLE" if ci.get("status")=="AVAILABLE" else "PARTIAL",
        "change":ci.get("summary",{}),
        "changed_line_findings":cl.get("summary",{}),
        "finding_lifecycle":li.get("summary",{}),
        "change_impact":impact.get("summary",{}),
        "security_test_coverage":cov.get("summary",{}),
        "limitations":[
            "Lifecycle states require baseline evidence.",
            "Candidate test files do not prove semantic security coverage.",
            "Change impact is static evidence and does not establish runtime reachability.",
            "No severity, exploitability, risk, or decision state is changed by this summary."
        ],
        "read_only":True,
    }
    return payload
