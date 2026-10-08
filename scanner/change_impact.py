"""
Feature 5 — Change Impact Analysis.
Builds deterministic file/module impact evidence from changed files and existing
finding/dependency references. It does not claim runtime reachability.
"""
from __future__ import annotations

from typing import Any, Dict


def _path(v: Any) -> str:
    """Return a deterministic, non-empty path representation.

    Normalize separators and remove only explicit leading ``./`` path prefixes;
    do not use ``lstrip`` because it strips characters rather than components.
    Absolute paths are intentionally preserved because path policy is a caller
    concern and silently converting them to relative paths can break identity.
    """
    if v is None:
        return ""
    p = str(v).replace("\\", "/").strip()
    while p.startswith("./"):
        p = p[2:]
    return p


def enrich_change_impact(payload: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        return payload

    ci = payload.get("change_intelligence") or {}
    files_list = ci.get("files", []) if isinstance(ci, dict) else []

    changed = sorted(
        {
            _path(x.get("path"))
            for x in files_list
            if isinstance(x, dict) and x.get("path") and _path(x.get("path"))
        }
    )

    finding_refs: Dict[str, int] = {}
    for f in payload.get("findings", []) or []:
        if not isinstance(f, dict):
            continue
        filepath = f.get("file") or f.get("path") or f.get("source_file")
        p = _path(filepath)
        if p:
            finding_refs[p] = finding_refs.get(p, 0) + 1

    impacted = [
        {
            "path": p,
            "direct_finding_count": int(finding_refs.get(p, 0)),
            "impact_basis": "CHANGED_FILE",
            "runtime_impact_verified": False,
        }
        for p in changed
    ]

    ci_status = ci.get("status") if isinstance(ci, dict) else None

    # Preserve previously enriched change_impact metadata and update only
    # Feature-5-owned fields.
    change_impact_data = payload.get("change_impact")
    if not isinstance(change_impact_data, dict):
        change_impact_data = {}

    change_impact_data.update({
        "status": "AVAILABLE" if ci_status == "AVAILABLE" else "UNAVAILABLE",
        "changed_files": impacted,
        "summary": {
            "changed_files": len(impacted),
            "files_with_findings": sum(
                1 for x in impacted if x["direct_finding_count"] > 0
            ),
        },
        "read_only": True,
        "runtime_reachability_inferred": False,
    })

    payload["change_impact"] = change_impact_data
    return payload
