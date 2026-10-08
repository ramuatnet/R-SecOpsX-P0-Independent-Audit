"""
Feature 11 — Malicious Package Intelligence Enhancement.

Adds evidence aggregation for package reputation/advisory indicators already
present in SBOM/dependency records. No package is labeled malicious solely
because an indicator is absent or because it is undeclared.
"""
from __future__ import annotations
from typing import Any, Dict

def enrich_malicious_package_intelligence(payload: Dict[str, Any]) -> Dict[str, Any]:
    sbom=payload.get("sbom",[]) or []
    rows=[]
    for p in sbom:
        if not isinstance(p,dict): continue
        indicators=[]
        for key in ("malicious","malware","reputation","typosquat","suspicious",
                    "known_malicious","package_risk","advisory"):
            if p.get(key) not in (None,"",False,[]):
                indicators.append({"field":key,"value":p.get(key)})
        rows.append({
            "package":str(p.get("name") or p.get("package") or p.get("component") or ""),
            "ecosystem":str(p.get("ecosystem") or p.get("type") or ""),
            "indicators":indicators,
            "maliciousness_decision":"NOT_DETERMINED_FROM_ABSENCE",
            "evidence_count":len(indicators),
        })
    rows.sort(key=lambda x:(x["ecosystem"],x["package"]))
    payload["malicious_package_intelligence"]={
        "status":"AVAILABLE","packages":rows,
        "summary":{"packages":len(rows),"packages_with_indicators":sum(1 for x in rows if x["indicators"])},
        "read_only":True,
        "external_reputation_query_performed":False,
    }
    return payload
