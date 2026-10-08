"""
Feature 6 — Security Change Graph.
Creates a deterministic evidence graph from already-produced change, finding,
dependency and lifecycle records. No new vulnerability decisions are made.
"""
from __future__ import annotations
from copy import deepcopy
from typing import Any, Dict

def enrich_security_change_graph(payload: Dict[str, Any]) -> Dict[str, Any]:
    payload = deepcopy(payload)
    nodes=[]; edges=[]
    ci=payload.get("change_intelligence") or {}
    for f in ci.get("files",[]) or []:
        if not isinstance(f,dict): continue
        p=str(f.get("path",""))
        if not p: continue
        fid="file:"+p
        nodes.append({"id":fid,"type":"changed_file","label":p})
        for finding in payload.get("findings",[]) or []:
            if not isinstance(finding,dict): continue
            fp=str(finding.get("file") or finding.get("path") or finding.get("source_file") or "").replace("\\","/").lstrip("./")
            if fp != p: continue
            iid=str(finding.get("finding_id") or finding.get("id") or "")
            if not iid: continue
            nid="finding:"+iid
            nodes.append({"id":nid,"type":"finding","label":iid})
            edges.append({"source":fid,"target":nid,"relation":"CHANGED_FILE_HAS_FINDING"})
    uniq={}
    for n in nodes: uniq[n["id"]]=n
    edge_keys=set(); dedup=[]
    for e in edges:
        k=(e["source"],e["target"],e["relation"])
        if k not in edge_keys:
            edge_keys.add(k); dedup.append(e)
    nodes=sorted(uniq.values(),key=lambda x:x["id"])
    dedup.sort(key=lambda x:(x["source"],x["target"],x["relation"]))
    payload["security_change_graph"]={
        "status":"AVAILABLE" if ci.get("status")=="AVAILABLE" else "UNAVAILABLE",
        "nodes":nodes,"edges":dedup,
        "summary":{"node_count":len(nodes),"edge_count":len(dedup)},
        "read_only":True,
        "decision_inference":False,
    }
    return payload
