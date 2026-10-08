"""V11 three-graph -> attack-graph -> RCMSP integration boundary."""
from __future__ import annotations
from .ai_graphs import build_agent_graph, build_mcp_graph, build_rag_graph
from .attack_graph import merge_graphs, summarize_attack_graph
from .owasp_mappings import map_technique
from .rcmsp import evaluate_rcmsp

def _evidence_ids(finding):
    ids=[]
    e=finding.get("canonical_evidence")
    if isinstance(e,dict) and e.get("evidence_id"): ids.append(e["evidence_id"])
    q=finding.get("canonical_qualified_evidence")
    if isinstance(q,dict):
        qe=q.get("evidence")
        if isinstance(qe,dict) and qe.get("evidence_id") and qe["evidence_id"] not in ids: ids.append(qe["evidence_id"])
    return ids

def build_v11_intelligence(finding):
    eids=_evidence_ids(finding)
    eid=eids[0] if eids else None
    graphs=[build_agent_graph(eid),build_mcp_graph(eid),build_rag_graph(eid)]
    attack=merge_graphs(graphs)
    attack_summary=summarize_attack_graph(attack)
    # vuln_type is the semantic key the OWASP catalogue is keyed on; rule_id
    # carries V11's own sequence numbers, which are not OWASP entry numbers.
    # Fall back to rule/rule_id/category for findings that carry no vuln_type.
    technique=(finding.get("vuln_type") or finding.get("rule") or finding.get("rule_id") or finding.get("category") or "").upper()
    mapping=map_technique(technique, misuse="TOOL" in technique, supply_chain="SUPPLY" in technique)
    decision=evaluate_rcmsp(evidence_ids=eids,graph_summary=attack_summary,mapping_summary=mapping)
    return {
        "agent_graph":graphs[0].to_dict(),
        "mcp_graph":graphs[1].to_dict(),
        "rag_graph":graphs[2].to_dict(),
        "attack_graph":attack.to_dict(),
        "attack_graph_summary":attack_summary,
        "owasp_mapping":mapping,
        "rcmsp":decision,
    }

def enrich_payload(payload):
    findings=payload.get("findings") or []
    if not findings:
        payload["v11_intelligence"]={"status":"NO_FINDINGS"}
        return payload
    contexts=[]
    for f in findings:
        contexts.append({"finding_id":f.get("finding_id"),"intelligence":build_v11_intelligence(f)})
    payload["v11_intelligence"]={"status":"PASS","findings":contexts}
    return payload
