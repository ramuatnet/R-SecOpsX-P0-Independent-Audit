import re
from uuid import UUID
from core.graph_schema import AttackNode, AttackRelationship, EvidenceReference, Relationship, SecurityGraph
from core.ai_graphs import build_agent_graph, build_mcp_graph, build_rag_graph
from core.attack_graph import merge_graphs, summarize_attack_graph
from core.owasp_mappings import map_technique
from core.rcmsp import evaluate_rcmsp
from core.v11_intelligence import build_v11_intelligence

EID="11111111-1111-4111-8111-111111111111"

def test_graph_node_uuid_and_type():
    n=AttackNode(node_type="Agent",label="a"); UUID(n.node_id); assert n.node_type=="Agent"
def test_evidence_reference_uuid():
    UUID(EvidenceReference(EID).evidence_id)
def test_relationship_enum():
    assert Relationship.INVOKES.value=="INVOKES"
def test_dangling_relationship_rejected():
    g=SecurityGraph("X"); a=g.add_node(AttackNode(node_type="A"))
    try: g.add_relationship(AttackRelationship(a.node_id,Relationship.INVOKES,"missing"))
    except ValueError: return
    assert False
def test_agent_graph_model():
    g=build_agent_graph(EID); assert g.graph_type=="AGENT_GRAPH"; g.validate()
def test_mcp_graph_model():
    g=build_mcp_graph(EID); assert g.graph_type=="MCP_GRAPH"; g.validate()
def test_rag_graph_model():
    g=build_rag_graph(EID); assert g.graph_type=="RAG_GRAPH"; g.validate()
def test_graph_evidence_reference():
    for g in (build_agent_graph(EID),build_mcp_graph(EID),build_rag_graph(EID)):
        assert any(e.evidence_id==EID for n in g.nodes for e in n.evidence)
def test_attack_graph_merge():
    a=merge_graphs([build_agent_graph(EID),build_mcp_graph(EID),build_rag_graph(EID)])
    assert a.graph_type=="ATTACK_GRAPH"; a.validate(); assert len(a.nodes)>0
def test_attack_graph_reachability():
    a=merge_graphs([build_agent_graph(EID)]); s=summarize_attack_graph(a); assert s["reachable"] is True
def test_prompt_injection_mapping():
    m=map_technique("PROMPT_INJECTION"); assert m["namespace"]=="LLM01:2025"
def test_tool_poisoning_misuse_only():
    m=map_technique("TOOL_POISONING",misuse=True); assert m["owasp"]==["ASI02"]
def test_tool_poisoning_supply_only():
    m=map_technique("TOOL_POISONING",supply_chain=True); assert m["owasp"]==["ASI04"]
def test_tool_poisoning_conditional():
    m=map_technique("TOOL_POISONING",misuse=True,supply_chain=True); assert set(m["owasp"])=={"ASI02","ASI04"}
def test_unknown_mapping_not_fabricated():
    assert map_technique("UNKNOWN")["owasp"]==[]
def test_rcmsp_separates_decision():
    d=evaluate_rcmsp(evidence_ids=[EID],graph_summary={"graph_type":"ATTACK_GRAPH","reachable":False},mapping_summary={})
    assert d["decision_context"]["evidence_ids"]==[EID]; assert d["validated_decision"] is True
def test_rcmsp_missing_evidence():
    d=evaluate_rcmsp(evidence_ids=[],graph_summary={"graph_type":"ATTACK_GRAPH","reachable":False},mapping_summary={})
    assert d["decision_outcome"]["outcome"]=="REVIEW_REQUIRED"
def test_end_to_end_intelligence():
    f={"finding_id":"F1","rule":"PROMPT_INJECTION","canonical_evidence":{"evidence_id":EID},
       "canonical_qualified_evidence":{"qualified":True,"evidence":{"evidence_id":EID}}}
    x=build_v11_intelligence(f)
    assert set(("agent_graph","mcp_graph","rag_graph","attack_graph","rcmsp")).issubset(x)
def test_end_to_end_provenance():
    f={"finding_id":"F1","rule":"PROMPT_INJECTION","canonical_evidence":{"evidence_id":EID}}
    x=build_v11_intelligence(f)
    assert x["rcmsp"]["provenance"]["engine"]=="R-SecOpsX"
