"""Minimal V11 Agent/MCP/RAG graph builders.

Builders are deliberately model-first. They accept evidence references and
produce graph objects; they do not implement speculative detection.
"""
from __future__ import annotations
from .graph_schema import SecurityGraph, AttackNode, AttackRelationship, EvidenceReference, Relationship

def _eref(evidence_id):
    return [EvidenceReference(evidence_id)] if evidence_id else []

def build_agent_graph(evidence_id=None):
    g=SecurityGraph("AGENT_GRAPH")
    agent=g.add_node(AttackNode(node_type="Agent", label="Agent", evidence=_eref(evidence_id)))
    goal=g.add_node(AttackNode(node_type="Goal", label="Goal"))
    tool=g.add_node(AttackNode(node_type="Tool", label="Tool"))
    identity=g.add_node(AttackNode(node_type="Identity", label="Identity"))
    privilege=g.add_node(AttackNode(node_type="Privilege", label="Privilege"))
    resource=g.add_node(AttackNode(node_type="Resource", label="Resource"))
    action=g.add_node(AttackNode(node_type="Action", label="Action"))
    outcome=g.add_node(AttackNode(node_type="Outcome", label="Outcome"))
    for a,b,r in [(agent,goal,Relationship.FLOWS_TO),(agent,tool,Relationship.INVOKES),
                  (agent,identity,Relationship.HAS_IDENTITY),(identity,privilege,Relationship.HAS_PRIVILEGE),
                  (tool,resource,Relationship.ACCESSES),(agent,action,Relationship.GENERATES),
                  (action,outcome,Relationship.PRODUCES)]:
        g.add_relationship(AttackRelationship(a.node_id,r,b.node_id,evidence=_eref(evidence_id)))
    return g

def build_mcp_graph(evidence_id=None):
    g=SecurityGraph("MCP_GRAPH")
    agent=g.add_node(AttackNode(node_type="Agent", label="Agent", evidence=_eref(evidence_id)))
    client=g.add_node(AttackNode(node_type="MCPClient", label="MCP Client"))
    server=g.add_node(AttackNode(node_type="MCPServer", label="MCP Server"))
    tool=g.add_node(AttackNode(node_type="Tool", label="Tool"))
    resource=g.add_node(AttackNode(node_type="Resource", label="Resource"))
    ext=g.add_node(AttackNode(node_type="ExternalSystem", label="External System"))
    for a,b,r in [(agent,client,Relationship.CALLS),(client,server,Relationship.AUTHENTICATES_TO),
                  (server,tool,Relationship.INVOKES),(tool,resource,Relationship.ACCESSES),
                  (resource,ext,Relationship.FLOWS_TO)]:
        g.add_relationship(AttackRelationship(a.node_id,r,b.node_id,evidence=_eref(evidence_id)))
    return g

def build_rag_graph(evidence_id=None):
    g=SecurityGraph("RAG_GRAPH")
    labels=["User","Prompt","Retriever","Vector Store","Document","Chunk","Context","Model","Agent","Response"]
    nodes=[g.add_node(AttackNode(node_type=x.replace(" ",""), label=x, evidence=_eref(evidence_id) if i in (2,4,6) else []))
           for i,x in enumerate(labels)]
    for a,b in zip(nodes,nodes[1:]):
        g.add_relationship(AttackRelationship(a.node_id,Relationship.FLOWS_TO,b.node_id,evidence=_eref(evidence_id)))
    return g
