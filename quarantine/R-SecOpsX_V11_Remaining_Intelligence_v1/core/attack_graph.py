"""V11 attack-graph construction over normalized evidence-backed graph objects."""
from __future__ import annotations
from .graph_schema import SecurityGraph, AttackNode, AttackRelationship, Relationship

def merge_graphs(graphs):
    out=SecurityGraph("ATTACK_GRAPH")
    for g in graphs:
        for n in g.nodes: out.nodes.append(n)
        for r in g.relationships: out.relationships.append(r)
    # add deterministic bridge edges between graph domains where evidence is shared
    by_e={}
    for n in out.nodes:
        for e in n.evidence: by_e.setdefault(e.evidence_id,[]).append(n)
    for eid,nodes in by_e.items():
        if len(nodes)>1:
            for a,b in zip(nodes,nodes[1:]):
                if a.node_id != b.node_id:
                    out.relationships.append(AttackRelationship(a.node_id,Relationship.FLOWS_TO,b.node_id,
                                                                evidence=[type(a.evidence[0])(eid)]))
    out.validate()
    return out

def enumerate_paths(graph, max_depth=8):
    adj={}
    for r in graph.relationships: adj.setdefault(r.source,[]).append(r.target)
    paths=[]
    for start in adj:
        stack=[(start,[start])]
        while stack:
            node,path=stack.pop()
            if len(path)>1: paths.append(path)
            if len(path)>=max_depth: continue
            for nxt in adj.get(node,[]):
                if nxt not in path: stack.append((nxt,path+[nxt]))
    return paths

def summarize_attack_graph(graph):
    paths=enumerate_paths(graph)
    return {
        "graph_type": graph.graph_type,
        "node_count": len(graph.nodes),
        "relationship_count": len(graph.relationships),
        "path_count": len(paths),
        "reachable": bool(paths),
        "impact": "contextual" if paths else "not_established",
    }
