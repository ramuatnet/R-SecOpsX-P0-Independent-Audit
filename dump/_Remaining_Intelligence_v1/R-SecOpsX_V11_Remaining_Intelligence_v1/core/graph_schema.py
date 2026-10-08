"""R-SecOpsX V11 controlled graph schema.

Research/production boundary: graph objects reference canonical Evidence IDs;
they do not create an alternate evidence model.
"""
from __future__ import annotations
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any
from uuid import UUID, uuid4
from datetime import datetime, timezone

class Relationship(str, Enum):
    DEPENDS_ON="DEPENDS_ON"; CALLS="CALLS"; READS="READS"; WRITES="WRITES"
    TRUSTS="TRUSTS"; AUTHENTICATES_TO="AUTHENTICATES_TO"; INVOKES="INVOKES"
    FLOWS_TO="FLOWS_TO"; EXPLOITS="EXPLOITS"; POISONS="POISONS"; ESCALATES_TO="ESCALATES_TO"
    HAS_IDENTITY="HAS_IDENTITY"; HAS_PRIVILEGE="HAS_PRIVILEGE"; ACCESSES="ACCESSES"
    GENERATES="GENERATES"; PRODUCES="PRODUCES"

@dataclass(frozen=True)
class EvidenceReference:
    evidence_id: str
    def __post_init__(self):
        UUID(self.evidence_id)

@dataclass
class AttackNode:
    node_id: str = field(default_factory=lambda: str(uuid4()))
    node_type: str = ""
    label: str = ""
    evidence: list[EvidenceReference] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    def __post_init__(self):
        UUID(self.node_id)
        if not self.node_type: raise ValueError("node_type is required")

@dataclass
class AttackRelationship:
    source: str
    relationship: Relationship
    target: str
    evidence: list[EvidenceReference] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

@dataclass
class SecurityGraph:
    graph_type: str
    nodes: list[AttackNode] = field(default_factory=list)
    relationships: list[AttackRelationship] = field(default_factory=list)
    generated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def add_node(self, node: AttackNode) -> AttackNode:
        self.nodes.append(node); return node
    def add_relationship(self, rel: AttackRelationship) -> AttackRelationship:
        if rel.source not in {n.node_id for n in self.nodes} or rel.target not in {n.node_id for n in self.nodes}:
            raise ValueError("relationship endpoint must reference graph nodes")
        self.relationships.append(rel); return rel
    def validate(self) -> None:
        UUID(self.nodes[0].node_id) if self.nodes else None
        node_ids={n.node_id for n in self.nodes}
        for n in self.nodes:
            UUID(n.node_id)
            for e in n.evidence: UUID(e.evidence_id)
        for r in self.relationships:
            if r.source not in node_ids or r.target not in node_ids: raise ValueError("dangling relationship")
            for e in r.evidence: UUID(e.evidence_id)
    def to_dict(self):
        self.validate()
        return {
            "graph_type": self.graph_type,
            "generated_at": self.generated_at,
            "nodes":[{"node_id":n.node_id,"node_type":n.node_type,"label":n.label,
                      "evidence":[asdict(e) for e in n.evidence],"metadata":n.metadata} for n in self.nodes],
            "relationships":[{"source":r.source,"relationship":r.relationship.value,"target":r.target,
                              "evidence":[asdict(e) for e in r.evidence],"metadata":r.metadata}
                             for r in self.relationships],
        }
