"""Formal RCMSP decision objects for V11.

This module intentionally separates evidence from decision and does not reduce
RCMSP to a numeric score.
"""
from __future__ import annotations
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from uuid import uuid4

@dataclass
class DecisionContext:
    context_id: str
    evidence_ids: list[str]
    graph_type: str
    provenance: dict

@dataclass
class DecisionState:
    state: str
    rationale: str

@dataclass
class DecisionPolicy:
    policy_id: str
    policy_name: str
    version: str

@dataclass
class DecisionOutcome:
    outcome: str
    confidence: str
    explanation: str
    provenance: dict

def evaluate_rcmsp(*, evidence_ids, graph_summary, mapping_summary, policy_id="V11-DEFAULT-REVIEW"):
    qualified=bool(evidence_ids)
    reachable=bool(graph_summary.get("reachable"))
    if not qualified:
        state=DecisionState("EVIDENCE_UNAVAILABLE","Required qualified evidence is unavailable.")
        outcome=DecisionOutcome("REVIEW_REQUIRED","LOW","Decision deferred because qualified evidence is unavailable.",
                                {"engine":"R-SecOpsX","component":"RCMSP"})
    elif reachable:
        state=DecisionState("SECURITY_REVIEW","Evidence-backed graph reachability requires contextual review.")
        outcome=DecisionOutcome("SECURITY_REVIEW_REQUIRED","HIGH",
                                "Qualified evidence and an established graph path require security review.",
                                {"engine":"R-SecOpsX","component":"RCMSP"})
    else:
        state=DecisionState("NO_ESTABLISHED_ATTACK_PATH","Evidence exists but no graph path was established.")
        outcome=DecisionOutcome("REVIEW_REQUIRED","MEDIUM",
                                "Evidence is present; no attack path was established by the current graph model.",
                                {"engine":"R-SecOpsX","component":"RCMSP"})
    context=DecisionContext(str(uuid4()),list(evidence_ids),graph_summary.get("graph_type","ATTACK_GRAPH"),
                            {"engine":"R-SecOpsX","component":"RCMSP"})
    policy=DecisionPolicy(policy_id,"V11 Formal Context-Aware Decision Policy","1.0")
    return {"decision_context":asdict(context),"decision_state":asdict(state),
            "decision_policy":asdict(policy),"decision_outcome":asdict(outcome),
            "validated_decision":True,"explanation":outcome.explanation,
            "provenance":outcome.provenance}
