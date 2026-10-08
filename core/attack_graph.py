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

def _ap_risk(finding):
    """The finding's own risk score, or None. Never 0 for absent.

    `finding.get("risk_score", 0)` is how a fabricated "Risk: 0" reached a report.
    A missing score must stay missing so the renderer omits the column.
    """
    v = finding.get("risk_score")
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        return round(float(v), 1)
    try:
        return round(float(str(v).strip()), 1)
    except (TypeError, ValueError):
        return None


def _ap_weakness(finding):
    """Human-readable weakness name, preferring the finding's own title.

    A title of "TAINT_SQL_INJECTION" makes the reader do the translation work; the
    finding already carries "SQL Injection" and it was being ignored.
    """
    for field in ("title", "vuln_type", "rule_id"):
        v = str(finding.get(field) or "").strip()
        if v:
            return v
    return "Unclassified weakness"


def _ap_narrative(finding, nodes, confirmed):
    """Compose a narrative from the record's own fields.

    Every clause traces to a field on the finding or the chain. No attack
    scenario is invented: a per-vulnerability prose table would describe outcomes
    this scan never observed, which is the failure mode this project treats as
    fabrication.

    The confirmed/candidate distinction is stated in words, not only in colour,
    because a colour band is not readable in a printed or text-extracted report.
    """
    weakness = _ap_weakness(finding)
    cwe = str(finding.get("cwe") or "").strip()
    cwe_clause = f" ({cwe})" if cwe else ""
    src = nodes[0] if nodes else "an unrecorded source"
    snk = nodes[-1] if len(nodes) > 1 else "an unrecorded sink"
    hops = max(0, len(nodes) - 1)
    location = ""
    fl, ln = finding.get("file"), finding.get("line")
    if fl:
        location = f" Observed at {fl}" + (f":{ln}." if ln else ".")

    chain_clause = (f"{hops} hop{'' if hops == 1 else 's'}"
                    if hops else "an unrecorded number of hops")

    if confirmed:
        return (
            f"A {weakness} finding{cwe_clause} traces from {src} to {snk} across "
            f"{chain_clause}. Both endpoints were observed in the finding's own "
            f"taint path, so the reachability of this chain is established by "
            f"static analysis.{location} This does NOT assert that the chain is "
            f"exploitable in a live environment: transport, deployment and "
            f"upstream validation are separate questions this scan does not answer."
        )

    return (
        f"A {weakness} finding{cwe_clause} is reported against {snk}, with "
        f"{src} as the apparent entry point across {chain_clause}.{location} "
        f"Reachability is NOT established: this is a pattern-level correlation, "
        f"not an observed data flow. To validate it, confirm that the entry point "
        f"reaches this sink at runtime and that no validation, sanitisation or "
        f"encoding upstream neutralises it."
    )


def get_attack_paths(findings):
    """
    V11 analyzer compatibility contract.

    Returns normalized attack-path records derived from finding-level
    source/sink/taint evidence. This function does not create a second
    graph schema.
    """
    if not findings:
        return []

    paths = []

    for finding in findings:
        if not isinstance(finding, dict):
            continue

        taint_path = finding.get("taint_path")
        source = finding.get("source")
        sink = finding.get("sink")

        # Preserve explicitly validated taint/source-to-sink evidence.
        #
        # REGRESSION FIX. `taint_path` is emitted as a STRING carrying the chain,
        # e.g. "body -> fetch(". This code wrapped any non-list value in a
        # single-element list, so `len(nodes) >= 2` was never true and EVERY
        # attack path was silently dropped.
        #
        # Measured effect on the 16-project prodtest corpus: attack_paths was 0
        # for all 16, including juice-shop, which carries 12 findings with real
        # source-to-sink taint evidence. The 2026-09-23 report on the same corpus
        # emitted 4 (1 confirmed, 3 pattern-only candidates), so this was a
        # regression rather than a property of the corpus.
        #
        # It survived review because reporting/pdf_report.py independently tests
        # for the string form ("->" in str(taint_path)) to detect taint-validated
        # findings. Both ends of the pipeline agreed the string form was normal;
        # only this function disagreed with them.
        if taint_path:
            if isinstance(taint_path, (list, tuple)):
                nodes = [str(x) for x in taint_path if x is not None]
            else:
                raw = str(taint_path)
                # Split only on a real arrow. A bare expression with no arrow
                # stays a single node rather than being split on some other
                # punctuation and inventing a path that was never observed.
                if "->" in raw:
                    segments = [seg.strip() for seg in raw.split("->")]
                    # Any empty segment makes the chain MALFORMED and it emits no
                    # path at all. Dropping the gap instead would collapse
                    # "a ->  -> b" into ["a", "b"], asserting a direct a->b edge
                    # whose hops were never observed. Fabricating an edge is worse
                    # than reporting nothing, so this fails closed.
                    if any(not seg for seg in segments):
                        nodes = []
                    else:
                        nodes = segments
                else:
                    nodes = [raw.strip()]

            if len(nodes) >= 2:
                _confirmed = finding.get("evidence_valid") is True
                # Propagate the finding's own computed fields. They were all
                # present and ignored: title "SQL Injection", severity "Medium",
                # risk_score 70.5 from core/risk_scorer.py, cwe "CWE-89". Because
                # they were absent here, the renderer saw no risk score and
                # omitted the column entirely, and fell back to the rule id for a
                # title. Carrying them restores the old report's content while
                # keeping the corrected evidence label.
                paths.append({
                    "path": nodes,
                    "source": nodes[0],
                    "sink": nodes[-1],
                    "finding_id": str(
                        finding.get("finding_id")
                        or finding.get("id")
                        or ""
                    ),
                    "rule_id": str(finding.get("rule_id") or ""),
                    "attack_path_status": (
                        "confirmed" if _confirmed else "candidate"
                    ),
                    "evidence_valid": finding.get("evidence_valid"),
                    "title": f"Attack Path: {_ap_weakness(finding)}",
                    "severity": finding.get("severity"),
                    "risk_score": _ap_risk(finding),
                    "cwe": finding.get("cwe"),
                    "vuln_type": finding.get("vuln_type"),
                    "confidence": finding.get("confidence"),
                    "exploitability": finding.get("exploitability"),
                    "file": finding.get("file"),
                    "line": finding.get("line"),
                    "narrative": _ap_narrative(finding, nodes, _confirmed),
                })
                continue

        # Explicit source/sink fields provide candidate-path evidence.
        if source and sink:
            paths.append({
                "path": [str(source), str(sink)],
                "source": str(source),
                "sink": str(sink),
                "finding_id": str(
                    finding.get("finding_id")
                    or finding.get("id")
                    or ""
                ),
                "rule_id": str(finding.get("rule_id") or ""),
                "attack_path_status": (
                    "confirmed"
                    if finding.get("evidence_valid") is True
                    else "candidate"
                ),
                "evidence_valid": finding.get("evidence_valid"),
            })

    return paths


def get_pivot_points(findings):
    """
    Identify findings participating in multiple modeled attack chains.

    Returns stable human-readable pivot labels. No alternate evidence
    representation is introduced.
    """
    if not findings:
        return []

    counts = {}

    for finding in findings:
        if not isinstance(finding, dict):
            continue

        key = (
            finding.get("file")
            or finding.get("file_path")
            or finding.get("full_path")
            or finding.get("sink_category")
            or finding.get("vuln_type")
        )

        if not key:
            continue

        key = str(key)
        counts[key] = counts.get(key, 0) + 1

    return [
        key
        for key, count in sorted(
            counts.items(),
            key=lambda item: (-item[1], item[0])
        )
        if count > 1
    ]
