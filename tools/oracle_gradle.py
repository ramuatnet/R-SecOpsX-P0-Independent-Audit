"""Independent Gradle dependencies-output edge oracle (R2.2).

Re-implements `gradle dependencies` parsing WITHOUT importing the extractor
(`analysis/lock_graph/gradle.py`): the oracle determines each node's parent
by maintaining an explicit parent-pointer array indexed by decoration depth
(deriving depth by iteratively consuming 5-character decoration groups),
structurally different from the extractor's formula-plus-stack approach.
Never validate an extractor against its own output.

Usage:
    python -I tools/oracle_gradle.py <gradle-dependencies.txt> <edges.json>
    python -I tools/oracle_gradle.py <gradle-dependencies.txt> <clean_report.json>

Semantics mirrored independently: level-1 entries under a configuration
header are DIRECT declarations (no parent edge, no synthetic root); `(*)`
elision keeps the edge; conflicts use the selected version; `project :x`
references have no registry identity (their subtree children are disclosed
as unresolvable, never invented). Exit 0 iff VERIFIED identity sets agree.
"""

import json
import re
import sys
from pathlib import Path


def consume_decoration(text):
    """Oracle's own depth rules: consume 5-char decoration groups from the
    start (``|    `` or 5 spaces); the next chars must be a connector."""
    depth = 0
    pos = 0
    while True:
        chunk = text[pos:pos + 5]
        if chunk == "|    ":
            depth += 1
            pos += 5
            continue
        if chunk == "     " and len(text) > pos + 5:
            depth += 1
            pos += 5
            continue
        break
    rest = text[pos:]
    connector = None
    if rest.startswith("+--- "):
        connector = "+--- "
    elif rest.startswith("\\--- "):
        connector = "\\--- "
    if connector is None:
        if depth == 0:
            return 0, text.strip()
        return None
    return depth + 1, rest[len(connector):].strip()


def parse_node(body):
    body = re.sub(r"\s*\([nc]\)\s*$", "", body)
    selected = ""
    if " -> " in body:
        body, selected = body.split(" -> ", 1)
        selected = selected.strip()
    body = re.sub(r"\s*\(\*\)\s*$", "", body)
    parts = [p.strip() for p in body.split(":")]
    if len(parts) != 3:
        return None
    version = parts[2]
    if selected:
        version = selected
    return {"name": f"{parts[0]}:{parts[1]}", "version": version,
            "project": False}


def parse_project(body):
    m = re.match(r"^project\s+(\S+)$", body.strip())
    return {"name": f"project {m.group(1)}", "version": "",
            "project": True} if m else None


def expected_edges(tree_path):
    lines = Path(tree_path).read_text(encoding="utf-8").splitlines()
    parents = [None] * 64   # parent-pointer array by depth
    expected = set()
    direct = 0
    for raw in lines:
        line = raw.rstrip()
        if not line.strip():
            continue
        if re.match(r"^>\s*Task\b", line):
            continue
        parsed = consume_decoration(line)
        if parsed is None:
            continue
        depth, body = parsed
        if depth == 0:
            parents = [None] * 64   # new configuration: reset pointers
            continue
        proj = parse_project(body)
        if proj is not None:
            parents[depth] = proj
            continue
        node = parse_node(body)
        if node is None:
            continue
        parent = parents[depth - 1] if depth >= 2 else None
        if depth == 1 or parent is None or parent.get("project"):
            direct += 1
            parents[depth] = node
            continue
        parents[depth] = node
        expected.add((parent["name"], parent["version"],
                      node["name"], node["version"]))
    return expected, direct


def main():
    tree = Path(sys.argv[1])
    edges_in = Path(sys.argv[2])
    payload = json.loads(edges_in.read_text(encoding="utf-8"))
    if isinstance(payload, dict):
        graph = payload.get("dependency_graph") or {}
        edges = [e for e in (graph.get("edges") or [])
                 if str(e.get("evidence_source") or "") == "GRADLE_DEPENDENCIES"]
    else:
        edges = payload

    expected, direct = expected_edges(tree)
    got = set()
    for e in edges:
        if str(e.get("confidence")) != "VERIFIED":
            continue
        got.add((str(e.get("parent_name")), str(e.get("parent_version")),
                 str(e.get("child_name")), str(e.get("child_version"))))

    wrong = got - expected
    missing = expected - got
    print(f"oracle expected VERIFIED edges: {len(expected)} "
          f"(direct declarations counted: {direct})")
    print(f"extractor VERIFIED edges: {len(edges)}")
    print(f"WRONG:   {len(wrong)}  {sorted(wrong)[:5]}")
    print(f"MISSING: {len(missing)}  {sorted(missing)[:5]}")
    ok = not wrong and not missing
    print("ORACLE RESULT:", "PASS" if ok else "FAIL")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
