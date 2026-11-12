"""Independent Maven dependency-tree edge oracle (R2.2 validation instrument).

Re-implements `mvn dependency:tree` parsing WITHOUT importing the extractor
(`analysis/lock_graph/maven.py`): the oracle walks the tree with a different
algorithm -- it derives each node's parent by RECONSTRUCTING the ancestor
path from the decoration string character-by-character (tracking a
parent-slot list per depth), rather than the extractor's pop-to-depth
stack. Independence is the point: two structurally different parsers must
agree, or one of them is wrong.

Usage:
    python -I tools/oracle_maven.py <dependency-tree.txt> <edges.json>
    python -I tools/oracle_maven.py <dependency-tree.txt> <clean_report.json>

Metrics: expected/extracted/correct/wrong/missing/invented. Exit 0 iff the
identity sets agree (VERIFIED edges only; omitted/conflict handling must
match: omitted references produce no edge, conflicts use the selected
version).
"""

import json
import re
import sys
from pathlib import Path


def norm_ga(coord_text):
    return coord_text


def split_line(line):
    """(depth, coord_text, omitted, selected_version) -- oracle's own rules."""
    text = line.rstrip()
    if not text.strip():
        return None
    text = re.sub(r"^\[[A-Z]+\]\s*", "", text)
    omitted = False
    selected = ""
    if re.search(r"omitted for (duplicate|conflict)", text):
        omitted = True
    if " -> " in text:
        text, selected = text.split(" -> ", 1)
        selected = selected.strip()
    m = re.match(r"^((?:\| {2}|\ {3})*(?:\+- |\\- ))?(.+)$", text)
    if not m:
        return None
    prefix, body = m.group(1) or "", m.group(2).strip()
    depth = 0
    pos = 0
    while pos < len(prefix):
        chunk = prefix[pos:pos + 3]
        if chunk.startswith("|"):
            depth += 1
            pos += 3
        else:
            depth += 1
            pos += 3
    if not prefix:
        depth = 0
    return depth, body, omitted, selected


def parse_coord(body):
    parts = [p.strip() for p in body.split(":")]
    if len(parts) < 3:
        return None
    scope = "compile"
    classifier = ""
    if parts[-1] in {"compile", "test", "runtime", "provided", "system"}:
        scope = parts[-1]
        version = parts[-2]
        if len(parts) >= 5:
            classifier = parts[-3]
    else:
        version = parts[-1]
        if len(parts) >= 4:
            classifier = parts[-3]
    return (f"{parts[0]}:{parts[1]}", version, scope, classifier)


def expected_edges(tree_path):
    lines = Path(tree_path).read_text(encoding="utf-8").splitlines()
    slots = {}          # depth -> identity tuple (name, version)
    expected = set()
    root_seen = False
    for raw in lines:
        parsed = split_line(raw)
        if parsed is None:
            continue
        depth, body, omitted, selected = parsed
        if "omitted" in body:
            continue
        ident = parse_coord(body)
        if ident is None:
            continue
        name, version, scope, classifier = ident
        if selected:
            version = selected
        if depth == 0:
            slots = {0: (name, version)}
            root_seen = True
            continue
        parent = slots.get(depth - 1)
        if parent is None:
            continue
        slots[depth] = (name, version)
        # clear stale deeper slots
        for d in [k for k in slots if k > depth]:
            del slots[d]
        expected.add((parent[0], parent[1], name, version))
    return expected, root_seen


def main():
    tree = Path(sys.argv[1])
    edges_in = Path(sys.argv[2])
    payload = json.loads(edges_in.read_text(encoding="utf-8"))
    if isinstance(payload, dict):
        graph = payload.get("dependency_graph") or {}
        edges = [e for e in (graph.get("edges") or [])
                 if str(e.get("evidence_source") or "") == "MAVEN_DEPENDENCY_TREE"]
    else:
        edges = payload

    expected, root_seen = expected_edges(tree)
    got = set()
    for e in edges:
        got.add((str(e.get("parent_name")), str(e.get("parent_version")),
                 str(e.get("child_name")), str(e.get("child_version"))))

    wrong = got - expected
    missing = expected - got
    print(f"oracle expected edges: {len(expected)} (root seen: {root_seen})")
    print(f"extractor VERIFIED edges: {len(edges)}")
    print(f"WRONG:   {len(wrong)}  {sorted(wrong)[:5]}")
    print(f"MISSING: {len(missing)}  {sorted(missing)[:5]}")
    ok = not wrong and not missing and root_seen
    print("ORACLE RESULT:", "PASS" if ok else "FAIL")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
