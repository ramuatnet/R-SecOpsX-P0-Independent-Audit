"""Independent Gradle dependencies-output edge oracle (R2.2; R2.6.1 update).

Re-implements `gradle dependencies` parsing WITHOUT importing the extractor
(`analysis/lock_graph/gradle.py`): the oracle determines each node's parent
by maintaining an explicit parent-pointer array indexed by decoration depth
(deriving depth by iteratively consuming 5-character decoration groups),
structurally different from the extractor's formula-plus-stack approach.
Never validate an extractor against its own output.

R2.6.1 marker semantics -- derived INDEPENDENTLY from the extractor (the
R2.2 oracle shared the extractor's `(n)`-stripping assumption, which is
exactly the shared-assumption failure the closure audit flagged):

- `(n)`  -- the printed version was requested but NOT resolved: the node
  carries NO resolved version; edges touching it are expected UNRESOLVED
  with empty versions on the affected side (identity names preserved).
- `(c)`  -- the printed version was selected by a dependency constraint
  and IS in use: expected VERIFIED at that version.
- `-> X` -- conflict resolution: the selected version X is resolved; a
  MISSING selected version (`g:a:1.0 ->`) is requested-but-unresolved
  and follows the (n) semantics.
- `(*)`  -- subtree elision: the edge is real and kept.
- `project :x` references have no registry identity (their subtree
  children are disclosed as unresolvable, never invented); those edges
  carry the extractor's own PROJECT_PARENT_UNSUPPORTED status and are
  reported separately from the (n) comparisons below.

Usage:
    python -I tools/oracle_gradle.py <gradle-dependencies.txt> <edges.json>
    python -I tools/oracle_gradle.py <gradle-dependencies.txt> <clean_report.json>

Reports VERIFIED wrong/missing, UNRESOLVED((n)-class) wrong/missing,
confidence mismatches (an (n)-expected identity emitted VERIFIED) and
resolution-status mismatches. Exit 0 iff all comparisons agree.
"""

import json
import re
import sys
from pathlib import Path

STATUS_NOT_RESOLVED = "GRADLE_VERSION_NOT_RESOLVED"


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
    """Independent (n)/(c)/arrow semantics -- see module docstring."""
    not_resolved = bool(re.search(r"\(n\)\s*$", body))
    body = re.sub(r"\s*\([nc]\)\s*$", "", body)
    selected = ""
    arrow = re.search(r"\s+->\s*(.*)$", body)
    if arrow:
        body = body[:arrow.start()]
        selected = arrow.group(1).strip()
        if not selected:
            not_resolved = True
    body = re.sub(r"\s*\(\*\)\s*$", "", body)
    parts = [p.strip() for p in body.split(":")]
    if len(parts) != 3:
        return None
    version = parts[2]
    if selected:
        version = selected
    if not_resolved:
        return {"name": f"{parts[0]}:{parts[1]}", "version": "",
                "project": False, "not_resolved": True}
    return {"name": f"{parts[0]}:{parts[1]}", "version": version,
            "project": False}


def parse_project(body):
    m = re.match(r"^project\s+(\S+)$", body.strip())
    return {"name": f"project {m.group(1)}", "version": "",
            "project": True} if m else None


def expected_edges(tree_path):
    lines = Path(tree_path).read_text(encoding="utf-8").splitlines()
    parents = [None] * 64   # parent-pointer array by depth
    expected = set()        # VERIFIED identities: (pn, pv, cn, cv)
    expected_unresolved = set()   # (n)-class UNRESOLVED identities
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
        identity = (parent["name"], parent["version"],
                    node["name"], node["version"])
        if parent.get("not_resolved") or node.get("not_resolved"):
            expected_unresolved.add(identity)
        else:
            expected.add(identity)
    return expected, expected_unresolved, direct


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

    expected, expected_unresolved, direct = expected_edges(tree)
    got_verified = set()
    got_unresolved = set()
    other_unresolved = 0
    for e in edges:
        identity = (str(e.get("parent_name")), str(e.get("parent_version")),
                    str(e.get("child_name")), str(e.get("child_version")))
        conf = str(e.get("confidence") or "").upper()
        status = str(e.get("resolution_status") or "")
        if conf == "VERIFIED":
            got_verified.add(identity)
        elif conf == "UNRESOLVED":
            if status == STATUS_NOT_RESOLVED:
                got_unresolved.add(identity)
            else:
                other_unresolved += 1
    # confidence mismatch: an (n)-expected identity emitted as VERIFIED
    confidence_mismatch = len(got_verified & expected_unresolved)

    wrong = got_verified - expected
    missing = expected - got_verified
    wrong_u = got_unresolved - expected_unresolved
    missing_u = expected_unresolved - got_unresolved
    print(f"oracle expected VERIFIED edges: {len(expected)} "
          f"(direct declarations counted: {direct})")
    print(f"oracle expected (n)-class UNRESOLVED edges: "
          f"{len(expected_unresolved)}")
    print(f"extractor VERIFIED edges: {len(got_verified)} | "
          f"(n)-class UNRESOLVED: {len(got_unresolved)} | "
          f"other UNRESOLVED (project-parent): {other_unresolved}")
    print(f"WRONG (VERIFIED):   {len(wrong)}  {sorted(wrong)[:5]}")
    print(f"MISSING (VERIFIED): {len(missing)}  {sorted(missing)[:5]}")
    print(f"WRONG ((n) UNRESOLVED):   {len(wrong_u)}  {sorted(wrong_u)[:5]}")
    print(f"MISSING ((n) UNRESOLVED): {len(missing_u)}  {sorted(missing_u)[:5]}")
    print(f"CONFIDENCE MISMATCHES ((n) identity emitted VERIFIED): "
          f"{confidence_mismatch}")
    ok = (not wrong and not missing and not wrong_u and not missing_u
          and confidence_mismatch == 0)
    print("ORACLE RESULT:", "PASS" if ok else "FAIL")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
