"""Independent Go evidence oracle (R2.4 validation instrument).

Re-implements go mod graph / go.mod / go.sum evidence derivation WITHOUT
importing the extractor (`analysis/lock_graph/gomod.py`): a fresh
token-based parser and its own identity handling derive the expected
edges / declaration counts / membership counts, and the extractor's
outputs are compared. Never validate an extractor against its own output.

Usage:
    python -I oracle_go.py <go-mod-graph.txt> <graph-edges.json>
    python -I oracle_go.py <go.mod> <extractor-envelope.json>
    python -I oracle_go.py <go.sum> <extractor-envelope.json>

The file kind is chosen by its name. Reports expected/extracted tallies
and exits 0 iff identities agree. For go mod graph, every expected edge
must appear VERIFIED in the extractor output with the exact identity;
malformed lines (two tokens with a versionless half) must appear
UNRESOLVED with the declared name preserved.
"""

import json
import sys
from pathlib import Path


def unescape(path):
    """Fresh decoding of Go's escaped module path (!x -> X)."""
    out = []
    i = 0
    while i < len(path):
        ch = path[i]
        if ch == "!" and i + 1 < len(path) and path[i + 1].islower():
            out.append(path[i + 1].upper())
            i += 2
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def split_token(token):
    token = token.strip()
    if "@" not in token:
        return (unescape(token), "")
    module, _, version = token.rpartition("@")
    return (unescape(module), version)


def is_version(v):
    return v.startswith("v") and len(v) > 1


def expected_graph(path):
    """-> (edges, malformed) as identity tuples, token-walk derivation."""
    edges = set()
    malformed = set()
    for raw in Path(path).read_text(encoding="utf-8",
                                    errors="replace").splitlines():
        tokens = raw.strip().split()
        if not tokens or raw.strip().startswith("#"):
            continue
        if len(tokens) != 2:
            continue
        parent = split_token(tokens[0])
        child = split_token(tokens[1])
        if parent[1] and child[1]:
            edges.add((parent[0], parent[1], child[0], child[1]))
        else:
            malformed.add((parent[0], parent[1], child[0], child[1]))
    return edges, malformed


def expected_gomod(path):
    """-> dict of declaration tallies (fresh state-machine derivation)."""
    direct = indirect = replacements = excludes = membership = 0
    section = None
    for raw in Path(path).read_text(encoding="utf-8",
                                    errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("//"):
            continue
        words = line.split()
        if not words:
            continue
        head = words[0]
        if head == "module":
            section = None
        elif head == "require":
            section = "require"
            if len(words) >= 3:
                membership += 1
                if line.endswith("// indirect"):
                    indirect += 1
                else:
                    direct += 1
            continue
        elif head == "replace":
            section = "replace"
            if "=>" in line:
                replacements += 1
            continue
        elif head == "exclude":
            section = None
            excludes += 1
            continue
        elif head == "go":
            section = None
            continue
        if section == "require" and len(words) >= 2:
            membership += 1
            if line.endswith("// indirect"):
                indirect += 1
            else:
                direct += 1
        elif section == "replace" and "=>" in line:
            replacements += 1
    return {"direct_declarations": direct,
            "indirect_declarations": indirect,
            "replacements": replacements,
            "excludes": excludes,
            "membership_packages": membership}


def expected_gosum(path):
    """-> (unique module@version count, checksum line count)."""
    modules = set()
    checksums = 0
    for raw in Path(path).read_text(encoding="utf-8",
                                    errors="replace").splitlines():
        fields = raw.strip().split()
        if len(fields) != 3 or not fields[2].startswith("h1:"):
            continue
        checksums += 1
        module = unescape(fields[0])
        version = fields[1]
        if version.endswith("/go.mod"):
            version = version[:-len("/go.mod")]
        if version.startswith("v"):
            modules.add((module, version))
    return len(modules), checksums


def main():
    evidence = Path(sys.argv[1])
    payload = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
    edges = payload.get("edges") or []
    tallies = payload.get("tallies") or {}
    name = evidence.name
    ok = True

    if name == "go-mod-graph.txt":
        exp_edges, exp_malformed = expected_graph(evidence)
        got = {(str(e.get("parent_name") or ""),
                str(e.get("parent_version") or ""),
                str(e.get("child_name") or ""),
                str(e.get("child_version") or ""))
               for e in edges if e.get("confidence") == "VERIFIED"}
        got_malformed = {
            (str(e.get("parent_name") or ""),
             str(e.get("parent_version") or ""),
             str(e.get("child_name") or ""))
            for e in edges
            if e.get("resolution_status") == "MALFORMED_GRAPH_LINE"}
        missing = exp_edges - got
        invented = got - exp_edges
        miss_malformed = {m for m in exp_malformed
                          if (m[0], m[1], m[2]) not in got_malformed}
        print(f"oracle graph: expected VERIFIED {len(exp_edges)}, "
              f"malformed {len(exp_malformed)}")
        print(f"extractor VERIFIED identities: {len(got)}")
        print(f"WRONG/MISSING: {len(missing)}  {sorted(missing)}")
        print(f"INVENTED: {len(invented)}  {sorted(invented)}")
        print(f"malformed not preserved: {len(miss_malformed)}  "
              f"{sorted(miss_malformed)}")
        ok = not missing and not invented and not miss_malformed
    elif name == "go.mod":
        exp = expected_gomod(evidence)
        print(f"oracle go.mod: {exp}")
        for key, value in exp.items():
            # membership_packages lives at the envelope root, the rest
            # inside tallies
            got_value = (payload.get("membership_packages")
                         if key == "membership_packages"
                         else tallies.get(key))
            status = "OK" if got_value == value else \
                f"MISMATCH (extractor {got_value})"
            if got_value != value:
                ok = False
            print(f"  {key}: {value} {status}")
    elif name == "go.sum":
        exp_members, exp_checksums = expected_gosum(evidence)
        got_members = payload.get("membership_packages")
        got_checksums = tallies.get("checksum_lines")
        print(f"oracle go.sum: membership {exp_members}, "
              f"checksum lines {exp_checksums}")
        print(f"extractor: membership {got_members}, "
              f"checksum lines {got_checksums}")
        if got_members != exp_members or got_checksums != exp_checksums:
            ok = False
    else:
        print(f"unknown evidence file kind: {name}")
        ok = False

    print("ORACLE RESULT:", "PASS" if ok else "FAIL")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
