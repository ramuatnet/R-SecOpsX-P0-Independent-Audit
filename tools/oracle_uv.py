"""Independent uv.lock edge oracle (R2.1 validation instrument).

Re-implements uv.lock requires-dist resolution WITHOUT importing the
extractor or its constraint matcher: interval expansion with its own parser
(structurally different from analysis/lock_graph/versions.py). Never
validate an extractor against its own output.

Usage:
    python -I oracle_uv.py <uv.lock> <extractor-edges.json>
    python -I oracle_uv.py <uv.lock> <clean_report.json>

Metrics: expected/extracted/correct/wrong/missing/invented/ambiguity
mismatches. Exit 0 iff identities agree.
"""

import json
import re
import sys
import tomllib
from pathlib import Path


def norm(name):
    return re.sub(r"[-_.]+", "-", str(name or "").strip()).casefold()


_VERSION_TOKEN = re.compile(r"^[0-9][0-9A-Za-z.*_-]*$")


def rel(version):
    text = str(version).strip()
    if not _VERSION_TOKEN.match(text):
        return None
    text = text.split("!", 1)[-1].split("+", 1)[0]
    out = []
    for piece in text.split("."):
        m = re.match(r"^(\d+)", piece)
        if not m:
            return None
        out.append(int(m.group(1)))
    return tuple(out) or None


def succ(t):
    return t[:-1] + (t[-1] + 1,)


def pad(t, n):
    return t + (0,) * (n - len(t))


def cmp(a, b):
    n = max(len(a), len(b))
    a, b = pad(a, n), pad(b, n)
    return (a > b) - (a < b)


def in_interval(ver, lo, hi):
    return cmp(ver, lo) >= 0 and cmp(ver, hi) < 0


BIG = (10 ** 9,)


def bounds_for(clause):
    m = re.match(r"^\s*(\^|~=|~|==|!=|>=|<=|>|<|=)?\s*(.+?)\s*$", clause)
    if not m:
        return None
    op, body = m.group(1) or "", m.group(2).strip()
    if op == "" and body == "*":
        return ((0,), BIG)
    if op in ("", "=", "=="):
        if body.endswith(".*"):
            core = rel(body[:-2])
            if core is None:
                return None
            return (core, succ(core))
        core = rel(body)
        if core is None:
            return None
        return (core, succ(pad(core, len(core))))
    if op == "^":
        core = rel(body)
        if core is None:
            return None
        p = pad(core, 3)
        if p[0] > 0:
            hi = (p[0] + 1, 0, 0)
        elif p[1] > 0:
            hi = (0, p[1] + 1, 0)
        else:
            hi = (0, 0, p[2] + 1)
        return (p, hi)
    if op in ("~", "~="):
        core = rel(body)
        if core is None:
            return None
        if len(core) >= 2:
            return (core, (core[0], core[1] + 1))
        return (core, succ(core))
    if op == "!=":
        return None
    core = rel(body)
    if core is None:
        return None
    if op == ">=":
        return (core, BIG)
    if op == ">":
        return (succ(pad(core, len(core) + 1)), BIG)
    if op == "<=":
        return ((0,), succ(pad(core, len(core) + 1)))
    if op == "<":
        return ((0,), core)
    return None


def _branch(version, constraint):
    ver = rel(version)
    if ver is None:
        return False
    for clause in str(constraint).split(","):
        if clause.strip().startswith("!="):
            m = re.match(r"^\s*!=\s*(.+?)\s*$", clause)
            if not m:
                return None
            body = m.group(1)
            if body.endswith(".*"):
                core = rel(body[:-2])
                if core is None:
                    return None
                if in_interval(ver, core, succ(core)):
                    return False
            else:
                core = rel(body)
                if core is None:
                    return None
                if cmp(ver, core) == 0:
                    return False
            continue
        iv = bounds_for(clause)
        if iv is None:
            return None
        if not in_interval(ver, *iv):
            return False
    return True


def satisfies_oracle(version, specifier):
    specifier = str(specifier or "").strip()
    if specifier in ("", "*"):
        return rel(version) is not None
    branches = specifier.split("||")
    if len(branches) > 1:
        results = [_branch(version, b) for b in branches]
        if any(r is None for r in results):
            return None
        return any(r is True for r in results)
    return _branch(version, specifier)


def expected_edges(lock_path):
    data = tomllib.loads(Path(lock_path).read_text(encoding="utf-8"))
    packages = [p for p in (data.get("package") or []) if isinstance(p, dict)]
    universe = {}
    for p in packages:
        n, v = norm(p.get("name")), str(p.get("version") or "").strip()
        if n and v:
            universe.setdefault(n, []).append(v)
    expected = {}
    for p in packages:
        metadata = p.get("metadata")
        if not isinstance(metadata, dict):
            continue
        requires = metadata.get("requires-dist")
        if not isinstance(requires, list):
            continue
        pn = norm(p.get("name"))
        pv = str(p.get("version") or "").strip()
        if not pn or not pv:
            continue
        for rec in requires:
            if not isinstance(rec, dict):
                continue
            dep = str(rec.get("name") or "").strip()
            if not dep:
                continue
            specifier = str(rec.get("specifier") or "").strip()
            cn = norm(dep)
            candidates = [v for v in universe.get(cn, [])
                          if satisfies_oracle(v, specifier)]
            parseable = satisfies_oracle("1.0", specifier) is not None \
                or specifier in ("", "*")
            if not parseable or not candidates:
                expected[(pn, pv, cn)] = ("UNRESOLVED", [])
            elif len(candidates) == 1:
                expected[(pn, pv, cn)] = ("VERIFIED", candidates)
            else:
                expected[(pn, pv, cn)] = ("AMBIGUOUS", sorted(candidates))
    return expected


def main():
    lock = Path(sys.argv[1])
    edges_in = Path(sys.argv[2])
    payload = json.loads(edges_in.read_text(encoding="utf-8"))
    if isinstance(payload, dict):
        graph = payload.get("dependency_graph") or {}
        edges = graph.get("edges") or []
        sources = graph.get("sources") or []
        edges = [e for e in edges
                 if str(e.get("evidence_source") or "") == "UV_REQUIRES_DIST"]
        _ = sources
    else:
        edges = payload

    expected = expected_edges(lock)
    got = {}
    for e in edges:
        key = (norm(e.get("parent_name")), str(e.get("parent_version")),
               norm(e.get("child_name")))
        got.setdefault(key, []).append((
            str(e.get("confidence")),
            str(e.get("child_version") or ""),
            sorted((e.get("ambiguity") or {}).get("candidates") or []),
        ))

    expected_keys = set(expected)
    got_keys = set(got)
    missing = expected_keys - got_keys
    invented = got_keys - expected_keys
    correct = wrong = amb_mismatch = 0
    wrong_samples = []
    for key in expected_keys & got_keys:
        state, cands = expected[key]
        entries = got[key]
        if state == "VERIFIED":
            if any(g[0] == "VERIFIED" and g[1] == cands[0] for g in entries):
                correct += 1
            else:
                wrong += 1
                if len(wrong_samples) < 5:
                    wrong_samples.append((key, cands, entries))
        elif state == "AMBIGUOUS":
            if any(g[0] == "AMBIGUOUS" and g[2] == cands for g in entries):
                correct += 1
            else:
                amb_mismatch += 1
                if len(wrong_samples) < 5:
                    wrong_samples.append((key, cands, entries))
        else:
            if any(g[0] == "VERIFIED" for g in entries):
                wrong += 1
                if len(wrong_samples) < 5:
                    wrong_samples.append((key, "UNRESOLVED->VERIFIED", entries))
            else:
                correct += 1

    print(f"oracle expected declarations: {len(expected_keys)}")
    print(f"extractor edges: {len(edges)}  identities: {len(got_keys)}")
    print(f"CORRECT:   {correct}")
    print(f"WRONG:     {wrong}  {wrong_samples}")
    print(f"MISSING:   {len(missing)}  {sorted(missing)}")
    print(f"INVENTED:  {len(invented)}  {sorted(invented)}")
    print(f"AMBIG mismatches: {amb_mismatch}")
    ok = wrong == 0 and not missing and not invented and amb_mismatch == 0
    print("ORACLE RESULT:", "PASS" if ok else "FAIL")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
