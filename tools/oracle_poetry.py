"""Independent Poetry lockfile edge oracle (R2.1 validation instrument).

Re-implements poetry.lock resolution WITHOUT importing the extractor or its
constraint matcher (`analysis/lock_graph/versions.py`): the oracle expands
each constraint into explicit [lo, hi) intervals with its own parser and
filters the resolved universe by interval membership. Never validate an
extractor against its own output.

Usage:
    python -I oracle_poetry.py <poetry.lock> <extractor-edges.json>
    python -I oracle_poetry.py <poetry.lock> <clean_report.json>

The second input is either a JSON list of contract edges or a scan payload
with dependency_graph.edges. Reports expected/extracted/correct/incorrect/
missing/invented/ambiguous/unresolved and exits 0 iff identities agree.

Confidence semantics mirrored independently: declaration matching exactly
one resolved version -> VERIFIED; >=2 -> AMBIGUOUS (candidates); 0 ->
UNRESOLVED. The oracle does not evaluate purls (the extractor's purl
authority is scanner.purl, pinned by unit tests) -- identity comparison uses
(name, version) tuples with PEP 503 normalization.
"""

import json
import re
import sys
import tomllib
from pathlib import Path


def norm(name):
    return re.sub(r"[-_.]+", "-", str(name or "").strip()).casefold()


# ---- independent interval-based constraint evaluation -----------------------
_VERSION_TOKEN = re.compile(r"^[0-9][0-9A-Za-z.*_-]*$")


def rel(version):
    # STRICT: a bound must be a clean version token -- accidental numeric
    # prefixes (e.g. swallowing "5.13.0 || >5.13.0" into "5.13") would let
    # the oracle accept constraints it does not actually understand.
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


def pad(t, n):
    return t + (0,) * (n - len(t))


def succ(t):
    return t[:-1] + (t[-1] + 1,)


def cmp(a, b):
    n = max(len(a), len(b))
    a, b = pad(a, n), pad(b, n)
    return (a > b) - (a < b)


def in_interval(ver, lo, hi):
    return cmp(ver, lo) >= 0 and cmp(ver, hi) < 0


def bounds_for(clause):
    """-> (lo, hi) or None when the clause is not understood."""
    m = re.match(r"^\s*(\^|~=|~|==|!=|>=|<=|>|<|=)?\s*(.+?)\s*$", clause)
    if not m:
        return None
    op, body = m.group(1) or "", m.group(2).strip()
    if op == "" and body == "*":
        return ((0,), (10 ** 9,))
    if op in ("", "=", "=="):
        if body.endswith(".*"):
            core = rel(body[:-2])
            if core is None:
                return None
            return (core, core[:-1] + (core[-1] + 1,))
        core = rel(body)
        if core is None:
            return None
        return (core, tuple(x + 1 for x in pad(core, len(core))))
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
        return (core, (core[0] + 1,))
    if op == "!=":
        return None  # exclusions handled by the caller, not intervals
    core = rel(body)
    if core is None:
        return None
    if op == ">=":
        return (core, (10 ** 9,))
    if op == ">":
        # exclusive lower bound: smallest release strictly greater than the
        # core (increment the LAST element of the padded core -- incrementing
        # every component wrongly excludes mid-range versions like 2.10.6
        # for ">2.1.0").
        return (succ(pad(core, len(core) + 1)), (10 ** 9,))
    if op == "<=":
        # inclusive upper bound: smallest release strictly greater than the
        # padded core.
        return ((0,), succ(pad(core, len(core) + 1)))
    if op == "<":
        return ((0,), core)
    return None


def satisfies_oracle(version, constraint):
    """True/False/None -- None = unparseable (mirrors contract semantics)."""
    constraint = str(constraint or "").strip()
    if constraint in ("", "*"):
        return rel(version) is not None
    ver = rel(version)
    if ver is None:
        return False
    branches = constraint.split("||")
    if len(branches) > 1:
        results = [_branch(version, b) for b in branches]
        if any(r is None for r in results):
            return None
        return any(r is True for r in results)
    return _branch(version, constraint)


def _branch(version, constraint):
    ver = rel(version)
    if ver is None:
        return False
    intervals = []
    for clause in constraint.split(","):
        if clause.strip().startswith("!="):
            m = re.match(r"^\s*!=\s*(.+?)\s*$", clause)
            if not m:
                return None
            body = m.group(1)
            if body.endswith(".*"):
                core = rel(body[:-2])
                if core is None:
                    return None
                if in_interval(ver, core, core[:-1] + (core[-1] + 1,)):
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
        intervals.append(iv)
    return all(in_interval(ver, lo, hi) for lo, hi in intervals)


# ---- oracle expected-edge computation ---------------------------------------
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
        deps = p.get("dependencies")
        if not isinstance(deps, dict):
            continue
        pn, pv = norm(p.get("name")), str(p.get("version") or "").strip()
        if not pn or not pv:
            continue
        for dep, spec in deps.items():
            cn = norm(dep)
            # A spec may be a single declaration or a LIST of alternative
            # declarations (each evaluated independently; a candidate is
            # matched if ANY alternative matches it). Union constraints
            # inside one string are handled by satisfies_oracle itself.
            if isinstance(spec, list):
                alternatives = [
                    str(s.get("version") or "*")
                    for s in spec if isinstance(s, dict)
                ] or ["*"]
            elif isinstance(spec, dict):
                alternatives = [str(spec.get("version") or "*")]
            else:
                alternatives = [str(spec or "*")]

            verified = set()
            ambiguous = set()
            for constraint in alternatives:
                matched = [v for v in universe.get(cn, [])
                           if satisfies_oracle(v, constraint)]
                parseable = satisfies_oracle("1.0", constraint) is not None
                if not parseable:
                    continue  # this alternative is declared-but-ununderstood
                if len(matched) == 1:
                    verified.update(matched)
                elif len(matched) > 1:
                    ambiguous.update(matched)
            if verified:
                expected[(pn, pv, cn)] = ("VERIFIED", sorted(verified))
            elif ambiguous:
                expected[(pn, pv, cn)] = ("AMBIGUOUS", sorted(ambiguous))
            else:
                expected[(pn, pv, cn)] = ("UNRESOLVED", [])
    return expected


def main():
    lock = Path(sys.argv[1])
    edges_in = Path(sys.argv[2])
    payload = json.loads(edges_in.read_text(encoding="utf-8"))
    if isinstance(payload, dict):
        edges = (payload.get("dependency_graph") or {}).get("edges") or []
        sources = (payload.get("dependency_graph") or {}).get("sources") or []
        edges = [e for e in edges
                 if str(e.get("source") or "") in sources or not sources]
        edges = [e for e in edges
                 if str(e.get("evidence_source") or "")
                 == "POETRY_PACKAGE_DEPENDENCIES"]
    else:
        edges = payload

    expected = expected_edges(lock)

    # extractor side: identity -> list of (confidence, child_version, candidates)
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
    wrong_samples, amb_samples = [], []
    for key in expected_keys & got_keys:
        state, cands = expected[key]
        entries = got[key]
        if state == "VERIFIED":
            hit = [g for g in entries
                   if g[0] == "VERIFIED" and g[1] == cands[0]]
            if hit:
                correct += 1
            else:
                wrong += 1
                if len(wrong_samples) < 5:
                    wrong_samples.append((key, cands, entries))
        elif state == "AMBIGUOUS":
            hit = [g for g in entries
                   if g[0] == "AMBIGUOUS" and g[2] == cands]
            if hit:
                amb_mismatch += 0
            else:
                amb_mismatch += 1
                if len(amb_samples) < 5:
                    amb_samples.append((key, cands, entries))
        else:  # UNRESOLVED: extractor must not emit a VERIFIED edge
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
    print(f"AMBIG mismatches: {amb_mismatch}  {amb_samples}")
    ok = wrong == 0 and not missing and not invented and amb_mismatch == 0
    print("ORACLE RESULT:", "PASS" if ok else "FAIL")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
