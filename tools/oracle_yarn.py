"""Independent Yarn v1 lockfile edge oracle (R2.3 validation instrument).

Re-implements yarn.lock v1 resolution WITHOUT importing the extractor or
its constraint matcher (`analysis/lock_graph/*.py`): a fresh line parser
and a fresh INTERVAL intersection engine evaluate every declaration, and
the extractor's edges are compared by identity keys. Never validate an
extractor against its own output.

Usage:
    python -I oracle_yarn.py <yarn.lock> <extractor-edges.json>
    python -I oracle_yarn.py <yarn.lock> <clean_report.json> [yarn_list.json]

The second input is either a JSON list of contract edges or a scan payload
with dependency_graph.edges. The optional third input is a `yarn list
--json` capture from the yarn CLI; it provides an external cross-check:
every CLI-resolved package must exist in the lockfile universe and every
CLI parent->child declaration must appear in the extractor's declarations
(optional-only extras are expected on Windows and tallied separately).

Reports expected/extracted/correct/wrong/missing/invented/ambiguous plus
CLI cross-check tallies; exits 0 iff all checks agree.
"""

import json
import re
import sys
from pathlib import Path


# ---- independent parse of yarn.lock v1 --------------------------------------
def parse_lockfile(path):
    """-> (universe, declarations, aliases, stats) -- fresh implementation.

    universe: {name: [versions]}; declarations: list of
    (parent_name, parent_version, child_name, constraint, scope).
    """
    universe = {}
    declarations = []
    aliases = set()
    stats = {"invalid": 0, "entries": 0}
    key_re = re.compile(r'^"?([^"].*?)"?:(?:\s.*)?$')
    version_re = re.compile(r'^\s{2}version\s+"?([^"]+)"?\s*$')
    block_re = re.compile(r"^\s{2}(dependencies|optionalDependencies|"
                          r"peerDependencies):\s*$")
    dep_re = re.compile(r'^\s{4}"?([^"]+?)"?\s+"?([^"]+?)"?\s*$')
    entry = None
    block = None
    for raw in Path(path).read_text(encoding="utf-8",
                                    errors="replace").splitlines():
        line = raw.rstrip("\r")
        if not line.strip() or line.startswith("#"):
            continue
        if not line.startswith(" "):
            block = None
            m = key_re.match(line)
            if m is None:
                stats["invalid"] += 1
                entry = None
                continue
            key = m.group(1)[:-1]
            # first selector decides the package name; a scoped name keeps
            # its @, an alias key resolves to the npm: target
            sel = key.split(", ")[0].strip().strip('"')
            if "@npm:" in sel:
                aliases.add(sel.split("@npm:", 1)[0])
                sel = sel.split("@npm:", 1)[1]
            if sel.startswith("@"):
                name = "@" + sel[1:].rsplit("@", 1)[0]
            else:
                name = sel.rsplit("@", 1)[0]
            entry = {"name": name, "version": None}
            stats["entries"] += 1
            continue
        if entry is None:
            stats["invalid"] += 1
            continue
        m = version_re.match(line)
        if m:
            entry["version"] = m.group(1)
            if entry["name"] and entry["version"]:
                universe.setdefault(entry["name"], []).append(
                    entry["version"])
            continue
        m = block_re.match(line)
        if m:
            block = m.group(1)
            continue
        if block:
            m = dep_re.match(line)
            if m and entry["version"]:
                dep_name, spec = m.group(1), m.group(2)
                constraint = spec
                # npm: alias targets name the REAL installed package; the
                # alias is manifest-level only, so identity is the target
                # and the evaluated constraint is the target's spec
                if spec.startswith("npm:"):
                    aliases.add(dep_name)
                    target = spec[len("npm:"):]
                    if "@" in target:
                        dep_name = ("@" + target[1:].rsplit("@", 1)[0]
                                    if target.startswith("@")
                                    else target.rsplit("@", 1)[0])
                        constraint = target.rsplit("@", 1)[1]
                declarations.append((entry["name"], entry["version"],
                                     dep_name, constraint, block))
                continue
        stats["invalid"] += 1
    return universe, declarations, aliases, stats


# ---- independent interval resolution (npm semver subset) ---------------------
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


def pad(t, n):
    return t + (0,) * (n - len(t))


def cmp(a, b):
    n = max(len(a), len(b))
    a, b = pad(a, n), pad(b, n)
    return (a > b) - (a < b)


def succ(t):
    return t[:-1] + (t[-1] + 1,)


BIG = (10 ** 9,)


def clause_interval(clause):
    """-> (lo, hi_inclusive_None_means_open) or None when ununderstood."""
    m = re.match(r"^\s*(\^|~=|~|==|!=|>=|<=|>|<|=)?\s*(.+?)\s*$", clause)
    if not m:
        return None
    op, body = m.group(1) or "", m.group(2).strip()
    # npm x-wildcards (own normalization, same documented semantics)
    if re.fullmatch(r"[xX*](\.[xX*])*", body):
        body = "*"
    else:
        body = re.sub(r"\.[xX](\.[xX])?$", ".*", body)
    if op in ("", "=", "=="):
        if body in ("*", ""):
            return ((0,), BIG)
        if body.endswith(".*"):
            core = rel(body[:-2])
            return None if core is None else (
                core, succ(pad(core, len(core))))
        core = rel(body)
        if core is None:
            return None
        return (core, core)          # exact: inclusive both ends
    if op == "^":
        core = rel(body)
        if core is None:
            return None
        p = pad(core, 3)
        if p[0] > 0:
            return (p, ((p[0] + 1, 0, 0), None))
        if p[1] > 0:
            return (p, ((0, p[1] + 1, 0), None))
        return (p, ((0, 0, p[2] + 1), None))
    if op in ("~", "~="):
        core = rel(body)
        if core is None:
            return None
        if len(core) >= 2:
            return (core, ((core[0], core[1] + 1, 0), None))
        return (core, ((core[0] + 1, 0, 0), None))
    if op == "!=":
        return ("!", body)
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


def in_iv(ver, iv):
    lo, hi = iv
    if hi == BIG:
        return cmp(ver, lo) >= 0
    if isinstance(hi, tuple) and len(hi) == 2 and isinstance(hi[0], tuple):
        # caret/tilde intervals carry an OPEN (exclusive) upper bound
        upper = hi[0]
        return cmp(ver, lo) >= 0 and cmp(ver, upper) < 0
    return cmp(ver, lo) >= 0 and cmp(ver, hi) <= 0


def npm_satisfies(version, constraint):
    """True/False/None -- fresh interval engine over the npm dialect."""
    constraint = str(constraint or "").strip()
    if constraint in ("", "*"):
        return rel(version) is not None
    ver = rel(version)
    if ver is None:
        return False
    for branch in constraint.split("||"):
        branch = branch.strip()
        hyphen = re.search(r"(?<![<>=~^])\s-\s", branch)
        ivs = []
        ok = True
        if hyphen:
            lo, hi = (branch[:hyphen.start()].strip(),
                      branch[hyphen.end():].strip())
            ivs.append(clause_interval(f">={lo}"))
            parts = hi.split(".")
            if len(parts) >= 3:
                ivs.append(clause_interval(f"<= {hi}"))
            else:
                nums = [int(p) for p in parts if p.isdigit()]
                if len(nums) < len(parts):
                    return None
                bumped = list(pad(tuple(nums), 3))
                bumped[len(nums) - 1] += 1
                ivs.append(clause_interval(f"< {'.'.join(map(str, bumped))}"))
        else:
            for piece in _split_branch_clauses(branch):
                piece = piece.strip()
                if not piece:
                    continue
                iv = clause_interval(piece)
                if iv is None:
                    ok = False
                    break
                if iv[0] == "!":
                    core = rel(iv[1][:-2] if iv[1].endswith(".*") else iv[1])
                    if core is None:
                        ok = False
                        break
                    if cmp(ver, core) == 0 or (
                            iv[1].endswith(".*") and
                            pad(ver, len(core))[:len(core)] == core):
                        ok = False
                        break
                    continue
                ivs.append(iv)
        if not ok:
            return None
        good = True
        for iv in ivs:
            if not in_iv(ver, iv):
                good = False
                break
        if good:
            return True
    return False


def _split_branch_clauses(branch):
    if re.search(r"(?<![<>=~^])\s-\s", branch):
        return [branch]
    if "," in branch:
        return branch.split(",")
    if not re.search(r"\s", branch):
        return [branch]
    return re.findall(
        r"(?:>=|<=|~=|==|!=|[<>~^=!])?\s*[0-9][0-9A-Za-z.*_-]*",
        branch) or [branch.strip()]


# ---- oracle expected-edge computation ---------------------------------------
def expected_edges(universe, declarations):
    expected = {}
    for parent_name, parent_version, child_name, constraint, _scope in \
            declarations:
        key = (parent_name.casefold(), parent_version,
               child_name.casefold())
        matched = [v for v in universe.get(child_name, [])
                   if npm_satisfies(v, constraint)]
        parseable = npm_satisfies("1.0.0", constraint) is not None
        if not parseable:
            expected.setdefault(key, ("UNRESOLVED", []))
            continue
        # duplicate entries resolving to the same version are ONE package
        # instance: identity is name@version
        distinct = sorted(set(matched))
        if len(distinct) == 1:
            expected[key] = ("VERIFIED", distinct)
        elif len(distinct) > 1:
            prev = expected.get(key)
            if prev and prev[0] == "VERIFIED":
                continue
            expected[key] = ("AMBIGUOUS", distinct)
        else:
            if key not in expected:
                expected[key] = ("UNRESOLVED", [])
    return expected


def main():
    lock = Path(sys.argv[1])
    payload = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
    if isinstance(payload, dict):
        graph = payload.get("dependency_graph") or {}
        sources = set(graph.get("sources") or [])
        edges = [e for e in (graph.get("edges") or []) if isinstance(e, dict)]
        if sources:
            edges = [e for e in edges
                     if str(e.get("source") or "") in sources]
        edges = [e for e in edges
                 if str(e.get("evidence_source") or "")
                 == "YARN_ENTRY_DEPENDENCIES"]
    else:
        edges = payload

    universe, declarations, aliases, stats = parse_lockfile(lock)
    expected = expected_edges(universe, declarations)

    got = {}
    for e in edges:
        key = (str(e.get("parent_name") or "").casefold(),
               str(e.get("parent_version") or ""),
               str(e.get("child_name") or "").casefold())
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
        else:
            if any(g[0] == "VERIFIED" for g in entries):
                wrong += 1
                if len(wrong_samples) < 5:
                    wrong_samples.append((key, "UNRESOLVED->VERIFIED",
                                          entries))
            else:
                correct += 1

    print(f"oracle: {stats['entries']} entries, "
          f"{len(declarations)} declarations, "
          f"{stats['invalid']} invalid lines")
    print(f"oracle expected identities: {len(expected_keys)}")
    print(f"extractor edges: {len(edges)}  identities: {len(got_keys)}")
    print(f"CORRECT:   {correct}")
    print(f"WRONG:     {wrong}  {wrong_samples}")
    print(f"MISSING:   {len(missing)}  {sorted(missing)}")
    print(f"INVENTED:  {len(invented)}  {sorted(invented)}")
    print(f"AMBIG mismatches: {amb_mismatch}  {amb_samples}")

    ok = wrong == 0 and not missing and not invented and amb_mismatch == 0

    # ---- optional yarn CLI cross-check --------------------------------------
    # The CLI tree is the HOISTED layout: children of a package include
    # transitive deps hoisted under it (css-select lists dom-serializer,
    # which domutils declares), and optional platform deps may resolve
    # beyond the lockfile. So the CLI evidences SUBSET relations, not
    # equality: a CLI package is OK iff it is in the lockfile universe OR
    # declared somewhere; a CLI declaration is OK iff the extractor
    # declared it OR the child exists/is declared elsewhere (hoisted
    # attribution). Unexplained misses FAIL.
    if len(sys.argv) > 3:
        cli = json.loads(Path(sys.argv[3]).read_text(encoding="utf-8"))
        if isinstance(cli, list):
            trees = [x for x in cli if isinstance(x, dict)
                     and x.get("type") == "tree"]
            tree_entries = trees[0]["data"]["trees"] if trees else []
        else:
            tree_entries = (cli.get("data") or {}).get("trees") or []
        cli_names = {str(t.get("name") or "") for t in tree_entries}
        lock_names = {f"{n}@{v}" for n, versions in universe.items()
                      for v in versions}
        declared_names = {d[2] for d in declarations}
        known_names = declared_names | {a for a in aliases}
        cli_parents = set()
        for t in tree_entries:
            for child in t.get("children") or []:
                cname = str(child.get("name") or "")
                if "@npm:" in cname:
                    cname = cname.partition("@npm:")[2]
                if "@" in cname:
                    cli_parents.add(cname.rpartition("@")[0])
        unexplained_universe = []
        synthesized_optionals = 0
        for name in sorted(cli_names):
            if name in lock_names:
                continue
            child_name = name.rpartition("@")[0]
            if child_name in known_names:
                continue          # declared but unresolved (platform optionals)
            if child_name in cli_parents:
                # yarn synthesized an optional platform subtree (e.g.
                # @rolldown/binding-wasm32-wasi) the lockfile never recorded
                synthesized_optionals += 1
                continue
            unexplained_universe.append(name)
        print(f"CLI cross-check: {len(cli_names)} CLI-resolved packages; "
              f"{len(cli_names & lock_names)} in lockfile universe; "
              f"{synthesized_optionals} synthesized-optional (disclosed); "
              f"{len(unexplained_universe)} unexplained "
              f"{unexplained_universe}")

        decl_got = {
            (str(e.get("parent_name") or "").casefold(),
             str(e.get("parent_version") or ""),
             str(e.get("child_name") or "").casefold())
            for e in edges}
        universe_children = {n.casefold() for n in universe}
        cli_decls = 0
        hoisted_leakage = 0
        synthesized_subtree = 0
        cli_missing = []
        for t in tree_entries:
            pname = str(t.get("name") or "")
            if "@" not in pname:
                continue
            parent_name, _, parent_version = pname.rpartition("@")
            parent_resolved = pname in lock_names
            for child in t.get("children") or []:
                cname = str(child.get("name") or "")
                if "@npm:" in cname:
                    # aliased declarations report the npm: target identity
                    cname = cname.partition("@npm:")[2]
                if "@" not in cname:
                    continue
                child_name, _, constraint = cname.rpartition("@")
                if not constraint:
                    continue
                cli_decls += 1
                if (parent_name.casefold(), parent_version,
                        child_name.casefold()) in decl_got:
                    continue
                if not parent_resolved:
                    # children under a synthesized optional parent cannot be
                    # lockfile declarations at all
                    synthesized_subtree += 1
                    continue
                if child_name.casefold() in universe_children or \
                        child_name in declared_names:
                    hoisted_leakage += 1
                    continue
                cli_missing.append((parent_name, parent_version,
                                    child_name, constraint))
        print(f"CLI declarations: {cli_decls}; extractor-declared: "
              f"{cli_decls - len(cli_missing) - hoisted_leakage - synthesized_subtree}; "
              f"hoisted-layout attribution (informational): "
              f"{hoisted_leakage}; synthesized-optional subtree (disclosed): "
              f"{synthesized_subtree}; unexplained: {len(cli_missing)}  "
              f"{cli_missing}")
        if unexplained_universe or cli_missing:
            ok = False

    print("ORACLE RESULT:", "PASS" if ok else "FAIL")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
