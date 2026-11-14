"""Independent Ruby/Bundler oracle (R2.5a validation instrument).

Re-implements Gemfile.lock specs resolution WITHOUT importing the
extractor (`analysis/lock_graph/rubygems.py`): a fresh indent-walk and
its own pessimistic-interval engine derive the expected graph, and the
extractor's edges are compared by identity keys. Never validate an
extractor against its own output.

Contract semantics modeled independently:
- a child constraint matching exactly ONE resolved gem instance ->
  VERIFIED;
- several matches -> AMBIGUOUS with the full candidate set;
- zero matches / unparseable constraint -> UNRESOLVED;
- '~>' pessimistic intervals computed with RubyGems' own bump rule
  (second-to-last segment), implemented as explicit [lo, hi) bounds --
  no operator mapping shared with the extractor.

Usage:
    python -I oracle_rubygems.py <Gemfile.lock> <extractor-edges.json>
    python -I oracle_rubygems.py <Gemfile> <extractor-envelope.json>

Reports expected/extracted/correct/wrong/missing/invented/ambiguous
plus declaration tallies; exits 0 iff identities agree.
"""

import json
import re
import sys
from pathlib import Path


def rel(version):
    """Numeric release head; alphanumeric prerelease pieces (real corpus
    shape ``>= 5.a``) take the longest numeric head -- the CONTRACT's
    disclosed approximation (R2.1), applied here as the comparison
    convention so a sound approximation is not flagged as disagreement."""
    text = str(version).strip()
    m = re.match(r"^(\d+(?:\.\d+)*)", text)
    if not m:
        return None
    return tuple(int(p) for p in m.group(1).split(".")) or None


def pad(t, n):
    return t + (0,) * (n - len(t))


def cmp(a, b):
    n = max(len(a), len(b))
    a, b = pad(a, n), pad(b, n)
    return (a > b) - (a < b)


def pessimistic_interval(core):
    """RubyGems '~> X': explicit [lo, hi) interval -- the SECOND-TO-LAST
    segment bumps (2-seg A.B -> [A.B, (A+1).0); 3-seg A.B.C ->
    [A.B.C, A.(B+1).0); 4-seg A.B.C.D -> [A.B.C.D, A.B.(C+1).0)); None
    when unmodelable."""
    nums = [int(p) for p in core.split(".")]
    if len(nums) == 1:
        return None                      # '~> A' is invalid RubyGems syntax
    lo = tuple(nums)
    hi = list(nums[:len(nums) - 1])
    hi[-1] += 1
    hi = hi + [0] * (len(nums) - len(hi))
    return (lo, tuple(hi))


def satisfies_oracle(version, constraint):
    """True/False/None over the Ruby dialect -- own interval engine."""
    text = str(constraint or "").strip()
    if text in ("", "*"):
        return rel(version) is not None
    ver = rel(version)
    if ver is None:
        return False
    for clause in text.split(","):
        clause = clause.strip()
        m = re.match(r"^(~>|>=|<=|==|!=|>|<|=)\s*(.+)$", clause)
        if not m:
            return None
        op, body = m.group(1), m.group(2).strip()
        if op == "~>":
            iv = pessimistic_interval(body)
            if iv is None:
                return None
            lo, hi = iv
            if cmp(ver, lo) < 0 or cmp(ver, hi) >= 0:
                return False
            continue
        core = rel(body)
        if core is None:
            return None
        if op in ("=", "=="):
            if cmp(ver, core) != 0:
                return False
        elif op == "!=":
            if cmp(ver, core) == 0:
                return False
        elif op == ">=":
            if cmp(ver, core) < 0:
                return False
        elif op == ">":
            if cmp(ver, core) <= 0:
                return False
        elif op == "<=":
            if cmp(ver, core) > 0:
                return False
        elif op == "<":
            if cmp(ver, core) >= 0:
                return False
    return True


def expected_lock(path):
    """-> (universe, expected) via a fresh indent-walk.

    expected: {(parent, pver, child): (confidence, cver, candidates)}.
    """
    universe = {}
    declarations = []
    section = None
    in_specs = False
    stack = []                    # (indent, name, version)
    direct = 0
    git_decl = 0
    platforms = 0
    for raw in Path(path).read_text(encoding="utf-8",
                                    errors="replace").splitlines():
        line = raw.rstrip("\r")
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if not line[:1].isspace():
            section = stripped
            in_specs = False
            stack = []
            continue
        if section in ("GEM", "GIT", "PATH", "PLUGIN"):
            if stripped == "specs:":
                in_specs = True
                stack = []
                continue
            if not in_specs:
                continue
            m = re.match(r"^(\S+)\s+\(([^)]+)\)\s*$", stripped)
            if m is None:
                continue
            name, version = m.group(1), m.group(2)
            indent = len(line) - len(line.lstrip(" "))
            if version.startswith((">", "<", "=", "~", "!")):
                while stack and stack[-1][0] >= indent:
                    stack.pop()
                if stack:
                    declarations.append((stack[-1][1], stack[-1][2],
                                         name, version))
                continue
            universe.setdefault(name, []).append(version)
            stack = [(i, n, v) for (i, n, v) in stack if i < indent]
            stack.append((indent, name, version))
        elif section == "PLATFORMS":
            platforms += 1
        elif section == "DEPENDENCIES":
            if stripped.endswith("!"):
                git_decl += 1
            direct += 1

    expected = {}
    for parent_name, parent_version, child_name, constraint in declarations:
        key = (parent_name, parent_version, child_name)
        # F-R5-3 (own implementation): an EXACT constraint that is not a
        # plain numeric version carries a platform variant or prerelease
        # head -- verbatim instance matching is authoritative, no numeric
        # fallback
        m_exact = re.match(r"^=\s*(\S+)$", constraint.strip())
        if m_exact and not re.fullmatch(r"\d+(?:\.\d+)*", m_exact.group(1)):
            requested = m_exact.group(1)
            verbatim = sorted({v for v in universe.get(child_name, [])
                               if v == requested})
            if not verbatim:
                expected.setdefault(key, ("UNRESOLVED", "", []))
                continue
            expected[key] = ("VERIFIED", verbatim[0], verbatim)
            continue
        matched = sorted({v for v in universe.get(child_name, [])
                          if satisfies_oracle(v, constraint)})
        parseable = satisfies_oracle("1.0.0", constraint) is not None
        if not parseable:
            expected.setdefault(key, ("UNRESOLVED", "", matched))
            continue
        if len(matched) == 1:
            expected[key] = ("VERIFIED", matched[0], matched)
        elif len(matched) > 1:
            prev = expected.get(key)
            if prev and prev[0] == "VERIFIED":
                continue
            expected[key] = ("AMBIGUOUS", "", matched)
        else:
            expected.setdefault(key, ("UNRESOLVED", "", []))
    tallies = {"direct_declarations": direct, "git_declarations": git_decl,
               "platforms": platforms, "membership_packages":
                   len({(n) for n in universe})}
    return universe, expected, tallies


def main():
    evidence = Path(sys.argv[1])
    payload = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
    edges = payload.get("edges") or []
    ok = True
    if evidence.name == "Gemfile.lock":
        universe, expected, tallies = expected_lock(evidence)
        got = {}
        for e in edges:
            key = (str(e.get("parent_name") or ""),
                   str(e.get("parent_version") or ""),
                   str(e.get("child_name") or ""))
            got.setdefault(key, []).append(
                (str(e.get("confidence")),
                 str(e.get("child_version") or ""),
                 sorted((e.get("ambiguity") or {}).get("candidates") or [])))
        exp_keys = set(expected)
        got_keys = set(got)
        missing = exp_keys - got_keys
        invented = got_keys - exp_keys
        correct = wrong = amb_bad = 0
        wrong_samples, amb_samples = [], []
        for key in exp_keys & got_keys:
            state, cver, cands = expected[key]
            entries = got[key]
            if state == "VERIFIED":
                if any(g[0] == "VERIFIED" and g[1] == cver
                       for g in entries):
                    correct += 1
                else:
                    wrong += 1
                    if len(wrong_samples) < 5:
                        wrong_samples.append((key, cver, entries))
            elif state == "AMBIGUOUS":
                if any(g[0] == "AMBIGUOUS" and g[2] == cands
                       for g in entries):
                    correct += 1
                else:
                    amb_bad += 1
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
        print(f"oracle lock: {len(universe)} gem names, "
              f"{len(exp_keys)} declared identities, tallies {tallies}")
        print(f"extractor edges: {len(edges)}  identities: {len(got_keys)}")
        print(f"CORRECT:   {correct}")
        print(f"WRONG:     {wrong}  {wrong_samples}")
        print(f"MISSING:   {len(missing)}  {sorted(missing)[:5]}")
        print(f"INVENTED:  {len(invented)}  {sorted(invented)[:5]}")
        print(f"AMBIG mismatches: {amb_bad}  {amb_samples}")
        ok = wrong == 0 and not missing and not invented and amb_bad == 0
        dt = payload.get("tallies") or {}
        for key, value in tallies.items():
            got_value = (payload.get("membership_packages")
                         if key == "membership_packages"
                         else dt.get(key))
            if got_value != value:
                ok = False
                print(f"  tally mismatch {key}: oracle {value} vs "
                      f"extractor {got_value}")
    elif evidence.name == "Gemfile":
        # fresh declaration count
        gem_lines = 0
        git_count = path_count = reg_count = 0
        groups = 0
        in_group = False
        for raw in evidence.read_text(encoding="utf-8",
                                      errors="replace").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("group ") and line.endswith("do"):
                groups += 1
                in_group = True
                continue
            if line == "end" and in_group:
                in_group = False
                continue
            m = re.match(r'^\s*gem\s+["\']([^"\']+)["\']', line)
            if m:
                gem_lines += 1
                if re.search(r"git:\s*[\"']", line):
                    git_count += 1
                elif re.search(r"path:\s*[\"']", line):
                    path_count += 1
                else:
                    reg_count += 1
        t = payload.get("tallies") or {}
        exp = {"gem_declarations": gem_lines, "source_git": git_count,
               "source_path": path_count, "source_registry": reg_count,
               "group_blocks": groups}
        print(f"oracle Gemfile: {exp}")
        for key, value in exp.items():
            got_value = t.get(key)
            if got_value != value:
                ok = False
                print(f"  MISMATCH {key}: oracle {value} vs extractor "
                      f"{got_value}")
    else:
        print(f"unknown evidence kind: {evidence.name}")
        ok = False

    print("ORACLE RESULT:", "PASS" if ok else "FAIL")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
