"""Independent Cargo evidence oracle (R2.4 validation instrument).

Re-implements Cargo.lock resolution and Cargo.toml declaration counting
WITHOUT importing the extractor (`analysis/lock_graph/cargo.py`): a fresh
TOML walk, its own dependency-entry parsing (whitespace/parenthesis
token walk) and its own instance resolution derive the expected graph.
Never validate an extractor against its own output.

Contract semantics modeled independently:
- a dependency entry resolving to exactly ONE package instance ->
  VERIFIED (exact name+version, or unique same-name, or source-hint
  disambiguated);
- a versionless entry naming several same-name instances -> AMBIGUOUS
  with the full candidate set;
- zero matches -> UNRESOLVED.

Usage:
    python -I oracle_cargo.py <Cargo.lock> <extractor-edges.json>
    python -I oracle_cargo.py <Cargo.toml> <extractor-envelope.json>

Reports correct/wrong/missing/invented/ambiguous/unresolved and exits 0
iff identities agree.
"""

import json
import sys
import tomllib
from pathlib import Path


def parse_dep_entry(entry):
    """Own token walk: 'name', 'name version', 'name version (source)'."""
    text = str(entry).strip().strip('"')
    source = ""
    if text.endswith(")") and "(" in text:
        depth = 0
        for idx in range(len(text) - 1, -1, -1):
            if text[idx] == ")":
                depth += 1
            elif text[idx] == "(":
                depth -= 1
                if depth == 0:
                    source = text[idx + 1:-1].strip()
                    text = text[:idx].strip()
                    break
    fields = text.split()
    if not fields:
        return ("", "", "")
    name = fields[0]
    version = fields[1] if len(fields) > 1 else ""
    return (name, version, source)


def expected_lock(path):
    """-> (verified, ambiguous, unresolved) from a fresh TOML walk."""
    data = tomllib.loads(Path(path).read_text(encoding="utf-8",
                                              errors="replace"))
    packages = [p for p in (data.get("package") or []) if isinstance(p, dict)]
    by_name = {}
    for p in packages:
        name = str(p.get("name") or "")
        version = str(p.get("version") or "")
        if name and version:
            by_name.setdefault(name, []).append(
                {"name": name, "version": version,
                 "source": str(p.get("source") or "")})

    verified = set()
    ambiguous = {}
    unresolved = set()
    for p in packages:
        parent_name = str(p.get("name") or "")
        parent_version = str(p.get("version") or "")
        if not parent_name or not parent_version:
            continue
        for entry in p.get("dependencies") or []:
            child_name, child_version, source_hint = parse_dep_entry(entry)
            if not child_name:
                continue
            blocks = by_name.get(child_name) or []
            if child_version:
                exact = [b for b in blocks if b["version"] == child_version]
                if len(exact) == 1:
                    verified.add((parent_name, parent_version,
                                  exact[0]["name"], exact[0]["version"]))
                    continue
                if not exact:
                    unresolved.add((parent_name, parent_version,
                                    child_name, child_version))
                    continue
            else:
                if len(blocks) == 1:
                    verified.add((parent_name, parent_version,
                                  blocks[0]["name"], blocks[0]["version"]))
                    continue
                if not blocks:
                    unresolved.add((parent_name, parent_version,
                                    child_name, child_version))
                    continue
            if source_hint:
                narrowed = [b for b in blocks
                            if source_hint in b["source"]]
                if len(narrowed) == 1:
                    verified.add((parent_name, parent_version,
                                  narrowed[0]["name"],
                                  narrowed[0]["version"]))
                    continue
            key = (parent_name, parent_version, child_name)
            ambiguous[key] = sorted(
                f"{b['name']}@{b['version']}" for b in blocks)
    return verified, ambiguous, unresolved


def expected_toml(path):
    """-> declaration tallies (fresh derivation, own counting)."""
    data = tomllib.loads(Path(path).read_text(encoding="utf-8",
                                              errors="replace"))
    out = {"dependencies_declarations": 0, "dev_dependencies_declarations": 0,
           "build_dependencies_declarations": 0, "target_blocks": 0,
           "renamed_dependencies": 0, "workspace_inherited_declarations": 0,
           "membership_packages": 0}

    def count(block):
        total = 0
        for name, spec in (block or {}).items():
            total += 1
            if isinstance(spec, dict):
                if spec.get("workspace") is True:
                    out["workspace_inherited_declarations"] += 1
                if spec.get("package"):
                    out["renamed_dependencies"] += 1
        return total

    out["dependencies_declarations"] = count(data.get("dependencies"))
    out["dev_dependencies_declarations"] = count(
        data.get("dev-dependencies"))
    out["build_dependencies_declarations"] = count(
        data.get("build-dependencies"))
    out["membership_packages"] = (out["dependencies_declarations"] +
                                  out["dev_dependencies_declarations"] +
                                  out["build_dependencies_declarations"])
    targets = data.get("target") or {}
    if isinstance(targets, dict):
        for _triple, sections in targets.items():
            if not isinstance(sections, dict):
                continue
            had = False
            for key in ("dependencies", "dev-dependencies",
                        "build-dependencies"):
                n = count(sections.get(key))
                if n:
                    had = True
                out["membership_packages"] += n
            if had:
                out["target_blocks"] += 1
    ws = data.get("workspace") or {}
    if isinstance(ws, dict):
        out["workspace_members"] = len(ws.get("members") or [])
        out["workspace_dependency_definitions"] = len(ws.get("dependencies")
                                                      or {})
    return out


def main():
    evidence = Path(sys.argv[1])
    payload = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
    ok = True
    if evidence.name == "Cargo.lock":
        edges = payload.get("edges") or []
        verified, ambiguous, unresolved = expected_lock(evidence)
        got = {(str(e.get("parent_name") or ""),
                str(e.get("parent_version") or ""),
                str(e.get("child_name") or ""),
                str(e.get("child_version") or ""))
               for e in edges if e.get("confidence") == "VERIFIED"}
        missing = verified - got
        invented = got - verified
        got_amb = {str(e.get("parent_name")) + "|" +
                   str(e.get("parent_version")) + "|" +
                   str(e.get("child_name")):
                   sorted((e.get("ambiguity") or {}).get("candidates") or [])
                   for e in edges if e.get("confidence") == "AMBIGUOUS"}
        amb_bad = {k: (v, got_amb.get(k)) for k, v in ambiguous.items()
                   if got_amb.get(k) != v}
        got_unres = {(str(e.get("parent_name") or ""),
                      str(e.get("parent_version") or ""),
                      str(e.get("child_name") or ""),
                      str(e.get("child_version") or ""))
                     for e in edges
                     if e.get("confidence") == "UNRESOLVED"
                     and e.get("resolution_status")
                     == "CHILD_NOT_IN_LOCKFILE"}
        unres_bad = unresolved - got_unres
        print(f"oracle lock: expected VERIFIED {len(verified)}, "
              f"AMBIGUOUS {len(ambiguous)}, UNRESOLVED {len(unresolved)}")
        print(f"extractor VERIFIED identities: {len(got)}")
        print(f"WRONG/MISSING: {len(missing)}  {sorted(missing)[:5]}")
        print(f"INVENTED: {len(invented)}  {sorted(invented)[:5]}")
        print(f"AMBIG mismatches: {len(amb_bad)}  "
              f"{list(amb_bad.items())[:3]}")
        print(f"UNRESOLVED not preserved: {len(unres_bad)}  "
              f"{sorted(unres_bad)[:3]}")
        ok = (not missing and not invented and not amb_bad
              and not unres_bad)
    elif evidence.name == "Cargo.toml":
        exp = expected_toml(evidence)
        tallies = payload.get("tallies") or {}
        print(f"oracle toml: {exp}")
        for key, value in exp.items():
            # membership_packages lives at the envelope root; optional
            # tally keys (workspace blocks) are absent when zero-valued
            got_value = (payload.get("membership_packages")
                         if key == "membership_packages"
                         else tallies.get(key, 0))
            state = "OK" if got_value == value else \
                f"MISMATCH (extractor {got_value})"
            if got_value != value:
                ok = False
            print(f"  {key}: {value} {state}")
    else:
        print(f"unknown evidence file kind: {evidence.name}")
        ok = False

    print("ORACLE RESULT:", "PASS" if ok else "FAIL")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
