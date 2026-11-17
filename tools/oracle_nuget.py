"""Independent .NET/NuGet oracle (R2.5b validation instrument).

Re-implements packages.config / Directory.Packages.props envelope
counting and packages.lock.json / project.assets.json resolved-edge
derivation WITHOUT importing the extractor
(`analysis/lock_graph/nuget.py`): a fresh XML/JSON walk, its own
Package/Version key splitting and its own restore-type counting derive
the expected values. Never validate an extractor against its own output.

Real-world status: the R2.5 corpus contains ZERO packages.lock.json /
project.assets.json files -- the lock tiers are fixture-validated in the
unit suite; this oracle validates the REAL corpus envelopes
(packages.config, Directory.Packages.props).

Usage:
    python -I oracle_nuget.py <packages.config> <envelope.json>
    python -I oracle_nuget.py <Directory.Packages.props> <envelope.json>
    python -I oracle_nuget.py <packages.lock.json> <envelope.json>
    python -I oracle_nuget.py <project.assets.json> <envelope.json>

Exits 0 iff identities agree.
"""

import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path


def split_key(key):
    """Fresh Package/Version split: rpartition on the last slash."""
    text = str(key or "").strip()
    name, sep, version = text.rpartition("/")
    if not sep or not name or not version:
        return (text, "")
    return (name, version)


def expected_packages_config(path):
    root = ET.parse(path).getroot()
    packages = root.findall(".//package")
    per_tfm = {}
    for p in packages:
        tfm = str(p.get("targetFramework") or "")
        per_tfm[tfm] = per_tfm.get(tfm, 0) + 1
    return len(packages), per_tfm


def expected_props(path):
    root = ET.parse(path).getroot()
    includes = root.findall(".//PackageVersion[@Include]")
    updates = root.findall(".//PackageVersion[@Update]")
    return len(includes), len(updates)


def expected_lock(path, is_assets):
    data = json.loads(Path(path).read_text(encoding="utf-8",
                                            errors="replace"))
    targets = data.get("targets") or {}
    universe = {}
    project_keys = set()
    for tfm, entries in targets.items():
        for key, meta in (entries or {}).items():
            universe.setdefault(key, str(tfm))
            if isinstance(meta, dict) and str(meta.get("type") or "") == \
                    "project":
                project_keys.add(key)
    verified = set()
    unresolved = set()
    runtime_assets = 0
    project_skips = 0
    for _tfm, entries in targets.items():
        for key, meta in (entries or {}).items():
            if isinstance(meta, dict) and str(meta.get("type") or "") == \
                    "project":
                continue
            for dep_key, _val in (meta or {}).get("dependencies") or {}:
                if dep_key in project_keys:
                    project_skips += 1
                    continue
                if dep_key in universe:
                    verified.add((key, dep_key))
                else:
                    unresolved.add((key, dep_key))
            runtime_assets += len((meta or {}).get("runtimeTargets") or {})
    restore_types = {}
    deps_section = data.get("dependencies") or {}
    if is_assets:
        blocks = [deps_section]
    else:
        blocks = list(deps_section.values())
    for block in blocks:
        for _name, meta in (block or {}).items():
            if isinstance(meta, dict):
                rtype = str(meta.get("type") or "")
                restore_types[rtype] = restore_types.get(rtype, 0) + 1
    return (verified, unresolved, runtime_assets, project_skips,
            restore_types, len(universe))


def main():
    evidence = Path(sys.argv[1])
    payload = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
    tallies = payload.get("tallies") or {}
    ok = True
    name = evidence.name

    if name == "packages.config":
        exp_members, per_tfm = expected_packages_config(evidence)
        got = payload.get("membership_packages")
        print(f"oracle packages.config: membership {exp_members}, "
              f"per-tfm {per_tfm}")
        if got != exp_members:
            ok = False
        print(f"extractor: {got}")
    elif name == "Directory.Packages.props":
        inc, upd = expected_props(evidence)
        print(f"oracle props: includes {inc}, updates {upd}")
        if tallies.get("cpm_includes") != inc or \
                tallies.get("cpm_updates") != upd:
            ok = False
        print(f"extractor: includes {tallies.get('cpm_includes')}, "
              f"updates {tallies.get('cpm_updates')}")
    elif name in ("packages.lock.json", "project.assets.json"):
        is_assets = name == "project.assets.json"
        (verified, unresolved, assets, skips, restore_types,
         universe_size) = expected_lock(evidence, is_assets)
        edges = payload.get("edges") or []
        got_verified = {(f"{e.get('parent_name')}/{e.get('parent_version')}",
                         f"{e.get('child_name')}/{e.get('child_version')}")
                        for e in edges
                        if e.get("confidence") == "VERIFIED"}
        missing = verified - got_verified
        invented = got_verified - verified
        got_unres = {(f"{e.get('parent_name')}/{e.get('parent_version')}",
                      f"{e.get('child_name')}/")
                     for e in edges
                     if e.get("resolution_status")
                     == "CHILD_NOT_IN_LOCKFILE"}
        exp_unres = {(p, f"{c.split('/')[0]}/")
                     for (p, c) in unresolved}
        print(f"oracle {name}: universe {universe_size}, VERIFIED "
              f"{len(verified)}, UNRESOLVED {len(unresolved)}, assets "
              f"{assets}, project skips {skips}, restore types "
              f"{restore_types}")
        print(f"WRONG/MISSING: {len(missing)}  {sorted(missing)}")
        print(f"INVENTED: {len(invented)}  {sorted(invented)}")
        if missing or invented:
            ok = False
        if tallies.get("runtime_assets") != assets or \
                tallies.get("project_refs_skipped") != skips:
            ok = False
            print(f"  tally mismatch runtime/project: "
                  f"{tallies.get('runtime_assets')}/{assets} "
                  f"{tallies.get('project_refs_skipped')}/{skips}")
        for rtype, count in restore_types.items():
            key = {"Direct": "restore_type_direct",
                   "Transitive": "restore_type_transitive",
                   "CentralTransitive": "restore_type_central_transitive",
                   "DirectTransitive":
                       "restore_type_direct_transitive"}.get(rtype)
            if key and tallies.get(key) != count:
                ok = False
                print(f"  restore-type mismatch {rtype}: oracle {count} "
                      f"vs extractor {tallies.get(key)}")
    else:
        print(f"unknown evidence kind: {name}")
        ok = False

    print("ORACLE RESULT:", "PASS" if ok else "FAIL")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
