"""Independent pnpm lockfile edge oracle (R2.3 validation instrument).

Re-implements pnpm-lock.yaml snapshot resolution WITHOUT importing the
extractor (`analysis/lock_graph/pnpm.py`): a fresh YAML walk and its own
identity/peer-suffix parsing derive the expected edge set, and the
extractor's edges are compared by identity keys. Never validate an
extractor against its own output.

Usage:
    python -I oracle_pnpm.py <pnpm-lock.yaml> <pnpm-edges.json>
        [npm-edges.json] [package-lock.json]

The optional npm pair enables the CROSS-FORMAT comparison (real evidence:
pnpm 11.10.0 `pnpm import` generated the pnpm lockfile from the same
project's package-lock.json, and the npm engine parsed that original).
Because the two files genuinely differ (pnpm import reads only the flat
``packages`` section -- nested-tree-only relations are absent from the
pnpm file; pnpm synthesizes peer/auto-installed relations absent from
package-lock), the comparison GATES on file-presence, not equality:

- every npm-only relation must be ABSENT from the pnpm file (else the
  extractor missed a recorded relation);
- every pnpm-only relation must be ABSENT from package-lock's flat
  packages deps (else the extractor invented one).

Reports expected/extracted/correct/wrong/missing/invented plus
cross-format classifications; exits 0 iff all gates agree.
"""

import json
import sys
from pathlib import Path

import yaml

NPM_MARK = "@npm:"
REGISTRY_SCHEMES = ("http:", "https:", "file:", "link:")


def split_peer_suffix(value):
    text = str(value or "").strip()
    peers = []
    while text.endswith(")"):
        open_at = text.rfind("(")
        if open_at < 0:
            break
        peers.insert(0, text[open_at + 1:-1])
        text = text[:open_at]
    return text, peers


def split_identity(key):
    text = str(key or "").strip()
    if text.startswith("@"):
        at = text.find("@", 1)
    else:
        at = text.find("@")
    if at < 0:
        return (text, "")
    return (text[:at], text[at + 1:])


def is_registry(value):
    base = split_peer_suffix(value)[0].strip()
    return bool(base) and "(" not in base and not base.startswith(
        REGISTRY_SCHEMES)


def parse_pnpm(path):
    """-> (universe, expected_edges) -- fresh derivation.

    expected_edges: {(parent_name, parent_version, child_name,
    child_version_or_''): (confidence, status, candidates)}.
    """
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8",
                                               errors="replace"))
    packages = data.get("packages") or {}
    universe = {str(k): (v if isinstance(v, dict) else {})
                for k, v in packages.items()}
    version_label = str(data.get("lockfileVersion") or "")
    if version_label == "5.4":
        relation_sources = [((str(k), v), k, False)
                            for k, v in packages.items()]
    else:
        snapshots = data.get("snapshots") or {}
        relation_sources = [((str(k), v), k, True)
                            for k, v in snapshots.items()]

    expected = {}
    for (key, rels), raw_key, is_snapshot in relation_sources:
        if not isinstance(rels, dict):
            continue
        name, raw_version = split_identity(key)
        base, _ = split_peer_suffix(raw_version)
        if not name or not base:
            continue
        for block in ("dependencies", "optionalDependencies"):
            for child_name, value in (rels.get(block) or {}).items():
                child_value, _ = split_peer_suffix(str(value))
                identity = (name, base, str(child_name))
                if not is_registry(child_value):
                    expected.setdefault(
                        (identity, ""), ("UNRESOLVED",
                                         "NON_REGISTRY_RESOLUTION", []))
                    continue
                # membership: packages universe, direct or alias spelling
                member = any(
                    k == f"{child_name}@{child_value}" or
                    (k.startswith(f"{child_name}{NPM_MARK}") and
                     split_identity(k.partition(NPM_MARK)[2])[1] ==
                     child_value)
                    for k in universe)
                snap_member = False
                if not member and not is_snapshot:
                    prefix = f"{child_name}@{child_value}"
                    snap_member = any(
                        k == prefix or k.startswith(prefix + "(")
                        for k in relation_keys(universe))
                if member or snap_member:
                    expected.setdefault(
                        (identity, child_value), ("VERIFIED", "", []))
                else:
                    expected.setdefault(
                        (identity, ""), ("UNRESOLVED",
                                         "CHILD_NOT_IN_LOCKFILE", []))
    return universe, expected, version_label


def relation_keys(universe):
    return list(universe.keys())


def pnpm_file_records_relation(path, parent_name, parent_version,
                               child_name):
    """True when the pnpm FILE itself could hold the relation."""
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8",
                                               errors="replace"))
    sections = []
    if str(data.get("lockfileVersion") or "") == "5.4":
        sections = [(data.get("packages") or {}).items()]
    else:
        sections = [(data.get("snapshots") or {}).items(),
                    (data.get("packages") or {}).items()]
    for section in sections:
        for key, rels in section:
            name, raw_version = split_identity(str(key))
            base, _ = split_peer_suffix(raw_version)
            if name != parent_name or base != parent_version:
                continue
            if not isinstance(rels, dict):
                continue
            for block in ("dependencies", "optionalDependencies"):
                if child_name in (rels.get(block) or {}):
                    return True
    return False


def package_lock_records_relation(lock_path, parent_name, parent_version,
                                  child_name):
    """True when package-lock's flat packages section records the relation."""
    pl = json.loads(Path(lock_path).read_text(encoding="utf-8"))
    pkgs = pl.get("packages") or {}
    wanted = f"{parent_name}@{parent_version}"
    for key, node in pkgs.items():
        if not isinstance(node, dict):
            continue
        # node_modules/<...>/name -> package name = last path segment
        parts = str(key).split("node_modules/")
        if not parts:
            continue
        node_name = parts[-1]
        version = str(node.get("version") or "")
        if node_name != parent_name or version != parent_version:
            continue
        for block in ("dependencies", "optionalDependencies"):
            deps = node.get(block) or {}
            if child_name in deps:
                return True
    return False


def main():
    lock = Path(sys.argv[1])
    payload = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
    edges = payload if isinstance(payload, list) else payload.get("edges")
    edges = [e for e in edges
             if str(e.get("evidence_source") or "")
             == "PNPM_SNAPSHOT_DEPENDENCIES"]

    universe, expected, version_label = parse_pnpm(lock)

    got = {}
    for e in edges:
        key = (str(e.get("parent_name") or ""),
               str(e.get("parent_version") or ""),
               str(e.get("child_name") or ""),
               str(e.get("child_version") or ""))
        got.setdefault(key, []).append((str(e.get("confidence")),
                                        str(e.get("resolution_status"))))

    expected_keys = set(expected)
    got_keys = set(got)
    missing = expected_keys - got_keys
    invented = got_keys - expected_keys
    correct = wrong = status_mismatch = 0
    wrong_samples, status_samples = [], []
    for key in expected_keys & got_keys:
        state, status, _cands = expected[key]
        entries = got[key]
        if state == "VERIFIED":
            if any(g[0] == "VERIFIED" for g in entries):
                correct += 1
            else:
                wrong += 1
                if len(wrong_samples) < 5:
                    wrong_samples.append((key, state, entries))
        else:
            if any(g[0] == "VERIFIED" for g in entries):
                wrong += 1
                if len(wrong_samples) < 5:
                    wrong_samples.append((key, f"{status}->VERIFIED",
                                          entries))
            elif any(g[1] and g[1] != status for g in entries if g[1]):
                status_mismatch += 1
                if len(status_samples) < 5:
                    status_samples.append((key, status, entries))
            else:
                correct += 1

    print(f"oracle: lockfileVersion {version_label}, "
          f"{len(universe)} packages, {len(expected_keys)} expected "
          f"identities")
    print(f"extractor edges: {len(edges)}  identities: {len(got_keys)}")
    print(f"CORRECT:   {correct}")
    print(f"WRONG:     {wrong}  {wrong_samples}")
    print(f"MISSING:   {len(missing)}  {sorted(missing)[:5]}")
    print(f"INVENTED:  {len(invented)}  {sorted(invented)[:5]}")
    print(f"STATUS mismatches: {status_mismatch}  {status_samples}")
    ok = wrong == 0 and not missing and not invented

    # ---- cross-format comparison (file-presence gates) ----------------------
    if len(sys.argv) > 3:
        npm_edges = json.loads(Path(sys.argv[3]).read_text(
            encoding="utf-8"))
        if isinstance(npm_edges, dict):
            npm_edges = npm_edges.get("edges") or []

        def parse_purl(purl):
            text = str(purl or "").replace("pkg:npm/", "")
            at = text.rfind("@")
            if at <= 0:
                return ("", "")
            return (text[:at].replace("%40", "@"), text[at + 1:])

        npm_rels = set()
        npm_root = 0
        for e in npm_edges:
            if str(e.get("parent") or "") == "pkg:npm/__root__":
                npm_root += 1
                continue
            pn, pv = parse_purl(e.get("parent"))
            if not pn:
                continue
            npm_rels.add((pn, pv, str(e.get("child_name") or ""),
                          str(e.get("child_version") or "")))
        pnpm_rels = {(e["parent_name"], e["parent_version"],
                      e["child_name"], e["child_version"])
                     for e in edges if e["confidence"] == "VERIFIED"}
        only_npm = sorted(npm_rels - pnpm_rels)
        only_pnpm = sorted(pnpm_rels - npm_rels)
        print(f"cross-format: npm unique {len(npm_rels)} "
              f"(root-declared {npm_root}, not edges), pnpm unique "
              f"{len(pnpm_rels)}; npm-only {len(only_npm)}, pnpm-only "
              f"{len(only_pnpm)}")

        lock_path = Path(sys.argv[4]) if len(sys.argv) > 4 else None
        unexplained = []
        for rel in only_npm:
            pn, pv, cn, _cv = rel
            if pnpm_file_records_relation(lock, pn, pv, cn):
                unexplained.append(("npm-only but recorded in pnpm file",
                                    rel))
        for rel in only_pnpm:
            pn, pv, cn, _cv = rel
            if lock_path and package_lock_records_relation(
                    lock_path, pn, pv, cn):
                unexplained.append(("pnpm-only but recorded in "
                                    "package-lock", rel))
        print(f"cross-format unexplained: {len(unexplained)}  "
              f"{unexplained[:3]}")
        if unexplained:
            ok = False

    print("ORACLE RESULT:", "PASS" if ok else "FAIL")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
