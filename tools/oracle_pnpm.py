"""Independent pnpm lockfile edge oracle (R2.3 remediation, F-R3-6).

Re-implements pnpm-lock.yaml snapshot resolution WITHOUT importing the
extractor (`analysis/lock_graph/pnpm.py`): a fresh YAML walk, its own
identity/peer-suffix/alias parsing, and CONTRACT confidence semantics
(R2_GRAPH_CONTRACT.md §3 -- not the extractor's code) derive the expected
edge set. Never validate an extractor against its own output.

Contract semantics modeled by the oracle:
- VERIFIED requires a registry-certifiable identity on BOTH sides: a
  tarball/git-resolved parent (or child value) can never be VERIFIED --
  expected UNRESOLVED with the value preserved;
- a child value resolving to an instance in the packages universe (direct
  or alias spelling) or existing as a snapshot instance is resolution
  evidence -> VERIFIED;
- membership miss -> UNRESOLVED CHILD_NOT_IN_LOCKFILE.

Usage:
    python -I oracle_pnpm.py <pnpm-lock.yaml> <pnpm-edges.json>
        [npm-edges.json] [package-lock.json]

The optional npm pair enables the CROSS-FORMAT comparison against the npm
engine's parse of the same project's package-lock.json (real evidence:
pnpm 11.10.0 `pnpm import` generated the pnpm lockfile from that original).
The two files genuinely differ, so the comparison CLASSIFIES the delta
against both source files (each parsed once) and gates only on genuine
extractor faults:

- FAIL: a pnpm-only edge the pnpm file does not record (invented);
- FAIL: an npm-only relation the pnpm file records at the SAME version
  (missed by the extractor);
- information: parent-absent flattening, version-divergent pairs,
  import-dropped relations.

Reports correct/wrong/missing/invented plus unresolved/ambiguous counts;
exits 0 iff all gates agree.
"""

import json
import sys
from pathlib import Path

import yaml

NPM_MARK = "@npm:"
REGISTRY_SCHEMES = ("http:", "https:", "file:", "link:")


# ---- fresh identity helpers (independent of the extractor) -------------------
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
    """Plain key -> (name, version); scoped names keep their prefix."""
    text = str(key or "").strip()
    if text.startswith("@"):
        at = text.find("@", 1)
    else:
        at = text.find("@")
    if at < 0:
        return (text, "")
    return (text[:at], text[at + 1:])


def key_identity(key):
    """Key -> (name, version, alias|None); alias keys resolve the target."""
    text = str(key or "").strip()
    if NPM_MARK in text:
        alias, _, target = text.partition(NPM_MARK)
        tname, tver = split_identity(target)
        return (tname, tver, alias or None)
    name, version = split_identity(text)
    return (name, version, None)


def v5_key_identity(key):
    """v5.4 slash key -> (name, version, alias|None)."""
    text = str(key or "").strip()
    base, _peers = split_peer_suffix(text)
    if "/" not in base:
        return ("", "", None)
    name, _, version = base.rpartition("/")
    if not name or not version or "/" in version:
        return ("", "", None)
    if NPM_MARK in name:
        alias, _, target = name.partition(NPM_MARK)
        return (target, version, alias or None)
    return (name, version, None)


def registry_version(value):
    base = split_peer_suffix(value)[0].strip()
    return bool(base) and "(" not in base and not base.startswith(
        REGISTRY_SCHEMES)


# ---- oracle expected-edge derivation ----------------------------------------
def parse_pnpm(path):
    """-> (universe, expected, version_label).

    expected: {(parent, pver, child, cver_or_''): (confidence, status)}.
    """
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8",
                                               errors="replace"))
    packages = data.get("packages") or {}
    version_label = str(data.get("lockfileVersion") or "")
    universe = {}
    if version_label == "5.4":
        for k, v in packages.items():
            if not isinstance(v, dict):
                continue
            name, version, alias = v5_key_identity(str(k))
            base, _ = split_peer_suffix(version)
            if name and base:
                universe[f"{name}@{base}"] = (v, alias)
        relation_sources = [
            (str(k), v, True) for k, v in packages.items()
            if isinstance(v, dict)]
        snapshots = {}
    else:
        for k, v in packages.items():
            if isinstance(v, dict):
                universe[str(k)] = (v, None)
        snapshots = data.get("snapshots") or {}
        relation_sources = [
            (str(k), v, False) for k, v in snapshots.items()
            if isinstance(v, dict)]

    snap_keys = set()
    for k, _v, _is_pkg in relation_sources:
        snap_keys.add(str(k))
    # v6 fallback also looks at packages keys for plain membership
    for k in universe:
        snap_keys.add(k)

    def member(name, version):
        """-> (resolved_name, alias) when name@version is resolvable."""
        direct = f"{name}@{version}"
        if direct in universe:
            if NPM_MARK in name:
                target = name.partition(NPM_MARK)[2]
                return (target, name.partition(NPM_MARK)[0])
            return (name, None)
        prefix = f"{name}{NPM_MARK}"
        for key in universe:
            if not key.startswith(prefix):
                continue
            tname, tver = split_identity(key.partition(NPM_MARK)[2])
            if tver == version:
                return (tname, key.partition(NPM_MARK)[0])
        # snapshot-instance fallback
        pre = f"{name}@{version}"
        for sk in snap_keys:
            if sk == pre or (sk.startswith(pre)
                             and sk[len(pre):len(pre) + 1] == "("):
                return (name, None)
        return ("", None)

    expected = {}
    for raw_key, rels, is_pkg in relation_sources:
        if version_label == "5.4":
            name, version, alias = v5_key_identity(raw_key)
        else:
            name, version, alias = key_identity(raw_key)
        base, _p = split_peer_suffix(version)
        if not name or not base:
            continue
        parent_registry = registry_version(base)
        for block in ("dependencies", "optionalDependencies"):
            for child_name, value in (rels.get(block) or {}).items():
                child_value, _ = split_peer_suffix(str(value))
                identity_parent = (name, base)
                if not base.strip() or not str(child_value).strip():
                    expected.setdefault(
                        (name, base, str(child_name), ""),
                        ("UNRESOLVED", "CHILD_NOT_IN_LOCKFILE"))
                    continue
                if not registry_version(child_value):
                    status = ("LOCAL_LINK"
                              if str(child_value).startswith("link:")
                              else "NON_REGISTRY_RESOLUTION")
                    expected.setdefault(
                        (name, base, str(child_name),
                         str(child_value)), ("UNRESOLVED", status))
                    continue
                resolved, calias = member(str(child_name),
                                          str(child_value))
                if not resolved:
                    expected.setdefault(
                        (name, base, str(child_name), ""),
                        ("UNRESOLVED", "CHILD_NOT_IN_LOCKFILE"))
                    continue
                if not parent_registry:
                    expected.setdefault(
                        (identity_parent + (resolved, str(child_value))),
                        ("UNRESOLVED", "NON_REGISTRY_PARENT"))
                else:
                    expected.setdefault(
                        (identity_parent + (resolved, str(child_value))),
                        ("VERIFIED", ""))
    return universe, expected, version_label


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
        got.setdefault(key, []).append((
            str(e.get("confidence")),
            str(e.get("resolution_status") or "")))

    expected_keys = set(expected)
    got_keys = set(got)
    missing = expected_keys - got_keys
    invented = got_keys - expected_keys
    correct = wrong = status_variance = 0
    wrong_samples, variance_samples = [], []
    for key in expected_keys & got_keys:
        state, status = expected[key]
        entries = got[key]
        verified_hit = any(g[0] == "VERIFIED" for g in entries)
        if state == "VERIFIED":
            if verified_hit:
                correct += 1
            else:
                wrong += 1
                if len(wrong_samples) < 5:
                    wrong_samples.append((key, state, entries))
        else:
            if verified_hit:
                wrong += 1
                if len(wrong_samples) < 5:
                    wrong_samples.append((key, f"{status}->VERIFIED",
                                          entries))
            else:
                if any(g[1] and g[1] != status for g in entries):
                    status_variance += 1
                    if len(variance_samples) < 5:
                        variance_samples.append((key, status, entries))
                else:
                    correct += 1

    exp_unresolved = sum(1 for v in expected.values()
                         if v[0] == "UNRESOLVED")
    exp_ambiguous = sum(1 for v in expected.values()
                        if v[0] == "AMBIGUOUS")
    got_unresolved = sum(1 for e in edges
                         if e.get("confidence") == "UNRESOLVED")
    got_ambiguous = sum(1 for e in edges
                        if e.get("confidence") == "AMBIGUOUS")
    print(f"oracle: lockfileVersion {version_label}, "
          f"{len(universe)} packages, {len(expected_keys)} expected "
          f"identities")
    print(f"extractor edges: {len(edges)}  identities: {len(got_keys)}")
    print(f"CORRECT:   {correct}")
    print(f"WRONG:     {wrong}  {wrong_samples}")
    print(f"MISSING:   {len(missing)}  {sorted(missing)}")
    print(f"INVENTED:  {len(invented)}  {sorted(invented)}")
    print(f"UNRESOLVED: expected {exp_unresolved} / extractor "
          f"{got_unresolved}")
    print(f"AMBIGUOUS:  expected {exp_ambiguous} / extractor "
          f"{got_ambiguous}")
    print(f"STATUS variance (non-gating): {status_variance}  "
          f"{variance_samples}")
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
            if pn:
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

        # both source files parsed ONCE; file-presence indexes
        pl_recs = set()
        if len(sys.argv) > 4:
            pl = json.loads(Path(sys.argv[4]).read_text(encoding="utf-8"))
            for key, node in (pl.get("packages") or {}).items():
                if not isinstance(node, dict):
                    continue
                parts = str(key).split("node_modules/")
                if not parts:
                    continue
                node_name = parts[-1]
                version = str(node.get("version") or "")
                for block in ("dependencies", "optionalDependencies"):
                    for child in (node.get(block) or {}):
                        pl_recs.add((node_name, version, child))

        data = yaml.safe_load(lock.read_text(encoding="utf-8",
                                             errors="replace"))
        pnpm_recs = set()       # (parent, pver, child, cver) exact
        pnpm_pc = set()         # (parent, pver, child) any version
        sections = []
        if version_label == "5.4":
            sections = [(data.get("packages") or {}).items()]
        else:
            sections = [(data.get("snapshots") or {}).items(),
                        (data.get("packages") or {}).items()]
        for section in sections:
            for key, rels in section:
                if version_label == "5.4":
                    name, version, _a = v5_key_identity(str(key))
                else:
                    name, version, _a = key_identity(str(key))
                base, _p = split_peer_suffix(version)
                if not isinstance(rels, dict) or not name or not base:
                    continue
                for block in ("dependencies", "optionalDependencies"):
                    for child, cval in (rels.get(block) or {}).items():
                        cbase, _cp = split_peer_suffix(str(cval))
                        pnpm_recs.add((name, base, str(child), str(cbase)))
                        pnpm_pc.add((name, base, str(child)))

        invented_in_cross = [r for r in only_pnpm if r not in pnpm_recs]
        # "missed" = the pnpm file records the relation at the SAME child
        # version the npm side reports, yet the extractor did not emit it.
        # A same-relation-different-version pair is B-class divergence
        # (both sides faithful to their own file), not a miss.
        missed_in_cross = [r for r in only_npm if r in pnpm_recs]
        # classification (informational)
        pnpm_parents = {(k[0], k[1]) for k in pnpm_pc}
        cls_a = [r for r in only_npm if (r[0], r[1]) not in pnpm_parents]
        cls_b = [r for r in only_npm
                 if (r[0], r[1]) in pnpm_parents and r[:3] in
                 set(x[:3] for x in pnpm_recs)]
        cls_c = [r for r in only_npm
                 if (r[0], r[1]) in pnpm_parents and r[:3] not in
                 set(x[:3] for x in pnpm_recs)]
        print(f"cross-format classes: A parent-absent-from-pnpm-file "
              f"{len(cls_a)}; B same-relation-different-child-version "
              f"{len(cls_b)}; C import-dropped {len(cls_c)}; "
              f"pnpm-only total {len(only_pnpm)}")
        print(f"cross-format gates: invented {len(invented_in_cross)} "
              f"{invented_in_cross}; missed {len(missed_in_cross)} "
              f"{missed_in_cross}")
        if invented_in_cross or missed_in_cross:
            ok = False

    print("ORACLE RESULT:", "PASS" if ok else "FAIL")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
