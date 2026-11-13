"""pnpm verified-edge extractor (R2.3, evidence tier: snapshot-declared).

Evidence basis: a pnpm-lock.yaml records the resolved universe in
``packages`` (resolution metadata per ``name@version``) and the dependency
relations in ``snapshots`` (v6+/v9) or inline in ``packages`` entries
(v5.4). A snapshot's ``dependencies`` / ``optionalDependencies`` values are
EXACT resolved identities (``1.1.3``, ``3.2.6(supports-color@5.5.0)``,
tarball URLs) -- an exact value whose ``name@version`` exists in the
packages universe is a VERIFIED edge; everything weaker is disclosed:
membership miss -> UNRESOLVED, link/file/URL -> UNRESOLVED with the value
preserved verbatim (the purl guard refuses to certify non-registry
versions). Membership alone is never an edge -- a package's presence in
``packages`` says nothing about WHO depends on it.

Peer-qualified identities: snapshot keys and dependency values carry
``(peer@ver)(peer2@ver2)`` instance suffixes. They qualify WHICH instance
resolves, never the package identity: the edge uses name@version, the
qualifiers record the peer instance verbatim. Importer (project-level)
declarations are counted and disclosed but never become edges: the project
is not a lockfile component (verified_root_declared stays npm-engine-only,
R2 contract §4).

Lockfile versions: 5.4, 6.0, 6.1, 9.0 parse; anything else answers with a
disclosed UNSUPPORTED envelope. The R2.3 corpus contains NO real pnpm
lockfiles -- the real-evidence benchmark is a pnpm 11.10.0-generated
lockfile (pnpm import from NodeGoat's package-lock.json), 5.4/6.0/6.1
coverage is fixture-based and disclosed.

FND-03: every slice bound is a named span (analysis.spans).
"""

from __future__ import annotations

from pathlib import Path

import yaml

from analysis.spans import WINDOW_1, WINDOW_M1
from analysis.lock_graph import contract

ENGINE = "PNPM_SNAPSHOT_GRAPH_V1"
EVIDENCE = "PNPM_SNAPSHOT_DEPENDENCIES"

SUPPORTED_VERSIONS = {"5.4", "6.0", "6.1", "9.0"}
_NPM_TARGET_MARK = "@npm:"


def _parse_lockfile_version(raw) -> str:
    """Normalize pnpm's string/float lockfileVersion spellings."""
    if isinstance(raw, str):
        return raw.strip().strip("'\"")
    if isinstance(raw, (int, float)):
        return str(float(raw))       # 9 -> '9.0', 5.4 -> '5.4', 6.1 -> '6.1'
    return ""


def _split_peer_suffix(value: str) -> tuple:
    """``3.2.6(sc@5.5.0)(x@1)`` -> (3.2.6, [sc@5.5.0, x@1])."""
    text = str(value or "").strip()
    peers = []
    while text.endswith(")"):
        open_at = text.rfind("(")
        if open_at < 0:
            break
        peers.insert(0, text[open_at + WINDOW_1:WINDOW_M1])
        text = text[:open_at]
    return text, peers


def _split_key_identity(key: str) -> tuple:
    """``@scope/name@1.2.3`` / ``name@1.2.3`` -> (name, version|'')."""
    text = str(key or "").strip()
    if text.startswith("@"):
        at = text.find("@", WINDOW_1)
    else:
        at = text.find("@")
    if at < 0:
        return (text, "")
    return (text[:at], text[at + WINDOW_1:])


def _real_name(name: str) -> tuple:
    """Resolve ``alias`` / ``alias@npm:real`` spelling -> (real, alias)."""
    if _NPM_TARGET_MARK in name:
        alias, _, target = name.partition(_NPM_TARGET_MARK)
        return (target, alias or None)
    return (name, None)


def _member_identity(universe: dict, name: str, version: str) -> tuple:
    """-> (resolved_name, matched_key, alias) when ``name@version`` (or an
    ``name@npm:real@version`` spelling) exists in the universe."""
    direct = f"{name}@{version}"
    if direct in universe:
        real, alias = _real_name(name)
        return (real, direct, alias)
    for key in universe:
        if not key.startswith(f"{name}@{_NPM_TARGET_MARK}"):
            continue
        target_part = key.partition(_NPM_TARGET_MARK)[WINDOW_2]
        target_name, key_version = _split_key_identity(target_part)
        if key_version == version:
            alias = key.partition(_NPM_TARGET_MARK)[0]
            return (target_name, key, alias or None)
    return ("", "", None)


def _snapshot_member(snapshots: dict, name: str, version: str) -> bool:
    """Fallback resolution evidence: a snapshot instance ``name@version`` --
    possibly peer-qualified -- exists in the snapshots section."""
    prefix = f"{name}@{version}"
    for key in snapshots:
        if key == prefix:
            return True
        if key.startswith(prefix) and key[len(prefix):len(prefix) + WINDOW_1] == "(":
            return True
    return False


def _extract_v6(data: dict, lockfile_path: str, version_label: str) -> dict:
    """v6.0/6.1/9.0: relations live in ``snapshots``."""
    packages = data.get("packages") or {}
    universe = {str(k): v for k, v in packages.items()
                if isinstance(v, dict)}
    snapshots = data.get("snapshots") or {}

    edges = []
    tallies = {"duplicate_records_dropped": 0, "invalid_records": 0}
    for snap_key, snap in snapshots.items():
        if not isinstance(snap, dict):
            tallies["invalid_records"] += 1
            continue
        parent_name, parent_version = _split_key_identity(snap_key)
        base, parent_peers = _split_peer_suffix(parent_version)
        if not parent_name or not base:
            tallies["invalid_records"] += 1
            continue
        parent_qualifiers = {}
        if parent_peers:
            parent_qualifiers["peer_instances"] = list(parent_peers)
        parent_registry_version = (
            "(" not in base and not base.startswith(("http:", "https:",
                                                     "file:", "link:")))
        for block, scope in (("dependencies", "runtime"),
                             ("optionalDependencies", "optional")):
            for child_name, value in (snap.get(block) or {}).items():
                edges.append(_build_snapshot_edge(
                    universe, snapshots, str(snap_key),
                    str(parent_name), base, dict(parent_qualifiers),
                    str(child_name), value, scope, lockfile_path, block,
                    snap.get("transitivePeerDependencies"),
                    non_registry_parent=not parent_registry_version))
    return _finish(edges, tallies, lockfile_path, version_label, data)


def _extract_v5(data: dict, lockfile_path: str, version_label: str) -> dict:
    """v5.4: relations are inline in ``packages`` entries."""
    packages = data.get("packages") or {}
    universe = {str(k): v for k, v in packages.items()
                if isinstance(v, dict)}
    edges = []
    tallies = {"duplicate_records_dropped": 0, "invalid_records": 0}
    for pkg_key, pkg in packages.items():
        if not isinstance(pkg, dict):
            tallies["invalid_records"] += 1
            continue
        raw_name, raw_version = _split_key_identity(str(pkg_key))
        base, parent_peers = _split_peer_suffix(raw_version)
        if not raw_name or not base:
            tallies["invalid_records"] += 1
            continue
        real_parent, parent_alias = _real_name(raw_name)
        parent_qualifiers = {}
        if parent_alias:
            parent_qualifiers["alias"] = parent_alias
        if parent_peers:
            parent_qualifiers["peer_instances"] = list(parent_peers)
        if pkg.get("dev") is True:
            parent_qualifiers["package_dev"] = True
        parent_registry_version = (
            "(" not in base and not base.startswith(("http:", "https:",
                                                     "file:", "link:")))
        for block, scope in (("dependencies", "runtime"),
                             ("optionalDependencies", "optional")):
            for child_name, value in (pkg.get(block) or {}).items():
                edges.append(_build_snapshot_edge(
                    universe, {}, str(pkg_key),
                    real_parent, base, dict(parent_qualifiers),
                    str(child_name), value, scope, lockfile_path, block,
                    None,
                    non_registry_parent=not parent_registry_version))
    return _finish(edges, tallies, lockfile_path, version_label, data)


def _registry_value(value) -> bool:
    """True when the value is a purl-certifiable registry version."""
    base = _split_peer_suffix(value)[0].strip()
    return bool(base) and "(" not in base and not base.startswith(
        ("http:", "https:", "file:", "link:"))


def _build_snapshot_edge(universe: dict, snapshots: dict, snap_key: str,
                         parent_name: str, parent_version: str,
                         parent_qualifiers: dict, child_name: str,
                         child_value, scope: str, lockfile_path: str,
                         block: str, transitive_peers,
                         non_registry_parent: bool = False) -> dict:
    base_value, child_peers = _split_peer_suffix(child_value)
    base_value = str(base_value).strip()
    qualifiers = dict(parent_qualifiers)
    if child_peers:
        qualifiers["peer_instances"] = list(child_peers)
    if transitive_peers:
        qualifiers["transitive_peer_dependencies"] = [
            str(p) for p in transitive_peers]
    location = f"snapshots: {snap_key} {block} {child_name}"

    def _edge(**kwargs):
        edge = contract.build_edge(
            ecosystem="npm", source=str(lockfile_path),
            source_location=location, evidence_source=EVIDENCE,
            scope=scope, qualifiers=qualifiers, **kwargs)
        edge["requested_spec"] = str(child_value)
        return edge

    if not _registry_value(child_value):
        # tarball/git/link resolutions carry no purl-certifiable version:
        # preserved verbatim, disclosed, never guessed into VERIFIED
        return _edge(parent_name=parent_name,
                     parent_version=parent_version,
                     child_name=child_name, child_version=base_value,
                     resolution_status=("LOCAL_LINK" if
                                        base_value.startswith("link:")
                                        else "NON_REGISTRY_RESOLUTION"))

    resolved_name, matched_key, alias = _member_identity(
        universe, child_name, base_value)
    if not resolved_name and _snapshot_member(snapshots, child_name,
                                              base_value):
        # a peer-qualified snapshot instance of the exact child version
        # exists -- resolution evidence, though no packages metadata
        resolved_name, matched_key, alias = child_name, "", None
    if not resolved_name:
        # snapshot-id presence is NOT proof of resolution: the packages
        # universe is the authority
        return _edge(parent_name=parent_name,
                     parent_version=parent_version,
                     child_name=child_name, child_version="",
                     resolution_status="CHILD_NOT_IN_LOCKFILE")
    if alias:
        qualifiers["alias"] = alias
    integrity = ""
    pkg_meta = universe.get(matched_key) or {}
    if pkg_meta.get("dev") is True:
        qualifiers["package_dev"] = True
    resolution = pkg_meta.get("resolution")
    if isinstance(resolution, dict) and resolution.get("integrity"):
        integrity = str(resolution["integrity"])
        qualifiers["integrity"] = integrity
    return _edge(parent_name=parent_name,
                 parent_version=parent_version,
                 child_name=resolved_name, child_version=base_value,
                 resolution_status=("NON_REGISTRY_PARENT"
                                    if non_registry_parent else ""))


def _importer_tallies(data: dict, version_label: str) -> dict:
    """Importer (project) declarations are counted, never edges."""
    tallies = {}
    total = 0
    if version_label == "5.4":
        importer_blocks = {".": {
            block: data.get(block) or {}
            for block in ("dependencies", "devDependencies",
                          "optionalDependencies")}}
    else:
        importer_blocks = data.get("importers") or {}
    for importer_path, blocks in importer_blocks.items():
        if not isinstance(blocks, dict):
            continue
        for block, deps in blocks.items():
            if not isinstance(deps, dict):
                continue
            scope = ("dev" if block == "devDependencies"
                     else "optional" if block == "optionalDependencies"
                     else "runtime")
            key = f"importer_declarations_{scope}"
            tallies[key] = tallies.get(key, 0) + len(deps)
            total += len(deps)
    if total:
        tallies["importer_declarations"] = total
    return tallies


def _finish(edges, tallies, lockfile_path, version_label, data):
    tallies.update(_importer_tallies(data, version_label))
    edges = sorted(edges, key=lambda e: (
        e["parent_name"], e["parent_version"], e["child_name"],
        e["confidence"], e.get("child_version") or "",
    ))
    verified_status = (contract.VERIFIED_EDGES_AVAILABLE if any(
        e["confidence"] == contract.VERIFIED for e in edges)
        else contract.NO_VERIFIED_EDGES)
    limitations = [
        "pnpm-lock.yaml declares the project's own dependencies in "
        "importers (v6+/v9) or root specifier blocks (v5.4): those "
        "declarations are counted (tallies.importer_declarations_*) but "
        "never become edges -- the project is not a lockfile component "
        "and no synthetic root is minted.",
        "snapshot dependency values are exact resolved instances; "
        "peer-qualified suffixes (ver(peer@x)) qualify the instance, not "
        "the identity -- package membership alone is never an edge and "
        "child instances missing from the packages universe stay "
        "UNRESOLVED.",
        "tarball/git/link resolutions carry no purl-certifiable version "
        "and are disclosed as NON_REGISTRY_RESOLUTION / LOCAL_LINK "
        "(UNRESOLVED) with the value preserved verbatim.",
    ]
    return contract.extraction_result(
        engine=ENGINE, source=str(lockfile_path),
        format_version=f"pnpm lockfileVersion {version_label}",
        graph_status=verified_status, edges=edges, tallies=tallies,
        limitations=limitations)


def extract(lockfile_path: str) -> dict:
    try:
        text = Path(lockfile_path).read_text(encoding="utf-8",
                                             errors="replace")
        data = yaml.safe_load(text)
    except Exception as exc:
        return contract.extraction_result(
            engine=ENGINE, source=str(lockfile_path),
            format_version="pnpm-lock.yaml",
            graph_status=contract.EXTRACTION_ERROR, edges=[],
            limitations=[f"pnpm-lock.yaml parse failed: {exc}"])
    if not isinstance(data, dict):
        return contract.extraction_result(
            engine=ENGINE, source=str(lockfile_path),
            format_version="pnpm-lock.yaml",
            graph_status=contract.UNSUPPORTED_FORMAT, edges=[],
            limitations=["pnpm-lock.yaml is not a mapping; no edges "
                         "fabricated."])
    version_label = _parse_lockfile_version(data.get("lockfileVersion"))
    if version_label not in SUPPORTED_VERSIONS:
        return contract.extraction_result(
            engine=ENGINE, source=str(lockfile_path),
            format_version=f"pnpm lockfileVersion {version_label or '?'}",
            graph_status=contract.UNSUPPORTED_FORMAT, edges=[],
            limitations=[f"pnpm lockfileVersion '{version_label or '?'}' "
                         f"is not supported (supported: "
                         f"{', '.join(sorted(SUPPORTED_VERSIONS))}); no "
                         "edges fabricated."])
    if version_label == "5.4":
        return _extract_v5(data, str(lockfile_path), version_label)
    return _extract_v6(data, str(lockfile_path), version_label)
