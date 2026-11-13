"""pnpm verified-edge extractor (R2.3, evidence tier: snapshot-declared).

Evidence basis: a pnpm-lock.yaml records the resolved universe in
``packages`` (resolution metadata per ``name@version``) and the dependency
relations in ``snapshots`` (v6+/v9) or inline in ``packages`` entries
(v5.4). A snapshot's ``dependencies`` / ``optionalDependencies`` values are
EXACT resolved identities (``1.1.3``, ``3.2.6(supports-color@5.5.0)``,
tarball URLs) -- an exact value whose ``name@version`` exists in the
packages universe is a VERIFIED edge; everything weaker is disclosed:
membership miss -> UNRESOLVED (declared child name preserved), a child
instance present only as a snapshot -> VERIFIED via the snapshot fallback,
link/file/URL values -> UNRESOLVED with the value preserved verbatim and a
NON_REGISTRY_RESOLUTION / LOCAL_LINK status. Membership alone is never an
edge -- a package's presence in ``packages`` says nothing about WHO depends
on it.

Identity and aliases: package keys may be plain (``name@version``), scoped
(``@scope/name@version``), aliased (``alias@npm:real@version`` -- the REAL
target is the identity, the alias travels as a qualifier), or peer-qualified
(``name@version(peer@x)`` -- the suffix qualifies the instance, never the
identity). v5.4 package keys are slash-separated (``pkg/1.2.3``,
``@scope/pkg/1.2.3``) and are normalized to name@version for membership.

A tarball/git-resolved PARENT carries no purl-certifiable identity: its
edges keep the resolved child but are downgraded UNRESOLVED by the purl
guard with a NON_REGISTRY_PARENT disclosure. Importer (project-level)
declarations are counted and disclosed but never become edges: the project
is not a lockfile component (verified_root_declared stays npm-engine-only,
R2 contract §4).

Lockfile versions: 5.4, 6.0, 6.1, 9.0 parse; anything else answers with a
disclosed UNSUPPORTED envelope. The R2.3 corpus contains NO project-
committed pnpm lockfiles -- the real-evidence benchmark is a pnpm
11.10.0-generated lockfile (pnpm import from NodeGoat's package-lock.json);
5.4/6.0/6.1 coverage is fixture-based and disclosed.

FND-03: every slice bound is a named span (analysis.spans).
"""

from __future__ import annotations

from pathlib import Path

import yaml

from analysis.spans import WINDOW_1, WINDOW_2, WINDOW_M1
from analysis.lock_graph import contract

ENGINE = "PNPM_SNAPSHOT_GRAPH_V1"
EVIDENCE = "PNPM_SNAPSHOT_DEPENDENCIES"

SUPPORTED_VERSIONS = {"5.4", "6.0", "6.1", "9.0"}
_NPM_TARGET_MARK = "@npm:"
_NON_REGISTRY_SCHEMES = ("http:", "https:", "file:", "link:")


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


def _is_registry_version(value: str) -> bool:
    """True when the value is a purl-certifiable registry version."""
    base = _split_peer_suffix(value)[0].strip()
    return bool(base) and "(" not in base and not base.startswith(
        _NON_REGISTRY_SCHEMES)


def _split_key_identity(key: str) -> tuple:
    """Plain ``@``-separated key -> (name, version|'').

    Scoped names keep their ``@scope/`` prefix; the FIRST ``@`` after a
    leading scope (or the first ``@`` overall) separates name from version.
    """
    text = str(key or "").strip()
    if text.startswith("@"):
        at = text.find("@", WINDOW_1)
    else:
        at = text.find("@")
    if at < 0:
        return (text, "")
    return (text[:at], text[at + WINDOW_1:])


def _key_identity(key: str) -> tuple:
    """Package/snapshot key -> (name, version_raw, alias|None).

    Alias keys (``alias@npm:real@version``) resolve to the REAL target
    identity; the alias travels separately as a qualifier.
    """
    text = str(key or "").strip()
    if _NPM_TARGET_MARK in text:
        alias, _, target = text.partition(_NPM_TARGET_MARK)
        tname, tver = _split_key_identity(target)
        return (tname, tver, alias or None)
    name, version = _split_key_identity(text)
    return (name, version, None)


def _split_v5_key(key: str) -> tuple:
    """v5.4 slash-separated package key -> (name, version_raw, peers,
    alias|None).

    ``pkg/1.2.3`` -> (pkg, 1.2.3, [], None); ``@scope/pkg/1.2.3`` keeps the
    scope; ``pkg/1.2.3(peer@1)`` strips the peer suffix; non-conforming
    keys return empty strings (counted invalid by the caller).
    """
    text = str(key or "").strip()
    base, peers = _split_peer_suffix(text)
    if "/" not in base:
        return ("", "", [], None)
    name, _, version = base.rpartition("/")
    if not name or not version or "/" in version:
        return ("", "", [], None)
    if _NPM_TARGET_MARK in name:
        real, alias = _real_name(name)
        return (real, version, peers, alias)
    return (name, version, peers, None)


def _real_name(name: str) -> tuple:
    """Resolve ``alias@npm:real`` spelling -> (real, alias)."""
    if _NPM_TARGET_MARK in name:
        alias, _, target = name.partition(_NPM_TARGET_MARK)
        return (target, alias or None)
    return (name, None)


def _member_identity(universe: dict, name: str, version: str) -> tuple:
    """-> (resolved_name, matched_key, alias) when ``name@version`` (or an
    ``alias@npm:real@version`` spelling) exists in the universe; ("", "",
    None) when it does not."""
    direct = f"{name}@{version}"
    if direct in universe:
        real, alias = _real_name(name)
        return (real, direct, alias)
    prefix = f"{name}{_NPM_TARGET_MARK}"
    for key in universe:
        if not key.startswith(prefix):
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
        if key.startswith(prefix) and \
                key[len(prefix):len(prefix) + WINDOW_1] == "(":
            return True
    return False


def _extract_v6(data: dict, lockfile_path: str, version_label: str) -> dict:
    """v6.0/6.1/9.0: relations live in ``snapshots``."""
    packages = data.get("packages") or {}
    universe = {}
    invalid = 0
    for k, v in packages.items():
        if isinstance(v, dict):
            universe[str(k)] = v
        else:
            # a malformed packages entry is counted, never silently dropped
            invalid += 1
    snapshots = data.get("snapshots") or {}

    edges = []
    tallies = {"duplicate_records_dropped": 0, "invalid_records": invalid}
    for snap_key, snap in snapshots.items():
        if not isinstance(snap, dict):
            tallies["invalid_records"] += 1
            continue
        parent_name, parent_version, parent_alias = _key_identity(snap_key)
        base, parent_peers = _split_peer_suffix(parent_version)
        if not parent_name or not base:
            tallies["invalid_records"] += 1
            continue
        parent_qualifiers = {}
        if parent_alias:
            parent_qualifiers["alias"] = parent_alias
        if parent_peers:
            parent_qualifiers["peer_instances"] = list(parent_peers)
        parent_registry = _is_registry_version(base)
        for block, scope in (("dependencies", "runtime"),
                             ("optionalDependencies", "optional")):
            for child_name, value in (snap.get(block) or {}).items():
                edges.append(_build_snapshot_edge(
                    universe, snapshots, str(snap_key),
                    str(parent_name), base, dict(parent_qualifiers),
                    str(child_name), value, scope, lockfile_path, block,
                    snap.get("transitivePeerDependencies"),
                    parent_registry))
    return _finish(edges, tallies, lockfile_path, version_label, data)


def _extract_v5(data: dict, lockfile_path: str, version_label: str) -> dict:
    """v5.4: relations are inline in ``packages`` entries; slash-separated
    keys are normalized to name@version for membership."""
    packages = data.get("packages") or {}
    universe = {}
    invalid = 0
    parsed = []
    for pkg_key, pkg in packages.items():
        if not isinstance(pkg, dict):
            invalid += 1
            continue
        name, version, peers, alias = _split_v5_key(str(pkg_key))
        base, extra_peers = _split_peer_suffix(version)
        peers = list(peers) + list(extra_peers)
        if not name or not base:
            invalid += 1
            continue
        parsed.append((name, base, peers, alias, str(pkg_key), pkg))
        universe[f"{name}@{base}"] = pkg

    edges = []
    tallies = {"duplicate_records_dropped": 0, "invalid_records": invalid}
    for name, base, peers, alias, raw_key, pkg in parsed:
        real_parent, parent_alias = _real_name(name)
        parent_qualifiers = {}
        if alias or parent_alias:
            parent_qualifiers["alias"] = alias or parent_alias
        if peers:
            parent_qualifiers["peer_instances"] = list(peers)
        if pkg.get("dev") is True:
            parent_qualifiers["package_dev"] = True
        parent_registry = _is_registry_version(base)
        for block, scope in (("dependencies", "runtime"),
                             ("optionalDependencies", "optional")):
            for child_name, value in (pkg.get(block) or {}).items():
                edges.append(_build_snapshot_edge(
                    universe, {}, raw_key,
                    real_parent, base, dict(parent_qualifiers),
                    str(child_name), value, scope, lockfile_path, block,
                    None, parent_registry))
    return _finish(edges, tallies, lockfile_path, version_label, data)


def _build_snapshot_edge(universe: dict, snapshots: dict, snap_key: str,
                         parent_name: str, parent_version: str,
                         parent_qualifiers: dict, child_name: str,
                         child_value, scope: str, lockfile_path: str,
                         block: str, transitive_peers,
                         parent_registry: bool = True) -> dict:
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

    if base_value and not _is_registry_version(base_value):
        # tarball/git/link resolutions carry no purl-certifiable version:
        # preserved verbatim, disclosed, never guessed into VERIFIED
        return _edge(parent_name=parent_name,
                     parent_version=parent_version,
                     child_name=child_name, child_version=base_value,
                     resolution_status=("LOCAL_LINK" if base_value.startswith(
                         "link:") else "NON_REGISTRY_RESOLUTION"))
    if not base_value:
        return _edge(parent_name=parent_name,
                     parent_version=parent_version,
                     child_name=child_name, child_version="",
                     resolution_status="CHILD_NOT_IN_LOCKFILE")

    resolved_name, matched_key, alias = _member_identity(
        universe, child_name, base_value)
    if not resolved_name and _snapshot_member(snapshots, child_name,
                                              base_value):
        # a peer-qualified snapshot instance of the exact child version
        # exists -- resolution evidence, though no packages metadata
        resolved_name, matched_key, alias = child_name, "", None
    if not resolved_name:
        return _edge(parent_name=parent_name,
                     parent_version=parent_version,
                     child_name=child_name, child_version="",
                     resolution_status="CHILD_NOT_IN_LOCKFILE")
    if alias:
        qualifiers["alias"] = alias
    pkg_meta = universe.get(matched_key) or {}
    resolution = pkg_meta.get("resolution")
    if isinstance(resolution, dict) and resolution.get("integrity"):
        qualifiers["integrity"] = str(resolution["integrity"])
    return _edge(parent_name=parent_name,
                 parent_version=parent_version,
                 child_name=resolved_name, child_version=base_value,
                 resolution_status=("" if parent_registry
                                    else "NON_REGISTRY_PARENT"))


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
        "UNRESOLVED with their declared name preserved (snapshot instances "
        "count as membership evidence).",
        "tarball/git/link resolutions carry no purl-certifiable version: "
        "child values are disclosed as NON_REGISTRY_RESOLUTION / "
        "LOCAL_LINK and tarball-resolved parents as NON_REGISTRY_PARENT, "
        "each UNRESOLVED with the value preserved verbatim.",
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
