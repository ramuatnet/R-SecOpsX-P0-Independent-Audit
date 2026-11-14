""".NET/NuGet verified-edge extractor (R2.5b, evidence tier: resolved
restore targets).

Evidence basis and tiers (approved R2.5b scope; format availability
established in the R2.5 survey):

- ``packages.lock.json`` / ``project.assets.json``: the ``targets``
  sections are the resolved restore state -- each ``Package/Version``
  entry (``type: package``) carries an exact-identity ``dependencies``
  map (``Child/Version`` keys; assets files may hold constraint strings
  as values). An entry resolving to an exact universe instance is a
  VERIFIED edge; a miss is UNRESOLVED; AMBIGUOUS is structurally absent
  (the evidence is instance-exact, like pnpm snapshots). Target
  frameworks travel as qualifiers; runtime-specific assets are files,
  not package relations (counted, never edges); ``type: project``
  entries have no package identity (skipped, counted). The TOP-LEVEL
  ``dependencies`` section is the PROJECT's restore state (types
  Direct/Transitive/CentralTransitive/DirectTransitive): tallied and
  disclosed, never edges -- the restore parent is the project, not a
  lockfile component (no synthetic root, R2 contract §4).

- ``packages.config``: a flat package list -- membership evidence only,
  NEVER edges (packages.config encodes no parent-child relationships).

- ``Directory.Packages.props``: the central package management catalog
  (``PackageVersion`` Include/Update) -- declarations tallied and
  disclosed, NEVER edges. csproj files are arbitrary-named and therefore
  not registry-dispatchable by exact filename: they remain the
  membership parser's territory (nuget_packages.py), which is disclosed
  here.

Universe: every ``Package/Version`` key across all TFMs; the SAME
name@version under several TFMs is one logical package instance (the
per-TFM edges stay distinct through their target_framework qualifier).
The recorded versions are post-restore (post-CPM-override) resolutions.

Real-world validation status: the corpus contains ZERO
packages.lock.json / project.assets.json files -- those tiers are
fixture-validated and disclosed; the REAL corpus evidence (packages.config,
Directory.Packages.props, csproj membership) validates the
membership/declaration envelopes.

FND-03: every slice bound is a named span (analysis.spans).
"""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from pathlib import Path

from analysis.spans import WINDOW_1
from analysis.lock_graph import contract

LOCK_ENGINE = "NUGET_LOCK_GRAPH_V1"
ASSETS_ENGINE = "NUGET_ASSETS_GRAPH_V1"
EVIDENCE = "NUGET_LOCK_TARGETS"
CONFIG_ENGINE = "NUGET_PACKAGES_CONFIG_V1"
PROPS_ENGINE = "NUGET_PROPS_DECLARATIONS_V1"
FORMAT_LOCK = "packages.lock.json"
FORMAT_ASSETS = "project.assets.json"
FORMAT_CONFIG = "packages.config"
FORMAT_PROPS = "Directory.Packages.props"


def _split_target_key(key: str) -> tuple:
    """``Newtonsoft.Json/13.0.1`` -> (name, version); last '/' splits."""
    text = str(key or "").strip()
    slash = text.rfind("/")
    if slash <= 0:
        return (text, "")
    return (text[:slash], text[slash + WINDOW_1:])


def _extract_targets(data: dict, engine: str, lockfile_path: str,
                     format_version: str) -> dict:
    """Shared resolved-edge walk over the ``targets`` sections."""
    targets = data.get("targets") or {}
    if not isinstance(targets, dict) or not targets:
        return contract.extraction_result(
            engine=engine, source=str(lockfile_path),
            format_version=format_version,
            graph_status=contract.UNSUPPORTED_FORMAT, edges=[],
            limitations=["File carries no resolved targets sections; "
                         "no edges fabricated."])

    universe = set()
    project_keys = set()
    for tfm in targets.values():
        if isinstance(tfm, dict):
            for key, meta in tfm.items():
                universe.add(str(key))
                if isinstance(meta, dict) and \
                        str(meta.get("type") or "") == "project":
                    project_keys.add(str(key))

    edges = []
    tallies = {"duplicate_records_dropped": 0, "invalid_records": 0,
               "project_refs_skipped": 0, "runtime_assets": 0,
               "restore_type_direct": 0, "restore_type_transitive": 0,
               "restore_type_central_transitive": 0,
               "restore_type_direct_transitive": 0}
    for tfm, entries in targets.items():
        if not isinstance(entries, dict):
            tallies["invalid_records"] += 1
            continue
        for key, meta in entries.items():
            if not isinstance(meta, dict):
                tallies["invalid_records"] += 1
                continue
            entry_type = str(meta.get("type") or "package")
            if entry_type == "project":
                tallies["project_refs_skipped"] += 1
                continue
            parent_name, parent_version = _split_target_key(key)
            if not parent_name or not parent_version:
                tallies["invalid_records"] += 1
                continue
            qualifiers = {"target_framework": str(tfm)}
            if meta.get("contentHash"):
                qualifiers["content_hash"] = str(meta["contentHash"])

            def _edge(**kwargs):
                return contract.build_edge(
                    ecosystem="nuget", source=str(lockfile_path),
                    source_location=f"targets[{tfm}] {key}",
                    evidence_source=EVIDENCE, scope="runtime",
                    qualifiers=qualifiers, **kwargs)

            for dep_key, dep_value in (meta.get("dependencies") or {}).items():
                child_name, child_version = _split_target_key(dep_key)
                if not child_name or not child_version:
                    tallies["invalid_records"] += 1
                    continue
                if dep_key in project_keys:
                    # the child is a project reference, not a package: no
                    # package identity to certify
                    tallies["project_refs_skipped"] += 1
                    continue
                if dep_key in universe:
                    edge = _edge(
                        parent_name=parent_name,
                        parent_version=parent_version,
                        child_name=child_name,
                        child_version=child_version)
                else:
                    edge = _edge(
                        parent_name=parent_name,
                        parent_version=parent_version,
                        child_name=child_name, child_version="",
                        resolution_status="CHILD_NOT_IN_LOCKFILE")
                if isinstance(dep_value, str) and dep_value.strip():
                    # project.assets.json carries constraint strings as
                    # dependency values; the key carries the exact version
                    edge["requested_spec"] = dep_value
                edges.append(edge)
            for asset_path in (meta.get("runtimeTargets") or {}):
                tallies["runtime_assets"] += 1

    restore = data.get("dependencies") or {}
    if isinstance(restore, dict):
        if engine == ASSETS_ENGINE:
            # project.assets.json: package-keyed restore map with types
            for _name, meta in restore.items():
                if not isinstance(meta, dict):
                    continue
                rtype = str(meta.get("type") or "").casefold()
                key = {"direct": "restore_type_direct",
                       "transitive": "restore_type_transitive",
                       "centraltransitive":
                           "restore_type_central_transitive",
                       "directtransitive":
                           "restore_type_direct_transitive",
                       }.get(rtype)
                if key:
                    tallies[key] += 1
        else:
            # packages.lock.json: TFM-keyed block whose per-package
            # entries carry the restore type
            for _tfm, deps in restore.items():
                if not isinstance(deps, dict):
                    continue
                for _name, meta in deps.items():
                    if not isinstance(meta, dict):
                        continue
                    rtype = str(meta.get("type") or "").casefold()
                    key = {"direct": "restore_type_direct",
                           "transitive": "restore_type_transitive",
                           "centraltransitive":
                               "restore_type_central_transitive",
                           "directtransitive":
                               "restore_type_direct_transitive",
                           }.get(rtype)
                    if key:
                        tallies[key] += 1

    deduped: dict[tuple, dict] = {}
    for edge in edges:
        k = (edge["parent_name"], edge["parent_version"],
             edge["child_name"], edge.get("child_version") or "",
             edge["confidence"], edge["qualifiers"].get("target_framework"))
        if k in deduped:
            tallies["duplicate_records_dropped"] += 1
            continue
        deduped[k] = edge
    edges = sorted(deduped.values(), key=lambda e: (
        e["parent_name"], e["parent_version"], e["child_name"],
        e["qualifiers"].get("target_framework") or "",
        e["confidence"], e.get("child_version") or "",
    ))
    verified_status = (contract.VERIFIED_EDGES_AVAILABLE if any(
        e["confidence"] == contract.VERIFIED for e in edges)
        else contract.NO_VERIFIED_EDGES)
    return contract.extraction_result(
        engine=engine, source=str(lockfile_path),
        format_version=format_version, graph_status=verified_status,
        edges=edges, tallies=tallies,
        membership_packages=len(universe),
        limitations=[
            "the targets sections are the resolved restore state: "
            "dependency keys carry EXACT resolved child identities, so "
            "AMBIGUOUS structurally cannot arise (like pnpm snapshots); "
            "membership alone is never an edge and misses stay "
            "UNRESOLVED.",
            "the top-level dependencies section is the PROJECT's restore "
            "state (types Direct/Transitive/CentralTransitive): tallied "
            "and disclosed, never edges -- no synthetic root is minted.",
            "runtime-specific assets are files, not package relations "
            "(counted); type=project entries have no package identity "
            "(skipped); recorded versions are post-restore resolutions "
            "(post central-package-management override).",
            "NO real packages.lock.json / project.assets.json exists in "
            "the R2.5 corpus -- this tier is fixture-validated and "
            "disclosed as such; real corpus evidence covers "
            "packages.config and Directory.Packages.props envelopes.",
        ])


def extract_lock(lockfile_path: str) -> dict:
    try:
        data = json.loads(Path(lockfile_path).read_text(
            encoding="utf-8", errors="replace"))
    except Exception as exc:
        return contract.extraction_result(
            engine=LOCK_ENGINE, source=str(lockfile_path),
            format_version=FORMAT_LOCK,
            graph_status=contract.EXTRACTION_ERROR, edges=[],
            limitations=[f"packages.lock.json parse failed: {exc}"])
    if not isinstance(data, dict):
        return contract.extraction_result(
            engine=LOCK_ENGINE, source=str(lockfile_path),
            format_version=FORMAT_LOCK,
            graph_status=contract.UNSUPPORTED_FORMAT, edges=[],
            limitations=["packages.lock.json is not an object; no edges "
                         "fabricated."])
    return _extract_targets(data, LOCK_ENGINE, str(lockfile_path),
                            FORMAT_LOCK)


def extract_assets(lockfile_path: str) -> dict:
    try:
        data = json.loads(Path(lockfile_path).read_text(
            encoding="utf-8", errors="replace"))
    except Exception as exc:
        return contract.extraction_result(
            engine=ASSETS_ENGINE, source=str(lockfile_path),
            format_version=FORMAT_ASSETS,
            graph_status=contract.EXTRACTION_ERROR, edges=[],
            limitations=[f"project.assets.json parse failed: {exc}"])
    if not isinstance(data, dict):
        return contract.extraction_result(
            engine=ASSETS_ENGINE, source=str(lockfile_path),
            format_version=FORMAT_ASSETS,
            graph_status=contract.UNSUPPORTED_FORMAT, edges=[],
            limitations=["project.assets.json is not an object; no edges "
                         "fabricated."])
    return _extract_targets(data, ASSETS_ENGINE, str(lockfile_path),
                            FORMAT_ASSETS)


def extract_packages_config(lockfile_path: str) -> dict:
    try:
        root = ET.parse(lockfile_path).getroot()
    except Exception as exc:
        return contract.extraction_result(
            engine=CONFIG_ENGINE, source=str(lockfile_path),
            format_version=FORMAT_CONFIG,
            graph_status=contract.EXTRACTION_ERROR, edges=[],
            limitations=[f"packages.config parse failed: {exc}"])
    packages = root.findall(".//package")
    return contract.extraction_result(
        engine=CONFIG_ENGINE, source=str(lockfile_path),
        format_version=FORMAT_CONFIG,
        graph_status=contract.UNSUPPORTED_FORMAT, edges=[],
        tallies={"package_entries": len(packages)},
        limitations=[
            "packages.config is a flat package list: it records which "
            "packages a project consumed but encodes NO parent-child "
            "relationships -- membership evidence only, never edges "
            "(approved R2.5b constraint).",
            "resolved parent-child relationships require "
            "packages.lock.json or project.assets.json evidence.",
        ],
        membership_packages=len(packages))


def extract_props(lockfile_path: str) -> dict:
    try:
        root = ET.parse(lockfile_path).getroot()
    except Exception as exc:
        return contract.extraction_result(
            engine=PROPS_ENGINE, source=str(lockfile_path),
            format_version=FORMAT_PROPS,
            graph_status=contract.EXTRACTION_ERROR, edges=[],
            limitations=[f"props parse failed: {exc}"])
    includes = root.findall(".//PackageVersion[@Include]")
    updates = root.findall(".//PackageVersion[@Update]")
    return contract.extraction_result(
        engine=PROPS_ENGINE, source=str(lockfile_path),
        format_version=FORMAT_PROPS,
        graph_status=contract.UNSUPPORTED_FORMAT, edges=[],
        tallies={"package_version_entries": len(includes) + len(updates),
                 "cpm_includes": len(includes),
                 "cpm_updates": len(updates)},
        limitations=[
            "Directory.Packages.props is the central package management "
            "catalog: version definitions consumed by csproj "
            "declarations -- tallied (Include vs Update) and disclosed, "
            "never edges.",
            "resolved parent-child relationships require "
            "packages.lock.json or project.assets.json evidence; csproj "
            "files are arbitrary-named and remain the membership "
            "parser's territory (nuget_packages.py).",
        ],
        membership_packages=len(includes))
