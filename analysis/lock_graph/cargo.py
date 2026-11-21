"""Cargo verified-edge extractor (R2.4, evidence tier: resolved lockfile).

Evidence basis and tiers (approved R2.4 scope):

- ``Cargo.lock`` (registered filename): TOML ``[[package]]`` blocks, each
  with ``name`` / ``version`` / ``source`` / ``dependencies``. The
  ``dependencies`` list IS the resolved evidence: each entry references a
  resolved package instance as ``name``, ``name version`` or
  ``name version (source)``. An entry that resolves to exactly one
  package instance is a VERIFIED edge; a versionless entry naming several
  same-name instances is AMBIGUOUS (candidates disclosed, never picked);
  zero matches are UNRESOLVED. Membership alone is never an edge.

  Cargo.lock does NOT record dependency KINDS (normal/dev/build are merged
  in the lock) or target specificity: edges carry scope=unknown and the
  limitation is disclosed. The parent package's ``source`` string
  (``registry+...``, ``git+...#rev``, absent for path dependencies) travels
  as provenance so registry/git/path identity is preserved. Lockfile
  format versions 1-4 parse (v1 lockfiles omit the version key and are
  treated as format 1, disclosed); unknown versions answer with a
  disclosed UNSUPPORTED envelope.

- ``Cargo.toml``: manifest declarations ([dependencies], [dev-dependencies],
  [build-dependencies], target.<triple>.* blocks), renamed dependencies
  (``key = { package = "real" }``), workspace inheritance
  (``key = { workspace = true }``) and source kinds. Declarations are
  tallied and disclosed, NEVER edges: a manifest declaration is not a
  resolved relationship (R2 contract §3) -- the lockfile carries the
  resolved graph.

No ``cargo`` CLI exists in the R2.4 environment (GAP-R2-08 analogue):
real ``cargo metadata`` artifacts cannot be generated here; the real
evidence validated is corpus-committed Cargo.lock files (the project's
own rust/Cargo.lock, format 4) and synthetic fixtures are disclosed.

FND-03: every slice bound is a named span (analysis.spans).
"""

from __future__ import annotations

import tomllib
from pathlib import Path

from analysis.spans import WINDOW_1, WINDOW_M1
from analysis.lock_graph import contract

ENGINE = "CARGO_LOCK_GRAPH_V1"
EVIDENCE = "CARGO_LOCK_DEPENDENCIES"
MANIFEST_ENGINE = "CARGO_TOML_DECLARATIONS_V1"
FORMAT_LOCK = "Cargo.lock"
FORMAT_MANIFEST = "Cargo.toml"

SUPPORTED_FORMATS = {1, 2, 3, 4}
_DEP_BLOCKS = (("dependencies", "unknown"),)


def _source_kind(source: str) -> str:
    """Source-string provenance kind: absent -> path, git+ -> git, else registry."""
    return ("path" if not source else
            ("git" if source.startswith("git+") else "registry"))


def _parse_dep_entry(entry: str) -> tuple:
    """``name`` / ``name version`` / ``name version (source)`` ->
    (name, version|'', source_hint|'')."""
    text = str(entry or "").strip().strip('"')
    source_hint = ""
    if text.endswith(")"):
        open_at = text.rfind("(")
        if open_at > 0:
            source_hint = text[open_at + WINDOW_1:WINDOW_M1].strip()
            text = text[:open_at].strip()
    parts = text.split()
    if not parts:
        return ("", "", "")
    name = parts[0]
    version = parts[WINDOW_1] if len(parts) > WINDOW_1 else ""
    return (name, version, source_hint)


def _resolve_entry(universe: dict, name: str, version: str,
                   source_hint: str) -> tuple:
    """-> (confidence, resolved_block|None, candidates).

    Resolution order: exact (name, version); source-hint disambiguation;
    unique same-name instance; multiple same-name instances -> AMBIGUOUS.
    """
    blocks = universe.get(name) or []
    if version:
        exact = [b for b in blocks if b["version"] == version]
        if len(exact) == 1:
            return (contract.VERIFIED, exact[0], [])
        if len(exact) > 1 and source_hint:
            by_source = [b for b in exact
                         if source_hint in str(b.get("source") or "")]
            if len(by_source) == 1:
                return (contract.VERIFIED, by_source[0], [])
        if not exact:
            return (contract.UNRESOLVED, None, [])
        # B-5c (F-R4-C, R2.3 yarn convention): dedupe the candidate
        # disclosure strings -- two instances can share name+version
        # (different sources) and rendered identically; the instances
        # stay distinct, the disclosure list does not repeat a string.
        return (contract.AMBIGUOUS, None,
                sorted({f"{b['name']}@{b['version']}" for b in exact}))
    if len(blocks) == 1:
        return (contract.VERIFIED, blocks[0], [])
    if not blocks:
        return (contract.UNRESOLVED, None, [])
    if source_hint:
        by_source = [b for b in blocks
                     if source_hint in str(b.get("source") or "")]
        if len(by_source) == 1:
            return (contract.VERIFIED, by_source[0], [])
    return (contract.AMBIGUOUS, None,
            sorted({f"{b['name']}@{b['version']}" for b in blocks}))


def extract(lockfile_path: str) -> dict:
    try:
        text = Path(lockfile_path).read_text(
            encoding="utf-8", errors="replace")
        data = tomllib.loads(text)
    except Exception as exc:
        return contract.extraction_result(
            engine=ENGINE, source=str(lockfile_path),
            format_version=FORMAT_LOCK,
            graph_status=contract.EXTRACTION_ERROR, edges=[],
            limitations=[f"Cargo.lock parse failed: {exc}"])
    if not isinstance(data, dict) or "package" not in data:
        return contract.extraction_result(
            engine=ENGINE, source=str(lockfile_path),
            format_version=FORMAT_LOCK,
            graph_status=contract.UNSUPPORTED_FORMAT, edges=[],
            limitations=["Cargo.lock declares no [[package]] sections; "
                         "no edges fabricated."])

    raw_version = data.get("version", 1)
    try:
        format_version = int(raw_version)
    except (TypeError, ValueError):
        format_version = None
    if format_version not in SUPPORTED_FORMATS:
        return contract.extraction_result(
            engine=ENGINE, source=str(lockfile_path),
            format_version=f"Cargo.lock format {raw_version or '?'}",
            graph_status=contract.UNSUPPORTED_FORMAT, edges=[],
            limitations=[f"Cargo.lock format version '{raw_version or '?'}' "
                         "is not supported (supported: 1-4); no edges "
                         "fabricated."])
    format_note = ("format version key absent: treated as format 1"
                   if "version" not in data else
                   f"format version {format_version}")

    packages = [p for p in (data.get("package") or [])
                if isinstance(p, dict)]
    universe: dict[str, list] = {}
    invalid_records = 0
    for pkg in packages:
        name = str(pkg.get("name") or "").strip()
        version = str(pkg.get("version") or "").strip()
        if not name or not version:
            invalid_records += 1
            continue
        universe.setdefault(name, []).append({
            "name": name, "version": version,
            "source": str(pkg.get("source") or "")})

    edges = []
    duplicate_dropped = 0
    for pkg in packages:
        parent_name = str(pkg.get("name") or "").strip()
        parent_version = str(pkg.get("version") or "").strip()
        if not parent_name or not parent_version:
            continue
        source = str(pkg.get("source") or "")
        parent_qualifiers = {"source_kind": _source_kind(source)}
        if source:
            parent_qualifiers["source"] = source
        for dep_entry in pkg.get("dependencies") or []:
            child_name, child_version, source_hint = _parse_dep_entry(
                dep_entry)
            location = (f"[[package] {parent_name}@{parent_version}] "
                        f"dependencies {child_name}")
            qualifiers = dict(parent_qualifiers)

            def _edge(**kwargs):
                edge = contract.build_edge(
                    ecosystem="crates.io", source=str(lockfile_path),
                    source_location=location, evidence_source=EVIDENCE,
                    scope="unknown", qualifiers=qualifiers, **kwargs)
                edge["requested_spec"] = str(dep_entry)
                return edge

            confidence, resolved, candidates = _resolve_entry(
                universe, child_name, child_version, source_hint)
            if confidence == contract.VERIFIED:
                # B-5b (D-020 Ruby precedent): the resolved child's own
                # [[package]] block is the child-side evidence -- disclose
                # child_source_kind/child_source (+ child_revision when the
                # source carries a # rev). AMBIGUOUS/UNRESOLVED children
                # resolve to no single instance: nothing fabricated.
                child_source = str(resolved.get("source") or "")
                qualifiers["child_source_kind"] = _source_kind(child_source)
                if child_source:
                    qualifiers["child_source"] = child_source
                    if "#" in child_source:
                        qualifiers["child_revision"] = \
                            child_source.rsplit("#", 1)[1]
                edges.append(_edge(
                    parent_name=parent_name,
                    parent_version=parent_version,
                    child_name=resolved["name"],
                    child_version=resolved["version"]))
            elif confidence == contract.AMBIGUOUS:
                edges.append(_edge(
                    parent_name=parent_name,
                    parent_version=parent_version,
                    child_name=child_name, child_version="",
                    confidence=contract.AMBIGUOUS,
                    ambiguity={"candidates": candidates},
                    resolution_status="AMBIGUOUS_MULTIPLE_INSTANCES"))
            else:
                edges.append(_edge(
                    parent_name=parent_name,
                    parent_version=parent_version,
                    child_name=child_name, child_version="",
                    resolution_status="CHILD_NOT_IN_LOCKFILE"))

    deduped: dict[tuple, dict] = {}
    for edge in edges:
        key = (edge["parent_name"], edge["parent_version"],
               edge["child_name"], edge.get("child_version") or "",
               edge["confidence"])
        if key in deduped:
            duplicate_dropped += 1
            continue
        deduped[key] = edge

    edges = sorted(deduped.values(), key=lambda e: (
        e["parent_name"], e["parent_version"], e["child_name"],
        e["confidence"], e.get("child_version") or "",
    ))
    verified_status = (contract.VERIFIED_EDGES_AVAILABLE if any(
        e["confidence"] == contract.VERIFIED for e in edges)
        else contract.NO_VERIFIED_EDGES)
    limitations = [
        "Cargo.lock merges normal/dev/build dependency kinds and does not "
        "record target specificity: edges carry scope=unknown (never "
        "invented); kind and target evidence requires `cargo metadata`.",
        "optional feature-gated dependencies appear only when ACTUALLY "
        "activated in the recorded resolution -- absence of an optional "
        "dependency is not evidence of absence in other feature "
        "combinations.",
        "renamed dependencies are manifest-level: Cargo.lock references "
        "the REAL package identity and the rename travels via the "
        "Cargo.toml declarations envelope.",
        f"{format_note}; no `cargo` CLI in this environment (GAP-R2-08 "
        "analogue), so real `cargo metadata` artifacts cannot be "
        "generated here.",
    ]
    return contract.extraction_result(
        engine=ENGINE, source=str(lockfile_path),
        format_version=(f"Cargo.lock format {format_version}"
                        if format_version else FORMAT_LOCK),
        graph_status=verified_status, edges=edges,
        tallies={"duplicate_records_dropped": duplicate_dropped,
                 "invalid_records": invalid_records},
        limitations=limitations)


# ---- Cargo.toml declarations envelope ---------------------------------------------
def _count_dep_block(block: dict, tallies: dict, prefix: str) -> tuple:
    """One dependency table -> (declaration_count, source-kind counts)."""
    declarations = 0
    renames = []
    workspace_inherited = 0
    for dep_name, spec in block.items():
        declarations += 1
        if isinstance(spec, dict):
            if spec.get("workspace") is True:
                workspace_inherited += 1
            if spec.get("package"):
                renames.append({"declared_as": dep_name,
                                "real_package": str(spec["package"])})
            for kind in ("path", "git", "registry"):
                if kind in spec:
                    key = f"{prefix}_source_{kind}"
                    tallies[key] = tallies.get(key, 0) + 1
                    break
            else:
                if "version" in spec:
                    key = f"{prefix}_source_registry"
                    tallies[key] = tallies.get(key, 0) + 1
        else:
            key = f"{prefix}_source_registry"
            tallies[key] = tallies.get(key, 0) + 1
    return declarations, renames, workspace_inherited


def extract_manifest(lockfile_path: str) -> dict:
    try:
        text = Path(lockfile_path).read_text(
            encoding="utf-8", errors="replace")
        data = tomllib.loads(text)
    except Exception as exc:
        return contract.extraction_result(
            engine=MANIFEST_ENGINE, source=str(lockfile_path),
            format_version=FORMAT_MANIFEST,
            graph_status=contract.EXTRACTION_ERROR, edges=[],
            limitations=[f"Cargo.toml parse failed: {exc}"])
    if not isinstance(data, dict):
        return contract.extraction_result(
            engine=MANIFEST_ENGINE, source=str(lockfile_path),
            format_version=FORMAT_MANIFEST,
            graph_status=contract.UNSUPPORTED_FORMAT, edges=[],
            limitations=["Cargo.toml is not a mapping; no edges "
                         "fabricated."])

    tallies: dict = {}
    membership = 0
    all_renames = []
    workspace_inherited = 0
    for block_name, prefix in (("dependencies", "dependencies"),
                               ("dev-dependencies", "dev_dependencies"),
                               ("build-dependencies", "build_dependencies")):
        block = data.get(block_name) or {}
        declarations, renames, inherited = _count_dep_block(
            block, tallies, prefix)
        tallies[f"{prefix}_declarations"] = declarations
        membership += declarations
        all_renames.extend(renames)
        workspace_inherited += inherited

    targets = data.get("target") or {}
    target_blocks = 0
    if isinstance(targets, dict):
        for _triple, sections in targets.items():
            if not isinstance(sections, dict):
                continue
            for block_name, prefix in (
                    ("dependencies", "target_dependencies"),
                    ("dev-dependencies", "target_dev_dependencies"),
                    ("build-dependencies", "target_build_dependencies")):
                block = sections.get(block_name) or {}
                declarations, renames, inherited = _count_dep_block(
                    block, tallies, prefix)
                if declarations:
                    target_blocks += 1
                tallies[f"{prefix}_declarations"] = \
                    tallies.get(f"{prefix}_declarations", 0) + declarations
                membership += declarations
                all_renames.extend(renames)
                workspace_inherited += inherited
    tallies["target_blocks"] = target_blocks

    if all_renames:
        tallies["rename_details"] = all_renames
    tallies["renamed_dependencies"] = len(all_renames)
    tallies["workspace_inherited_declarations"] = workspace_inherited
    workspace = data.get("workspace")
    if isinstance(workspace, dict):
        members = workspace.get("members") or []
        tallies["workspace_members"] = len(members)
        ws_deps = workspace.get("dependencies") or {}
        if isinstance(ws_deps, dict):
            tallies["workspace_dependency_definitions"] = len(ws_deps)

    limitations = [
        "Cargo.toml declarations are manifest statements, not "
        "resolved relationships: they are tallied (per block, with "
        "source kinds, renames and workspace inheritance) and "
        "disclosed, never edges -- no synthetic root is minted.",
        "resolved parent-child relationships require Cargo.lock "
        "evidence (or `cargo metadata`, unavailable here: GAP-R2-08 "
        "analogue).",
    ]
    for rename in all_renames:
        limitations.append(
            f"renamed dependency (manifest alias evidence, not a "
            f"relationship): declared as '{rename['declared_as']}' for "
            f"real package '{rename['real_package']}'.")

    return contract.extraction_result(
        engine=MANIFEST_ENGINE, source=str(lockfile_path),
        format_version=FORMAT_MANIFEST,
        graph_status=contract.UNSUPPORTED_FORMAT, edges=[],
        tallies=tallies, limitations=limitations,
        membership_packages=membership)
