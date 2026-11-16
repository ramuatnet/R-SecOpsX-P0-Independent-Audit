"""Gradle verified-edge extractor (R2.2, evidence tier: resolved-evidence-required).

Evidence basis: `gradle dependencies` output declares parent-child pairs
with resolved versions per configuration. Gradle prints NO root project
line, so level-1 entries under a configuration header are the project's
DIRECT declarations -- counted (`direct_declarations`), never given an
invented parent (no synthetic root for non-npm ecosystems, per the R2.0
approval). Transitive parentage starts at depth >= 2 from the decoration
tree.

Marker semantics (R2.6.1 -- corrected from the R2 final closure audit's
F-1 finding; the (n) and (c) markers are NOT interchangeable):

- ``(n)`` -- the printed version was REQUESTED but NOT resolved (e.g.
  conflicted away). The node has NO resolved version: the edge is
  disclosed UNRESOLVED with the requested version travelling as a
  qualifier (`requested_version` / `parent_requested_version`) and
  `resolution_status=GRADLE_VERSION_NOT_RESOLVED`. A requested version is
  never silently promoted to a resolved one, and no fingerprint is minted
  (contract: fingerprints exist only for VERIFIED identities). This
  applies wherever the node sits -- as a child or as a parent.
- ``(c)`` -- R2.6.2: a DEPENDENCY CONSTRAINT entry, NOT a dependency
  (Gradle userguide: "This element is a dependency constraint, not a
  dependency. Look for the matching dependency elsewhere in the tree.").
  The constraint's version is never promoted: the entry is disclosed
  UNRESOLVED (`GRADLE_CONSTRAINT_ENTRY_NOT_DEPENDENCY`, constraint
  version as a qualifier, no fingerprint) on both parent and child
  sides, tallied (`constraint_entries`), and depth-1 constraint lines
  are not counted as direct declarations.
- ``(*)`` means "subtree already printed" -- the dependency still exists
  and its edge is kept (`subtree_elided` qualifier).
- Conflict resolutions (``-> selected``) carry the selected version; the
  requested version travels as a qualifier (`conflict_resolved`). A
  missing selected version (``g:a:1.0 -> ``) is requested-but-unresolved
  and follows the (n) semantics.
- ``project :module`` references have no registry identity -- skipped and
  tallied (their subtree edges are disclosed UNRESOLVED
  `PROJECT_PARENT_UNSUPPORTED`, never invented).

The same pair under multiple configurations dedupes by identity with
configurations merged (identity-stable fingerprints, per the common
contract).

``gradle.lockfile`` is a flat resolved-version list -- no parent map, so it
answers a disclosed membership-only envelope (never fabricates edges).
"""

from __future__ import annotations

import re
from pathlib import Path

from analysis.lock_graph import contract
from analysis.spans import WINDOW_6, WINDOW_60, WINDOW_80

ENGINE = "GRADLE_DEPENDENCIES_V1"
EVIDENCE = "GRADLE_DEPENDENCIES"

_LEVEL = 5  # one gradle ancestor level: '|    ' (pipe+4sp) or 5 spaces
_KNOWN_GRADLE_SCOPES = re.compile(r"test|androidTest|debug|release|")


def _scope_of(configuration: str) -> str:
    if "test" in configuration:
        return "test"
    return "runtime"


def _split_decorations(line: str) -> tuple[int, str] | None:
    """Gradle line -> (depth, body); None when not a tree line.

    Gradle's decoration: each ancestor level is ``|`` + 4 spaces or 5
    spaces, then the connector (``+--- `` / ``\\--- ``). Depth = 1 +
    pipes + spaces//5. Leading whitespace is STRUCTURE. Column-0 text
    without a connector is a configuration header (returned as-is with
    depth 0 for the caller to interpret).
    """
    if re.match(r"^>\s*Task\b", line):
        # "> Task :proj:dependencies" banner: skip the whole line (stripping
        # it to empty would masquerade as a configuration header).
        return None
    text = line.rstrip()
    if not text.strip():
        return None
    for connector in ("+--- ", "\\--- "):
        idx = text.find(connector)
        if idx == -1:
            continue
        prefix = text[:idx]
        if set(prefix) <= set("| "):
            depth = 1 + prefix.count("|") + prefix.count(" ") // _LEVEL
            return depth, text[idx + len(connector):].strip()
        return None
    if text[:WINDOW_6].strip() == "" and "|" in text[:WINDOW_6]:
        return None
    return 0, text.strip()


def _parse_node(body: str) -> dict | None:
    """`g:a:version` (+ markers/conflicts) -> identity dict, or None for
    project references / unparseable entries.

    R2.6.1: an ``(n)`` marker marks the printed version as NOT resolved
    -- the node keeps its requested version as a qualifier and carries no
    resolved version (the contract downgrades the edge to UNRESOLVED, so
    a requested version is never promoted).
    R2.6.2: a ``(c)`` marker identifies a DEPENDENCY CONSTRAINT, not an
    in-use dependency -- the entry is disclosed UNRESOLVED
    (GRADLE_CONSTRAINT_ENTRY_NOT_DEPENDENCY) with the constraint version
    as a qualifier, and never independently creates a VERIFIED dependency
    edge or fingerprint. The two markers are distinct and must not share
    one code path."""
    not_resolved = bool(re.search(r"\(n\)\s*$", body))
    constraint_entry = bool(re.search(r"\(c\)\s*$", body))
    # strip ALL trailing (c)/(n) markers (defensive: real Gradle never
    # prints both, but "1.0.0 (c) (n)" must not leave "(c)" in the version)
    while re.search(r"\s*\([nc]\)\s*$", body):
        body = re.sub(r"\s*\([nc]\)\s*$", "", body)
    conflict = ""
    arrow = re.search(r"\s+->\s*(.*)$", body)
    if arrow:
        body = body[:arrow.start()]
        selected = arrow.group(1).strip()
        if selected:
            conflict = selected
        else:
            # `g:a:1.0 ->` with no selected version: requested but
            # unresolved -- same evidence semantics as (n).
            not_resolved = True
    star = bool(re.search(r"\(\*\)\s*$", body))
    body = re.sub(r"\s*\(\*\)\s*$", "", body)
    parts = [p.strip() for p in body.split(":")]
    if len(parts) == 2:
        # F-RG-2: platform/BOM-selected version shape `g:a -> selected`
        # (conflict-resolution arrow with NO requested version printed on
        # the left).  Gradle prints `->` only from resolution results and
        # the selected version's subtree expands below the node, so the
        # node IS resolved at the selected version.  The requested version
        # is not printed and is never invented: the edge discloses
        # `version_selected_by_platform` instead (no speculative
        # constraint-to-dependency matching).
        group, artifact = parts
        if not group or not artifact or not arrow:
            return None
        sel = re.sub(r"\s*\(\*\)\s*$", "", conflict).strip()
        node = {"name": f"{group}:{artifact}", "version": "",
                "star": bool(re.search(r"\(\*\)\s*$", conflict)),
                "requested_version": ""}
        if not_resolved:
            # `(n)`-marked or `g:a ->` empty: requested-but-unresolved --
            # no resolved version, never promoted (as the 3-part path).
            node["not_resolved"] = True
        elif constraint_entry:
            # `g:a -> v (c)`: dependency CONSTRAINT -- no resolved version.
            node["constraint"] = True
            node["constraint_version"] = sel
        else:
            if not sel:
                return None
            node["version"] = sel
            node["version_selected_by_platform"] = True
        return node
    if len(parts) != 3:
        return None
    group, artifact, version = parts
    if not group or not artifact or not version:
        return None
    node = {
        "name": f"{group}:{artifact}",
        "version": version,
        "star": star,
        "requested_version": "",
    }
    if not_resolved:
        node["requested_version"] = version
        node["version"] = ""      # NO resolved version: never promoted
        node["not_resolved"] = True
        if constraint_entry:
            # defensive: both markers (real Gradle never prints this) --
            # the (n) semantics win, the constraint marker still disclosed
            node["constraint_version"] = version
    elif constraint_entry:
        # R2.6.2: a (c) entry is a DEPENDENCY CONSTRAINT, not a dependency
        # (Gradle userguide: "This element is a dependency constraint, not
        # a dependency. Look for the matching dependency elsewhere in the
        # tree."). It carries no resolved version: the constraint's
        # required version travels as a qualifier and the entry is
        # disclosed UNRESOLVED -- never promoted, never VERIFIED.
        node["requested_version"] = version
        node["version"] = ""
        node["constraint"] = True
        node["constraint_version"] = version
    elif conflict:
        node["requested_version"] = version
        node["version"] = conflict
        node["conflict"] = True
    return node


def _is_project_reference(body: str) -> bool:
    return body.strip().startswith("project ")


def _has_deeper_following(lines: list[str], i: int) -> bool:
    """True when a tree line deeper than ``lines[i]`` follows -- i.e. the
    node has a subtree whose parentage would be lost (F-RG-2 §5: such an
    unparseable node keeps the fatal error; leaves are tallied instead)."""
    parsed = _split_decorations(lines[i])
    if parsed is None:
        return False
    depth = parsed[0]
    for nxt in lines[i + 1:]:
        p = _split_decorations(nxt)
        if p is None:
            continue
        return p[0] > depth
    return False


def extract(lockfile_path: str) -> dict:
    try:
        lines = Path(lockfile_path).read_text(
            encoding="utf-8", errors="replace").splitlines()
    except Exception as exc:
        return contract.extraction_result(
            engine=ENGINE,
            source=str(lockfile_path),
            format_version="gradle-dependencies",
            graph_status=contract.EXTRACTION_ERROR,
            edges=[],
            limitations=[f"gradle output read failed: {exc}"],
        )

    edges: list[dict] = []
    duplicate_dropped = 0
    direct_declarations = 0
    unsupported = 0
    not_resolved_markers = 0
    constraint_entries = 0
    invalid_nodes = 0
    limitations: list[str] = []
    configuration = ""
    stack: list[tuple[int, dict]] = []
    for i, raw in enumerate(lines):
        parsed = _split_decorations(raw)
        if parsed is None:
            continue
        depth, text = parsed
        if depth == 0:
            header = text.strip()
            if header.startswith("> Task"):
                continue
            # configuration header (column 0, no decoration)
            configuration = header
            stack = []
            continue

        if _is_project_reference(text):
            # no registry identity: counted, and kept on the stack so the
            # subtree's real structure is not orphaned.
            unsupported += 1
            stack.append((depth, {"name": text.strip(), "version": "",
                                  "project": True}))
            continue

        node = _parse_node(text)
        if node is None:
            # F-RG-2 §5 hardening: an unparseable LEAF is tallied and
            # disclosed (limitation + invalid_nodes) instead of blanking
            # the whole evidence source; an unparseable node WITH a subtree
            # keeps the fatal error -- the children's parentage is unknown
            # and detections must never differ.
            if _has_deeper_following(lines, i):
                return contract.extraction_result(
                    engine=ENGINE,
                    source=str(lockfile_path),
                    format_version="gradle-dependencies",
                    graph_status=contract.EXTRACTION_ERROR,
                    edges=[],
                    limitations=[
                        f"unparseable gradle node with subtree: "
                        f"{text[:WINDOW_80]!r}"],
                )
            invalid_nodes += 1
            limitations.append(
                f"unparseable gradle node (leaf, dropped): "
                f"{text[:WINDOW_80]!r}")
            continue

        if depth == 1:
            # R2.6.2: a depth-1 constraint entry is a CONSTRAINT, not one
            # of the project's direct dependencies.
            if node.get("constraint"):
                constraint_entries += 1
            else:
                # direct declaration of the project: counted, not edged
                direct_declarations += 1
            stack = [(1, node)]
            continue

        while stack and stack[-1][0] >= depth:
            stack.pop()
        if not stack:
            return contract.extraction_result(
                engine=ENGINE,
                source=str(lockfile_path),
                format_version="gradle-dependencies",
                graph_status=contract.EXTRACTION_ERROR,
                edges=[],
                limitations=[f"orphan gradle node at depth {depth}: {text[:WINDOW_60]!r}"],
            )
        parent = stack[-1][1]
        parent_is_project = bool(parent.get("project"))

        qualifiers: dict = {"configuration": configuration}
        if node.get("requested_version"):
            qualifiers["requested_version"] = node["requested_version"]
            if node.get("conflict"):
                qualifiers["conflict_resolved"] = "true"
        if node.get("constraint_version"):
            qualifiers["constraint_version"] = node["constraint_version"]
        if node.get("star"):
            qualifiers["subtree_elided"] = "true"
        if node.get("version_selected_by_platform"):
            # F-RG-2: the selected version was chosen by a platform/BOM
            # (the platform itself is not printed by `dependencies` and is
            # never guessed); no requested_version exists on this shape.
            qualifiers["version_selected_by_platform"] = "true"
        # R2.6.1: an (n) endpoint -- child or parent -- has no resolved
        # version; the contract downgrades the edge to UNRESOLVED and the
        # requested version is disclosed, never promoted.
        resolution_status = ""
        if node.get("not_resolved"):
            not_resolved_markers += 1
            resolution_status = "GRADLE_VERSION_NOT_RESOLVED"
        if not parent_is_project and parent.get("not_resolved"):
            qualifiers["parent_requested_version"] = \
                parent.get("requested_version", "")
            resolution_status = "GRADLE_VERSION_NOT_RESOLVED"
        # R2.6.2: a (c) endpoint -- child or parent -- is a DEPENDENCY
        # CONSTRAINT, not a dependency: the edge is disclosed UNRESOLVED
        # with the constraint version retained as a qualifier, never
        # promoted and never VERIFIED (no fingerprint).
        if node.get("constraint"):
            constraint_entries += 1
            resolution_status = "GRADLE_CONSTRAINT_ENTRY_NOT_DEPENDENCY"
        if not parent_is_project and parent.get("constraint"):
            qualifiers["parent_constraint_version"] = \
                parent.get("constraint_version", "")
            resolution_status = "GRADLE_CONSTRAINT_ENTRY_NOT_DEPENDENCY"

        if parent_is_project:
            # the parent has no registry identity -- disclosed as
            # UNRESOLVED, never invented as a registry artifact edge.
            edges.append(contract.build_edge(
                ecosystem="maven",
                parent_name=parent["name"], parent_version="",
                child_name=node["name"], child_version=node["version"],
                source=str(lockfile_path),
                source_location=f"{configuration} depth {depth}",
                evidence_source=EVIDENCE,
                scope=_scope_of(configuration),
                qualifiers=qualifiers,
                resolution_status="PROJECT_PARENT_UNSUPPORTED"))
            stack.append((depth, node))
            continue
        edges.append(contract.build_edge(
            ecosystem="maven",
            parent_name=parent["name"], parent_version=parent["version"],
            child_name=node["name"], child_version=node["version"],
            source=str(lockfile_path),
            source_location=f"{configuration} depth {depth}",
            evidence_source=EVIDENCE,
            scope=_scope_of(configuration),
            qualifiers=qualifiers,
            resolution_status=resolution_status))
        stack.append((depth, node))

    # same identity under multiple configurations: dedupe by identity with
    # configurations merged (identity-stable fingerprints)
    deduped: dict[tuple, dict] = {}
    for edge in edges:
        key = (edge["parent_name"], edge["parent_version"],
               edge["child_name"], edge.get("child_version") or "",
               edge["confidence"])
        existing = deduped.get(key)
        if existing is None:
            deduped[key] = edge
            continue
        duplicate_dropped += 1
        quals = existing.setdefault("qualifiers", {})
        prev = quals.get("configurations") or quals.get("configuration")
        new = edge.get("qualifiers", {}).get("configuration")
        merged = f"{prev},{new}" if prev else new
        quals["configurations"] = merged
        quals.pop("configuration", None)

    edges = sorted(deduped.values(), key=lambda e: (
        e["parent_name"], e["parent_version"], e["child_name"],
        e.get("child_version") or "",
    ))
    verified = contract.VERIFIED_EDGES_AVAILABLE if edges else \
        contract.NO_VERIFIED_EDGES
    return contract.extraction_result(
        engine=ENGINE,
        source=str(lockfile_path),
        format_version="gradle-dependencies",
        graph_status=verified,
        edges=edges,
        tallies={
            "direct_declarations": direct_declarations,
            "unsupported": unsupported,
            "duplicate_records_dropped": duplicate_dropped,
            "not_resolved_markers": not_resolved_markers,
            "constraint_entries": constraint_entries,
            "invalid_nodes": invalid_nodes,
        },
        limitations=limitations,
    )


def extract_lockfile(lockfile_path: str) -> dict:
    """gradle.lockfile: flat resolved-version pins -- membership only."""
    membership = 0
    try:
        for line in Path(lockfile_path).read_text(
                encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line and ":" in line:
                membership += 1
        return contract.extraction_result(
            engine="GRADLE_LOCKFILE_V1",
            source=str(lockfile_path),
            format_version="gradle.lockfile",
            graph_status=contract.UNSUPPORTED_FORMAT,
            edges=[],
            limitations=[
                "gradle.lockfile is a flat resolved-version pin list and "
                "encodes no parent-child relationships; verified edges "
                "require resolved evidence -- generate with `gradle "
                "dependencies` (registered filename: "
                "gradle-dependencies.txt). Membership classification "
                "comes from the manifest parsers; nothing is inferred.",
            ],
            membership_packages=membership,
        )
    except Exception as exc:
        return contract.extraction_result(
            engine="GRADLE_LOCKFILE_V1",
            source=str(lockfile_path),
            format_version="gradle.lockfile",
            graph_status=contract.EXTRACTION_ERROR,
            edges=[],
            limitations=[f"gradle.lockfile read failed: {exc}"],
        )
