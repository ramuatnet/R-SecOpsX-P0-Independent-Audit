"""Gradle verified-edge extractor (R2.2, evidence tier: resolved-evidence-required).

Evidence basis: `gradle dependencies` output declares parent-child pairs
with resolved versions per configuration. Gradle prints NO root project
line, so level-1 entries under a configuration header are the project's
DIRECT declarations -- counted (`direct_declarations`), never given an
invented parent (no synthetic root for non-npm ecosystems, per the R2.0
approval). Transitive parentage starts at depth >= 2 from the decoration
tree.

Markers: ``(*)`` means "subtree already printed" -- the dependency still
exists and its edge is kept; ``(c)`` constraint and ``(n)`` unresolved
markers are disclosed via qualifiers; ``project :module`` references have
no registry identity -- skipped and tallied. Conflict resolutions
(``-> selected``) carry the selected version; the requested version
travels as a qualifier. The same pair under multiple configurations
dedupes by identity with configurations merged (identity-stable
fingerprints, per the common contract).

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
    project references / unparseable entries."""
    body = re.sub(r"\s*\([nc]\)\s*$", "", body)  # constraint / not-resolved
    conflict = ""
    if " -> " in body:
        body, selected = body.split(" -> ", 1)
        conflict = selected.strip()
    star = bool(re.search(r"\(\*\)\s*$", body))
    body = re.sub(r"\s*\(\*\)\s*$", "", body)
    parts = [p.strip() for p in body.split(":")]
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
    if conflict:
        node["requested_version"] = version
        node["version"] = conflict
        node["conflict"] = True
    return node


def _is_project_reference(body: str) -> bool:
    return body.strip().startswith("project ")


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
    configuration = ""
    stack: list[tuple[int, dict]] = []
    for raw in lines:
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
            return contract.extraction_result(
                engine=ENGINE,
                source=str(lockfile_path),
                format_version="gradle-dependencies",
                graph_status=contract.EXTRACTION_ERROR,
                edges=[],
                limitations=[f"unparseable gradle node: {text[:WINDOW_80]!r}"],
            )

        if depth == 1:
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
            qualifiers["conflict_resolved"] = "true"
        if node.get("star"):
            qualifiers["subtree_elided"] = "true"

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
            qualifiers=qualifiers))
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
        },
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
