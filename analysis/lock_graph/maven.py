"""Maven verified-edge extractor (R2.2, evidence tier: resolved-evidence-required).

Evidence basis (verified on REAL `mvn dependency:tree` output -- the
BenchmarkJava corpus file plus freshly generated offline evidence): the
dependency tree declares parent-child pairs with RESOLVED versions and
scopes. The tree's root line is the scanned project itself.

Honesty rules (master prompt §7, approved R2.0 tier model):
- A pom.xml is direct declarations with unresolved properties/ranges -- it
  is NOT a graph and the registry answers it with a disclosed UNSUPPORTED
  envelope pointing at the `mvn dependency:tree` convention. Manifests never
  produce edges.
- Pruned references ("omitted for duplicate/conflict") are absent from the
  resolved graph -- skipped and tallied, never invented as edges.
- Conflict resolutions ("-> selected", verbose output) carry the SELECTED
  version; the requested version travels as a qualifier.
- Classifiers (5-part coordinates) travel as qualifiers; the purl names the
  group:artifact coordinate (scanner.purl single authority).
"""

from __future__ import annotations

import re

from pathlib import Path

from analysis.lock_graph import contract

ENGINE = "MAVEN_DEPENDENCY_TREE_V1"
EVIDENCE = "MAVEN_DEPENDENCY_TREE"

_KNOWN_SCOPES = {"compile", "test", "runtime", "provided", "system"}
_ROOT_CONVENTION = (
    "pom declarations are direct-only with unresolved properties/ranges; "
    "verified parent-child edges require resolved evidence -- generate with "
    "`mvn dependency:tree -DoutputFile=dependency-tree.txt` (registered "
    "filename: dependency-tree.txt)"
)


def _parse_coordinate(coord: str) -> dict | None:
    """`g:a:type[:classifier]:version[:scope]` -> identity dict, or None."""
    parts = [p.strip() for p in coord.split(":")]
    if len(parts) < 3:
        return None
    group, artifact = parts[0], parts[1]
    scope = "compile"
    classifier = ""
    if parts[-1] in _KNOWN_SCOPES:
        scope = parts[-1]
        version = parts[-2]
        if len(parts) >= 5:
            classifier = parts[-3]
    else:
        version = parts[-1]
        if len(parts) >= 4:
            classifier = parts[-3]
    if not group or not artifact or not version:
        return None
    return {
        "name": f"{group}:{artifact}",
        "version": version,
        "scope": scope,
        "classifier": classifier,
        "type": parts[2] if len(parts) >= 3 else "jar",
    }


def _split_decorations(line: str) -> tuple[int, str] | None:
    """Tree line -> (depth, coordinate-text); None when not a tree line.

    mvn's decoration is structural: each ancestor level contributes either
    ``|`` + 2 spaces or 3 spaces, followed by the connector (``+- `` /
    ``\\- ``). Depth = 1 + pipes + (spaces before the connector) // 3.
    The root line carries no decoration (depth 0). Leading whitespace is
    STRUCTURE and must not be stripped.
    """
    text = line.rstrip()
    if not text.strip():
        return None
    text = re.sub(r"^\[[A-Z]+\]\s*", "", text)  # [INFO] etc.
    for connector in ("+- ", "\\- "):
        idx = text.find(connector)
        if idx == -1:
            continue
        prefix = text[:idx]
        if set(prefix) <= set("| "):
            depth = 1 + prefix.count("|") + prefix.count(" ") // 3
            return depth, text[idx + len(connector):].strip()
        return None  # decoration would be a guess -- refuse the line
    if text[:6].strip() == "" and "|" in text[:6]:
        return None  # bare continuation fragment
    return 0, text.strip()


def extract(lockfile_path: str) -> dict:
    try:
        lines = Path(lockfile_path).read_text(
            encoding="utf-8", errors="replace").splitlines()
    except Exception as exc:
        return contract.extraction_result(
            engine=ENGINE,
            source=str(lockfile_path),
            format_version="maven-dependency-tree",
            graph_status=contract.EXTRACTION_ERROR,
            edges=[],
            limitations=[f"dependency-tree read failed: {exc}"],
        )

    root = None
    stack: list[dict] = []  # (depth, identity) ancestors
    edges: list[dict] = []
    omitted = conflicts = 0
    for raw in lines:
        line = raw.rstrip()
        if not line.strip():
            continue
        parsed = _split_decorations(line)
        if parsed is None:
            return contract.extraction_result(
                engine=ENGINE,
                source=str(lockfile_path),
                format_version="maven-dependency-tree",
                graph_status=contract.EXTRACTION_ERROR,
                edges=[],
                limitations=[f"unparseable tree line: {raw[:80]!r}"],
            )
        depth, text = parsed

        # pruned references: absent from the resolved graph
        if " - omitted for " in text or "omitted for duplicate" in text:
            omitted += 1
            continue

        selected_version = ""
        if " -> " in text:
            text, selected_version = text.split(" -> ", 1)
            selected_version = selected_version.strip()
            conflicts += 1

        identity = _parse_coordinate(text)
        if identity is None:
            return contract.extraction_result(
                engine=ENGINE,
                source=str(lockfile_path),
                format_version="maven-dependency-tree",
                graph_status=contract.EXTRACTION_ERROR,
                edges=[],
                limitations=[f"unparseable coordinate: {text[:80]!r}"],
            )
        if selected_version:
            # verbose trees print "-> selected": the pre-arrow version was
            # REQUESTED, the post-arrow one is what the resolver chose.
            identity["requested_version"] = identity["version"]
            if ":" in selected_version:
                sel = _parse_coordinate(selected_version)
                identity["version"] = sel["version"] if sel else selected_version
            else:
                identity["version"] = selected_version
            identity["conflict"] = True

        if depth == 0:
            # the scanned project itself: parent of every level-1 dep
            root = dict(identity)
            stack = [(0, identity)]
            continue

        while stack and stack[-1][0] >= depth:
            stack.pop()
        if not stack:
            return contract.extraction_result(
                engine=ENGINE,
                source=str(lockfile_path),
                format_version="maven-dependency-tree",
                graph_status=contract.EXTRACTION_ERROR,
                edges=[],
                limitations=[f"orphan tree node at depth {depth}: {text[:60]!r}"],
            )
        parent = stack[-1][1]

        qualifiers: dict = {"scope_declared": identity["scope"]}
        if identity["classifier"]:
            qualifiers["classifier"] = identity["classifier"]
        qualifiers["packaging"] = identity["type"]
        if identity.get("conflict"):
            qualifiers["requested_version"] = identity["requested_version"]
            qualifiers["selected_version"] = identity["version"]
            qualifiers["conflict_resolved"] = "true"
        if depth == 1 and root:
            qualifiers["root"] = (
                f"{root['name']}:{root['type']}:{root['version']}")

        edges.append(contract.build_edge(
            ecosystem="maven",
            parent_name=parent["name"], parent_version=parent["version"],
            child_name=identity["name"], child_version=identity["version"],
            source=str(lockfile_path),
            source_location=f"depth {depth} under {parent['name']}",
            evidence_source=EVIDENCE,
            scope=identity["scope"],
            qualifiers=qualifiers))
        stack.append((depth, identity))

    edges.sort(key=lambda e: (
        e["parent_name"], e["parent_version"], e["child_name"],
        e.get("child_version") or "",
    ))
    verified = contract.VERIFIED_EDGES_AVAILABLE if edges else \
        contract.NO_VERIFIED_EDGES
    return contract.extraction_result(
        engine=ENGINE,
        source=str(lockfile_path),
        format_version="maven-dependency-tree",
        graph_status=verified,
        edges=edges,
        tallies={"unsupported": omitted},
        limitations=(["conflict resolutions counted"] if conflicts else []),
    )


def extract_manifest(manifest_path: str) -> dict:
    """pom.xml / build.gradle answer: manifests are not graphs (disclosed)."""
    name = Path(manifest_path).name
    return contract.extraction_result(
        engine=ENGINE if name == "pom.xml" else "GRADLE_MANIFEST_V1",
        source=str(manifest_path),
        format_version=name,
        graph_status=contract.UNSUPPORTED_FORMAT,
        edges=[],
        limitations=[
            f"{name} declarations are direct-only with unresolved "
            f"properties/ranges; {_ROOT_CONVENTION}" if name == "pom.xml"
            else f"{name} declarations do not encode a resolved graph; "
                 "verified edges require resolved evidence -- generate with "
                 "`gradle dependencies` (registered filename: "
                 "gradle-dependencies.txt)",
        ],
    )
