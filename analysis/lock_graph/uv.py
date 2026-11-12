"""uv verified-edge extractor (R2.1, evidence tier: constraint-resolvable).

Evidence basis (verified on the flask corpus, R2.0): uv.lock's
``[[package]]`` entries carry ``[package.metadata].requires-dist`` -- the
parent's declared dependencies as {name, specifier, marker, extra} records
-- and the lockfile holds the resolved universe. Exactly one candidate ->
VERIFIED; multiple -> AMBIGUOUS with candidates disclosed; zero or an
unparseable specifier -> UNRESOLVED. An empty specifier means "any resolved
version" and is still exact evidence (the lockfile resolved exactly one
child identity for that name). Membership alone is never an edge.

Markers/extras are recorded verbatim as qualifiers; `extra` additionally
drives scope=optional (extras-conditional dependency). Package source
(registry/virtual/editable/git) travels as qualifiers.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

from analysis.lock_graph import contract
from analysis.lock_graph.contract import norm_pypi
from analysis.lock_graph.versions import satisfies

ENGINE = "UV_LOCK_GRAPH_V1"
EVIDENCE = "UV_REQUIRES_DIST"


def _source_qualifiers(source) -> dict:
    if not isinstance(source, dict):
        return {}
    qual = {}
    stype = "virtual" if source.get("virtual") else \
        "editable" if source.get("editable") else \
        "git" if source.get("git") else \
        "path" if source.get("path") else "registry"
    qual["source_type"] = stype
    for key in ("git", "url", "registry", "path"):
        if source.get(key):
            qual["source"] = str(source[key])
            break
    for key in ("tag", "branch", "reference", "revision", "subdirectory"):
        if source.get(key):
            qual[f"source_{key}"] = str(source[key])
    return qual


def extract(lockfile_path: str) -> dict:
    try:
        text = Path(lockfile_path).read_text(encoding="utf-8", errors="replace")
        data = tomllib.loads(text)
    except Exception as exc:
        return contract.extraction_result(
            engine=ENGINE,
            source=str(lockfile_path),
            format_version="uv.lock",
            graph_status=contract.EXTRACTION_ERROR,
            edges=[],
            limitations=[f"uv.lock parse failed: {exc}"],
        )

    packages = [p for p in (data.get("package") or []) if isinstance(p, dict)]
    universe: dict[str, list[str]] = {}
    for pkg in packages:
        name = str(pkg.get("name") or "").strip()
        version = str(pkg.get("version") or "").strip()
        if name and version:
            universe.setdefault(norm_pypi(name), []).append(version)

    edges: list[dict] = []
    duplicate_dropped = 0
    for pkg in packages:
        metadata = pkg.get("metadata")
        if not isinstance(metadata, dict):
            continue
        requires = metadata.get("requires-dist")
        if not isinstance(requires, list):
            continue
        parent_name = str(pkg.get("name") or "").strip()
        parent_version = str(pkg.get("version") or "").strip()
        source_quals = _source_qualifiers(pkg.get("source"))
        for rec in requires:
            if not isinstance(rec, dict):
                continue
            dep_name = str(rec.get("name") or "").strip()
            if not dep_name:
                continue
            specifier = str(rec.get("specifier") or "").strip()
            marker = rec.get("marker")
            extra = rec.get("extra")

            qualifiers: dict = dict(source_quals)
            if marker:
                qualifiers["markers"] = str(marker)
            extra = rec.get("extra")
            if not extra and marker and re.match(
                    r"extra\s*==", str(marker)):
                # Real uv.lock shape (verified on flask): extras-conditional
                # deps carry the extra ONLY inside the marker
                # (marker = "extra == 'async'").
                m = re.match(r"extra\s*==\s*['\"]([^'\"]+)['\"]",
                             str(marker).strip())
                if m:
                    extra = m.group(1)
            if extra:
                qualifiers["extra"] = str(extra)
            scope = "optional" if extra else "runtime"

            location = (f"[[package] {parent_name}@{parent_version}] "
                        f"[package.metadata] requires-dist {dep_name}")
            candidates = universe.get(norm_pypi(dep_name), [])

            if not candidates:
                edges.append(contract.build_edge(
                    ecosystem="pypi",
                    parent_name=parent_name, parent_version=parent_version,
                    child_name=dep_name, child_version="",
                    source=str(lockfile_path), source_location=location,
                    evidence_source=EVIDENCE, scope=scope,
                    qualifiers=qualifiers,
                    resolution_status="CHILD_NOT_IN_LOCKFILE"))
                continue

            matched = [v for v in candidates if satisfies(v, specifier)]
            if len(matched) == 1:
                edges.append(contract.build_edge(
                    ecosystem="pypi",
                    parent_name=parent_name, parent_version=parent_version,
                    child_name=dep_name, child_version=matched[0],
                    source=str(lockfile_path), source_location=location,
                    evidence_source=EVIDENCE, scope=scope,
                    qualifiers=qualifiers))
            elif len(matched) > 1:
                edges.append(contract.build_edge(
                    ecosystem="pypi",
                    parent_name=parent_name, parent_version=parent_version,
                    child_name=dep_name, child_version="",
                    source=str(lockfile_path), source_location=location,
                    evidence_source=EVIDENCE, scope=scope,
                    qualifiers=qualifiers,
                    confidence=contract.AMBIGUOUS,
                    ambiguity={"specifier": specifier,
                               "candidates": sorted(matched)},
                    resolution_status="MULTIPLE_CANDIDATES"))
            else:
                parseable = satisfies("1.0", specifier) is not None
                edges.append(contract.build_edge(
                    ecosystem="pypi",
                    parent_name=parent_name, parent_version=parent_version,
                    child_name=dep_name, child_version="",
                    source=str(lockfile_path), source_location=location,
                    evidence_source=EVIDENCE, scope=scope,
                    qualifiers=qualifiers,
                    resolution_status=("UNPARSEABLE_CONSTRAINT"
                                       if not parseable
                                       else "NO_MATCHING_VERSION")))

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
        prev = (existing.get("qualifiers") or {}).get("markers")
        new = (edge.get("qualifiers") or {}).get("markers")
        if new and new != prev:
            merged = f"{prev} && {new}" if prev else new
            existing.setdefault("qualifiers", {})["markers"] = merged

    edges = sorted(deduped.values(), key=lambda e: (
        e["parent_name"], e["parent_version"], e["child_name"],
        e["confidence"], e.get("child_version") or "",
    ))
    verified = contract.VERIFIED_EDGES_AVAILABLE if any(
        e["confidence"] == contract.VERIFIED for e in edges
    ) else contract.NO_VERIFIED_EDGES
    return contract.extraction_result(
        engine=ENGINE,
        source=str(lockfile_path),
        format_version="uv.lock",
        graph_status=verified,
        edges=edges,
        tallies={"duplicate_records_dropped": duplicate_dropped},
    )
