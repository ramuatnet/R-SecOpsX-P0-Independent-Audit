"""Poetry verified-edge extractor (R2.1, evidence tier: constraint-resolvable).

Evidence basis (verified on the DVAP corpus, R2.0): poetry.lock's
``[[package]]`` entries carry per-package ``[package.dependencies]``
declarations (name + constraint + markers + optional flag), and the lockfile
itself holds the resolved universe. A declaration that matches exactly one
resolved child version is a VERIFIED edge; multiple matches are AMBIGUOUS
with candidates disclosed; zero matches or constraints this matcher cannot
understand are UNRESOLVED. Membership alone is never an edge.

Markers and extras are environment-conditional declarations, not
relationships to invent or drop: they are recorded verbatim in
``qualifiers`` and the edge keeps its resolution evidence. Package source
(registry/git/url) travels as qualifiers too.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

from analysis.lock_graph import contract
from analysis.lock_graph.contract import norm_pypi
from analysis.lock_graph.versions import satisfies

ENGINE = "POETRY_LOCK_GRAPH_V1"
EVIDENCE = "POETRY_PACKAGE_DEPENDENCIES"


def _source_qualifiers(source) -> dict:
    if not isinstance(source, dict):
        return {}
    qual = {}
    stype = str(source.get("type") or ("git" if source.get("git") else "registry"))
    qual["source_type"] = stype
    for key in ("git", "url", "registry"):
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
            format_version="poetry.lock",
            graph_status=contract.EXTRACTION_ERROR,
            edges=[],
            limitations=[f"poetry.lock parse failed: {exc}"],
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
        deps = pkg.get("dependencies")
        if not isinstance(deps, dict):
            continue
        parent_name = str(pkg.get("name") or "").strip()
        parent_version = str(pkg.get("version") or "").strip()
        source_quals = _source_qualifiers(pkg.get("source"))
        for dep_name_raw, spec in deps.items():
            dep_name = str(dep_name_raw).strip()
            # A spec may be a single declaration or a LIST of alternatives
            # (real poetry.lock shape, e.g. dill's python_version-gated
            # entries). Each alternative is declared evidence; the same
            # resolved identity from alternatives dedupes by fingerprint
            # with markers merged.
            if isinstance(spec, list):
                alternatives = [s for s in spec if isinstance(s, dict)] or \
                    [{"version": "*"}]
            else:
                alternatives = [spec]
            for alt in alternatives:
                if isinstance(alt, dict):
                    constraint = str(alt.get("version") or "*")
                    markers = alt.get("markers")
                    optional = bool(alt.get("optional"))
                    extras = alt.get("extras")
                else:
                    constraint = str(alt or "*")
                    markers = None
                    optional = False
                    extras = None

                qualifiers: dict = dict(source_quals)
                if markers:
                    qualifiers["markers"] = str(markers)
                if extras:
                    qualifiers["extras"] = \
                        "[" + ",".join(str(e) for e in extras) + "]"
                scope = "optional" if optional else "runtime"

                location = (f"[[package] {parent_name}@{parent_version}] "
                            f"[package.dependencies] {dep_name}")
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

                matched = [v for v in candidates if satisfies(v, constraint)]
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
                        ambiguity={"constraint": constraint,
                                   "candidates": sorted(matched)},
                        resolution_status="MULTIPLE_CANDIDATES"))
                else:
                    parseable = satisfies("1.0", constraint) is not None
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

    # Alternative declarations of the same resolved identity dedupe by
    # identity+confidence; markers merge so no declaration evidence is lost.
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
        format_version="poetry.lock",
        graph_status=verified,
        edges=edges,
        tallies={"duplicate_records_dropped": duplicate_dropped},
    )
