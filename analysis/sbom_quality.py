"""SBOM quality scoring - sbomqs-style, offline-honest.

    from analysis.sbom_quality import score_sbom
    quality = score_sbom(packages, doc=ingest_doc)

WHAT IT IS
----------
A 0-100 quality score over the same internal package shape the rest of
the pipeline uses, built from factors that can be computed OFFLINE from
the document itself: the NTIA minimum elements, licence quality, strict
version pinning, dependency-graph depth/coverage, hash integrity, and
(factoring in the enrichment result) known-vulnerability share.

WHAT IT DELIBERATELY IS NOT
---------------------------
Several sbomqs factors cannot be honestly computed from a document
alone and are listed as not_covered rather than guessed:

    software_widely_adoption   needs a registry/telemetry signal
    up_to_date_version         needs a registry "latest" signal
    annotated_tags             needs project-specific annotation policy
    absolute_path              source-path provenance, not in most SBOMs
    ntia_data_fidelity         purchase/ownership evidence - not
                               derivable from the document

The known-vulnerability factor is computed only when the advisory query
actually completed for this inventory (callers pass
`advisory_checked`; the enrichment sets `vulnerabilities` only on
packages WITH advisories, so key presence alone cannot prove the query
ran); otherwise the factor is excluded and the exclusion is disclosed
(`factors_excluded` + `scored_factors`/`total_factors`).

The score is earned/computable-max normalised to 100, so an SBOM scored
without the vuln factor is comparable but flagged: read
`scored_factors`/`total_factors` before quoting the number.
"""
from __future__ import annotations

import re
from typing import Any

# Versions that are NOT strict pins: ranges, wildcards, empty, unknown.
_RANGE_CHARS = re.compile(r"[\^~,\s*]|(>=|<=|!=|\|\||x|X)")
_SEMVERISH = re.compile(r"^[vV]?\d[\w.+-]*$")


def _is_pinned(version: Any) -> bool:
    s = str(version or "").strip()
    if not s or s.lower() in ("unknown", "latest", "*"):
        return False
    if _RANGE_CHARS.search(s):
        return False
    return bool(_SEMVERISH.match(s))


def _is_real_version(version: Any) -> bool:
    s = str(version or "").strip()
    return bool(s) and s.lower() not in ("unknown", "*", "latest")


def _has_identifier(pkg: dict) -> bool:
    return bool(str(pkg.get("purl") or "").strip()
                or str(pkg.get("cpe") or "").strip()
                or str(pkg.get("sbom_ref") or "").strip())


def _has_license(pkg: dict) -> bool:
    s = str(pkg.get("license") or "").strip()
    return bool(s) and s.lower() not in ("unknown", "noassertion", "none")


def _has_hash(pkg: dict) -> bool:
    return bool(pkg.get("hashes"))


def _graph_node_names(dependency_edges) -> set[str] | None:
    """Best-effort node extraction from any dependency-edge list shape."""
    names: set[str] = set()
    seen_edge = False
    for edge in dependency_edges or []:
        if not isinstance(edge, dict):
            continue
        seen_edge = True
        for key in ("ref", "from", "to", "name", "source", "target"):
            value = edge.get(key)
            if isinstance(value, str) and value:
                names.add(value)
        depends = edge.get("depends_on") or edge.get("dependencies") or []
        if isinstance(depends, list):
            for item in depends:
                if isinstance(item, str) and item:
                    names.add(item)
                elif isinstance(item, dict) and item.get("name"):
                    names.add(str(item["name"]))
    if not seen_edge:
        return None
    return names


def _factor(name: str, weight: float, earned_units: float, total_units: float,
            detail: str) -> dict:
    total_units = max(total_units, 1)
    earned = weight * min(max(earned_units / total_units, 0.0), 1.0)
    return {
        "name": name,
        "weight": weight,
        "earned": round(earned, 2),
        "max": weight,
        "coverage": round(earned_units / total_units, 4),
        "detail": detail,
    }


def score_sbom(packages: list[dict],
               doc: dict | None = None,
               dependency_edges: list | None = None,
               generated_at: str | None = None,
               tools: list | None = None,
               advisory_checked: bool | None = None) -> dict:
    """Score an inventory. Returns the quality report dict.

    doc                the ingest document from scanner.sbom_reader (or None
                       in scan mode, where generated_at/tools/edges come
                       from the run itself)
    dependency_edges   graph edges when not taken from doc
    generated_at/tools scan-mode equivalents of doc metadata
    advisory_checked   whether the advisory query (OSV) actually completed
                       for this inventory. None = auto-detect by key
                       presence, which only works when every package
                       carries a `vulnerabilities` key. Callers that know
                       (main.py reads advisory_service_status()) should
                       pass the boolean: enrichment sets the key only on
                       packages WITH advisories, so key-presence detection
                       misreads a fully-enriched but mostly-clean
                       inventory as unchecked.
    """
    packages = [p for p in (packages or []) if str(p.get("name") or "").strip()]
    n = len(packages)

    doc = doc or {}
    created = str(doc.get("created") or generated_at or "")
    doc_tools = list(doc.get("tools") or tools or [])
    if dependency_edges is None:
        dependency_edges = doc.get("dependencies") or []

    factors: list[dict] = []
    excluded: list[dict] = []

    if n == 0:
        return {
            "score": 0.0,
            "grade": "F",
            "component_count": 0,
            "factors": [],
            "factors_excluded": [],
            "scored_factors": 0,
            "total_factors": 0,
            "note": "no components to score",
        }

    # --- NTIA minimum elements (6 of 7 computable; data fidelity is not)
    with_id = sum(1 for p in packages if _has_identifier(p))
    factors.append(_factor(
        "ntia_unique_identifier", 8, with_id, n,
        "%d/%d components carry a purl, CPE or sbom-ref" % (with_id, n)))

    with_version = sum(1 for p in packages if _is_real_version(p.get("version")))
    factors.append(_factor(
        "ntia_version", 6, with_version, n,
        "%d/%d components have a resolvable version" % (with_version, n)))

    with_supplier = sum(1 for p in packages if str(p.get("supplier") or "").strip())
    factors.append(_factor(
        "ntia_supplier", 6, with_supplier, n,
        "%d/%d components name a supplier/author" % (with_supplier, n)))

    node_names = _graph_node_names(dependency_edges)
    if node_names is None:
        factors.append(_factor(
            "ntia_dependency_relationship", 8, 0, 1,
            "no dependency relationships declared"))
    elif not node_names:
        # a graph exists but no node names were extractable from the shape
        # at hand: credit existence, not coverage, and say so.
        factors.append(_factor(
            "ntia_dependency_relationship", 8, 0.5, 1,
            "dependency relationships present (coverage not measurable "
            "from this edge shape)"))
    else:
        referenced = sum(1 for p in packages
                         if p.get("name") in node_names
                         or p.get("sbom_ref") in node_names)
        factors.append(_factor(
            "ntia_dependency_relationship", 8, referenced, n,
            "%d/%d components appear in the dependency graph"
            % (referenced, n)))

    factors.append(_factor(
        "ntia_timestamp", 4, 1 if created else 0, 1,
        "document timestamp: %s" % (created or "absent")))

    factors.append(_factor(
        "ntia_author", 3, 1 if doc_tools else 0, 1,
        "generator tools: %s" % (", ".join(doc_tools) if doc_tools else "absent")))

    # --- quality factors
    with_license = sum(1 for p in packages if _has_license(p))
    factors.append(_factor(
        "license_quality", 15, with_license, n,
        "%d/%d components declare a licence" % (with_license, n)))

    pinned = sum(1 for p in packages if _is_pinned(p.get("version")))
    factors.append(_factor(
        "strict_pinning", 15, pinned, n,
        "%d/%d versions are strict pins" % (pinned, n)))

    with_hash = sum(1 for p in packages if _has_hash(p))
    factors.append(_factor(
        "hash_integrity", 10, with_hash, n,
        "%d/%d components carry hashes" % (with_hash, n)))

    # --- known-vulnerability share: only honest when the advisory query
    # completed. Missing `vulnerabilities` keys count as "no known
    # advisories" (that is what the key means elsewhere: .get(...) or []),
    # but only when the query is known to have run at all.
    if advisory_checked is None:
        advisory_checked = all("vulnerabilities" in p for p in packages)
    if advisory_checked:
        clean = sum(1 for p in packages if not (p.get("vulnerabilities") or []))
        factors.append(_factor(
            "known_vulnerabilities", 15, clean, n,
            "%d/%d components have no known advisories (OSV-enriched)"
            % (clean, n)))
    else:
        excluded.append({
            "name": "known_vulnerabilities",
            "reason": "the advisory lookup did not complete for this "
                      "inventory; a vulnerability count would be a guess",
        })

    scored_max = sum(f["max"] for f in factors)
    earned = sum(f["earned"] for f in factors)
    score = round((earned / scored_max) * 100, 1) if scored_max else 0.0

    if score >= 90:
        grade = "A"
    elif score >= 80:
        grade = "B"
    elif score >= 70:
        grade = "C"
    elif score >= 60:
        grade = "D"
    else:
        grade = "F"

    return {
        "score": score,
        "grade": grade,
        "component_count": n,
        "factors": factors,
        "factors_excluded": excluded,
        "scored_factors": len(factors),
        "total_factors": len(factors) + len(excluded),
        "not_covered": [
            "sbomqs: software_widely_adopted (needs a registry signal)",
            "sbomqs: up_to_date_version (needs a registry 'latest' signal)",
            "sbomqs: annotated_tags (needs project annotation policy)",
            "sbomqs: absolute_path (source-path provenance, absent from "
            "most SBOMs)",
            "ntia: data_fidelity (purchase/ownership evidence is not "
            "derivable from the document)",
        ],
    }
