"""
R-SecOpsX V10
Dependency Graph V2 â€” Authoritative Relationship Engine

Design rule:
  Only AUTHORITATIVE relationship evidence can produce a verified edge.

Inference such as:
  parent
  introduced_by
  dependency_path
  dependency_type

must never be promoted to a verified dependency edge by this module.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any, Dict, Iterable, List, Optional
import hashlib


ENGINE_VERSION = "DEPENDENCY_GRAPH_V2.0"

VERIFIED = "VERIFIED"
UNVERIFIED = "UNVERIFIED"
INFERRED = "INFERRED"
UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class DependencyEdge:
    parent: str
    child: str
    source: str
    relationship: str
    evidence: str
    confidence: str = VERIFIED

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _clean(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _canonical_name(value: Any) -> str:
    return _clean(value).lower()


def canonical_component_id(
    name: Any,
    version: Any = "",
    ecosystem: Any = "",
    purl: Any = "",
) -> str:
    """
    Prefer PURL when authoritative.

    Otherwise use a deterministic ecosystem:name@version identity.
    """
    purl_value = _clean(purl)
    if purl_value:
        return purl_value

    eco = _canonical_name(ecosystem) or "unknown"
    pkg = _canonical_name(name) or "unknown"
    ver = _clean(version) or "unknown"

    return f"{eco}:{pkg}@{ver}"


def edge_fingerprint(parent: str, child: str, source: str) -> str:
    raw = f"{parent}|{child}|{source}".encode("utf-8", errors="ignore")
    return hashlib.sha256(raw).hexdigest()[:24]


def _extract_name(val) -> str:
    """
    Extracts a valid package name from a string or structured dictionary entry.

    Rejects malformed component identities (bool, int, list, None, empty/invalid dicts)
    by returning an empty string.
    """
    # Reject booleans explicitly.
    if isinstance(val, bool):
        return ""

    # Direct valid string case.
    if isinstance(val, str):
        return val.strip()

    # Structured entry handling.
    if isinstance(val, dict):
        for key in ("name", "package", "component", "id", "Id"):
            candidate = val.get(key)

            # Structured identity must itself be a string.
            if isinstance(candidate, str):
                cleaned = candidate.strip()

                if cleaned:
                    return cleaned

        return ""

    # Reject numbers, lists, tuples, None, and other arbitrary types.
    return ""


def _authoritative_dependency_entries(
    package: Dict[str, Any],
) -> Iterable[Any]:
    """
    Extract only fields that represent an explicit dependency declaration.

    This function intentionally does NOT inspect:
      parent
      introduced_by
      dependency_path
      dependency_chain
    """
    for key in (
        "dependencies",
        "requires",
        "resolved_dependencies",
        "resolvedDependencies",
    ):
        value = package.get(key)

        if isinstance(value, dict):
            yield from value.items()

        elif isinstance(value, list):
            yield from value


def build_verified_edges(
    packages: List[Dict[str, Any]],
    source: str,
) -> Dict[str, Any]:
    """
    Build verified dependency edges from authoritative package relationship
    records supplied by the caller.

    The caller must provide authoritative relationship data.
    This engine never infers parent-child relationships from transitive flags.
    """

    edges: List[DependencyEdge] = []
    rejected_inference_count = 0

    package_index: Dict[str, Dict[str, Any]] = {}

    for package in packages or []:
        if not isinstance(package, dict):
            continue

        identity = canonical_component_id(
            package.get("name"),
            package.get("version"),
            package.get("ecosystem"),
            package.get("purl") or package.get("PURL"),
        )

        package_index[identity] = package

    seen = set()

    for package in packages or []:
        if not isinstance(package, dict):
            continue

        parent_id = canonical_component_id(
            package.get("name"),
            package.get("version"),
            package.get("ecosystem"),
            package.get("purl") or package.get("PURL"),
        )

        entries = list(_authoritative_dependency_entries(package))

        for entry in entries:
            child_value = entry[0] if isinstance(entry, tuple) else entry
            tuple_child_version = ""
            if isinstance(entry, tuple) and len(entry) > 1:
                # A tuple selector is authoritative only when its selector
                # value is actually a string. Do not coerce malformed values
                # such as integers, lists, dicts, or booleans into versions.
                tuple_selector_raw = entry[1]

                if not isinstance(tuple_selector_raw, str):
                    continue

                tuple_selector = _clean(tuple_selector_raw)

                if tuple_selector:
                    normalized_selector = tuple_selector.lstrip("=v").strip()
                    if (
                        normalized_selector
                        and normalized_selector[0].isdigit()
                        and all(
                            part.isdigit()
                            for part in normalized_selector.split(".")
                            if part
                        )
                    ):
                        tuple_child_version = normalized_selector

            child_name = _extract_name(child_value)

            if not child_name:
                continue

            child_version = tuple_child_version
            child_purl = ""

            if isinstance(child_value, dict):
                child_version = _clean(
                    child_value.get("version")
                    or child_value.get("resolved_version")
                )
                child_purl = _clean(
                    child_value.get("purl")
                    or child_value.get("PURL")
                )
            elif isinstance(child_value, str):
                # Preserve an explicitly declared concrete version.
                # Do not resolve registry ranges or selectors here.
                selector = _clean(child_value)
                if selector and (
                    selector[0].isdigit()
                    or selector[0] in ("v", "=")
                ):
                    normalized_selector = selector.lstrip("=v").strip()
                    if normalized_selector and all(
                        part.isdigit()
                        for part in normalized_selector.split(".")
                        if part
                    ):
                        child_version = normalized_selector

            child_id = canonical_component_id(
                child_name,
                child_version,
                package.get("ecosystem"),
                child_purl,
            )

            fingerprint = edge_fingerprint(parent_id, child_id, source)

            if fingerprint in seen:
                continue

            seen.add(fingerprint)

            edges.append(
                DependencyEdge(
                    parent=parent_id,
                    child=child_id,
                    source=source,
                    relationship="AUTHORITATIVE_DEPENDENCY_DECLARATION",
                    evidence="explicit dependency relationship field",
                    confidence=VERIFIED,
                )
            )

    # Existing inferred metadata is explicitly counted but never converted
    # into graph edges.
    for package in packages or []:
        if not isinstance(package, dict):
            continue

        if any(
            package.get(key)
            for key in (
                "parent",
                "parent_package",
                "introduced_by",
                "dependency_path",
                "dependency_chain",
            )
        ):
            rejected_inference_count += 1

    return {
        "engine": ENGINE_VERSION,
        "graph_status": (
            "VERIFIED_EDGES_AVAILABLE"
            if edges
            else "NO_VERIFIED_EDGES"
        ),
        "verified_edge_count": len(edges),
        "rejected_inference_count": rejected_inference_count,
        "edges": [edge.as_dict() for edge in edges],
        "evidence_policy": (
            "AUTHORITATIVE_RELATIONSHIP_FIELDS_ONLY"
        ),
    }


def validate_graph(graph: Dict[str, Any]) -> Dict[str, Any]:
    """
    Deterministic structural validation.
    """

    errors: List[str] = []
    edges = graph.get("edges", [])

    if not isinstance(edges, list):
        errors.append("edges must be a list")
        edges = []

    seen = set()

    for index, edge in enumerate(edges):
        if not isinstance(edge, dict):
            errors.append(f"edge[{index}] is not an object")
            continue

        parent = _clean(edge.get("parent"))
        child = _clean(edge.get("child"))
        confidence = _clean(edge.get("confidence"))

        if not parent:
            errors.append(f"edge[{index}] missing parent")

        if not child:
            errors.append(f"edge[{index}] missing child")

        if confidence != VERIFIED:
            errors.append(
                f"edge[{index}] is not VERIFIED"
            )

        key = (parent, child)

        if key in seen:
            errors.append(
                f"duplicate edge: {parent} -> {child}"
            )

        seen.add(key)

    reported_count = graph.get("verified_edge_count", 0)

    if reported_count != len(edges):
        errors.append(
            "verified_edge_count does not match edges length"
        )

    return {
        "valid": not errors,
        "error_count": len(errors),
        "errors": errors,
        "verified_edge_count": len(edges),
    }


def smoke_test() -> Dict[str, Any]:
    """
    Verify the most important invariant:

    explicit relationship => VERIFIED edge

    inferred parent/path => never becomes an edge.
    """

    packages = [
        {
            "name": "express",
            "version": "5.1.0",
            "ecosystem": "npm",
            "dependencies": [
                {
                    "name": "qs",
                    "version": "6.14.0",
                }
            ],
        },
        {
            "name": "qs",
            "version": "6.14.0",
            "ecosystem": "npm",
        },
        {
            "name": "fake-transitive",
            "version": "1.0.0",
            "ecosystem": "npm",
            "parent": "express",
            "dependency_path": [
                "express",
                "fake-transitive",
            ],
        },
    ]

    graph = build_verified_edges(
        packages,
        source="package-lock.json",
    )

    validation = validate_graph(graph)

    assert validation["valid"]
    assert graph["verified_edge_count"] == 1

    edge = graph["edges"][0]

    assert edge["confidence"] == VERIFIED
    assert edge["parent"] == "npm:express@5.1.0"
    assert edge["child"] == "npm:qs@6.14.0"

    assert not any(
        edge["child"] == "npm:fake-transitive@1.0.0"
        for edge in graph["edges"]
    )

    return {
        "status": "DEPENDENCY_GRAPH_V2_SMOKE_PASS",
        "verified_edges": graph["verified_edge_count"],
        "rejected_inferences": graph["rejected_inference_count"],
        "graph_status": graph["graph_status"],
    }


if __name__ == "__main__":
    print(smoke_test())
