"""npm adapter: maps the proven npm engine into the common contract (R2.1).

The engine (`analysis/npm_lock_graph_v2.py`) is NOT modified -- this adapter
wraps it and ENRICHES each parseable edge with the common-schema fields.
Original engine fields (parent/child raw ids, confidence, fingerprint,
source, requested_spec, ...) survive untouched, so every existing consumer
keeps its exact behavior and the Task 6 NodeGoat byte-stability gate holds.

Enrichment is strictly additive and partial-safe:
- registry endpoints that parse to name@version get
  ecosystem/parent_name/parent_version/child_name/child_version/purl fields;
- the synthetic root and workspace/file endpoints do NOT get parent_name /
  child-side fields when unparseable, so the join's fallback purl parsing
  (and root handling) keeps working exactly as before.
"""

from __future__ import annotations

from analysis.npm_lock_graph_v2 import extract_verified_edges as _engine
from scanner.purl import purl as _purl


def _parse_npm_id(node_id) -> tuple[str, str]:
    """``pkg:npm/<name>[@<ver>]`` -> ``(name, ver)``; ("", "") otherwise."""
    text = str(node_id or "").strip()
    if not text.startswith("pkg:npm/"):
        return "", ""
    rest = text[len("pkg:npm/"):]
    if rest == "__root__":
        return "__root__", ""
    name, sep, version = rest.rpartition("@")
    if not sep or not name:
        return "", ""
    return name, version


def extract(lockfile_path: str) -> dict:
    result = _engine(str(lockfile_path))
    for edge in result.get("edges", []) or []:
        if not isinstance(edge, dict) or "ecosystem" in edge:
            continue
        edge["ecosystem"] = "npm"
        edge["evidence_source"] = "NPM_LOCKFILE_DEPENDENCIES"
        edge.setdefault("scope", "runtime")
        edge.setdefault("qualifiers", {})
        child_name, child_version = _parse_npm_id(edge.get("child"))
        if child_name and child_version and child_name != "__root__":
            edge["child_name"] = child_name
            edge["child_version"] = child_version
            edge["child_purl"] = (
                _purl(child_name, child_version, "npm") or "")
        parent_name, parent_version = _parse_npm_id(edge.get("parent"))
        if (parent_name and parent_version
                and parent_name != "__root__"):
            edge["parent_name"] = parent_name
            edge["parent_version"] = parent_version
            edge["parent_purl"] = (
                _purl(parent_name, parent_version, "npm") or "")
        source_location = ""
        parent_path = str(edge.get("parent_lockfile_path") or "")
        child_path = str(edge.get("child_lockfile_path") or "")
        if parent_path or child_path:
            source_location = f"{parent_path} -> {child_path}".strip(" ->")
        if source_location:
            edge["source_location"] = source_location
    return result
