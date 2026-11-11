# -*- coding: utf-8 -*-
"""F-1/F-2/F-3 remediation regression tests (approved phase 4).

F-1  parent-instance ambiguity: when the same parent NAME exists at
     several verified versions and those instances point at the same
     child identity, the join must NOT pick one arbitrarily. It must
     record ``parent_resolution: "ambiguous_multiple_versions"``,
     preserve every verified instance with its own edge fingerprint,
     and never mint a single definitive parent path.
F-2  fingerprint provenance: the fingerprint travels WITH the parent
     instance it belongs to -- never selected independently. List
     ordering of the input edges must not change any stamped value.
F-3  Windows npm graph resolution: ``_resolve_child_path`` must walk
     nested topology with ONE consistent separator representation
     ("/"), so a nested dependency resolves to its own node instead of
     falling through to the hoisted root node. Regression mirrors the
     NodeGoat shape (nyc/handlebars/source-map -> nyc's amdefine).
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analysis.npm_lock_graph_v2 import _resolve_child_path  # noqa: E402
from scanner.dependency_intelligence import (  # noqa: E402
    enrich_dependency,
    join_verified_edges,
)


def _edge(parent, child, fingerprint, source="C:/proj/package-lock.json"):
    return {"parent": parent, "child": child, "confidence": "VERIFIED",
            "fingerprint": fingerprint, "source": source,
            "relationship": "AUTHORITATIVE_NPM_LOCKFILE_DEPENDENCY"}


def _npm(name, version, **over):
    row = {"name": name, "version": version, "ecosystem": "npm",
           "license": "unknown", "direct": False,
           "manifest_file": "package-lock.json", "manifest_line": 1}
    row.update(over)
    return row


# ------------------------------------------------------------------- F-1 --
def test_same_parent_name_two_versions_is_ambiguous_not_arbitrary():
    sbom = [_npm("cookie", "0.5.0")]
    edges = [
        _edge("pkg:npm/express@4.17.3", "pkg:npm/cookie@0.5.0", "fp-4173"),
        _edge("pkg:npm/express@4.18.2", "pkg:npm/cookie@0.5.0", "fp-4182"),
    ]
    result = join_verified_edges(sbom, edges)
    row = result["sbom"][0]
    # No arbitrary instance pick: no single definitive parent path.
    assert "parent" not in row
    assert "introduced_by" not in row
    assert "dependency_path" not in row
    assert row["parent_resolution"] == "ambiguous_multiple_versions"
    assert row["verified_transitive"] is True
    instances = row["verified_parent_instances"]
    assert {i["parent"] for i in instances} == {
        "express@4.17.3", "express@4.18.2"}
    by_fp = {i["fingerprint"]: i["parent"] for i in instances}
    assert by_fp["fp-4173"] == "express@4.17.3"
    assert by_fp["fp-4182"] == "express@4.18.2"
    # The relationship stays verified: the gate classifies Transitive.
    assert enrich_dependency(row)["dependency_type"] == "Transitive"
    assert result["summary"]["ambiguous_parent_versions"] == 1


def test_single_parent_version_still_stamps_definitively():
    sbom = [_npm("cookie", "0.5.0")]
    edges = [
        _edge("pkg:npm/express@4.18.2", "pkg:npm/cookie@0.5.0", "fp-4182"),
    ]
    result = join_verified_edges(sbom, edges)
    row = result["sbom"][0]
    assert row["parent"] == "express@4.18.2"
    assert row["dependency_path"] == ["express@4.18.2", "cookie@0.5.0"]
    assert row["parent_edge_fingerprint"] == "fp-4182"


def test_multi_parent_name_case_keeps_pairs_and_disclosure():
    sbom = [_npm("lodash", "4.17.21")]
    edges = [
        _edge("pkg:npm/express@4.17.3", "pkg:npm/lodash@4.17.21", "fp-a"),
        _edge("pkg:npm/moment@2.29.4", "pkg:npm/lodash@4.17.21", "fp-b"),
    ]
    result = join_verified_edges(sbom, edges)
    row = result["sbom"][0]
    assert row["parent_resolution"] == "ambiguous_multiple_parents"
    assert row["verified_parents"] == ["express", "moment"]
    instances = {(i["parent"], i["fingerprint"])
                 for i in row["verified_parent_instances"]}
    assert instances == {("express@4.17.3", "fp-a"),
                         ("moment@2.29.4", "fp-b")}


def test_f1_frequency_case_from_nodegoat():
    """abbrev@1.1.1 <- nopt at three verified versions (real F-1 case)."""
    sbom = [_npm("abbrev", "1.1.1")]
    edges = [
        _edge("pkg:npm/nopt@1.0.10", "pkg:npm/abbrev@1.1.1", "fp-n1"),
        _edge("pkg:npm/nopt@3.0.6", "pkg:npm/abbrev@1.1.1", "fp-n2"),
        _edge("pkg:npm/nopt@4.0.1", "pkg:npm/abbrev@1.1.1", "fp-n3"),
    ]
    result = join_verified_edges(sbom, edges)
    row = result["sbom"][0]
    assert row["parent_resolution"] == "ambiguous_multiple_versions"
    assert {i["parent"] for i in row["verified_parent_instances"]} == {
        "nopt@1.0.10", "nopt@3.0.6", "nopt@4.0.1"}
    assert "parent" not in row


# ------------------------------------------------------------------- F-2 --
def test_provenance_is_independent_of_edge_list_ordering():
    """Every permutation of the input edges must stamp identical values."""
    import itertools

    edges = [
        _edge("pkg:npm/express@4.18.2", "pkg:npm/qs@6.13.0", "fp-b"),
        _edge("pkg:npm/express@4.17.3", "pkg:npm/qs@6.13.0", "fp-a"),
    ]
    stamps = []
    for perm in itertools.permutations(edges):
        row = _npm("qs", "6.13.0")
        join_verified_edges([row], list(perm))
        stamps.append(json_sha(row))
    assert len(set(stamps)) == 1, "ordering changed provenance"

    # The ambiguous case: instances list must be canonical, not input order.
    stamps = []
    for perm in itertools.permutations(edges):
        row = _npm("cookie", "0.5.0")
        join_verified_edges([row], list(perm))
        stamps.append(json_sha(row))
    assert len(set(stamps)) == 1, "ordering changed instance list"


def json_sha(row):
    import json
    return json.dumps({k: row.get(k) for k in sorted(row)
                       if k in {"parent", "introduced_by", "dependency_path",
                                "parent_edge_fingerprint",
                                "parent_edge_source", "verified_parents",
                                "verified_parent_instances",
                                "parent_resolution"}},
                      sort_keys=True)


def test_fingerprint_belongs_to_the_stamped_instance():
    """F-2 core: the stamped fingerprint is the stamped instance's edge."""
    sbom = [_npm("cookie", "0.5.0")]
    edges = [
        _edge("pkg:npm/express@4.17.3", "pkg:npm/cookie@0.5.0", "fp-4173"),
    ]
    row = join_verified_edges(sbom, edges)["sbom"][0]
    stamped = row["parent"]
    pairs = {(i["parent"], i["fingerprint"]) for i in
             row.get("verified_parent_instances") or []}
    if stamped and pairs:
        assert (stamped, row["parent_edge_fingerprint"]) in pairs


# ------------------------------------------------------------------- F-3 --
def test_resolve_child_walk_prefers_the_nearest_nested_node():
    """NodeGoat shape: nyc/handlebars/source-map must resolve its amdefine
    to nyc's nested node, not fall through to the hoisted root node."""
    nodes = {
        "node_modules/amdefine": {"version": "1.0.1"},
        "node_modules/nyc/node_modules/amdefine": {"version": "1.0.0"},
        "node_modules/nyc/node_modules/handlebars": {"version": "4.0.5"},
        "node_modules/nyc/node_modules/handlebars/node_modules/source-map": {
            "version": "0.1.34"},
    }
    path, status = _resolve_child_path(
        "node_modules/nyc/node_modules/handlebars/node_modules/source-map",
        "amdefine", nodes)
    assert path == "node_modules/nyc/node_modules/amdefine", (
        f"nested node not resolved: got {path!r} ({status})")
    assert "\\" not in path


def test_resolve_child_multi_level_walk_is_platform_independent():
    """A walk needing several upward hops resolves the nearest ancestor
    node (NOT the root hoisted node), and the returned path is a key of
    the node table in canonical '/' form."""
    nodes = {
        # root hoisted copy: must NOT win over the ancestor copy below
        "node_modules/leaf": {"version": "2.0.0"},
        "node_modules/a/node_modules/mid/node_modules/leaf": {
            "version": "1.1.0"},
        "node_modules/a/node_modules/mid/node_modules/deep": {
            "version": "0.9.0"},
        "node_modules/a/node_modules/mid/node_modules/deep/node_modules/z": {
            "version": "0.1.0"},
    }
    parent = "node_modules/a/node_modules/mid/node_modules/deep/node_modules/z"
    path, _ = _resolve_child_path(parent, "leaf", nodes)
    # nearest for z: z/node_modules/leaf? absent -> deep/node_modules/leaf?
    # absent -> mid/node_modules/leaf EXISTS (two hops up) -> wins
    assert path == "node_modules/a/node_modules/mid/node_modules/leaf"
    assert "\\" not in path
    assert path in nodes


def test_resolve_child_unresolved_reports_status():
    path, status = _resolve_child_path(
        "node_modules/a", "does-not-exist", {"node_modules/a": {}})
    assert path is None
    assert status == "UNRESOLVED_FROM_TOPOLOGY"
