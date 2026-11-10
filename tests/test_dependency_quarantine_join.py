# -*- coding: utf-8 -*-
"""Task 3 -- heuristic-candidate quarantine + verified-edge integration.

Pins the two approved follow-ups to the Task 2 evidence gate:

  * QUARANTINE: components guessed from the built-in TRANSITIVE_DEPS table
    never enter the canonical SBOM. They are collected separately with
    provenance (source table, parent, reason) and an explicit disclosure,
    and therefore cannot inflate component counts, dependency summaries,
    vulnerability counts or reachability metrics.
  * VERIFIED-EDGE JOIN: parent / introduced_by / dependency_path are
    populated ONLY from VERIFIED package-lock graph edges, matched on
    purl identity (ecosystem/name/version, npm-normalized). Ambiguous
    (multiple distinct parents) or incomplete (no resolved version)
    matches are disclosed, never guessed -- the record keeps whatever
    classification the evidence gate honestly allows.

Offline, pure-unit: no sockets, no benchmark scans.
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.dependency_intelligence import (  # noqa: E402
    enrich_dependency,
    dependency_summary,
    join_verified_edges,
)
from scanner.package_intelligence import build_package_summary  # noqa: E402
from scanner.sbom import (  # noqa: E402
    HEURISTIC_CANDIDATE_DISCLOSURE,
    heuristic_candidate_section,
    finalize_sbom_packages,
    generate_sbom,
)


@pytest.fixture()
def _dark_external_advisory(monkeypatch):
    """Offline: identity the OSV/NVD pass inside finalize (no sockets)."""
    from scanner import sbom as sbom_mod
    monkeypatch.setattr(sbom_mod, "enrich_packages_with_external_vulns",
                        lambda pkgs: list(pkgs))


# ============================================================ QUARANTINE ==
def test_collect_transitive_candidates_returns_canonical_plus_candidates():
    from scanner.sbom import _collect_transitive_candidates

    base = [{"name": "flask", "version": "1.0.2", "ecosystem": "PyPI",
             "license": "MIT", "direct": True,
             "manifest_file": "requirements.txt", "manifest_line": 1}]
    canonical, candidates = _collect_transitive_candidates(base)

    # The canonical list is NOT extended: no guessed component joins it.
    assert [p["name"] for p in canonical] == ["flask"]
    assert len(canonical) == 1
    names = {c["name"] for c in candidates}
    assert names == {"jinja2", "werkzeug", "itsdangerous", "click", "blinker"}


def test_candidates_carry_provenance_and_no_classification_claim():
    from scanner.sbom import _collect_transitive_candidates

    base = [{"name": "django", "version": "4.2", "ecosystem": "PyPI",
             "license": "BSD", "direct": True,
             "manifest_file": "requirements.txt", "manifest_line": 3}]
    _, candidates = _collect_transitive_candidates(base)
    assert [c["name"] for c in candidates] == ["sqlparse"]
    cand = candidates[0]
    assert cand["transitive_guess"] is True
    assert cand["heuristic_source"] == "TRANSITIVE_DEPS_TABLE"
    assert cand["heuristic_parent"] == "django"
    assert "django" in cand["heuristic_reason"] and "sqlparse" in cand["heuristic_reason"]
    # A guess is not a classification: the candidate claims no
    # dependency_type (that word is reserved for evidence-backed records).
    assert "dependency_type" not in cand


def test_finalize_quarantines_candidates_out_of_canonical(_dark_external_advisory):
    buf: list[dict] = []
    out = finalize_sbom_packages(
        [{"name": "flask", "version": "1.0.2", "ecosystem": "PyPI",
          "license": "MIT", "direct": True}], heuristic_candidates=buf)
    assert {p["name"] for p in out} == {"flask"}
    assert {c["name"] for c in buf} == {
        "jinja2", "werkzeug", "itsdangerous", "click", "blinker"}


def test_ingest_path_collects_no_candidates(_dark_external_advisory):
    buf: list[dict] = []
    finalize_sbom_packages(
        [{"name": "flask", "version": "1.0.2", "ecosystem": "PyPI",
          "license": "MIT", "direct": True}],
        add_transitive=False, heuristic_candidates=buf)
    assert buf == []


def test_generate_sbom_end_to_end_quarantine(tmp_path, _dark_external_advisory):
    (tmp_path / "requirements.txt").write_text(
        "flask==1.0.2\nsix==1.16.0\n", encoding="utf-8")
    buf: list[dict] = []
    sbom = generate_sbom(str(tmp_path), heuristic_candidates=buf)
    names = {p["name"] for p in sbom}
    # Only manifest-declared rows are canonical.
    assert names == {"flask", "six"}
    assert {c["name"] for c in buf} == {
        "jinja2", "werkzeug", "itsdangerous", "click", "blinker"}


def test_summaries_see_only_canonical_rows(tmp_path, _dark_external_advisory):
    (tmp_path / "requirements.txt").write_text(
        "flask==1.0.2\nsix==1.16.0\n", encoding="utf-8")
    buf: list[dict] = []
    sbom = generate_sbom(str(tmp_path), heuristic_candidates=buf)
    dep = dependency_summary(sbom)
    pkg = build_package_summary(sbom)
    # 2 direct manifest rows, zero transitives: the 5 guesses live in buf,
    # not in the summaries.
    assert dep["direct_dependencies"] == 2
    assert dep["transitive_dependencies"] == 0
    assert pkg["direct_packages"] == 2
    assert pkg["transitive_packages"] == 0


def test_candidate_section_shape():
    section = heuristic_candidate_section([
        {"name": "jinja2", "transitive_guess": True}])
    assert section["count"] == 1
    assert section["source_engine"] == "TRANSITIVE_DEPS_TABLE_V1"
    assert section["disclosure"] == HEURISTIC_CANDIDATE_DISCLOSURE
    assert len(section["candidates"]) == 1
    assert "TRANSITIVE_DEPS" in HEURISTIC_CANDIDATE_DISCLOSURE


# ====================================================== VERIFIED-EDGE JOIN
def _edge(parent, child, fingerprint="fp-1", source="C:/proj/package-lock.json",
          confidence="VERIFIED"):
    return {"parent": parent, "child": child, "confidence": confidence,
            "fingerprint": fingerprint, "source": source,
            "relationship": "AUTHORITATIVE_NPM_LOCKFILE_DEPENDENCY"}


def _npm(name, version, **over):
    row = {"name": name, "version": version, "ecosystem": "npm",
           "license": "unknown", "direct": False,
           "manifest_file": "package-lock.json", "manifest_line": 1}
    row.update(over)
    return row


def test_join_populates_parent_from_single_verified_edge():
    sbom = [_npm("qs", "6.13.0")]
    edges = [_edge("pkg:npm/express@4.17.3", "pkg:npm/qs@6.13.0")]
    result = join_verified_edges(sbom, edges)
    row = result["sbom"][0]
    assert row["parent"] == "express@4.17.3"
    assert row["introduced_by"] == "express@4.17.3"
    assert row["dependency_path"] == ["express@4.17.3", "qs@6.13.0"]
    assert row["verified_transitive"] is True
    assert row["relationship_source"] == "VERIFIED_NPM_LOCKFILE_EDGE"
    assert row["parent_edge_fingerprint"] == "fp-1"
    # The gate classifies it Transitive through the verified parent.
    assert enrich_dependency(row)["dependency_type"] == "Transitive"
    assert result["summary"]["parented"] == 1


def test_join_ambiguous_parents_disclose_without_guessing():
    sbom = [_npm("lodash", "4.17.21")]
    edges = [
        _edge("pkg:npm/express@4.17.3", "pkg:npm/lodash@4.17.21", "fp-a"),
        _edge("pkg:npm/moment@2.29.4", "pkg:npm/lodash@4.17.21", "fp-b"),
    ]
    result = join_verified_edges(sbom, edges)
    row = result["sbom"][0]
    # Verified transitive, but NO single parent is manufactured.
    assert row["verified_transitive"] is True
    assert "parent" not in row
    assert "introduced_by" not in row
    assert "dependency_path" not in row
    assert row["parent_resolution"] == "ambiguous_multiple_parents"
    assert row["verified_parents"] == ["express", "moment"]
    assert result["summary"]["ambiguous_parents"] == 1
    # The gate accepts the verified marker as evidence (not a guess).
    assert enrich_dependency(row)["dependency_type"] == "Transitive"


def test_join_root_only_edge_does_not_fabricate_a_parent():
    sbom = [_npm("express", "4.17.3", direct=True)]
    edges = [_edge("pkg:npm/__root__", "pkg:npm/express@4.17.3")]
    result = join_verified_edges(sbom, edges)
    row = result["sbom"][0]
    assert "__root__" not in str(row.get("parent") or "")
    assert "parent" not in row
    assert row["verified_root_declared"] is True
    # Direct records keep their manifest introduction; nothing is stamped.
    assert "introduced_by" not in row
    assert result["summary"]["root_declared_only"] == 1


def test_join_root_plus_package_parent_uses_the_package_parent():
    sbom = [_npm("qs", "6.13.0", direct=True)]
    edges = [
        _edge("pkg:npm/__root__", "pkg:npm/qs@6.13.0"),
        _edge("pkg:npm/express@4.17.3", "pkg:npm/qs@6.13.0"),
    ]
    result = join_verified_edges(sbom, edges)
    row = result["sbom"][0]
    # Direct record: manifest introduction is kept, no parent overwrite.
    assert "parent" not in row
    assert result["summary"]["root_declared_only"] == 0


def test_join_incomplete_identity_is_disclosed_not_guessed():
    # Manifest range without a resolved version: identity cannot be matched.
    sbom = [_npm("lodash", "unknown", manifest_file="package.json")]
    edges = [_edge("pkg:npm/express@4.17.3", "pkg:npm/lodash@4.17.21")]
    result = join_verified_edges(sbom, edges)
    row = result["sbom"][0]
    assert "parent" not in row and "verified_transitive" not in row
    # Retains whatever the gate honestly allows (Unknown here: the
    # manifest_file is package.json, a direct manifest, but the record is
    # flagged non-direct with no parent evidence).
    assert enrich_dependency(row)["dependency_type"] == "Unknown"
    assert result["summary"]["skipped_incomplete_identity"] == 1


def test_join_ignores_non_npm_records():
    sbom = [{"name": "flask", "version": "1.0.2", "ecosystem": "PyPI",
             "direct": True}]
    edges = [_edge("pkg:npm/express@4.17.3", "pkg:npm/flask@1.0.2")]
    result = join_verified_edges(sbom, edges)
    assert result["summary"]["skipped_non_npm"] == 1
    assert "parent" not in result["sbom"][0]


def test_join_ignores_unverified_and_malformed_edges():
    sbom = [_npm("qs", "6.13.0")]
    edges = [
        _edge("pkg:npm/express@4.17.3", "pkg:npm/qs@6.13.0",
              confidence="UNRESOLVED"),
        {"parent": "pkg:npm/express@4.17.3", "child": "pkg:npm/qs@6.13.0"},
        "not-a-dict",
        _edge("pkg:npm/express@4.17.3", "pkg:npm/qs"),  # versionless child
    ]
    result = join_verified_edges(sbom, edges)
    row = result["sbom"][0]
    assert "parent" not in row
    assert result["summary"]["matched"] == 0


def test_join_scoped_package_identity():
    sbom = [_npm("@babel/core", "7.0.0")]
    edges = [_edge("pkg:npm/gulp@4.0.2", "pkg:npm/@babel/core@7.0.0")]
    result = join_verified_edges(sbom, edges)
    row = result["sbom"][0]
    assert row["parent"] == "gulp@4.0.2"
    assert row["dependency_path"] == ["gulp@4.0.2", "@babel/core@7.0.0"]


def test_join_name_matching_is_case_insensitive_version_exact():
    sbom = [_npm("QS", "6.13.0")]
    edges = [
        _edge("pkg:npm/express@4.17.3", "pkg:npm/qs@6.13.0"),
        _edge("pkg:npm/express@4.17.3", "pkg:npm/qs@6.12.0"),  # other version
    ]
    result = join_verified_edges(sbom, edges)
    row = result["sbom"][0]
    assert row["parent"] == "express@4.17.3"
    assert result["summary"]["parented"] == 1


def test_join_no_edges_touches_nothing():
    row = _npm("qs", "6.13.0")
    before = dict(row)
    result = join_verified_edges([row], [])
    assert result["sbom"][0] == before
    assert result["summary"]["unmatched"] == 1


def test_join_summary_discloses_limits():
    result = join_verified_edges([], [])
    summary = result["summary"]
    assert summary["engine"] == "VERIFIED_EDGE_JOIN_V1"
    assert "npm" in summary["disclosure"]
    assert "never" in summary["disclosure"] or "Nothing is guessed" in summary["disclosure"]


def test_join_multi_ecosystem_same_name_version_is_npm_only():
    # A PyPI record with the same name/version must NOT absorb npm edges.
    sbom = [_npm("qs", "6.13.0"),
            {"name": "qs", "version": "6.13.0", "ecosystem": "PyPI",
             "direct": False}]
    edges = [_edge("pkg:npm/express@4.17.3", "pkg:npm/qs@6.13.0")]
    result = join_verified_edges(sbom, edges)
    assert result["sbom"][0].get("parent") == "express@4.17.3"
    assert "parent" not in result["sbom"][1]
