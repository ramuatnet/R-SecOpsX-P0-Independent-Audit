# -*- coding: utf-8 -*-
"""Task 2 -- dependency classification evidence gate (RC-2 / RC-3 / RC-5).

Pins the contract that replaced flag-only classification:

  * ``direct=False`` alone is NOT transitive evidence -- without a named
    parent, a real path head, or authoritative lockfile membership the
    record is honestly Unknown;
  * no layer synthesizes a parent: the "Unknown parent dependency"
    placeholder and the [manifest, "transitive", name] hop are gone, and
    older payloads that still carry them degrade to honest classes;
  * lockfile-parsed rows are tree members (Transitive) that never invent
    a parent; poetry.lock / Pipfile.lock rows stop fabricating Direct;
  * both summaries (dependency_summary / sbom_summary) read the same
    classification rule and agree on the same payload;
  * finalize's stamp uses the same gate as the enrich layer.

Offline, pure-unit: no network, no benchmark scans, no full SBOM runs.
"""
from __future__ import annotations

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.dependency_intelligence import (  # noqa: E402
    UNKNOWN_PARENT,
    dependency_summary,
    enrich_dependency,
    enrich_dependency_intelligence,
    infer_dependency_depth,
    infer_dependency_path,
    infer_dependency_type,
    infer_introduced_by,
)
from scanner.manifests.poetry_lock import (  # noqa: E402
    parse_pipfile_lock,
    parse_poetry_lock,
)
from scanner.manifests.pyproject_toml import parse_pyproject_toml  # noqa: E402
from scanner.package_intelligence import (  # noqa: E402
    build_package_summary,
    dependency_path as pkg_dependency_path,
)


def _pkg(**over):
    base = {"name": "lodash", "version": "4.17.21", "ecosystem": "npm",
            "license": "unknown"}
    base.update(over)
    return base


# ------------------------------------------------------- classification --
def test_direct_flag_classifies_direct_without_fabrication():
    row = _pkg(direct=True, manifest_file="package.json")
    enriched = enrich_dependency(row)
    assert enriched["dependency_type"] == "Direct"
    assert enriched["is_direct"] is True and enriched["is_transitive"] is False
    assert enriched["dependency_path"] == ["lodash@4.17.21"]
    assert enriched["introduced_by"] == "package.json"
    assert enriched["dependency_depth"] == 1


def test_parented_transitive_keeps_the_named_parent():
    row = _pkg(name="qs", version="6.13.0", direct=False,
               parent="express@4.17.3")
    enriched = enrich_dependency(row)
    assert enriched["dependency_type"] == "Transitive"
    assert enriched["dependency_path"] == ["express@4.17.3", "qs@6.13.0"]
    assert enriched["introduced_by"] == "express@4.17.3"
    assert enriched["dependency_depth"] == 2
    assert enriched["is_transitive"] is True


def test_bare_direct_false_is_unknown_not_transitive():
    """RC-2: the flag alone is not a verified parent-child relationship."""
    enriched = enrich_dependency(_pkg(direct=False))
    assert enriched["dependency_type"] == "Unknown"
    assert enriched["is_transitive"] is False
    assert enriched["dependency_path"] == ["lodash@4.17.21"]
    assert enriched["introduced_by"] == ""
    assert enriched["dependency_depth"] == 0


def test_is_transitive_flag_alone_is_not_evidence():
    assert infer_dependency_type(_pkg(is_transitive=True)) == "Unknown"


def test_transitive_guess_is_not_evidence():
    """The _add_transitive row shape: a self-confessed guess is re-inferred
    to Unknown by the classification layer (the producer change itself is
    deferred Task 2 follow-up; the gate refuses to repeat the claim)."""
    row = _pkg(name="jinja2", version="unknown", direct=False,
               transitive_guess=True, dependency_type="Transitive",
               manifest_file="requirements.txt")
    enriched = enrich_dependency(row)
    assert enriched["dependency_type"] == "Unknown"
    assert enriched["is_transitive"] is False


def test_lockfile_membership_is_transitive_without_inventing_a_parent():
    enriched = enrich_dependency(
        _pkg(direct=False, manifest_file="C:/proj/package-lock.json"))
    assert enriched["dependency_type"] == "Transitive"
    # Membership evidence names no parent: nothing may be invented.
    assert enriched["introduced_by"] == ""
    assert enriched["dependency_path"] == ["lodash@4.17.21"]
    assert enriched["dependency_depth"] == 0


def test_manifest_filename_alone_classifies_only_by_lockfile_kind():
    # direct absent: the manifest filename is the only signal
    assert infer_dependency_type(
        _pkg(manifest_file="yarn.lock")) == "Transitive"
    assert infer_dependency_type(
        _pkg(manifest_file="requirements.txt")) == "Direct"
    assert infer_dependency_type(
        _pkg(manifest_file="data/reports/scan.json")) == "Unknown"


def test_full_lockfile_vocabulary_carries_membership_evidence():
    """Every lockfile format the scanner parses must count as membership
    evidence -- cargo/uv/bun/composer/gem/nuget rows keep Transitive, and
    flag-less deno/nuget rows stop falling into the old Direct default."""
    for lockname in ("Cargo.lock", "uv.lock", "bun.lock", "composer.lock",
                     "Gemfile.lock", "packages.lock.json", "deno.lock"):
        row = _pkg(name="serde", version="1.0.0", direct=False,
                   manifest_file=f"vendor/{lockname}")
        assert infer_dependency_type(row) == "Transitive", lockname
        assert infer_introduced_by(row) == "", lockname
    # go.mod is a direct manifest, not a lockfile: a bare non-direct row
    # from it carries no membership evidence.
    assert infer_dependency_type(
        _pkg(direct=False, manifest_file="go.mod")) == "Unknown"


def test_depth_only_from_real_hops():
    assert infer_dependency_depth(_pkg(direct=True)) == 1
    assert infer_dependency_depth(
        _pkg(direct=False, parent="express@4.17.3",
             dependency_path=["express@4.17.3", "lodash@4.17.21"])) == 2
    assert infer_dependency_depth(_pkg(direct=False)) == 0


# ------------------------------------------- no synthesis, old payloads --
def test_old_placeholder_payload_degrades_honestly():
    """A cached record enriched by the retired synthesizer lands on the
    honest class: the placeholder is never trusted as evidence and never
    re-emitted as introduced_by. The stale path passes through verbatim
    (upstream claims are preserved, not trusted -- and no new scan can
    produce one)."""
    row = _pkg(direct=False, introduced_by=UNKNOWN_PARENT,
               dependency_path=[UNKNOWN_PARENT, "lodash@4.17.21"])
    enriched = enrich_dependency(row)
    assert enriched["dependency_type"] == "Unknown"
    assert enriched["introduced_by"] == ""


def test_no_enriched_record_carries_the_placeholder():
    rows = [
        _pkg(direct=True, manifest_file="package.json"),
        _pkg(name="qs", direct=False, parent="express@4.17.3"),
        _pkg(direct=False, manifest_file="yarn.lock"),
        _pkg(direct=False, transitive_guess=True),
    ]
    for enriched in enrich_dependency_intelligence(rows):
        for key, value in enriched.items():
            if isinstance(value, str):
                assert UNKNOWN_PARENT not in value, key
            if isinstance(value, list):
                assert not any(
                    isinstance(v, str) and UNKNOWN_PARENT in v
                    for v in value), key


def test_enrichment_is_idempotent():
    row = _pkg(direct=False, parent="express@4.17.3")
    once = enrich_dependency(row)
    twice = enrich_dependency(once)
    assert twice["dependency_type"] == once["dependency_type"]
    assert twice["dependency_path"] == once["dependency_path"]
    assert twice["introduced_by"] == once["introduced_by"]


# ------------------------------------------------- producer no-synthesis --
def test_package_intelligence_no_longer_fabricates_hops():
    row = _pkg(direct=False, manifest_file="x/package-lock.json")
    assert pkg_dependency_path(row) == []
    assert pkg_dependency_path(_pkg(direct=True)) == []
    # A path the record already carries passes through untouched.
    carried = ["express@4.17.3", "lodash@4.17.21"]
    assert pkg_dependency_path(_pkg(dependency_path=carried)) == carried


# ------------------------------------------------------ poetry / pipfile --
def test_poetry_lock_rows_are_tree_members_not_directs(tmp_path):
    lock = tmp_path / "poetry.lock"
    lock.write_text(
        '[[package]]\nname = "click"\nversion = "8.1.3"\n'
        'category = "main"\n\n[[package]]\nname = "pytest"\n'
        'version = "7.4.0"\ncategory = "dev"\n',
        encoding="utf-8")
    rows = parse_poetry_lock(str(lock))
    assert rows, "poetry.lock rows must parse"
    for row in rows:
        assert row["direct"] is False, row["name"]
    # The evidence gate classifies them as tree members via the lockfile
    # manifest_file -- without inventing a parent.
    assert infer_dependency_type(rows[0]) == "Transitive"
    assert infer_introduced_by(rows[0]) == ""


def test_pyproject_poetry_dependencies_still_declare_directs(tmp_path):
    """The cross-fill source: pyproject.toml [tool.poetry.dependencies]."""
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        '[tool.poetry.dependencies]\npython = "^3.11"\n'
        'flask = "^2.3.2"\n', encoding="utf-8")
    rows = parse_pyproject_toml(str(pyproject))
    flask = next(r for r in rows if r["name"] == "flask")
    assert flask["direct"] is True


def test_pipfile_lock_rows_are_tree_members_not_directs(tmp_path):
    lock = tmp_path / "Pipfile.lock"
    lock.write_text(json.dumps({
        "default": {"requests": {"version": "==2.31.0"}},
        "develop": {"pytest": {"version": "==7.4.0"}},
    }), encoding="utf-8")
    rows = parse_pipfile_lock(str(lock))
    assert {r["direct"] for r in rows} == {False}
    for row in rows:
        assert infer_dependency_type(row) == "Transitive"


# ------------------------------------------------------------- summaries --
def test_dependency_summary_counts_gated_classes():
    rows = [
        _pkg(name="flask", direct=True, manifest_file="requirements.txt",
             vulnerability_count=2),
        _pkg(name="qs", direct=False, parent="express@4.17.3",
             vulnerability_count=1),
        _pkg(name="locked", direct=False,
             manifest_file="package-lock.json"),
        _pkg(name="guessed", direct=False, transitive_guess=True,
             manifest_file="requirements.txt"),
        _pkg(name="opaque", direct=False),
    ]
    summary = dependency_summary(enrich_dependency_intelligence(rows))
    assert summary["direct_dependencies"] == 1
    assert summary["transitive_dependencies"] == 2   # qs + locked
    assert summary["unknown_dependencies"] == 2      # guessed + opaque
    assert summary["vulnerable_direct_dependencies"] == 1
    assert summary["vulnerable_transitive_dependencies"] == 1


def test_both_summaries_agree_on_the_same_payload(_dark_external_advisory):
    """sbom_summary and dependency_summary read ONE classification rule,
    at both pipeline stages that actually occur (finalize-stamped and
    fully enriched). Raw parser rows carry no dependency_type string, so
    dependency_summary only speaks once a stamp exists."""
    from scanner.sbom import finalize_sbom_packages

    rows = [
        _pkg(name="flask", version="1.0.2", direct=True,
             manifest_file="requirements.txt"),
        _pkg(name="qs", version="6.13.0", direct=False,
             parent="express@4.17.3"),
        _pkg(name="locked", version="2.0.0", license="MIT",
             direct=False, manifest_file="package-lock.json"),
        _pkg(name="guessed", version="unknown", direct=False,
             transitive_guess=True, manifest_file="requirements.txt"),
    ]
    # Stage 1: finalize-stamped records (main.py runs build_package_summary
    # on exactly this state).
    stamped = finalize_sbom_packages(
        [dict(r) for r in rows], add_transitive=False)
    dep_summary = dependency_summary(stamped)
    sbom_summary = build_package_summary(stamped)
    assert sbom_summary["direct_packages"] == dep_summary["direct_dependencies"]
    assert (sbom_summary["transitive_packages"]
            == dep_summary["transitive_dependencies"])
    # Stage 2: fully enriched records (post dependency intelligence).
    enriched = enrich_dependency_intelligence([dict(r) for r in stamped])
    dep_summary = dependency_summary(enriched)
    sbom_summary = build_package_summary(enriched)
    assert sbom_summary["direct_packages"] == dep_summary["direct_dependencies"]
    assert (sbom_summary["transitive_packages"]
            == dep_summary["transitive_dependencies"])


# ------------------------------------------------------- finalize stamp --
@pytest.fixture()
def _dark_external_advisory(monkeypatch):
    """Offline: identity the OSV/NVD pass inside finalize (no sockets)."""
    from scanner import sbom as sbom_mod
    monkeypatch.setattr(sbom_mod, "enrich_packages_with_external_vulns",
                        lambda pkgs: list(pkgs))


def test_finalize_stamp_uses_the_shared_gate(_dark_external_advisory):
    """The finalize stamp and the enrich layer cannot disagree."""
    from scanner.sbom import finalize_sbom_packages

    pkgs = [
        # Flag-less record: no evidence either way -> Unknown (was Direct).
        _pkg(name="flagless", version="1.0.0"),
        # Fabricated guess shape -> Unknown (was Transitive).
        _pkg(name="guessed", version="unknown", direct=False,
             transitive_guess=True, manifest_file="requirements.txt"),
        # Lockfile row -> Transitive via membership evidence.
        _pkg(name="locked", version="2.0.0", license="MIT",
             direct=False, manifest_file="package-lock.json"),
    ]
    out = finalize_sbom_packages(pkgs, add_transitive=False)
    by = {p["name"]: p for p in out}
    assert by["flagless"]["dependency_type"] == "Unknown"
    assert by["guessed"]["dependency_type"] == "Unknown"
    assert by["locked"]["dependency_type"] == "Transitive"
