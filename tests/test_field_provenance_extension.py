"""Per-field provenance for purl, cvss, dependency_type and parent (R1/W2, GAP-14).

The defect this pins: ``field_provenance`` covered version and license only;
purl, cvss_version, dependency_type and parent were stamped by
``_stamp_report_fields`` / the verified-edge join with no "why" record, so a
provenance consumer cannot ask "why does this row have this purl?" or "is
this parent a verified edge?".

Contract (R1 approval):
- populated fields get REASON-ONLY provenance entries -- ``value_state.resolve``
  lets a provenance ``state`` override its ladder, so a state-bearing entry on
  a populated field would change rendered values (core/value_state.py:225-233);
- the classification gate's public contract is untouched: the evidence basis
  is read from the same branch logic ``infer_dependency_type`` uses;
- parent provenance echoes the join's already-stamped single-hop edge
  fingerprint and source -- it is an immediate edge record, NEVER a
  root-to-package path claim.
"""

import pytest

from scanner.sbom import _stamp_report_fields
from scanner.dependency_intelligence import (
    infer_dependency_type,
    stamp_parent_provenance,
)
from core.value_state import cell, resolve


def _provenance(pkg, field):
    prov = pkg.get("field_provenance") or {}
    return prov.get(field)


# ----------------------------------------------------------- compatibility --
def test_provenance_preserves_values_and_rendered_cells():
    # The compatibility invariant, precisely: fields with REAL values resolve
    # identically with and without provenance, and renderer-consumed cells
    # (renderers resolve version/fixed_versions/severity only -- none carry
    # W2 provenance) render identically.
    pkg = {"name": "flask", "version": "2.0.0", "ecosystem": "pypi",
           "license": "BSD-3-Clause"}
    _stamp_report_fields(pkg)
    bare = {k: v for k, v in pkg.items() if k != "field_provenance"}
    for field in ("purl", "version", "license"):
        assert resolve(pkg, field) == resolve(bare, field), field
    for field in ("version", "severity"):
        assert cell(pkg, field) == cell(bare, field), field
    for field in ("purl", "dependency_type"):
        entry = _provenance(pkg, field)
        assert entry is not None, field
        assert "state" not in entry, "reason-only entries must not carry state"
    state, _, _ = resolve(pkg, "purl")
    assert state == "VALUE"


def test_labeled_absence_is_disclosed_not_rendered_today():
    # value_state ladder step 4: a reason-only provenance entry on a
    # placeholder-valued field resolves UNKNOWN-with-reason instead of a
    # bare ABSENT. No renderer resolves these fields today, so no rendered
    # cell changes; the flip IS the provenance answer ("why is this --").
    # This test discloses the behavior as a decision, not an accident.
    pkg = {"name": "mystery", "version": "1.0.0", "ecosystem": "npm"}
    _stamp_report_fields(pkg)
    state, reason, _ = resolve(pkg, "dependency_type")
    assert state == "UNKNOWN"
    assert reason == "GATE_NO_EVIDENCE"


def test_existing_provenance_entries_stay_authoritative():
    pkg = {"name": "flask", "version": "2.0.0", "ecosystem": "pypi",
           "field_provenance": {"purl": {"reason": "INGEST_ADAPTER"}}}
    _stamp_report_fields(pkg)
    assert _provenance(pkg, "purl") == {"reason": "INGEST_ADAPTER"}


# -------------------------------------------------------------------- purl --
def test_populated_purl_provenance_records_the_authority():
    pkg = {"name": "flask", "version": "2.0.0", "ecosystem": "pypi"}
    _stamp_report_fields(pkg)
    assert pkg["purl"] == "pkg:pypi/flask@2.0.0"
    assert _provenance(pkg, "purl") == {"reason": "PURL_DERIVED"}


def test_unresolvable_purl_absence_is_recorded_not_invented():
    pkg = {"name": "left-pad", "version": "unknown", "ecosystem": "npm"}
    _stamp_report_fields(pkg)
    assert "purl" not in pkg
    entry = _provenance(pkg, "purl")
    assert entry == {"reason": "PURL_UNRESOLVABLE"}
    assert "state" not in entry


# ------------------------------------------------------------------- cvss --
def test_cvss_provenance_names_the_offline_table():
    pkg = {"name": "flask", "version": "0.1.0", "ecosystem": "pypi",
           "cvss_method": "STATIC_OFFLINE_CVSS_V1"}
    _stamp_report_fields(pkg)
    assert pkg["cvss_version"] == "3.1"
    assert _provenance(pkg, "cvss") == {"reason": "OFFLINE_CVSS_TABLE"}


def test_no_cvss_record_means_no_cvss_provenance():
    pkg = {"name": "flask", "version": "2.0.0", "ecosystem": "pypi"}
    _stamp_report_fields(pkg)
    assert "cvss_version" not in pkg
    assert _provenance(pkg, "cvss") is None


# -------------------------------------------------------- dependency_type --
def test_direct_flag_records_gate_basis():
    pkg = {"name": "express", "version": "4.18.2", "ecosystem": "npm",
           "direct": True}
    _stamp_report_fields(pkg)
    assert pkg["dependency_type"] == "Direct"
    assert _provenance(pkg, "dependency_type") == {
        "reason": "GATE_MANIFEST_DIRECT"}
    assert infer_dependency_type(pkg) == "Direct"


def test_lockfile_membership_records_gate_basis(tmp_path):
    lock = tmp_path / "Gemfile.lock"
    lock.write_text("GEM\n  specs:\n    rails (7.0.3.1)\n", encoding="utf-8")
    pkg = {"name": "rails", "version": "7.0.3.1", "ecosystem": "RubyGems",
           "direct": False, "manifest_file": str(lock)}
    _stamp_report_fields(pkg)
    assert pkg["dependency_type"] == "Transitive"
    assert _provenance(pkg, "dependency_type") == {
        "reason": "GATE_LOCKFILE_MEMBERSHIP"}


def test_flagless_row_records_no_evidence():
    pkg = {"name": "mystery", "version": "1.0.0", "ecosystem": "npm"}
    _stamp_report_fields(pkg)
    assert pkg["dependency_type"] == "Unknown"
    assert _provenance(pkg, "dependency_type") == {"reason": "GATE_NO_EVIDENCE"}


# ------------------------------------------------------------------ parent --
def test_parent_provenance_echoes_the_verified_edge():
    pkg = {
        "name": "cookie", "version": "0.4.2", "ecosystem": "npm",
        "parent": "express@4.18.2",
        "introduced_by": "express",
        "dependency_path": ["express@4.18.2", "cookie@0.4.2"],
        "parent_edge_fingerprint": "sha256:abc123",
        "parent_edge_source": "package-lock.json",
    }
    stamp_parent_provenance([pkg])
    entry = _provenance(pkg, "parent")
    assert entry["reason"] == "VERIFIED_PARENT_EDGE"
    assert entry["source"] == "package-lock.json"
    assert entry["fingerprint"] == "sha256:abc123"
    # Single-hop invariant: provenance echoes the one hop, never a path.
    assert "path" not in entry
    assert len(pkg["dependency_path"]) == 2


def test_ambiguous_parent_provenance_mints_no_path():
    pkg = {
        "name": "cookie", "version": "0.5.0", "ecosystem": "npm",
        "parent_resolution": "ambiguous_multiple_versions",
        "verified_parent_instances": [
            {"parent": "send@1.0.0", "fingerprint": "f1", "source": "s1"},
            {"parent": "send@0.19.0", "fingerprint": "f2", "source": "s2"},
        ],
    }
    stamp_parent_provenance([pkg])
    entry = _provenance(pkg, "parent")
    assert entry == {"reason": "PARENT_AMBIGUOUS_MULTIPLE_VERSIONS"}
    assert "parent" not in pkg
    assert "dependency_path" not in pkg


def test_multi_parent_provenance_mints_no_path():
    pkg = {
        "name": "mime-types", "version": "1.0.0", "ecosystem": "npm",
        "parent_resolution": "ambiguous_multiple_parents",
        "verified_parents": ["send", "accepts"],
    }
    stamp_parent_provenance([pkg])
    assert _provenance(pkg, "parent") == {
        "reason": "PARENT_AMBIGUOUS_MULTIPLE_PARENTS"}
    assert "dependency_path" not in pkg


def test_root_declared_provenance_names_the_declaration():
    pkg = {"name": "express", "version": "4.18.2", "ecosystem": "npm",
           "verified_root_declared": True}
    stamp_parent_provenance([pkg])
    assert _provenance(pkg, "parent") == {"reason": "PARENT_ROOT_DECLARED"}
    assert "parent" not in pkg
    assert "dependency_path" not in pkg


def test_untouched_records_get_no_parent_provenance():
    pkg = {"name": "flask", "version": "2.0.0", "ecosystem": "pypi"}
    stamp_parent_provenance([pkg])
    assert _provenance(pkg, "parent") is None
