"""Common lock-graph contract, registry and npm adapter (R2.1, approved R2.0).

The contract (audit_output/R2_GRAPH_CONTRACT.md) is the single edge schema
every ecosystem extractor emits: the npm engine's proven shape is a strict
subset, mapped at the ADAPTER layer only -- the npm engine itself is not
modified. Five confidence states bind honesty: only VERIFIED edges may join;
AMBIGUOUS carries candidates and never mints a parent; UNSUPPORTED formats
never fabricate edges.

Compat pins verified here:
- the npm adapter preserves every original engine field (confidence,
  fingerprint, parent/child raw ids) and only ADDS common-schema fields;
- verified_edge_count is unchanged by enrichment;
- the registry dispatches by lockfile filename and answers unknown names
  with a disclosed UNSUPPORTED envelope, never an exception.
"""

import json

from analysis.lock_graph import contract, registry
from analysis.lock_graph.npm_adapter import extract as npm_extract


# ---------------------------------------------------------------- contract --
def test_verified_edge_requires_both_versions():
    e = contract.build_edge(
        ecosystem="pypi", parent_name="flask", parent_version="3.0.3",
        child_name="click", child_version="8.1.7",
        source="poetry.lock", source_location="[[package] flask]",
        evidence_source="POETRY_PACKAGE_DEPENDENCIES")
    assert e["confidence"] == "VERIFIED"
    assert e["fingerprint"].startswith("sha256:")
    assert e["parent_purl"] == "pkg:pypi/flask@3.0.3"
    assert e["child_purl"] == "pkg:pypi/click@8.1.7"
    assert e["scope"] == "runtime"


def test_missing_child_version_downgrades_confidence():
    # A versionless child identity can never be VERIFIED (no guessing).
    e = contract.build_edge(
        ecosystem="pypi", parent_name="flask", parent_version="3.0.3",
        child_name="click", child_version="",
        source="poetry.lock", source_location="loc",
        evidence_source="POETRY_PACKAGE_DEPENDENCIES")
    assert e["confidence"] == "UNRESOLVED"
    assert e["parent_purl"] == "pkg:pypi/flask@3.0.3"
    assert e["child_purl"] == ""


def test_fingerprint_is_deterministic_and_field_order_free():
    a = contract.build_edge(
        ecosystem="pypi", parent_name="a", parent_version="1.0",
        child_name="b", child_version="2.0",
        source="x", source_location="l", evidence_source="E")
    b = contract.build_edge(
        ecosystem="pypi", parent_name="a", parent_version="1.0",
        child_name="b", child_version="2.0",
        source="other-path", source_location="different",
        evidence_source="E")
    # Identity-stable: source/lockfile path cannot move the fingerprint.
    assert a["fingerprint"] == b["fingerprint"]
    c = contract.build_edge(
        ecosystem="pypi", parent_name="a", parent_version="1.1",
        child_name="b", child_version="2.0",
        source="x", source_location="l", evidence_source="E")
    assert c["fingerprint"] != a["fingerprint"]


def test_unresolvable_identity_yields_no_purl_and_no_confidence_gain():
    e = contract.build_edge(
        ecosystem="pypi", parent_name="flask", parent_version="unknown",
        child_name="click", child_version="8.1.7",
        source="x", source_location="l", evidence_source="E")
    assert e["confidence"] == "UNRESOLVED"
    assert e["parent_purl"] == ""


def test_envelope_counts_verified_only_and_carries_limitations():
    e1 = contract.build_edge(
        ecosystem="pypi", parent_name="a", parent_version="1.0",
        child_name="b", child_version="1.0",
        source="x", source_location="l", evidence_source="E")
    e2 = contract.build_edge(
        ecosystem="pypi", parent_name="a", parent_version="1.0",
        child_name="c", child_version="",
        source="x", source_location="l", evidence_source="E")
    env = contract.extraction_result(
        engine="TEST_GRAPH_V1", source="x", format_version="t1",
        graph_status="VERIFIED_EDGES_AVAILABLE",
        edges=[e1, e2], limitations=["limit one"])
    assert env["verified_edge_count"] == 1
    assert env["tallies"]["unresolved"] == 1
    assert env["limitations"] == ["limit one"]
    assert env["evidence_policy"] == "AUTHORITATIVE_RELATIONSHIP_FIELDS_ONLY"


# ---------------------------------------------------------------- registry --
def test_registry_names_cover_r2_scope():
    # R2.1: npm/poetry/uv/pipenv; R2.2 adds Java: resolved-evidence files
    # (dependency-tree.txt, gradle-dependencies.txt) plus manifest files
    # that must answer with disclosed UNSUPPORTED envelopes (never edges).
    assert registry.LOCKFILE_NAMES == {
        "package-lock.json", "poetry.lock", "uv.lock", "Pipfile.lock",
        "dependency-tree.txt", "pom.xml",
        "gradle-dependencies.txt", "gradle.lockfile",
        "build.gradle", "settings.gradle",
    }


def test_registry_dispatches_npm_and_preserves_output(tmp_path):
    lock = tmp_path / "package-lock.json"
    lock.write_text(json.dumps({
        "name": "demo", "version": "1.0.0",
        "lockfileVersion": 3,
        "requires": True,
        "packages": {
            "": {"name": "demo", "version": "1.0.0",
                 "dependencies": {"lodash": "^4.17.21"}},
            "node_modules/lodash": {"version": "4.17.21",
                                    "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"},
        },
    }), encoding="utf-8")
    result = registry.extract_for_file(str(lock))
    assert result["graph_status"] == "VERIFIED_EDGES_AVAILABLE"
    assert result["verified_edge_count"] == 1
    edge = result["edges"][0]
    # original engine fields survive enrichment untouched
    assert edge["parent"] == "pkg:npm/__root__"
    assert edge["child"] == "pkg:npm/lodash@4.17.21"
    assert edge["confidence"] == "VERIFIED"
    assert edge["fingerprint"]
    # common-schema fields added by the adapter
    assert edge["ecosystem"] == "npm"
    assert edge["child_name"] == "lodash"
    assert edge["child_version"] == "4.17.21"
    assert edge["child_purl"] == "pkg:npm/lodash@4.17.21"
    assert "parent_name" not in edge  # synthetic root: no parent fields added


def test_npm_adapter_engine_passthrough_on_unsupported_version(tmp_path):
    lock = tmp_path / "package-lock.json"
    lock.write_text(json.dumps({"lockfileVersion": 1}), encoding="utf-8")
    result = npm_extract(str(lock))
    assert result["graph_status"] == "UNSUPPORTED_LOCKFILE_VERSION"
    assert result["edges"] == []


def test_registry_answers_unknown_names_with_disclosed_envelope(tmp_path):
    other = tmp_path / "something.lock"
    other.write_text("whatever", encoding="utf-8")
    result = registry.extract_for_file(str(other))
    assert result["graph_status"] == "UNSUPPORTED_FORMAT"
    assert result["edges"] == []
    assert result["limitations"]


def test_registry_membership_only_placeholder_never_fabricates(tmp_path):
    # Pipfile.lock (R2.1): membership-only format -> no edges, disclosed.
    lock = tmp_path / "Pipfile.lock"
    lock.write_text(json.dumps({
        "_meta": {"hash": {"sha256": "x"}},
        "default": {"flask": {"version": "==3.0.3", "hashes": ["sha256:y"]}},
        "develop": {},
    }), encoding="utf-8")
    result = registry.extract_for_file(str(lock))
    assert result["graph_status"] == "UNSUPPORTED_FORMAT"
    assert result["edges"] == []
    assert any("membership" in str(l).lower() for l in result["limitations"])
    assert result["membership_packages"] == 1


# ------------------------------------------------- R2.2 F-2 equivalence --
def test_norm_pypi_matches_join_identity():
    # The join keeps an inlined (import-light) copy of the PyPI identity
    # rule; this test pins the two spellings to stay equivalent across the
    # spellings real manifests/lockfiles emit.
    from scanner.dependency_intelligence import _norm_identity_name
    spellings = [
        ("typing_extensions", "typing-extensions"),
        ("Flask_Login", "flask-login"),
        ("Pillow", "pillow"),
        ("zope.interface", "zope-interface"),
        ("a..b--c__d", "a-b-c-d"),
        ("HTTPS/lib", "https-lib"),
    ]
    for raw, _ in spellings:
        assert contract.norm_pypi(raw) == _norm_identity_name("pypi", raw), raw
