"""Verified-edge join goes multi-ecosystem (R2.1, approved R2.0 contract).

The matching MECHANICS were already ecosystem-agnostic; only the gate and
edge-id parsing were npm-specific. R2.1 opens the gate to the approved
ecosystem set with per-ecosystem identity normalization:

- PyPI: PEP 503 name normalization (`[-_.]+ -> -`, casefold) — a
  `typing_extensions` edge joins a `typing-extensions` record;
- Maven: `group:artifact` kept whole;
- Go: module path casefold;
- npm: unchanged casefold.

Binding invariants pinned here:
- an npm edge NEVER stamps a PyPI record (ecosystem-scoped identity — the
  pre-R2.1 contract's security property, now structural);
- AMBIGUOUS-confidence edges never join;
- unsupported ecosystems still count in skipped_non_npm;
- by_ecosystem tallies are additive (existing summary keys unchanged).
"""

from scanner.dependency_intelligence import join_verified_edges


def _row(name, version, ecosystem, **kw):
    d = {"name": name, "version": version, "ecosystem": ecosystem,
         "direct": False, "manifest_file": "requirements.txt"}
    d.update(kw)
    return d


def _pypi_edge(parent, pver, child, cver, **extra):
    e = {
        "ecosystem": "pypi",
        "parent_name": parent, "parent_version": pver,
        "child_name": child, "child_version": cver,
        "confidence": "VERIFIED",
        "evidence_source": "POETRY_PACKAGE_DEPENDENCIES",
        "source": "poetry.lock",
        "fingerprint": "sha256:t",
    }
    e.update(extra)
    return e


def test_pypi_edge_joins_pypi_record():
    sbom = [_row("typing-extensions", "4.7.1", "PyPI")]
    edges = [_pypi_edge("requests", "2.31.0", "typing_extensions", "4.7.1")]
    result = join_verified_edges(sbom, edges)
    row = result["sbom"][0]
    assert row["parent"] == "requests@2.31.0"
    assert row["verified_transitive"] is True
    assert row["parent_edge_source"] == "poetry.lock"
    assert result["summary"]["matched"] == 1
    assert result["summary"]["parented"] == 1


def test_npm_edge_never_stamps_pypi_record():
    # Ecosystem-scoped identity: cross-ecosystem matching is impossible.
    sbom = [_row("flask", "1.0.2", "PyPI")]
    edges = [{"parent": "pkg:npm/express@4.17.3",
              "child": "pkg:npm/flask@1.0.2", "confidence": "VERIFIED"}]
    result = join_verified_edges(sbom, edges)
    row = result["sbom"][0]
    assert "parent" not in row
    assert result["summary"]["unmatched"] == 1


def test_npm_legacy_edges_still_join_npm_records():
    sbom = [{"name": "lodash", "version": "4.17.21", "ecosystem": "npm",
             "direct": False, "manifest_file": "package-lock.json"}]
    edges = [{"parent": "pkg:npm/express@4.17.3",
              "child": "pkg:npm/lodash@4.17.21", "confidence": "VERIFIED",
              "fingerprint": "f", "source": "package-lock.json"}]
    result = join_verified_edges(sbom, edges)
    assert result["sbom"][0]["parent"] == "express@4.17.3"


def test_maven_edge_joins_maven_record():
    sbom = [_row("junit:junit", "4.13.2", "Maven")]
    edges = [{
        "ecosystem": "maven",
        "parent_name": "org.apache.commons:commons-lang3",
        "parent_version": "3.12.0",
        "child_name": "junit:junit", "child_version": "4.13.2",
        "confidence": "VERIFIED", "source": "deps.txt", "fingerprint": "m",
    }]
    result = join_verified_edges(sbom, edges)
    assert result["sbom"][0]["parent"] == \
        "org.apache.commons:commons-lang3@3.12.0"


def test_golang_module_path_casefold_join():
    sbom = [_row("github.com/beego/bee", "v1.12.0", "Go")]
    edges = [{
        "ecosystem": "golang",
        "parent_name": "github.com/example/app", "parent_version": "v0.1.0",
        "child_name": "github.com/Beego/bee", "child_version": "v1.12.0",
        "confidence": "VERIFIED", "source": "go.mod", "fingerprint": "g",
    }]
    result = join_verified_edges(sbom, edges)
    assert result["summary"]["parented"] == 1


def test_ambiguous_edge_never_joins():
    sbom = [_row("click", "8.1.7", "PyPI")]
    edges = [_pypi_edge("flask", "3.0.3", "click", "8.1.7",
                        confidence="AMBIGUOUS",
                        ambiguity={"candidates": ["8.1.7", "8.1.3"]})]
    result = join_verified_edges(sbom, edges)
    assert "parent" not in result["sbom"][0]
    assert result["summary"]["matched"] == 0


def test_unsupported_ecosystem_still_counted_non_npm():
    sbom = [_row("some.swift.pkg", "1.0", "Swift")]
    result = join_verified_edges(sbom, [])
    assert result["summary"]["skipped_non_npm"] == 1


def test_by_ecosystem_tallies_are_additive():
    sbom = [_row("typing-extensions", "4.7.1", "PyPI"),
            {"name": "lodash", "version": "4.17.21", "ecosystem": "npm",
             "direct": False, "manifest_file": "package-lock.json"}]
    edges = [
        _pypi_edge("requests", "2.31.0", "typing_extensions", "4.7.1"),
        {"parent": "pkg:npm/express@4.17.3", "child": "pkg:npm/lodash@4.17.21",
         "confidence": "VERIFIED", "fingerprint": "f",
         "source": "package-lock.json"},
    ]
    result = join_verified_edges(sbom, edges)
    by = result["summary"]["by_ecosystem"]
    assert by["pypi"]["parented"] == 1
    assert by["npm"]["parented"] == 1
    # existing summary keys unchanged
    assert result["summary"]["parented"] == 2
    assert result["summary"]["engine"] == "VERIFIED_EDGE_JOIN_V1"
