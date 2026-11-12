"""Poetry verified-edge extractor (R2.1, evidence tier: constraint-resolvable).

Evidence basis (verified on real corpus, R2.0): poetry.lock's
``[[package]]`` entries carry per-package ``[package.dependencies]``
declarations (name + constraint + markers + optional flag); the lockfile
also holds the resolved universe, so a declaration that matches EXACTLY ONE
resolved child version is a VERIFIED edge; multiple matches are AMBIGUOUS
(candidates disclosed, never picked); zero matches or unparseable
constraints are UNRESOLVED. Membership alone is never an edge.

Registry integration: poetry.lock dispatches here (R2.1a stub replaced).
"""

import json

from analysis.lock_graph import registry
from analysis.lock_graph.poetry import extract


def _write(tmp_path, text, name="poetry.lock"):
    lock = tmp_path / name
    lock.write_text(text, encoding="utf-8")
    return str(lock)


CHAIN = """\
[[package]]
name = "alpha"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }

[package.dependencies]
beta = ">=1.0"

[[package]]
name = "beta"
version = "1.2.0"

[package.dependencies]
gamma = {version = "*", markers = "python_version < '3.11'"}

[[package]]
name = "gamma"
version = "2.0.0"
"""


def test_chain_resolves_verified_edges_with_markers(tmp_path):
    result = extract(_write(tmp_path, CHAIN))
    assert result["graph_status"] == "VERIFIED_EDGES_AVAILABLE"
    assert result["verified_edge_count"] == 2
    edges = {(e["parent_name"], e["child_name"]): e for e in result["edges"]}
    ab = edges[("alpha", "beta")]
    assert ab["child_version"] == "1.2.0"
    assert ab["confidence"] == "VERIFIED"
    assert ab["parent_purl"] == "pkg:pypi/alpha@1.0.0"
    assert ab["child_purl"] == "pkg:pypi/beta@1.2.0"
    assert ab["fingerprint"].startswith("sha256:")
    bg = edges[("beta", "gamma")]
    assert bg["child_version"] == "2.0.0"
    assert bg["qualifiers"]["markers"] == "python_version < '3.11'"
    assert bg["evidence_source"] == "POETRY_PACKAGE_DEPENDENCIES"


def test_registry_dispatches_poetry(tmp_path):
    result = registry.extract_for_file(_write(tmp_path, CHAIN))
    assert result["engine"] == "POETRY_LOCK_GRAPH_V1"
    assert result["verified_edge_count"] == 2


def test_multi_parent_two_edges(tmp_path):
    # gamma and delta both declare alpha: two parents, one child, two edges.
    lock = CHAIN.replace(
        'name = "gamma"\nversion = "2.0.0"',
        'name = "gamma"\nversion = "2.0.0"\n\n[package.dependencies]'
        '\nalpha = ">=1.0"\n\n[[package]]\nname = "delta"\nversion = "1.0.0"'
        '\n\n[package.dependencies]\nalpha = ">=1.0"',
    )
    result = extract(_write(tmp_path, lock))
    parents = sorted(e["parent_name"] for e in result["edges"]
                     if e["child_name"] == "alpha"
                     and e["confidence"] == "VERIFIED")
    assert parents == ["delta", "gamma"]


def test_duplicate_versions_constraints_pick_instances(tmp_path):
    lock = """\
[[package]]
name = "alpha"
version = "1.0.0"

[package.dependencies]
beta = ">=2.0"

[[package]]
name = "delta"
version = "1.0.0"

[package.dependencies]
beta = "<2"

[[package]]
name = "beta"
version = "1.0.0"

[[package]]
name = "beta"
version = "2.0.0"
"""
    result = extract(_write(tmp_path, lock))
    got = {(e["parent_name"], e["child_version"]) for e in result["edges"]
           if e["child_name"] == "beta" and e["confidence"] == "VERIFIED"}
    assert got == {("alpha", "2.0.0"), ("delta", "1.0.0")}


def test_constraint_forms_caret_tilde_exact_range_wildcard(tmp_path):
    lock = """\
[[package]]
name = "app"
version = "1.0.0"

[package.dependencies]
w-caret = "^2.0.0"
w-tilde = "~1.4.2"
w-exact = "==1.2.3"
w-pin = "1.2.3"
w-range = ">=1.0,<2.0"
w-wildcard = "1.2.*"

[[package]]
name = "w-caret"
version = "2.5.0"

[[package]]
name = "w-tilde"
version = "1.4.9"

[[package]]
name = "w-exact"
version = "1.2.3"

[[package]]
name = "w-pin"
version = "1.2.3"

[[package]]
name = "w-range"
version = "1.5.0"

[[package]]
name = "w-wildcard"
version = "1.2.7"
"""
    result = extract(_write(tmp_path, lock))
    got = {e["child_name"]: e["child_version"] for e in result["edges"]
           if e["confidence"] == "VERIFIED"}
    assert got == {
        "w-caret": "2.5.0", "w-tilde": "1.4.9", "w-exact": "1.2.3",
        "w-pin": "1.2.3", "w-range": "1.5.0", "w-wildcard": "1.2.7",
    }


def test_same_parent_two_versions_each_resolves_own_deps(tmp_path):
    lock = """\
[[package]]
name = "beta"
version = "1.0.0"

[package.dependencies]
gamma = "<2"

[[package]]
name = "beta"
version = "2.0.0"

[package.dependencies]
gamma = ">=2"

[[package]]
name = "gamma"
version = "1.5.0"

[[package]]
name = "gamma"
version = "2.5.0"
"""
    result = extract(_write(tmp_path, lock))
    got = {(e["parent_version"], e["child_version"])
           for e in result["edges"] if e["confidence"] == "VERIFIED"}
    assert got == {("1.0.0", "1.5.0"), ("2.0.0", "2.5.0")}


def test_ambiguous_constraint_discloses_never_picks(tmp_path):
    lock = """\
[[package]]
name = "alpha"
version = "1.0.0"

[package.dependencies]
beta = ">=1.0"

[[package]]
name = "beta"
version = "1.0.0"

[[package]]
name = "beta"
version = "2.0.0"
"""
    result = extract(_write(tmp_path, lock))
    assert result["verified_edge_count"] == 0
    assert result["tallies"]["ambiguous"] == 1
    edge = result["edges"][0]
    assert edge["confidence"] == "AMBIGUOUS"
    assert edge["ambiguity"]["candidates"] == ["1.0.0", "2.0.0"]
    assert edge["child_version"] == ""
    assert edge["child_purl"] == ""


def test_unresolved_child_absent_and_bad_constraint(tmp_path):
    lock = """\
[[package]]
name = "alpha"
version = "1.0.0"

[package.dependencies]
ghost = ">=1.0"
weird = "nonsense-constraint ~~~"

[[package]]
name = "weird"
version = "1.0.0"
"""
    result = extract(_write(tmp_path, lock))
    assert result["verified_edge_count"] == 0
    assert result["tallies"]["unresolved"] == 2
    statuses = {e["child_name"]: e["resolution_status"]
                for e in result["edges"]}
    assert statuses["ghost"] == "CHILD_NOT_IN_LOCKFILE"
    assert statuses["weird"] == "UNPARSEABLE_CONSTRAINT"


def test_optional_scope_and_git_source_qualifiers(tmp_path):
    lock = """\
[[package]]
name = "alpha"
version = "1.0.0"

[package.dependencies]
extra-dep = {version = ">=1.0", optional = true}

[[package]]
name = "extra-dep"
version = "1.1.0"

[[package]]
name = "gitpkg"
version = "0.9.0"
source = { git = "https://example.com/repo.git", tag = "v0.9.0" }

[package.dependencies]
helper = ">=0.1"

[[package]]
name = "helper"
version = "0.2.0"
"""
    result = extract(_write(tmp_path, lock))
    by_child = {e["child_name"]: e for e in result["edges"]
                if e["confidence"] == "VERIFIED"}
    assert by_child["extra-dep"]["scope"] == "optional"
    # the git-sourced PARENT's qualifiers travel on its outgoing edges
    assert by_child["helper"]["parent_name"] == "gitpkg"
    assert by_child["helper"]["qualifiers"]["source_type"] == "git"
    assert by_child["helper"]["qualifiers"]["source"] == \
        "https://example.com/repo.git"


def test_malformed_toml_is_disclosed_not_fatal(tmp_path):
    result = extract(_write(tmp_path, "[[package]\nname ="))
    assert result["graph_status"] == "EXTRACTION_ERROR"
    assert result["edges"] == []
    assert result["limitations"]


def test_deterministic_output_and_fingerprints(tmp_path):
    path = _write(tmp_path, CHAIN, name="one.lock")
    a = extract(path)
    b = extract(path)
    # same input -> byte-identical edges (fingerprints included)
    assert json.dumps(a["edges"], sort_keys=True) == \
        json.dumps(b["edges"], sort_keys=True)
    # fingerprints are identity-stable across lockfile PATHS as well
    c = extract(_write(tmp_path, CHAIN, name="two.lock"))
    fp_a = sorted(e["fingerprint"] for e in a["edges"])
    fp_c = sorted(e["fingerprint"] for e in c["edges"])
    assert fp_a == fp_c


def test_membership_without_dependencies_yields_no_edges(tmp_path):
    # A lockfile body with no [package.dependencies] anywhere: membership
    # evidence only -- no invented edges (master prompt §7).
    lock = """\
[[package]]
name = "solo"
version = "3.2.1"
"""
    result = extract(_write(tmp_path, lock))
    assert result["graph_status"] == "NO_VERIFIED_EDGES"
    assert result["edges"] == []


def test_union_constraint_from_real_corpus_shape(tmp_path):
    # Real form found on DVAP (pylint): ">=4.2.5,<5.13.0 || >5.13.0,<7".
    # Union semantics are exact OR over branches -- resolved honestly.
    lock = """[[package]]
name = "pylint"
version = "3.3.4"

[package.dependencies]
isort = ">=4.2.5,<5.13.0 || >5.13.0,<7"

[[package]]
name = "isort"
version = "5.12.0"
"""
    result = extract(_write(tmp_path, lock))
    assert result["verified_edge_count"] == 1
    edge = result["edges"][0]
    assert (edge["child_name"], edge["child_version"]) == ("isort", "5.12.0")
    assert edge["confidence"] == "VERIFIED"


def test_list_alternatives_dedupe_to_one_edge(tmp_path):
    # Real form found on DVAP (dill): a LIST of marker-differentiated
    # declarations of the same dependency. All resolve to the same pinned
    # version -> one deduped edge, markers merged, duplicate tallied.
    lock = """[[package]]
name = "app"
version = "1.0.0"

[package.dependencies]
dill = [
    {version = ">=0.2", markers = 'python_version < "3.11"'},
    {version = ">=0.3.6", markers = 'python_version >= "3.11"'},
]

[[package]]
name = "dill"
version = "0.3.9"
"""
    result = extract(_write(tmp_path, lock))
    assert result["verified_edge_count"] == 1
    assert result["tallies"]["duplicate_records_dropped"] == 1
    edge = result["edges"][0]
    assert (edge["parent_name"], edge["child_name"],
            edge["child_version"]) == ("app", "dill", "0.3.9")
    assert "python_version <" in edge["qualifiers"]["markers"]
    assert "python_version >=" in edge["qualifiers"]["markers"]
