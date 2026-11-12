"""uv verified-edge extractor (R2.1, evidence tier: constraint-resolvable).

Evidence basis (verified on the flask corpus, R2.0): uv.lock's ``[[package]]``
entries carry ``[package.metadata].requires-dist`` -- the parent's declared
dependencies as {name, specifier, marker, extra} records -- and the lockfile
holds the resolved universe. Exactly one candidate -> VERIFIED; multiple ->
AMBIGUOUS (candidates disclosed); zero -> UNRESOLVED. Empty specifier means
any resolved version. Membership alone is never an edge.
"""

import json

from analysis.lock_graph import registry
from analysis.lock_graph.uv import extract


def _write(tmp_path, text, name="uv.lock"):
    lock = tmp_path / name
    lock.write_text(text, encoding="utf-8")
    return str(lock)


FLASK_LIKE = """\
[[package]]
name = "flask"
version = "3.1.0"
source = { registry = "https://pypi.org/simple" }

[package.metadata]
requires-dist = [
    { name = "click", specifier = ">=8.1.3" },
    { name = "itsdangerous", specifier = ">=2.2.0" },
    { name = "asgiref", specifier = ">=3.2", marker = "extra == 'async'" },
]

[[package]]
name = "click"
version = "8.1.7"

[[package]]
name = "itsdangerous"
version = "2.2.0"

[[package]]
name = "asgiref"
version = "3.8.1"
"""


def test_requires_dist_resolves_verified_edges(tmp_path):
    result = extract(_write(tmp_path, FLASK_LIKE))
    assert result["graph_status"] == "VERIFIED_EDGES_AVAILABLE"
    assert result["verified_edge_count"] == 3
    edges = {(e["parent_name"], e["child_name"]): e for e in result["edges"]}
    fc = edges[("flask", "click")]
    assert fc["child_version"] == "8.1.7"
    assert fc["confidence"] == "VERIFIED"
    assert fc["parent_purl"] == "pkg:pypi/flask@3.1.0"
    assert fc["evidence_source"] == "UV_REQUIRES_DIST"
    fa = edges[("flask", "asgiref")]
    assert fa["scope"] == "optional"
    assert fa["qualifiers"]["markers"] == "extra == 'async'"
    assert fa["qualifiers"]["extra"] == "async"


def test_registry_dispatches_uv(tmp_path):
    result = registry.extract_for_file(_write(tmp_path, FLASK_LIKE))
    assert result["engine"] == "UV_LOCK_GRAPH_V1"
    assert result["verified_edge_count"] == 3


def test_empty_specifier_matches_any_resolved_version(tmp_path):
    lock = """\
[[package]]
name = "app"
version = "1.0"

[package.metadata]
requires-dist = [
    { name = "free" },
]

[[package]]
name = "free"
version = "9.9.9"
"""
    result = extract(_write(tmp_path, lock))
    edge = result["edges"][0]
    assert edge["confidence"] == "VERIFIED"
    assert edge["child_version"] == "9.9.9"


def test_union_specifier_resolves(tmp_path):
    # Real PEP 508 union shape (mirrors pylint's isort pin).
    lock = """\
[[package]]
name = "linter"
version = "3.3.4"

[package.metadata]
requires-dist = [
    { name = "isort", specifier = ">=4.2.5,<5.13.0 || >5.13.0,<7" },
]

[[package]]
name = "isort"
version = "5.12.0"
"""
    result = extract(_write(tmp_path, lock))
    assert result["verified_edge_count"] == 1
    assert result["edges"][0]["child_version"] == "5.12.0"


def test_duplicate_versions_constraints_pick_instances(tmp_path):
    lock = """\
[[package]]
name = "app"
version = "1.0"

[package.metadata]
requires-dist = [
    { name = "lib", specifier = ">=2" },
]

[[package]]
name = "other"
version = "1.0"

[package.metadata]
requires-dist = [
    { name = "lib", specifier = "<2" },
]

[[package]]
name = "lib"
version = "1.0.0"

[[package]]
name = "lib"
version = "2.0.0"
"""
    result = extract(_write(tmp_path, lock))
    got = {(e["parent_name"], e["child_version"])
           for e in result["edges"] if e["confidence"] == "VERIFIED"}
    assert got == {("app", "2.0.0"), ("other", "1.0.0")}


def test_multiple_versions_of_same_parent(tmp_path):
    lock = """\
[[package]]
name = "lib"
version = "1.0"

[package.metadata]
requires-dist = [
    { name = "dep", specifier = "<2" },
]

[[package]]
name = "lib"
version = "2.0"

[package.metadata]
requires-dist = [
    { name = "dep", specifier = ">=2" },
]

[[package]]
name = "dep"
version = "1.5.0"

[[package]]
name = "dep"
version = "2.5.0"
"""
    result = extract(_write(tmp_path, lock))
    got = {(e["parent_version"], e["child_version"])
           for e in result["edges"] if e["confidence"] == "VERIFIED"}
    assert got == {("1.0", "1.5.0"), ("2.0", "2.5.0")}


def test_ambiguous_discloses_never_picks(tmp_path):
    lock = """\
[[package]]
name = "app"
version = "1.0"

[package.metadata]
requires-dist = [
    { name = "lib", specifier = ">=1" },
]

[[package]]
name = "lib"
version = "1.0.0"

[[package]]
name = "lib"
version = "2.0.0"
"""
    result = extract(_write(tmp_path, lock))
    assert result["verified_edge_count"] == 0
    assert result["tallies"]["ambiguous"] == 1
    edge = result["edges"][0]
    assert edge["confidence"] == "AMBIGUOUS"
    assert edge["ambiguity"]["candidates"] == ["1.0.0", "2.0.0"]


def test_unresolved_absent_child_and_bad_specifier(tmp_path):
    lock = """\
[[package]]
name = "app"
version = "1.0"

[package.metadata]
requires-dist = [
    { name = "ghost", specifier = ">=1.0" },
    { name = "weird", specifier = ">>>nonsense" },
]

[[package]]
name = "weird"
version = "1.0.0"
"""
    result = extract(_write(tmp_path, lock))
    assert result["tallies"]["unresolved"] == 2
    statuses = {e["child_name"]: e["resolution_status"]
                for e in result["edges"]}
    assert statuses["ghost"] == "CHILD_NOT_IN_LOCKFILE"
    assert statuses["weird"] == "UNPARSEABLE_CONSTRAINT"


def test_malformed_toml_is_disclosed_not_fatal(tmp_path):
    result = extract(_write(tmp_path, "[[package]\nname ="))
    assert result["graph_status"] == "EXTRACTION_ERROR"
    assert result["edges"] == []


def test_deterministic_output(tmp_path):
    path = _write(tmp_path, FLASK_LIKE)
    a = extract(path)
    b = extract(path)
    assert json.dumps(a["edges"], sort_keys=True) == \
        json.dumps(b["edges"], sort_keys=True)


def test_membership_without_metadata_yields_no_edges(tmp_path):
    lock = """\
[[package]]
name = "solo"
version = "2.0.0"
source = { virtual = "." }
"""
    result = extract(_write(tmp_path, lock))
    assert result["graph_status"] == "NO_VERIFIED_EDGES"
    assert result["edges"] == []
