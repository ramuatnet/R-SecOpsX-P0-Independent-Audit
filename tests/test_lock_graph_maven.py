"""Maven verified-edge extractor (R2.2, evidence tier: resolved-evidence-required).

Evidence basis (verified on REAL `mvn dependency:tree` output: the
BenchmarkJava corpus file committed 2026-09-11 and freshly generated
offline evidence): the dependency tree declares parent-child pairs with
RESOLVED versions and scopes. A pom.xml alone is direct declarations with
unresolved properties/ranges -- it is NOT a graph and never produces edges
(master prompt §7: do not treat manifest declarations as proof of resolved
transitive relationships).

Pruned references ("omitted for duplicate/conflict") are not edges in the
resolved graph -- skipped and tallied. Conflict resolutions ("-> selected")
carry the SELECTED version, disclosed via qualifier.
"""

import json

import pytest

from analysis.lock_graph import registry
from analysis.lock_graph.maven import extract


def _write(tmp_path, text, name="dependency-tree.txt"):
    f = tmp_path / name
    f.write_text(text, encoding="utf-8")
    return str(f)


CHAIN = """\
com.example:app:jar:1.0.0
+- com.example:lib-a:jar:2.0.0:compile
|  \\- com.example:lib-b:jar:3.0.0:compile
|     \\- com.google.guava:guava:jar:33.0.0-jre:compile
\\- junit:junit:jar:4.13.2:test
   \\- org.hamcrest:hamcrest-core:jar:1.3:test
"""


def test_chain_resolves_verified_edges_with_scopes(tmp_path):
    result = extract(_write(tmp_path, CHAIN))
    assert result["graph_status"] == "VERIFIED_EDGES_AVAILABLE"
    assert result["verified_edge_count"] == 5
    edges = {(e["parent_name"], e["child_name"]): e for e in result["edges"]}
    ab = edges[("com.example:lib-a", "com.example:lib-b")]
    assert ab["child_version"] == "3.0.0"
    assert ab["scope"] == "compile"
    assert ab["parent_purl"] == "pkg:maven/com.example/lib-a@2.0.0"
    assert ab["child_purl"] == "pkg:maven/com.example/lib-b@3.0.0"
    assert ab["fingerprint"].startswith("sha256:")
    assert ab["evidence_source"] == "MAVEN_DEPENDENCY_TREE"
    jr = edges[("junit:junit", "org.hamcrest:hamcrest-core")]
    assert jr["scope"] == "test"


def test_root_edges_declared_by_the_project(tmp_path):
    result = extract(_write(tmp_path, CHAIN))
    edges = {(e["parent_name"], e["child_name"]) for e in result["edges"]}
    assert ("com.example:app", "com.example:lib-a") in edges
    assert ("com.example:app", "junit:junit") in edges
    root_edge = [e for e in result["edges"]
                 if e["child_name"] == "com.example:lib-a"][0]
    assert root_edge["parent_version"] == "1.0.0"
    assert root_edge["qualifiers"]["root"] == "com.example:app:jar:1.0.0"


def test_registry_dispatches_maven_tree(tmp_path):
    result = registry.extract_for_file(_write(tmp_path, CHAIN))
    assert result["engine"] == "MAVEN_DEPENDENCY_TREE_V1"
    assert result["verified_edge_count"] == 5


def test_classifier_coordinates_carry_qualifier(tmp_path):
    tree = """\
com.example:app:jar:1.0.0
+- io.netty:netty-transport-native-epoll:jar:linux-x86_64:4.1.100:compile
"""
    result = extract(_write(tmp_path, tree))
    edge = result["edges"][0]
    assert edge["child_name"] == "io.netty:netty-transport-native-epoll"
    assert edge["child_version"] == "4.1.100"
    assert edge["qualifiers"]["classifier"] == "linux-x86_64"
    assert edge["confidence"] == "VERIFIED"


def test_multi_parent_two_edges(tmp_path):
    tree = """\
com.example:app:jar:1.0.0
+- com.example:parent-one:jar:1.0.0:compile
|  \\- shared:shared-lib:jar:5.0.0:compile
\\- com.example:parent-two:jar:2.0.0:compile
   \\- shared:shared-lib:jar:5.0.0:compile
"""
    result = extract(_write(tmp_path, tree))
    parents = sorted(e["parent_name"] for e in result["edges"]
                     if e["child_name"] == "shared:shared-lib")
    assert parents == ["com.example:parent-one", "com.example:parent-two"]


def test_duplicate_versions_in_different_branches(tmp_path):
    tree = """\
com.example:app:jar:1.0.0
+- com.example:old-user:jar:1.0.0:compile
|  \\- com.example:lib:jar:1.0.0:compile
\\- com.example:new-user:jar:1.0.0:compile
   \\- com.example:lib:jar:2.0.0:compile
"""
    result = extract(_write(tmp_path, tree))
    got = {(e["parent_name"], e["child_version"])
           for e in result["edges"] if e["child_name"] == "com.example:lib"}
    assert got == {("com.example:old-user", "1.0.0"),
                   ("com.example:new-user", "2.0.0")}


def test_conflict_resolution_uses_selected_version(tmp_path):
    # verbose dependency:tree prints "-> selected" on the resolved node.
    tree = """\
com.example:app:jar:1.0.0
+- com.example:old-user:jar:1.0.0:compile
|  \\- com.example:lib:jar:1.0.0:compile -> 2.0.0
\\- com.example:new-user:jar:1.0.0:compile
   \\- com.example:lib:jar:2.0.0:compile
"""
    result = extract(_write(tmp_path, tree))
    conflict = [e for e in result["edges"]
                if e["parent_name"] == "com.example:old-user"
                and e["child_name"] == "com.example:lib"][0]
    assert conflict["child_version"] == "2.0.0"
    assert conflict["qualifiers"]["requested_version"] == "1.0.0"
    assert conflict["qualifiers"]["conflict_resolved"] == "true"


def test_omitted_references_are_not_edges(tmp_path):
    # Pruned references are absent from the resolved graph -- tallied,
    # never invented as edges (master prompt §7).
    tree = """\
com.example:app:jar:1.0.0
+- com.example:lib-a:jar:2.0.0:compile
|  \\- (com.example:lib-b:jar:3.0.0:compile - omitted for duplicate)
\\- com.example:lib-b:jar:3.0.0:compile
   \\- com.google.guava:guava:jar:33.0.0-jre:compile
"""
    result = extract(_write(tmp_path, tree))
    assert result["tallies"]["unsupported"] == 1
    children = {e["child_name"] for e in result["edges"]}
    assert "com.example:lib-b" in children  # the real location is edged
    # the omitted reference produced no edge from lib-a
    assert all(e["parent_name"] != "com.example:lib-a"
               for e in result["edges"])


def test_malformed_tree_is_disclosed_not_fatal(tmp_path):
    result = extract(_write(tmp_path, "\x00\x01 not a tree"))
    assert result["graph_status"] == "EXTRACTION_ERROR"
    assert result["edges"] == []


def test_deterministic_output(tmp_path):
    path = _write(tmp_path, CHAIN)
    a = extract(path)
    b = extract(path)
    assert json.dumps(a["edges"], sort_keys=True) == \
        json.dumps(b["edges"], sort_keys=True)


def test_pom_xml_never_produces_edges(tmp_path):
    # Manifest declarations are direct-only and properties/ranges are
    # unresolved -- a pom must answer UNSUPPORTED with disclosure.
    result = registry.extract_for_file(
        _write(tmp_path,
               "<project><dependencies>"
               "<dependency><groupId>junit</groupId></dependency>"
               "</dependencies></project>",
               name="pom.xml"))
    assert result["graph_status"] == "UNSUPPORTED_FORMAT"
    assert result["edges"] == []
    assert any("dependency:tree" in str(l) for l in result["limitations"])


def test_gradle_buildfile_never_produces_edges(tmp_path):
    result = registry.extract_for_file(
        _write(tmp_path, "plugins { id 'java' }", name="build.gradle"))
    assert result["graph_status"] == "UNSUPPORTED_FORMAT"
    assert result["edges"] == []


def test_empty_tree_yields_no_edges(tmp_path):
    result = extract(_write(tmp_path, "com.example:app:jar:1.0.0\n"))
    assert result["graph_status"] == "NO_VERIFIED_EDGES"
    assert result["edges"] == []


def test_optional_marker_from_real_maven_output(tmp_path):
    # Real shape (WebGoat tree, freshly generated offline 2026-11-12):
    # optional dependencies carry a trailing "(optional)" marker after the
    # scope -- it must map to scope=optional, not corrupt the version.
    tree = """com.example:app:jar:1.0.0
+- org.projectlombok:lombok:jar:1.18.46:provided (optional)
"""
    result = extract(_write(tmp_path, tree))
    assert result["verified_edge_count"] == 1
    edge = result["edges"][0]
    assert edge["child_version"] == "1.18.46"
    assert edge["confidence"] == "VERIFIED"
    assert edge["scope"] == "optional"
    assert edge["qualifiers"]["scope_declared"] == "provided"
