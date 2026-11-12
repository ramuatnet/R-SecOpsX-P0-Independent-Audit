"""Gradle verified-edge extractor (R2.2, evidence tier: resolved-evidence-required).

Evidence basis: `gradle dependencies` output declares parent-child pairs
with resolved versions per configuration. Gradle prints NO root project
line, so level-1 entries under a configuration header are the project's
DIRECT declarations -- they are counted, never given an invented parent
(no synthetic root for non-npm ecosystems, per the R2.0 approval).
Transitive parentage starts at depth >= 2 from the decoration tree.

`(*)` markers mean "subtree already printed" -- the dependency itself is
still a real edge and is kept. `(c)` constraints and `(n)` unresolved
markers are disclosed. `project :module` references have no registry
identity -- skipped and tallied. Conflict resolutions ("-> selected")
carry the selected version.
"""

import json

from analysis.lock_graph import registry
from analysis.lock_graph.gradle import extract


def _write(tmp_path, text, name="gradle-dependencies.txt"):
    f = tmp_path / name
    f.write_text(text, encoding="utf-8")
    return str(f)


RUNTIME = """\
> Task :app:dependencies

runtimeClasspath
+--- com.fasterxml.jackson.core:jackson-databind:2.13.0
|    +--- com.fasterxml.jackson.core:jackson-core:2.13.0
|    \\--- com.fasterxml.jackson.core:jackson-annotations:2.13.0
\\--- org.slf4j:slf4j-api:1.7.32

testRuntimeClasspath
+--- org.junit.jupiter:junit-jupiter:5.8.2
|    \\--- org.junit.jupiter:junit-jupiter-api:5.8.2
\\--- com.fasterxml.jackson.core:jackson-databind:2.13.0
|    \\--- com.fasterxml.jackson.core:jackson-core:2.13.0
"""


def test_transitive_edges_resolve_with_configurations(tmp_path):
    result = extract(_write(tmp_path, RUNTIME))
    assert result["graph_status"] == "VERIFIED_EDGES_AVAILABLE"
    edges = {(e["parent_name"], e["child_name"]): e for e in result["edges"]}
    dj = edges[("com.fasterxml.jackson.core:jackson-databind",
                "com.fasterxml.jackson.core:jackson-core")]
    assert dj["child_version"] == "2.13.0"
    assert dj["confidence"] == "VERIFIED"
    assert dj["evidence_source"] == "GRADLE_DEPENDENCIES"
    assert dj["parent_purl"] == \
        "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.0"


def test_configuration_qualifiers_merge_on_dedupe(tmp_path):
    # jackson-databind -> jackson-annotations appears under BOTH
    # configurations? (databind's subtree repeats) -- one deduped edge,
    # configurations merged, duplicates tallied.
    result = extract(_write(tmp_path, RUNTIME))
    edges = {(e["parent_name"], e["child_name"]): e
             for e in result["edges"]
             if e["child_name"] == "com.fasterxml.jackson.core:jackson-core"}
    dj = edges[("com.fasterxml.jackson.core:jackson-databind",
                "com.fasterxml.jackson.core:jackson-core")]
    assert "runtimeClasspath" in dj["qualifiers"]["configurations"]
    assert result["tallies"]["duplicate_records_dropped"] == 1


def test_level1_direct_declarations_are_counted_not_edged(tmp_path):
    # Gradle prints no root project line: level-1 entries are the
    # project's direct declarations -- no invented parent (R2.0 approval:
    # no synthetic root for non-npm ecosystems).
    result = extract(_write(tmp_path, RUNTIME))
    level1 = [e for e in result["edges"]
              if e["child_name"] in
              ("com.fasterxml.jackson.core:jackson-databind",
               "org.slf4j:slf4j-api", "org.junit.jupiter:junit-jupiter")]
    assert level1 == []
    assert result["tallies"]["direct_declarations"] == 4


def test_registry_dispatches_gradle_output(tmp_path):
    result = registry.extract_for_file(_write(tmp_path, RUNTIME))
    assert result["engine"] == "GRADLE_DEPENDENCIES_V1"
    assert result["verified_edge_count"] == len(result["edges"]) > 0


def test_multi_parent_across_configurations(tmp_path):
    tree = """\
> Task :app:dependencies

compileClasspath
+--- parent-one:lib:1.0
|    \\--- shared:shared-lib:5.0.0

testClasspath
+--- parent-two:lib:2.0
|    \\--- shared:shared-lib:5.0.0
"""
    result = extract(_write(tmp_path, tree))
    parents = sorted(e["parent_name"] for e in result["edges"]
                     if e["child_name"] == "shared:shared-lib")
    assert parents == ["parent-one:lib", "parent-two:lib"]


def test_duplicate_versions_in_different_branches(tmp_path):
    tree = """\
> Task :app:dependencies

runtimeClasspath
+--- old-user:lib:1.0
|    \\--- shared:lib:1.0.0
\\--- new-user:lib:1.0
     \\--- shared:lib:2.0.0
"""
    result = extract(_write(tmp_path, tree))
    got = {(e["parent_name"], e["child_version"])
           for e in result["edges"] if e["child_name"] == "shared:lib"}
    assert got == {("old-user:lib", "1.0.0"), ("new-user:lib", "2.0.0")}


def test_star_marker_edge_is_real_and_kept(tmp_path):
    # (*) means "subtree already printed" -- the dependency still exists.
    tree = """\
> Task :app:dependencies

runtimeClasspath
+--- parent-one:lib:1.0
|    \\--- shared:lib:5.0.0
\\--- parent-two:lib:1.0
     \\--- shared:lib:5.0.0 (*)
"""
    result = extract(_write(tmp_path, tree))
    got = {(e["parent_name"], e["child_version"])
           for e in result["edges"] if e["child_name"] == "shared:lib"}
    assert got == {("parent-one:lib", "5.0.0"), ("parent-two:lib", "5.0.0")}


def test_conflict_resolution_uses_selected_version(tmp_path):
    tree = """\
> Task :app:dependencies

runtimeClasspath
+--- parent:lib:1.0
|    \\--- shared:lib:1.0.0 -> 2.0.0
"""
    result = extract(_write(tmp_path, tree))
    edge = result["edges"][0]
    assert edge["child_version"] == "2.0.0"
    assert edge["qualifiers"]["requested_version"] == "1.0.0"
    assert edge["qualifiers"]["conflict_resolved"] == "true"


def test_project_references_skipped_and_counted(tmp_path):
    tree = """\
> Task :app:dependencies

runtimeClasspath
+--- project :core
|    \\--- org.apache.commons:commons-lang3:3.12.0
\\--- project :util
"""
    result = extract(_write(tmp_path, tree))
    assert result["tallies"]["unsupported"] == 2
    children = {e["child_name"] for e in result["edges"]}
    assert "org.apache.commons:commons-lang3" in children
    assert all(not c.startswith("project ") for c in children)


def test_malformed_output_is_disclosed_not_fatal(tmp_path):
    # undecorated garbage is honestly an empty tree (NO_VERIFIED_EDGES);
    # a decorated line with an unparseable node is the error case.
    empty = extract(_write(tmp_path, "\x00\x01 garbage"))
    assert empty["graph_status"] == "NO_VERIFIED_EDGES"
    assert empty["edges"] == []
    broken = extract(_write(tmp_path, "runtimeClasspath\n+--- :::: \n"))
    assert broken["graph_status"] == "EXTRACTION_ERROR"
    assert broken["edges"] == []
    assert broken["limitations"]


def test_deterministic_output(tmp_path):
    path = _write(tmp_path, RUNTIME)
    a = extract(path)
    b = extract(path)
    assert json.dumps(a["edges"], sort_keys=True) == \
        json.dumps(b["edges"], sort_keys=True)


def test_gradle_lockfile_is_membership_only_disclosure(tmp_path):
    lock = _write(tmp_path,
                  "com.fasterxml.jackson.core:jackson-databind:2.13.0="
                  "runtimeClasspath\n"
                  "org.slf4j:slf4j-api:1.7.32=runtimeClasspath\n",
                  name="gradle.lockfile")
    result = registry.extract_for_file(lock)
    assert result["graph_status"] == "UNSUPPORTED_FORMAT"
    assert result["edges"] == []
    assert result["membership_packages"] == 2
    assert any("membership" in str(l).lower() for l in result["limitations"])
