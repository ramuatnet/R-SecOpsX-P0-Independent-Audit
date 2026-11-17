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

import pytest

from analysis.lock_graph import registry
from analysis.lock_graph.gradle import extract


from pathlib import Path


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
    # a decorated line with an unparseable LEAF is disclosed (F-RG-2 §5
    # hardening: tally + limitation) and is not fatal -- the fatal case is
    # an unparseable node WITH a subtree (test_frg2_s14).
    empty = extract(_write(tmp_path, "\x00\x01 garbage"))
    assert empty["graph_status"] == "NO_VERIFIED_EDGES"
    assert empty["edges"] == []
    broken = extract(_write(tmp_path, "runtimeClasspath\n+--- :::: \n"))
    assert broken["graph_status"] != "EXTRACTION_ERROR"
    assert broken["edges"] == []
    assert broken["tallies"]["invalid_nodes"] == 1
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


# -- R2.6.1: Gradle (n)/(c) marker evidence semantics (red-first) -------------

N_TREE = """\
> Task :app:dependencies

runtimeClasspath
+--- org.gradle.test:gd-a:1.0.0
|    \\--- org.gradle.test:gd-c:3.0.0 (n)
|         \\--- org.gradle.test:gd-d:4.0.0
\\--- org.gradle.test:gd-b:2.0.0
|    \\--- org.gradle.test:gd-e:5.0.0
"""


def test_n_marker_child_is_unresolved_not_verified(tmp_path):
    # (n) = the requested version was NOT resolved: the edge is disclosed
    # UNRESOLVED with the requested version as a qualifier -- never VERIFIED
    # at the requested version (R2.6.1; F-1 from the R2 final closure audit).
    result = extract(_write(tmp_path, N_TREE))
    edge = [e for e in result["edges"] if e["child_name"] == "org.gradle.test:gd-c"][0]
    assert edge["confidence"] == "UNRESOLVED"
    assert edge["child_version"] == ""
    assert edge["qualifiers"]["requested_version"] == "3.0.0"
    assert edge["resolution_status"] == "GRADLE_VERSION_NOT_RESOLVED"


def test_n_marker_requested_version_never_promoted(tmp_path):
    result = extract(_write(tmp_path, N_TREE))
    edge = [e for e in result["edges"] if e["child_name"] == "org.gradle.test:gd-c"][0]
    assert edge["child_version"] != "3.0.0"
    assert edge["child_purl"] == ""


def test_n_marker_parent_is_unresolved_not_invented(tmp_path):
    # an (n) node used as a PARENT has no resolved identity either: edges
    # FROM it are disclosed UNRESOLVED with an empty parent version.
    tree = """\
> Task :app:dependencies

runtimeClasspath
+--- org.gradle.test:gd-c:3.0.0 (n)
|    \\--- org.gradle.test:gd-d:4.0.0
"""
    result = extract(_write(tmp_path, tree))
    assert len(result["edges"]) == 1
    edge = result["edges"][0]
    assert edge["parent_name"] == "org.gradle.test:gd-c"
    assert edge["parent_version"] == ""
    assert edge["child_name"] == "org.gradle.test:gd-d"
    assert edge["confidence"] == "UNRESOLVED"
    assert edge["qualifiers"]["parent_requested_version"] == "3.0.0"
    assert edge["resolution_status"] == "GRADLE_VERSION_NOT_RESOLVED"


def test_n_marker_edge_mints_no_fingerprint(tmp_path):
    # fingerprints exist only for VERIFIED identities (contract); an
    # unresolved (n) edge carries none.
    result = extract(_write(tmp_path, N_TREE))
    edge = [e for e in result["edges"] if e["child_name"] == "org.gradle.test:gd-c"][0]
    assert "fingerprint" not in edge


def test_resolved_sibling_in_same_tree_stays_verified(tmp_path):
    # preservation: resolved edges around the (n) marker keep their
    # resolved semantics and identity-stable fingerprints. The (n) node's
    # OWN subtree edge is parent-side-unresolved (see the dedicated test
    # above) and stays out of the VERIFIED set.
    result = extract(_write(tmp_path, N_TREE))
    verified = {(e["parent_name"], e["child_name"], e["child_version"])
                for e in result["edges"] if e["confidence"] == "VERIFIED"}
    assert verified == {
        ("org.gradle.test:gd-b", "org.gradle.test:gd-e", "5.0.0"),
    }
    for e in result["edges"]:
        if e["confidence"] == "VERIFIED":
            assert e["fingerprint"].startswith("sha256:")
    child_edge = [e for e in result["edges"]
                  if e["child_name"] == "org.gradle.test:gd-d"][0]
    assert child_edge["confidence"] == "UNRESOLVED"
    assert child_edge["qualifiers"]["parent_requested_version"] == "3.0.0"


def test_c_marker_constraint_entry_is_disclosed_not_verified(tmp_path):
    # R2.6.2: (c) marks a DEPENDENCY CONSTRAINT, not a dependency (Gradle
    # userguide). The constraint version is never promoted: the entry is
    # disclosed UNRESOLVED with the constraint version as a qualifier.
    # (Rewritten from the R2.6.1-era test that pinned the pre-docs
    # VERIFIED classification -- disclosed test correction.)
    tree = """> Task :app:dependencies

runtimeClasspath
+--- org.gradle.test:gd-parent:1.0.0
|    \--- org.gradle.test:gd-constrained:2.0.0 (c)
"""
    result = extract(_write(tmp_path, tree))
    edge = result["edges"][0]
    assert edge["confidence"] == "UNRESOLVED"
    assert edge["child_version"] == ""
    assert edge["qualifiers"]["constraint_version"] == "2.0.0"
    assert edge["resolution_status"] == "GRADLE_CONSTRAINT_ENTRY_NOT_DEPENDENCY"
    assert "fingerprint" not in edge


def test_not_resolved_markers_are_tallied(tmp_path):
    result = extract(_write(tmp_path, N_TREE))
    assert result["tallies"]["not_resolved_markers"] == 1


def test_versionless_node_is_disclosed_not_verified(tmp_path):
    # an ambiguous/missing version never silently resolves (contract
    # downgrade path, exercised through gradle's identity split).
    tree = """\
> Task :app:dependencies

runtimeClasspath
+--- org.gradle.test:gd-parent:1.0.0
|    \\--- org.gradle.test:gd-loose:1.0 -> 
"""
    result = extract(_write(tmp_path, tree))
    edge = result["edges"][0]
    assert edge["confidence"] == "UNRESOLVED"
    assert edge["child_version"] == ""


# -- R2.6.2: Gradle (c) constraint-entry semantics (red-first) ----------------
#
# (c) marks a DEPENDENCY CONSTRAINT, not a dependency (Gradle userguide:
# "This element is a dependency constraint, not a dependency. Look for
# the matching dependency elsewhere in the tree."). Constraint entries
# are disclosed as UNRESOLVED non-dependency evidence -- never VERIFIED,
# never promoted, no fingerprint -- mirroring the R2.6.1 (n) pattern.

C_TREE = """\
> Task :app:dependencies

runtimeClasspath
+--- org.gradle.test:gd-parent:1.0.0
|    \\--- org.gradle.test:gd-constrained:2.0.0 (c)
\\--- org.gradle.test:gd-real:3.0.0
|    \\--- org.gradle.test:gd-dep:4.0.0
"""


def _constraint_edge(result):
    return [e for e in result["edges"]
            if e["child_name"] == "org.gradle.test:gd-constrained"][0]


def test_constraint_only_entry_is_unresolved_not_verified(tmp_path):
    # (c) = constraint entry, NOT a dependency: UNRESOLVED disclosure
    # edge with the constraint version retained as a qualifier.
    result = extract(_write(tmp_path, C_TREE))
    e = _constraint_edge(result)
    assert e["confidence"] == "UNRESOLVED"
    assert e["child_version"] == ""
    assert e["qualifiers"]["constraint_version"] == "2.0.0"
    assert e["resolution_status"] == "GRADLE_CONSTRAINT_ENTRY_NOT_DEPENDENCY"


def test_constraint_version_never_promoted(tmp_path):
    result = extract(_write(tmp_path, C_TREE))
    e = _constraint_edge(result)
    assert e["child_version"] != "2.0.0"
    assert e["child_purl"] == ""


def test_constraint_edge_mints_no_fingerprint(tmp_path):
    result = extract(_write(tmp_path, C_TREE))
    assert "fingerprint" not in _constraint_edge(result)


def test_constraint_plus_matching_resolved_dependency(tmp_path):
    # the constraint line discloses; the REAL resolved dependency (printed
    # on its own line elsewhere in the tree) stays VERIFIED from its own
    # evidence -- no evidence lost, no fabrication.
    tree = """\
> Task :app:dependencies

runtimeClasspath
+--- org.gradle.test:gd-parent:1.0.0
|    \\--- org.gradle.test:gd-constrained:2.0.0 (c)
\\--- org.gradle.test:gd-other:1.1.0
|    \\--- org.gradle.test:gd-constrained:2.0.0
"""
    result = extract(_write(tmp_path, tree))
    disc = [e for e in result["edges"]
            if e["child_name"] == "org.gradle.test:gd-constrained"]
    assert {e["confidence"] for e in disc} == {"UNRESOLVED", "VERIFIED"}
    resolved = [e for e in disc if e["confidence"] == "VERIFIED"][0]
    assert resolved["child_version"] == "2.0.0"
    assert resolved["fingerprint"].startswith("sha256:")


def test_constraint_plus_unrelated_same_module_name(tmp_path):
    # a different group's same-named module must not be captured by the
    # constraint's identity.
    tree = """\
> Task :app:dependencies

runtimeClasspath
+--- org.gradle.test:gd-parent:1.0.0
|    \\--- org.gradle.test:common:1.0.0 (c)
\\--- org.gradle.test:gd-real:3.0.0
|    \\--- org.other:common:1.0.0
"""
    result = extract(_write(tmp_path, tree))
    by_child = {e["child_name"]: e["confidence"]
                for e in result["edges"]}
    assert by_child["org.gradle.test:common"] == "UNRESOLVED"
    assert by_child["org.other:common"] == "VERIFIED"


def test_constraint_plus_different_resolved_version(tmp_path):
    # the constraint version is NOT promoted even when a different
    # version of the module is resolved elsewhere.
    tree = """\
> Task :app:dependencies

runtimeClasspath
+--- org.gradle.test:gd-parent:1.0.0
|    \\--- org.gradle.test:gd-constrained:2.0.0 (c)
\\--- org.gradle.test:gd-real:3.0.0
|    \\--- org.gradle.test:gd-constrained:2.5.0
"""
    result = extract(_write(tmp_path, tree))
    edges = {(e["child_version"], e["confidence"])
             for e in result["edges"]
             if e["child_name"] == "org.gradle.test:gd-constrained"}
    assert edges == {("", "UNRESOLVED"), ("2.5.0", "VERIFIED")}


def test_multiple_resolved_candidates_with_constraint(tmp_path):
    # two resolved instances of the constrained module: both stay
    # VERIFIED from their own lines; the constraint stays a disclosure.
    tree = """\
> Task :app:dependencies

runtimeClasspath
+--- org.gradle.test:gd-parent:1.0.0
|    \\--- org.gradle.test:gd-constrained:2.0.0 (c)
\\--- org.gradle.test:gd-real:3.0.0
|    \\--- org.gradle.test:gd-constrained:2.0.0
     \\--- org.gradle.test:gd-inner:1.0.0
\\--- org.gradle.test:gd-real2:4.0.0
|    \\--- org.gradle.test:gd-constrained:2.5.0
"""
    result = extract(_write(tmp_path, tree))
    disc = [e for e in result["edges"]
            if e["child_name"] == "org.gradle.test:gd-constrained"]
    assert sum(1 for e in disc if e["confidence"] == "VERIFIED") == 2
    assert sum(1 for e in disc
               if e["confidence"] == "UNRESOLVED"
               and e["resolution_status"]
               == "GRADLE_CONSTRAINT_ENTRY_NOT_DEPENDENCY") == 1


def test_parent_side_constraint_is_unresolved(tmp_path):
    # a constraint entry used as a PARENT has no resolved identity: edges
    # FROM it are disclosed UNRESOLVED with the constraint version.
    tree = """\
> Task :app:dependencies

runtimeClasspath
+--- org.gradle.test:gd-constrained:2.0.0 (c)
|    \\--- org.gradle.test:gd-d:4.0.0
"""
    result = extract(_write(tmp_path, tree))
    assert len(result["edges"]) == 1
    e = result["edges"][0]
    assert e["parent_name"] == "org.gradle.test:gd-constrained"
    assert e["parent_version"] == ""
    assert e["child_name"] == "org.gradle.test:gd-d"
    assert e["confidence"] == "UNRESOLVED"
    assert e["qualifiers"]["parent_constraint_version"] == "2.0.0"
    assert e["resolution_status"] == "GRADLE_CONSTRAINT_ENTRY_NOT_DEPENDENCY"


def test_child_side_constraint_under_parent(tmp_path):
    # child-side constraint: disclosed against its printed parent.
    result = extract(_write(tmp_path, C_TREE))
    e = _constraint_edge(result)
    assert e["parent_name"] == "org.gradle.test:gd-parent"
    assert e["parent_version"] == "1.0.0"
    assert e["confidence"] == "UNRESOLVED"


def test_constraint_under_different_configurations_dedupes(tmp_path):
    tree = """\
> Task :app:dependencies

runtimeClasspath
+--- org.gradle.test:gd-parent:1.0.0
|    \\--- org.gradle.test:gd-constrained:2.0.0 (c)

testClasspath
+--- org.gradle.test:gd-parent:1.0.0
|    \\--- org.gradle.test:gd-constrained:2.0.0 (c)
"""
    result = extract(_write(tmp_path, tree))
    disc = [e for e in result["edges"]
            if e["child_name"] == "org.gradle.test:gd-constrained"]
    assert len(disc) == 1
    assert disc[0]["confidence"] == "UNRESOLVED"
    assert "runtimeClasspath" in disc[0]["qualifiers"]["configurations"]
    assert result["tallies"]["constraint_entries"] == 2


def test_constraint_combined_with_n_marker(tmp_path):
    # defensive: (n) takes precedence (the version is not resolved);
    # the constraint marker is still disclosed.
    tree = """\
> Task :app:dependencies

runtimeClasspath
+--- org.gradle.test:gd-parent:1.0.0
|    \\--- org.gradle.test:gd-weird:1.0.0 (c) (n)
"""
    result = extract(_write(tmp_path, tree))
    e = result["edges"][0]
    assert e["confidence"] == "UNRESOLVED"
    assert e["resolution_status"] == "GRADLE_VERSION_NOT_RESOLVED"
    assert e["qualifiers"]["requested_version"] == "1.0.0"


def test_malformed_constraint_output_is_disclosed(tmp_path):
    # a malformed constraint line is disclosed, never fabricated.
    # (F-RG-2 §5 hardening: an unparseable LEAF no longer blanks the whole
    # file -- it is tallied (`invalid_nodes`) and named in `limitations`,
    # while the rest of the file still extracts.  The with-subtree case
    # keeps the fatal error; see test_frg2_s14.)
    tree = """\
> Task :app:dependencies

runtimeClasspath
+--- org.gradle.test:gd-parent:1.0.0
|    \\--- org.gradle.test:gd-bad: (c)
"""
    result = extract(_write(tmp_path, tree))
    assert result["graph_status"] != "EXTRACTION_ERROR"
    assert result["edges"] == []
    assert result["tallies"]["invalid_nodes"] == 1
    assert result["limitations"]


def test_repeated_constraint_entries_tallied(tmp_path):
    tree = """\
> Task :app:dependencies

runtimeClasspath
+--- org.gradle.test:gd-parent:1.0.0
|    \\--- org.gradle.test:gd-constrained:2.0.0 (c)
|    \\--- org.gradle.test:gd-constrained:2.0.0 (c)
"""
    result = extract(_write(tmp_path, tree))
    disc = [e for e in result["edges"]
            if e["child_name"] == "org.gradle.test:gd-constrained"]
    assert len(disc) == 1 and disc[0]["confidence"] == "UNRESOLVED"
    assert result["tallies"]["constraint_entries"] == 2


def test_depth1_constraint_not_counted_as_direct_declaration(tmp_path):
    # a depth-1 constraint line is a CONSTRAINT, not one of the project's
    # direct dependencies.
    tree = """\
> Task :app:dependencies

runtimeClasspath
+--- org.gradle.test:gd-constrained:2.0.0 (c)
\\--- org.gradle.test:gd-real:3.0.0
|    \\--- org.gradle.test:gd-dep:4.0.0
"""
    result = extract(_write(tmp_path, tree))
    assert result["tallies"]["direct_declarations"] == 1
    assert result["tallies"]["constraint_entries"] == 1
    # a depth-1 line is never edged (no parent exists to disclose from):
    # the constraint disclosure is the tally itself.
    assert all(e["child_name"] != "org.gradle.test:gd-constrained"
               for e in result["edges"])


def test_resolved_dependencies_around_constraints_unchanged(tmp_path):
    # preservation: resolved edges keep their semantics and fingerprints.
    result = extract(_write(tmp_path, C_TREE))
    verified = {(e["parent_name"], e["child_name"], e["child_version"])
                for e in result["edges"] if e["confidence"] == "VERIFIED"}
    assert verified == {
        ("org.gradle.test:gd-real", "org.gradle.test:gd-dep", "4.0.0"),
    }


# ---------------------------------------------------------------------------
# F-RG-2: platform/BOM-selected version shape `group:artifact -> selected`
# (conflict-resolution arrow with NO requested version on the left).
# Fixtures are VERBATIM lines from the preserved real reports (line refs in
# comments): audit_output/real_gradle/micrometer/raw_dependencies.txt and
# .../mockito/raw_dependencies.txt.  Proposal (source of truth):
# audit_output/F_RG_2_REMEDIATION_PROPOSAL.md.  F-RG-1 (conflict+elision on
# the 3-part path) was deliberately NOT fixed by F-RG-2 and was pinned by
# test_frg2_s8_conflict_marker_semantics_untouched; the authorized F-RG-1
# remediation (2026-11-17) rewrote that pin in place to the remediated
# semantics and adds the F-RG-1 matrix block below.
# ---------------------------------------------------------------------------

# micrometer:218-228 verbatim -- netty BOM constraints + platform node +
# its subtree (the block whose pre-fix EXTRACTION_ERROR blanked the file).
FRG2_NETTY_TREE = """\
> Task :app:dependencies

runtimeClasspath
+--- io.netty:netty-bom:4.2.20.Final
|    +--- io.netty:netty-transport:4.2.20.Final (c)
|    +--- io.netty:netty-common:4.2.20.Final (c)
|    +--- io.netty:netty-buffer:4.2.20.Final (c)
|    \\--- io.netty:netty-resolver:4.2.20.Final (c)
+--- io.netty:netty-transport -> 4.2.20.Final
|    +--- io.netty:netty-common:4.2.20.Final
|    +--- io.netty:netty-buffer:4.2.20.Final
|    |    \\--- io.netty:netty-common:4.2.20.Final
|    \\--- io.netty:netty-resolver:4.2.20.Final
|         \\--- io.netty:netty-common:4.2.20.Final
"""

# micrometer:313-318 verbatim -- platform BOM node with (c) children.
FRG2_KOTLIN_BOM_TREE = """\
> Task :app:dependencies

runtimeClasspath
+--- org.jetbrains.kotlin:kotlin-bom -> 2.4.21
|    +--- org.jetbrains.kotlin:kotlin-stdlib-jdk8:2.4.21 (c)
|    +--- org.jetbrains.kotlin:kotlin-reflect:2.4.21 (c)
|    +--- org.jetbrains.kotlin:kotlin-stdlib:2.4.21 (c)
|    +--- org.jetbrains.kotlin:kotlin-stdlib-jdk7:2.4.21 (c)
|    \\--- org.jetbrains.kotlin:kotlin-stdlib-common:2.4.21 (c)
"""

# micrometer:313-321 verbatim -- the BOM block plus the platform+elision
# combo line and the plain 3-part elision child (existing (*) semantics).
FRG2_KOTLIN_COMBO_TREE = """\
> Task :app:dependencies

runtimeClasspath
+--- org.jetbrains.kotlin:kotlin-bom -> 2.4.21
|    +--- org.jetbrains.kotlin:kotlin-stdlib-jdk8:2.4.21 (c)
|    +--- org.jetbrains.kotlin:kotlin-reflect:2.4.21 (c)
|    +--- org.jetbrains.kotlin:kotlin-stdlib:2.4.21 (c)
|    +--- org.jetbrains.kotlin:kotlin-stdlib-jdk7:2.4.21 (c)
|    \\--- org.jetbrains.kotlin:kotlin-stdlib-common:2.4.21 (c)
+--- org.jetbrains.kotlin:kotlin-reflect -> 2.4.21
|    \\--- org.jetbrains.kotlin:kotlin-stdlib:2.4.21 (*)
+--- org.jetbrains.kotlin:kotlin-stdlib-jdk8 -> 2.4.21 (*)
"""

# micrometer:15 + :1504 composed at their real depths (depth-1 registry
# parent + the report's only depth>=2 platform+elision line).
FRG2_JUNIT_TREE = """\
> Task :app:dependencies

runtimeClasspath
+--- com.google.errorprone:error_prone_core:2.52.0
|    +--- org.junit.jupiter:junit-jupiter -> 5.14.4 (*)
"""

# mockito:114-119 verbatim -- the F-RG-1 conflict+elision block (used as
# the preservation fixture: direct accounting AND the pinned F-RG-1 state).
FRG2_MOCKITO_TREE = """\
> Task :app:dependencies

runtimeClasspath
+--- com.google.googlejavaformat:google-java-format:1.27.0
|    \\--- com.google.guava:guava:32.1.3-jre -> 33.4.0-jre (*)
+--- com.google.auto:auto-common:1.2.2
|    \\--- com.google.guava:guava:32.0.1-jre -> 33.4.0-jre (*)
+--- com.google.guava:guava:33.4.0-jre (*)
"""


def _load_oracle():
    import importlib.util
    from pathlib import Path as _P
    spec = importlib.util.spec_from_file_location(
        "oracle_gradle_frg2",
        _P(__file__).resolve().parent.parent / "tools" / "oracle_gradle.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_frg2_s1_depth1_platform_selection(tmp_path):
    # matrix #1 (micrometer:223): the depth-1 platform node parses and is
    # counted as a direct declaration -- pre-fix this whole file was
    # EXTRACTION_ERROR (edges=[]).
    result = extract(_write(tmp_path, FRG2_NETTY_TREE))
    assert result["graph_status"] == "VERIFIED_EDGES_AVAILABLE", \
        result.get("limitations")
    assert result["tallies"]["direct_declarations"] == 2  # netty-bom +
    # netty-transport (platform node: level-1 = direct, never edged)
    # R2.6.2 constraint children of the BOM are unchanged (preservation):
    cons = [e for e in result["edges"]
            if e["resolution_status"] == "GRADLE_CONSTRAINT_ENTRY_NOT_DEPENDENCY"]
    assert len(cons) == 4


def test_frg2_s2_platform_bom_node(tmp_path):
    # matrix #2 (micrometer:313): platform BOM node parses; its (c)
    # children stay R2.6.2 constraint disclosures.
    result = extract(_write(tmp_path, FRG2_KOTLIN_BOM_TREE))
    assert result["graph_status"] != "EXTRACTION_ERROR", result.get("limitations")
    assert result["tallies"]["direct_declarations"] == 1  # kotlin-bom
    cons = [e for e in result["edges"]
            if e["resolution_status"] == "GRADLE_CONSTRAINT_ENTRY_NOT_DEPENDENCY"]
    assert len(cons) == 5
    assert all(e["confidence"] == "UNRESOLVED" for e in cons)


def test_frg2_s3_platform_elision_combo(tmp_path):
    # matrix #3 (micrometer:321): `g:a -> v (*)` -- platform selection
    # combined with subtree elision.  Depth-1 occurrence counts as a
    # direct declaration; the report's depth-2 3-part elision child keeps
    # the EXISTING (*) semantics (VERIFIED, clean version, subtree_elided).
    result = extract(_write(tmp_path, FRG2_KOTLIN_COMBO_TREE))
    assert result["graph_status"] == "VERIFIED_EDGES_AVAILABLE", \
        result.get("limitations")
    assert result["tallies"]["direct_declarations"] == 3  # bom + reflect +
    # stdlib-jdk8 (all three depth-1 platform nodes)
    edges = {(e["parent_name"], e["child_name"]): e for e in result["edges"]}
    plain = edges[("org.jetbrains.kotlin:kotlin-reflect",
                   "org.jetbrains.kotlin:kotlin-stdlib")]
    assert plain["child_version"] == "2.4.21"
    assert plain["confidence"] == "VERIFIED"
    assert plain["qualifiers"].get("subtree_elided") == "true"


def test_frg2_s4_subtree_parenting_under_platform_node(tmp_path):
    # matrix #4 (micrometer:223ff): children at depth>=2 parent to the
    # platform node's SELECTED identity.
    result = extract(_write(tmp_path, FRG2_NETTY_TREE))
    edges = {(e["parent_name"], e["parent_version"],
              e["child_name"], e["child_version"]): e
             for e in result["edges"]}
    for child in ("io.netty:netty-common", "io.netty:netty-buffer",
                  "io.netty:netty-resolver"):
        e = edges[("io.netty:netty-transport", "4.2.20.Final", child,
                   "4.2.20.Final")]
        assert e["confidence"] == "VERIFIED", e
        assert e["parent_purl"] == \
            "pkg:maven/io.netty/netty-transport@4.2.20.Final"
    # depth-3 parenting under a platform child is unchanged
    e = edges[("io.netty:netty-buffer", "4.2.20.Final",
               "io.netty:netty-common", "4.2.20.Final")]
    assert e["confidence"] == "VERIFIED"


def test_frg2_s5_platform_qualifier_disclosure(tmp_path):
    # matrix #5 (micrometer:1504): the platform edge discloses
    # version_selected_by_platform and NO requested_version (none was
    # printed -- never invented).
    result = extract(_write(tmp_path, FRG2_JUNIT_TREE))
    assert result["graph_status"] == "VERIFIED_EDGES_AVAILABLE", \
        result.get("limitations")
    edge = next(e for e in result["edges"]
                if e["child_name"] == "org.junit.jupiter:junit-jupiter")
    assert edge["child_version"] == "5.14.4"  # elision marker stripped
    assert edge["confidence"] == "VERIFIED"
    quals = edge["qualifiers"]
    assert quals.get("version_selected_by_platform") == "true"
    assert "requested_version" not in quals
    assert quals.get("subtree_elided") == "true"


def test_frg2_s6_platform_fingerprint_minted(tmp_path):
    # matrix #6: the platform edge carries an identity-stable fingerprint
    # (VERIFIED identities only, per the common contract).
    p = _write(tmp_path, FRG2_JUNIT_TREE)
    r1 = extract(p)
    r2 = extract(p)
    e1 = next(e for e in r1["edges"]
              if e["child_name"] == "org.junit.jupiter:junit-jupiter")
    e2 = next(e for e in r2["edges"]
              if e["child_name"] == "org.junit.jupiter:junit-jupiter")
    assert e1.get("fingerprint"), "VERIFIED platform edge must carry a fingerprint"
    assert e1["fingerprint"] == e2["fingerprint"]


def test_frg2_s7_direct_declarations_unchanged_for_depth1(tmp_path):
    # matrix #7 (mockito:114-119, preservation): depth-1 direct-declaration
    # accounting is untouched by the platform-shape work.
    result = extract(_write(tmp_path, FRG2_MOCKITO_TREE))
    assert result["tallies"]["direct_declarations"] == 3


def test_frg2_s8_conflict_combo_frg1_semantics(tmp_path):
    # matrix #8 of F-RG-2, REWRITTEN by the authorized F-RG-1 remediation
    # (2026-11-17; formerly test_frg2_s8_conflict_marker_semantics_untouched,
    # which pinned the pre-fix defect state -- UNRESOLVED, marker-
    # contaminated selected version, no fingerprint -- while F-RG-1 was
    # out of scope).  The 3-part conflict+elision combo now resolves at
    # the CLEAN selected version (VERIFIED, conflict_resolved +
    # subtree_elided, identity-stable fingerprint); the depth-1 direct-
    # declaration accounting is unchanged.
    result = extract(_write(tmp_path, FRG2_MOCKITO_TREE))
    assert result["tallies"]["direct_declarations"] == 3
    edges = {(e["parent_name"], e["child_name"]): e for e in result["edges"]}
    for parent, requested in (
            ("com.google.auto:auto-common", "32.0.1-jre"),
            ("com.google.googlejavaformat:google-java-format",
             "32.1.3-jre")):
        e = edges[(parent, "com.google.guava:guava")]
        assert e["child_version"] == "33.4.0-jre", e
        assert e["confidence"] == "VERIFIED", e
        assert e["qualifiers"]["requested_version"] == requested, e
        assert e["qualifiers"]["conflict_resolved"] == "true"
        assert e["qualifiers"]["subtree_elided"] == "true"
        assert e.get("fingerprint")


def test_frg2_s9_oracle_expects_platform_verified():
    # matrix #3 pairing: the independent oracle must parse the same shape
    # (pre-fix it silently skipped it -- the shared-assumption gap).
    og = _load_oracle()
    node = og.parse_node("io.netty:netty-transport -> 4.2.20.Final")
    assert node is not None
    assert node["name"] == "io.netty:netty-transport"
    assert node["version"] == "4.2.20.Final"
    assert not node.get("not_resolved") and not node.get("constraint")


def test_frg2_s10_oracle_platform_elision_strips_marker():
    # pairing for matrix #3 at depth>=2 (micrometer:1504).
    og = _load_oracle()
    node = og.parse_node("org.junit.jupiter:junit-jupiter -> 5.14.4 (*)")
    assert node is not None
    assert node["version"] == "5.14.4"


def test_frg2_s11_oracle_skip_orphan_not_misattributed(tmp_path):
    # matrix #3 pairing (§3.2): a skipped/unparseable parent must NOT
    # re-attribute its children to `direct` (the skip-orphan defect that
    # miscounted 54 subtree nodes on the real micrometer report).  The
    # 4-part body is unparseable to BOTH implementations (a stand-in for
    # any future unknown shape) so the skip mechanism itself is exercised
    # after the platform-shape fix removes the real-world skips.
    og = _load_oracle()
    tree = """\
> Task :app:dependencies

runtimeClasspath
+--- org.gradle.test:gd-parent:1.0.0
|    \\--- org.gradle.test:gd-bad:1.0:extra
|         \\--- org.gradle.test:gd-child:2.0.0
"""
    p = tmp_path / "gradle-dependencies.txt"
    p.write_text(tree, encoding="utf-8")
    _exp, _unres, _cons, direct = og.expected_edges(str(p))
    assert direct == 1, (
        "children of a skipped/unparseable parent must not be counted as "
        f"direct declarations (got {direct})")


def test_frg2_s12_oracle_two_direction(tmp_path):
    # matrix #3 pairing (§3.3): the oracle REJECTS a pre-fix-style payload
    # (empty edges -- the pre-fix extractor blanked these files) naming the
    # platform identity as MISSING, and ACCEPTS the post-fix extraction.
    import subprocess
    import sys
    from pathlib import Path as _P
    og_path = _P(__file__).resolve().parent.parent / "tools" / "oracle_gradle.py"
    tree = tmp_path / "gradle-dependencies.txt"
    tree.write_text(FRG2_JUNIT_TREE, encoding="utf-8")
    # (a) reject: empty payload
    empty = tmp_path / "prefix_edges.json"
    empty.write_text("[]", encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, "-I", str(og_path), str(tree), str(empty)],
        capture_output=True, text=True)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "org.junit.jupiter:junit-jupiter" in proc.stdout
    assert "MISSING (VERIFIED)" in proc.stdout
    # (b) accept: the extractor's own (post-fix) payload
    payload = tmp_path / "postfix_edges.json"
    payload.write_text(
        json.dumps(extract(str(tree))["edges"]), encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, "-I", str(og_path), str(tree), str(payload)],
        capture_output=True, text=True)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "ORACLE RESULT: PASS" in proc.stdout


def test_frg2_s13_unparseable_leaf_tallied_not_fatal(tmp_path):
    # §5 hardening: an unparseable LEAF is disclosed (limitation + invalid
    # tally) instead of blanking the whole evidence source; the rest of the
    # file still extracts.
    tree = """\
> Task :app:dependencies

runtimeClasspath
+--- org.gradle.test:gd-parent:1.0.0
|    +--- org.gradle.test:gd-child:2.0.0
|    \\--- org.gradle.test:gd-bad: (c)
"""
    result = extract(_write(tmp_path, tree))
    assert result["graph_status"] == "VERIFIED_EDGES_AVAILABLE", \
        result.get("limitations")
    assert result["tallies"]["invalid_nodes"] == 1
    assert any("gd-bad" in lim for lim in result["limitations"])
    kept = {(e["parent_name"], e["child_name"]) for e in result["edges"]}
    assert ("org.gradle.test:gd-parent", "org.gradle.test:gd-child") in kept


def test_frg2_s14_unparseable_with_subtree_still_fails(tmp_path):
    # §5 hardening (preservation half): an unparseable node WITH a subtree
    # keeps the fatal error -- the children's parentage is unknown and
    # detections must never differ.
    tree = """\
> Task :app:dependencies

runtimeClasspath
+--- org.gradle.test:gd-parent:1.0.0
|    \\--- org.gradle.test:gd-bad:
|         \\--- org.gradle.test:gd-child:2.0.0
"""
    result = extract(_write(tmp_path, tree))
    assert result["graph_status"] == "EXTRACTION_ERROR"
    assert result["edges"] == []
    assert result["limitations"]


# ---------------------------------------------------------------------------
# F-RG-1: conflict+elision combo `group:artifact:requested -> selected (*)`.
# Authorized 2026-11-17; the approved proposal
# audit_output/F_RG_1_REMEDIATION_PROPOSAL.md is the source of truth.
# Matrix rows #1-#7 are implemented 1:1 below (M1-M7).  M8 is the
# authorization-mandated F-RG-2/(c)/(n) compatibility pin; M9/M10 pin the
# proposal §2.5/§2.2 semantics definitions (an unknown marker after the
# arrow is strict-unparseable; a selected that is empty once the marker is
# stripped printed no resolved version).  The F-RG-2-era pin of the
# untouched defect state (test_frg2_s8_conflict_marker_semantics_untouched,
# above) is REWRITTEN in place to pin the remediated semantics -- that
# rewrite is the sanctioning change this authorization exists to make.
# ---------------------------------------------------------------------------

# mockito:114-115 and :118-119 verbatim line texts, composed at explicit
# depths (the report nests these blocks deeper under configuration
# subsections; the F-RG-2 fixtures compose verbatim line text at explicit
# depths -- same disclosed precedent).
FRG1_GJF_TREE = """\
> Task :app:dependencies

runtimeClasspath
+--- com.google.googlejavaformat:google-java-format:1.27.0
|    \\--- com.google.guava:guava:32.1.3-jre -> 33.4.0-jre (*)
"""

FRG1_AUTOCOMMON_TREE = """\
> Task :app:dependencies

runtimeClasspath
+--- com.google.auto:auto-common:1.2.2
|    \\--- com.google.guava:guava:32.0.1-jre -> 33.4.0-jre (*)
"""

FRG1_COMBO_TREE = """\
> Task :app:dependencies

runtimeClasspath
+--- com.google.googlejavaformat:google-java-format:1.27.0
|    \\--- com.google.guava:guava:32.1.3-jre -> 33.4.0-jre (*)
+--- com.google.auto:auto-common:1.2.2
|    \\--- com.google.guava:guava:32.0.1-jre -> 33.4.0-jre (*)
+--- com.google.guava:guava:33.4.0-jre (*)
"""

# The ACTUAL pre-fix extractor output for FRG1_COMBO_TREE (captured at the
# red phase on the pre-fix code, byte-embedded; full JSON also preserved at
# audit_output/frg1/logs/combo_prefix_edges.json): both combo edges emitted
# UNRESOLVED with the marker-contaminated child version, an empty
# resolution_status and no fingerprint.
FRG1_PREFIX_PAYLOAD = [
    {
        "ecosystem": "maven",
        "parent_name": "com.google.auto:auto-common",
        "parent_version": "1.2.2",
        "child_name": "com.google.guava:guava",
        "child_version": "33.4.0-jre (*)",
        "parent_purl": "pkg:maven/com.google.auto/auto-common@1.2.2",
        "child_purl": "",
        "source": "audit_output/frg1/logs/m_combo_fixture_tree.txt",
        "source_location": "runtimeClasspath depth 2",
        "evidence_source": "GRADLE_DEPENDENCIES",
        "scope": "runtime",
        "qualifiers": {
            "configuration": "runtimeClasspath",
            "requested_version": "32.0.1-jre",
            "conflict_resolved": "true",
        },
        "kind": "",
        "resolution_status": "",
        "confidence": "UNRESOLVED",
    },
    {
        "ecosystem": "maven",
        "parent_name": "com.google.googlejavaformat:google-java-format",
        "parent_version": "1.27.0",
        "child_name": "com.google.guava:guava",
        "child_version": "33.4.0-jre (*)",
        "parent_purl": "pkg:maven/com.google.googlejavaformat/"
                       "google-java-format@1.27.0",
        "child_purl": "",
        "source": "audit_output/frg1/logs/m_combo_fixture_tree.txt",
        "source_location": "runtimeClasspath depth 2",
        "evidence_source": "GRADLE_DEPENDENCIES",
        "scope": "runtime",
        "qualifiers": {
            "configuration": "runtimeClasspath",
            "requested_version": "32.1.3-jre",
            "conflict_resolved": "true",
        },
        "kind": "",
        "resolution_status": "",
        "confidence": "UNRESOLVED",
    },
]

_REAL_MOCKITO = (Path(__file__).resolve().parent.parent / "audit_output"
                 / "real_gradle" / "mockito" / "raw_dependencies.txt")


def test_frg1_m1_conflict_elision_resolves_clean_selected(tmp_path):
    # matrix #1 (mockito:114-115): `requested -> selected (*)` resolves at
    # the CLEAN selected version -- VERIFIED, `conflict_resolved` +
    # `subtree_elided` qualifiers, identity-stable fingerprint.  Pre-fix
    # the marker contaminated the version (UNRESOLVED, empty status, no
    # fingerprint).
    result = extract(_write(tmp_path, FRG1_GJF_TREE))
    assert result["graph_status"] == "VERIFIED_EDGES_AVAILABLE", \
        result.get("limitations")
    edge = result["edges"][0]
    assert edge["child_name"] == "com.google.guava:guava"
    assert edge["child_version"] == "33.4.0-jre", edge
    assert edge["confidence"] == "VERIFIED", edge
    assert edge["qualifiers"]["requested_version"] == "32.1.3-jre"
    assert edge["qualifiers"]["conflict_resolved"] == "true"
    assert edge["qualifiers"]["subtree_elided"] == "true"
    assert edge["child_purl"] == "pkg:maven/com.google.guava/guava@33.4.0-jre"
    assert edge.get("fingerprint"), "VERIFIED edge must carry a fingerprint"


def test_frg1_m2_conflict_elision_second_occurrence(tmp_path):
    # matrix #2 (mockito:118-119, the auto-common occurrence -- the shape
    # is parent-agnostic): identical remediated semantics.
    result = extract(_write(tmp_path, FRG1_AUTOCOMMON_TREE))
    edge = result["edges"][0]
    assert edge["child_version"] == "33.4.0-jre", edge
    assert edge["confidence"] == "VERIFIED", edge
    assert edge["qualifiers"]["requested_version"] == "32.0.1-jre"
    assert edge["qualifiers"]["subtree_elided"] == "true"


def test_frg1_m3_oracle_parses_clean_selected():
    # matrix #3 (O-RG-1 pairing): the independent oracle's parse of the
    # combo line expects the CLEAN selected version.  Pre-fix the oracle
    # expected the marker-carrying tuple (the O-RG-1 artifact).
    og = _load_oracle()
    node = og.parse_node(
        "com.google.guava:guava:32.1.3-jre -> 33.4.0-jre (*)")
    assert node is not None
    assert node["name"] == "com.google.guava:guava"
    assert node["version"] == "33.4.0-jre", node
    assert not node.get("not_resolved") and not node.get("constraint")


def test_frg1_m3b_oracle_genuine_two_direction(tmp_path):
    # matrix #3 (§3.3): genuine two-direction.  (a) The corrected oracle
    # REJECTS the ACTUAL pre-fix extractor output (captured verbatim at
    # the red phase, embedded above): the clean VERIFIED identities are
    # MISSING.  (b) The post-fix extraction is ACCEPTED (exit 0).
    import subprocess
    import sys
    from pathlib import Path as _P
    og_path = _P(__file__).resolve().parent.parent / "tools" / \
        "oracle_gradle.py"
    tree = tmp_path / "gradle-dependencies.txt"
    tree.write_text(FRG1_COMBO_TREE, encoding="utf-8")
    prefix = tmp_path / "prefix_edges.json"
    prefix.write_text(json.dumps(FRG1_PREFIX_PAYLOAD), encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, "-I", str(og_path), str(tree), str(prefix)],
        capture_output=True, text=True)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "MISSING (VERIFIED)" in proc.stdout
    assert "com.google.guava:guava" in proc.stdout
    assert "33.4.0-jre" in proc.stdout
    postfix = tmp_path / "postfix_edges.json"
    postfix.write_text(
        json.dumps(extract(str(tree))["edges"]), encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, "-I", str(og_path), str(tree), str(postfix)],
        capture_output=True, text=True)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "ORACLE RESULT: PASS" in proc.stdout


def test_frg1_m4_left_side_marker_depth1_direct_declaration(tmp_path):
    # matrix #4 (mockito:117, preservation): a marker on the LEFT side
    # only (`g:a:v (*)` at depth 1) keeps the direct-declaration
    # accounting -- never edged, never reclassified.
    tree = """\
> Task :app:dependencies

runtimeClasspath
+--- com.google.guava:guava:33.4.0-jre (*)
+--- org.example:other:1.0
"""
    result = extract(_write(tmp_path, tree))
    assert result["tallies"]["direct_declarations"] == 2
    assert result["edges"] == []


def test_frg1_m5_plain_conflict_unchanged(tmp_path):
    # matrix #5 (preservation): a plain conflict without a marker keeps
    # the existing VERIFIED + conflict_resolved semantics.
    tree = """\
> Task :app:dependencies

runtimeClasspath
+--- parent:lib:1.0
|    \\--- shared:lib:1.0.0 -> 2.0.0
"""
    result = extract(_write(tmp_path, tree))
    edge = result["edges"][0]
    assert edge["child_version"] == "2.0.0"
    assert edge["confidence"] == "VERIFIED"
    assert edge["qualifiers"]["requested_version"] == "1.0.0"
    assert edge["qualifiers"]["conflict_resolved"] == "true"
    assert "subtree_elided" not in edge["qualifiers"]


def test_frg1_m6_plain_elision_unchanged(tmp_path):
    # matrix #6 (preservation): a plain elision without a conflict keeps
    # the existing VERIFIED + subtree_elided semantics (no
    # conflict_resolved, no requested_version).
    tree = """\
> Task :app:dependencies

runtimeClasspath
+--- parent-one:lib:1.0
|    \\--- shared:lib:5.0.0
\\--- parent-two:lib:1.0
     \\--- shared:lib:5.0.0 (*)
"""
    result = extract(_write(tmp_path, tree))
    edges = {(e["parent_name"], e["child_version"]): e
             for e in result["edges"] if e["child_name"] == "shared:lib"}
    assert set(edges) == {("parent-one:lib", "5.0.0"),
                          ("parent-two:lib", "5.0.0")}
    star = edges[("parent-two:lib", "5.0.0")]
    assert star["confidence"] == "VERIFIED"
    assert star["qualifiers"]["subtree_elided"] == "true"
    assert "conflict_resolved" not in star["qualifiers"]


def test_frg1_m7_full_mockito_exact_reconciliation(tmp_path):
    # matrix #7: the FULL real mockito-core report reconciles EXACTLY
    # against the corrected oracle -- 103 VERIFIED (101 + the 2 combo
    # edges), 0 WRONG / 0 MISSING.  Pre-fix: 101 VERIFIED and the oracle
    # reported the 2 combo identities MISSING with marker-carrying
    # tuples.  Skipped (honestly) when the preserved real-corpus evidence
    # is absent from the checkout.
    if not _REAL_MOCKITO.exists():
        pytest.skip("real-corpus evidence not available in this checkout")
    import subprocess
    import sys
    from pathlib import Path as _P
    result = extract(str(_REAL_MOCKITO))
    verified = [e for e in result["edges"] if e["confidence"] == "VERIFIED"]
    assert len(verified) == 103, \
        f"expected 103 VERIFIED (101 + 2 combo), got {len(verified)}"
    combo = [e for e in result["edges"]
             if e["child_name"] == "com.google.guava:guava"
             and e["qualifiers"].get("conflict_resolved") == "true"]
    assert len(combo) == 2
    assert all(e["child_version"] == "33.4.0-jre" and
               e["qualifiers"].get("subtree_elided") == "true"
               for e in combo)
    og_path = _P(__file__).resolve().parent.parent / "tools" / \
        "oracle_gradle.py"
    payload = tmp_path / "edges.json"
    payload.write_text(json.dumps(result["edges"]), encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, "-I", str(og_path), str(_REAL_MOCKITO),
         str(payload)],
        capture_output=True, text=True)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "WRONG (VERIFIED):   0" in proc.stdout
    assert "MISSING (VERIFIED): 0" in proc.stdout
    assert "ORACLE RESULT: PASS" in proc.stdout


def test_frg1_m8_platform_and_marker_semantics_untouched(tmp_path):
    # authorization items 5-6 (compatibility pin): the F-RG-2 platform
    # path and the (c)/(n) semantics are unchanged by the F-RG-1 work.
    # The platform+elision combo (`g:a -> v (*)`, 2-part) keeps
    # version_selected_by_platform + subtree_elided and NEVER gains
    # conflict_resolved / requested_version; (c)/(n)-marked lines keep
    # their disclosures.
    result = extract(_write(tmp_path, FRG2_JUNIT_TREE))
    edge = next(e for e in result["edges"]
                if e["child_name"] == "org.junit.jupiter:junit-jupiter")
    assert edge["child_version"] == "5.14.4"
    assert edge["confidence"] == "VERIFIED"
    quals = edge["qualifiers"]
    assert quals.get("version_selected_by_platform") == "true"
    assert quals.get("subtree_elided") == "true"
    assert "requested_version" not in quals
    assert "conflict_resolved" not in quals
    cons_tree = """\
> Task :app:dependencies

runtimeClasspath
+--- org.gradle.test:gd-parent:1.0.0
|    +--- org.gradle.test:gd-constrained:2.0.0 (c)
|    \\--- org.gradle.test:gd-unresolved:3.0.0 (n)
"""
    cons = extract(_write(tmp_path, cons_tree))
    by_name = {e["child_name"]: e for e in cons["edges"]}
    assert by_name["org.gradle.test:gd-constrained"][
        "resolution_status"] == "GRADLE_CONSTRAINT_ENTRY_NOT_DEPENDENCY"
    assert by_name["org.gradle.test:gd-unresolved"][
        "resolution_status"] == "GRADLE_VERSION_NOT_RESOLVED"


def test_frg1_m9_unknown_marker_after_arrow_strict_unparseable(tmp_path):
    # §2.5 semantics pin: an unknown marker after the arrow is strict-
    # unparseable (node-level; F-RG-2 §5 file-level policy: a LEAF is
    # tallied + disclosed, a node WITH a subtree keeps the fatal error).
    # Pre-fix the shape accidentally produced a contaminated UNRESOLVED
    # edge (empty status) instead.  The shape does not occur in the real
    # corpus (the F-RG-2 review's 1,710/1,710 line accounting has no such
    # class); the behavior is defined, not guessed.
    leaf = """\
> Task :app:dependencies

runtimeClasspath
+--- org.gradle.test:gd-parent:1.0.0
|    \\--- org.gradle.test:gd-child:2.0.0 -> 3.0.0 (x)
"""
    result = extract(_write(tmp_path, leaf))
    # the fixture has no other edges, so the honest envelope is
    # NO_VERIFIED_EDGES (disclosed, not fatal) -- matching the
    # test_malformed_constraint_output_is_disclosed convention.
    assert result["graph_status"] != "EXTRACTION_ERROR", \
        result.get("limitations")
    assert result["tallies"]["invalid_nodes"] == 1
    assert any("gd-child" in lim for lim in result["limitations"])
    assert all(e["child_name"] != "org.gradle.test:gd-child"
               for e in result["edges"])
    subtree = """\
> Task :app:dependencies

runtimeClasspath
+--- org.gradle.test:gd-parent:1.0.0
|    \\--- org.gradle.test:gd-child:2.0.0 -> 3.0.0 (x)
|         \\--- org.gradle.test:gd-grandchild:4.0.0
"""
    result2 = extract(_write(tmp_path, subtree))
    assert result2["graph_status"] == "EXTRACTION_ERROR"
    assert result2["edges"] == []


def test_frg1_m10_star_only_selected_is_not_resolved(tmp_path):
    # §2.2 corner pin: a selected that is empty once the marker is
    # stripped (`-> (*)`) printed NO resolved version --
    # requested-but-unresolved, never promoted (the requested version is
    # disclosed, no fingerprint).  Pre-fix the marker contaminated the
    # version (UNRESOLVED with an empty resolution status).
    tree = """\
> Task :app:dependencies

runtimeClasspath
+--- org.gradle.test:gd-parent:1.0.0
|    \\--- org.gradle.test:gd-child:2.0.0 -> (*)
"""
    result = extract(_write(tmp_path, tree))
    edge = result["edges"][0]
    assert edge["child_version"] == "", edge
    assert edge["confidence"] == "UNRESOLVED"
    assert edge["resolution_status"] == "GRADLE_VERSION_NOT_RESOLVED", edge
    assert edge["qualifiers"]["requested_version"] == "2.0.0"
    assert not edge.get("fingerprint")
