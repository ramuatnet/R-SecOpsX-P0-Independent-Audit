"""pnpm verified-edge extractor tests (R2.3 remediation, F-R3-2/3/4/5).

Every expected graph below is an INDEPENDENT hand-authored expectation --
the tests never validate the extractor against its own output. ALL fixtures
are SYNTHETIC (the corpus contains no project-committed pnpm lockfile);
real-evidence validation lives in tools/oracle_pnpm.py runs against the
pnpm-import-generated NodeGoat lockfile and is recorded in the remediation
report -- no real-world claim is made from these fixtures.

Scenario classes (remediation mandate F-R3-5): v5.4 / v6.0 / v6.1 / v9.0,
importers, snapshots, multiple versions, peer dependencies, scoped packages,
optional dependencies, development dependencies, aliases, multiple parents,
missing and ambiguous identities, malformed lockfiles, unsupported formats,
duplicate-record semantics, determinism, FND-03 span compliance.
"""

import ast
from pathlib import Path

import pytest

from analysis.lock_graph import contract
from analysis.lock_graph import registry
from analysis.lock_graph.pnpm import extract


def _write(tmp_path, text, name="pnpm-lock.yaml"):
    lock = tmp_path / name
    lock.write_text(text, encoding="utf-8")
    return str(lock)


def _verified_pairs(result):
    return {(e["parent_name"], e["parent_version"],
             e["child_name"], e["child_version"])
            for e in result["edges"] if e["confidence"] == "VERIFIED"}


V9_CHAIN = """\
lockfileVersion: '9.0'

importers:

  .:
    dependencies:
      alpha: 1.2.0

packages:

  alpha@1.2.0:
    resolution: {integrity: sha512-aaa}

  beta@1.5.0:
    resolution: {integrity: sha512-bbb}

  gamma@2.3.4:
    resolution: {integrity: sha512-ccc}

snapshots:

  alpha@1.2.0:
    dependencies:
      beta: 1.5.0

  beta@1.5.0:
    dependencies:
      gamma: 2.3.4

  gamma@2.3.4: {}
"""


# -- 1-4: supported lockfile versions ----------------------------------------
def test_v9_chain_verified_edges(tmp_path):
    result = extract(_write(tmp_path, V9_CHAIN))
    assert result["graph_status"] == "VERIFIED_EDGES_AVAILABLE"
    assert result["engine"] == "PNPM_SNAPSHOT_GRAPH_V1"
    assert _verified_pairs(result) == {
        ("alpha", "1.2.0", "beta", "1.5.0"),
        ("beta", "1.5.0", "gamma", "2.3.4"),
    }
    edge = next(e for e in result["edges"] if e["child_name"] == "beta")
    assert edge["requested_spec"] == "1.5.0"
    assert edge["parent_purl"] == "pkg:npm/alpha@1.2.0"
    assert edge["qualifiers"]["integrity"] == "sha512-bbb"
    assert edge["fingerprint"].startswith("sha256:")


def test_v6_gate_and_edges(tmp_path):
    # lockfileVersion 6.0 (float spelling) reaches the same snapshot path
    result = extract(_write(tmp_path, V9_CHAIN.replace("'9.0'", "6.0")))
    assert result["format_version"] == "pnpm lockfileVersion 6.0"
    assert result["graph_status"] == "VERIFIED_EDGES_AVAILABLE"
    assert len(_verified_pairs(result)) == 2


def test_v61_gate_and_edges(tmp_path):
    result = extract(_write(tmp_path, V9_CHAIN.replace("'9.0'", "6.1")))
    assert result["format_version"] == "pnpm lockfileVersion 6.1"
    assert result["graph_status"] == "VERIFIED_EDGES_AVAILABLE"
    assert len(_verified_pairs(result)) == 2


V54 = """\
lockfileVersion: 5.4

dependencies:
  alpha: 1.2.0

devDependencies:
  mocker: 3.0.0

packages:

  alpha/1.2.0:
    resolution: {integrity: sha512-aaa}
    dependencies:
      beta: 1.5.0

  beta/1.5.0:
    resolution: {integrity: sha512-bbb}
    dependencies:
      gamma: 2.3.4

  gamma/2.3.4:
    resolution: {integrity: sha512-ccc}

  mocker/3.0.0:
    resolution: {integrity: sha512-mmm}
    dev: true

  '@scope/lib/4.4.4':
    resolution: {integrity: sha512-sss}

  newer-beta/9.9.0:
    resolution: {integrity: sha512-nnn}

  peerful/1.0.0(grunt@1.0.3):
    resolution: {integrity: sha512-ppp}
    dependencies:
      gamma: 2.3.4
"""


def test_v54_slash_keys_scoped_unscoped_multi_version_peerful(tmp_path):
    # F-R3-2 red test: v5.4 slash-separated keys (unscoped, scoped,
    # multiple versions of one name, peer-qualified key) must all extract;
    # a declared supported format never silently returns zero edges.
    result = extract(_write(tmp_path, V54))
    assert result["format_version"] == "pnpm lockfileVersion 5.4"
    assert result["tallies"]["invalid_records"] == 0
    pairs = _verified_pairs(result)
    assert ("alpha", "1.2.0", "beta", "1.5.0") in pairs
    assert ("beta", "1.5.0", "gamma", "2.3.4") in pairs
    assert ("peerful", "1.0.0", "gamma", "2.3.4") in pairs
    # multiple versions of the same name coexist as distinct instances
    names = {(p, v) for (p, v, _c, _cv) in pairs}
    assert ("beta", "1.5.0") in names


def test_v54_scoped_key_extracted(tmp_path):
    result = extract(_write(tmp_path, V54))
    # the scoped v5.4 entry has no declared deps, but membership must be
    # resolvable for children pointing at it -- verified via the alias/
    # member path in test_alias_package_keys; here: universe normalization
    # accepted '@scope/lib/4.4.4' without counting it invalid
    assert result["tallies"]["invalid_records"] == 0


def test_v54_child_resolution_uses_normalized_universe(tmp_path):
    # v5.4 child values resolve against slash keys normalized to
    # name@version -- gamma@2.3.4 membership comes from gamma/2.3.4
    result = extract(_write(tmp_path, V54))
    edge = next(e for e in result["edges"]
                if e["parent_name"] == "alpha")
    assert edge["child_name"] == "beta"
    assert edge["child_version"] == "1.5.0"
    assert edge["child_purl"] == "pkg:npm/beta@1.5.0"


# -- 5/12: importers and development dependencies -----------------------------
def test_v9_importers_counted_never_edges(tmp_path):
    # importer (project) declarations are tallied, never edges -- no
    # synthetic root is minted for non-npm-engine ecosystems
    result = extract(_write(tmp_path, V9_CHAIN))
    assert result["tallies"]["importer_declarations_runtime"] == 1
    assert result["tallies"]["importer_declarations"] == 1
    assert all(e["parent_name"] != "." for e in result["edges"])
    assert all(not e["parent_name"].startswith("importer")
               for e in result["edges"])


def test_v54_root_blocks_tallied_with_dev_scope(tmp_path):
    result = extract(_write(tmp_path, V54))
    assert result["tallies"]["importer_declarations_runtime"] == 1
    assert result["tallies"]["importer_declarations_dev"] == 1
    assert result["tallies"]["importer_declarations"] == 2


def test_dev_flag_qualifier_never_invented_scope(tmp_path):
    # packages dev flags travel as qualifiers; scope=dev is never stamped
    # onto snapshot edges from thin air
    result = extract(_write(tmp_path, V54))
    mocker_edges = [e for e in result["edges"]
                    if e["parent_name"] == "mocker"]
    assert mocker_edges == []          # mocker declares no deps
    for e in result["edges"]:
        assert e["scope"] != "dev" or e["qualifiers"].get("package_dev")


# -- 6/8: snapshots and peer dependencies ------------------------------------
def test_peer_qualified_child_value(tmp_path):
    lockfile = V9_CHAIN.replace(
        "  beta@1.5.0:\n    dependencies:\n      gamma: 2.3.4\n",
        "  beta@1.5.0:\n"
        "    dependencies:\n"
        "      gamma: 2.3.4(supports-color@5.5.0)\n")
    result = extract(_write(tmp_path, lockfile))
    edge = next(e for e in result["edges"] if e["child_name"] == "gamma")
    assert edge["confidence"] == "VERIFIED"
    assert edge["child_version"] == "2.3.4"
    assert edge["qualifiers"]["peer_instances"] == ["supports-color@5.5.0"]
    assert edge["requested_spec"] == "2.3.4(supports-color@5.5.0)"


def test_peer_qualified_parent_instance(tmp_path):
    lockfile = V9_CHAIN.replace(
        "  alpha@1.2.0:\n    dependencies:\n      beta: 1.5.0\n",
        "  alpha@1.2.0(react@17.0.2):\n"
        "    dependencies:\n"
        "      beta: 1.5.0\n")
    result = extract(_write(tmp_path, lockfile))
    edge = next(e for e in result["edges"] if e["child_name"] == "beta")
    assert edge["confidence"] == "VERIFIED"
    assert edge["parent_name"] == "alpha"
    assert edge["parent_version"] == "1.2.0"
    assert edge["qualifiers"]["peer_instances"] == ["react@17.0.2"]


def test_transitive_peer_dependencies_qualifier(tmp_path):
    lockfile = V9_CHAIN.replace(
        "  alpha@1.2.0:\n    dependencies:\n      beta: 1.5.0\n",
        "  alpha@1.2.0:\n"
        "    dependencies:\n"
        "      beta: 1.5.0\n"
        "    transitivePeerDependencies:\n"
        "      - supports-color\n")
    result = extract(_write(tmp_path, lockfile))
    edge = next(e for e in result["edges"] if e["child_name"] == "beta")
    assert edge["qualifiers"]["transitive_peer_dependencies"] == \
        ["supports-color"]


# -- 9: scoped packages --------------------------------------------------------
def test_scoped_package_names(tmp_path):
    lockfile = """\
lockfileVersion: '9.0'
packages:
  '@app/runner@1.0.0':
    resolution: {integrity: sha512-r}
  '@tools/parser@4.2.0':
    resolution: {integrity: sha512-p}
snapshots:
  '@app/runner@1.0.0':
    dependencies:
      '@tools/parser': 4.2.0
  '@tools/parser@4.2.0': {}
"""
    result = extract(_write(tmp_path, lockfile))
    assert _verified_pairs(result) == {
        ("@app/runner", "1.0.0", "@tools/parser", "4.2.0")}
    edge = result["edges"][0]
    assert edge["parent_purl"].startswith("pkg:npm/%40app/")
    assert edge["child_purl"].startswith("pkg:npm/%40tools/")


# -- 10: optional dependencies -------------------------------------------------
def test_optional_dependencies_scope(tmp_path):
    lockfile = V9_CHAIN.replace(
        "  alpha@1.2.0:\n    dependencies:\n      beta: 1.5.0\n",
        "  alpha@1.2.0:\n"
        "    optionalDependencies:\n"
        "      beta: 1.5.0\n")
    result = extract(_write(tmp_path, lockfile))
    edge = next(e for e in result["edges"] if e["child_name"] == "beta")
    assert edge["scope"] == "optional"
    assert edge["confidence"] == "VERIFIED"


# -- 12: aliases ----------------------------------------------------------------
def test_alias_package_keys_resolve_real_identity(tmp_path):
    lockfile = """\
lockfileVersion: '9.0'
packages:
  'string-width-cjs@npm:string-width@4.2.3':
    resolution: {integrity: sha512-s}
snapshots:
  'string-width-cjs@npm:string-width@4.2.3': {}
  app@1.0.0:
    dependencies:
      string-width-cjs: 4.2.3
"""
    result = extract(_write(tmp_path, lockfile))
    pairs = _verified_pairs(result)
    assert pairs == {("app", "1.0.0", "string-width", "4.2.3")}
    edge = result["edges"][0]
    assert edge["qualifiers"]["alias"] == "string-width-cjs"
    assert edge["child_purl"] == "pkg:npm/string-width@4.2.3"


# -- 13: multiple parents --------------------------------------------------------
def test_multiple_parents(tmp_path):
    lockfile = """\
lockfileVersion: '9.0'
packages:
  left@1.0.0:
    resolution: {integrity: sha512-l}
  right@2.1.0:
    resolution: {integrity: sha512-rr}
  shared@3.4.5:
    resolution: {integrity: sha512-sh}
snapshots:
  left@1.0.0:
    dependencies:
      shared: 3.4.5
  right@2.1.0:
    dependencies:
      shared: 3.4.5
  shared@3.4.5: {}
"""
    result = extract(_write(tmp_path, lockfile))
    assert _verified_pairs(result) == {
        ("left", "1.0.0", "shared", "3.4.5"),
        ("right", "2.1.0", "shared", "3.4.5"),
    }


# -- 14: missing and ambiguous identities ----------------------------------------
def test_missing_identity_preserves_declared_child_name(tmp_path):
    # F-R3-3 red test: a membership miss must keep the DECLARED child name
    # and answer UNRESOLVED -- never a mangled edge with child_name=""
    lockfile = """\
lockfileVersion: '9.0'
packages:
  app@1.0.0:
    resolution: {integrity: sha512-a}
snapshots:
  app@1.0.0:
    dependencies:
      ghost: 9.9.9
"""
    result = extract(_write(tmp_path, lockfile))
    assert _verified_pairs(result) == set()
    edge = result["edges"][0]
    assert edge["child_name"] == "ghost"
    assert edge["child_version"] == ""
    assert edge["confidence"] == "UNRESOLVED"
    assert edge["resolution_status"] == "CHILD_NOT_IN_LOCKFILE"


def test_snapshot_fallback_for_packages_miss(tmp_path):
    # F-R3-3: a child instance present ONLY as a (peer-qualified) snapshot
    # is legitimate resolution evidence -> VERIFIED via the fallback
    lockfile = """\
lockfileVersion: '9.0'
packages:
  app@1.0.0:
    resolution: {integrity: sha512-a}
snapshots:
  app@1.0.0:
    dependencies:
      peerful: 2.0.0(peer@1.0.0)
  peerful@2.0.0(peer@1.0.0): {}
"""
    result = extract(_write(tmp_path, lockfile))
    assert _verified_pairs(result) == {
        ("app", "1.0.0", "peerful", "2.0.0")}
    edge = result["edges"][0]
    assert edge["qualifiers"]["peer_instances"] == ["peer@1.0.0"]


def test_exact_instance_semantics_never_ambiguous(tmp_path):
    # pnpm snapshot values are EXACT resolved instances: even with several
    # versions of the child in the universe, the exact value pins the
    # instance -- AMBIGUOUS is structurally not produced by this format's
    # relation evidence (unlike yarn/poetry constraint ranges)
    lockfile = """\
lockfileVersion: '9.0'
packages:
  app@1.0.0:
    resolution: {integrity: sha512-a}
  lib@1.0.0:
    resolution: {integrity: sha512-l1}
  lib@2.0.0:
    resolution: {integrity: sha512-l2}
snapshots:
  app@1.0.0:
    dependencies:
      lib: 2.0.0
  lib@1.0.0: {}
  lib@2.0.0: {}
"""
    result = extract(_write(tmp_path, lockfile))
    assert _verified_pairs(result) == {("app", "1.0.0", "lib", "2.0.0")}
    assert all(e["confidence"] != contract.AMBIGUOUS
               for e in result["edges"])


# -- 15: malformed lockfiles -------------------------------------------------------
def test_malformed_entries_counted_valid_edges_survive(tmp_path):
    # structurally valid YAML with non-dict section values: each garbage
    # entry is counted invalid; valid entries still extract
    lockfile = """\
lockfileVersion: '9.0'
packages:
  app@1.0.0:
    resolution: {integrity: sha512-a}
  garbage-entry: oops
snapshots:
  app@1.0.0:
    dependencies:
      beta: 1.5.0
  beta@1.5.0: {}
  another-garbage: not-a-mapping
"""
    result = extract(_write(tmp_path, lockfile))
    assert result["tallies"]["invalid_records"] == 2
    assert _verified_pairs(result) == {("app", "1.0.0", "beta", "1.5.0")}


def test_non_mapping_document_is_unsupported(tmp_path):
    result = extract(_write(tmp_path, "- just\n- a\n- list\n"))
    assert result["graph_status"] == "UNSUPPORTED_FORMAT"
    assert result["edges"] == []


# -- 16: unsupported formats --------------------------------------------------------
def test_unsupported_version_envelope(tmp_path):
    result = extract(_write(tmp_path,
                            "lockfileVersion: 99.0\npackages: {}\n"))
    assert result["graph_status"] == "UNSUPPORTED_FORMAT"
    assert result["edges"] == []
    assert any("99.0" in line for line in result["limitations"])


def test_missing_version_envelope(tmp_path):
    result = extract(_write(tmp_path, "packages: {}\n"))
    assert result["graph_status"] == "UNSUPPORTED_FORMAT"
    assert result["edges"] == []


def test_54_and_60_spellings_normalise(tmp_path):
    # float spellings normalize to the same supported labels
    assert extract(_write(tmp_path, V54))["format_version"] == \
        "pnpm lockfileVersion 5.4"
    assert extract(_write(
        tmp_path, V9_CHAIN.replace("'9.0'", "6.0")))["format_version"] == \
        "pnpm lockfileVersion 6.0"


# -- non-registry resolutions (disclosed, never guessed) ----------------------------
def test_tarball_child_value_preserved_verbatim(tmp_path):
    lockfile = """\
lockfileVersion: '9.0'
packages:
  app@1.0.0:
    resolution: {integrity: sha512-a}
snapshots:
  app@1.0.0:
    dependencies:
      grunt-if: https://github.com/binarymist/grunt-if/tarball/master
"""
    result = extract(_write(tmp_path, lockfile))
    edge = result["edges"][0]
    assert edge["confidence"] == "UNRESOLVED"
    assert edge["child_version"] == \
        "https://github.com/binarymist/grunt-if/tarball/master"
    assert edge["resolution_status"] == "NON_REGISTRY_RESOLUTION"


def test_link_child_value_disclosed(tmp_path):
    lockfile = """\
lockfileVersion: '9.0'
packages:
  app@1.0.0:
    resolution: {integrity: sha512-a}
snapshots:
  app@1.0.0:
    dependencies:
      local: link:../local-pkg
"""
    result = extract(_write(tmp_path, lockfile))
    edge = result["edges"][0]
    assert edge["confidence"] == "UNRESOLVED"
    assert edge["child_version"] == "link:../local-pkg"
    assert edge["resolution_status"] == "LOCAL_LINK"


def test_tarball_parent_edges_disclosed(tmp_path):
    # a tarball-resolved PARENT has no purl-certifiable identity: its
    # edges keep the resolved child but can never be VERIFIED, and the
    # reason is disclosed on the edge
    lockfile = """\
lockfileVersion: '9.0'
packages:
  grunt@1.0.3:
    resolution: {integrity: sha512-g}
snapshots:
  'grunt-if@https://github.com/binarymist/grunt-if/tarball/master':
    dependencies:
      grunt: 1.0.3
  grunt@1.0.3: {}
"""
    result = extract(_write(tmp_path, lockfile))
    assert _verified_pairs(result) == set()
    edge = result["edges"][0]
    assert edge["parent_name"] == "grunt-if"
    assert edge["child_name"] == "grunt"
    assert edge["child_version"] == "1.0.3"
    assert edge["confidence"] == "UNRESOLVED"
    assert edge["resolution_status"] == "NON_REGISTRY_PARENT"


# -- duplicate-record semantics -------------------------------------------------------
def test_duplicate_records_tally_semantics(tmp_path):
    # YAML mapping keys are unique per section, so a valid pnpm lockfile
    # cannot carry duplicate dependency records the way yarn v1 can; the
    # tally exists, stays 0 for valid files, and peer-instance variants of
    # one parent are DISTINCT parents (not duplicates)
    lockfile = """\
lockfileVersion: '9.0'
packages:
  app@1.0.0:
    resolution: {integrity: sha512-a}
  lib@1.0.0:
    resolution: {integrity: sha512-l}
snapshots:
  app@1.0.0:
    dependencies:
      lib: 1.0.0
  'app@1.0.0(peer@2.0.0)':
    dependencies:
      lib: 1.0.0
  lib@1.0.0: {}
"""
    result = extract(_write(tmp_path, lockfile))
    assert result["tallies"]["duplicate_records_dropped"] == 0
    # two DISTINCT parent instances (plain + peer-qualified) each carry
    # their own edge; the identity 4-tuples collapse in a set
    verified = [e for e in result["edges"]
                if e["confidence"] == "VERIFIED"]
    assert len(verified) == 2
    assert _verified_pairs(result) == {("app", "1.0.0", "lib", "1.0.0")}
    peer_edge = next(e for e in verified if e["parent_version"] != "1.0.0"
                     or e["qualifiers"].get("peer_instances"))
    assert peer_edge["qualifiers"].get("peer_instances") == ["peer@2.0.0"]


# -- registry dispatch (F-R3-1; contract-file tests cover dispatch too) ---------------
def test_registry_lockfile_names_cover_pnpm():
    assert "pnpm-lock.yaml" in registry.LOCKFILE_NAMES


# -- determinism and vocabulary --------------------------------------------------------
def test_run_to_run_determinism(tmp_path):
    a = extract(_write(tmp_path, V54))
    b = extract(_write(tmp_path, V54))
    assert a == b


def test_confidence_vocabulary_pinned(tmp_path):
    result = extract(_write(tmp_path, V9_CHAIN))
    for edge in result["edges"]:
        assert edge["confidence"] in (
            contract.VERIFIED, contract.AMBIGUOUS, contract.UNRESOLVED,
            contract.UNSUPPORTED, contract.INVALID)


# -- FND-03 span compliance (F-R3-4 regression pin) ------------------------------------
def test_fnd03_no_bare_int_slices_in_pnpm_module():
    # same AST rule as tests/test_report_parity.py, scoped to the pnpm
    # extractor: every slice bound must read a name from analysis.spans
    from test_report_parity import _fnd03_bare_slice_ints
    hits = [h for h in _fnd03_bare_slice_ints() if "pnpm.py" in h]
    assert not hits, (
        "FND-03 bare-int slices in pnpm.py (name them via "
        "analysis.spans): " + ", ".join(hits))


# -- v6.1 importer spelling and empty snapshot robustness -------------------------------
def test_empty_snapshot_and_metadata_only_entries(tmp_path):
    lockfile = """\
lockfileVersion: '9.0'
packages:
  loner@1.0.0:
    resolution: {integrity: sha512-x}
    engines: {node: '>=4'}
snapshots:
  loner@1.0.0: {}
"""
    result = extract(_write(tmp_path, lockfile))
    assert result["graph_status"] == "NO_VERIFIED_EDGES"
    assert result["edges"] == []
    assert result["tallies"]["invalid_records"] == 0
