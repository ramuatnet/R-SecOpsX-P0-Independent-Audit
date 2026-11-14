"""Ruby/Bundler verified-edge extractor tests (R2.5a).

Every expected graph is an INDEPENDENT hand-authored expectation -- the
tests never validate the extractor against its own output. Fixtures are
SYNTHETIC unless stated; real-corpus validation (railsgoat-main 737-line
Gemfile.lock, the two vuln-test-corpus locks) runs through
tools/oracle_rubygems.py and is recorded in the R2_5 delivery report.

Evidence tiers (approved R2.5a scope):
- Gemfile.lock ``specs:`` blocks (GEM/GIT/PATH sections) -> the resolved
  universe WITH parent-child declarations: parent = gem@version, child
  lines carry constraints resolved against the universe (VERIFIED unique /
  AMBIGUOUS multi / UNRESOLVED none). Ruby's pessimistic operator ``~>``
  is mapped LOCALLY onto the shared matcher's tilde (exact semantics for
  both segment counts) -- versions.py untouched.
- Gemfile -> manifest declarations tallied and disclosed, NEVER edges
  (the require-parent is the application, not a lockfile component).

Scenario classes: direct/transitive/multi-level chains, multiple parents,
multiple versions, platform variants, git/path/registry sources,
constraints (=, >=, ~> normalization), ambiguous and unresolved
identities, malformed files, unsupported files, duplicates, dispatch,
determinism, vocabulary. Ruby has no peer-dependency machinery; groups
live only in the Gemfile (tallied there).
"""

import pytest

from analysis.lock_graph import contract
from analysis.lock_graph import registry


def _write(tmp_path, text, name):
    lock = tmp_path / name
    lock.write_text(text, encoding="utf-8")
    return str(lock)


def _verified_pairs(result):
    return {(e["parent_name"], e["parent_version"],
             e["child_name"], e["child_version"])
            for e in result["edges"] if e["confidence"] == "VERIFIED"}


LOCK = """\
GEM
  remote: https://rubygems.org/
  specs:
    actionpack (7.0.4)
      rack (>= 2.2.4)
      rack-session (~> 2.0)
    rack (2.2.8)
    rack-session (2.0.1)
      rack (>= 3.0.0)
    rack (3.0.8)

PLATFORMS
  x86_64-linux
  arm64-darwin-21

DEPENDENCIES
  actionpack
  rack-session

BUNDLED WITH
   2.4.10
"""


def test_lock_chain_verified_edges(tmp_path):
    # SYNTHETIC: actionpack -> rack (2.2.8 via >= 2.2.4 unique among
    # {2.2.8, 3.0.8}? NO -- >= 2.2.4 matches BOTH: ambiguity coverage is
    # in its own test; this chain uses exact pins)
    lock = """\
GEM
  remote: https://rubygems.org/
  specs:
    actionpack (7.0.4)
      rack (= 2.2.8)
      rack-session (~> 2.0)
    rack (2.2.8)
    rack-session (2.0.1)
      rack (= 3.0.8)
    rack (3.0.8)
"""
    result = registry.extract_for_file(_write(tmp_path, lock, "Gemfile.lock"))
    assert result["engine"] == "BUNDLER_LOCK_GRAPH_V1"
    assert result["graph_status"] == "VERIFIED_EDGES_AVAILABLE"
    assert _verified_pairs(result) == {
        ("actionpack", "7.0.4", "rack", "2.2.8"),
        ("actionpack", "7.0.4", "rack-session", "2.0.1"),
        ("rack-session", "2.0.1", "rack", "3.0.8"),
    }
    edge = next(e for e in result["edges"] if e["child_name"] == "rack"
                and e["parent_name"] == "actionpack")
    assert edge["ecosystem"] == "rubygems"
    assert edge["parent_purl"] == "pkg:gem/actionpack@7.0.4"
    assert edge["requested_spec"] == "= 2.2.8"
    assert edge["fingerprint"].startswith("sha256:")
    assert edge["evidence_source"] == "BUNDLER_LOCK_SPECS"


def test_lock_multi_level_chain(tmp_path):
    lock = """\
GEM
  remote: https://rubygems.org/
  specs:
    top (1.0.0)
      mid (= 2.0.0)
    mid (2.0.0)
      leaf (= 3.0.0)
    leaf (3.0.0)
"""
    result = registry.extract_for_file(_write(tmp_path, lock, "Gemfile.lock"))
    assert _verified_pairs(result) == {
        ("top", "1.0.0", "mid", "2.0.0"),
        ("mid", "2.0.0", "leaf", "3.0.0"),
    }


def test_lock_pessimistic_operator_normalized_locally(tmp_path):
    # ~> 2.0 means >= 2.0, < 3.0 -- mapped onto the shared matcher's tilde
    lock = """\
GEM
  remote: https://rubygems.org/
  specs:
    app (1.0.0)
      lib (~> 2.0)
    lib (2.5.0)
"""
    result = registry.extract_for_file(_write(tmp_path, lock, "Gemfile.lock"))
    assert _verified_pairs(result) == {("app", "1.0.0", "lib", "2.5.0")}
    edge = result["edges"][0]
    assert edge["requested_spec"] == "~> 2.0"


def test_lock_multiple_versions_ambiguous(tmp_path):
    # >= 2.2.4 matches BOTH rack instances -> AMBIGUOUS, candidates
    # disclosed, never picked
    result = registry.extract_for_file(_write(tmp_path, LOCK, "Gemfile.lock"))
    amb = [e for e in result["edges"] if e["confidence"] == "AMBIGUOUS"]
    assert len(amb) == 1
    assert amb[0]["parent_name"] == "actionpack"
    assert amb[0]["child_name"] == "rack"
    assert amb[0]["ambiguity"]["candidates"] == ["2.2.8", "3.0.8"]
    assert amb[0]["resolution_status"] == "MULTIPLE_CANDIDATES"
    assert "fingerprint" not in amb[0]


def test_lock_multiple_parents(tmp_path):
    lock = """\
GEM
  remote: https://rubygems.org/
  specs:
    left (1.0.0)
      shared (= 5.0.0)
    right (2.0.0)
      shared (= 5.0.0)
    shared (5.0.0)
"""
    result = registry.extract_for_file(_write(tmp_path, lock, "Gemfile.lock"))
    assert _verified_pairs(result) == {
        ("left", "1.0.0", "shared", "5.0.0"),
        ("right", "2.0.0", "shared", "5.0.0"),
    }


def test_lock_platform_variant_identity(tmp_path):
    # REAL corpus shape: platform-specific gems carry the platform in the
    # version string; the identity stays name@version-verbatim
    lock = """\
GEM
  remote: https://rubygems.org/
  specs:
    nokogiri (1.14.0-x86_64-linux)
    app (1.0.0)
      nokogiri (= 1.14.0-x86_64-linux)
"""
    result = registry.extract_for_file(_write(tmp_path, lock, "Gemfile.lock"))
    assert _verified_pairs(result) == {
        ("app", "1.0.0", "nokogiri", "1.14.0-x86_64-linux")}


def test_lock_git_section_provenance(tmp_path):
    # SYNTHETIC: GIT section specs resolve with git source provenance
    lock = """\
GIT
  remote: https://github.com/example/forked.git
  revision: abc123def4567890
  specs:
    forked (1.2.0)
      base (= 2.0.0)

GEM
  remote: https://rubygems.org/
  specs:
    base (2.0.0)
"""
    result = registry.extract_for_file(_write(tmp_path, lock, "Gemfile.lock"))
    pairs = _verified_pairs(result)
    assert pairs == {("forked", "1.2.0", "base", "2.0.0")}
    edge = result["edges"][0]
    assert edge["qualifiers"]["source_kind"] == "git"
    assert edge["qualifiers"]["source"] == \
        "https://github.com/example/forked.git"
    assert edge["qualifiers"]["revision"] == "abc123def4567890"


def test_lock_path_section_provenance(tmp_path):
    lock = """\
PATH
  remote: ../local/gem
  specs:
    localgem (0.1.0)
      dep (= 1.0.0)

GEM
  remote: https://rubygems.org/
  specs:
    dep (1.0.0)
"""
    result = registry.extract_for_file(_write(tmp_path, lock, "Gemfile.lock"))
    pairs = _verified_pairs(result)
    assert pairs == {("localgem", "0.1.0", "dep", "1.0.0")}
    edge = result["edges"][0]
    assert edge["qualifiers"]["source_kind"] == "path"
    assert edge["qualifiers"]["source"] == "../local/gem"


def test_lock_registry_provenance(tmp_path):
    result = registry.extract_for_file(_write(tmp_path, LOCK, "Gemfile.lock"))
    edge = next(e for e in result["edges"]
                if e["parent_name"] == "actionpack")
    assert edge["qualifiers"]["source_kind"] == "registry"
    assert edge["qualifiers"]["source"] == "https://rubygems.org/"


def test_lock_missing_identity_unresolved(tmp_path):
    lock = """\
GEM
  remote: https://rubygems.org/
  specs:
    app (1.0.0)
      ghost (= 9.9.9)
"""
    result = registry.extract_for_file(_write(tmp_path, lock, "Gemfile.lock"))
    assert _verified_pairs(result) == set()
    edge = result["edges"][0]
    assert edge["child_name"] == "ghost"
    assert edge["confidence"] == "UNRESOLVED"
    assert edge["resolution_status"] == "CHILD_NOT_IN_LOCKFILE"


def test_lock_no_matching_version_unresolved(tmp_path):
    lock = """\
GEM
  remote: https://rubygems.org/
  specs:
    app (1.0.0)
      lib (>= 9.0)
    lib (2.0.0)
"""
    result = registry.extract_for_file(_write(tmp_path, lock, "Gemfile.lock"))
    edge = result["edges"][0]
    assert edge["child_name"] == "lib"
    assert edge["confidence"] == "UNRESOLVED"
    assert edge["resolution_status"] == "NO_MATCHING_VERSION"


def test_lock_duplicate_declarations_dedupe_with_tally(tmp_path):
    # two parent instances declaring the same child identity dedupe
    lock = """\
GEM
  remote: https://rubygems.org/
  specs:
    app (1.0.0)
      lib (= 2.0.0)
      lib (= 2.0.0)
    lib (2.0.0)
"""
    result = registry.extract_for_file(_write(tmp_path, lock, "Gemfile.lock"))
    assert len(_verified_pairs(result)) == 1
    assert result["tallies"]["duplicate_records_dropped"] == 1


def test_lock_malformed_lines_counted(tmp_path):
    lock = """\
GEM
  remote: https://rubygems.org/
  specs:
    app (1.0.0)
    this line is not a spec (at all
    broken
"""
    result = registry.extract_for_file(_write(tmp_path, lock, "Gemfile.lock"))
    assert result["tallies"]["invalid_records"] >= 1
    # app parsed and kept (no deps)
    assert result["membership_packages"] >= 1


def test_lock_not_a_lockfile_envelope(tmp_path):
    result = registry.extract_for_file(
        _write(tmp_path, "random content\n", "Gemfile.lock"))
    assert result["graph_status"] == "UNSUPPORTED_FORMAT"
    assert result["edges"] == []


def test_lock_declarations_tallied_never_edges(tmp_path):
    # DEPENDENCIES is the app's declared set: tallied (with git ! marks),
    # never edges -- no synthetic root for non-npm ecosystems
    result = registry.extract_for_file(_write(tmp_path, LOCK, "Gemfile.lock"))
    assert result["tallies"]["direct_declarations"] == 2
    assert result["tallies"]["platforms"] == 2
    assert all(e["parent_name"] != "." and not e["parent_name"].startswith(
        "app (root)") for e in result["edges"])


# -- Gemfile manifest envelope ------------------------------------------------------
GEMFILE = """\
source "https://rubygems.org"

gem "rails", "~> 8.0.0"
gem "pg"
gem "forked", git: "https://github.com/example/forked.git"

group :development, :test do
  gem "rspec-rails"
  gem "pry-byebug"
end
"""


def test_gemfile_declarations_tallied_never_edges(tmp_path):
    result = registry.extract_for_file(_write(tmp_path, GEMFILE, "Gemfile"))
    assert result["engine"] == "BUNDLER_GEMFILE_DECLARATIONS_V1"
    assert result["graph_status"] == "UNSUPPORTED_FORMAT"
    assert result["edges"] == []
    t = result["tallies"]
    assert t["gem_declarations"] == 5
    assert t["source_git"] == 1
    assert t["source_registry"] == 4
    assert t["group_blocks"] == 1
    assert result["membership_packages"] == 5


def test_gemfile_without_gems_unsupported(tmp_path):
    # line-protocol manifest: content declaring no gems answers a
    # disclosed unsupported envelope (no parser can crash on Ruby source)
    result = registry.extract_for_file(
        _write(tmp_path, "just some text\n", "Gemfile"))
    assert result["graph_status"] == "UNSUPPORTED_FORMAT"
    assert result["edges"] == []


def test_lock_pessimistic_zero_major_explicit_conjunction(tmp_path):
    # '~> 0.8' = >= 0.8, < 1.0 -- caret would wrongly bump the minor;
    # the local mapping emits an explicit conjunction instead
    lock = """\
GEM
  remote: https://rubygems.org/
  specs:
    app (1.0.0)
      lib (~> 0.8)
    lib (0.9.0)
"""
    result = registry.extract_for_file(_write(tmp_path, lock, "Gemfile.lock"))
    assert _verified_pairs(result) == {("app", "1.0.0", "lib", "0.9.0")}


# -- dispatch, determinism, vocabulary -----------------------------------------------
def test_registry_dispatches_ruby_files():
    assert {"Gemfile.lock", "Gemfile"} <= registry.LOCKFILE_NAMES


def test_run_to_run_determinism(tmp_path):
    a = registry.extract_for_file(_write(tmp_path, LOCK, "Gemfile.lock"))
    b = registry.extract_for_file(_write(tmp_path, LOCK, "Gemfile.lock"))
    assert a == b


def test_confidence_vocabulary_pinned(tmp_path):
    result = registry.extract_for_file(_write(tmp_path, LOCK, "Gemfile.lock"))
    for edge in result["edges"]:
        assert edge["confidence"] in (
            contract.VERIFIED, contract.AMBIGUOUS, contract.UNRESOLVED,
            contract.UNSUPPORTED, contract.INVALID)
