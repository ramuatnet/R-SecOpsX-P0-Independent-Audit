"""Gemfile.lock direct declarations come from the DEPENDENCIES section (R1/W3, GAP-09).

The defect this pins: ``parse_gemfile_lock`` stamped ``direct = (indent <= 4)``,
but a real Gemfile.lock lists EVERY resolved gem -- declared and pulled-in
alike -- flat at 4-space indent in ``specs:`` (measured on railsgoat-main:
197 specs, all stamped direct). The authoritative declared set is the
``DEPENDENCIES`` section, which the parser never read. Because
``infer_dependency_type`` returns "Direct" unconditionally for
``direct is True`` (Task 2, RC-2), every Gemfile.lock row -- including pure
transitive gems -- bypassed the evidence gate and classified Direct.

Contract (R1 approval): the DEPENDENCIES section is the direct declaration
authority; every other resolved spec stamps ``direct=False`` and classifies
through the evidence gate via lockfile membership; indentation is never a
classification signal.

Known limitation (registered follow-up, NOT in R1 scope): GIT/PATH/PLUGIN
section specs are not collected by the parser at all -- unchanged here.
"""

import re
from pathlib import Path

from scanner.manifests.gemfile_lock import parse_gemfile_lock
from scanner.dependency_intelligence import infer_dependency_type

CORPUS_LOCK = (Path(__file__).resolve().parents[1]
               / "tests" / "vuln-test-corpus" / "sca" / "rubygems"
               / "vulnerable" / "Gemfile.lock")

RAILS_TREE = """\
GEM
  remote: https://rubygems.org/
  specs:
    rails (7.0.3.1)
      actioncable (= 7.0.3.1)
      actionpack (= 7.0.3.1)
    actioncable (7.0.3.1)
    actionpack (7.0.3.1)

PLATFORMS
  ruby

DEPENDENCIES
  rails

BUNDLED WITH
   2.4.10
"""


def _write(tmp_path, text):
    lock = tmp_path / "Gemfile.lock"
    lock.write_text(text, encoding="utf-8")
    return str(lock)


def _by_name(rows):
    return {r["name"]: r for r in rows}


def test_declared_gem_is_direct(tmp_path):
    rows = _by_name(parse_gemfile_lock(_write(tmp_path, RAILS_TREE)))
    assert rows["rails"]["direct"] is True


def test_undeclared_specs_are_not_direct(tmp_path):
    # actioncable/actionpack are pulled in by rails and sit at the SAME
    # 4-space indent -- indentation must not make them direct.
    rows = _by_name(parse_gemfile_lock(_write(tmp_path, RAILS_TREE)))
    assert rows["actioncable"]["direct"] is False
    assert rows["actionpack"]["direct"] is False


def test_undeclared_rows_classify_transitive_via_evidence_gate(tmp_path):
    # End-to-end through Task 2's gate: a non-direct Gemfile.lock row has
    # lockfile-membership evidence, so it classifies Transitive -- never
    # Unknown, and no longer Direct.
    rows = parse_gemfile_lock(_write(tmp_path, RAILS_TREE))
    types = {r["name"]: infer_dependency_type(r) for r in rows}
    assert types["rails"] == "Direct"
    assert types["actioncable"] == "Transitive"
    assert types["actionpack"] == "Transitive"


def test_declared_entry_with_constraint_still_matches(tmp_path):
    tree = RAILS_TREE.replace("DEPENDENCIES\n  rails\n",
                              "DEPENDENCIES\n  rails (~> 7.0)\n")
    rows = _by_name(parse_gemfile_lock(_write(tmp_path, tree)))
    assert rows["rails"]["direct"] is True


def test_declared_not_resolved_is_not_invented(tmp_path):
    tree = RAILS_TREE.replace("DEPENDENCIES\n  rails\n",
                              "DEPENDENCIES\n  rails\n  ghostgem\n")
    rows = parse_gemfile_lock(_write(tmp_path, tree))
    names = {r["name"] for r in rows}
    assert "ghostgem" not in names
    assert names == {"rails", "actioncable", "actionpack"}


def test_constraint_lines_are_still_skipped(tmp_path):
    # The 6-space `name (= x.y)` constraint specs under each gem must stay
    # excluded from the row set even though they now sit inside a resolved
    # tree's flat spec list.
    rows = _by_name(parse_gemfile_lock(_write(tmp_path, RAILS_TREE)))
    assert set(rows) == {"rails", "actioncable", "actionpack"}
    assert all(re.fullmatch(r"\d+(?:\.\d+)*", r["version"]) for r in rows.values())


def test_real_corpus_lockfile_classification():
    # The real-tree evidence that motivated W3: only `rails` is declared in
    # this corpus lockfile; actioncable/actionpack are transitive.
    assert CORPUS_LOCK.exists(), "corpus fixture missing"
    rows = _by_name(parse_gemfile_lock(str(CORPUS_LOCK)))
    assert rows["rails"]["direct"] is True
    assert rows["actioncable"]["direct"] is False
    assert rows["actionpack"]["direct"] is False


def test_real_railsgoat_lockfile_subset_is_transitive():
    # railsgoat-main: 197 resolved specs, far fewer DEPENDENCIES entries.
    # A purely-transitive gem must not carry direct=True.
    railsgoat = Path(r"D:\data\Code test\prodtest\railsgoat-main\Gemfile.lock")
    if not railsgoat.exists():
        import pytest
        pytest.skip("railsgoat corpus not present on this machine")
    rows = _by_name(parse_gemfile_lock(str(railsgoat)))
    declared_indirect = [n for n, r in rows.items()
                         if n in ("websocket-driver", "nio4r", "zeitwerk")]
    assert declared_indirect, "expected railsgoat transitive gems in row set"
    for name in declared_indirect:
        assert rows[name]["direct"] is False, name
