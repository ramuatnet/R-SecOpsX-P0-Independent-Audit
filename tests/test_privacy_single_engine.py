# -*- coding: utf-8 -*-
r"""T-14.2 / task.md section 14 item 2 -- privacy engine pick-one guard.

Task text: ``privacy_data_exposure_engine.py`` exists in *both*
``scanner/`` and ``analysis/``. Pick one.

Measured ground (2026-11-02, before this batch): the duplication was
already absent when checked -- exactly ONE definition of
``enrich_privacy_data_exposure`` exists outside excluded trees, at
``analysis/privacy_data_exposure_engine.py``, and git history has no
``scanner/privacy_data_exposure_engine.py`` ever added or deleted
(same staleness class as the task's "Ruby + Solidity enumerated but
unmatched" line, which landed @5694d8f). The pick is recorded here as
a GUARD so a second copy cannot quietly reappear: the check runs over
the tree (excluding the untracked legacy ``backup/`` copies and
``__pycache__``) and a teeth fixture proves the checker would flag a
duplicate.

No natural red for the main assertion (the invariant already holds --
disclosed); teeth instead, same pattern as the orphan-gate teeth test
(test_language_gate_check_rejects_orphan_mapping).
"""
from __future__ import annotations

import pathlib
import re

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]

#: Directories never scanned for definitions: untracked legacy .bak
#: trees (pre-existing, disclosed) and interpreter caches.
EXCLUDED_PARTS = {"backup", "__pycache__", ".git", "node_modules",
                  "dump", "quarantine", "Working folder"}

DEF_NEEDLE = "def enrich_privacy_data_exposure"

CHOSEN = "analysis/privacy_data_exposure_engine.py"

# Line-anchored on purpose: a bare substring needle self-matches this
# very file (DEF_NEEDLE = "def enrich_..." on one line -- measured in
# the red run). ``^def `` only matches a real module-level def.
_DEF_RE = re.compile(r"^def enrich_privacy_data_exposure\b", re.MULTILINE)


def _definitions(root: pathlib.Path) -> list[str]:
    """Repo-relative paths (posix) defining the privacy entry point."""
    hits: list[str] = []
    for path in root.rglob("*.py"):
        parts = set(path.parts)
        if parts & EXCLUDED_PARTS:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if _DEF_RE.search(text):
            hits.append(path.relative_to(root).as_posix())
    return sorted(hits)


# ---------------------------------------------------------------- disclosure


def test_chosen_copy_is_the_analysis_one():
    assert (REPO / CHOSEN).is_file(), "the chosen engine copy is missing"
    assert not (REPO / "scanner" / "privacy_data_exposure_engine.py").exists(), (
        "scanner/ copy reappeared -- §14 item 2 is pick-ONE")


def test_exactly_one_definition_in_the_tree():
    hits = _definitions(REPO)
    assert hits == [CHOSEN], hits


# -------------------------------------------------------------------- teeth


def test_checker_flags_a_duplicate(tmp_path):
    """The guard must fail when a second copy exists (fixture, not the
    live tree -- proves the check has teeth without mutating the repo)."""
    chosen = tmp_path / "analysis" / "privacy_data_exposure_engine.py"
    chosen.parent.mkdir(parents=True)
    chosen.write_text(
        "def enrich_privacy_data_exposure(*a, **k):\n    return {}\n",
        encoding="utf-8")
    assert _definitions(tmp_path) == ["analysis/privacy_data_exposure_engine.py"]

    dup = tmp_path / "scanner" / "privacy_data_exposure_engine.py"
    dup.parent.mkdir(parents=True)
    dup.write_text(chosen.read_text(encoding="utf-8"), encoding="utf-8")
    hits = _definitions(tmp_path)
    assert "scanner/privacy_data_exposure_engine.py" in hits, hits
    assert len(hits) == 2, hits


@pytest.mark.requires_prod_tree(artifact="backup/")
def test_backup_copies_are_excluded():
    """The 33 untracked legacy backup/ copies must not trip the guard."""
    backup = REPO / "backup"
    if not backup.is_dir():
        return  # nothing to prove on a tree without backup/
    backup_defs = [p for p in backup.rglob("*.py")
                   if _DEF_RE.search(_safe_read(p))]
    # sanity: they exist (so the exclusion is doing real work) ...
    assert backup_defs, "expected legacy backup copies to exist"
    # ... and none of them are in the live-tree result.
    live = _definitions(REPO)
    assert not any("backup/" in hit for hit in live), live


def _safe_read(path: pathlib.Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return ""
