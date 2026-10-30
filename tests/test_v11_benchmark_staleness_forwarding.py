"""Staleness must be recomputed for every row, and 'unknown' must not read as 'fresh'.

THE DEFECT, MEASURED
--------------------
Staleness was computed only for the project in the current invocation, inside the
per-target loop. Rows carried forward by merge() kept whatever `stale` value they had
from whenever they last ran -- or None, if they had never had one computed.

The reporting filter was then:

    fresh = [r for r in ok if not r.get("stale")]

None is falsy, so a row carrying no staleness information at all was counted as
fresh. That is not a subtle edge case, it is what happened:

    transformers-main artifact was 5.69 hours older than main.py
    transformers-main sweep row:  stale=None
    and was counted in "projects scanned cleanly: 2 / 9"
    and folded into the 4,193 findings reported as "current build only"

The harness asserted a project described the current build when it demonstrably did
not. Same absence-read-as-evidence inversion as G-125 and G-137, in the component
that produces the numbers people quote.

It triggers on every partial run. `--only llama_index` recomputed llama_index's flag
and left the other eight untouched, so a run that improves one project can leave the
others quietly overstating their currency -- with no visible change in the output.

THE INVARIANT
-------------
Currency is recomputed from the artifact on disk for every row that was not scanned
in this run; a row scanned in this run is fresh by construction; a row with no
artifact is explicitly unknown; and only `stale is False` counts as current.
"""
from __future__ import annotations

import ast
import importlib
import json
import pathlib
import sys
import time

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

mod = importlib.import_module("analysis.compare_ai_benchmarks")
SRC = (REPO / "analysis" / "compare_ai_benchmarks.py").read_text(encoding="utf-8")


# ------------------------------------------------------------- static shape --

def test_the_freshness_filter_requires_an_explicit_false():
    """The one-line inversion. `not r.get("stale")` is the defect.

    Checked against the parsed tree rather than the text. A text search cannot tell
    live code from a docstring describing the old bug, and this file's own comments
    quote that exact expression -- so the first version of this test failed on its
    own documentation, which is the sort of false positive worth designing out.
    """
    assert 'if r.get("stale") is False' in SRC, (
        "the freshness filter must require `stale is False`. Anything else treats a "
        "row whose currency was never established as evidence that it is current.")

    tree = ast.parse(SRC)
    offenders = []
    for node in ast.walk(tree):
        # Any bare `not X`, not merely `not X and Y`. The original defect is
        # `[... if not r.get("stale")]`, where the negation is a comprehension
        # condition and therefore a plain UnaryOp with no BoolOp around it. An
        # earlier version of this check looked only inside BoolOp and therefore
        # reported the pre-fix file as clean -- the assertion passed against the
        # exact code it exists to catch.
        if not (isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not)):
            continue
        seg = ast.get_source_segment(SRC, node) or ""
        if '.get("stale")' in seg or ".get('stale')" in seg:
            offenders.append(seg.replace("\n", " ")[:90])
    assert not offenders, (
        f"a live negation of the stale flag survives in executable code: {offenders}")


def test_unverified_rows_are_counted_separately_not_folded_in():
    assert 'r.get("stale") is None' in SRC, (
        "rows whose currency is unknown need their own bucket, or they vanish "
        "between 'fresh' and 'stale'")
    assert "currency never established" in SRC, (
        "the summary must state how many rows had no established currency; a reader "
        "cannot audit a tally whose excluded rows are never named")


def test_refresh_is_called_and_not_just_defined():
    assert SRC.count("refresh_staleness(results)") >= 2, (
        "refresh_staleness must be called after every merge AND once before the "
        "final summary, or a later merge can reintroduce rows with no flag")


# ------------------------------------------------------ behavioural checks --

def _write_artifacts(monkeypatch, tmp_path, ages: dict) -> None:
    """Create artifacts with the given age in seconds relative to the
    staleness anchor (newest production source mtime) -- the value
    artifact_staleness actually compares against.  Anchoring on
    time.time() instead made these tests wall-clock dependent despite
    the comment below: they passed only while some production file
    happened to be less than `age` old, and started failing once 20h
    had elapsed since main.py was last written (observed 2026-10-31,
    failed at HEAD too)."""
    out = tmp_path / "artifacts"
    anchor, _names = mod.newest_production_source_mtime()
    if not anchor:                       # no sources at all -> fall back
        anchor = time.time()
    for name, age in ages.items():
        d = out / name
        d.mkdir(parents=True, exist_ok=True)
        art = d / "clean_report.json"
        art.write_text(json.dumps({"metadata": {}, "findings": []}), encoding="utf-8")
        when = anchor - age
        import os
        os.utime(art, (when, when))
    monkeypatch.setattr(mod, "OUT", out)


def test_a_carried_forward_row_has_its_currency_recomputed(tmp_path, monkeypatch):
    """The regression. This row was never scanned in this run."""
    # 5.69 hours is the real measured gap for transformers-main; 36000s is close
    # enough to prove the point without depending on wall-clock state.
    _write_artifacts(monkeypatch, tmp_path, {"transformers-main": 36000 * 2})
    rows = [{"project": "transformers-main", "returncode": 0,
             "findings_len": 4173, "kloc": 1788, "seconds": 0,
             "scanned_this_run": False}]
    out = mod.refresh_staleness(rows)
    assert out[0]["stale"] is True, (
        "a row carried forward from a previous run must have its staleness "
        "recomputed from the artifact on disk, not inherit a flag from whenever it "
        "was last written")
    assert out[0]["staleness"]["reason"]


def test_a_row_with_no_staleness_key_is_not_mistaken_for_fresh(tmp_path, monkeypatch):
    """The specific inversion: absent flag, no artifact, previously counted fresh."""
    _write_artifacts(monkeypatch, tmp_path, {})
    rows = [{"project": "llama_index-main", "returncode": 0,
             "findings_len": 2737, "kloc": 471, "seconds": 0}]
    out = mod.refresh_staleness(rows)
    assert out[0]["stale"] is None, (
        "no artifact means currency is unknown, and unknown must be recorded as None "
        "-- omitting the key is what let it be read as fresh")
    assert "no clean_report.json" in out[0]["staleness"]["reason"]


def test_a_failed_scan_is_not_labelled_current(tmp_path, monkeypatch):
    """A regression introduced by the fix for this very defect.

    `scanned_this_run` is set when the scanner is LAUNCHED, before its outcome is
    known. So a refresher that treats it as sufficient marks a timed-out scan as
    describing the current build -- which is precisely the absence-read-as-evidence
    inversion G-139 removed, reintroduced through the fix.

    It happened: transformers-main came out of a sweep labelled `stale: False` with
    `findings_len: None`, having timed out and produced no artifact at all. The
    console tally said 8 of 9 current, and the markdown currency column would have
    read "current" beside a bolded rc=-9.
    """
    _write_artifacts(monkeypatch, tmp_path, {})
    rows = [{"project": "transformers-main", "returncode": -9,
             "scanned_this_run": True, "seconds": 7196.0}]
    out = mod.refresh_staleness(rows)
    assert out[0]["stale"] is None, (
        "a scan that timed out established nothing; it is not evidence that any "
        "artifact describes the current build")
    assert "did not complete" in out[0]["staleness"]["reason"]


def test_a_successful_scan_is_fresh_by_construction(tmp_path, monkeypatch):
    """Otherwise `stale is False` could never mean 'known current'."""
    _write_artifacts(monkeypatch, tmp_path, {})
    rows = [{"project": "babyagi-main", "returncode": 0, "findings_len": 20,
             "kloc": 7, "scanned_this_run": True}]
    assert mod.refresh_staleness(rows)[0]["stale"] is False


def test_a_zero_returncode_with_no_findings_is_not_current(tmp_path, monkeypatch):
    """rc=0 alone is not success; scan_one's 'no artifact was written' path."""
    _write_artifacts(monkeypatch, tmp_path, {})
    rows = [{"project": "odd-proj", "returncode": 0, "scanned_this_run": True,
             "error": "returncode 0 but no clean_report.json was written"}]
    out = mod.refresh_staleness(rows)
    assert out[0]["stale"] is None, (
        "a row with rc=0 but no findings_len has produced nothing; the harness's own "
        "message for that path says so")


def test_a_fresh_artifact_is_reported_fresh(tmp_path, monkeypatch):
    _write_artifacts(monkeypatch, tmp_path, {"babyagi-main": 0})
    rows = [{"project": "babyagi-main", "returncode": 0, "findings_len": 20,
             "kloc": 7, "scanned_this_run": False}]
    assert mod.refresh_staleness(rows)[0]["stale"] is False


def test_every_row_is_refreshed_not_only_the_named_one(tmp_path, monkeypatch):
    """A refresher that only handles its argument's first element is a trap."""
    _write_artifacts(monkeypatch, tmp_path, {"a-proj": 36000 * 2, "b-proj": 0})
    rows = [{"project": "a-proj", "returncode": 0, "findings_len": 1, "kloc": 1},
            {"project": "b-proj", "returncode": 0, "findings_len": 2, "kloc": 2},
            {"project": "c-proj", "returncode": 0, "findings_len": 3, "kloc": 3}]
    out = mod.refresh_staleness(rows)
    assert [r["stale"] for r in out] == [True, False, None]
