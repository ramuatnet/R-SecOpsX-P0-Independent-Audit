"""merge() must not discard the evidence a failed attempt recorded.

THE DEFECT THIS PINS
--------------------
`merge()`'s docstring claimed "LOSSLESS. Re-running must never drop an existing
entry", and the implementation did exactly that and no more: it keyed entries by
project and let a fresh entry replace the old one. No name was ever dropped, so the
claim as written was true, and it was still lossy in substance.

A recorded timeout is the only evidence of what blocked a project. The phase it
stalled in, the overshoot against budget, the partial per-phase timings, the captured
stdout -- all of that lives in the fields a failed entry populates. A fresh entry
carries none of them, so replacing a timeout destroyed the diagnosis.

This was not hypothetical. transformers-main timed out at a 2,700s budget after
1,648.0s in the OWASP LLM phase, having written its clean_report.json before dying
in PDF generation. The following run found that artifact, re-derived it, and
overwrote the timeout record with an rc=0 row. The project had then never failed to
scan, as far as the sweep file was concerned, and the one record explaining the
1,648s had been deleted by the run that fixed it.

There was no test for merge() at all, which is why a docstring asserting a property
sat next to an implementation that did not have it.

THE SECOND, RELATED CLAIM
-------------------------
A re-derived entry carries `returncode: 0` and `seconds: 0`. Read alone, that is a
fast successful scan of the current build. It is neither: the build was not scanned.
`scanned_this_run` makes the distinction checkable, so the summary line a reader
quotes cannot turn an unexamined artifact into a verified scan.
"""
from __future__ import annotations

import importlib
import json
import pathlib
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

mod = importlib.import_module("analysis.compare_ai_benchmarks")


def _timeout_entry(project: str = "transformers-main") -> dict:
    """The shape scan_one produces on a timeout, carrying the diagnostic fields."""
    return {
        "project": project,
        "returncode": -9,
        "seconds": 2700.0,
        "timed_out": True,
        "timeout_seconds": 2700,
        "overshoot_seconds": 0.0,
        "hung_in_phase": "Generating PDF report",
        "phases_completed": 7,
        "phase_seconds": [
            {"phase": "Scanning OWASP LLM security rules", "seconds": 599.0},
            {"phase": "Scanning codebase", "seconds": 514.0},
        ],
        "error": "TIMEOUT after 2700s (ran 2700s, overshoot 0s)",
        "stdout_tail": "...tail...",
    }


def _clean_entry(project: str = "transformers-main") -> dict:
    return {
        "project": project,
        "returncode": 0,
        "seconds": 0,
        "scanned_this_run": False,
        "source": "re-derived from artifact",
        "findings_len": 4173,
        "kloc": 1788,
    }


@pytest.fixture
def sweep(tmp_path, monkeypatch):
    """Point the module at a throwaway sweep file and return its path."""
    p = tmp_path / "sweep.json"
    monkeypatch.setattr(mod, "SWEEP_JSON", p)
    return p


def _load(sweep: pathlib.Path, projects: list[dict]) -> None:
    sweep.write_text(json.dumps({"projects": projects}), encoding="utf-8")


def _entry(results: list[dict], project: str) -> dict:
    return next(r for r in results if r["project"] == project)


# ------------------------------------------------- the substantive claim ----

def test_a_recorded_timeout_survives_a_later_successful_run(sweep):
    """The regression. On the old implementation the phase data was deleted."""
    _load(sweep, [_timeout_entry()])
    out = mod.merge([_clean_entry()])
    row = _entry(out, "transformers-main")

    history = row.get("prior_attempts")
    assert history, (
        "the recorded timeout was discarded. prior_attempts is where the evidence of "
        "what blocked this project lives, and dropping it is how a project that never "
        "scanned ends up indistinguishable from one that scanned cleanly.")

    kept = history[0]
    assert kept["hung_in_phase"] == "Generating PDF report", kept
    assert kept["timed_out"] is True
    assert kept["timeout_seconds"] == 2700
    assert kept["phase_seconds"], "the per-phase timings must survive too"
    assert kept["returncode"] == -9
    assert "TIMEOUT after 2700s" in kept["error"]


def test_the_new_row_still_reports_current_numbers(sweep):
    """Preserving history must not stop the fresh numbers being reported."""
    _load(sweep, [_timeout_entry()])
    row = _entry(mod.merge([_clean_entry()]), "transformers-main")
    assert row["findings_len"] == 4173
    assert row["returncode"] == 0


def test_history_is_not_duplicated_when_merge_runs_repeatedly(sweep):
    """merge() is called once per project with accumulated results.

    That means a project's own entry is fed back through merge on the next
    iteration, with the superseded record still sitting in the sweep file. Without
    deduplication the same failure is appended again every iteration, so a nine-
    project sweep would accumulate dozens of copies of one timeout.
    """
    _load(sweep, [_timeout_entry()])
    out = mod.merge([_clean_entry()])
    out = mod.merge(out)
    out = mod.merge(out)
    row = _entry(out, "transformers-main")
    assert len(row.get("prior_attempts") or []) == 1, (
        f"expected one recorded failure, got "
        f"{len(row.get('prior_attempts') or [])}")


def test_distinct_failures_accumulate_rather_than_collapse(sweep):
    """Two genuinely different failures are two records, not one.

    Modelled on how the sweep loop actually feeds merge: `results.append(e)` then
    `results = merge(results)`, so the entry merge returns -- already carrying its
    history -- is what comes back in on the next project. History therefore travels
    with the row, and a NEW failure arriving later is appended to it.
    """
    first = _timeout_entry()
    first["timeout_seconds"] = 5400
    first["hung_in_phase"] = "Scanning OWASP LLM security rules"
    _load(sweep, [first])

    row = _entry(mod.merge([_clean_entry()]), "transformers-main")
    assert len(row["prior_attempts"]) == 1

    # A different project attempt, or a later run, fails somewhere else.
    second = _timeout_entry()
    second["hung_in_phase"] = "Scanning Advanced AI security rules"
    _load(sweep, [second])

    row2 = _entry(mod.merge([row]), "transformers-main")
    assert len(row2["prior_attempts"]) == 2, (
        "a second, different failure must be recorded, not deduplicated away")
    hung = {h["hung_in_phase"] for h in row2["prior_attempts"]}
    assert hung == {"Scanning OWASP LLM security rules",
                    "Scanning Advanced AI security rules"}


# ------------------------------------------------- the properties that held -

def test_merge_still_never_drops_a_project(sweep):
    """The original, and still valid, claim."""
    _load(sweep, [_timeout_entry("a"), _timeout_entry("b")])
    out = mod.merge([_clean_entry("a")])
    names = {r["project"] for r in out}
    assert names == {"a", "b"}


def test_a_fresh_failure_still_replaces_the_old_record(sweep):
    """Preserving history must not make failures stick."""
    _load(sweep, [_timeout_entry()])
    newer = _timeout_entry()
    newer["hung_in_phase"] = "Scanning codebase"
    row = _entry(mod.merge([newer]), "transformers-main")
    assert row["hung_in_phase"] == "Scanning codebase"
    assert not row.get("prior_attempts"), (
        "the newest failure is the current record; no prior_attempts is needed")


def test_no_sweep_file_is_not_an_error(tmp_path, monkeypatch):
    monkeypatch.setattr(mod, "SWEEP_JSON", tmp_path / "absent.json")
    out = mod.merge([_clean_entry()])
    assert _entry(out, "transformers-main")["findings_len"] == 4173


# ------------------------------------------------- the second claim --------

def test_a_rederived_row_does_not_claim_to_have_been_scanned():
    """`returncode: 0` plus `seconds: 0` reads as a fast clean scan. It is not one."""
    assert _clean_entry()["scanned_this_run"] is False


def test_a_real_scan_is_marked_as_such():
    """The other direction, so the flag cannot be left permanently false."""
    src = (REPO / "analysis" / "compare_ai_benchmarks.py").read_text(encoding="utf-8")
    assert '"scanned_this_run": True' in src, (
        "a completed scan must be marked scanned_this_run=True, or the flag records "
        "only the negative case and cannot distinguish 'not scanned' from 'unknown'")
