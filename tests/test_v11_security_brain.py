# -*- coding: utf-8 -*-
r"""Tests for the security brain itself.

A self-validation instrument that is not itself under test is an unfalsifiable
oracle -- the exact shape the corpus work spent six phases refusing. So the
brain gets the same treatment it gives the scanner:

  * its level structure is asserted, not assumed;
  * a full run must PASS on the healthy tree and be deterministic across two
    runs (same verdict, same counts, same check order);
  * a check that fails must fail the verdict and move the exit code to 1 --
    proven by INJECTING a failing check rather than by hoping one breaks;
  * a check that cannot establish its claim (raises) must read as BLOCKED and
    move the exit code to 2, never to PASS -- environmental limits are BLOCKED
    per the handoff contract, and a brain that papers over them would lie;
  * the offline contract is tested at its sharpest point: an operator who set
    RSECOPSX_LIVE_FEEDS=1 must get their value back after the run, because a
    validation tool that mutates its operator's environment disqualifies
    itself;
  * the teeth check's EVIDENCE must record both directions (legacy sink
    re-fired, fixed sink silent) -- a teeth result that only asserts its own
    pass is not inspectable.

The full-brain tests run the real checks against the real tree (~2s, L0's
compile pass dominating). Subset runs keep the rest fast.
"""
from __future__ import annotations

import pytest

from analysis.validation.brain import Brain


def _fail_check() -> str:
    """CLAIM: an injected failure must fail the verdict (test fixture)."""
    raise AssertionError("injected failure: the brain must surface me")


def _boom_check() -> str:
    """CLAIM: an injected crash must read as BLOCKED, never PASS (fixture)."""
    raise RuntimeError("injected environmental failure")


def test_levels_are_complete_ordered_and_claimed():
    brain = Brain()
    assert brain.LEVEL_IDS == ("L0", "L1", "L2", "L3", "L4", "L5")
    for lvl in brain.LEVEL_IDS:
        checks = brain._checks[lvl]
        assert checks, "%s has no checks" % lvl
        for _name, fn in checks:
            doc = (fn.__doc__ or "").strip()
            assert doc, "%s.%s states no claim" % (lvl, fn.__name__)
            assert doc.startswith("CLAIM:"), (
                "%s.%s claim must start with 'CLAIM:'" % (lvl, fn.__name__))


def test_full_run_passes_on_healthy_tree_and_is_deterministic():
    brain = Brain()
    v1 = brain.run()
    v2 = Brain().run()
    assert v1["exit_code"] == 0, _first_failure(v1)
    assert v1["verdict"] == "PASS"
    assert v1["counts"].get("pass", 0) == v2["counts"].get("pass", 0)
    assert [c["name"] for c in v1["checks"]] == [c["name"] for c in v2["checks"]]
    assert v1["verdict"] == v2["verdict"] == "PASS"


def _first_failure(verdict: dict) -> str:
    rows = [c for c in verdict["checks"] if c["status"] != "pass"]
    return "; ".join("%s/%s: %s" % (c["level"], c["name"], c["evidence"])
                     for c in rows[:3]) or "no failures recorded"


def test_injected_failure_fails_verdict_with_exit_1():
    brain = Brain()
    brain.add_check("L1", _fail_check)
    verdict = brain.run(only=["L1"])
    assert verdict["verdict"] == "FAIL"
    assert verdict["exit_code"] == 1
    row = [c for c in verdict["checks"] if c["name"] == "_fail_check"][0]
    assert row["status"] == "fail"
    assert "injected failure" in row["evidence"]


def test_injected_crash_reads_as_blocked_with_exit_2():
    brain = Brain()
    brain.add_check("L2", _boom_check)
    verdict = brain.run(only=["L2"])
    row = [c for c in verdict["checks"] if c["name"] == "_boom_check"][0]
    assert row["status"] == "blocked"
    assert verdict["verdict"] == "BLOCKED"
    assert verdict["exit_code"] == 2


def test_fail_outranks_blocked_in_the_verdict():
    brain = Brain()
    brain.add_check("L1", _fail_check)
    brain.add_check("L2", _boom_check)
    verdict = brain.run(only=["L1", "L2"])
    assert verdict["verdict"] == "FAIL"
    assert verdict["exit_code"] == 1


def test_operator_live_feeds_setting_survives_the_run(monkeypatch):
    import os

    monkeypatch.setenv("RSECOPSX_LIVE_FEEDS", "1")
    brain = Brain()
    verdict = brain.run(only=["L2"])
    assert verdict["verdict"] == "PASS", _first_failure(verdict)
    assert os.environ.get("RSECOPSX_LIVE_FEEDS") == "1", (
        "the brain mutated its operator's environment")


def test_teeth_evidence_records_both_directions():
    brain = Brain()
    verdict = brain.run(only=["L4"])
    row = [c for c in verdict["checks"]
           if c["name"] == "_chk_L4_word_boundary_control_has_teeth"][0]
    assert row["status"] == "pass"
    ev = row["evidence"]
    assert "re-fired" in ev and "kills" in ev, ev


def test_unknown_level_is_rejected_not_ignored():
    with pytest.raises(ValueError):
        Brain().run(only=["L9"])


def test_cli_returns_int_exit_codes():
    from analysis.validation.brain import main

    assert main(["--levels", "L1"]) == 0
