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

import pathlib

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


def test_new_engine_coverage_present():
    """L1 must gate the secrets path, language reachability AND the privacy
    gate; L3 must sweep every engine's rule table including PII; L4 must
    probe iac+secrets through the corpus machinery, prove the bundle gate
    load-bearing, and hold the privacy engine to its behavioral contract."""
    brain = Brain()
    l1 = {n for n, _ in brain._checks["L1"]}
    assert {"_chk_L1_secrets_nonproduction_gate",
            "_chk_L1_language_gates_not_orphaned",
            "_chk_L1_pii_nonproduction_gate",
            "_chk_L1_pii_skip_dirs_in_sync"} <= l1
    l3 = {n for n, _ in brain._checks["L3"]}
    assert "_chk_L3_all_engine_rule_tables_wellformed" in l3
    l4 = {n for n, _ in brain._checks["L4"]}
    assert {"_chk_L4_iac_and_secrets_engines_crash_free",
            "_chk_L4_bundle_gate_has_teeth",
            "_chk_L4_privacy_engine_crash_free_and_gated"} <= l4


def test_privacy_gate_suppresses_and_passes_by_contract():
    """Direct teeth for the PII gate: nested localization and spec shapes are
    gated, production paths are not -- asserting the RELATIVE-path slash
    semantics the engine documents rather than the shape an outsider would
    guess."""
    import tempfile

    from analysis.privacy_data_exposure_engine import _is_non_production_text

    d = tempfile.mkdtemp(prefix="rsx_brain_pii_teeth_")
    gated = _is_non_production_text(
        pathlib.Path(d) / "src" / "i18n" / "strings.py", "x = 1", d)
    passed = _is_non_production_text(
        pathlib.Path(d) / "src" / "payments" / "service.py", "x = 1", d)
    assert gated and not passed


def test_privacy_engine_behavioral_gate_and_determinism():
    """The enrich-level contract: a production file with a concrete email
    yields its indicator, a nested i18n file with the same evidence yields
    none, and two runs agree exactly."""
    import tempfile

    from analysis.privacy_data_exposure_engine import (
        enrich_privacy_data_exposure as enrich,
    )

    d = pathlib.Path(tempfile.mkdtemp(prefix="rsx_brain_pii_run_"))
    (d / "service.py").write_text(
        'user_email = "alice@acme-corp.example"\n', encoding="utf-8")
    (d / "src" / "i18n").mkdir(parents=True)
    (d / "src" / "i18n" / "strings.py").write_text(
        'user_email = "bob@acme-corp.example"\n', encoding="utf-8")

    a = enrich(str(d), live_progress=False)
    b = enrich(str(d), live_progress=False)
    assert a == b
    files = {str(i.get("file", "")).replace("\\", "/")
             for i in a["indicators"]}
    assert any(f.endswith("service.py") for f in files), files
    assert not any("i18n" in f for f in files), files


def test_rule_table_sweep_covers_all_engines():
    brain = Brain()
    verdict = brain.run(only=["L3"])
    row = [c for c in verdict["checks"]
           if c["name"] == "_chk_L3_all_engine_rule_tables_wellformed"][0]
    assert row["status"] == "pass", row["evidence"]
    # The sweep must have covered the wide tables, not just a token few.
    # 343 = 183 enterprise (160 + 14 T-14.1b long-tail language rules
    # + 9 PHP webshell pack, registered in sast.py)
    # + 18 regex (17 + PYTHON_JINJA_FROM_STRING) + 13 known-secret + 10 generic-secret
    # + 18 tf + 17 docker + 12 k8s + 5 missing-rules + 40 llm + 10 cbom
    # + 10 pii-patterns + 7 pii-exposure + 6 PowerShell (C2-WIN) = 349.
    # Pinned exactly on purpose: adding or dropping a rule must fail this test
    # and force a conscious update.
    assert "349 rules across 12 tables" in row["evidence"], row["evidence"]


def test_iac_secrets_probes_report_per_fixture_counts():
    brain = Brain()
    verdict = brain.run(only=["L4"])
    row = [c for c in verdict["checks"]
           if c["name"] == "_chk_L4_iac_and_secrets_engines_crash_free"][0]
    assert row["status"] == "pass", row["evidence"]
    for fixture in ("iam_wildcard.tf", "root_user.Dockerfile",
                    "privileged_pod.yaml", "aws_credentials.py"):
        assert fixture in row["evidence"], (fixture, row["evidence"])


def test_language_gate_check_rejects_orphan_mapping(monkeypatch):
    """Teeth for the orphan-gate check: a LANG_BY_EXT key SCANNABLE_EXT
    refuses must fail the level (the G7/.sol shape)."""
    import scanner.sast as sast

    def orphan_probe() -> str:
        """CLAIM: an orphaned language gate must fail the L1 check (fixture)."""
        from analysis.validation import brain as brain_mod

        monkeypatch.setattr(
            sast, "LANG_BY_EXT", {**sast.LANG_BY_EXT, ".zz9": "fictitious"})
        brain_mod._chk_L1_language_gates_not_orphaned()
        return "unreachable -- the orphan must have raised"

    brain = Brain()
    brain.add_check("L1", orphan_probe)
    verdict = brain.run(only=["L1"])
    row = [c for c in verdict["checks"]
           if c["name"] == "orphan_probe"][0]
    assert row["status"] == "fail"
    assert "orphaned" in row["evidence"]
