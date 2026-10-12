"""V1 mutation testing: the scanner must notice one-edit security changes.

Two layers of assertion:
  * the default case table kills (scanner capability -- a survivor here is
    a demonstrated blind spot, reported as a miss, never relabelled), and
  * the harness's own miss/noise reporting is not vacuous -- synthetic
    cases whose outcomes are known prove it can fail, because a harness
    that can only print PASS measures nothing.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from analysis.validation.mutation import (  # noqa: E402
    MUTATION_CASES,
    MutationCase,
    run_case,
    run_mutations,
)


def test_default_case_table_is_well_formed():
    ids = [c.id for c in MUTATION_CASES]
    assert len(ids) == len(set(ids)), "duplicate case ids"
    assert len(MUTATION_CASES) >= 8, "case table shrank"
    for c in MUTATION_CASES:
        assert c.safe != c.mutated, f"{c.id}: safe and mutated sources identical"
        assert c.safe.strip() and c.mutated.strip()
        assert c.expect_cwes or c.expect_rules, f"{c.id}: no match criteria"
        assert c.filename.endswith((".py", ".go", ".java", ".js", ".ts", ".rb", ".php"))


def test_every_default_mutation_is_killed():
    summary = run_mutations()
    failures = []
    for r in summary["results"]:
        if r.status == "survived":
            failures.append(
                f"{r.case_id}: scanner did not report {r.description!r} "
                f"in the mutated source (baseline was clean)")
        elif r.status == "baseline_noisy":
            failures.append(
                f"{r.case_id}: baseline already matches the defect family "
                f"({[f.get('rule_id') for f in r.baseline_hits][:3]}), "
                f"so this pair measures nothing")
    assert not failures, "\n".join(failures)
    assert summary["ok"] and summary["killed"] == len(MUTATION_CASES)


def test_harness_reports_survivor_when_nothing_detects_it():
    # Canary: a mutation whose expected family cannot fire must come back
    # "survived" with a clean baseline. If this ever reports "killed", the
    # matcher is accepting unrelated findings and every PASS above is void.
    case = MutationCase(
        id="canary_survivor",
        description="nothing detects this family",
        filename="canary.py",
        safe="x = 1\n",
        mutated="y = 2\n",
        expect_rules=("NEVER_MATCHES_ANY_RULE",),
        expect_cwes=("CWE-0000",),
    )
    result = run_case(case)
    assert result.status == "survived"
    assert result.baseline_hits == []
    assert result.mutant_hits == []


def test_harness_flags_a_noisy_baseline():
    # Canary: when the safe source already trips the expected family, the
    # pair must be rejected as unmeasurable instead of counting as a kill.
    case = MutationCase(
        id="canary_noisy",
        description="baseline already vulnerable",
        filename="canary.py",
        safe='def go(raw):\n    return eval(raw)\n',
        mutated='def go(raw):\n    return eval(raw, {})\n',
        expect_cwes=("CWE-94", "CWE-95"),
        expect_rules=("EVAL",),
    )
    result = run_case(case)
    assert result.status == "baseline_noisy"
    assert result.baseline_hits, "expected the baseline eval() to be reported"


def test_single_case_runner_and_json_ready_shape():
    summary = run_mutations([MUTATION_CASES[0]])
    assert summary["total"] == 1
    assert summary["killed"] == 1
    assert summary["results"][0].case_id == MUTATION_CASES[0].id
    assert summary["results"][0].ok


def test_cli_exit_codes(tmp_path, capsys):
    from analysis.validation import mutation as mod

    # Default table passes (exit 0).
    assert mod.main([]) == 0

    # An impossible case on the command line is a usage error (exit 2 from
    # argparse), not a silent pass.
    with pytest.raises(SystemExit) as exc:
        mod.main(["--case", "no_such_case"])
    assert exc.value.code == 2
