"""T-9.17 ReDoS suite in CI (task.md section 13 "ReDoS suite in CI").

WHAT THIS DELIVERS (and pins):
* ci_matrix gains an 11th gate ``redos_suite`` running
  tests/test_redos_budget.py -- the T-0.5 suite has existed since the
  budget landed, but it only ever rode the generic pytest run, which no
  CI job invokes wholesale, so the matrix never audited the rule tables
  or proved the subprocess hard-guard still interrupts a catastrophe;
* validation.yml gains a standalone ``redos-suite`` job (direct signal,
  same shape as phase0-gate-tests) and lists it in ci-matrix's
  ``needs`` so a red ReDoS suite gates the matrix the way the other
  suites do.

Tests: disclosure needles in the ci_matrix source, workflow structure
through yaml, a recorder that captures run_ci_matrix's gate registry
WITHOUT executing the gates (so the pins cost milliseconds, not the
full matrix), and a collect-smoke of the gated suite file.
"""
from __future__ import annotations

import pathlib
import subprocess
import sys

import pytest
import yaml

REPO = pathlib.Path(__file__).resolve().parents[1]
CI_SRC = REPO / "analysis" / "validation" / "ci_matrix.py"
WORKFLOW_PATH = REPO / ".github" / "workflows" / "validation.yml"
REDOS_SUITE = REPO / "tests" / "test_redos_budget.py"

#: The registry run_ci_matrix must build, in append order.  A gate
#: added later extends this tuple deliberately (one batch = one
#: measurement); a gate silently dropped or reordered fails here.
EXPECTED_GATES = (
    "golden_corpus",
    "corpus_manifest",
    "corpus_replay",
    "version_fuzzing",
    "v0_unit_tests",
    "phase0_gate_tests",
    "mutation_testing",
    "rust_core",
    "engine_parity",
    "variant_stability",
    "redos_suite",
)


def _ci_src() -> str:
    return CI_SRC.read_text(encoding="utf-8")


def _workflow() -> dict:
    return yaml.safe_load(WORKFLOW_PATH.read_text(encoding="utf-8"))


# ---------------------------------------------------------------- disclosure


def test_disclosure_needles_ci_matrix():
    src = _ci_src()
    needles = (
        "ReDoS suite in CI (task.md section 13",
        "redos_suite",
        "test_redos_budget.py",
        "REGEX_TIMEOUT",
    )
    for needle in needles:
        assert needle in src, "ci_matrix disclosure missing: %r" % needle


# ------------------------------------------------------------------ workflow


def test_workflow_has_standalone_redos_job():
    workflow = _workflow()
    assert "redos-suite" in workflow["jobs"], "redos-suite job missing"
    runs = [
        str(step.get("run", ""))
        for step in workflow["jobs"]["redos-suite"]["steps"]
    ]
    joined = "\n".join(runs)
    assert "test_redos_budget.py" in joined, joined
    assert "pip install pytest" in joined, joined
    assert "ubuntu-latest" == workflow["jobs"]["redos-suite"]["runs-on"]


def test_workflow_lists_redos_in_ci_matrix_needs():
    workflow = _workflow()
    needs = workflow["jobs"]["ci-matrix"]["needs"]
    assert "redos-suite" in needs, needs
    # the phase5 pin: pr-scan is pull-request-only, a needs-edge onto a
    # skipped job would silence ci-matrix on every push.
    assert "pr-scan" not in needs, needs


# ------------------------------------------------------- gate registry pins


def test_gate_registry_is_pinned(monkeypatch):
    """Capture the gate list without executing any gate.

    run_ci_matrix only builds commands via _run; replacing it with a
    recorder turns the whole registry into a millisecond-scale pin
    (names, order, the redos command bytes, its tight cap).
    """
    from analysis.validation import ci_matrix

    recorded: list[dict] = []

    def _recorder(name, cmd, timeout=300):
        recorded.append({"name": name, "cmd": list(cmd),
                         "timeout": timeout})
        return {"name": name, "exit_code": 0, "passed": True,
                "stdout_tail": "", "stderr_tail": ""}

    monkeypatch.setattr(ci_matrix, "_run", _recorder)
    result = ci_matrix.run_ci_matrix()

    names = tuple(g["name"] for g in recorded)
    assert names == EXPECTED_GATES, names
    assert result["total"] == len(EXPECTED_GATES)
    assert result["failed"] == []

    redos = next(g for g in recorded if g["name"] == "redos_suite")
    assert redos["cmd"] == [
        sys.executable, "-m", "pytest",
        str(REPO / "tests" / "test_redos_budget.py"),
        "-v", "--tb=short",
    ]
    # tight cap on purpose: the suite measures ~7s standalone, and a
    # default 300s cap would swallow hangs the way v0's cap does.
    assert redos["timeout"] == 120, redos["timeout"]


# ------------------------------------------------------------- suite health


def test_gated_suite_file_still_collects():
    """The CI gate must point at a suite that imports and collects."""
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", str(REDOS_SUITE),
         "--collect-only", "-q"],
        cwd=str(REPO), capture_output=True, text=True, encoding="utf-8",
        errors="replace", timeout=120)
    assert proc.returncode == 0, (proc.stdout[-1500:], proc.stderr[-1500:])
    assert "test_redos_budget.py::" in proc.stdout, proc.stdout[-1500:]
