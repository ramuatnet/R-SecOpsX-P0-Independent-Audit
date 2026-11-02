# -*- coding: utf-8 -*-
r"""T-14.2 -- wire analysis/audit_dead_code.py into CI (task.md section 14
"Dead code": ``analysis/audit_dead_code.py`` exists -- wire it into CI).

Measured ground (2026-11-02, before this batch):

* the audit itself is green today: 677 live .py files, 677 reachable,
  0 dead, exit 0 (stdlib-only, seconds-fast) -- so wiring it into CI
  cannot go red on day one;
* it was NOT wired anywhere: no ci_matrix gate, no validation.yml job
  -- the reachability question G-060 introduced was answerable only by
  a human remembering to run it;
* the t117 gate-registry pin (EXPECTED_GATES) currently ends at
  ``self_sbom`` (gate 12) -- a 13th gate must extend that tuple in the
  same commit or the pin fails (deliberate, one batch = one
  measurement).

Shape follows the t117/t118 precedent exactly: a tight-capped matrix
gate + a standalone validation.yml job listed in ci-matrix's needs, so
a dead module gates the matrix the way the other suites do. The audit
is stdlib-only, so the standalone job needs no pip install (pinned).
"""
from __future__ import annotations

import json
import pathlib
import subprocess
import sys

import yaml

REPO = pathlib.Path(__file__).resolve().parents[1]
CI_SRC = REPO / "analysis" / "validation" / "ci_matrix.py"
WORKFLOW_PATH = REPO / ".github" / "workflows" / "validation.yml"
AUDIT = REPO / "analysis" / "audit_dead_code.py"


def _ci_src() -> str:
    return CI_SRC.read_text(encoding="utf-8")


def _workflow() -> dict:
    return yaml.safe_load(WORKFLOW_PATH.read_text(encoding="utf-8"))


# ---------------------------------------------------------------- disclosure


def test_disclosure_needles_ci_matrix():
    src = _ci_src()
    needles = (
        "T-14.2",
        "dead_code_audit",
        "audit_dead_code.py",
    )
    for needle in needles:
        assert needle in src, "ci_matrix disclosure missing: %r" % needle


# ------------------------------------------------------- gate registry pins


def test_gate_registry_includes_dead_code_audit(monkeypatch):
    """Capture the gate list without executing any gate (t117 pattern).

    Pins the 13th gate's name, command bytes and tight cap; the full
    append-order tuple lives in test_t117_redos_ci.EXPECTED_GATES
    (updated in this batch's commit per the pin's own instruction).
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
    assert "dead_code_audit" in names, names
    assert names.index("dead_code_audit") == len(names) - 1, (
        "dead_code_audit must be appended last (append-order pin)", names)
    assert result["failed"] == []

    gate = next(g for g in recorded if g["name"] == "dead_code_audit")
    assert gate["cmd"] == [
        sys.executable, str(REPO / "analysis" / "audit_dead_code.py"),
    ]
    # tight cap on purpose: the audit measures seconds standalone
    # (677 files walked), and a default 300s cap would swallow hangs
    # the way v0's cap does (same rationale as redos 120 / sbom 60).
    assert gate["timeout"] == 60, gate["timeout"]


# ------------------------------------------------------------------ workflow


def test_workflow_has_standalone_dead_code_job():
    workflow = _workflow()
    assert "dead-code-audit" in workflow["jobs"], (
        "dead-code-audit job missing")
    job = workflow["jobs"]["dead-code-audit"]
    runs = [str(step.get("run", "")) for step in job["steps"]]
    joined = "\n".join(runs)
    assert "analysis/audit_dead_code.py" in joined, joined
    assert "ubuntu-latest" == job["runs-on"]
    # stdlib-only audit: the job must not grow a pip install (pinned so
    # a dependency creep fails here instead of hiding in CI).
    assert "pip install" not in joined, joined


def test_workflow_lists_dead_code_in_ci_matrix_needs():
    workflow = _workflow()
    needs = workflow["jobs"]["ci-matrix"]["needs"]
    assert "dead-code-audit" in needs, needs
    # the phase5 pin, restated: pr-san is pull-request-only (a needs-edge
    # onto a skipped job would silence ci-matrix on every push).
    assert "pr-scan" not in needs, needs


# ------------------------------------------------------------- suite health


def test_audit_script_runs_clean():
    """Collect-smoke for the gated script: it executes, exits 0 and the
    invariant it exists for holds (zero dead modules). `dead == []` is
    the G-060 reachability invariant, not a pinned count of anything
    that legitimately grows."""
    proc = subprocess.run(
        [sys.executable, str(AUDIT), "--json"],
        capture_output=True, text=True, encoding="utf-8",
        errors="replace", cwd=str(REPO), timeout=60)
    assert proc.returncode == 0, proc.stdout[-500:] + proc.stderr[-500:]
    data = json.loads(proc.stdout)
    assert data["dead"] == [], data["dead"]
