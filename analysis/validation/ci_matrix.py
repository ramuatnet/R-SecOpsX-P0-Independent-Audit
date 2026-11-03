"""CI validation matrix runner (Phase V6).

Runs all validation phases in sequence and reports a unified status.
Designed to be called from CI (GitHub Actions, GitLab CI, etc.).

Exit codes:
    0   all gates passed
    1   at least one gate failed
"""
from __future__ import annotations

import json
import logging
import subprocess
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

_LOG = logging.getLogger("rsx.analysis.validation.ci_matrix")

ROOT = Path(__file__).resolve().parents[2]


def _run(name: str, cmd: list[str], timeout: int = 300) -> dict:
    """Run a validation command and return its result."""
    _LOG.info("running: %s", " ".join(cmd))
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=str(ROOT),
            timeout=timeout,
        )
        return {
            "name": name,
            "command": cmd,
            "exit_code": result.returncode,
            "passed": result.returncode == 0,
            "stdout_tail": result.stdout[-2000:] if result.stdout else "",
            "stderr_tail": result.stderr[-1000:] if result.stderr else "",
        }
    except subprocess.TimeoutExpired:
        return {
            "name": name,
            "command": cmd,
            "exit_code": -1,
            "passed": False,
            "stdout_tail": "",
            "stderr_tail": "TIMEOUT",
        }
    except Exception as e:
        return {
            "name": name,
            "command": cmd,
            "exit_code": -1,
            "passed": False,
            "stdout_tail": "",
            "stderr_tail": str(e),
        }


def run_ci_matrix() -> dict:
    """Run all validation gates and return the unified result."""
    gates = []

    # V0: golden corpus (all families)
    gates.append(_run(
        "golden_corpus",
        [sys.executable, "-m", "analysis.validation.run",
         "--corpus", str(ROOT / "tests" / "vuln-test-corpus")]
    ))

    # T-3.1: the committed manifest + pinned SCA store must describe the
    # corpus as it stands (a label/fixture edit without a re-emit fails
    # here, before the replay can diff against a stale index).
    gates.append(_run(
        "corpus_manifest",
        [sys.executable, str(ROOT / "tools" / "emit_corpus_manifest.py"),
         "--check"]
    ))

    # T-3.2: deterministic replay -- double-run byte-identical, golden
    # diff, and the manifest's TP/FN/FP assertions, all offline.
    gates.append(_run(
        "corpus_replay",
        [sys.executable, "-m", "analysis.validation.replay"]
    ))

    # V2.3: version fuzzing
    gates.append(_run(
        "version_fuzzing",
        [sys.executable, "-m", "analysis.validation.fuzz_versions", "--count", "1000"]
    ))

    # V0: V0 unit tests. T-15 (section 15): calibrated timeout, not the
    # 300s _run default -- the healthy gate measured 374.2s (173 passed,
    # rc=0, 2026-11-03) and had been chronically false-red under the
    # default for 6+ matrix runs. 600s = measured + hang headroom (the
    # same class engine_parity/variant_stability already use); a real
    # hang still fails the gate.
    gates.append(_run(
        "v0_unit_tests",
        [sys.executable, "-m", "pytest",
         str(ROOT / "tests" / "test_v01_golden_corpus.py"),
         str(ROOT / "tests" / "test_v02_normalizer_comparator.py"),
         str(ROOT / "tests" / "test_v03_differential.py"),
         "-v", "--tb=short"],
        timeout=600,
    ))

    # Phase 0: security gate tests
    gates.append(_run(
        "phase0_gate_tests",
        [sys.executable, "-m", "pytest",
         str(ROOT / "tests" / "test_phase0_security_gate.py"),
         str(ROOT / "tests" / "test_phase0_gate_metadata.py"),
         "-v", "--tb=short"]
    ))

    # V1.3: mutation testing (one-edit defect pairs must be detected)
    gates.append(_run(
        "mutation_testing",
        [sys.executable, "-m", "analysis.validation.mutation"]
    ))

    # T-1.1/T-1.2: native engine -- cargo build + crate unit tests + the
    # bridge tests with RSX_RUST_REQUIRED=1. Fails RED (never skips) when
    # the toolchain or the build is missing: a silently dropped gate is a
    # silent drop of native-engine validation.
    gates.append(_run(
        "rust_core",
        [sys.executable, str(ROOT / "tools" / "rust_core_gate.py")],
        timeout=900,
    ))

    # T-1.5: engine parity -- py vs rust on the golden corpus, normalized
    # rows, annotated deltas. Runs AFTER rust_core (same process order)
    # so the native extension the build just produced is loadable; if it
    # is not, this gate fails RED the same way rust_core does -- never a
    # silent skip. Strict/perf modes are on-demand flip criteria, not CI.
    gates.append(_run(
        "engine_parity",
        [sys.executable, "-m", "analysis.validation.parity_gate"],
        timeout=600,
    ))

    # T-3.3: per-rule detection stability vs the committed baseline.
    # Fails on any per-rule drop beyond the 5pp tolerance (task.md
    # gate). Reverse mode (--reverse) is the FN hunt and stays on-demand
    # -- CI measures forward stability only.
    gates.append(_run(
        "variant_stability",
        [sys.executable, "-m", "analysis.validation.variant_hunter",
         "--check-baseline"],
        timeout=600,
    ))

    # T-9.17 ReDoS suite in CI (task.md section 13): the T-0.5 ReDoS
    # budget suite runs as its own matrix gate.  The suite has existed
    # since the budget landed (static nested-quantifier audit over the
    # rule tables, subprocess hard-guard interrupting a synthetic
    # catastrophe with a REGEX_TIMEOUT row instead of a silent skip, the
    # 5 MB minified-JS <250ms accept criterion) but only ever rode the
    # generic pytest run, which no CI job invokes wholesale.  Tight
    # 120s cap on purpose: ~7s standalone, and a default 300s cap would
    # swallow hangs the way the v0 cap does.
    gates.append(_run(
        "redos_suite",
        [sys.executable, "-m", "pytest",
         str(ROOT / "tests" / "test_redos_budget.py"),
         "-v", "--tb=short"],
        timeout=120,
    ))

    # T-9.18 SBOM of the scanner itself (task.md section 13): the
    # committed CycloneDX self-SBOM is re-generated from the repo
    # sources (pyproject extras, Cargo.lock resolution, Dockerfile
    # base) and byte-compared -- a dependency edit without a re-emit
    # fails here (rc 0/1/2; drift is 1).  Offline, seconds-fast, tight
    # 60s cap.
    gates.append(_run(
        "self_sbom",
        [sys.executable, str(ROOT / "tools" / "emit_self_sbom.py"),
         "--check"],
        timeout=60,
    ))

    # T-14.2 (task.md section 14 "Dead code"): analysis/audit_dead_code.py
    # is wired into CI as the 13th gate -- the G-060 reachability audit
    # (no root reaches a live .py => dead, exit 1) had no CI surface
    # before, so a quarantinable module could sit unnoticed. The audit
    # is stdlib-only and walks the tree in seconds (677 files measured),
    # hence the tight 60s cap (same rationale as redos 120 / sbom 60:
    # a default 300s cap would swallow hangs the way the v0 cap does).
    gates.append(_run(
        "dead_code_audit",
        [sys.executable, str(ROOT / "analysis" / "audit_dead_code.py")],
        timeout=60,
    ))

    passed = sum(1 for g in gates if g["passed"])
    failed = [g["name"] for g in gates if not g["passed"]]

    return {
        "total": len(gates),
        "passed": passed,
        "failed": failed,
        "gates": gates,
    }


def main(argv: list[str] | None = None) -> int:
    import argparse
    parser = argparse.ArgumentParser(
        prog="analysis.validation.ci_matrix",
        description="Run the full CI validation matrix.")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    result = run_ci_matrix()

    if args.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        print("CI Validation Matrix")
        print("=" * 60)
        for gate in result["gates"]:
            status = "PASS" if gate["passed"] else "FAIL"
            print("  [%s] %s" % (status, gate["name"]))
            if not gate["passed"]:
                stderr = gate.get("stderr_tail", "")
                if stderr:
                    print("    stderr: %s" % stderr[:200])
        print()
        print("Result: %d/%d passed" % (result["passed"], result["total"]))
        if result["failed"]:
            print("Failed: %s" % ", ".join(result["failed"]))

    return 0 if not result["failed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
