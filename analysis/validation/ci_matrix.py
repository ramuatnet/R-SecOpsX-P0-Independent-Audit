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


def _run(name: str, cmd: list[str]) -> dict:
    """Run a validation command and return its result."""
    _LOG.info("running: %s", " ".join(cmd))
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=str(ROOT),
            timeout=300,
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

    # V2.3: version fuzzing
    gates.append(_run(
        "version_fuzzing",
        [sys.executable, "-m", "analysis.validation.fuzz_versions", "--count", "1000"]
    ))

    # V0: V0 unit tests
    gates.append(_run(
        "v0_unit_tests",
        [sys.executable, "-m", "pytest",
         str(ROOT / "tests" / "test_v01_golden_corpus.py"),
         str(ROOT / "tests" / "test_v02_normalizer_comparator.py"),
         str(ROOT / "tests" / "test_v03_differential.py"),
         "-v", "--tb=short"]
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
