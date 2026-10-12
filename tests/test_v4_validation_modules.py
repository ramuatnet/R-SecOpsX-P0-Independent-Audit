"""Validation modules are importable and wired into the CI matrix (Phase V6).

This module exists for two reasons:
  1. It makes analysis/validation/*.py reachable from the test tree, which the
     dead-code guard (test_v11_dead_code_guard.py) requires.
  2. It pins the CLI entry points so a refactor that breaks the module path
     fails CI rather than quietly dropping a validation gate.
"""
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def test_validation_modules_import():
    from analysis.validation import ci_matrix, corpus, fuzz_versions, metrics, normalize, run, sbom_conformance  # noqa: F401
    assert hasattr(fuzz_versions, "fuzz_versions")
    assert hasattr(sbom_conformance, "validate_sbom_conformance")
    assert hasattr(ci_matrix, "run_ci_matrix")


def test_run_module_exposes_families():
    from analysis.validation.corpus import FAMILIES
    assert set(FAMILIES) == {"sast", "sca", "secrets", "iac", "sbom", "cbom", "ai_ml"}


def test_fuzz_version_comparators_agree_on_core_pairs():
    from analysis.validation.fuzz_versions import _compare_maven, _rsx_compare_maven
    for a, b, expected in [
        ("1.0", "1.0", 0),
        ("1.0", "2.0", -1),
        ("2.0", "1.0", 1),
        ("1.0-SNAPSHOT", "1.0", -1),
    ]:
        assert _rsx_compare_maven(a, b) == expected, (a, b)
        assert _compare_maven(a, b) == expected, (a, b)


def test_run_corpus_cli_is_invocable():
    r = subprocess.run(
        [sys.executable, "-m", "analysis.validation.run",
         "--corpus", str(ROOT / "tests" / "vuln-test-corpus"), "--json"],
        capture_output=True, text=True, cwd=str(ROOT), timeout=300,
    )
    assert r.returncode in (0, 1), r.stderr  # 2 = nothing scored = real failure
    import json
    result = json.loads(r.stdout)
    assert result["overall"]["expected"] > 0
