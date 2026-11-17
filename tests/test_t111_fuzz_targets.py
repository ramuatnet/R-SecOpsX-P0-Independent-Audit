"""T-9.11 cargo fuzz targets (task.md section 13 first line).

task.md section 13 ("Hardening & assurance") opens with "cargo fuzz
targets (rule compiler, parsers, walker, DAST response parser)".
cargo fuzz is NOT adopted (broken rustup + clang toolchain; offline
no-required-deps + suite-testability precedent, see the module
docstring) -- the four named targets are fuzzed in-house with seeded
generators and hard iteration budgets in
analysis/validation/fuzz_targets.py.

Suite-side iteration counts are deliberately small (the walker target
is ~600ms/tree including the determinism double-scan; the compiler
target is sub-ms per iteration); the standalone CLI runs the full
budgets.  Contract: every target returns zero failures -- typed
ValueError/AssertionError inside a target is counted, anything else
(pyo3 panic, unexpected TypeError, determinism break) fails the test.
"""
from __future__ import annotations

import pathlib

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
MODULE_PATH = REPO / "analysis" / "validation" / "fuzz_targets.py"


def _module_text() -> str:
    return MODULE_PATH.read_text(encoding="utf-8").lower()


def test_cargo_fuzz_not_adopted_disclosure_greppable():
    text = _module_text()
    assert "cargo fuzz" in text
    assert "not adopted" in text


def test_all_four_task_targets_registered():
    from analysis.validation import fuzz_targets

    assert set(fuzz_targets.TARGETS) == {
        "rule_compiler", "program_parser", "source_parse", "walker",
        "dast_response",
    }


@pytest.mark.requires_rust_ext
def test_rule_compiler_fuzz_contract_small():
    from analysis.validation.fuzz_targets import fuzz_rule_compiler

    result = fuzz_rule_compiler(iterations=120, seed=9111)
    assert result["failures"] == [], result["failures"][:2]
    # both sides of the contract should be exercised: some configs
    # must compile, some must be rejected with a typed ValueError
    assert result["compiled"] + result["rejected"] == 120
    assert result["compiled"] > 0
    assert result["rejected"] > 0


@pytest.mark.requires_rust_ext
def test_program_parser_fuzz_contract_small():
    from analysis.validation.fuzz_targets import fuzz_program_parser

    result = fuzz_program_parser(iterations=80, seed=9112)
    assert result["failures"] == [], result["failures"][:2]
    assert result["accepted"] + result["rejected"] == 80
    # garbage/truncation is expected to dominate the rejected count
    assert result["rejected"] > 0


@pytest.mark.requires_rust_ext
def test_source_parse_fuzz_contract_small():
    from analysis.validation.fuzz_targets import fuzz_source_parse

    result = fuzz_source_parse(files=12, seed=9113)
    assert result["failures"] == [], result["failures"][:2]
    assert result["files"] == 12


@pytest.mark.requires_rust_ext
def test_walker_fuzz_deterministic_small():
    from analysis.validation.fuzz_targets import fuzz_walker

    result = fuzz_walker(trees=6, seed=9114)
    assert result["failures"] == [], result["failures"][:2]
    # determinism is double-scanned on the first 3 trees only
    assert result["deterministic"] == 3


def test_dast_response_fuzz_contract_small():
    from analysis.validation.fuzz_targets import fuzz_dast_response

    result = fuzz_dast_response(iterations=150, seed=9115)
    assert result["failures"] == [], result["failures"][:2]


@pytest.mark.requires_rust_ext
def test_run_all_same_seed_deterministic():
    from analysis.validation.fuzz_targets import run_all

    first = run_all(iterations=12, seed=9200)
    second = run_all(iterations=12, seed=9200)
    assert first["total_failures"] == 0, first
    assert second["total_failures"] == 0, second
    assert first["schema"] == "rsecopsx.fuzz_targets/v1"
    for a, b in zip(first["targets"], second["targets"]):
        assert a["target"] == b["target"]
        for key in ("compiled", "rejected", "accepted", "deterministic",
                    "files", "iterations", "failures", "rng_digest"):
            assert a.get(key) == b.get(key), (a["target"], key)
        # every target must expose its mutation-stream fingerprint
        # (same seed -> same digest; an unseeded rng would diverge)
        assert a.get("rng_digest"), a["target"]


def test_contract_violation_is_reported_not_swallowed(monkeypatch):
    """The failure path itself must be observable: a non-contract
    exception (pyo3-panic stand-in) from the compiler has to surface
    as a target failure, not be swallowed into the rejected count."""
    from scanner import rust_engine
    from analysis.validation import fuzz_targets

    def boom(_cfg):
        raise RuntimeError("injected panic stand-in")

    monkeypatch.setattr(rust_engine, "_compile_program", boom)
    result = fuzz_targets.fuzz_rule_compiler(iterations=5, seed=9401)
    assert len(result["failures"]) >= 1, result
    assert result["failures"][0]["error"] == "RuntimeError"
    assert result["failures"][0]["where"].startswith("rule_compiler#")


def test_failures_append_caps_at_five():
    from analysis.validation import fuzz_targets

    failures: list = []
    for i in range(9):
        try:
            raise ValueError(f"e{i}")
        except ValueError as exc:
            fuzz_targets._failures_append(failures, f"x#{i}", exc)
    assert len(failures) == fuzz_targets.FAILURE_CAP == 5


@pytest.mark.requires_rust_ext
def test_main_cli_exit_codes():
    from analysis.validation import fuzz_targets

    rc = fuzz_targets.main(["--iterations", "8", "--seed", "9300"])
    assert rc in (0, 1), rc
    rc2 = fuzz_targets.main(["--iterations", "8", "--seed", "9300",
                             "--json"])
    assert rc2 == rc
