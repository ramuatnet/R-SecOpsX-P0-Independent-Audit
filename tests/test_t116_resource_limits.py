"""T-9.16 memory + CPU limits (task.md section 13).

Pins the in-house resource-limit layer: a portable in-process watchdog
(CPU via time.process_time, memory via stdlib ctypes sampling) that
injects ResourceLimitExceeded into the main thread, cooperative
stage-boundary checks in main.py, the --max-memory-mb/--max-cpu-seconds
wiring, the breach guard's machine-readable exit-2 contract, and the
gate CLI that probes all three behaviors in child processes.
"""
from __future__ import annotations

import ast
import pathlib
import subprocess
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
CORE_SRC = REPO / "core" / "resource_limits.py"
GATE_SRC = REPO / "analysis" / "validation" / "resource_limits.py"
MAIN_SRC = REPO / "main.py"


def _core_src() -> str:
    return CORE_SRC.read_text(encoding="utf-8")


def _main_src() -> str:
    return MAIN_SRC.read_text(encoding="utf-8")


# ---------------------------------------------------------------- disclosure


def test_disclosure_needles_core():
    src = _core_src()
    needles = (
        "memory + CPU limits (task.md section 13",
        "ground rule 12",
        "PyThreadState_SetAsyncExc",
        "NOT ADOPTED",
        "psutil",
        "Job Objects",
        "watchdog",
    )
    for needle in needles:
        assert needle in src, "core disclosure missing: %r" % needle


def test_disclosure_needles_gate():
    src = GATE_SRC.read_text(encoding="utf-8")
    needles = (
        "memory + CPU limits (task.md section 13",
        "EXIT CODES",
        "RESOURCE LIMIT EXCEEDED",
        "could-not-run",
    )
    for needle in needles:
        assert needle in src, "gate disclosure missing: %r" % needle


def test_gate_imports_are_stdlib_only():
    tree = ast.parse(GATE_SRC.read_text(encoding="utf-8"))
    allowed = {"__future__", "argparse", "json", "os", "pathlib", "subprocess",
               "sys", "tempfile", "textwrap", "time"}
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                found.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                found.add(node.module.split(".")[0])
    assert found <= allowed, found - allowed


# ------------------------------------------------------------------ constants


def test_gate_module_constants_pinned():
    # The in-test import IS the liveness edge: the dead-code guard
    # (tests/test_v11_dead_code_guard.py) sees static imports only, so
    # a subprocess-spawned gate must still be imported here or it sits
    # unreachable in the live tree (same pattern as t115's det.SCHEMA).
    from analysis.validation import resource_limits as gate
    assert gate.SCHEMA == "rsecopsx.resource_limits_gate/v1"
    assert gate.CHILD_TIMEOUT_S >= 5


def test_constants_pinned():
    from core import resource_limits as rl
    assert rl.DEFAULT_MAX_MEMORY_MB == 8192
    assert rl.DEFAULT_MAX_CPU_SECONDS == 7200
    assert rl.SAMPLE_INTERVAL_S == 0.5
    assert rl.LIMIT_EXCEEDED_EXIT_CODE == 2


# ------------------------------------------------------------- main.py wiring


def test_main_flags_and_activation_pinned():
    # The flags exist, activation happens after the per-scan collectors,
    # and the guard wraps main() -- pin every wiring site (mutation
    # needle: dropping any one of these must fail this test).
    src = _main_src()
    assert '"--max-memory-mb"' in src
    assert '"--max-cpu-seconds"' in src
    assert "resource_limits.activate(args.max_memory_mb, args.max_cpu_seconds)" in src
    assert "@resource_limits.guard" in src
    # flags use the shared defaults (not duplicated magic numbers)
    assert "default=resource_limits.DEFAULT_MAX_MEMORY_MB" in src
    assert "default=resource_limits.DEFAULT_MAX_CPU_SECONDS" in src


def test_stage_boundary_check_is_pinned():
    # Cooperative check() must live INSIDE _timing_start_stage so every
    # one of the 85 _step() stage boundaries refuses to start past a
    # breach.  Slice the function body, not a global grep, so the needle
    # cannot be satisfied by a comment elsewhere (mutation needle).
    src = _main_src()
    start = src.index("def _timing_start_stage(")
    end = src.index("def _format_duration(")
    body = src[start:end]
    assert "resource_limits.check()" in body


def test_activation_sits_with_the_per_scan_collectors():
    src = _main_src()
    i_act = src.index("resource_limits.activate(args.max_memory_mb")
    i_walk = src.index("file_index.walk(target)")
    i_begin = src.index("file_index.begin_scan()")
    # after the collectors begin, before the walk starts
    assert i_begin < i_act < i_walk


# ------------------------------------------------------------------ primitives


def test_memory_sampler_returns_positive_mb():
    from core import resource_limits as rl
    mb = rl.current_memory_mb()
    assert mb is not None and mb > 0, mb


def test_cpu_clock_is_monotonic():
    from core import resource_limits as rl
    a = rl.process_cpu_seconds()
    b = rl.process_cpu_seconds()
    assert a >= 0 and b >= a


def test_cooperative_cpu_breach_raises():
    from core import resource_limits as rl
    rl.activate(max_memory_mb=0, max_cpu_seconds=1e-9, quiet=True)
    try:
        with pytest.raises(rl.ResourceLimitExceeded) as ei:
            rl.check()
        text = ei.value.describe()
        assert "RESOURCE LIMIT EXCEEDED" in text
        assert "kind=cpu" in text
        assert "limit=" in text and "observed=" in text
    finally:
        rl.deactivate()
    assert rl.snapshot()["active"] is False


def test_cooperative_memory_breach_raises():
    from core import resource_limits as rl
    # 1 MB is below any running interpreter's working set -> immediate
    rl.activate(max_memory_mb=1, max_cpu_seconds=0, quiet=True)
    try:
        with pytest.raises(rl.ResourceLimitExceeded) as ei:
            rl.check()
        assert "kind=memory" in ei.value.describe()
    finally:
        rl.deactivate()


def test_disabled_limits_never_raise():
    from core import resource_limits as rl
    rl.activate(max_memory_mb=0, max_cpu_seconds=0, quiet=True)
    try:
        rl.check()  # must not raise
        snap = rl.snapshot()
        assert snap["active"] is True
        assert snap["enforcement"] == "disabled"
    finally:
        rl.deactivate()


def test_snapshot_shape():
    from core import resource_limits as rl
    snap = rl.snapshot()
    for key in ("active", "max_memory_mb", "max_cpu_seconds",
                "peak_memory_mb", "peak_cpu_seconds", "enforcement"):
        assert key in snap, key


def test_guard_prints_machine_readable_row_and_exits_2(capsys):
    from core import resource_limits as rl

    @rl.guard
    def _burning():
        raise rl.ResourceLimitExceeded(
            kind="cpu", limit=1.0, observed=1.5)

    with pytest.raises(SystemExit) as ei:
        _burning()
    assert ei.value.code == rl.LIMIT_EXCEEDED_EXIT_CODE
    err = capsys.readouterr().err
    assert "RESOURCE LIMIT EXCEEDED" in err
    assert "kind=cpu" in err
    assert "limit=1.0" in err and "observed=1.5" in err


def test_injection_primitive_present_in_core():
    # The watchdog must inject via the grounded primitive (probe-proven).
    assert "PyThreadState_SetAsyncExc" in _core_src()
    assert "_inject" in _core_src()


# -------------------------------------------------------------- end-to-end


def test_gate_cli_probes_all_enforcement_paths(capsys):
    """`python -m analysis.validation.resource_limits` -> rc 0.

    The gate spawns child processes: a CPU burner that must be killed by
    the watchdog (kind=cpu), a memory grower that must be caught
    (kind=memory), a disabled-limits control that must complete, and an
    immediate cooperative breach.  ~10s.
    """
    proc = subprocess.run(
        [sys.executable, "-m", "analysis.validation.resource_limits",
         "--json"],
        cwd=str(REPO), capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=120)
    assert proc.returncode == 0, (proc.stdout[-2000:], proc.stderr[-2000:])
    import json
    payload = json.loads(proc.stdout.strip().splitlines()[-1])
    assert payload["ok"] is True
    assert payload["schema"] == "rsecopsx.resource_limits_gate/v1"
    assert payload["probes"] and all(
        p["expected"] for p in payload["probes"]), payload["probes"]
