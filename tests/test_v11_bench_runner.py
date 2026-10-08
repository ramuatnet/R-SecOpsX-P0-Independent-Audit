"""The benchmark runner's timeout and its diagnostics must work.

WHY THIS IS A TEST AND NOT A REFACTOR
-------------------------------------
The runner reported

    rc=-9 after 10519s  TIMEOUT after 7200s

for llama_index-main: a 7,200s budget that took 10,519s to give up. The 55-minute
overshoot is not the scanner being slow -- it is the kill failing. `subprocess.run`
kills only the direct child, the scanner's process pool keeps the stdout pipe open,
and `communicate()` blocks waiting for output that will never be closed. Two of nine
projects then looked like "slow" when what actually happened was "the harness cannot
stop them", and each retry paid the overshoot on top of the budget.

The second defect compounds it: on `TimeoutExpired` the handler set `tail = ""`,
discarding the `TimeoutExpired` output it was holding. So a timeout produced no
evidence about whether the scan was hung or merely slow -- opposite problems with
opposite fixes -- and the temptation was to raise the timeout, which makes the next
run slower and teaches nothing.

THE THIRD DEFECT IS THE ONE THAT MATTERS MOST FOR MAINTENANCE
-------------------------------------------------------------
The phase-timing parser shipped matching NOTHING. It assumed an ELAPSED format of
`\\d+h:\\d+m:\\d+s` with literal separators, while `_format_duration` emits `MM:SS.ss`
under an hour and `HH:MM:SS.ss` at or above. The regex compiled, ran, and returned
an empty list -- indistinguishable from "this scan recorded no phases". Every
phase-timing field would have been empty forever, silently.

So the parser is asserted here against REAL captured scanner output. A diagnostic
that is present, plausible and empty is worse than one that is absent.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from analysis.compare_ai_benchmarks import (  # noqa: E402
    _duration_seconds,
    _kill_tree,
    parse_last_started_phase,
    parse_phase_timings,
)

# Genuine output captured from a real scan of prodtest/wrongsecrets-master. Not a
# hand-written sample: a fixture invented to match the regex proves nothing, which
# is precisely how the broken regex came to look correct.
REAL_OUTPUT = """  [PHASE START] Scanning codebase | START=2026-10-07 12:02:04.063 | GAP_FROM_PREVIOUS_END=00:00.00
  >>  Scanning codebase  (regex + AST taint, 2 workers)
       => 45 raw findings in 5.4s
       [PHASE END] Scanning codebase | END=2026-10-07 12:02:09.460 | ELAPSED=00:05.40 | GAP_FROM_PREVIOUS_END=00:00.00
       [PHASE START] Generating SBOM & dependency analysis | START=2026-10-07 12:02:09.460 | GAP_FROM_PREVIOUS_END=00:00.00
  >>  Generating SBOM & dependency analysis
       [PHASE END] Generating SBOM & dependency analysis | END=2026-10-07 12:02:09.912 | ELAPSED=00:00.45 | GAP_FROM_PREVIOUS_END=00:00.00
       [PHASE START] Generating CBOM crypto inventory | START=2026-10-07 12:02:09.913 | GAP_FROM_PREVIOUS_END=00:00.00
       [PHASE END] Generating CBOM crypto inventory | END=2026-10-07 12:02:11.140 | ELAPSED=00:01.22 | GAP_FROM_PREVIOUS_END=00:00.00
       [PHASE START] Generating PDF report | START=2026-10-07 12:02:12.000 | GAP_FROM_PREVIOUS_END=00:00.00
"""


# ------------------------------------------------- the parser is not a no-op --

def test_phase_parser_matches_real_scanner_output():
    """The regression guard for the silent no-op.

    If this ever returns an empty list the failure mode is invisible: the runner
    would keep working and every phase-timing field would be empty.
    """
    phases = parse_phase_timings(REAL_OUTPUT)

    assert phases, (
        "the phase parser matched nothing against real captured output. An empty "
        "result here is indistinguishable from 'no phases recorded'."
    )
    assert len(phases) == 3


def test_phase_durations_are_exact():
    phases = {p["phase"]: p["seconds"] for p in parse_phase_timings(REAL_OUTPUT)}

    assert phases["Scanning codebase"] == pytest.approx(5.40)
    assert phases["Generating CBOM crypto inventory"] == pytest.approx(1.22)
    assert phases["Generating SBOM & dependency analysis"] == pytest.approx(0.45)


def test_phase_precisions_match_the_scanner_output():
    """`round(x, 1)` reported a 1.22s phase as 1.2s.

    Two decimals, because `_format_duration` emits two. A diagnostic that quietly
    rounds away the precision it is reporting is reporting a different number than
    the scanner printed.
    """
    phases = {p["phase"]: p["seconds"]
              for p in parse_phase_timings(REAL_OUTPUT)}

    assert phases["Generating CBOM crypto inventory"] == 1.22


def test_phases_are_sorted_longest_first():
    seconds = [p["seconds"] for p in parse_phase_timings(REAL_OUTPUT)]

    assert seconds == sorted(seconds, reverse=True)


@pytest.mark.parametrize(
    ("token", "want"),
    [
        ("00:05.40", 5.40),      # under an hour: MM:SS.ss
        ("01:30.00", 90.00),
        ("00:00.45", 0.45),
        ("01:23:45.67", 5025.67),  # one hour or more: HH:MM:SS.ss
        ("02:00:00.00", 7200.00),
    ],
)
def test_both_duration_shapes_parse(token, want):
    """`_format_duration` switches shape at one hour.

    A parser written for one shape silently returns nothing for the other, which
    looks like "only the fast phases were recorded" rather than like a defect. The
    two timed-out projects both exceeded an hour, so this is the shape that mattered.
    """
    got = _duration_seconds(token)

    assert got is not None, f"{token!r} did not parse"
    assert got == pytest.approx(want)


@pytest.mark.parametrize("token", ["nonsense", "1:2:3:4", "", ":", "a:b"])
def test_bad_duration_tokens_return_none_rather_than_raising(token):
    assert _duration_seconds(token) is None


def test_in_flight_phase_is_identified_at_truncation():
    """The one field that turns "TIMEOUT" into something actionable."""
    assert parse_last_started_phase(REAL_OUTPUT) == "Generating PDF report"


def test_completed_run_reports_nothing_in_flight():
    """A scan that finished must not be reported as hung in its last phase."""
    completed = "\n".join(
        line for line in REAL_OUTPUT.splitlines() if "PDF report" not in line)

    assert parse_last_started_phase(completed) is None


@pytest.mark.parametrize("text", ["", None, "hello", "   ",
                                  "[PHASE END] Scanning | ELAPSED="])
def test_degenerate_input_does_not_crash(text):
    assert isinstance(parse_phase_timings(text), list)
    assert isinstance(parse_last_started_phase(text), (str, type(None)))


# ---------------------------------------------------- the kill actually kills --

def test_kill_tree_is_a_noop_on_an_already_dead_process():
    """It must not raise when there is nothing to kill."""
    import subprocess
    import sys as _sys

    proc = subprocess.Popen([_sys.executable, "-c", "pass"],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    proc.wait()

    _kill_tree(proc)  # must not raise


def test_kill_tree_terminates_a_process_that_spawned_a_grandchild():
    """The scenario that produced the 55-minute overshoot.

    A child that spawns a grandchild holding the same pipe, so killing the child
    alone leaves the pipe open. If this regresses, every timed-out project goes
    back to costing its budget plus the overshoot, and the cause stays invisible.
    """
    import subprocess
    import sys as _sys
    import time

    grandchild = (
        "import time, sys\n"
        "sys.stdout.write('grandchild up\\n'); sys.stdout.flush()\n"
        "time.sleep(120)\n"
    )
    child = (
        "import subprocess, sys, time\n"
        f"subprocess.Popen([sys.executable, '-c', {grandchild!r}])\n"
        "sys.stdout.write('child up\\n'); sys.stdout.flush()\n"
        "time.sleep(120)\n"
    )

    proc = subprocess.Popen(
        [_sys.executable, "-c", child],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, encoding="utf-8", errors="replace",
    )
    # Wait for the grandchild to actually be holding the pipe, so the test cannot
    # pass merely because the race was not set up yet.
    deadline = time.time() + 30
    saw = ""
    while time.time() < deadline:
        line = proc.stdout.readline()
        saw += line
        if "grandchild up" in saw:
            break
    assert "grandchild up" in saw, (
        "grandchild never announced itself; the test cannot prove the kill")

    t0 = time.time()
    _kill_tree(proc)
    elapsed = time.time() - t0

    try:
        leftover = proc.communicate(timeout=20)[0]
    except subprocess.TimeoutExpired:
        proc.kill()
        pytest.fail("stdout pipe still open 20s after the kill -- "
                    "grandchild survived, so communicate() would block and the "
                    "timeout overshoot is back")

    assert proc.returncode is not None
    assert elapsed < 60, f"the kill itself took {elapsed:.0f}s"
    assert leftover is not None