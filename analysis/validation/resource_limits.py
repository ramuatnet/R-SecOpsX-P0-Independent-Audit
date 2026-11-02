"""T-9.16 gate: memory + CPU limits (task.md section 13 "memory + CPU
limits").

Probes every enforcement path of core/resource_limits.py in CHILD
processes (a breach aborts the scan -- never probe in-process):

  cpu_probe      activate(0, 1.0) + CPU burn  -> watchdog injects
                 ResourceLimitExceeded, guard exits 2, stderr row
                 carries kind=cpu
  memory_probe   activate(192, 0) + 32MB-step grow loop -> kind=memory
                 the same way (grow stops well before the 768MB cap
                 when enforcement works)
  disabled_probe activate(0, 0) + short burn -> completes rc 0 with
                 CHILD-DONE (control: defaults-off never trips)
  check_probe    immediate cooperative breach via check() on a 1e-9
                 budget (child, so this module stays stdlib-only)
                 -> kind=cpu raised without waiting for any sample

EXIT CODES:
 0  every probe behaved as expected (limits enforced / control clean)
 1  a probe did NOT enforce (child completed over budget, wrong kind,
    or wrong exit code) -- enforcement regression
 2  could-not-run (core module missing, child crashed for an unrelated
    reason, malformed --json output)
"""
from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import sys
import textwrap
import time

SCHEMA = "rsecopsx.resource_limits_gate/v1"
CHILD_TIMEOUT_S = 20

REPO = str(pathlib.Path(__file__).resolve().parents[2])
# python -c children have no __file__: inject the repo root explicitly.
_REPO_SNIPPET = "import sys\nsys.path.insert(0, %r)\n" % REPO

_CPU_CHILD = _REPO_SNIPPET + textwrap.dedent(
    """
    import time
    from core import resource_limits as rl

    @rl.guard
    def workload():
        rl.activate(0, 1.0, quiet=True)
        end = time.time() + 10   # hard cap: unenforced -> CHILD-DONE rc0
        while time.time() < end:
            pass
        print("CHILD-DONE")

    workload()
    """
)

_MEMORY_CHILD = _REPO_SNIPPET + textwrap.dedent(
    """
    import time
    from core import resource_limits as rl

    @rl.guard
    def workload():
        rl.activate(192, 0, quiet=True)   # interpreter already ~20-40MB
        hold = []
        for _ in range(24):               # 768MB cap if never enforced
            hold.append(bytearray(32 * 1024 * 1024))
            time.sleep(0.05)
        print("CHILD-DONE")

    workload()
    """
)

_DISABLED_CHILD = _REPO_SNIPPET + textwrap.dedent(
    """
    import time
    from core import resource_limits as rl

    rl.activate(0, 0, quiet=True)
    rl.check()
    end = time.time() + 1.0
    while time.time() < end:
        pass
    print("CHILD-DONE")
    """
)

# Also a child: the gate module itself stays stdlib-only (its ast
# import whitelist test forbids even first-party imports), and a breach
# aborts the process by design anyway.
_CHECK_CHILD = _REPO_SNIPPET + textwrap.dedent(
    """
    from core import resource_limits as rl

    rl.activate(0, 1e-9, quiet=True)
    try:
        rl.check()
        print("NO-RAISE")
        raise SystemExit(0)
    except rl.ResourceLimitExceeded as exc:
        print(exc.describe())
        raise SystemExit(2)
    finally:
        rl.deactivate()
    """
)


def _run_child(name: str, script: str) -> dict:
    started = time.time()
    try:
        proc = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=CHILD_TIMEOUT_S)
    except subprocess.TimeoutExpired:
        return {"name": name, "expected": False, "rc": None,
                "detail": "child timeout (never enforced, never finished)",
                "elapsed_s": round(time.time() - started, 2)}
    out = (proc.stdout or "") + (proc.stderr or "")
    return {"name": name, "rc": proc.returncode,
            "expected": proc.returncode == 2
            and "RESOURCE LIMIT EXCEEDED" in out,
            "detail": out[-600:].replace("\n", " | "),
            "elapsed_s": round(time.time() - started, 2)}


def _disabled_control() -> dict:
    script = _DISABLED_CHILD
    try:
        proc = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=CHILD_TIMEOUT_S)
    except subprocess.TimeoutExpired:
        return {"name": "disabled_probe", "expected": False, "rc": None,
                "detail": "disabled control timed out"}
    out = (proc.stdout or "") + (proc.stderr or "")
    return {"name": "disabled_probe", "rc": proc.returncode,
            "expected": proc.returncode == 0 and "CHILD-DONE" in out
            and "RESOURCE LIMIT EXCEEDED" not in out,
            "detail": out[-600:].replace("\n", " | ")}


def _check_probe() -> dict:
    """Immediate cooperative breach (child): no sample interval needed."""
    result = _run_child("check_probe", _CHECK_CHILD)
    detail = result.get("detail") or ""
    result["expected"] = bool(
        result.get("rc") == 2
        and "RESOURCE LIMIT EXCEEDED" in detail
        and "kind=cpu" in detail
        and "limit=" in detail
        and "observed=" in detail
        and "NO-RAISE" not in detail)
    return result


def run_probes() -> list:
    probes = [
        _run_child("cpu_probe", _CPU_CHILD),
        _run_child("memory_probe", _MEMORY_CHILD),
        _disabled_control(),
        _check_probe(),
    ]
    return probes


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="T-9.16 memory + CPU limits enforcement gate")
    parser.add_argument("--json", action="store_true",
                        help="emit one JSON payload on the last line")
    args = parser.parse_args(argv)

    started = time.time()
    try:
        probes = run_probes()
    except Exception as exc:  # noqa: BLE001 - could-not-run
        payload = {"schema": SCHEMA, "ok": False, "rc": 2,
                   "probes": [], "detail": "could-not-run: %r" % (exc,),
                   "elapsed_s": round(time.time() - started, 2)}
        if args.json:
            print(json.dumps(payload, sort_keys=True))
        else:
            print("could-not-run: %r" % (exc,))
        return 2

    ok = all(p["expected"] for p in probes)
    payload = {"schema": SCHEMA, "ok": ok, "probes": probes,
               "elapsed_s": round(time.time() - started, 2)}
    if args.json:
        print(json.dumps(payload, sort_keys=True))
    else:
        for p in probes:
            status = "OK " if p["expected"] else "FAIL"
            print("  [%s] %-16s rc=%s %ss" % (
                status, p["name"], p.get("rc"), p.get("elapsed_s", "?")))
            print("        %s" % p["detail"])
        print("resource_limits gate: %s" % ("PASS" if ok else "FAIL"))
    if not ok:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
