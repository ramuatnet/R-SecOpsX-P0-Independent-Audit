"""End-to-end pipeline validation (Phase V5).

WHY A SUBPROCESS, NOT AN IMPORT
-------------------------------
Every other module in this package calls the scanners as functions. This one
deliberately does not, because the thing under test here is the pipeline -- the
argument parsing, the logging setup, the phase ordering, the gate's exit code,
and the writing of every artifact. Calling ``scan_directory()`` in-process would
test the scanner and skip all of the above, which is exactly the part that has
broken before: a renderer that throws is caught and printed, so the run still
"passes" while a promised artifact is silently missing.

Running the real CLI is also the only way to measure the exit code, which is
the contract a CI integration actually depends on.

WHAT IS MEASURED
----------------
    artifacts     every artifact the CLI promises must exist AND parse
    determinism   two runs on the same input must agree on findings
    gate          --fail-on must exit 1 on a vulnerable target and 0 on a
                  clean one, and the gate block in clean_report.json must
                  agree with the exit code

Exit codes
    0   every target behaved as specified
    1   at least one target did not
"""
from __future__ import annotations
try:
    from analysis.spans import WINDOW_3, WINDOW_M4000
except ImportError:  # FND-03: standalone, repo root not on path
    import sys as _fnd03_sys
    from pathlib import Path as _fnd03_path
    _fnd03_sys.path.insert(0, str(_fnd03_path(__file__).resolve().parents[2]))
    from analysis.spans import WINDOW_3, WINDOW_M4000

import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

_LOG = logging.getLogger("rsx.analysis.validation.e2e")

ROOT = Path(__file__).resolve().parents[2]
# Scan-target fixtures live under tests/ rather than beside this module: the
# dead-code guard (test_v11_dead_code_guard.py) audits every .py in the live
# tree for reachability, and these files are deliberately never imported -- app.py
# is a vulnerable Flask app whose import would register routes. tests/ is a
# protected root, the same reason tests/vuln-test-corpus holds .py fixtures.
TARGETS = ROOT / "tests" / "e2e_targets"
CLI = ROOT / "main.py"

# Artifacts every successful scan must write. The Excel workbooks and PDFs are
# excluded because the harness passes --no-pdf/--no-excel; including them would
# measure the renderer, not the pipeline, and would make the suite depend on
# reportlab and openpyxl being installed.
REQUIRED_ARTIFACTS = (
    "clean_report.json",
    "Security_Report.sarif",
    "Security_Report.vex.json",
    "Security_CycloneDX.json",
    "Security_SPDX.spdx.json",
    "Security_CBOM.cdx.json",
    "Security_AIBOM.cdx.json",
    "scan.log",
)

JSON_ARTIFACTS = (
    "clean_report.json",
    "Security_Report.sarif",
    "Security_Report.vex.json",
    "Security_CycloneDX.json",
    "Security_SPDX.spdx.json",
    "Security_CBOM.cdx.json",
    "Security_AIBOM.cdx.json",
)


def _run_cli(target: Path, outdir: Path, *extra: str) -> dict:
    """Run the real CLI on one target and capture everything observable."""
    cmd = [sys.executable, str(CLI), str(target), "-o", str(outdir),
           "--no-pdf", "--no-excel", "--quiet", *extra]
    proc = subprocess.run(cmd, capture_output=True, text=True,
                          cwd=str(ROOT), timeout=600)
    return {
        "cmd": cmd,
        "exit_code": proc.returncode,
        "stdout": proc.stdout[WINDOW_M4000:],
        "stderr": proc.stderr[WINDOW_M4000:],
    }


def _read_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return exc


def _findings_signature(report: dict) -> list[tuple]:
    """Reduce a clean_report.json to the part that must be reproducible.

    Timestamps, durations, serial numbers and absolute paths differ by
    construction between runs. What must not differ is which defects were
    found, where, and how they were classed -- so the signature carries only
    those fields.
    """
    out = []
    for f in report.get("findings", []) or []:
        out.append((
            str(f.get("rule_id") or f.get("vuln_type") or ""),
            str(f.get("cwe") or ""),
            int(f.get("line") or 0),
            os.path.basename(str(f.get("file") or "")),
        ))
    return sorted(out)


def _check_bom_structure(outdir: Path, result: dict) -> None:
    """Offline conformance check for the CycloneDX 1.6 BOM artifacts.

    E2E stays offline on purpose: analysis/validation/sbom_conformance.py
    also validates against the official schemas over the network, and a
    suite that fails because githubusercontent was unreachable would train
    people to ignore it. What is checked here is everything that does not
    need a fetch -- document identity (bomFormat/specVersion), and for
    non-empty inventories the cbomkit structural contract (every
    cryptographic-asset carries cryptoProperties with a valid assetType and
    its asset-specific sub-object; every ML component carries provider
    provenance). Empty inventories skip the content check: a clean target
    has no crypto to inventory, and that is a valid document, not a
    malformed one.
    """
    from analysis.validation.sbom_conformance import (
        _aibom_schema_check,
        _cbomkit_parse_check,
    )

    ok = True
    for name, checker in (
        ("Security_CBOM.cdx.json", _cbomkit_parse_check),
        ("Security_AIBOM.cdx.json", _aibom_schema_check),
    ):
        doc = _read_json(outdir / name)
        if not isinstance(doc, dict):
            result["problems"].append("%s unreadable: %s" % (name, doc))
            ok = False
            continue
        if doc.get("bomFormat") != "CycloneDX" or doc.get("specVersion") != "1.6":
            result["problems"].append(
                "%s is not a CycloneDX 1.6 doc (bomFormat=%r specVersion=%r)"
                % (name, doc.get("bomFormat"), doc.get("specVersion")))
            ok = False
            continue
        if not (doc.get("components") or []):
            continue
        check = checker(doc)
        if not check.get("valid"):
            result["problems"].append(
                "%s: %s" % (name, (check.get("errors") or [])[:WINDOW_3]))
            ok = False
    result["checks"]["bom_structure"] = ok


def _check_target(target: Path, fail_on: str | None = None) -> dict:
    """Run one target and return a structured result.

    The target is copied into the temp directory before scanning, for the
    same reason analysis/validation/run.py copies corpus fixtures: these
    fixtures live under tests/, and the secrets scanner deliberately
    withholds its known-signature layer (AWS/GitHub/OpenAI key patterns)
    from paths inside test directories (_is_nonproduction_context). A real
    scan target is never inside the scanner's own test tree, so scanning
    the copy measures the pipeline a user would actually run -- the first
    draft scanned in place and silently lost every KNOWN_SECRET_RULES
    finding the moment the fixtures moved under tests/.
    """
    result = {"target": target.name, "fail_on": fail_on,
              "problems": [], "checks": {}}

    with tempfile.TemporaryDirectory(prefix="rsx_e2e_") as tmp:
        target_copy = Path(tmp) / "target"
        shutil.copytree(target, target_copy)
        outdir = Path(tmp) / "reports"
        run = _run_cli(target_copy, outdir, *(["--fail-on", fail_on] if fail_on else []))
        result["exit_code"] = run["exit_code"]

        # 1. Artifacts exist.
        missing = [a for a in REQUIRED_ARTIFACTS if not (outdir / a).is_file()]
        result["checks"]["artifacts_exist"] = not missing
        if missing:
            result["problems"].append("missing artifacts: %s" % ", ".join(missing))
            return result

        # 2. Artifacts parse.
        broken = {}
        for name in JSON_ARTIFACTS:
            parsed = _read_json(outdir / name)
            if isinstance(parsed, Exception):
                broken[name] = str(parsed)
        result["checks"]["artifacts_parse"] = not broken
        if broken:
            result["problems"].append("unparseable artifacts: %s" % broken)

        # 2b. The two 1.6 BOM artifacts are well-formed CycloneDX.
        _check_bom_structure(outdir, result)

        report = _read_json(outdir / "clean_report.json")
        if isinstance(report, Exception):
            result["problems"].append("clean_report.json unreadable")
            return result

        # 3. The report declares its own gate, and it must match the exit code.
        #
        # The expectation is computed from the findings' own severities, not
        # from "any finding exists": --fail-on only trips on a finding at or
        # ABOVE the named rung, so a report full of Medium findings exits 0
        # under --fail-on high. Asserting the blunt version of this made the
        # first run of this harness report a false failure against a gate that
        # was behaving exactly as documented.
        gate = (report.get("security_gate") or report.get("metadata", {})
                .get("security_gate") or {})
        result["checks"]["gate_recorded"] = bool(gate)
        if fail_on:
            order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
            rung = order.get(fail_on, 99)
            blocking = [f for f in (report.get("findings") or [])
                        if order.get(str(f.get("severity", "")).lower(), -1) >= rung]
            expect_fail = bool(blocking)
            exited_1 = run["exit_code"] == 1
            result["checks"]["gate_matches_exit"] = exited_1 == expect_fail
            result["blocking_count"] = len(blocking)
            if exited_1 != expect_fail:
                result["problems"].append(
                    "gate/exit mismatch: %d findings at/above %s but exit=%d"
                    % (len(blocking), fail_on, run["exit_code"]))

        # 4. Determinism: a second run must find the same defects. It scans
        # the same copy, not the original -- scanning the original would
        # compare two different paths and report the known-signature-layer
        # difference as flakiness.
        outdir2 = Path(tmp) / "reports2"
        _run_cli(target_copy, outdir2)
        report2 = _read_json(outdir2 / "clean_report.json")
        if isinstance(report2, dict):
            same = _findings_signature(report) == _findings_signature(report2)
            result["checks"]["deterministic"] = same
            if not same:
                result["problems"].append(
                    "two runs disagreed: %d findings vs %d"
                    % (len(_findings_signature(report)),
                       len(_findings_signature(report2))))
            result["finding_count"] = len(_findings_signature(report))

    result["ok"] = not result["problems"]
    return result


def run_e2e(targets_dir: Path | None = None) -> dict:
    """Run every E2E target and return the aggregated result."""
    base = Path(targets_dir or TARGETS)
    results = []

    for target in sorted(p for p in base.iterdir() if p.is_dir()):
        results.append(_check_target(target))

    # Gate behaviour is measured separately, because it is a property of the
    # CLI rather than of any one target. Both sides need a target whose
    # findings actually reach the rung: iam_wildcard carries a High IAM
    # wildcard finding so it must trip --fail-on high, while clean_app has no
    # findings at all so it must not. Using flask_sql for the failing case was
    # the bug in this harness's first draft -- every finding there is Medium,
    # so exiting 0 was the correct behaviour and the assertion was what failed.
    vulnerable = base / "iam_wildcard"
    clean = base / "clean_app"
    if vulnerable.is_dir():
        results.append(_check_target(vulnerable, fail_on="high"))
    if clean.is_dir():
        results.append(_check_target(clean, fail_on="high"))

    failed = [r for r in results if not r.get("ok")]
    return {
        "total": len(results),
        "passed": len(results) - len(failed),
        "failed": [r["target"] + ("[fail-on]" if r.get("fail_on") else "")
                   for r in failed],
        "results": results,
    }


def main(argv: list[str] | None = None) -> int:
    import argparse
    parser = argparse.ArgumentParser(
        prog="analysis.validation.e2e",
        description="Run the full pipeline end to end and verify its outputs.")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--targets", default=None)
    args = parser.parse_args(argv)

    outcome = run_e2e(Path(args.targets) if args.targets else None)

    if args.json:
        print(json.dumps(outcome, indent=2, default=str))
    else:
        print("E2E pipeline validation")
        print("=" * 60)
        for r in outcome["results"]:
            label = r["target"] + (" [fail-on]" if r.get("fail_on") else "")
            status = "PASS" if r.get("ok") else "FAIL"
            extra = ""
            if "finding_count" in r:
                extra = "  findings=%d" % r["finding_count"]
            print("  [%s] %-24s exit=%s%s" % (status, label, r.get("exit_code"), extra))
            for p in r["problems"]:
                print("        ! %s" % p)
        print()
        print("Result: %d/%d passed" % (outcome["passed"], outcome["total"]))
        if outcome["failed"]:
            print("Failed: %s" % ", ".join(outcome["failed"]))

    return 0 if not outcome["failed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
