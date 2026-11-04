"""T-9.12 self-scan clean gate (task.md section 13 "self-scan clean").

The scanner's own repository is scanned through the full main.py
pipeline (accuracy layer ON, RSECOPSX_ACCURACY_INCLUDE_REVIEW=1) and
must come out CLEAN:

    clean := accuracy.filtered_count == 0

i.e. zero TRUE_POSITIVE and zero NEEDS_REVIEW verdicts once the
committed repo-root ``.sastignore`` (walk-time scope path rules +
rule-data / eval-fixture filename suppressions) and the inline
``# sast-ignore RULE reason`` annotations are applied.  Suppressed
findings are never deleted: the audit keeps every row with its
SUPPRESSED_USER / SUPPRESSED_KNOWN verdict and reason, and this tool
prints those counts as disclosure next to the clean verdict.

Scope (repo-root .sastignore, loaded only when the scan target root IS
this repository -- external targets never read it):
  walk-time path rules: data/ dump/ docs/ tests/ Working folder/
    integration_fixture_llm01/ payloads/ baseline/
  finding-level filename rules: llm_security.py atlas_mappings.py
    owasp_mappings.py fix_patch_intelligence.py
    llm_context_precision.py benchmark_llm_precision_controlled.py
    benchmark_sast_corpus.py benchmark_evidence_validation_v1.py

One accepted-findings set lives in baseline/sast_baseline.json for
rows that CANNOT carry inline markers:
  * the four self-match rows on main.py itself -- main.py (291 KiB)
    exceeds the accuracy layer's 256 KiB source-read bound
    (analysis.ufib_brain _MAX_FILE_BYTES), so read_source returns None
    there and inline markers cannot attach;
  * the three RUST_HARDCODED_CREDENTIAL rows on the rust version/schema
    constants -- the T-1.3 gate (tests/test_rust_core.py
    test_no_rule_logic_in_rust_source) forbids rule ids anywhere in
    rust/src/*.rs, so an inline marker would trade one gate for another.
The baseline mechanism matches by rule+file+line without needing
file_text; those rows are recorded as SUPPRESSED_KNOWN and the line
numbers are kept honest by this tool's pinned BASELINE_ENTRIES tuple
(a main.py or rust edit that shifts those lines fails the pin until
the baseline is re-measured).

The clean bar is measured, not asserted from memory: run this module
(``python -m analysis.validation.self_scan``) to re-measure.  A repo
scan walks ~450 product files through every engine and typically takes
several minutes; the standalone CLI is the full-budget run, while the
suite pins the policy with small-scope e2e runs (``--target deploy``).

EXIT CODES:
    0  clean (filtered_count == 0)
    1  not clean (filtered_count > 0, rows listed) or scan failed
    2  could-not-run (main.py missing, no clean_report.json, bad JSON)
"""
from __future__ import annotations
try:
    from analysis.spans import WINDOW_M400
except ImportError:  # FND-03: standalone, repo root not on path
    import sys as _fnd03_sys
    from pathlib import Path as _fnd03_path
    _fnd03_sys.path.insert(0, str(_fnd03_path(__file__).resolve().parents[2]))
    from analysis.spans import WINDOW_M400

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

# Pinned copies of the repo-root .sastignore policy; tests assert the
# file on disk matches these tuples so a dropped line is a test failure,
# not a silently wider self-scan.
SCOPE_PATH_RULES: "tuple[str, ...]" = (
    "data/",
    "dump/",
    "docs/",
    "tests/",
    "Working folder/",
    "integration_fixture_llm01/",
    "payloads/",
    "baseline/",
)
SCOPE_FILENAME_RULES: "tuple[str, ...]" = (
    "llm_security.py",
    "atlas_mappings.py",
    "owasp_mappings.py",
    "fix_patch_intelligence.py",
    "llm_context_precision.py",
    "benchmark_llm_precision_controlled.py",
    "benchmark_sast_corpus.py",
    "benchmark_evidence_validation_v1.py",
)

# Accepted self-match rows that cannot carry inline markers (see the
# module docstring): main.py over the 256 KiB read bound, and the rust
# constants under the T-1.3 no-rule-ids-in-rust gate.  Pinned so a
# line shift fails the suite until the baseline is re-measured.
BASELINE_PATH = "baseline/sast_baseline.json"
BASELINE_ENTRIES: "dict[str, list[dict]]" = {
    "PY_REDOS_NESTED_QUANTIFIER": [
        {"file": "main.py", "line": 2303},
        {"file": "main.py", "line": 2644},
    ],
    "LLM02_INSECURE_OUTPUT_HANDLING": [
        {"file": "main.py", "line": 2398},
    ],
    "LLM06_SENSITIVE_INFORMATION_DISCLOSURE": [
        {"file": "main.py", "line": 3585},
    ],
    "RUST_HARDCODED_CREDENTIAL": [
        {"file": "rust/src/engine.rs", "line": 23},
        {"file": "rust/src/engine.rs", "line": 24},
        {"file": "rust/src/spans.rs", "line": 32},
    ],
}


def is_clean(filtered_count: int) -> bool:
    """The clean bar: zero filtered findings (TP, or NR under the flag)."""
    return int(filtered_count) == 0


def _parse_report(report_path: Path) -> "dict":
    data = json.loads(report_path.read_text(encoding="utf-8"))
    accuracy = data.get("accuracy") or {}
    summary = (data.get("metadata") or {}).get("accuracy_summary") or {}
    verdicts = accuracy.get("counts") or summary.get("verdicts") or {}
    suppressed = 0
    for row in accuracy.get("audit") or []:
        verdict = str(row.get("verdict") or "")
        if verdict.startswith("SUPPRESSED"):
            suppressed += 1
    return {
        "filtered_count": int(accuracy.get("filtered_count")
                              if accuracy.get("filtered_count") is not None
                              else summary.get("filtered", -1)),
        "verdicts": dict(verdicts),
        "suppressed_audit_rows": suppressed,
        "audit_rows": len(accuracy.get("audit") or []),
        "total": summary.get("total"),
        "flag": accuracy.get("flag"),
    }


def run_self_scan(target: "str | os.PathLike | None" = None,
                  *, timeout: int = 1800) -> "dict":
    """Run ``python main.py <target>`` under the accuracy-review flag.

    Returns a dict: rc (0 clean / 1 not-clean / 2 could-not-run),
    plus the parsed accuracy summary and the subprocess returncode.
    """
    target_path = Path(target) if target is not None else REPO_ROOT
    if not target_path.is_dir():
        return {"rc": 2, "error": "target is not a directory",
                "filtered_count": None}
    main_py = REPO_ROOT / "main.py"
    if not main_py.is_file():
        return {"rc": 2, "error": "main.py not found", "filtered_count": None}

    out_dir = Path(tempfile.mkdtemp(prefix="rsx_t112_scan_"))
    try:
        env = dict(os.environ)
        env["RSECOPSX_ACCURACY_INCLUDE_REVIEW"] = "1"
        env["RSECOPSX_ACCURACY_LAYER"] = "1"
        proc = subprocess.run(
            [sys.executable, str(main_py), str(target_path),
             "--output-dir", str(out_dir), "--quiet", "--no-pdf",
             "--no-excel"],
            cwd=str(REPO_ROOT), env=env, timeout=timeout,
            capture_output=True, text=True, encoding="utf-8",
            errors="replace",
        )
        report_path = out_dir / "clean_report.json"
        if not report_path.is_file():
            return {"rc": 2,
                    "error": "no clean_report.json (subprocess rc=%s)"
                             % proc.returncode,
                    "stderr_tail": (proc.stderr or "")[WINDOW_M400:],
                    "filtered_count": None}
        try:
            parsed = _parse_report(report_path)
        except (OSError, ValueError) as exc:
            return {"rc": 2, "error": "bad clean_report.json: %s" % exc,
                    "filtered_count": None}
        parsed["subprocess_rc"] = proc.returncode
        parsed["rc"] = 0 if is_clean(parsed["filtered_count"]) else 1
        return parsed
    except subprocess.TimeoutExpired:
        return {"rc": 2, "error": "scan timed out after %ss" % timeout,
                "filtered_count": None}
    finally:
        shutil.rmtree(out_dir, ignore_errors=True)


def main(argv: "list[str] | None" = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m analysis.validation.self_scan",
        description="T-9.12 self-scan clean gate (task.md section 13).")
    parser.add_argument("--target", default=None,
                        help="scan target directory (default: repo root)")
    parser.add_argument("--timeout", type=int, default=1800,
                        help="subprocess timeout in seconds")
    parser.add_argument("--json", action="store_true",
                        help="machine-readable summary on stdout")
    args = parser.parse_args(argv)

    result = run_self_scan(args.target, timeout=args.timeout)
    if args.json:
        original = sys.stdout
        try:
            import io as _io
            wrapper = _io.TextIOWrapper(original.buffer, encoding="utf-8",
                                        errors="replace")
            sys.stdout = wrapper
            print(json.dumps(result, indent=2, sort_keys=True))
            wrapper.flush()
        finally:
            sys.stdout = original
            try:
                wrapper.detach()
            except Exception:
                pass
        return int(result.get("rc", 2))

    if result.get("rc") == 2:
        print("[SELF-SCAN] could-not-run: %s" % result.get("error"))
        return 2
    verdicts = result.get("verdicts") or {}
    print("[SELF-SCAN] total=%s filtered_count=%s suppressed_audit_rows=%s"
          % (result.get("total"), result.get("filtered_count"),
             result.get("suppressed_audit_rows")))
    print("[SELF-SCAN] verdicts=%s" % json.dumps(verdicts, sort_keys=True))
    if result["rc"] == 0:
        print("[SELF-SCAN] CLEAN")
    else:
        print("[SELF-SCAN] NOT CLEAN (filtered_count=%s)"
              % result.get("filtered_count"))
    return int(result["rc"])


if __name__ == "__main__":
    raise SystemExit(main())
