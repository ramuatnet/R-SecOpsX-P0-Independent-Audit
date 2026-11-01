"""T-9.15 deterministic output assertion (task.md section 13).

Runs the real CLI twice on the same target (two independent child
processes, default per-process hash randomization -- NO seed pinning)
and asserts that every report artifact is byte-identical after
normalizing the DECLARED volatile classes only:

    iso_timestamp        2026-11-01T15:19:22[.,frac][Z|offset]
                         and the log form 2026-11-01 15:19:22,577
    compact_timestamp    SPDX documentNamespace form 20261101T151922Z
    uuid                 urn:uuid:<uuid> and bare uuid4 values
    json_duration        JSON values under keys containing
                         seconds/duration/elapsed (key kept, value masked)
    log_duration_assign  ELAPSED=/GAP=/GAP_FROM_PREVIOUS_END= assignments
    log_duration_prose   "in 0.2s" prose timings in scan.log
    bare_duration        MM:SS.ss / HH:MM:SS.ss duration strings
    file_size            parenthesized artifact-size annotations in
                         scan.log's write table, e.g. (270.1 KB): the
                         table prints each file's byte length, volatile
                         values (duration digit counts, fraction
                         widths) change that length, which flips the
                         0.1KB rounding between runs (observed under
                         suite load: 270.1 KB vs 270.2 KB); content
                         equality is still checked directly on every
                         artifact itself
    archive_name         the report zip's embedded DDMMYYYY HHMM
                         wall-clock (main.py names it that BY DESIGN --
                         `target Security_Report 0111202 1705.zip` --
                         and scan.log records the path; when the two
                         child runs straddle a minute boundary the
                         logged names differ, so the stamp is masked
                         right where it appears)
    output_path          this run's --output-dir path (run1 vs run2 differ
                         by construction; replaced with <OUT>)

Anything else that differs between the two runs -- finding rows, rule
ids, ordering, SBOM content, SARIF, CSV, Markdown -- is a determinism
defect and fails the gate.  Six of the fifteen artifacts are expected to
be byte-identical with no normalization at all (DefectDojo, Jira CSV,
PR comment, both QBOM layers, SARIF); the rest normalize clean.

RELATIONSHIP: analysis/validation/e2e.py `_findings_signature` asserts
defect-level agreement (rule, line) across two runs; this gate asserts
ARTIFACT-level byte stability of the full report surface after the
declared normalization -- strictly stronger for report files and
complementary to it.

SCOPE: the JSON/text/CSV/Markdown artifact surface (the gate runs the
children with --no-pdf --no-excel: the PDF and XLSX renderers embed
binary document metadata by design and are covered by their own tests,
not here).  The report zip that main.py writes BESIDE the output dir
(file name embeds wall-clock by design) is outside the compared set and
is cleaned up with the gate's temp root.  Offline by construction: two
local scans of a local fixture, no network stages.

EXIT CODES:
    0  deterministic (every artifact identical or normalized-equal)
    1  NOT deterministic (any real diff, missing side, or file-set
       mismatch between the two runs)
    2  could-not-run (main.py missing, child failed or timed out, no
       artifacts written, bad --target)
"""
from __future__ import annotations

import argparse
import io
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

SCHEMA = "rsecopsx.deterministic_output/v1"

# Pinned class order/tuple -- the disclosure contract.  Tests pin this.
VOLATILE_CLASSES = (
    "iso_timestamp",
    "compact_timestamp",
    "uuid",
    "json_duration",
    "log_duration_assign",
    "log_duration_prose",
    "bare_duration",
    "file_size",
    "archive_name",
    "output_path",
)

_TS = re.compile(
    rb"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?"
    rb"(?:Z|[+-]\d{2}:?\d{2})?")
_TS_COMPACT = re.compile(rb"\b\d{8}T\d{6}Z\b")
_UUID = re.compile(
    rb"urn:uuid:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    rb"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
    rb"|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    rb"[0-9a-fA-F]{12}")
_JSON_DURATION = re.compile(
    rb'("[^"]*(?:seconds|duration|elapsed)[^"]*"\s*:\s*)'
    rb'(?:"[^"]*"|-?[0-9]+(?:\.[0-9]+)?)',
    re.I)
_LOG_ASSIGN = re.compile(
    rb"((?:ELAPSED|GAP_FROM_PREVIOUS_END|GAP)=)\S+")
_LOG_PROSE = re.compile(rb"\bin \d+\.\d+s\b")
_BARE_DURATION = re.compile(
    rb"\b\d{2}:\d{2}:\d{2}\.\d{2}\b|\b\d{2}:\d{2}\.\d{2}\b")
_FILE_SIZE = re.compile(rb"\(\d+(?:\.\d+)?\s*[KM]B\)")
_ARCHIVE_NAME = re.compile(rb"Security_Report \d{8} \d{4}")

# The gate's own temp dirs use the batch prefix (never a secrets-scanner
# production-looking name).
TEMP_PREFIX = "rsx_t115_det_"
RUN_ARGS = ("--quiet", "--no-pdf", "--no-excel")
DEFAULT_TIMEOUT = 600

_FIXTURE_APP = (
    "import hashlib\n"
    "\n"
    "API_KEY = 'sk-live-0000000000000000000000000000abcd'\n"
    "\n"
    "def handler(request):\n"
    "    h = hashlib.md5(request.args['q'].encode()).hexdigest()\n"
    "    import subprocess\n"
    "    subprocess.call('ls ' + request.args['q'], shell=True)\n"
    "    return h\n"
)
_FIXTURE_REQ = "requests==2.31.0\n"


def normalize(data: bytes, out_dir: pathlib.Path) -> bytes:
    """Mask the DECLARED volatile classes; leave everything else intact.

    Each class is a named, pinned pattern (VOLATILE_CLASSES) -- widening
    a class would hide real content differences, narrowing one would
    fail legitimate runs; both directions are under test.
    """
    data = _TS.sub(b"<TS>", data)
    data = _TS_COMPACT.sub(b"<TS>", data)
    data = _UUID.sub(b"<UUID>", data)
    data = _JSON_DURATION.sub(rb"\1<DUR>", data)
    data = _LOG_ASSIGN.sub(rb"\1<DUR>", data)
    data = _LOG_PROSE.sub(b"in <DUR>", data)
    data = _BARE_DURATION.sub(b"<DUR>", data)
    data = _FILE_SIZE.sub(b"(SIZE)", data)
    data = _ARCHIVE_NAME.sub(b"Security_Report <TS>", data)
    out = str(out_dir).encode("utf-8", "surrogateescape")
    posix = out_dir.as_posix().encode("utf-8", "surrogateescape")
    data = data.replace(out, b"<OUT>")
    if posix != out:
        data = data.replace(posix, b"<OUT>")
    return data


def build_fixture(root: pathlib.Path) -> pathlib.Path:
    """Write the synthetic scan target (seeded findings + SCA pin)."""
    target = root / "target"
    target.mkdir(parents=True, exist_ok=True)
    (target / "app.py").write_text(_FIXTURE_APP, encoding="utf-8")
    (target / "requirements.txt").write_text(_FIXTURE_REQ, encoding="utf-8")
    return target


def run_once(target: pathlib.Path, out_dir: pathlib.Path,
             timeout: int) -> dict:
    """Run one real CLI scan; return rc plus a stderr tail on failure."""
    main_py = pathlib.Path(__file__).resolve().parents[2] / "main.py"
    if not main_py.is_file():
        return {"rc": 2, "error": "main.py not found"}
    cmd = [sys.executable, str(main_py), str(target),
           "--output-dir", str(out_dir), *RUN_ARGS]
    # Deliberately the DEFAULT environment: no hash-seed pinning, so a
    # set-order regression shows up here instead of in production.
    try:
        proc = subprocess.run(
            cmd, cwd=str(main_py.parent), capture_output=True,
            text=True, encoding="utf-8", errors="replace",
            timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"rc": 2, "error": "scan timed out after %ss" % timeout}
    if proc.returncode != 0:
        return {"rc": 2,
                "error": "scan failed rc=%s" % proc.returncode,
                "stderr_tail": (proc.stderr or "")[-400:]}
    if not (out_dir / "clean_report.json").is_file():
        return {"rc": 2, "error": "no clean_report.json written"}
    return {"rc": 0}


def compare_dirs(dir1: pathlib.Path, dir2: pathlib.Path) -> dict:
    """Byte-compare two artifact dirs after declared normalization."""
    files1 = sorted(p.name for p in dir1.iterdir() if p.is_file())
    files2 = sorted(p.name for p in dir2.iterdir() if p.is_file())
    result = {
        "file_sets_equal": files1 == files2,
        "files": {},
        "different": [],
        "missing": sorted(set(files1) ^ set(files2)),
        "identical": 0,
        "normalized": 0,
    }
    for name in sorted(set(files1) | set(files2)):
        p1, p2 = dir1 / name, dir2 / name
        if not p1.is_file() or not p2.is_file():
            result["files"][name] = "missing"
            continue
        b1, b2 = p1.read_bytes(), p2.read_bytes()
        if b1 == b2:
            result["files"][name] = "identical"
            result["identical"] += 1
            continue
        n1 = normalize(b1, dir1)
        n2 = normalize(b2, dir2)
        if n1 == n2:
            result["files"][name] = "normalized"
            result["normalized"] += 1
            continue
        result["files"][name] = "different"
        offset = next((i for i, (c1, c2) in enumerate(zip(n1, n2))
                       if c1 != c2), min(len(n1), len(n2)))
        lo = max(0, offset - 40)
        result["different"].append({
            "name": name,
            "offset": offset,
            "side1": repr(n1[lo:offset + 60]),
            "side2": repr(n2[lo:offset + 60]),
        })
    result["ok"] = (result["file_sets_equal"]
                    and not result["different"]
                    and not result["missing"]
                    and bool(files1))
    return result


def run_assertion(target: "str | os.PathLike | None" = None,
                  *, timeout: int = DEFAULT_TIMEOUT,
                  keep: bool = False) -> dict:
    """Double-scan and compare.  Returns rc + structured result."""
    root = pathlib.Path(tempfile.mkdtemp(prefix=TEMP_PREFIX))
    try:
        if target is None:
            scan_target = build_fixture(root)
        else:
            scan_target = pathlib.Path(target)
            if not scan_target.is_dir():
                return {"rc": 2,
                        "error": "target is not a directory: %s"
                                 % scan_target}
        run1, run2 = root / "run1", root / "run2"
        first = run_once(scan_target, run1, timeout)
        if first["rc"] != 0:
            return dict(first, run=1)
        second = run_once(scan_target, run2, timeout)
        if second["rc"] != 0:
            return dict(second, run=2)
        comparison = compare_dirs(run1, run2)
        outcome = {"rc": 0 if comparison["ok"] else 1,
                   "target": str(scan_target),
                   "comparison": comparison,
                   "kept_dir": str(root) if keep else None}
        if not comparison["ok"]:
            outcome["error"] = "artifacts diverged"
        return outcome
    finally:
        if not keep:
            shutil.rmtree(root, ignore_errors=True)


def main(argv: "list[str] | None" = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m analysis.validation.deterministic_output",
        description="T-9.15 deterministic output assertion "
                    "(task.md section 13).")
    parser.add_argument("--target", default=None,
                        help="scan target directory (default: a built "
                             "synthetic fixture in a temp dir)")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT,
                        help="per-scan subprocess timeout in seconds")
    parser.add_argument("--keep", action="store_true",
                        help="keep the temp root (fixture + both runs)")
    parser.add_argument("--json", action="store_true",
                        help="machine-readable summary on stdout")
    args = parser.parse_args(argv)

    original = sys.stdout
    try:
        wrapper = io.TextIOWrapper(original.buffer, encoding="utf-8",
                                   errors="replace")
        sys.stdout = wrapper
        outcome = run_assertion(args.target, timeout=args.timeout,
                                keep=args.keep)
        comparison = outcome.get("comparison") or {}
        files = comparison.get("files") or {}
        payload = {
            "schema": SCHEMA,
            "ok": outcome["rc"] == 0,
            "rc": outcome["rc"],
            "error": outcome.get("error"),
            "files": files,
            "identical": comparison.get("identical", 0),
            "normalized": comparison.get("normalized", 0),
            "different": comparison.get("different", []),
            "missing": comparison.get("missing", []),
            "file_sets_equal": comparison.get("file_sets_equal"),
            "kept_dir": outcome.get("kept_dir"),
        }
        if args.json:
            print(json.dumps(payload, sort_keys=True))
        else:
            if outcome["rc"] == 2:
                print("COULD-NOT-RUN: %s" % outcome.get("error"))
            else:
                for name in sorted(files):
                    print("  %-42s %s" % (name, files[name].upper()))
                for item in payload["different"]:
                    print("  DIFF %s @%s\n    1: %s\n    2: %s"
                          % (item["name"], item["offset"],
                             item["side1"], item["side2"]))
                if payload["missing"]:
                    print("  MISSING SIDE: %s"
                          % ", ".join(payload["missing"]))
                if outcome["rc"] == 0:
                    print("DETERMINISTIC (%d identical, %d normalized)"
                          % (payload["identical"], payload["normalized"]))
                    print("deterministic output assertion: PASS")
                else:
                    print("NOT DETERMINISTIC (%d differing)"
                          % len(payload["different"]))
                    print("deterministic output assertion: FAIL")
        sys.stdout.flush()
        sys.stdout.detach()
        sys.stdout = original
        return outcome["rc"]
    except BaseException:
        sys.stdout.flush()
        sys.stdout.detach()
        sys.stdout = original
        raise


if __name__ == "__main__":
    raise SystemExit(main())
