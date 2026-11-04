"""T-1.5: engine parity gate -- py vs rust, normalized, byte-identical.

Runs BOTH engines on the same target, normalizes paths (absolute ->
target-relative posix) and ordering (canonical sort), then compares
every finding row EXCEPT the fields that differ by construction:
`engine` (the stamp itself), `evidence` and `group_key` (derived from
file/line/snippet on both sides). After that normalization the rows must
be byte-identical -- that is the literal gate.

Because the Rust v1 engine is pre-parity by design (see status.limits
printed on every rust run), the default mode compares against a
committed annotation set: every actual delta row must carry an
annotation with a machine-readable class + reason, and every annotation
must still be LIVE (stale annotations fail too -- they are a silent
drop waiting to happen). Green therefore means "the delta set is
exactly the disclosed set": any new divergence fails, any closed one
forces the annotation out.

Modes:
    default                 corpus target, annotated compare
    --strict                ignore annotations: literal byte-identical
                            (the flip-default criterion; red until the
                            engines converge)
    --perf                  add the perf gate: p50/p95 speedup on the
                            corpus >= --min-speedup, a minified ~5 MB
                            JS bundle scans in < --bundle-budget seconds
                            (Rust side), peak working set under
                            --mem-budget MB (fresh subprocess per
                            engine so the numbers mean one engine only)
    --target PATH           scan this target instead of the corpus
    --full                  corpus + BenchmarkJava + the canonical
                            prodtest project list (compare_prodtest_
                            corpus.ORDER_HINT) for each entry that exists
    --update-annotations    rewrite tests/parity/known_divergences.json
                            from THIS run (inspect the diff before you
                            commit it: an annotation is a disclosed
                            divergence, never a fix)

Exit codes: 0 green, 1 red or environment failure, 2 usage error.

Usage:
    python -m analysis.validation.parity_gate
    python -m analysis.validation.parity_gate --strict --perf
    python -m analysis.validation.parity_gate --update-annotations
"""
from __future__ import annotations
try:
    from analysis.spans import WINDOW_16, WINDOW_2, WINDOW_M2000
except ImportError:  # FND-03: standalone, repo root not on path
    import sys as _fnd03_sys
    from pathlib import Path as _fnd03_path
    _fnd03_sys.path.insert(0, str(_fnd03_path(__file__).resolve().parents[2]))
    from analysis.spans import WINDOW_16, WINDOW_2, WINDOW_M2000

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

REPO = Path(__file__).resolve().parents[2]
ANNOTATIONS_PATH = REPO / "tests" / "parity" / "known_divergences.json"
ANNOTATION_SCHEMA = "rsecopsx.parity_annotations/v1"
BENCHMARK_DIR = Path(r"D:\Data\Code test\prodtest\BenchmarkJava-master")
PRODTEST_DIR = Path(r"D:\Data\Code test\prodtest")
CORPUS = REPO / "tests" / "vuln-test-corpus"
# Canonical prodtest targets -- same list analysis/compare_prodtest_corpus.py
# sweeps (ORDER_HINT minus BenchmarkJava, which gets its own target name).
PRODTEST_TARGETS = [
    "LLMForge-main",
    "VAmPI-master",
    "dvpwa-master",
    "Damn-Vulnerable-RESTaurant-API-Game-main",
    "argip-platform",
    "DVAP-main",
    "damn-vulnerable-defi-master",
    "NodeGoat-master",
    "railsgoat-main",
    "DVWA-master",
    "GenAI-Red-Team-Lab-main",
    "juice-shop-git",
    "wrongsecrets-master",
    "WebGoat-main",
    "web-security-testing-guide-master",
]

# Differ by construction between the engines; excluded from rows.
DERIVED = ("engine", "evidence", "group_key")


def _rel(file_str: str, root: Path) -> str:
    """Absolute native path -> target-relative posix; outside paths keep
    their normalised (lowercased) form so both engines still compare
    equal across drive-letter case and separator style."""
    try:
        rel = os.path.relpath(file_str, str(root))
    except ValueError:  # different drives
        rel = file_str
    if not rel.startswith(".."):
        return rel.replace(os.sep, "/").replace("\\", "/")
    return file_str.replace(os.sep, "/").replace("\\", "/").lower()


def _row(finding: dict, root: Path) -> dict:
    row = {k: v for k, v in finding.items() if k not in DERIVED}
    row["file"] = _rel(str(row.get("file") or ""), root)
    return row


def _row_json(row: dict) -> str:
    return json.dumps(row, sort_keys=True, ensure_ascii=True)


def _hash(row_json: str) -> str:
    return hashlib.sha256(row_json.encode("utf-8")).hexdigest()[:WINDOW_16]


def _key(row: dict) -> tuple:
    return (row.get("rule_id"), row.get("file"), row.get("line"))


def _scan_py(target: Path) -> list[dict]:
    from scanner.sast import scan_directory

    return scan_directory(str(target), workers=2)


def _scan_rust(target: Path) -> tuple[list[dict], dict]:
    from scanner import rust_engine

    findings = rust_engine.scan_directory(str(target), workers=2)
    return findings, rust_engine._LAST_STATUS or {}


def _classify(
    side: str,
    row: dict,
    other_rows: list[dict],
    unsupported_ids: set[str],
) -> tuple[str, str]:
    """Machine-readable class + human reason for one delta row."""
    rid = str(row.get("rule_id") or "?")
    if side == "py":
        if rid in unsupported_ids:
            return (
                "unsupported_regex_crate",
                "python-only regex syntax; the regex crate rejects the "
                "pattern and the engine discloses it in rules_unsupported",
            )
        if "TAINT" in rid:  # TAINT_* and JAVA_TAINT_* alike
            return (
                "taint_not_ported",
                "row comes from the Python taint engine; the Rust v1 "
                "engine is regex + enterprise tables only (status.limits)",
            )
    same_anchor = [r for r in other_rows if _key(r) == _key(row)]
    if same_anchor:
        # Same (rule,file,line) but the grouped representative differs:
        # when either side carries taint-flow metadata, the Python
        # engine's taint layer enriched the representative at that
        # root_key (engine_priority in core.deduplicator); the Rust v1
        # tables have no taint layer (status.limits).
        for r in (row, *same_anchor):
            if r.get("taint_chain") or r.get("taint_path"):
                return (
                    "taint_metadata_collision",
                    "the Python taint layer enriched the grouped "
                    "representative at this anchor (description/"
                    "taint_chain/source_expr/...); the Rust engine runs "
                    "the regex + enterprise tables only (status.limits)",
                )
        return (
            "anchor_field_drift",
            "both engines fire at rule+file+line but the row differs "
            "elsewhere (commonly snippet: Python's focus-pattern evidence "
            "vs the Rust engine's stripped matched line -- status.limits)",
        )
    same_rf = [r for r in other_rows if _key(r)[:WINDOW_2] == _key(row)[:WINDOW_2]]
    if same_rf:
        return (
            "focus_reanchor",
            "same rule+file on both engines at different lines "
            "(Python's focus-pattern/evidence re-anchor is not ported)",
        )
    if side == "py":
        return (
            "py_only_unexplained",
            "needs triage: not an unsupported rule, not taint, no rust "
            "counterpart line -- classify only with evidence",
        )
    return (
        "py_suppression_not_ported",
        "the Python engine suppressed this row (rule-specific validators "
        "and in-string/comment suppression are not ported in v1 -- "
        "status.limits)",
    )


def _update_annotations(all_rows: list[dict], path: Path = ANNOTATIONS_PATH) -> None:
    deduped = {(a["target"], a["row_hash"]): a for a in all_rows}
    doc = {
        "schema": ANNOTATION_SCHEMA,
        "annotations": sorted(
            deduped.values(), key=lambda a: (a["target"], a["side"], a["row_hash"])
        ),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )


def _load_annotations() -> dict[tuple[str, str], dict]:
    if not ANNOTATIONS_PATH.exists():
        return {}
    doc = json.loads(ANNOTATIONS_PATH.read_text(encoding="utf-8"))
    if doc.get("schema") != ANNOTATION_SCHEMA:
        raise SystemExit(
            f"annotations schema {doc.get('schema')!r} != {ANNOTATION_SCHEMA!r}"
        )
    return {(a["target"], a["row_hash"]): a for a in doc.get("annotations", [])}


def _compare_target(
    name: str, target: Path, annotations: dict, strict: bool
) -> tuple[list[dict], list[dict], list[dict], int, int]:
    """Returns (all-delta annotations, stale annotations, unannotated
    deltas, py finding count, rust finding count)."""
    py_findings = _scan_py(target)
    rust_findings, status = _scan_rust(target)
    py_rows = [_row(f, target) for f in py_findings]
    rust_rows = [_row(f, target) for f in rust_findings]

    # Row-level multiset via canonical json; duplicates keep multiplicity.
    py_bag: dict[str, int] = {}
    rust_bag: dict[str, int] = {}
    for r in py_rows:
        k = _row_json(r)
        py_bag[k] = py_bag.get(k, 0) + 1
    for r in rust_rows:
        k = _row_json(r)
        rust_bag[k] = rust_bag.get(k, 0) + 1

    unsupported_ids = {u.get("id") for u in status.get("rules_unsupported", [])}
    deltas: list[tuple[str, dict]] = []
    for k, n in py_bag.items():
        for _ in range(n - rust_bag.get(k, 0)):
            deltas.append(("py", json.loads(k)))
    for k, n in rust_bag.items():
        for _ in range(n - py_bag.get(k, 0)):
            deltas.append(("rust", json.loads(k)))

    all_rows: list[dict] = []
    unannotated: list[dict] = []
    seen_live: set[tuple[str, str]] = set()
    for side, row in deltas:
        row_hash = _hash(_row_json(row))
        cls, reason = _classify(
            side, row, rust_rows if side == "py" else py_rows, unsupported_ids
        )
        ann = {
            "target": name,
            "side": side,
            "row_hash": row_hash,
            "rule_id": row.get("rule_id"),
            "file": row.get("file"),
            "line": row.get("line"),
            "class": cls,
            "reason": reason,
        }
        all_rows.append(ann)
        ann_key = (name, row_hash)
        if ann_key in annotations:
            seen_live.add(ann_key)
            continue  # disclosed and still true
        unannotated.append(ann)  # strict mode has no annotations at all

    stale = [
        a
        for (t, h), a in annotations.items()
        if t == name and (t, h) not in seen_live
    ]
    return all_rows, stale, unannotated, len(py_findings), len(rust_findings)


def _perf_gate(
    min_speedup: float, bundle_budget: float, mem_budget_mb: float, runs: int
) -> list[str]:
    """Fresh subprocess-per-engine measurements. Returns failure lines."""
    failures: list[str] = []
    worker = r'''
import json, sys, time, ctypes
sys.path.insert(0, sys.argv[1])
target = sys.argv[2]
engine = sys.argv[3]
runs = int(sys.argv[4])
if engine == "py":
    from scanner.sast import scan_directory
    scan_directory(target, workers=2)  # warmup
    ts = []
    n = 0
    for _ in range(runs):
        t0 = time.perf_counter()
        n = len(scan_directory(target, workers=2))
        ts.append(time.perf_counter() - t0)
else:
    from scanner import rust_engine
    rust_engine.scan_directory(target, workers=2)  # warmup
    ts = []
    n = 0
    for _ in range(runs):
        t0 = time.perf_counter()
        n = len(rust_engine.scan_directory(target, workers=2))
        ts.append(time.perf_counter() - t0)
class PMC(ctypes.Structure):
    _fields_ = [("PageFaultCount", ctypes.c_ulong),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t)]
k32 = ctypes.windll.kernel32
psapi = ctypes.windll.psapi
k32.GetCurrentProcess.restype = ctypes.c_void_p
psapi.GetProcessMemoryInfo.argtypes = [
    ctypes.c_void_p, ctypes.POINTER(PMC), ctypes.c_uint32]
psapi.GetProcessMemoryInfo.restype = ctypes.c_int
pmc = PMC(); pmc.cb = ctypes.sizeof(PMC)
_ok = psapi.GetProcessMemoryInfo(
    k32.GetCurrentProcess(), ctypes.byref(pmc), pmc.cb)
if not _ok:
    raise SystemExit("GetProcessMemoryInfo failed")
def pct(vals, q):
    s = sorted(vals); k = (len(s) - 1) * q
    lo, hi = int(k), min(int(k) + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (k - lo)
print(json.dumps({"p50": pct(ts, 0.5), "p95": pct(ts, 0.95),
                  "findings": n, "peak_ws_mb": pmc.PeakWorkingSetSize / 1e6}))
'''

    def run_engine(engine: str, target: str, n: int) -> dict:
        out = subprocess.run(
            [sys.executable, "-c", worker, str(REPO), target, engine, str(n)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=1800,
            cwd=str(REPO),
        )
        if out.returncode != 0:
            raise SystemExit(
                f"perf worker ({engine}) failed:\n{out.stderr[WINDOW_M2000:]}"
            )
        return json.loads(out.stdout.strip().splitlines()[-1])

    py = run_engine("py", str(CORPUS), runs)
    rust = run_engine("rust", str(CORPUS), runs)
    speedup = py["p50"] / rust["p50"] if rust["p50"] else 0.0
    print(
        f"[perf] corpus: py p50={py['p50']*1000:.1f}ms p95={py['p95']*1000:.1f}ms | "
        f"rust p50={rust['p50']*1000:.1f}ms p95={rust['p95']*1000:.1f}ms | "
        f"speedup p50={speedup:.2f}x | peak ws py={py['peak_ws_mb']:.0f}MB "
        f"rust={rust['peak_ws_mb']:.0f}MB"
    )
    if speedup < min_speedup:
        failures.append(
            f"perf: p50 speedup {speedup:.2f}x < required {min_speedup}x"
        )
    if rust["peak_ws_mb"] > mem_budget_mb:
        failures.append(
            f"perf: rust peak working set {rust['peak_ws_mb']:.0f}MB > "
            f"budget {mem_budget_mb:.0f}MB"
        )

    # ~5 MB minified JS bundle, deterministic content (gitignored). In a
    # DIRECTORY: the Rust walk takes a directory root, and the Python
    # walk accepts one too -- same shape for both engines.
    bundle_dir = REPO / "tests" / "parity" / "_perf"
    bundle = bundle_dir / "bundle5mb.js"
    bundle_dir.mkdir(parents=True, exist_ok=True)
    if not bundle.exists() or bundle.stat().st_size < 4_800_000:
        line = (
            "var a=function(x){return x*3+Math.random()};"
            "function b(y){if(y>0){return a(y)+y}else{return 0}}"
        )
        with bundle.open("w", encoding="utf-8") as fh:
            fh.write("function e(){return 1};")
            while fh.tell() < 5_000_000:
                fh.write(line)
                fh.write("var o=JSON.parse('{}');")
    b_rust = run_engine("rust", str(bundle_dir), max(3, runs // 2))
    b_py = run_engine("py", str(bundle_dir), max(3, runs // 2))
    print(
        f"[perf] 5MB bundle: rust p50={b_rust['p50']*1000:.0f}ms "
        f"(budget {bundle_budget*1000:.0f}ms) | py p50={b_py['p50']*1000:.0f}ms"
    )
    if b_rust["p50"] > bundle_budget:
        failures.append(
            f"perf: 5MB bundle rust p50 {b_rust['p50']*1000:.0f}ms > "
            f"budget {bundle_budget*1000:.0f}ms"
        )
    return failures


def _targets(full: bool, explicit: str | None) -> list[tuple[str, Path]]:
    if explicit:
        p = Path(explicit)
        if not p.exists():
            raise SystemExit(f"target not found: {p}")
        return [(p.name, p)]
    out = [("corpus", CORPUS)]
    if full:
        if BENCHMARK_DIR.exists():
            out.append(("benchmark-java", BENCHMARK_DIR))
        for name in PRODTEST_TARGETS:
            d = PRODTEST_DIR / name
            if d.is_dir():
                out.append((name, d))
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="T-1.5 py-vs-rust parity gate")
    ap.add_argument("--strict", action="store_true",
                    help="literal byte-identical; annotations ignored")
    ap.add_argument("--perf", action="store_true",
                    help="add the p50 speedup / bundle / memory gate")
    ap.add_argument("--full", action="store_true",
                    help="corpus + BenchmarkJava + canonical prodtest list")
    ap.add_argument("--target", help="compare one explicit target")
    ap.add_argument("--update-annotations", action="store_true",
                    help="rewrite the annotations file from this run")
    ap.add_argument("--min-speedup", type=float, default=5.0)
    ap.add_argument("--bundle-budget", type=float, default=2.0)
    ap.add_argument("--mem-budget-mb", type=float, default=4096.0)
    ap.add_argument("--runs", type=int, default=5,
                    help="timed runs per engine for --perf")
    args = ap.parse_args(argv)

    from scanner import rust_engine  # noqa: F401  (fails loud if unbuilt)

    annotations = {} if args.strict else _load_annotations()
    all_new: list[dict] = []
    failures: list[str] = []
    report: list[str] = []

    for name, target in _targets(args.full, args.target):
        fresh, stale, unannotated, py_n, rust_n = _compare_target(
            name, target, annotations, args.strict
        )
        all_new.extend(fresh)
        report.append(
            f"target {name}: py={py_n} rust={rust_n} findings; "
            f"{len(unannotated)} unannotated delta(s), {len(stale)} stale"
        )
        for ann in unannotated:
            failures.append(
                f"{name}: UNANNOTATED {ann['side']} "
                f"{ann['rule_id']} {ann['file']}:{ann['line']} "
                f"[{ann['class']}] {ann['reason']}"
            )
        for ann in stale:
            failures.append(
                f"{name}: STALE annotation {ann['row_hash']} "
                f"{ann['side']} {ann['rule_id']} {ann['file']}:{ann['line']} "
                "(the divergence is gone -- remove the annotation)"
            )

    if args.update_annotations:
        if args.strict:
            raise SystemExit("--update-annotations cannot pair with --strict")
        _update_annotations(all_new)
        print(f"annotations rewritten: {ANNOTATIONS_PATH} "
              f"({len(all_new)} delta row(s))")
        return 0

    if args.perf:
        failures.extend(
            _perf_gate(args.min_speedup, args.bundle_budget,
                       args.mem_budget_mb, args.runs)
        )

    for line in report:
        print(line)
    if failures:
        print(f"\nPARITY GATE: RED ({len(failures)} failure(s))")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("\nPARITY GATE: GREEN "
          f"({'' if args.strict else 'annotated deltas match, '}"
          "normalized rows otherwise byte-identical)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
