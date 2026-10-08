"""SAST/taint benchmark reconciliation harness.

Establishes an explicit, human-written GROUND TRUTH for the controlled
multi-language corpus (benchmark id: `sast-multilang-2026-10`), runs the
pipeline, matches findings semantically, and reports TP/FP/FN with
precision / recall / F1 plus a per-miss root-cause classification.

Ground truth is written *before* the scan is run. The scanner's own output
is never treated as ground truth.

Usage:
    python analysis/benchmark_sast_corpus.py
    python analysis/benchmark_sast_corpus.py --baseline <clean_report.json>
    python analysis/benchmark_sast_corpus.py --fixture <dir> --out <dir>
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
DEFAULT_FIXTURE = Path(
    r"C:\Users\janan\AppData\Local\Temp\opencode\p04_e2e_fixture"
)
DEFAULT_OUT = REPO / "reports"

BENCHMARK_ID = "sast-multilang-2026-10"
BENCHMARK_LANGUAGES = ["python", "javascript", "java", "csharp", "go", "php"]


@dataclass(frozen=True)
class GroundTruth:
    id: str
    file: str
    line: int
    category: str
    vulnerable: bool
    note: str
    expected_source: str
    expected_sink: str


# ---------------------------------------------------------------------------
# GROUND TRUTH (authored independently of the scanner; see note per row)
# ---------------------------------------------------------------------------
GROUND_TRUTH: list[GroundTruth] = [
    # ---- TRUE vulnerabilities -------------------------------------------
    GroundTruth("GT-01", "app.py", 6, "sql_injection", True,
                "Flask request arg concatenated into SQL text",
                "request.args.get('n')", "c.execute"),
    GroundTruth("GT-02", "app.py", 13, "command_injection", True,
                "Flask request arg passed to a shell interpreter",
                "request.args.get('cmd')", "subprocess.run"),
    GroundTruth("GT-03", "server.js", 6, "command_injection", True,
                "Express query concatenated into child_process.execSync",
                "req.query.id", "cp.execSync"),
    GroundTruth("GT-04", "server.js", 7, "code_injection", True,
                "Express query passed to eval()",
                "req.query.code", "eval"),
    GroundTruth("GT-05", "views.py", 5, "path_traversal", True,
                "Django GET param opened as a filesystem path",
                "request.GET.get('path')", "open"),
    GroundTruth("GT-06", "views.py", 8, "sql_injection", True,
                "Django POST body used as an identifier",
                "request.POST['name']", "c.execute"),
    GroundTruth("GT-07", "Vuln.java", 6, "command_injection", True,
                "Servlet parameter passed to Runtime.exec",
                "request.getParameter('cmd')", "Runtime.getRuntime().exec"),
    GroundTruth("GT-08", "Vuln.java", 10, "sql_injection", True,
                "Servlet parameter concatenated into JDBC query",
                "request.getParameter('n')", "st.executeQuery"),
    GroundTruth("GT-09", "Vuln.java", 12, "path_traversal", True,
                "Servlet parameter appended to a filesystem path",
                "request.getParameter('f')", "Paths.get"),
    GroundTruth("GT-10", "Controller.cs", 7, "sql_injection", True,
                "Action parameter concatenated into SqlCommand text",
                "id (action argument)", "new SqlCommand"),
    GroundTruth("GT-11", "main.go", 10, "command_injection", True,
                "HTTP query routed to a shell via exec.Command(sh, -c, q)",
                "r.URL.Query().Get('q')", "exec.Command"),
    GroundTruth("GT-12", "index.php", 4, "sql_injection", True,
                "Superglobal concatenated into mysqli query text",
                "$_GET['id']", "$db->query"),
    GroundTruth("GT-13", "index.php", 5, "command_injection", True,
                "Superglobal concatenated into a shell command",
                "$_GET['id']", "system"),

    # ---- MUST-NOT-FIND (negative controls) ------------------------------
    GroundTruth("NT-01", "app.py", 10, "sql_injection", False,
                "Bind parameter: value is data, not SQL structure",
                "request.args.get('id')", "c.execute(q, (...))"),
    GroundTruth("NT-02", "app.py", 17, "xss", False,
                "html.escape applied before rendering is a proven sanitizer",
                "request.args.get('q')", "render_template_string"),
    GroundTruth("NT-03", "app.py", 22, "command_injection", False,
                "Taint killed by a subsequent constant assignment",
                "input()", "subprocess.run"),
    GroundTruth("NT-04", "app.py", 26, "command_injection", False,
                "argv vector with no shell interpretation",
                "request.args.get('f')", "subprocess.run([...])"),
    GroundTruth("NT-05", "views.py", 15, "sql_injection", False,
                "Constant query text; no attacker-controlled input exists",
                "none (literal 'SELECT 1')", "c.execute(query)"),
    GroundTruth("NT-06", "Vuln.java", 9, "sql_injection", False,
                "Statement declaration only; the injection is on line 10",
                "none", "c.createStatement"),
]

# Root-cause taxonomy (see engineering standard section 18).
MISS_REASONS = {
    "GT-03": "SINK_GAP / RULE_GAP",
    "GT-12": "PARSER_GAP",
    "GT-13": "PARSER_GAP",
}

CATEGORY_ALIASES = {
    "sql_injection": "sql_injection",
    "sql injection": "sql_injection",
    "command_injection": "command_injection",
    "command injection": "command_injection",
    "code_injection": "code_injection",
    "code injection": "code_injection",
    "path_traversal": "path_traversal",
    "path traversal": "path_traversal",
    "xss": "xss",
}


def canon_category(value) -> str:
    v = str(value or "").strip().lower()
    return CATEGORY_ALIASES.get(v, v)


def load_findings(report: Path) -> list[dict]:
    data = json.loads(Path(report).read_text(encoding="utf-8"))
    findings = data.get("findings") if isinstance(data, dict) else None
    if findings is None:
        findings = data
    return [f for f in findings if isinstance(f, dict)]


def run_scan(fixture: Path, out: Path) -> list[dict]:
    if out.exists():
        import shutil
        shutil.rmtree(out)
    proc = subprocess.run(
        [sys.executable, str(REPO / "main.py"), str(fixture), "-o", str(out),
         "--no-excel"],
        capture_output=True, text=True, cwd=str(REPO),
        encoding="utf-8", errors="replace",
    )
    if proc.returncode != 0:
        raise SystemExit(
            f"scan failed rc={proc.returncode}\n"
            f"{(proc.stdout or '')[-2000:]}\n{(proc.stderr or '')[-2000:]}"
        )
    return load_findings(out / "clean_report.json")


@dataclass
class Match:
    ground_truth_id: str
    status: str                      # TRUE_POSITIVE / FALSE_NEGATIVE / ...
    match_confidence: str = "NO_MATCH"
    matched_finding: dict | None = None
    reason_missed: str = ""
    note: str = ""


def reconcile(findings: list[dict]) -> dict:
    norm = []
    for f in findings:
        norm.append({
            "file": Path(str(f.get("file") or "")).name.lower(),
            "line": int(f.get("line") or 0),
            "category": canon_category(f.get("vuln_type")),
            "rule_id": str(f.get("rule_id") or ""),
            "severity": str(f.get("severity") or ""),
            "confidence": str(f.get("confidence") or f.get("confidence_label") or ""),
            "evidence_valid": f.get("evidence_valid"),
            "snippet": str(f.get("snippet") or "")[:120],
        })

    matches: list[Match] = []
    claimed: set[int] = set()

    for gt in GROUND_TRUTH:
        want_file, want_line = gt.file.lower(), gt.line
        exact = [
            i for i, n in enumerate(norm)
            if i not in claimed
            and n["file"] == want_file
            and n["line"] == want_line
            and n["category"] == gt.category
        ]
        if exact:
            i = exact[0]
            claimed.add(i)
            matches.append(Match(gt.id, "TRUE_POSITIVE" if gt.vulnerable
                                 else "FALSE_POSITIVE",
                                 "EXACT_MATCH", norm[i], "", gt.note))
            continue

        # Relaxed: same file + category within a small line window.
        near = [
            i for i, n in enumerate(norm)
            if i not in claimed
            and n["file"] == want_file
            and n["category"] == gt.category
            and abs(n["line"] - want_line) <= 3
        ]
        if near:
            i = near[0]
            claimed.add(i)
            matches.append(Match(gt.id, "TRUE_POSITIVE" if gt.vulnerable
                                 else "FALSE_POSITIVE",
                                 "PROBABLE_MATCH", norm[i], "", gt.note))
            continue

        # Same file+category somewhere else: still absorbs a negative control
        # only when the finding is on a *different* line (recorded, not TP).
        if gt.vulnerable:
            matches.append(Match(
                gt.id, "FALSE_NEGATIVE", "NO_MATCH", None,
                MISS_REASONS.get(gt.id, "UNKNOWN"), gt.note))
        else:
            matches.append(Match(gt.id, "TRUE_NEGATIVE", "NO_MATCH", None,
                                 "", gt.note))

    unmatched = [norm[i] for i in range(len(norm)) if i not in claimed]
    for n in unmatched:
        on_vulnerable_line = any(
            g.file.lower() == n["file"] and g.line == n["line"] and g.vulnerable
            for g in GROUND_TRUTH
        )
        # Any finding that maps to no ground-truth row is a false positive for
        # precision purposes; the reason is retained for triage.
        matches.append(Match(
            "-", "FALSE_POSITIVE",
            "POSSIBLE_MATCH" if on_vulnerable_line else "NO_MATCH", n,
            "GROUND_TRUTH_CATEGORY_MISMATCH" if on_vulnerable_line
            else "RULE_OVERMATCH",
            "finding not mapped to any ground-truth row"))

    tp = [m for m in matches if m.status == "TRUE_POSITIVE"]
    fp = [m for m in matches if m.status == "FALSE_POSITIVE"]
    fn = [m for m in matches if m.status == "FALSE_NEGATIVE"]
    tn = [m for m in matches if m.status == "TRUE_NEGATIVE"]

    precision = len(tp) / (len(tp) + len(fp)) if (tp or fp) else None
    recall = len(tp) / (len(tp) + len(fn)) if (tp or fn) else None
    f1 = (2 * precision * recall / (precision + recall)
          if precision and recall else None)

    gt_total = sum(1 for g in GROUND_TRUTH if g.vulnerable)
    by_cat: dict[str, dict] = {}
    for g in GROUND_TRUTH:
        if not g.vulnerable:
            continue
        row = by_cat.setdefault(g.category, {"ground_truth": 0, "detected": 0})
        row["ground_truth"] += 1
        if any(m.ground_truth_id == g.id and m.status == "TRUE_POSITIVE"
               for m in matches):
            row["detected"] += 1
    for row in by_cat.values():
        row["missed"] = row["ground_truth"] - row["detected"]
        row["recall"] = round(row["detected"] / row["ground_truth"], 4)

    return {
        "benchmark_id": BENCHMARK_ID,
        "languages": BENCHMARK_LANGUAGES,
        "ground_truth_total": gt_total,
        "ground_truth_negative_controls": sum(
            1 for g in GROUND_TRUTH if not g.vulnerable),
        "rsecopsx_findings": len(norm),
        "true_positives": len(tp),
        "false_positives": len(fp),
        "false_negatives": len(fn),
        "true_negatives": len(tn),
        "unmatched_findings": len(unmatched),
        "precision": round(precision, 4) if precision is not None else None,
        "recall": round(recall, 4) if recall is not None else None,
        "f1": round(f1, 4) if f1 is not None else None,
        "detection_rate": round(len(tp) / gt_total, 4) if gt_total else None,
        "by_category": by_cat,
        "matches": [asdict(m) for m in matches],
        "raw_findings": norm,
    }


def write_reports(result: dict, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "benchmark_reconciliation.json").write_text(
        json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")

    def pct(v):
        return "n/a" if v is None else f"{v * 100:.1f}%"

    lines = [
        f"# Benchmark Reconciliation — `{result['benchmark_id']}`",
        "",
        f"Languages: {', '.join(result['languages'])}",
        "",
        "| Metric | Count |",
        "|---|---:|",
        f"| Ground-truth vulnerabilities | {result['ground_truth_total']} |",
        f"| Negative controls (must not fire) | {result['ground_truth_negative_controls']} |",
        f"| R-SecOpsX findings | {result['rsecopsx_findings']} |",
        f"| True positives | {result['true_positives']} |",
        f"| False positives | {result['false_positives']} |",
        f"| False negatives | {result['false_negatives']} |",
        f"| True negatives | {result['true_negatives']} |",
        f"| Detection rate | {pct(result['detection_rate'])} |",
        f"| Precision | {pct(result['precision'])} |",
        f"| Recall | {pct(result['recall'])} |",
        f"| F1 | {pct(result['f1'])} |",
        "",
        "## Detection by category",
        "",
        "| Category | Ground truth | Detected | Missed | Recall |",
        "|---|---:|---:|---:|---:|",
    ]
    for cat, row in sorted(result["by_category"].items()):
        lines.append(
            f"| {cat} | {row['ground_truth']} | {row['detected']} | "
            f"{row['missed']} | {pct(row['recall'])} |")

    lines += ["", "## Missed vulnerabilities", ""]
    missed = [m for m in result["matches"] if m["status"] == "FALSE_NEGATIVE"]
    if not missed:
        lines.append("_None._")
    for m in missed:
        lines.append(f"- **{m['ground_truth_id']}** — root cause: "
                     f"`{m['reason_missed'] or 'UNKNOWN'}` — {m['note']}")

    lines += ["", "## False positives", ""]
    fps = [m for m in result["matches"] if m["status"] == "FALSE_POSITIVE"]
    if not fps:
        lines.append("_None._")
    for m in fps:
        f = m["matched_finding"] or {}
        lines.append(
            f"- **{m['ground_truth_id']}** — {f.get('file')}:{f.get('line')} "
            f"`{f.get('rule_id')}` — reason: `{m['reason_missed']}` — {m['note']}")

    (out_dir / "benchmark_reconciliation.md").write_text(
        "\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--fixture", type=Path, default=DEFAULT_FIXTURE)
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--scan-out", type=Path,
                    default=DEFAULT_OUT / "_benchmark_scan")
    ap.add_argument("--baseline", type=Path, default=None,
                    help="existing clean_report.json to score for trend")
    args = ap.parse_args()

    t0 = time.time()
    findings = run_scan(args.fixture, args.scan_out)
    elapsed = time.time() - t0

    result = reconcile(findings)
    result["scan_seconds"] = round(elapsed, 2)

    if args.baseline:
        base = reconcile(load_findings(args.baseline))
        result["trend"] = {
            "baseline_file": str(args.baseline),
            "precision_before": base["precision"],
            "precision_after": result["precision"],
            "recall_before": base["recall"],
            "recall_after": result["recall"],
            "f1_before": base["f1"],
            "f1_after": result["f1"],
            "fp_before": base["false_positives"],
            "fp_after": result["false_positives"],
            "fn_before": base["false_negatives"],
            "fn_after": result["false_negatives"],
        }

    write_reports(result, args.out)

    print(f"benchmark={result['benchmark_id']}  scan={elapsed:.1f}s")
    print(f"  ground truth : {result['ground_truth_total']} vulns + "
          f"{result['ground_truth_negative_controls']} negative controls")
    print(f"  findings     : {result['rsecopsx_findings']}")
    print(f"  TP/FP/FN/TN  : {result['true_positives']}/"
          f"{result['false_positives']}/{result['false_negatives']}/"
          f"{result['true_negatives']}")
    print(f"  precision    : {result['precision']}")
    print(f"  recall       : {result['recall']}")
    print(f"  f1           : {result['f1']}")
    for cat, row in sorted(result["by_category"].items()):
        print(f"    {cat:<20} {row['detected']}/{row['ground_truth']} "
              f"recall={row['recall']}")
    if "trend" in result:
        t = result["trend"]
        print(f"  TREND f1: {t['f1_before']} -> {t['f1_after']}   "
              f"recall: {t['recall_before']} -> {t['recall_after']}   "
              f"fp: {t['fp_before']} -> {t['fp_after']}")
    print(f"  reports      : {args.out / 'benchmark_reconciliation.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
