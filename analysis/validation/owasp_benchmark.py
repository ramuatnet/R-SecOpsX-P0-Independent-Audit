"""OWASP BenchmarkJava differential run (Phase V1.4).

The golden corpus is ours; this is someone else's -- 2740 labelled Java
servlet tests (1415 vulnerable, 1325 negative) with per-test ground truth
in ``expectedresults-1.2.csv`` (test id, category, real vulnerability,
CWE). Running it answers the question our own fixtures cannot: how does
R-SecOpsX score on the community-standard SAST benchmark, with the
community's own labels?

Methodology decisions, each deliberate:

* Per-TEST scoring, not per-line (the Benchmark's own convention): a test
  is detected when any finding lands in ``BenchmarkTestNNNNN.java``, since
  the oracle labels the file, not the line.
* Two recall numbers. "detected" counts any finding in a true-positive
  test; "cwe-aligned" additionally requires the finding's CWE to be the
  labelled CWE, so a stray unrelated hit cannot masquerade as detection
  of the category. The aligned number is the honest one.
* False positives are counted on NEGATIVE tests (label real=false): a
  finding there is wrong by the Benchmark's own ground truth. Both the
  number of negative tests flagged and raw finding count are reported --
  one rule firing 10x in one file and ten rules firing once differ.
* The scanner never sees the labels. No filename, ID or comment special
  casing: this module is the only place Benchmark specifics live (the
  scanner-side Java layers are deliberately generic API semantics).

The run is REPORT-ONLY by default (exit 0): absolute recall against an
external oracle is a measurement, not a pass/fail contract. ``--min-recall``
turns it into a regression gate when a project wants one.

Scanning the full tree takes minutes; ``--findings-out`` dumps raw
findings and ``--reuse-findings`` rescoring from the dump, so iteration on
scoring questions does not repeat the scan.

Usage:
    python -m analysis.validation.owasp_benchmark --benchmark-dir <clone>
        [--json] [--findings-out f.json] [--reuse-findings f.json]
        [--min-recall 0.7]
"""
from __future__ import annotations

import argparse
import csv
import json
import logging
import re
import sys
import time
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

_LOG = logging.getLogger("rsx.analysis.validation.owasp_benchmark")

TEST_ID_RE = re.compile(r"(BenchmarkTest\d+)", re.I)
TRUTH_CSV = "expectedresults-1.2.csv"
SCAN_SUBDIR = Path("src") / "main" / "java"


@dataclass(frozen=True)
class GroundTruth:
    test_id: str
    category: str
    real_vulnerability: bool
    cwe: str


def load_ground_truth(benchmark_dir: Path) -> dict[str, GroundTruth]:
    """Parse expectedresults-1.2.csv into {test_id: label}."""
    csv_path = Path(benchmark_dir) / TRUTH_CSV
    if not csv_path.is_file():
        raise FileNotFoundError(
            "%s not found -- pass the root of an OWASP-Benchmark/BenchmarkJava "
            "clone (git clone --depth 1 https://github.com/OWASP-Benchmark/"
            "BenchmarkJava.git)" % csv_path)
    truth: dict[str, GroundTruth] = {}
    with open(csv_path, newline="", encoding="utf-8") as fh:
        for row in csv.reader(line for line in fh if not line.startswith("#")):
            if len(row) < 4:
                continue
            truth[row[0].strip()] = GroundTruth(
                test_id=row[0].strip(),
                category=row[1].strip(),
                real_vulnerability=row[2].strip().lower() == "true",
                cwe=row[3].strip(),
            )
    return truth


def scan_benchmark(benchmark_dir: Path) -> list[dict]:
    """Scan the benchmark's Java sources with the pipeline's SAST layers."""
    from scanner.sast import scan_directory

    target = Path(benchmark_dir) / SCAN_SUBDIR
    if not target.is_dir():
        raise FileNotFoundError("%s not found in the benchmark clone" % target)
    _LOG.info("scanning %s (takes minutes for 2740 test files)", target)
    return list(scan_directory(str(target)))


def score(findings: list[dict], truth: dict[str, GroundTruth]) -> dict:
    """Aggregate findings against the labelled tests.

    Findings not attributable to a BenchmarkTest file (helpers, service
    classes) are counted but never scored -- the oracle says nothing about
    them, and silently folding them into either side would fabricate
    labels.
    """
    per_test: dict[str, list[dict]] = defaultdict(list)
    off_target = 0
    for f in findings:
        m = TEST_ID_RE.search(str(f.get("file") or ""))
        if m:
            per_test[m.group(1).lower()].append(f)
        else:
            off_target += 1

    cats: dict[str, dict] = defaultdict(lambda: {
        "true_total": 0, "detected": 0, "detected_cwe_aligned": 0,
        "false_total": 0, "fp_tests": 0, "fp_findings": 0,
    })
    for tid, gt in truth.items():
        c = cats[gt.category]
        hits = per_test.get(tid.lower(), [])
        if gt.real_vulnerability:
            c["true_total"] += 1
            if hits:
                c["detected"] += 1
                # CSV holds bare numbers ("89"); findings hold "CWE-89".
                want = "cwe-" + str(gt.cwe).replace("cwe-", "").replace("CWE-", "")
                if any(str(h.get("cwe") or "").strip().lower() == want for h in hits):
                    c["detected_cwe_aligned"] += 1
        else:
            c["false_total"] += 1
            if hits:
                c["fp_tests"] += 1
                c["fp_findings"] += len(hits)

    categories: dict[str, dict] = {}
    totals = defaultdict(int)
    for cat in sorted(cats):
        c = cats[cat]
        categories[cat] = {
            **c,
            "recall": (c["detected"] / c["true_total"]) if c["true_total"] else None,
            "recall_cwe_aligned": (c["detected_cwe_aligned"] / c["true_total"])
            if c["true_total"] else None,
            "fp_rate": (c["fp_tests"] / c["false_total"]) if c["false_total"] else None,
        }
        for k in ("true_total", "detected", "detected_cwe_aligned",
                  "false_total", "fp_tests", "fp_findings"):
            totals[k] += c[k]

    overall = {
        **totals,
        "recall": totals["detected"] / totals["true_total"] if totals["true_total"] else None,
        "recall_cwe_aligned": (totals["detected_cwe_aligned"] / totals["true_total"])
        if totals["true_total"] else None,
        "fp_rate": totals["fp_tests"] / totals["false_total"] if totals["false_total"] else None,
    }
    return {
        "categories": categories,
        "overall": overall,
        "off_target_findings": off_target,
        "tests_with_findings": len(per_test),
    }


def _print_table(result: dict) -> None:
    print("%-13s %5s %6s %6s %6s %6s %6s %8s %7s"
          % ("category", "true", "found", "cwe+", "fpT", "fpF", "neg",
             "recall", "fpRate"))
    print("-" * 74)
    for cat, c in result["categories"].items():
        rec = "%.0f%%" % (100 * c["recall"]) if c["recall"] is not None else "-"
        fpr = "%.0f%%" % (100 * c["fp_rate"]) if c["fp_rate"] is not None else "-"
        print("%-13s %5d %6d %6d %6d %6d %6d %8s %7s"
              % (cat, c["true_total"], c["detected"], c["detected_cwe_aligned"],
                 c["fp_tests"], c["fp_findings"], c["false_total"], rec, fpr))
    print("-" * 74)
    o = result["overall"]
    # A synthetic truth can lack one side entirely (no negative tests ->
    # fp_rate None), and printing must degrade to "-" rather than crash
    # mid-table -- the tests caught exactly that.
    orec = "%.1f%%" % (100 * o["recall"]) if o["recall"] is not None else "-"
    ofpr = "%.1f%%" % (100 * o["fp_rate"]) if o["fp_rate"] is not None else "-"
    ocwe = ("%.1f%%" % (100 * o["recall_cwe_aligned"])
            if o["recall_cwe_aligned"] is not None else "-")
    print("%-13s %5d %6d %6d %6d %6d %6d %8s %7s"
          % ("OVERALL", o["true_total"], o["detected"], o["detected_cwe_aligned"],
             o["fp_tests"], o["fp_findings"], o["false_total"], orec, ofpr))
    print("cwe-aligned recall: %s   off-target findings: %d"
          % (ocwe, result["off_target_findings"]))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="analysis.validation.owasp_benchmark",
        description="Score R-SecOpsX against the OWASP BenchmarkJava oracle.")
    parser.add_argument("--benchmark-dir", type=Path, default=None,
                        help="clone root of OWASP-Benchmark/BenchmarkJava")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--findings-out", type=Path, default=None,
                        help="dump raw findings here for offline rescoring")
    parser.add_argument("--reuse-findings", type=Path, default=None,
                        help="score from a previous dump instead of scanning")
    parser.add_argument("--min-recall", type=float, default=None,
                        help="exit 1 when overall (any-finding) recall is below this")
    args = parser.parse_args(argv)

    if args.reuse_findings:
        findings = json.loads(args.reuse_findings.read_text(encoding="utf-8"))
        if args.benchmark_dir is None:
            parser.error("--reuse-findings still needs --benchmark-dir for the labels")
    else:
        if args.benchmark_dir is None:
            parser.error("--benchmark-dir is required (or pass --reuse-findings)")
        findings = scan_benchmark(args.benchmark_dir)
        if args.findings_out:
            args.findings_out.write_text(json.dumps(findings, default=str),
                                         encoding="utf-8")
            _LOG.info("raw findings written to %s", args.findings_out)

    truth = load_ground_truth(Path(args.benchmark_dir or "."))
    t0 = time.time()
    result = score(findings, truth)
    result["scored_in_seconds"] = round(time.time() - t0, 2)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        _print_table(result)

    if args.min_recall is not None:
        rec = result["overall"]["recall"] or 0.0
        if rec < args.min_recall:
            print("FAIL: recall %.3f < --min-recall %.3f" % (rec, args.min_recall))
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
