"""Language-granularity benchmark (G-059).

Why this exists
---------------
G-059 records that detection granularity differs by language: Python reaches a
real AST while every other language is served by regular expressions
(``scanner/taint_engine.py:2194-2198``). Until the class-A SAST number is
*split* by language, F1 = 1.0 is unattributable -- it cannot say whether the
regex path costs precision, recall, or nothing at all.

This benchmark reuses the class-A corpus and its matcher unchanged, then
stratifies the same reconciliation by language, so every number here
reconciles with ``reports/benchmark_reconciliation.json`` by construction
(asserted as a verdict, not assumed).

Ground truth
------------
The ground truth is ``analysis/benchmark_sast_corpus.GROUND_TRUTH``, authored
independently of the scanner before any scan. Nothing here re-derives truth
from scanner output.

Honest limitation
-----------------
Per-language denominators are small (1 to 4 vulnerabilities). One miss moves a
language's recall by 1/N, so a language with N = 1 can only ever score 0.0 or
1.0. The benchmark therefore reports ``min_detectable_delta`` per language and
fails ``v4_corpus_detects_granularity_delta`` while the corpus is too small to
attribute a granularity cost. A FAIL here means "not yet measurable", not
"regex is as good as an AST".

Output (distinct names, nothing else is overwritten):
    reports/benchmark_reconciliation_language_granularity.json
    reports/benchmark_reconciliation_language_granularity.md
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
BASE_PATH = REPO / "analysis" / "benchmark_sast_corpus.py"

# ---------------------------------------------------------------------------
# Language attribution
# ---------------------------------------------------------------------------
EXT_LANG = {
    ".py": "python",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript",
    ".cjs": "javascript", ".ts": "javascript", ".tsx": "javascript",
    ".java": "java",
    ".cs": "csharp",
    ".go": "go",
    ".php": "php",
}


def language_of(filename) -> str:
    return EXT_LANG.get(Path(str(filename or "")).suffix.lower(), "unknown")


# Detection technique per language, transcribed from the dispatch we verify at
# runtime below. If the dispatch changes, verification fails and the labels
# cannot silently go stale.
TECHNIQUE = {
    "python":   "AST (ast.parse)",
    "java":     "REGEX (java_semantic text patterns)",
    "javascript": "REGEX (enterprise text pass only)",
    "csharp":   "REGEX (enterprise text pass only)",
    "go":       "REGEX (enterprise text pass only)",
    "php":      "REGEX (enterprise text pass only)",
}


def verify_dispatch() -> list[str]:
    """Fail loudly if the engine no longer matches the labels we publish.

    A benchmark that labels a path "AST" after the dispatch stopped using an
    AST would be worse than no benchmark at all.
    """
    problems: list[str] = []
    taint = (REPO / "scanner" / "taint_engine.py").read_text(encoding="utf-8")
    sast = (REPO / "scanner" / "sast.py").read_text(encoding="utf-8")

    checks = [
        ("python branch calls _python_ast_findings",
         r'lang\s*==\s*"python"[\s\S]{0,120}_python_ast_findings'),
        ("java branch calls _scan_java_semantic",
         r'lang\s*==\s*"java"[\s\S]{0,120}_scan_java_semantic'),
        ("text pass runs for every language", r"_scan_enterprise_text\("),
        ("a real ast.parse exists", r"ast\.parse\("),
        ("taint engine imports ast", r"^\s*import ast\b"),
        ("every declarative rule compiles to a regex",
         r're\.compile\(r\["pat"\]'),
    ]
    for label, pat in checks:
        # Search both files rather than guessing which holds the pattern; a
        # pattern that vanishes from both is exactly the drift we want to catch.
        if not re.search(pat, taint, re.M) and not re.search(pat, sast, re.M):
            problems.append(label)
    return problems


def _load_base():
    name = "_sast_corpus_base"
    spec = importlib.util.spec_from_file_location(name, BASE_PATH)
    mod = importlib.util.module_from_spec(spec)
    # Must be registered before exec_module: @dataclass resolves annotations
    # via sys.modules[cls.__module__], which returns None otherwise (3.14).
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------
def prf(tp: int, fp: int, fn: int) -> dict:
    p = (tp / (tp + fp)) if (tp + fp) else None
    r = (tp / (tp + fn)) if (tp + fn) else None
    if p is None or r is None:
        f1 = None
    elif p + r == 0:
        f1 = 0.0
    else:
        f1 = 2 * p * r / (p + r)
    return {
        "tp": tp, "fp": fp, "fn": fn,
        "precision": round(p, 4) if p is not None else None,
        "recall": round(r, 4) if r is not None else None,
        "f1": round(f1, 4) if f1 is not None else None,
    }


def stratify(base, result: dict) -> dict:
    gt_by_id = {g.id: g for g in base.GROUND_TRUTH}

    buckets: dict[str, Counter] = {}
    gt_total: Counter = Counter()
    gt_neg: Counter = Counter()

    for g in base.GROUND_TRUTH:
        lang = language_of(g.file)
        if g.vulnerable:
            gt_total[lang] += 1
        else:
            gt_neg[lang] += 1

    for m in result["matches"]:
        status = m["status"]
        if m["ground_truth_id"] in gt_by_id:
            lang = language_of(gt_by_id[m["ground_truth_id"]].file)
        else:
            matched = m.get("matched_finding") or {}
            lang = language_of(matched.get("file"))
        c = buckets.setdefault(lang, Counter())
        if status == "TRUE_POSITIVE":
            c["tp"] += 1
        elif status == "FALSE_NEGATIVE":
            c["fn"] += 1
        elif status == "TRUE_NEGATIVE":
            c["tn"] += 1
        elif status == "FALSE_POSITIVE":
            c["fp"] += 1

    out = {}
    for lang in sorted(set(gt_total) | set(gt_neg) | set(buckets)):
        c = buckets.get(lang, Counter())
        n = gt_total.get(lang, 0)
        row = prf(c["tp"], c["fp"], c["fn"])
        row.update({
            "technique": TECHNIQUE.get(lang, "unknown"),
            "ground_truth_vulnerable": n,
            "ground_truth_negative_controls": gt_neg.get(lang, 0),
            "true_negatives": c["tn"],
            # Smallest recall step this corpus can express: one miss.
            "min_detectable_delta": round(1 / n, 4) if n else None,
        })
        out[lang] = row

    # Fold languages into technique groups.
    groups: dict[str, dict] = {}
    for lang, row in out.items():
        key = row["technique"]
        g = groups.setdefault(key, Counter())
        g["tp"] += row["tp"]; g["fp"] += row["fp"]; g["fn"] += row["fn"]
        g["tn"] += row["true_negatives"]
        g["n"] += row["ground_truth_vulnerable"]
        g["langs"] += 1
    grouped = {}
    for key, c in groups.items():
        row = prf(c["tp"], c["fp"], c["fn"])
        row.update({"languages": c["langs"], "ground_truth_vulnerable": c["n"],
                    "true_negatives": c["tn"]})
        grouped[key] = row
    return out, grouped


def main() -> int:
    ap = argparse.ArgumentParser(description="Language-granularity benchmark (G-059)")
    ap.add_argument("--fixture", default=None, help="corpus directory to scan")
    ap.add_argument("--baseline", default=None,
                    help="existing clean_report.json to stratify instead of scanning")
    ap.add_argument("--out", default=str(REPO / "reports" /
                                         "benchmark_reconciliation_language_granularity"))
    args = ap.parse_args()

    dispatch_problems = verify_dispatch()
    problems = list(dispatch_problems)

    base = _load_base()

    if args.baseline:
        findings = base.load_findings(Path(args.baseline))
    else:
        fixture = Path(args.fixture) if args.fixture else base.DEFAULT_FIXTURE
        if not fixture.exists():
            raise SystemExit(f"fixture not found: {fixture}")
        out_dir = REPO / "reports" / "_lang_granularity_scan"
        findings = base.run_scan(fixture, out_dir)

    result = base.reconcile(findings)
    by_lang, by_tech = stratify(base, result)

    # The stratification must reconcile with the class-A number.
    parts = Counter()
    for row in by_lang.values():
        parts["tp"] += row["tp"]; parts["fp"] += row["fp"]
        parts["fn"] += row["fn"]; parts["tn"] += row["true_negatives"]
    reconciles = (parts["tp"] == result["true_positives"]
                  and parts["fp"] == result["false_positives"]
                  and parts["fn"] == result["false_negatives"]
                  and parts["tn"] == result["true_negatives"])
    if not reconciles:
        problems.append("stratified counts do not reconcile with the class-A benchmark")

    expected_langs = {language_of(g.file) for g in base.GROUND_TRUTH}
    measured = set(by_lang) & expected_langs
    all_measured = expected_langs <= set(by_lang)
    if not all_measured:
        problems.append(f"languages with ground truth but no row: "
                        f"{sorted(expected_langs - set(by_lang))}")

    # Adequacy: can this corpus express a granularity difference at all?
    max_n = max((r["ground_truth_vulnerable"] for r in by_lang.values()), default=0)
    DETECTABLE_N = 10
    corpus_adequate = max_n >= DETECTABLE_N

    verdict = {
        "v1_dispatch_labels_match_source": not dispatch_problems,
        "v2_stratification_reconciles_with_class_a": reconciles,
        "v3_every_language_with_truth_is_measured": all_measured,
        "v4_corpus_detects_granularity_delta": corpus_adequate,
    }

    payload = {
        "benchmark": "language-granularity-2026-10",
        "root_causes": ["G-059"],
        "corpus": base.BENCHMARK_ID,
        "corpus_languages": base.BENCHMARK_LANGUAGES,
        "ground_truth_source": "analysis/benchmark_sast_corpus.GROUND_TRUTH "
                               "(authored independently of the scanner)",
        "ground_truth_authored_before_scan": True,
        "class_a_reconciliation": {
            "true_positives": result["true_positives"],
            "false_positives": result["false_positives"],
            "false_negatives": result["false_negatives"],
            "true_negatives": result["true_negatives"],
            "precision": result["precision"], "recall": result["recall"],
            "f1": result["f1"],
        },
        "by_language": by_lang,
        "by_technique": by_tech,
        "detectability": {
            "largest_per_language_ground_truth": max_n,
            "needed_to_attribute_a_delta": DETECTABLE_N,
            "smallest_recognisable_step_per_language": {
                k: v["min_detectable_delta"] for k, v in by_lang.items()},
            "note": "A language with N=1 can only score 0.0 or 1.0, so a "
                    "per-language F1 of 1.0 on this corpus does not show that "
                    "the regex path is as good as an AST - it shows the corpus "
                    "cannot tell the difference.",
        },
        "verdict": verdict,
        "problems": problems,
        "honest_limitation": (
            "This measures outcomes, not mechanisms. It splits the class-A "
            "number by language and labels each language with the technique "
            "its dispatch uses, verified against source at runtime. It cannot "
            "isolate granularity as the cause of any difference, because no "
            "difference is detectable at these denominators."
        ),
    }

    out_json = args.out if args.out.endswith(".json") else args.out + ".json"
    out_md = out_json[:-5] + ".md"
    Path(out_json).parent.mkdir(parents=True, exist_ok=True)
    Path(out_json).write_text(json.dumps(payload, indent=2, ensure_ascii=False),
                              encoding="utf-8")

    def pct(v):
        return "n/a" if v is None else f"{v * 100:.1f}%"

    lines = [
        "# Language-granularity benchmark", "",
        f"Root cause: {', '.join(payload['root_causes'])}", "",
        f"Corpus: `{payload['corpus']}`  ",
        f"Ground truth: {payload['ground_truth_source']}, "
        f"authored before the scan.", "",
        "## Per language", "",
        "| language | technique | GT vulns | neg ctrl | TP | FP | FN | TN "
        "| precision | recall | F1 | smallest recall step |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for lang, r in by_lang.items():
        lines.append(
            f"| {lang} | {r['technique']} | {r['ground_truth_vulnerable']} "
            f"| {r['ground_truth_negative_controls']} | {r['tp']} | {r['fp']} "
            f"| {r['fn']} | {r['true_negatives']} | {pct(r['precision'])} "
            f"| {pct(r['recall'])} | {pct(r['f1'])} "
            f"| {r['min_detectable_delta']} |")

    lines += ["", "## By detection technique", "",
              "| technique | languages | GT vulns | TP | FP | FN | precision "
              "| recall | F1 |", "|---|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for tech, r in sorted(by_tech.items()):
        lines.append(
            f"| {tech} | {r['languages']} | {r['ground_truth_vulnerable']} "
            f"| {r['tp']} | {r['fp']} | {r['fn']} | {pct(r['precision'])} "
            f"| {pct(r['recall'])} | {pct(r['f1'])} |")

    ca = payload["class_a_reconciliation"]
    lines += [
        "", "## Reconciliation with the class-A benchmark", "",
        f"TP/FP/FN/TN = {ca['true_positives']}/{ca['false_positives']}/"
        f"{ca['false_negatives']}/{ca['true_negatives']}, "
        f"P={pct(ca['precision'])} R={pct(ca['recall'])} F1={pct(ca['f1'])} "
        f"- identical by construction: the stratification only regroups the "
        f"same `reconcile()` output.", "",
        "## Detectability", "",
        f"Largest per-language ground truth: **{max_n}**; needed to attribute "
        f"a granularity delta: **{DETECTABLE_N}**.", "",
        payload["detectability"]["note"], "",
        "## Honest limitation", "", payload["honest_limitation"], "",
        "## Verdict", "",
    ]
    for k, v in verdict.items():
        lines.append(f"- {k}: {'PASS' if v else 'FAIL'}")
    if problems:
        lines += ["", "## Problems", ""] + [f"- {p}" for p in problems]
    lines.append("")
    Path(out_md).write_text("\n".join(lines), encoding="utf-8")

    print(f"wrote {out_json}")
    print(f"wrote {out_md}")
    print(f"  class-A TP/FP/FN/TN = {ca['true_positives']}/{ca['false_positives']}"
          f"/{ca['false_negatives']}/{ca['true_negatives']}")
    for lang, r in by_lang.items():
        print(f"  {lang:<11} {r['technique']:<34} N={r['ground_truth_vulnerable']} "
              f"P={r['precision']} R={r['recall']} F1={r['f1']}")
    for k, v in verdict.items():
        print(f"  {k}: {'PASS' if v else 'FAIL'}")
    for p in problems:
        print(f"  problem: {p}")
    return 0 if all(verdict.values()) and not problems else 1


if __name__ == "__main__":
    sys.exit(main())
