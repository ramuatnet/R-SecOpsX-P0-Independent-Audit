"""Report triage: classify every finding in a clean_report.json as
Likely-FP / Likely-Real / Needs-Review, WITHOUT needing the source tree.

Usage:
    python analysis/validation/triage_report.py <clean_report.json> [--out <dir>]
"""
from __future__ import annotations
import argparse, json, os, re, sys
from collections import Counter, defaultdict
from pathlib import Path

FP_TESTED = {
    "CONFIG_CONTEXTUAL_CREDENTIAL", "MISSING_RATE_LIMIT_ENDPOINT",
    "TAINT_MULTIPART_TRAVERSAL", "JAVA_PATH_TRAVERSAL_FILE",
    "GENERIC_API_KEY_PASSWORD", "TAINT_PROTOTYPE_POLLUTION",
    "TAINT_SSRF_EXPANDED", "LLM06_SENSITIVE_INFORMATION_DISCLOSURE",
}

UNTESTED = {
    "SPRING_MISSING_VALIDATION", "TAINT_SPRING_QUERY_INJECTION",
    "JAVA_XXE_PARSER", "JAVA_REFLECTION_SETACCESSIBLE",
    "JAVA_HQL_JPQL_INJECTION", "JAVA_J3_PATH_TRAVERSAL",
    "JAVA_J3_SQL_INJECTION", "JAVA_J4_PATH", "JAVA_J4_LDAP",
    "JAVA_JDBC_SQL_CONCAT", "JAVA_JNDI_LOG4SHELL_LOOKUP",
    "JAVA_J2_WEAK_RANDOM", "GENERIC_ZIPSLIP", "API_LOGIN_BRUTE_FORCE",
}

SNIPPET_FP_PATTERNS = [
    (re.compile(r"Random\s+rand\s*=\s*new\s+Random\(\)", re.I),
     "JAVA_J2_WEAK_RANDOM",
     "Random() in utility code - not crypto"),
    (re.compile(r"\.setAccessible\(true\)", re.I),
     "JAVA_REFLECTION_SETACCESSIBLE",
     "setAccessible in framework code - often required"),
    (re.compile(r"fileName\s*->\s*File\(", re.I),
     "TAINT_MULTIPART_TRAVERSAL",
     "Multipart filename handling - usually sanitized"),
]


def score_finding(f):
    score = 0
    reasons = []
    rid = f.get("rule_id", "")

    if rid in FP_TESTED:
        score += 50
        reasons.append("rule has documented FP family")
    if rid in UNTESTED:
        score += 20
        reasons.append("rule has no FP test coverage")
    detection = (f.get("detection") or "").lower()
    if "heuristic" in detection:
        score += 15
        reasons.append("classified as heuristic")
    if not f.get("source") and not f.get("sink") and not f.get("data_flow"):
        score += 10
        reasons.append("no source/sink/data_flow recorded")
    tp = f.get("taint_path")
    if tp and len(str(tp)) < 30:
        score += 10
        reasons.append("shallow taint_path")
    if f.get("confidence") == "LOW":
        score += 10
        reasons.append("LOW confidence")
    snippet = f.get("snippet") or ""
    for pat, rule_family, reason in SNIPPET_FP_PATTERNS:
        if rule_family == rid and pat.search(snippet):
            score += 15
            reasons.append("snippet matches known FP: " + reason)
            break
    if f.get("evidence_valid") is False:
        score += 20
        reasons.append("scanner marked evidence_valid=False")

    return min(score, 100), reasons


def categorize(score):
    if score >= 50:
        return "LIKELY_FP"
    if score >= 25:
        return "NEEDS_REVIEW"
    return "LIKELY_REAL"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("report_pos", nargs="?", default=None,
                    help="path to clean_report.json")
    ap.add_argument("--report", dest="report_opt", default=None,
                    help="path to clean_report.json (alias, used by the "
                         "validation CLI)")
    ap.add_argument("--out", default=None, help="output directory")
    args = ap.parse_args(argv)

    report_path = args.report_opt or args.report_pos
    if not report_path:
        ap.error("a clean_report.json path is required")

    report = json.load(open(report_path, encoding="utf-8"))
    findings = report["findings"]
    meta = report.get("metadata", {})

    scored = []
    for f in findings:
        score, reasons = score_finding(f)
        scored.append({
            "rule_id": f.get("rule_id"),
            "file": f.get("file"),
            "line": f.get("line"),
            "severity": f.get("severity"),
            "confidence": f.get("confidence"),
            "snippet": f.get("snippet"),
            "fp_score": score,
            "category": categorize(score),
            "reasons": reasons,
        })

    cats = Counter(s["category"] for s in scored)
    by_rule = defaultdict(lambda: {"total": 0, "fp": 0, "review": 0, "real": 0})
    for s in scored:
        r = by_rule[s["rule_id"]]
        r["total"] += 1
        key = s["category"].lower().replace("likely_", "")
        if key == "needs_review":
            key = "review"
        r[key] += 1

    out_dir = Path(args.out) if args.out else Path(report_path).parent / "_triage"
    out_dir.mkdir(parents=True, exist_ok=True)

    triage_json = {
        "source_report": str(Path(report_path).resolve()),
        "total_findings": len(findings),
        "risk_score": meta.get("risk_score"),
        "summary": {
            "LIKELY_FP": cats["LIKELY_FP"],
            "NEEDS_REVIEW": cats["NEEDS_REVIEW"],
            "LIKELY_REAL": cats["LIKELY_REAL"],
        },
        "by_rule": {k: dict(v) for k, v in sorted(by_rule.items())},
        "findings": scored,
    }
    json_path = out_dir / "triage_report.json"
    json_path.write_text(json.dumps(triage_json, indent=2), encoding="utf-8")

    md = []
    md.append("# Report Triage: %s\n" % Path(report_path).name)
    md.append("Total findings: **%d** | Risk score: %s\n" % (len(findings), meta.get("risk_score")))
    md.append("## Summary\n")
    md.append("| Category | Count | % |")
    md.append("|---|---|---|")
    for cat in ("LIKELY_FP", "NEEDS_REVIEW", "LIKELY_REAL"):
        c = cats[cat]
        md.append("| %s | %d | %.1f%% |" % (cat, c, 100 * c / len(findings)))
    md.append("")
    md.append("## By Rule\n")
    md.append("| Rule | Total | FP | Review | Real | FP% |")
    md.append("|---|---|---|---|---|---|")
    for rid, v in sorted(by_rule.items(), key=lambda x: -x[1]["total"]):
        fp_pct = 100 * v["fp"] / v["total"] if v["total"] else 0
        md.append("| %s | %d | %d | %d | %d | %.0f%% |" % (
            rid, v["total"], v["fp"], v["review"], v["real"], fp_pct))
    md.append("")
    md.append("## Top 20 Highest-FP-Score Findings\n")
    md.append("| Score | Rule | File | Line | Snippet |")
    md.append("|---|---|---|---|---|")
    for s in sorted(scored, key=lambda x: -x["fp_score"])[:20]:
        snip = (s["snippet"] or "")[:60].replace("|", "\\|")
        md.append("| %d | %s | %s | %s | %s |" % (
            s["fp_score"], s["rule_id"], s["file"], s["line"], snip))
    md.append("")
    md.append("## Files to Manually Review (highest FP concentration)\n")
    md.append("| File | Total | Likely FP | FP% |")
    md.append("|---|---|---|---|")
    by_file = defaultdict(lambda: {"total": 0, "fp": 0})
    for s in scored:
        f = by_file[s["file"]]
        f["total"] += 1
        if s["category"] == "LIKELY_FP":
            f["fp"] += 1
    top_files = sorted(by_file.items(), key=lambda x: -x[1]["fp"])[:15]
    for path, v in top_files:
        fp_pct = 100 * v["fp"] / v["total"] if v["total"] else 0
        md.append("| %s | %d | %d | %.0f%% |" % (path, v["total"], v["fp"], fp_pct))
    md.append("")
    md.append("## Next Steps\n")
    md.append("1. Re-scan with current version to collapse FP-tested findings")
    md.append("2. Manually review the top 15 files above")
    md.append("3. For each surviving FP, add a test to test_i_prodtest_report_fp_families.py")
    md.append("4. Fix the rule and re-scan")

    md_path = out_dir / "triage_report.md"
    md_path.write_text("\n".join(md), encoding="utf-8")

    print("=" * 70)
    print("TRIAGE SUMMARY: %s" % Path(report_path).name)
    print("=" * 70)
    print("Total findings: %d | Risk score: %s" % (len(findings), meta.get("risk_score")))
    print()
    for cat in ("LIKELY_FP", "NEEDS_REVIEW", "LIKELY_REAL"):
        c = cats[cat]
        print("  %-15s %5d  (%.1f%%)" % (cat, c, 100 * c / len(findings)))
    print()
    print("By rule (top 10):")
    for rid, v in sorted(by_rule.items(), key=lambda x: -x[1]["total"])[:10]:
        fp_pct = 100 * v["fp"] / v["total"] if v["total"] else 0
        print("  %-40s total=%4d  fp=%4d  (%.0f%%)" % (rid, v["total"], v["fp"], fp_pct))
    print()
    print("Files: %s" % out_dir)
    print("  triage_report.json  (full per-finding scores)")
    print("  triage_report.md    (human-readable summary)")
    return 0


if __name__ == "__main__":
    main()
