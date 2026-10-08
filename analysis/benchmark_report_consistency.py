"""Report-consistency benchmark: does every number in the report describe
the population the report actually contains?

Run twice against the same corpus - once before and once after the
serialization-boundary fixes tracked as G-047 / G-048 / G-049 - so the
result is a trend rather than a single reading.

Four properties are checked, all computable from `clean_report.json` alone:

  P1 OWASP aggregate integrity   sum(owasp[*].count) must equal len(findings),
                                 and must equal framework_mapping_summary's
                                 own by_owasp total. Before the fix these two
                                 disagreed with each other and with findings.
  P2 Insight parity              every count-bearing insight line must state
                                 a number that matches the final findings.
  P3 Coverage preservation       a scoping change that removes findings must
                                 not remove ground-truth matches.
  P4 Finding scope               how much of the report sits in files that
                                 cannot contain what the rule asserts.

Console figures are parsed from a scan transcript when one is supplied with
`--console-log`; they are reported separately from the artifact-derived ones
because console staleness was the defect itself and cannot be recovered from
the written file.

Usage:
    python analysis/benchmark_report_consistency.py \
        --before <old_clean_report.json> --after <new_clean_report.json> \
        [--console-log <scan.log>] \
        [--out reports/benchmark_reconciliation_report_consistency]
"""
from __future__ import annotations

import argparse
import io
import json
import os
import re
import sys
from collections import Counter

INSIGHT_PATTERNS = [
    ("ssrf", re.compile(r"^SSRF RISK: (\d+) "), "ssrf"),
    ("deserialization", re.compile(r"^DESERIALIZATION: (\d+) "), "insecure_deserialization"),
    ("secret", re.compile(r"^SECRET EXPOSURE: (\d+) "), "hardcoded_secret"),
    ("injection", re.compile(r"^INJECTION CLUSTER: (\d+) "),
     ("sql_injection", "command_injection", "code_injection", "xss")),
]

WITHHELD_PATH = re.compile(r"/(?:i18n|locale|locales|translations|l10n)/|"
                           r"/(?:data|datasets|seeds|fixtures)/(?:static|seed|seeds|fixture|fixtures)/",
                           re.I)


def _findings(report: dict) -> list[dict]:
    return [f for f in (report.get("findings") or []) if isinstance(f, dict)]


def _owasp_total(report: dict) -> int:
    return sum(int(v.get("count") or 0) for v in (report.get("owasp") or {}).values()
               if isinstance(v, dict))


def _framework_total(report: dict) -> int:
    by = ((report.get("framework_mapping_summary") or {}).get("by_owasp")) or {}
    return sum(int(v or 0) for v in by.values())


def _actual_counts(findings: list[dict]) -> dict:
    """Counts keyed by the *insight* name so claims and reality line up.

    The report's `vuln_type` vocabulary and the insight-line vocabulary differ
    (insight says "DESERIALIZATION" / "SECRET EXPOSURE", findings say
    "insecure_deserialization" / "hardcoded_secret"), so the mapping is made
    here rather than by string-matching the insight text.
    """
    injection = {"sql_injection", "command_injection", "code_injection", "xss"}
    return {
        "ssrf": sum(1 for f in findings if f.get("vuln_type") == "ssrf"),
        "deserialization": sum(1 for f in findings
                               if f.get("vuln_type") == "insecure_deserialization"),
        "secret": sum(1 for f in findings if f.get("vuln_type") == "hardcoded_secret"),
        "injection": sum(1 for f in findings if f.get("vuln_type") in injection),
        "findings": len(findings),
    }


def _insight_claims(report: dict) -> dict:
    claims = {}
    for line in report.get("insights") or []:
        if not isinstance(line, str):
            continue
        for name, pattern, _ in INSIGHT_PATTERNS:
            m = pattern.search(line)
            if m:
                claims[name] = int(m.group(1))
    return claims


def _inventory_total(target: str | None) -> int | None:
    """Count declared challenges straight from the ground-truth inventory.

    The inventory is the ground truth object, not something either report
    produced, so it is the only fair denominator for comparing two runs.
    """
    if not target:
        return None
    path = os.path.join(target, "data", "static", "challenges.yml")
    if not os.path.exists(path):
        return None
    text = io.open(path, encoding="utf-8", errors="replace").read()
    try:
        import yaml
        data = yaml.safe_load(text)
        if isinstance(data, (list, dict)):
            return len(data)
    except Exception:
        pass
    return len(re.findall(r"^\s*-\s+key\s*:", text, re.M)) or None


def _coverage(report: dict, total: int | None) -> dict:
    """Derive coverage from the findings themselves.

    The pre-fix report carries no coverage fields at all (that is G-049), so
    comparing `challenges_covered_count` would be comparing a number against
    nothing. Deriving both sides from
    `findings[].benchmark_ground_truth.challenge_key` puts the two runs on the
    same basis regardless of which code version wrote the file. Matching logic
    was untouched by G-049, which only added the reverse index.
    """
    covered: set[str] = set()
    declared = 0
    for f in _findings(report):
        gt = f.get("benchmark_ground_truth") or {}
        if gt.get("status") != "DECLARED_INTENTIONAL":
            continue
        declared += 1
        key = gt.get("challenge_key")
        if key:
            covered.add(key)
    self_reported = ((report.get("metadata") or {}).get("benchmark_ground_truth")) or {}
    return {
        "challenges_total": total,
        "challenges_covered_count": len(covered),
        "challenges_covered": sorted(covered),
        "declared_intentional_findings": declared,
        "challenge_recall_derived": (round(len(covered) / total, 4) if total else None),
        "report_wrote_coverage_fields": "challenges_covered_count" in self_reported,
        "report_challenge_recall": self_reported.get("challenge_recall"),
    }


def _scope(findings: list[dict]) -> dict:
    withheld = [f for f in findings
                if WITHHELD_PATH.search(str(f.get("file") or "").replace("\\", "/"))]
    by_ext = Counter(os.path.splitext(str(f.get("file") or ""))[1] for f in findings)
    return {
        "findings": len(findings),
        "in_withheld_paths": len(withheld),
        "withheld_path_rules": dict(Counter(str(f.get("rule_id")) for f in withheld)),
        "severity": dict(Counter(str(f.get("severity")) for f in findings)),
        "top_extensions": dict(by_ext.most_common(8)),
    }


def _severity_insight_parity(report: dict, metadata: dict) -> dict:
    """Do the severity-bearing insight sentences match the severity table?

    ``metadata.severity_distribution`` is the population the console severity
    table prints (SAST findings plus unique vulnerable dependency packages).
    ``generate_insights()`` counts the SAST-only population instead, so on
    Juice Shop the ``HIGH RISK`` sentence read 2 while the table directly
    beneath it read High 4. ``COMPLIANCE RISK`` was worse: clean_report.json
    and the console said 2 while ``Security_Report.pdf`` said 5, because only
    the PDF and Excel ran ``normalize_report_insights()``.

    Both numbers are re-read from the artifact rather than recomputed, so this
    works on any corpus and on reports written before the fix.
    """
    dist = metadata.get("severity_distribution") or {}
    high = int(dist.get("High") or 0)
    critical = int(dist.get("Critical") or 0)
    out: dict = {}
    for line in report.get("insights") or []:
        if not isinstance(line, str):
            continue
        m = re.match(r"^HIGH RISK:\s*(\d+)\s+high-severity", line)
        if m and "high_risk" not in out:
            claimed = int(m.group(1))
            out["high_risk"] = {"claimed": claimed, "expected": high,
                                "match": claimed == high}
        m = re.match(r"^COMPLIANCE RISK:\s*(\d+)\s+Critical/High findings", line)
        if m and "compliance_risk" not in out:
            claimed = int(m.group(1))
            out["compliance_risk"] = {"claimed": claimed, "expected": critical + high,
                                      "match": claimed == critical + high}
    return out


def measure(report: dict, inventory_total: int | None = None) -> dict:
    findings = _findings(report)
    actual = _actual_counts(findings)
    claims = _insight_claims(report)
    owasp_total = _owasp_total(report)
    framework_total = _framework_total(report)
    metadata = report.get("metadata") or {}

    insight_parity = {}
    for name, _, _ in INSIGHT_PATTERNS:
        if name in claims:
            insight_parity[name] = {
                "claimed": claims[name],
                "actual": actual.get(name),
                "match": claims[name] == actual.get(name),
            }

    mitre_ids = [m.get("id") for m in (report.get("mitre") or []) if isinstance(m, dict)]
    on_findings = set()
    for f in findings:
        v = f.get("mitre") or f.get("mitre_attack")
        for t in (v if isinstance(v, list) else [v]):
            t = str(t or "").strip()
            if t:
                on_findings.add(t)

    severity_parity = _severity_insight_parity(report, metadata)

    return {
        "findings": len(findings),
        "metadata_total_findings": metadata.get("total_findings"),
        "metadata_sast_findings": metadata.get("sast_findings"),
        "severity_distribution": metadata.get("severity_distribution"),
        "severity_sum": sum(int(v or 0) for v in (metadata.get("severity_distribution") or {}).values()),
        "risk_score": metadata.get("risk_score"),
        "owasp_total": owasp_total,
        "owasp_delta_vs_findings": owasp_total - len(findings),
        "framework_owasp_total": framework_total,
        "framework_delta_vs_findings": framework_total - len(findings),
        "cross_aggregate_delta": owasp_total - framework_total,
        "mitre_techniques": mitre_ids,
        "mitre_techniques_absent_from_findings": [t for t in mitre_ids if t not in on_findings],
        "insight_claims": claims,
        "insight_parity": insight_parity,
        "insight_parity_all_match": all(v["match"] for v in insight_parity.values()),
        "severity_parity": severity_parity,
        "severity_parity_all_match": all(v["match"] for v in severity_parity.values()),
        "ground_truth": _coverage(report, inventory_total),
        "scope": _scope(findings),
        "config_credential_findings": sum(
            1 for f in findings if f.get("rule_id") == "CONFIG_CONTEXTUAL_CREDENTIAL"),
    }


def console_figures(path: str | None) -> dict | None:
    if not path or not os.path.exists(path):
        return None
    raw = open(path, "rb").read()
    # Tee-Object and PowerShell redirection disagree about encoding, so try the
    # plausible ones and prefer whichever actually contains scan output.
    text = None
    for enc in ("utf-8-sig", "utf-16", "utf-8", "cp1252"):
        try:
            candidate = raw.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
        if text is None:
            text = candidate
        if "unique findings" in candidate or "Ground truth coverage" in candidate:
            text = candidate
            break
    text = text or raw.decode("utf-8", errors="replace")
    out: dict = {}
    m = re.search(r"=> (\d+) unique findings \| Risk: ([\d.]+)/100 \| Attack Paths: (\d+)", text)
    if m:
        out["unique_findings"] = int(m.group(1))
        out["risk_score"] = float(m.group(2))
        out["attack_paths"] = int(m.group(3))
    rows = dict(re.findall(r"\| \[(?:CRIT|HIGH|MED|LOW|INFO)\]\s+(\w+)\s+(\d+)", text))
    if rows:
        out["severity"] = {k: int(v) for k, v in rows.items()}
        out["severity_sum"] = sum(out["severity"].values())
    m = re.search(r"=> Ground truth coverage: (\d+)/(\d+) challenges mapped \| recall ([\d.]+)", text)
    if m:
        out["ground_truth_coverage"] = {
            "covered": int(m.group(1)), "total": int(m.group(2)), "recall": float(m.group(3))}
    return out or None


def _consistency(m: dict) -> dict:
    return {
        "owasp_matches_findings": m["owasp_delta_vs_findings"] == 0,
        "framework_matches_findings": m["framework_delta_vs_findings"] == 0,
        "aggregates_agree_with_each_other": m["cross_aggregate_delta"] == 0,
        "severity_sum_matches_total": m["severity_sum"] == m["metadata_total_findings"],
        "insights_match_findings": m["insight_parity_all_match"],
        "no_stale_mitre_technique": not m["mitre_techniques_absent_from_findings"],
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--before", required=True)
    ap.add_argument("--after", required=True)
    ap.add_argument("--target",
                    help="Juice Shop root; data/static/challenges.yml is read from here as the "
                         "denominator, independent of either report")
    ap.add_argument("--console-log-before")
    ap.add_argument("--console-log-after")
    ap.add_argument("--out", default=r"reports\benchmark_reconciliation_report_consistency")
    args = ap.parse_args()

    inventory_total = _inventory_total(args.target)
    before = measure(json.load(io.open(args.before, encoding="utf-8")), inventory_total)
    after = measure(json.load(io.open(args.after, encoding="utf-8")), inventory_total)
    before_consistency = _consistency(before)
    after_consistency = _consistency(after)

    b_gt, a_gt = before["ground_truth"], after["ground_truth"]
    coverage_preserved = (
        b_gt["challenges_covered"] == a_gt["challenges_covered"]
        and b_gt["declared_intentional_findings"] == a_gt["declared_intentional_findings"]
        and b_gt["challenges_total"] == a_gt["challenges_total"]
    )

    findings_removed = before["findings"] - after["findings"]
    removed_all_config = (
        before["config_credential_findings"] - after["config_credential_findings"] == findings_removed
    )

    payload = {
        "benchmark": "report-consistency-2026-10",
        "root_causes": ["G-047", "G-048", "G-049", "G-053"],
        "corpus": "OWASP Juice Shop (data/static/challenges.yml, 116 declared challenges)",
        "before_report": os.path.abspath(args.before),
        "after_report": os.path.abspath(args.after),
        "properties": {
            "P1_owasp_aggregate_integrity": {
                "before": before_consistency, "after": after_consistency,
                "owasp_delta": [before["owasp_delta_vs_findings"], after["owasp_delta_vs_findings"]],
                "cross_aggregate_delta": [before["cross_aggregate_delta"], after["cross_aggregate_delta"]],
            },
            "P2_insight_parity": {
                "before": before["insight_parity"], "after": after["insight_parity"],
                "all_match_before": before["insight_parity_all_match"],
                "all_match_after": after["insight_parity_all_match"],
            },
            "P3_coverage_preservation": {
                "preserved": coverage_preserved,
                "derivation": "Both sides are derived from "
                              "findings[].benchmark_ground_truth.challenge_key, because the "
                              "pre-fix report has no coverage fields (that is G-049) and the "
                              "denominator comes from data/static/challenges.yml.",
                "before": {k: b_gt.get(k) for k in ("challenges_total", "challenges_covered_count",
                                                    "challenge_recall_derived",
                                                    "declared_intentional_findings",
                                                    "report_wrote_coverage_fields")},
                "after": {k: a_gt.get(k) for k in ("challenges_total", "challenges_covered_count",
                                                   "challenge_recall_derived",
                                                   "declared_intentional_findings",
                                                   "report_wrote_coverage_fields")},
                "covered_set_before": b_gt["challenges_covered"],
                "covered_set_after": a_gt["challenges_covered"],
                "note": "A scoping change that removes findings but also removes ground-truth "
                        "matches is a regression, not a precision gain.",
            },
            "P4_finding_scope": {
                "semantics": "after <= before: withholding must never introduce a finding into "
                             "one of those paths, and a corpus that has none of them passes "
                             "trivially. A strict improvement would fail on such a corpus for "
                             "no reason.",
                "before": before["scope"], "after": after["scope"],
                "findings_removed": findings_removed,
                "all_removed_were_config_credentials": removed_all_config,
                "config_credential_findings": [before["config_credential_findings"],
                                               after["config_credential_findings"]],
            },
        },
        "console": {
            "before": console_figures(args.console_log_before),
            "after": console_figures(args.console_log_after),
            "note": "Console figures are parsed from a transcript when supplied. They are not "
                    "recoverable from the written artifact, which is why the stale-console defect "
                    "had to be pinned by a source-ordering test.",
        },
        "verdict": {
            "p1": after_consistency["owasp_matches_findings"] and after_consistency["aggregates_agree_with_each_other"],
            "p2": after["insight_parity_all_match"],
            "p3": coverage_preserved,
            "p4": after["scope"]["in_withheld_paths"] <= before["scope"]["in_withheld_paths"],
            "p5": after["severity_parity_all_match"],
        },
    }

    out_json = args.out if args.out.endswith(".json") else args.out + ".json"
    out_md = out_json[:-5] + ".md"
    os.makedirs(os.path.dirname(os.path.abspath(out_json)) or ".", exist_ok=True)
    json.dump(payload, io.open(out_json, "w", encoding="utf-8"), ensure_ascii=False, indent=2)

    lines = ["# Report-consistency benchmark", "",
             f"Corpus: {payload['corpus']}", "",
             "Root causes: " + ", ".join(payload["root_causes"]), "",
             "| property | before | after |", "|---|---|---|"]
    rows = [
        ("findings", before["findings"], after["findings"]),
        ("owasp total", before["owasp_total"], after["owasp_total"]),
        ("owasp - findings delta", before["owasp_delta_vs_findings"], after["owasp_delta_vs_findings"]),
        ("cross-aggregate delta", before["cross_aggregate_delta"], after["cross_aggregate_delta"]),
        ("insight parity", before["insight_parity_all_match"], after["insight_parity_all_match"]),
        ("severity insight parity (P5)", before["severity_parity_all_match"],
         after["severity_parity_all_match"]),
        ("stale MITRE techniques", len(before["mitre_techniques_absent_from_findings"]),
         len(after["mitre_techniques_absent_from_findings"])),
        ("findings in withheld paths", before["scope"]["in_withheld_paths"],
         after["scope"]["in_withheld_paths"]),
        ("CONFIG_CONTEXTUAL_CREDENTIAL", before["config_credential_findings"],
         after["config_credential_findings"]),
        ("challenges covered", b_gt.get("challenges_covered_count"), a_gt.get("challenges_covered_count")),
        ("declared-intentional findings", b_gt.get("declared_intentional_findings"),
         a_gt.get("declared_intentional_findings")),
        ("challenge recall", b_gt.get("challenge_recall_derived"),
         a_gt.get("challenge_recall_derived")),
    ]
    for name, b, a in rows:
        lines.append(f"| {name} | {b} | {a} |")

    lines += ["", "## Insight parity (claimed vs actual)", "",
              "| insight | claimed before | claimed after | actual |", "|---|---|---|---|"]
    for name in INSIGHT_PATTERNS:
        key = name[0]
        b = (before["insight_parity"] or {}).get(key, {})
        a = (after["insight_parity"] or {}).get(key, {})
        lines.append(f"| {key} | {b.get('claimed', '-')} | {a.get('claimed', '-')} "
                     f"| {a.get('actual', '-')} |")

    lines += ["", "## Severity insight vs severity table (P5)", "",
              "The severity table and `metadata.severity_distribution` both count SAST "
              "findings plus unique vulnerable dependency packages; the insight sentences "
              "were produced from the SAST-only population and, for the console and "
              "clean_report.json, were never normalised.", "",
              "| sentence | claimed before | expected before | claimed after | expected after |",
              "|---|---|---|---|---|"]
    for key in ("high_risk", "compliance_risk"):
        b = (before["severity_parity"] or {}).get(key, {})
        a = (after["severity_parity"] or {}).get(key, {})
        lines.append(f"| {key} | {b.get('claimed', '-')} | {b.get('expected', '-')} "
                     f"| {a.get('claimed', '-')} | {a.get('expected', '-')} |")

    lines += ["", "## Verdict", ""]
    for k, v in payload["verdict"].items():
        lines.append(f"- {k}: {'PASS' if v else 'FAIL'}")
    lines += ["", f"Preservation gate (P3): "
                  f"{'PASS - no ground-truth match lost' if coverage_preserved else 'FAIL'}", ""]
    io.open(out_md, "w", encoding="utf-8").write("\n".join(lines))

    print(f"wrote {out_json}")
    print(f"wrote {out_md}")
    for k, v in payload["verdict"].items():
        print(f"  {k}: {'PASS' if v else 'FAIL'}")
    return 0 if all(payload["verdict"].values()) else 1


if __name__ == "__main__":
    sys.exit(main())
