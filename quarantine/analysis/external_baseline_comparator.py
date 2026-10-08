"""
analysis/external_baseline_comparator.py

R-SecOpsX External Baseline Comparator.
Stdlib only. Compares Dependency-Track evidence with R-SecOpsX clean_report.json.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List


def _load_json(path: str | Path) -> Dict[str, Any]:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"JSON file not found: {p}")
    data = json.loads(p.read_text(encoding="utf-8-sig"))
    if not isinstance(data, dict):
        raise ValueError(f"Expected JSON object in {p}")
    return data


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return default if value is None else int(value)
    except Exception:
        return default


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return default if value is None else float(value)
    except Exception:
        return default


def _pct(numerator: int | float, denominator: int | float) -> float:
    if not denominator:
        return 0.0
    return round((float(numerator) / float(denominator)) * 100.0, 2)


def _dt_metrics(dt_summary: Dict[str, Any]) -> Dict[str, Any]:
    dt = dt_summary.get("dependency_track", {}) or {}
    metrics = dt.get("metrics", {}) or {}

    return {
        "component_count_reported": _safe_int(dt.get("component_count")),
        "components_metric": _safe_int(metrics.get("components")),
        "finding_count": _safe_int(dt.get("finding_count")),
        "findings_total": _safe_int(metrics.get("findingsTotal")),
        "vulnerabilities": _safe_int(metrics.get("vulnerabilities")),
        "vulnerable_components": _safe_int(metrics.get("vulnerableComponents")),
        "critical": _safe_int(metrics.get("critical")),
        "high": _safe_int(metrics.get("high")),
        "medium": _safe_int(metrics.get("medium")),
        "low": _safe_int(metrics.get("low")),
        "policy_violation_count": _safe_int(dt.get("policy_violation_count")),
        "policy_violations_total": _safe_int(metrics.get("policyViolationsTotal")),
        "inherited_risk_score": _safe_float(metrics.get("inheritedRiskScore")),
    }


def _rsecopsx_metrics(clean_report: Dict[str, Any], dt_summary: Dict[str, Any]) -> Dict[str, Any]:
    meta = clean_report.get("metadata")
    if not isinstance(meta, dict):
        meta = dt_summary.get("rsecopsx", {}) or {}

    return {
        "total_findings": _safe_int(meta.get("total_findings")),
        "sast_findings": _safe_int(meta.get("sast_findings")),
        "sca_findings": _safe_int(meta.get("sca_findings")),
        "sbom_packages": _safe_int(meta.get("sbom_packages")),
        "direct_packages": _safe_int(meta.get("direct_packages") or meta.get("direct_dependencies")),
        "transitive_packages": _safe_int(meta.get("transitive_packages") or meta.get("transitive_dependencies")),
        "vulnerable_packages": _safe_int(meta.get("vulnerable_packages")),
        "reachable_vulnerable_packages": _safe_int(meta.get("reachable_vulnerable_packages")),
        "not_observed_vulnerable_packages": _safe_int(meta.get("not_observed_vulnerable_packages")),
        "kev_packages": _safe_int(meta.get("kev_packages")),
        "known_epss_packages": _safe_int(meta.get("known_epss_packages")),
        "license_risks": _safe_int(meta.get("license_risks")),
        "risk_score": _safe_float(meta.get("risk_score")),
        "release_readiness_decision": str(meta.get("release_readiness_decision", "")),
        "executive_decision": str(meta.get("executive_decision", "")),
    }


def _capability_matrix(rx: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [
        {"capability": "SBOM/component inventory", "dependency_track": "Yes", "rsecopsx": "Yes", "interpretation": "Both tools provide component inventory."},
        {"capability": "License visibility", "dependency_track": "Yes", "rsecopsx": "Yes + policy signals", "interpretation": "R-SecOpsX adds license risk/policy counters."},
        {"capability": "Vulnerability enumeration", "dependency_track": "Feed-dependent", "rsecopsx": f"{rx['vulnerable_packages']} vulnerable packages", "interpretation": "Captured Dependency-Track evidence showed no vulnerability enrichment; R-SecOpsX produced vulnerability signals."},
        {"capability": "Reachability-aware prioritization", "dependency_track": "No", "rsecopsx": f"{rx['reachable_vulnerable_packages']} reachable vulnerable packages", "interpretation": "R-SecOpsX adds context-aware dependency prioritization."},
        {"capability": "KEV fusion", "dependency_track": "Not evidenced", "rsecopsx": f"{rx['kev_packages']} KEV packages", "interpretation": "R-SecOpsX integrates known-exploited vulnerability signal."},
        {"capability": "EPSS fusion", "dependency_track": "Not evidenced", "rsecopsx": f"{rx['known_epss_packages']} EPSS-enriched packages", "interpretation": "R-SecOpsX integrates exploit probability signal."},
        {"capability": "SAST/code-level findings", "dependency_track": "Out of scope", "rsecopsx": f"{rx['sast_findings']} SAST findings", "interpretation": "Do not compare directly; Dependency-Track baseline is SBOM/SCA-oriented."},
        {"capability": "Release decisioning", "dependency_track": "No", "rsecopsx": rx["release_readiness_decision"] or rx["executive_decision"], "interpretation": "R-SecOpsX converts analysis into release decision output."},
    ]


def build_external_baseline_comparison(dependency_track_summary: Dict[str, Any], rsecopsx_report: Dict[str, Any]) -> Dict[str, Any]:
    dt = _dt_metrics(dependency_track_summary)
    rx = _rsecopsx_metrics(rsecopsx_report, dependency_track_summary)

    dt_vuln_available = (
        dt["vulnerabilities"] > 0
        or dt["vulnerable_components"] > 0
        or dt["findings_total"] > 0
        or dt["finding_count"] > 0
    )

    status = (
        "INVENTORY_AND_VULNERABILITY_BASELINE_AVAILABLE"
        if dt_vuln_available
        else "INVENTORY_BASELINE_VALID_VULNERABILITY_FEED_NOT_EVIDENCED"
    )

    return {
        "schema": "RSECOPSX_EXTERNAL_BASELINE_COMPARISON_V1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "comparison_status": status,
        "dependency_track": dt,
        "rsecopsx": rx,
        "derived_metrics": {
            "inventory_delta_rsecopsx_minus_dependency_track": rx["sbom_packages"] - dt["components_metric"],
            "rsecopsx_inventory_as_percent_of_dependency_track": _pct(rx["sbom_packages"], dt["components_metric"]),
            "vulnerable_package_delta_rsecopsx_minus_dependency_track": rx["vulnerable_packages"] - dt["vulnerable_components"],
            "dependency_track_vulnerability_enrichment_observed": dt_vuln_available,
            "rsecopsx_reachable_vulnerable_rate": _pct(rx["reachable_vulnerable_packages"], rx["vulnerable_packages"]),
            "rsecopsx_kev_rate_over_vulnerable_packages": _pct(rx["kev_packages"], rx["vulnerable_packages"]),
            "rsecopsx_epss_enrichment_rate_over_vulnerable_packages": _pct(rx["known_epss_packages"], rx["vulnerable_packages"]),
        },
        "capability_matrix": _capability_matrix(rx),
        "paper_safe_interpretation": (
            "Dependency-Track successfully provided an external SBOM inventory baseline. "
            "In the captured baseline evidence, vulnerability enrichment was not observed; therefore, "
            "quantitative comparison should focus on inventory reconstruction and capability coverage, "
            "while R-SecOpsX demonstrates added contextual prioritization through reachability, KEV, EPSS, and release-decision signals."
            if not dt_vuln_available else
            "Dependency-Track provided an external SBOM/SCA baseline with vulnerability enrichment. "
            "R-SecOpsX can be compared as a contextual prioritization layer that adds reachability, KEV, EPSS, and release-decision signals."
        ),
        "do_not_claim": [
            "Do not claim Dependency-Track failed.",
            "Do not claim R-SecOpsX is universally better than Dependency-Track.",
            "Do not compare R-SecOpsX SAST findings against Dependency-Track because Dependency-Track is SBOM/SCA-oriented.",
            "Do not use Dependency-Track zero vulnerabilities as proof of weakness unless datasource/feed state is documented.",
        ],
    }


def _md_table(rows: List[Dict[str, Any]], columns: List[str]) -> str:
    lines = ["| " + " | ".join(columns) + " |", "| " + " | ".join(["---"] * len(columns)) + " |"]
    for row in rows:
        lines.append("| " + " | ".join(str(row.get(c, "")) for c in columns) + " |")
    return "\n".join(lines)


def write_markdown_report(comparison: Dict[str, Any], output_path: str | Path) -> None:
    dt = comparison["dependency_track"]
    rx = comparison["rsecopsx"]
    dm = comparison["derived_metrics"]

    metric_rows = [
        {"Metric": "Components / packages", "Dependency-Track": dt["components_metric"], "R-SecOpsX": rx["sbom_packages"]},
        {"Metric": "Vulnerable components / packages", "Dependency-Track": dt["vulnerable_components"], "R-SecOpsX": rx["vulnerable_packages"]},
        {"Metric": "Findings", "Dependency-Track": dt["findings_total"], "R-SecOpsX": rx["total_findings"]},
        {"Metric": "Reachable vulnerable packages", "Dependency-Track": "Not available", "R-SecOpsX": rx["reachable_vulnerable_packages"]},
        {"Metric": "KEV packages", "Dependency-Track": "Not evidenced", "R-SecOpsX": rx["kev_packages"]},
        {"Metric": "EPSS-enriched packages", "Dependency-Track": "Not evidenced", "R-SecOpsX": rx["known_epss_packages"]},
        {"Metric": "Risk score", "Dependency-Track": dt["inherited_risk_score"], "R-SecOpsX": rx["risk_score"]},
        {"Metric": "Release decision", "Dependency-Track": "Not available", "R-SecOpsX": rx["release_readiness_decision"] or rx["executive_decision"]},
    ]

    text = [
        "# External Baseline Comparison: Dependency-Track vs R-SecOpsX",
        "",
        f"Generated: {comparison['generated_at']}",
        "",
        f"Status: `{comparison['comparison_status']}`",
        "",
        "## Summary",
        "",
        comparison["paper_safe_interpretation"],
        "",
        "## Quantitative Snapshot",
        "",
        _md_table(metric_rows, ["Metric", "Dependency-Track", "R-SecOpsX"]),
        "",
        "## Derived Metrics",
        "",
        f"- R-SecOpsX inventory as percent of Dependency-Track inventory: {dm['rsecopsx_inventory_as_percent_of_dependency_track']}%",
        f"- Inventory delta: {dm['inventory_delta_rsecopsx_minus_dependency_track']}",
        f"- R-SecOpsX reachable vulnerable rate: {dm['rsecopsx_reachable_vulnerable_rate']}%",
        f"- R-SecOpsX KEV rate over vulnerable packages: {dm['rsecopsx_kev_rate_over_vulnerable_packages']}%",
        f"- R-SecOpsX EPSS enrichment rate over vulnerable packages: {dm['rsecopsx_epss_enrichment_rate_over_vulnerable_packages']}%",
        "",
        "## Capability Matrix",
        "",
        _md_table(comparison["capability_matrix"], ["capability", "dependency_track", "rsecopsx", "interpretation"]),
        "",
        "## Paper Safety Notes",
        "",
    ]
    text.extend([f"- {x}" for x in comparison["do_not_claim"]])
    Path(output_path).write_text("\n".join(text) + "\n", encoding="utf-8")


def run(dependency_track_summary_path: str | Path, rsecopsx_report_path: str | Path, output_dir: str | Path) -> Dict[str, Any]:
    dt_summary = _load_json(dependency_track_summary_path)
    rsecopsx_report = _load_json(rsecopsx_report_path)
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    comparison = build_external_baseline_comparison(dt_summary, rsecopsx_report)
    (out_dir / "external_baseline_comparison.json").write_text(json.dumps(comparison, indent=2, default=str), encoding="utf-8")
    write_markdown_report(comparison, out_dir / "External_Baseline_Comparison.md")
    return comparison


def main() -> None:
    parser = argparse.ArgumentParser(description="R-SecOpsX external baseline comparator")
    parser.add_argument("--dependency-track-summary", default="reports/dependency_track_baseline/11_comparison_summary.json")
    parser.add_argument("--rsecopsx-report", default="reports/clean_report.json")
    parser.add_argument("--output-dir", default="reports")
    args = parser.parse_args()

    comparison = run(args.dependency_track_summary, args.rsecopsx_report, args.output_dir)
    print("External baseline comparison complete.")
    print(f"Status: {comparison['comparison_status']}")
    print(f"Output: {Path(args.output_dir) / 'external_baseline_comparison.json'}")
    print(f"Output: {Path(args.output_dir) / 'External_Baseline_Comparison.md'}")


if __name__ == "__main__":
    main()
