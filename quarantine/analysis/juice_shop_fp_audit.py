#!/usr/bin/env python3
r"""
Juice Shop / R-SecOpsX false-positive audit helper.

Reads an existing clean_report.json once and produces compact audit artifacts.
It DOES NOT modify the source report.

Usage:
    py analysis\juice_shop_fp_audit.py
    py analysis\juice_shop_fp_audit.py --input reports\clean_report.json
"""

from __future__ import annotations

import argparse
import csv
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable


THIRD_PARTY_MARKERS = (
    "node_modules",
    "\\node_modules\\",
    "/node_modules/",
    "vendor",
    "\\vendor\\",
    "/vendor/",
)

GENERATED_MARKERS = (
    "\\dist\\", "/dist/",
    "\\build\\", "/build/",
    "\\coverage\\", "/coverage/",
    "\\out\\", "/out/",
    ".min.js", ".bundle.js",
)

ARTIFACT_MARKERS = (
    "bom.json",
    "sbom",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
)

TEST_MARKERS = (
    "\\test\\", "/test/",
    "\\tests\\", "/tests/",
    "__tests__",
    "\\fixtures\\", "/fixtures/",
    "cypress",
)

DOC_MARKERS = (
    ".md", ".markdown", ".txt", ".rst",
)

TYPE_DEF_SUFFIXES = (".d.ts",)

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


def norm_path(value: Any) -> str:
    if value is None:
        return ""
    return str(value).replace("/", "\\").lower()


def classify_path(path: str) -> str:
    p = norm_path(path)
    if not p:
        return "UNKNOWN"

    if any(x in p for x in THIRD_PARTY_MARKERS):
        return "THIRD_PARTY"
    if any(x in p for x in ARTIFACT_MARKERS):
        return "ARTIFACT/BOM"
    if any(x in p for x in GENERATED_MARKERS):
        return "GENERATED/BUILD"
    if any(x in p for x in TEST_MARKERS):
        return "TEST/FIXTURE"
    if p.endswith(TYPE_DEF_SUFFIXES):
        return "TYPE_DEFINITION"
    if p.endswith(DOC_MARKERS):
        return "DOCUMENTATION"
    return "FIRST_PARTY_OR_UNKNOWN"


def walk_findings(obj: Any) -> Iterable[dict]:
    """Find dicts that look like R-SecOpsX findings anywhere in the JSON."""
    if isinstance(obj, dict):
        # Common finding signatures. Avoid treating arbitrary nested objects as findings.
        keys = {str(k).lower() for k in obj.keys()}
        signature = (
            "title" in keys
            or "name" in keys
        ) and (
            "severity" in keys
            or "risk" in keys
            or "cwe" in keys
            or "finding_id" in keys
            or "finding" in keys
            or "description" in keys
        )
        if signature:
            yield obj
        for v in obj.values():
            yield from walk_findings(v)
    elif isinstance(obj, list):
        for item in obj:
            yield from walk_findings(item)


def first_value(d: dict, *names: str) -> Any:
    lower = {str(k).lower(): v for k, v in d.items()}
    for n in names:
        if n.lower() in lower:
            return lower[n.lower()]
    return None


def flatten_text(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, (str, int, float, bool)):
        return str(v)
    if isinstance(v, list):
        return " | ".join(flatten_text(x) for x in v[:20])
    if isinstance(v, dict):
        return json.dumps(v, ensure_ascii=False, separators=(",", ":"))
    return str(v)


def extract_paths(f: dict) -> list[str]:
    paths: list[str] = []

    candidates = (
        "file", "filepath", "file_path", "path", "location",
        "affected_files", "files", "locations", "source_file",
    )

    for key in candidates:
        value = first_value(f, key)
        if isinstance(value, str):
            paths.append(value)
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, str):
                    paths.append(item)
                elif isinstance(item, dict):
                    for k in ("file", "path", "filepath", "file_path", "location"):
                        x = first_value(item, k)
                        if isinstance(x, str):
                            paths.append(x)
        elif isinstance(value, dict):
            for k in ("file", "path", "filepath", "file_path", "location"):
                x = first_value(value, k)
                if isinstance(x, str):
                    paths.append(x)

    # De-duplicate while preserving order.
    seen = set()
    out = []
    for p in paths:
        if p and p not in seen:
            seen.add(p)
            out.append(p)
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", default="reports/clean_report.json")
    ap.add_argument("--output-dir", default="reports/fp_audit")
    args = ap.parse_args()

    src = Path(args.input)
    out = Path(args.output_dir)
    out.mkdir(parents=True, exist_ok=True)

    if not src.exists():
        raise FileNotFoundError(f"Report not found: {src}")

    print(f"Loading report: {src}")
    print(f"Size: {src.stat().st_size / (1024 * 1024):.1f} MB")

    with src.open("r", encoding="utf-8") as fh:
        report = json.load(fh)

    findings = list(walk_findings(report))
    # The recursive heuristic can encounter nested copies. Deduplicate by stable
    # serialized identity where possible.
    unique: list[dict] = []
    seen_ids = set()
    for f in findings:
        fid = first_value(f, "finding_id", "id", "uuid")
        if fid:
            key = ("id", str(fid))
        else:
            key = (
                "fallback",
                str(first_value(f, "title", "name", "rule", "category")),
                str(first_value(f, "file", "filepath", "path", "location")),
                str(first_value(f, "line", "line_number")),
                str(first_value(f, "cwe")),
            )
        if key not in seen_ids:
            seen_ids.add(key)
            unique.append(f)

    rows = []
    category_counts = Counter()
    severity_counts = Counter()
    engine_counts = Counter()
    path_class_counts = Counter()
    llm_counts = Counter()
    cwe_counts = Counter()
    rule_counts = Counter()
    confidence_counts = Counter()
    scope_combo_counts = Counter()

    for idx, f in enumerate(unique, 1):
        title = flatten_text(first_value(f, "title", "name", "finding", "rule", "category"))
        severity = flatten_text(first_value(f, "severity", "level")).upper()
        cwe = flatten_text(first_value(f, "cwe", "cwe_id"))
        engine = flatten_text(first_value(f, "engine", "detector", "detection", "source"))
        confidence = flatten_text(first_value(f, "confidence")).upper()
        rule = flatten_text(first_value(f, "rule_id", "rule", "check_id", "category"))
        description = flatten_text(first_value(f, "description", "message"))
        paths = extract_paths(f)

        classes = [classify_path(p) for p in paths]
        if not classes:
            classes = ["UNKNOWN"]

        if "THIRD_PARTY" in classes:
            scope = "THIRD_PARTY_PRESENT"
        elif "GENERATED/BUILD" in classes:
            scope = "GENERATED_BUILD_PRESENT"
        elif "ARTIFACT/BOM" in classes:
            scope = "ARTIFACT_BOM_PRESENT"
        elif "TEST/FIXTURE" in classes:
            scope = "TEST_FIXTURE_PRESENT"
        elif "TYPE_DEFINITION" in classes:
            scope = "TYPE_DEFINITION_PRESENT"
        elif all(c == "FIRST_PARTY_OR_UNKNOWN" for c in classes):
            scope = "FIRST_PARTY_OR_UNKNOWN"
        else:
            scope = "MIXED"

        # LLM identification is intentionally broad for audit purposes.
        text = " ".join((title, rule, description, engine)).lower()
        is_llm = (
            "llm" in text or
            "prompt" in text or
            "chatbot" in text or
            "model" in text and ("ai" in text or "llm" in text)
        )

        category_counts[title or "(blank)"] += 1
        severity_counts[severity or "UNKNOWN"] += 1
        engine_counts[engine or "UNKNOWN"] += 1
        confidence_counts[confidence or "UNKNOWN"] += 1
        rule_counts[rule or "UNKNOWN"] += 1
        cwe_counts[cwe or "UNKNOWN"] += 1
        scope_combo_counts[scope] += 1
        for c in set(classes):
            path_class_counts[c] += 1
        if is_llm:
            llm_counts[rule or title or "UNKNOWN"] += 1

        rows.append({
            "index": idx,
            "finding_id": flatten_text(first_value(f, "finding_id", "id", "uuid")),
            "title": title,
            "rule": rule,
            "severity": severity,
            "confidence": confidence,
            "engine": engine,
            "cwe": cwe,
            "scope_class": scope,
            "path_classes": "; ".join(sorted(set(classes))),
            "path_count": len(paths),
            "sample_paths": " | ".join(paths[:10]),
            "llm_candidate": "YES" if is_llm else "NO",
        })

    csv_path = out / "fp_audit_findings.csv"
    with csv_path.open("w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()) if rows else [
            "index", "finding_id", "title", "rule", "severity", "confidence",
            "engine", "cwe", "scope_class", "path_classes", "path_count",
            "sample_paths", "llm_candidate"
        ])
        writer.writeheader()
        writer.writerows(rows)

    summary = {
        "status": "RSECOPSX_JUICE_SHOP_FP_AUDIT_V1",
        "input": str(src),
        "input_size_bytes": src.stat().st_size,
        "finding_objects_detected": len(findings),
        "unique_findings_audited": len(unique),
        "severity_counts": dict(severity_counts),
        "scope_class_counts": dict(scope_combo_counts),
        "path_class_counts": dict(path_class_counts),
        "confidence_counts": dict(confidence_counts),
        "engine_counts": dict(engine_counts),
        "top_rules": rule_counts.most_common(50),
        "top_cwes": cwe_counts.most_common(50),
        "top_titles": category_counts.most_common(50),
        "llm_candidate_rules": llm_counts.most_common(50),
        "notes": [
            "This is a triage/audit report, not a ground-truth precision/recall calculation.",
            "Path classification is heuristic and must be manually validated before changing scanner rules.",
            "The original clean_report.json is never modified.",
        ],
    }

    json_path = out / "fp_audit_summary.json"
    json_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")

    md = []
    md.append("# R-SecOpsX Juice Shop v20.2.0 — FP Audit")
    md.append("")
    md.append(f"- Input: `{src}`")
    md.append(f"- Input size: {src.stat().st_size / (1024 * 1024):.1f} MB")
    md.append(f"- Finding objects detected: **{len(findings):,}**")
    md.append(f"- Unique findings audited: **{len(unique):,}**")
    md.append("")
    md.append("## Severity")
    for k, v in severity_counts.most_common():
        md.append(f"- {k}: {v:,}")
    md.append("")
    md.append("## Scope / Path Classification")
    for k, v in path_class_counts.most_common():
        md.append(f"- {k}: {v:,}")
    md.append("")
    md.append("## Finding Scope Classification")
    for k, v in scope_combo_counts.most_common():
        md.append(f"- {k}: {v:,}")
    md.append("")
    md.append("## Confidence")
    for k, v in confidence_counts.most_common():
        md.append(f"- {k}: {v:,}")
    md.append("")
    md.append("## Top Rules")
    for k, v in rule_counts.most_common(30):
        md.append(f"- `{k}`: {v:,}")
    md.append("")
    md.append("## LLM Candidate Findings")
    for k, v in llm_counts.most_common(30):
        md.append(f"- `{k}`: {v:,}")
    md.append("")
    md.append("> This audit is for triage. It does not claim TP/FP ground truth.")
    md.append("> Do not tune rules from these heuristic classifications alone.")
    md_path = out / "fp_audit_summary.md"
    md_path.write_text("\n".join(md) + "\n", encoding="utf-8")

    print("\nAudit complete.")
    print(f"Unique findings audited : {len(unique):,}")
    print(f"CSV                    : {csv_path}")
    print(f"JSON                   : {json_path}")
    print(f"Markdown               : {md_path}")
    print("\nTop scope classes:")
    for k, v in scope_combo_counts.most_common():
        print(f"  {k:28} {v:,}")
    print("\nTop path classes:")
    for k, v in path_class_counts.most_common():
        print(f"  {k:28} {v:,}")
    print("\nTop LLM candidates:")
    for k, v in llm_counts.most_common(10):
        print(f"  {k:40} {v:,}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
