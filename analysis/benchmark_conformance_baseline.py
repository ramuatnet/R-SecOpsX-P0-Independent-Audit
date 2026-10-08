"""Measure the mandatory P0 conformance baseline and fail while it is unmet.

    python analysis/benchmark_conformance_baseline.py
    python analysis/benchmark_conformance_baseline.py --report <clean_report.json>

Every one of the eleven declared standards is probed against live production
code and, where the probe needs one, against a produced artifact. The benchmark
exits non-zero while any mandatory P0 standard is NOT_VERIFIED, because a
mandatory baseline that passes while most of it is absent would be a false
assurance.

Excluding artifact-dependent probes by running without --report is legitimate
but weakens the measurement; the printed summary says so explicitly.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from core.conformance_baseline import (  # noqa: E402
    BASELINE_ID,
    BASELINE_VERSION,
    STANDARD_BASELINE,
    evaluate_baseline,
    load_artifact,
)

OUT_DIR = PROJECT_ROOT / "reports"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--report", help="produced clean_report.json for artifact probes")
    ap.add_argument("--root", default=str(PROJECT_ROOT))
    args = ap.parse_args()

    artifact = load_artifact(args.report) if args.report else None
    result = evaluate_baseline(Path(args.root), artifact)

    verified = result["verified_keys"]
    not_verified = result["not_verified_keys"]

    print("=" * 78)
    print("R-SecOpsX MANDATORY P0 CONFORMANCE BASELINE")
    print("=" * 78)
    print(f"baseline   : {BASELINE_ID} v{BASELINE_VERSION}")
    print(f"standards  : {result['mandatory_total']} mandatory P0")
    print(f"verified   : {result['mandatory_verified']}/{result['mandatory_total']} "
          f"({result['coverage_ratio']:.1%})")
    print(f"production : {result['production_source_files']} source files "
          f"(tests/, docs/, reports/, analysis/ excluded as non-implementation)")
    print(f"artifact   : {'supplied' if artifact is not None else 'NOT SUPPLIED'}")
    print("-" * 78)

    for std in result["standards"]:
        mark = "PASS" if std["status"] == "VERIFIED" else "FAIL"
        print(f"[{mark}] {std['key']:<14} {std['title']}")
        print(f"         version: {std['version']}")
        for p in std["probes"]:
            flag = "ok " if p["status"] == "PASS" else "XX "
            req = "req" if p["required"] else "opt"
            print(f"       {flag}[{req}] {p['name']:<32} {p['detail']}")
            if p["status"] == "FAIL":
                print(f"            -> {p['description']}")
        print()

    print("-" * 78)
    print(f"VERIFIED      : {', '.join(verified) or 'none'}")
    print(f"NOT_VERIFIED  : {', '.join(not_verified) or 'none'}")
    print()

    failing = len(not_verified)
    if artifact is None:
        print("NOTE: no --report supplied, so artifact-dependent probes cannot pass.")
        print("      Standards that need one are reported NOT_VERIFIED on that basis,")
        print("      not because the capability is known to be absent.")
        print()

    if failing:
        print(f"OPEN GAP: {failing} of {result['mandatory_total']} mandatory P0 standards "
              f"are NOT_VERIFIED.")
        print("  These are registered in reports/gap_register.json. The baseline is")
        print("  mandatory, so this benchmark is expected to fail until they are closed.")
        print("  It must not be made to pass by relaxing a probe or removing a standard.")
    else:
        print("All mandatory P0 standards verified.")

    payload = dict(result)
    payload["failing_standards"] = failing
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUT_DIR / "benchmark_conformance_baseline.json").write_text(
        json.dumps(payload, indent=2), encoding="utf-8"
    )

    md = [
        "# Mandatory P0 conformance baseline",
        "",
        f"**Baseline:** `{BASELINE_ID}` v{BASELINE_VERSION}  ",
        f"**Verified:** {result['mandatory_verified']}/{result['mandatory_total']} "
        f"({result['coverage_ratio']:.1%})  ",
        f"**Artifact supplied:** {'yes' if artifact is not None else 'no'}",
        "",
        "| Standard | Version | Status | Failed probes |",
        "|---|---|---|---|",
    ]
    for std in result["standards"]:
        md.append(
            f"| `{std['key']}` | {std['version']} | **{std['status']}** | "
            f"{', '.join('`%s`' % f for f in std['failed_probes']) or '-'} |"
        )
    md += ["", "## Not verified", ""]
    for key in not_verified:
        std = next(s for s in result["standards"] if s["key"] == key)
        md.append(f"- **`{key}`** — {', '.join(std['failed_probes'])}")
    md += [
        "",
        "> A passing baseline requires all eleven standards to verify. The gap is",
        "> recorded rather than closed; no probe may be relaxed to make it green.",
        "",
    ]
    (OUT_DIR / "benchmark_conformance_baseline.md").write_text(
        "\n".join(md), encoding="utf-8"
    )
    print("reports: reports/benchmark_conformance_baseline.json | .md")

    return 1 if failing else 0


if __name__ == "__main__":
    raise SystemExit(main())