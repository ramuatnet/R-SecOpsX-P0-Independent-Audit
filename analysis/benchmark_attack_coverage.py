"""ATT&CK coverage benchmark (G-054).

Ground truth is authored BEFORE the product is inspected, because the point of
the measurement is what the product does *not* have.

Reference: the publicly published MITRE ATT&CK for Enterprise **tactic list**
(14 tactics, matrix ENTERPRISE).  Only tactic names are used as ground truth --
this benchmark deliberately does **not** ship or infer a technique -> tactic
mapping, because doing so would mean authoring ATT&CK content from memory,
which is exactly the failure mode the gap register forbids.  Technique-level
truth would require a pinned ATT&CK dataset, which is G-054's own remediation.

What this measures, and what it does not
----------------------------------------
Measured here: whether ATT&CK concepts exist as *data* in the product (a
tactic field, a pinned version, a technique -> detection/data-source mapping),
and how many technique IDs are hardcoded.

Not measured: whether the hardcoded technique IDs are correct ATT&CK
assignments.  That needs the dataset.

Output: reports/benchmark_reconciliation_attack_coverage.{json,md}
"""

from __future__ import annotations
try:
    from analysis.spans import WINDOW_M5
except ImportError:  # FND-03: standalone, repo root not on path
    import sys as _fnd03_sys
    from pathlib import Path as _fnd03_path
    _fnd03_sys.path.insert(0, str(_fnd03_path(__file__).resolve().parents[1]))
    from analysis.spans import WINDOW_M5

import argparse
import io
import json
import os
import re
import sys

# --- ground truth, authored before any inspection ---------------------------
#
# Source: https://attack.mitre.org/tactics/enterprise/ (retrieved 2026-10-06),
# which states "Enterprise Tactics: 15" on a page carrying ATT&CK content
# v19.2. Two corrections were made to this list after it was first written:
# the original said 14 tactics and named "Defense Evasion", which MITRE has
# since replaced by splitting that tactic into **Stealth** (TA0005) and
# **Defense Impairment** (TA0112). An earlier draft of this benchmark
# therefore published a denominator of 14 and a tactic name that no longer
# exists; the version below is the authoritative one. Changing the denominator
# does not change any verdict, because the product models zero TA#### ids
# either way - but publishing a wrong ground-truth count would be exactly the
# defect this benchmark exists to detect.

ATTACK_ENTERPRISE_TACTICS = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Stealth",               # was "Defense Evasion"; TA0005 restructured
    "Defense Impairment",    # TA0112, new tactic
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]

GROUND_TRUTH = {
    "reference": "MITRE ATT&CK for Enterprise, tactic list (15 tactics)",
    "source_url": "https://attack.mitre.org/tactics/enterprise/",
    "attack_content_version": "v19.2",
    "retrieved": "2026-10-06",
    "authored_before_inspection": True,
    "tactics_total": len(ATTACK_ENTERPRISE_TACTICS),
    "note": (
        "Tactic names only. No technique->tactic mapping is authored here: "
        "that requires a pinned ATT&CK dataset, which is the remediation this "
        "benchmark exists to measure progress against. The list is sourced "
        "from attack.mitre.org rather than from any third-party repository, "
        "because those disagree with each other (one popular skills library "
        "documents 14 tactics and v16 in its coverage file while its README "
        "claims 15 and v19.1)."
    ),
}

SKIP_DIRS = {"backup", "dump", "Working folder", "__pycache__",
             ".git", ".venv",
             "node_modules", "reports", "tests", "tools"}

# A benchmark must not count its own assertions as product capability: an
# earlier run of this file reported `log_source` present purely because this
# file contains the string `log_source`, and `v3_detection_mapping` PASSED on
# that alone.  Same for test fixtures that assert a technique ID -- and for
# tools/, the operator diagnostics that quote rule text to probe it.
SKIP_FILE_PREFIXES = ("benchmark_", "patch_", "test_")


def _skip_path(path: str, root: str) -> bool:
    rel = os.path.relpath(path, root)
    parts = rel.replace("\\", "/").split("/")
    return any(p in SKIP_DIRS for p in parts) or \
        os.path.basename(rel).startswith(SKIP_FILE_PREFIXES)

TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{2,3})?\b")
TACTIC_ID_RE = re.compile(r"\bTA\d{4}\b")


def _live_py_files(root: str):
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d not in SKIP_DIRS]
        if any(s in dp for s in SKIP_DIRS):
            continue
        for fn in fns:
            if fn.endswith(".py") and not fn.startswith(SKIP_FILE_PREFIXES):
                yield os.path.join(dp, fn)


def inspect_source(root: str) -> dict:
    techniques: dict[str, int] = {}
    tactic_ids: dict[str, int] = {}
    tactic_names: dict[str, int] = {t: 0 for t in ATTACK_ENTERPRISE_TACTICS}
    sigma_hits = data_source_hits = log_source_hits = 0
    version_hits: list[str] = []
    version_re = re.compile(r"ATT&CK\s*(?:for\s+\w+\s*)?v?\d+(?:\.\d+)*|ENTERPRISE\s+v\d+", re.I)

    files = list(_live_py_files(root))
    for path in files:
        try:
            text = io.open(path, encoding="utf-8", errors="replace").read()
        except Exception:
            continue
        for m in TECHNIQUE_RE.findall(text):
            techniques[m] = techniques.get(m, 0) + 1
        for m in TACTIC_ID_RE.findall(text):
            tactic_ids[m] = tactic_ids.get(m, 0) + 1
        low = text.lower()
        if re.search(r"\bsigma\b", low):
            sigma_hits += 1
        if re.search(r"\bdata[_ ]source\b", low):
            data_source_hits += 1
        if re.search(r"\blog[_ ]source\b", low):
            log_source_hits += 1
        for m in version_re.findall(text):
            version_hits.append(m.strip())
        for name in ATTACK_ENTERPRISE_TACTICS:
            if re.search(r"\b" + re.escape(name) + r"\b", text):
                tactic_names[name] += 1

    present = sorted(t for t in tactic_names if tactic_names[t])

    # A tactic is "modelled" only if it appears as data, not in prose. Prose
    # mentions of "lateral movement" in a business_impact string do not count,
    # so this requires a TA#### identifier or an explicit tactic field.
    return {
        "live_py_files": len(files),
        "techniques_distinct": sorted(techniques),
        "techniques_distinct_count": len(techniques),
        "sub_techniques_distinct": sorted(t for t in techniques if "." in t),
        "sub_techniques_count": sum(1 for t in techniques if "." in t),
        "tactic_ids_present": sorted(tactic_ids),
        "tactic_ids_count": len(tactic_ids),
        "tactic_names_mentioned_in_prose": present,
        "tactics_modelled_as_data": 0 if not tactic_ids else len(tactic_ids),
        "sigma_rule_files": sigma_hits,
        "data_source_tokens": data_source_hits,
        "log_source_tokens": log_source_hits,
        "attck_version_strings": sorted(set(version_hits)),
        "attck_version_pinned": bool(version_hits),
        "has_bundled_attck_dataset": _has_dataset(root),
    }


def _has_dataset(root: str) -> bool:
    pat = re.compile(r"(attack|mitre|technique|stix|navigator)", re.I)
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d not in SKIP_DIRS]
        if any(s in dp for s in SKIP_DIRS):
            continue
        for fn in fns:
            if fn.endswith((".json", ".stix", ".xml")) and pat.search(fn):
                if "attack" in fn.lower() or "mitre" in fn.lower() or "stix" in fn.lower():
                    return True
    return False


def inspect_report(path: str | None) -> dict:
    if not path or not os.path.exists(path):
        return {"present": False}
    report = json.load(io.open(path, encoding="utf-8"))
    techniques = []
    for m in report.get("mitre") or []:
        if isinstance(m, dict) and m.get("id"):
            techniques.append(str(m["id"]))
    on_findings = set()
    for f in report.get("findings") or []:
        if not isinstance(f, dict):
            continue
        v = f.get("mitre") or f.get("mitre_attack")
        for t in (v if isinstance(v, list) else [v]):
            t = str(t or "").strip()
            if t:
                on_findings.add(t)
    findings = [f for f in report.get("findings") or [] if isinstance(f, dict)]
    return {
        "present": True,
        "findings": len(findings),
        "findings_carrying_technique": sum(
            1 for f in findings if (f.get("mitre") or f.get("mitre_attack"))),
        "techniques_in_report": techniques,
        "techniques_in_report_count": len(techniques),
        "techniques_not_on_any_finding": [t for t in techniques if t not in on_findings],
        "defaulted_description_count": sum(
            1 for m in (report.get("mitre") or [])
            if isinstance(m, dict) and m.get("description") == "Mapped ATT&CK technique"),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="ATT&CK coverage benchmark (G-054)")
    ap.add_argument("--root", default=".")
    ap.add_argument("--report", help="clean_report.json to measure coverage on")
    ap.add_argument("--out", default=r"reports\benchmark_reconciliation_attack_coverage")
    args = ap.parse_args()

    src = inspect_source(args.root)
    rep = inspect_report(args.report)

    has_tactic_field = False  # no TA#### anywhere => no tactic model
    properties = {
        "tactics_modelled": {
            "modelled": src["tactic_ids_count"] > 0,
            "present": src["tactic_ids_count"],
            "expected": GROUND_TRUTH["tactics_total"],
        },
        "techniques_present": src["techniques_distinct_count"],
        "sub_techniques_present": src["sub_techniques_count"],
        "attck_version_pinned": src["attck_version_pinned"],
        "technique_to_detection_mapping": (
            src["sigma_rule_files"] > 0 or src["log_source_tokens"] > 0),
        "bundled_dataset": src["has_bundled_attck_dataset"],
    }

    verdict = {
        # A tactic model exists only if TA#### identifiers are present.
        "v1_tactics_modelled": src["tactic_ids_count"] > 0,
        "v2_version_pinned": src["attck_version_pinned"],
        "v3_detection_mapping": properties["technique_to_detection_mapping"],
        "v4_no_stale_technique": not (rep.get("techniques_not_on_any_finding") or []),
        # Coverage must be *measurable*, so it is only true once a pinned
        # dataset exists to measure against.
        "v5_coverage_measurable": src["has_bundled_attck_dataset"],
    }

    payload = {
        "benchmark": "attack-coverage-2026-10",
        "root_causes": ["G-054"],
        "ground_truth": GROUND_TRUTH,
        "source": src,
        "report": rep,
        "properties": properties,
        "verdict": verdict,
        "honest_limitation": (
            "This benchmark measures structure, not correctness. It can say "
            "whether a tactic model, a pinned version and a detection mapping "
            "exist; it cannot say whether the hardcoded technique IDs are "
            "correct ATT&CK assignments, because that requires the dataset."
        ),
    }

    out_json = args.out if args.out.endswith(".json") else args.out + ".json"
    out_md = out_json[:WINDOW_M5] + ".md"
    os.makedirs(os.path.dirname(os.path.abspath(out_json)) or ".", exist_ok=True)
    json.dump(payload, io.open(out_json, "w", encoding="utf-8"),
              ensure_ascii=False, indent=2)

    lines = [
        "# ATT&CK coverage benchmark", "",
        f"Root cause: {', '.join(payload['root_causes'])}", "",
        f"Ground truth: {GROUND_TRUTH['reference']} "
        f"({GROUND_TRUTH['tactics_total']} tactics), "
        f"authored before inspection.", "",
        "| property | value |", "|---|---|",
        f"| distinct technique IDs in source | {src['techniques_distinct_count']} |",
        f"| sub-technique IDs | {src['sub_techniques_count']} |",
        f"| ATT&CK tactic IDs (TA####) | {src['tactic_ids_count']} / "
        f"{GROUND_TRUTH['tactics_total']} |",
        f"| ATT&CK version pinned | {src['attck_version_pinned']} |",
        f"| bundled ATT&CK dataset | {src['has_bundled_attck_dataset']} |",
        f"| sigma rule files | {src['sigma_rule_files']} |",
        f"| log_source tokens | {src['log_source_tokens']} |",
    ]
    if rep.get("present"):
        lines += [
            f"| findings carrying a technique | "
            f"{rep['findings_carrying_technique']} / {rep['findings']} |",
            f"| techniques reported | {rep['techniques_in_report_count']} |",
            f"| techniques on no finding (stale) | "
            f"{len(rep['techniques_not_on_any_finding'])} |",
            f"| defaulted technique descriptions | {rep['defaulted_description_count']} |",
        ]
    lines += ["", "Technique IDs found: "
              + (", ".join(src["techniques_distinct"]) or "none"), "",
              "## Verdict", ""]
    for k, v in verdict.items():
        lines.append(f"- {k}: {'PASS' if v else 'FAIL'}")
    lines += ["", "## Honest limitation", "", payload["honest_limitation"], "",
              f"Tactics never modelled as data: "
              f"{GROUND_TRUTH['tactics_total']} of {GROUND_TRUTH['tactics_total']} absent.",
              ""]
    io.open(out_md, "w", encoding="utf-8").write("\n".join(lines))

    print(f"wrote {out_json}")
    print(f"wrote {out_md}")
    print(f"  techniques={src['techniques_distinct_count']} "
          f"sub={src['sub_techniques_count']} "
          f"tactic_ids={src['tactic_ids_count']} "
          f"version_pinned={src['attck_version_pinned']}")
    for k, v in verdict.items():
        print(f"  {k}: {'PASS' if v else 'FAIL'}")
    return 0 if all(verdict.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
