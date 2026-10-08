"""Run R-SecOpsX across every project in prodtest, one by one, and compare each
result against the vulnerability report that project has already declared.

Design constraints, because the comparison is the whole point
-------------------------------------------------------------
1. Ground truth must be READ, never authored here. The only machine-readable
   declared ground truth in the corpus is juice-shop's
   `data/static/challenges.yml`. Every other project declares its intended
   vulnerabilities in prose (README, lesson text), which this harness does NOT
   convert into a pass/fail oracle -- doing so would mean writing the expected
   answers myself, which is exactly the failure mode the project forbids.

2. So each project lands in one of three honest buckets:
   - DECLARED_MACHINE_READABLE : a declared list exists as data -> compared
     automatically, finding-by-finding.
   - DECLARED_PROSE_ONLY       : a declared list exists only in prose -> reported
     with our counts and the location of the declaration, explicitly NOT scored.
   - NO_DECLARATION            : nothing declared -> reported, not scored.

3. A project is never reported as "passing". Every scored comparison reports
   declared-vs-detected with both directions: what we found that they declared
   (recall), and what we found that they did not declare (precision-side), plus
   what they declared that we did not find. The last of those is the interesting
   one and must never be dropped to make a number look better.

4. Results are written incrementally after each project so a long sweep
   survives interruption, and each project's own output goes to its own
   subdirectory under the reports folder rather than colliding.

Usage:
    python analysis/validate_prodtest_corpus.py [--only NAME ...] [--skip NAME ...]
"""
from __future__ import annotations

import argparse
import json
import pathlib
import re
import subprocess
import sys
import time
from datetime import datetime, timezone

REPO = pathlib.Path(__file__).resolve().parents[1]
PRODTEST = pathlib.Path(r"D:\Data\Code test\prodtest")
REPORTS = PRODTEST / "reports"
SWEEP_JSON = REPORTS / "corpus_validation.json"
SWEEP_MD = REPORTS / "corpus_validation.md"

# Projects that are not scan targets.
NON_TARGETS = {"reports"}

# Rough relative cost, used only to order the sweep so the scored project runs
# first and the cheapest useful ones follow. Not a correctness input.
ORDER_HINT = [
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
    "BenchmarkJava-master",
]

PROSE_DECLARATION_HINTS = {
    "DVWA-master": ["README.md", "vulnerable/README*"],
    "wrongsecrets-master": ["README.md"],
    "WebGoat-main": ["README.md", "src/main/java/org/owasp/webgoat/lessons/**"],
    "railsgoat-main": ["README.md"],
    "NodeGoat-master": ["README.md", "artillery-scripts/**"],
    "Damn-Vulnerable-RESTaurant-API-Game-main": ["README.md"],
    "BenchmarkJava-master": ["README.md"],
    "VAmPI-master": ["README.md"],
    "LLMForge-main": ["README.md"],
}


# ---------------------------------------------------------------------------
# Declared ground truth: READ ONLY
# ---------------------------------------------------------------------------

def load_declared_challenges(project_dir: pathlib.Path) -> dict | None:
    """Read a declared, machine-readable vulnerability list if the project has one.

    Only challenges.yml is treated as an oracle, and only because it is the
    project's own machine-readable declaration of the vulnerabilities it
    deliberately contains. Anything else is reported as undeclared rather than
    guessed at.

    Structure (OWASP Juice Shop): a top-level YAML list whose items begin with a
    bare `-`. Each item carries an indented `key:` (the challenge identifier,
    which is what the scanner's ground-truth layer matches on), a `name:`
    (human title), `category:` and `difficulty:`. An earlier version of this
    parser matched `^name:` at column 0 and therefore extracted ZERO challenges
    from a 116-entry file while reporting a machine-readable oracle -- a silent
    false comparison that would have read as "we detected none of the declared
    vulnerabilities".
    """
    for rel in ("data/static/challenges.yml", "challenges.yml"):
        p = project_dir / rel
        if not p.exists():
            continue
        text = p.read_text(encoding="utf-8", errors="replace")

        challenges = []
        for block in re.split(r"^\s*-\s*$", text, flags=re.MULTILINE):
            if "name:" not in block and "key:" not in block:
                continue
            entry = {}
            for field in ("key", "name", "category"):
                m = re.search(rf"^\s+{field}:\s*(.+?)\s*$", block, re.MULTILINE)
                if m:
                    entry[field] = m.group(1).strip().strip("'\"")
            m = re.search(r"^\s+difficulty:\s*(\d+)\s*$", block, re.MULTILINE)
            if m:
                entry["difficulty"] = int(m.group(1))
            if entry.get("key") or entry.get("name"):
                challenges.append(entry)

        # The `key` is the identifier; fall back to name only if absent, and say
        # so rather than pretending both are interchangeable.
        by_key = {c["key"] for c in challenges if c.get("key")}
        return {
            "source": rel,
            "machine_readable": True,
            "declared_count": len(challenges),
            "declared_keys": sorted(by_key),
            "declared_names": sorted(c.get("name", "") for c in challenges if c.get("name")),
            "challenges": challenges,
            "by_category": _tally(challenges, "category"),
            "by_difficulty": _tally(challenges, "difficulty"),
        }
    return None


def _tally(challenges: list[dict], field: str) -> dict:
    out = {}
    for c in challenges:
        v = c.get(field)
        if v in (None, ""):
            continue
        out[str(v)] = out.get(str(v), 0) + 1
    return dict(sorted(out.items(), key=lambda kv: (-kv[1], kv[0])))


def find_prose_declarations(name: str, project_dir: pathlib.Path) -> list[str]:
    out = []
    for pattern in PROSE_DECLARATION_HINTS.get(name, ["README.md"]):
        for p in sorted(project_dir.glob(pattern))[:3]:
            try:
                size = p.stat().st_size
            except OSError:
                continue
            out.append(f"{p.relative_to(project_dir).as_posix()} ({size:,} bytes)")
    return out


# ---------------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------------

def run_scan(name: str, project_dir: pathlib.Path, out_dir: pathlib.Path,
             timeout: int) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    cmd = [sys.executable, "main.py", str(project_dir), "--workers", "8",
           "--output", str(out_dir)]
    started = time.time()
    try:
        # Explicit UTF-8 with replacement. The default on this host is cp1252,
        # which raises UnicodeDecodeError inside subprocess's reader thread on the
        # tool's own output and loses the captured streams.
        proc = subprocess.run(cmd, cwd=str(REPO), capture_output=True,
                              text=True, encoding="utf-8", errors="replace",
                              timeout=timeout)
        rc = proc.returncode
        err_tail = (proc.stderr or "")[-1500:]
    except subprocess.TimeoutExpired:
        rc, err_tail = -1, f"TIMEOUT after {timeout}s"
    except Exception as exc:
        rc, err_tail = -2, f"launch failed: {exc}"
    elapsed = time.time() - started

    report = out_dir / "clean_report.json"
    result = {
        "returncode": rc,
        "elapsed_seconds": round(elapsed, 1),
        "report_exists": report.exists(),
        "stderr_tail": err_tail if rc != 0 else "",
    }
    if report.exists():
        result["report_bytes"] = report.stat().st_size
    return result


def summarize(report_path: pathlib.Path) -> dict:
    rep = json.loads(report_path.read_text(encoding="utf-8", errors="replace"))
    meta = rep.get("metadata") or {}
    findings = rep.get("findings") or []
    sev = {}
    for f in findings:
        s = str(f.get("severity") or "?").upper()
        sev[s] = sev.get(s, 0) + 1

    rules = {}
    for f in findings:
        rid = str(f.get("rule_id") or f.get("vuln_type") or "?")
        rules[rid] = rules.get(rid, 0) + 1

    gt = meta.get("benchmark_ground_truth") or {}
    frameworks = {}
    for key in ("ssdf_alignment", "asvs_summary", "free_ai_summary",
                "compliance_summary"):
        blob = rep.get(key)
        if isinstance(blob, dict):
            frameworks[key] = {
                k: blob.get(k) for k in
                ("observed", "total_practices", "catalogue_size",
                 "requirements_reachable_count", "recommendations_reachable_count",
                 "findings_mapped", "findings_unmapped")
                if blob.get(k) is not None
            }

    return {
        "total_findings": meta.get("total_findings"),
        "sast_findings": len(findings),
        "severity": dict(sorted(sev.items())),
        "distinct_rules": len(rules),
        "top_rules": sorted(rules.items(), key=lambda kv: -kv[1])[:8],
        "risk_score": meta.get("risk_score"),
        "release_decision": meta.get("canonical_release_decision"),
        "executive_decision": meta.get("canonical_executive_decision"),
        "ground_truth": {
            "dataset": gt.get("dataset"),
            "declared_intentional_findings": gt.get("declared_intentional_findings"),
            "undeclared_findings": gt.get("undeclared_findings"),
            "unresolved_findings": gt.get("unresolved_findings"),
            "challenges_total": gt.get("challenges_total"),
            "challenges_covered_count": gt.get("challenges_covered_count"),
            "challenges_covered": gt.get("challenges_covered") or [],
            "challenges_missed": gt.get("challenges_missed_count"),
            "classification_complete": gt.get("classification_complete"),
        } if gt else None,
        "frameworks": frameworks,
        "attack_paths": len(rep.get("attack_paths") or []),
    }


def compare_to_declared(declared: dict, summary: dict) -> dict:
    """Declared vs detected, for a project that publishes its own list.

    Reports BOTH directions, because a single ratio hides the number that
    actually matters for a scanner:

      * detected_and_attributed -- declared vulnerabilities we evidenced
      * declared_not_detected    -- declared vulnerabilities we did not find
      * unresolved_findings      -- our findings that could not be attributed to
                                   any declared vulnerability

    The third is the precision-side. It is never collapsed into the first and
    never dropped to make a number look better.
    """
    gt = summary.get("ground_truth") or {}
    covered = set(gt.get("challenges_covered") or [])
    declared_keys = set(declared.get("declared_keys") or [])
    declared_names = list(declared.get("declared_names") or [])

    # challenges_covered holds challenge KEYS; fall back to matching names if a
    # future artifact carries only titles.
    if not (declared_keys & covered) and declared_names:
        covered = {c for c in covered if c in set(declared_names)}

    hit = declared_keys & covered
    missed = sorted(declared_keys - covered)

    out = {
        "declared_total": len(declared_keys) or len(declared_names),
        "detected_and_attributed_to_declared": len(hit),
        "detected_challenge_keys": sorted(hit),
        "declared_not_detected": len(missed),
        "declared_not_detected_keys": missed[:60],
        "detected_total_findings": summary.get("sast_findings"),
        "scanner_attributed_findings": gt.get("declared_intentional_findings"),
        "undeclared_findings": gt.get("undeclared_findings"),
        "unresolved_findings": gt.get("unresolved_findings"),
        "challenges_total": gt.get("challenges_total"),
    }
    denom = len(declared_keys) or len(declared_names)
    if denom:
        out["declared_recall"] = round(len(hit) / denom, 4)
    return out


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def write_reports(results: list[dict]) -> None:
    REPORTS.mkdir(parents=True, exist_ok=True)
    SWEEP_JSON.write_text(json.dumps(results, indent=2, default=str), encoding="utf-8")

    lines = [
        "# R-SecOpsX corpus validation -- prodtest",
        "",
        f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}",
        "",
        "Ground truth is READ from each project's own declaration. Where a project",
        "declares its vulnerabilities only in prose, the comparison is reported but",
        "NOT scored: writing the expected answers would be authoring the oracle.",
        "",
        "| Project | Scan | Findings | Rules | Declared | Detected vs declared | Unresolved |",
        "|---|---|---|---|---|---|---|",
    ]
    for r in results:
        s = r.get("summary") or {}
        c = r.get("comparison") or {}
        decl = r.get("declared") or {}
        if decl.get("machine_readable"):
            cmp_txt = (f"{c.get('detected_and_attributed_to_declared', '?')}"
                       f"/{c.get('declared_total', '?')}")
        else:
            cmp_txt = "not scored"
        lines.append(
            f"| `{r['project']}` | {r.get('scan', {}).get('returncode')} "
            f"({r.get('scan', {}).get('elapsed_seconds')}s) "
            f"| {s.get('total_findings')} | {s.get('distinct_rules')} "
            f"| {c.get('declared_total', decl.get('prose_only') and 'prose' or '-')} "
            f"| {cmp_txt} | {c.get('unresolved_findings', '-')} |"
        )
    lines += ["", "## Per project", ""]
    for r in results:
        lines.append(f"### `{r['project']}`")
        lines.append("")
        lines.append(f"- bucket: **{r.get('bucket')}**")
        lines.append(f"- scan: rc={r.get('scan', {}).get('returncode')} "
                     f"in {r.get('scan', {}).get('elapsed_seconds')}s")
        s = r.get("summary") or {}
        if s:
            lines.append(f"- findings: {s.get('total_findings')} "
                         f"(SAST {s.get('sast_findings')}), severity {s.get('severity')}")
            lines.append(f"- distinct rules: {s.get('distinct_rules')}")
            lines.append(f"- top rules: {s.get('top_rules')}")
            lines.append(f"- release: {s.get('release_decision')} / "
                         f"{s.get('executive_decision')}")
            gt = s.get("ground_truth")
            if gt:
                lines.append(f"- ground truth: {gt.get('challenges_covered_count')}"
                             f"/{gt.get('challenges_total')} challenges, "
                             f"{gt.get('declared_intentional_findings')} declared-intentional, "
                             f"{gt.get('unresolved_findings')} unresolved")
        d = r.get("declared") or {}
        if d.get("machine_readable"):
            lines.append(f"- declared source: `{d['source']}` "
                         f"({d.get('declared_count')} declarations)")
        elif d.get("prose_only"):
            lines.append("- declared in prose only (NOT scored): "
                         + ", ".join(d.get("locations") or []))
        else:
            lines.append("- no machine-readable declaration found; not scored")
        if r.get("comparison"):
            lines.append(f"- comparison: {json.dumps(r['comparison'], default=str)[:400]}")
        if r.get("error"):
            lines.append(f"- error: {r['error'][:300]}")
        lines.append("")

    SWEEP_MD.write_text("\n".join(lines), encoding="utf-8")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", nargs="*", default=None)
    ap.add_argument("--skip", nargs="*", default=[])
    ap.add_argument("--timeout", type=int, default=2400)
    args = ap.parse_args()

    targets = []
    for d in sorted(PRODTEST.iterdir()):
        if not d.is_dir() or d.name in NON_TARGETS:
            continue
        if args.only and d.name not in args.only:
            continue
        if d.name in args.skip:
            continue
        targets.append(d)

    targets.sort(key=lambda p: (
        ORDER_HINT.index(p.name) if p.name in ORDER_HINT else 999, p.name))

    results = []
    if SWEEP_JSON.exists():
        try:
            prior = {r["project"]: r for r in json.loads(SWEEP_JSON.read_text(encoding="utf-8"))}
        except Exception:
            prior = {}
    else:
        prior = {}

    # Carry forward results for projects this invocation is not visiting.
    # Without this, `--only <one project>` silently truncates the corpus report,
    # destroying 15 completed entries -- which is exactly what happened once.
    visited = {p.name for p in targets}
    for name, entry in prior.items():
        if name not in visited and entry.get("summary"):
            results.append(entry)

    print(f"corpus: {len(targets)} projects from {PRODTEST}")
    print("=" * 78)

    for i, proj in enumerate(targets, 1):
        name = proj.name
        print(f"[{i}/{len(targets)}] {name} ...", flush=True)

        # Declared ground truth is cheap to read; do it first so the bucket and
        # comparison are always current even when the scan is reused.
        declared = load_declared_challenges(proj)
        prose = find_prose_declarations(name, proj)

        prior_entry = prior.get(name)
        report = REPORTS / name / "clean_report.json"
        if prior_entry and prior_entry.get("summary"):
            entry = dict(prior_entry)
            print("    reusing prior scan result (declaration re-read)")
        elif report.exists():
            # An artifact from an earlier run is present but the results file
            # lost its record. Re-derive from the artifact instead of rescanning:
            # a sweep is expensive and the report is the thing being validated.
            entry = {"project": name, "path": str(proj),
                     "scan": {"returncode": None, "elapsed_seconds": None,
                              "report_exists": True,
                              "note": "re-derived from an existing artifact; not rescanned"}}
            print("    re-deriving summary from existing artifact (not rescanning)")
        else:
            entry = {"project": name, "path": str(proj), "scan": None}

        if declared:
            entry["bucket"] = "DECLARED_MACHINE_READABLE"
            entry["declared"] = declared
        elif prose:
            entry["bucket"] = "DECLARED_PROSE_ONLY"
            entry["declared"] = {"prose_only": True, "locations": prose}
        else:
            entry["bucket"] = "NO_DECLARATION"
            entry["declared"] = {}

        if not entry.get("scan"):
            scan = run_scan(name, proj, REPORTS / name, args.timeout)
            entry["scan"] = scan
            print(f"    rc={scan['returncode']} in {scan['elapsed_seconds']}s", flush=True)

        if report.exists():
            try:
                summary = summarize(report)
                entry["summary"] = summary
                if declared:
                    entry["comparison"] = compare_to_declared(declared, summary)
                print(f"    findings={summary['total_findings']} "
                      f"rules={summary['distinct_rules']} "
                      f"release={summary.get('release_decision')}", flush=True)
            except Exception as exc:
                entry["error"] = f"summary failed: {exc}"
        else:
            entry["error"] = f"no report produced (rc={(entry.get('scan') or {}).get('returncode')})"
            print(f"    !! {entry['error']}", flush=True)

        results.append(entry)
        write_reports(results)
        print("    " + "-" * 70, flush=True)

    write_reports(results)
    print()
    print("=" * 78)
    scored = [r for r in results if (r.get("declared") or {}).get("machine_readable")]
    print(f"projects scanned : {len(results)}")
    print(f"scored vs declared: {len(scored)}")
    print(f"reports: {SWEEP_JSON}")
    print(f"         {SWEEP_MD}")
    print("=" * 78)
    return 0


if __name__ == "__main__":
    sys.exit(main())