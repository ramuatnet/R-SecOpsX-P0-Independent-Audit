"""SBOM/SCA benchmark reconciliation — R-SecOpsX vs Trivy vs Grype.

Ground truth comes from OSV.dev, queried for each exact package@version
*before* any compared tool ran, so no tool's output is treated as truth.

Two independent measurements:

  1. Package discovery   — did the tool find the packages that are declared?
  2. Vulnerability match — did it attribute the right CVEs to the right
                           package@version, and did it invent any?

Usage:
    python analysis/benchmark_sca_corpus.py
    python analysis/benchmark_sca_corpus.py --fixture <dir>
"""
from __future__ import annotations
try:
    from analysis.spans import WINDOW_200, WINDOW_4
except ImportError:  # FND-03: standalone, repo root not on path
    import sys as _fnd03_sys
    from pathlib import Path as _fnd03_path
    _fnd03_sys.path.insert(0, str(_fnd03_path(__file__).resolve().parents[1]))
    from analysis.spans import WINDOW_200, WINDOW_4

import argparse
import json
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
DEFAULT_FIXTURE = Path(
    r"C:\Users\janan\AppData\Local\Temp\opencode\p09_sca_bench"
)
DEFAULT_OUT = REPO / "reports"
BENCHMARK_ID = "sca-multilang-2026-10"

# Name spellings each tool uses for the same Maven artifact.
_MAVEN_ALIASES = {
    "log4j-core": "log4j-core",
    "commons-lang3": "commons-lang3",
}

# The scanned project's own artifact (package.json `name` / pom artifactId).
# Tools emit it; it is not a dependency, so it is excluded from FP.
_ROOT_ARTIFACTS = {"sca-bench"}


def norm_pkg(name: str) -> str:
    """Reduce any tool's package spelling to a comparable key."""
    n = str(name or "").strip().lower()
    n = re.sub(r"^(pypi:|npm:|maven:|gem:|cargo:|golang:)", "", n)
    # Maven: group:artifact or group/artifact -> artifact
    if ":" in n and not n.startswith("cve-"):
        n = n.rsplit(":", 1)[-1]
    n = n.rsplit("/", 1)[-1]
    n = n.strip()
    if n in _MAVEN_ALIASES:
        return _MAVEN_ALIASES[n]
    return n


def norm_version(v: str) -> str:
    """`==2.19.1` (requirements.txt pin) and `v4.17.4` (npm) -> `2.19.1`."""
    s = str(v or "").strip().lower()
    s = re.sub(r"^[<>=!~^]+", "", s)
    s = s.lstrip("v")
    return s or "unknown"


# ---------------------------------------------------------------------------
# Ground truth
# ---------------------------------------------------------------------------

def load_ground_truth(fixture: Path) -> dict:
    gt = json.loads((fixture / "ground_truth.json").read_text(encoding="utf-8"))
    for p in gt["packages"]:
        p["key"] = norm_pkg(p["name"])
        p["vulnerable"] = bool(p["cves"])
    return gt


# ---------------------------------------------------------------------------
# Tool runners
# ---------------------------------------------------------------------------

def _entry(raw) -> dict:
    """Uniform per-package record.

    Keeps the *raw* version alongside the normalised one so the report can
    show when a tool emits a string no downstream consumer can use directly
    (a PURL/SPDX version must be ``2.19.1``, never ``==2.19.1``).
    """
    raw_s = str(raw or "")
    return {"version": norm_version(raw_s), "raw_version": raw_s, "cves": set()}


def run_rsecopsx(fixture: Path) -> dict:
    sys.path.insert(0, str(REPO))
    from scanner.sbom import generate_sbom

    pkgs = generate_sbom(str(fixture))
    found: dict[str, dict] = {}
    for p in pkgs:
        key = norm_pkg(p.get("name"))
        ver = norm_version(p.get("version"))
        cves = set()
        for v in (p.get("vulnerabilities") or []):
            if not isinstance(v, dict):
                if isinstance(v, str) and v.startswith("CVE-"):
                    cves.add(v)
                continue
            # R-SecOpsX's OSV adapter stores the CVE both in ``cve`` and in
            # ``aliases``. Reading only ``cve`` undercounts the tool.
            for candidate in ([v.get("cve"), v.get("id")]
                              + list(v.get("aliases") or [])):
                if isinstance(candidate, str) and candidate.startswith("CVE-"):
                    cves.add(candidate)
        prev = found.get(key)
        if prev is None or (prev["version"] == "unknown" and ver != "unknown"):
            found[key] = {
                "version": ver,
                "cves": cves,
                "raw_version": str(p.get("version") or ""),
                "purl": p.get("purl"),
            }
    return {"name": "R-SecOpsX", "available": True, "packages": found}


def run_trivy(fixture: Path) -> dict:
    exe = shutil.which("trivy")
    if not exe:
        return {"name": "Trivy", "available": False, "reason": "not installed"}
    out = fixture / "_trivy.json"
    cmd = [exe, "fs", "--scanners", "vuln", "--format", "json",
           "--quiet", "--output", str(out), str(fixture)]
    env = dict(**{k: v for k, v in __import__("os").environ.items()})
    env["TRIVY_CACHE_DIR"] = str(Path(__import__("os").environ.get(
        "TEMP", ".")) / "opencode" / "trivy_cache")
    subprocess.run(cmd, capture_output=True, env=env, timeout=600)
    if not out.exists():
        return {"name": "Trivy", "available": False, "reason": "no output"}
    data = json.loads(out.read_text(encoding="utf-8"))
    found: dict[str, dict] = {}
    for res in data.get("Results") or []:
        for v in res.get("Vulnerabilities") or []:
            key = norm_pkg(v.get("PkgName"))
            e = found.setdefault(key, _entry(v.get("InstalledVersion")))
            vid = v.get("VulnerabilityID") or ""
            if vid.startswith("CVE-"):
                e["cves"].add(vid)
        # packages with no vulns still count as discovered
        for p in (res.get("Packages") or []):
            key = norm_pkg(p.get("Name"))
            found.setdefault(key, _entry(p.get("Version")))
    out.unlink(missing_ok=True)
    return {"name": "Trivy", "available": True, "packages": found}


def _grype_cves(match: dict) -> set[str]:
    """Grype keys matches on GHSA/OSV ids; the CVE is a *sibling* of
    ``vulnerability`` on the match (``relatedVulnerabilities``), or in
    ``aliases``. Reading only ``vulnerability.id`` scores Grype at 0 CVEs
    when it in fact matched correctly."""
    out: set[str] = set()
    vul = match.get("vulnerability") or {}
    pool = [vul] + list(match.get("relatedVulnerabilities") or [])
    for item in pool:
        if not isinstance(item, dict):
            continue
        for candidate in [item.get("id")] + list(item.get("aliases") or []):
            if isinstance(candidate, str) and candidate.startswith("CVE-"):
                out.add(candidate)
    return out


def run_grype(fixture: Path) -> dict:
    exe = shutil.which("grype")
    if not exe:
        return {"name": "Grype", "available": False, "reason": "not installed"}
    vuln_out = fixture / "_grype_vuln.json"
    sbom_out = fixture / "_grype_sbom.cdx.json"
    for p in (vuln_out, sbom_out):
        p.unlink(missing_ok=True)

    # Two outputs: the match list (CVEs) and the CycloneDX inventory (packages
    # with no vulnerabilities still have to count as discovered).
    proc = subprocess.run(
        [exe, f"dir:{fixture}", "-o", f"json={vuln_out}",
         "-o", f"cyclonedx-json={sbom_out}", "-q"],
        capture_output=True, timeout=900)

    if not vuln_out.exists():
        err = proc.stderr.decode("utf-8", "replace") if isinstance(proc.stderr, bytes) else str(proc.stderr or "")
        return {"name": "Grype", "available": False,
                "reason": (err[:WINDOW_200] or "no output")}

    found: dict[str, dict] = {}
    if sbom_out.exists():
        sbom = json.loads(sbom_out.read_text(encoding="utf-8"))
        for c in sbom.get("components") or []:
            key = norm_pkg(c.get("name"))
            found.setdefault(key, _entry(c.get("version")))

    data = json.loads(vuln_out.read_text(encoding="utf-8"))
    for m in data.get("matches") or []:
        art = m.get("artifact") or {}
        key = norm_pkg(art.get("name"))
        e = found.setdefault(key, _entry(art.get("version")))
        e["cves"] |= _grype_cves(m)

    for p in (vuln_out, sbom_out):
        p.unlink(missing_ok=True)
    return {"name": "Grype", "available": True, "packages": found}


# ---------------------------------------------------------------------------
# Reconciliation
# ---------------------------------------------------------------------------

def _pr(tp: int, fp: int, fn: int) -> dict:
    p = tp / (tp + fp) if (tp + fp) else None
    r = tp / (tp + fn) if (tp + fn) else None
    f1 = (2 * p * r / (p + r)) if (p and r) else (0.0 if (p == 0 or r == 0) and (tp + fp + fn) else None)
    return {"tp": tp, "fp": fp, "fn": fn,
            "precision": round(p, 4) if p is not None else None,
            "recall": round(r, 4) if r is not None else None,
            "f1": round(f1, 4) if f1 is not None else None}


def reconcile(gt: dict, tool: dict) -> dict:
    gt_pkgs = {p["key"]: p for p in gt["packages"]}
    found = tool.get("packages") or {}

    # --- package discovery -------------------------------------------
    tp = [k for k in gt_pkgs if k in found]
    fn = [k for k in gt_pkgs if k not in found]
    extra_all = [k for k in found if k not in gt_pkgs]
    # Trivy and Grype also emit the scanned project itself (the pom groupId/
    # artifactId and package.json name). That is not a dependency, so it is
    # reported but not counted against discovery precision.
    root_artifacts = sorted(k for k in extra_all if k in _ROOT_ARTIFACTS)
    extra = sorted(k for k in extra_all if k not in _ROOT_ARTIFACTS)
    discovery = _pr(len(tp), len(extra), len(fn))

    # version accuracy on the packages that were found
    ver_ok, ver_bad = [], []
    for k in tp:
        want = norm_version(gt_pkgs[k]["version"])
        got = found[k]["version"]
        (ver_ok if got == want else ver_bad).append(
            {"package": k, "expected": want, "got": got,
             "raw": found[k].get("raw_version")})

    # A version that still carries its specifier (`==2.19.1`) is unusable in a
    # PURL/SPDX component and is what the advisory query receives verbatim.
    raw_unusable = sorted(
        k for k, e in found.items()
        if e.get("raw_version") and e["raw_version"] != e["version"]
    )

    # --- vulnerability matching --------------------------------------
    cve_tp = cve_fp = cve_fn = 0
    per_pkg = []
    vuln_expected = 0
    vuln_identified = 0
    false_safe_hits = []
    for k, g in sorted(gt_pkgs.items()):
        gt_cves = set(g["cves"])
        tool_cves = set(found.get(k, {}).get("cves") or set())
        if g["vulnerable"]:
            vuln_expected += 1
            if tool_cves & gt_cves:
                vuln_identified += 1
        elif tool_cves:
            false_safe_hits.append(
                {"package": k, "version": g["version"],
                 "invented_cves": sorted(tool_cves)})

        hit = gt_cves & tool_cves
        miss = gt_cves - tool_cves
        invent = tool_cves - gt_cves
        cve_tp += len(hit)
        cve_fn += len(miss)
        cve_fp += len(invent)
        if g["vulnerable"] or tool_cves:
            per_pkg.append({
                "package": k, "version": g["version"],
                "ground_truth_cves": len(gt_cves),
                "reported_cves": len(tool_cves),
                "correct": len(hit), "missed": len(miss),
                "invented": len(invent),
                "sample_missed": sorted(miss)[:WINDOW_4],
                "sample_invented": sorted(invent)[:WINDOW_4],
            })

    return {
        "tool": tool["name"],
        "available": tool.get("available", True),
        "reason": tool.get("reason"),
        "discovery": discovery,
        "discovered_count": len(found),
        "extra_packages": extra,
        "root_artifacts": root_artifacts,
        "version_ok": len(ver_ok),
        "version_mismatch": ver_bad,
        "raw_version_unusable": raw_unusable,
        "vulnerable_expected": vuln_expected,
        "vulnerable_identified": vuln_identified,
        "safe_controls_false_matched": false_safe_hits,
        "cve_matching": _pr(cve_tp, cve_fp, cve_fn),
        "per_package": per_pkg,
    }


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def write_reports(gt: dict, results: list[dict], out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    payload = {"benchmark_id": BENCHMARK_ID, "ground_truth": gt, "tools": results}
    (out_dir / "benchmark_reconciliation_sca.json").write_text(
        json.dumps(payload, indent=2, ensure_ascii=False, default=str),
        encoding="utf-8")

    gt_total_cves = sum(len(p["cves"]) for p in gt["packages"])
    gt_vuln = sum(1 for p in gt["packages"] if p["vulnerable"])
    gt_safe = sum(1 for p in gt["packages"] if not p["vulnerable"])

    def pct(v):
        return "n/a" if v is None else f"{v * 100:.1f}%"

    L = [
        f"# SBOM/SCA Benchmark Reconciliation — `{BENCHMARK_ID}`",
        "",
        "Ground truth established from **OSV.dev**, queried per exact",
        "package@version before any compared tool ran. No tool is treated as",
        "the reference.",
        "",
        "| Ground truth | Count |",
        "|---|---:|",
        f"| Packages declared | {len(gt['packages'])} |",
        f"| Packages with >=1 CVE | {gt_vuln} |",
        f"| Safe controls (0 CVEs) | {gt_safe} |",
        f"| Total CVEs | {gt_total_cves} |",
        "",
        "## Tool comparison",
        "",
        "| Metric | " + " | ".join(r["tool"] for r in results) + " |",
        "|---|" + "---:|" * len(results),
    ]

    rows = [
        ("Packages discovered", lambda r: str(r["discovered_count"])),
        ("Discovery precision", lambda r: pct(r["discovery"]["precision"])),
        ("Discovery recall", lambda r: pct(r["discovery"]["recall"])),
        ("Discovery F1", lambda r: pct(r["discovery"]["f1"])),
        ("Version parsed correctly", lambda r: str(r["version_ok"])),
        ("Version mismatched", lambda r: str(len(r["version_mismatch"]))),
        ("Version still carries its specifier", lambda r: str(len(r["raw_version_unusable"]))),
        ("Vulnerable pkgs identified", lambda r: f"{r['vulnerable_identified']}/{r['vulnerable_expected']}"),
        ("Safe controls falsely matched", lambda r: str(len(r["safe_controls_false_matched"]))),
        ("CVE TP", lambda r: str(r["cve_matching"]["tp"])),
        ("CVE FP (invented)", lambda r: str(r["cve_matching"]["fp"])),
        ("CVE FN (missed)", lambda r: str(r["cve_matching"]["fn"])),
        ("CVE precision", lambda r: pct(r["cve_matching"]["precision"])),
        ("CVE recall", lambda r: pct(r["cve_matching"]["recall"])),
        ("CVE F1", lambda r: pct(r["cve_matching"]["f1"])),
    ]
    for label, fn in rows:
        L.append(f"| {label} | " + " | ".join(fn(r) for r in results) + " |")

    for r in results:
        L += ["", f"### {r['tool']}", ""]
        if not r["available"]:
            L.append(f"_Not run: {r.get('reason')}_")
            continue
        if r["extra_packages"]:
            L.append(f"- Extra packages (not declared): "
                     f"{', '.join(r['extra_packages'])}")
        if r["root_artifacts"]:
            L.append(f"- Project's own artifact (not a dependency, excluded "
                     f"from FP): {', '.join(r['root_artifacts'])}")
        for m in r["version_mismatch"]:
            L.append(f"- Version mismatch: `{m['package']}` expected "
                     f"`{m['expected']}`, got `{m['got']}` (raw "
                     f"`{m['raw']}`)")
        if r["raw_version_unusable"]:
            L.append("- **Version still carries its specifier:** "
                     + ", ".join(f"`{k}`" for k in r["raw_version_unusable"])
                     + " — invalid in a PURL/SPDX component, and the exact "
                       "string is what the advisory query receives as "
                       "`version=`.")
        for f in r["safe_controls_false_matched"]:
            L.append(f"- **False vulnerability match**: `{f['package']}` "
                     f"{f['version']} is clean, reported "
                     f"{', '.join(f['invented_cves'])}")
        L += ["", "| Package | GT CVEs | Reported | Correct | Missed | Invented |",
              "|---|---:|---:|---:|---:|---:|"]
        for p in r["per_package"]:
            L.append(f"| {p['package']} {p['version']} | "
                     f"{p['ground_truth_cves']} | {p['reported_cves']} | "
                     f"{p['correct']} | {p['missed']} | {p['invented']} |")

    (out_dir / "benchmark_reconciliation_sca.md").write_text(
        "\n".join(L) + "\n", encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--fixture", type=Path, default=DEFAULT_FIXTURE)
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = ap.parse_args()

    gt = load_ground_truth(args.fixture)
    t0 = time.time()
    tools = [run_rsecopsx(args.fixture), run_trivy(args.fixture),
             run_grype(args.fixture)]
    results = [reconcile(gt, t) for t in tools]
    write_reports(gt, results, args.out)

    print(f"benchmark={BENCHMARK_ID}  elapsed={time.time() - t0:.1f}s")
    print(f"  ground truth: {len(gt['packages'])} packages, "
          f"{sum(len(p['cves']) for p in gt['packages'])} CVEs, "
          f"{sum(1 for p in gt['packages'] if p['vulnerable'])} vulnerable, "
          f"{sum(1 for p in gt['packages'] if not p['vulnerable'])} safe controls")
    for r in results:
        if not r["available"]:
            print(f"  {r['tool']:<12} NOT RUN ({r.get('reason')})")
            continue
        d, c = r["discovery"], r["cve_matching"]
        print(f"  {r['tool']:<12} pkgs={r['discovered_count']:<3} "
              f"P={d['precision']} R={d['recall']} F1={d['f1']} | "
              f"vuln {r['vulnerable_identified']}/{r['vulnerable_expected']} | "
              f"CVE P={c['precision']} R={c['recall']} F1={c['f1']} "
              f"(invented {c['fp']}, missed {c['fn']})")
        if r["version_mismatch"]:
            print(f"               version mismatches: "
                  f"{len(r['version_mismatch'])}")
        if r["safe_controls_false_matched"]:
            print(f"               SAFE CONTROLS FALSELY MATCHED: "
                  f"{[f['package'] for f in r['safe_controls_false_matched']]}")
    print(f"  reports      : {args.out / 'benchmark_reconciliation_sca.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
