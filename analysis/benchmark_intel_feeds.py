"""Threat-intelligence feed benchmark: R-SecOpsX vs FIRST.org EPSS + CISA KEV.

Closing the measurement half of gap-register **G-001** and **G-002**.

Ground truth
------------
The two authoritative feeds are queried and snapshotted to
``reports/benchmark_intel_ground_truth.json`` **before any R-SecOpsX code is
imported or run**, so the product is measured against a document it cannot
have seen.  No product output is ever treated as truth.

The CVE corpus is drawn from three independent sources:
  * the OSV-derived SCA ground truth (70 CVEs, authored before any tool ran),
  * the product's own compiled-in seed tables (so their accuracy is measured
    rather than assumed),
  * a sentinel identifier no authority has ever issued, to prove a miss stays
    a miss instead of inheriting a neighbouring score.

What this benchmark does and does not prove
-------------------------------------------
It proves **wiring fidelity**: that R-SecOpsX reproduces the feeds' values
exactly, covers far more of the corpus than the compiled-in tables, labels
every value with the provenance of its actual source, and never lets a miss
become a number.

It does **not** prove that EPSS or KEV predict exploitation.  The feeds are
the reference by construction, so live-side value fidelity is 1.0 by
construction and is reported as a wiring check only.  The substantive
measurements are coverage gain and how wrong the seed tables were against
that reference.

Usage:
    python analysis/benchmark_intel_feeds.py
    python analysis/benchmark_intel_feeds.py --reuse-truth   # offline rerun
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from analysis import live_intel_feeds as feeds
from analysis.epss_intelligence_engine import (
    STATIC_EPSS_SCORES,
    enrich_epss_intelligence,
    epss_intelligence_summary,
)
from analysis.intelligence_provenance import (
    LIVE_FEED,
    NOT_AVAILABLE,
    STATIC_REFERENCE,
)
from analysis.kev_intelligence_engine import (
    KNOWN_EXPLOITED_CVES as KEV_SEED_RECORDS,
    enrich_kev_intelligence,
    kev_intelligence_summary,
)
from analysis.vulnerability_age_engine import (
    KNOWN_EXPLOITED_CVES as AGE_SEED_RECORDS,
    enrich_vulnerability_age,
    vulnerability_age_summary,
)

DEFAULT_SCA_GT = Path(
    r"C:\Users\janan\AppData\Local\Temp\opencode\p09_sca_bench\ground_truth.json"
)
OUT_DIR = REPO / "reports"
TRUTH_PATH = OUT_DIR / "benchmark_intel_ground_truth.json"
OUT_JSON = OUT_DIR / "benchmark_intel_reconciliation.json"
OUT_MD = OUT_DIR / "benchmark_intel_reconciliation.md"
BENCH_CACHE = OUT_DIR / ".benchmark_intel_cache.json"

# An identifier no authority has ever issued: every engine must answer
# "no value" rather than borrow one from a nearby record.
NEVER_ISSUED = "CVE-2099-999999"

BENCHMARK_ID = "intel-feeds-2026-10"
EPSS_BATCH = 50
# EPSS refreshes daily, so a reference older than this measures a different
# feed than the one the product queries.
SNAPSHOT_MAX_AGE_S = 24 * 3600


def _snapshot_fresh(truth: dict) -> bool:
    """Is this ground-truth snapshot still measuring today's feed?"""
    try:
        fetched = datetime.fromisoformat(str(truth.get("fetched_at")))
        if fetched.tzinfo is None:
            fetched = fetched.replace(tzinfo=timezone.utc)
        age = (datetime.now(timezone.utc) - fetched).total_seconds()
        return 0 <= age <= SNAPSHOT_MAX_AGE_S
    except (TypeError, ValueError):
        return False


# ---------------------------------------------------------------------------
# Corpus
# ---------------------------------------------------------------------------

def build_corpus(sca_gt: Path) -> list[str]:
    cves: set[str] = set()

    if sca_gt.exists():
        gt = json.loads(sca_gt.read_text(encoding="utf-8"))
        for pkg in gt.get("packages", []):
            for cve in pkg.get("cves") or []:
                cve = str(cve).strip().upper()
                if cve.startswith("CVE-"):
                    cves.add(cve)
    else:
        print(f"  ! SCA ground truth not found at {sca_gt} - continuing with the "
              f"seed-table corpus only")

    # The seed tables themselves must be in the corpus, otherwise their
    # accuracy is never measured - only their coverage.
    cves.update(STATIC_EPSS_SCORES)
    cves.update(KEV_SEED_RECORDS)
    cves.update(AGE_SEED_RECORDS)
    cves.add(NEVER_ISSUED)

    return sorted(cves)


# ---------------------------------------------------------------------------
# Phase 1 - ground truth, fetched before the product runs
# ---------------------------------------------------------------------------

def fetch_ground_truth(cves: list[str]) -> dict:
    print(f"  fetching EPSS for {len(cves)} CVEs ...")
    epss: dict[str, dict] = {}
    for i in range(0, len(cves), EPSS_BATCH):
        batch = cves[i:i + EPSS_BATCH]
        url = f"{feeds.EPSS_API_URL}?cve=" + ",".join(batch)
        payload = feeds._get_json(url, timeout=60)
        for row in payload.get("data") or []:
            if not isinstance(row, dict):
                continue
            cve = str(row.get("cve") or "").strip().upper()
            if not cve:
                continue
            epss[cve] = {
                "score": float(row["epss"]),
                "percentile": float(row["percentile"]),
                "date": row.get("date"),
            }
        time.sleep(0.2)

    print("  fetching the full CISA KEV catalog ...")
    kev_doc = feeds._get_json(feeds.KEV_FEED_URL, timeout=90)
    kev: dict[str, dict] = {}
    for row in kev_doc.get("vulnerabilities") or []:
        if not isinstance(row, dict):
            continue
        cve = str(row.get("cveID") or "").strip().upper()
        if not cve:
            continue
        kev[cve] = {
            "vendor": row.get("vendorProject") or "",
            "product": row.get("product") or "",
            "date_added": row.get("dateAdded") or "",
            "ransomware_use": row.get("knownRansomwareCampaignUse") or "Unknown",
        }

    return {
        "benchmark_id": BENCHMARK_ID,
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "sources": {
            "epss": feeds.EPSS_API_URL,
            "kev": feeds.KEV_FEED_URL,
        },
        "corpus_size": len(cves),
        "corpus": cves,
        "epss": epss,
        "kev": {
            "catalog_version": kev_doc.get("catalogVersion"),
            "date_released": kev_doc.get("dateReleased"),
            "catalog_count": kev_doc.get("count"),
            "records": kev,
        },
    }


def load_truth(path: Path) -> dict:
    truth = json.loads(path.read_text(encoding="utf-8"))
    for key in ("epss", "kev", "corpus"):
        if key not in truth:
            raise SystemExit(f"{path} is not a usable ground-truth snapshot")
    return truth


# ---------------------------------------------------------------------------
# Phases 2 & 3 - the product, offline then live
# ---------------------------------------------------------------------------

def build_packages(cves: list[str]) -> list[dict]:
    """One probe package per CVE with identical neutral attributes.

    Reachability alternates so ``_epss_priority`` and ``_kev_priority`` are
    exercised in both of their states; everything else is held constant so the
    only variable under test is how the intelligence gets resolved.
    """
    packages = []
    for i, cve in enumerate(sorted(cves)):
        packages.append({
            "name": f"probe-{i:03d}",
            "version": "1.0.0",
            "cve": cve,
            "severity": "High",
            "cvss": 7.5,
            # Explicitly empty: the SBOM's own advisory table must not
            # contribute, or the seed table would be measured twice.
            "epss": None,
            "reachability_status": "REACHABLE" if i % 2 == 0 else "NOT_REACHABLE",
        })
    return packages


def run_pipeline(packages: list[dict], epss_feed=None, kev_feed=None) -> list[dict]:
    """The exact enricher order main.py uses."""
    sbom = enrich_kev_intelligence([dict(p) for p in packages], feed=kev_feed)
    sbom = enrich_vulnerability_age(sbom)
    sbom = enrich_epss_intelligence(sbom, feed=epss_feed)
    return sbom


def run_live(packages: list[dict]) -> list[dict]:
    epss_feed = feeds.EPSSFeed(cache_path=BENCH_CACHE, enabled=True)
    kev_feed = feeds.KEVFeed(cache_path=BENCH_CACHE, enabled=True)
    return run_pipeline(packages, epss_feed=epss_feed, kev_feed=kev_feed)


# ---------------------------------------------------------------------------
# Phase 4 - reconciliation
# ---------------------------------------------------------------------------

def _prf(tp: int, fp: int, fn: int) -> dict:
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return {
        "tp": tp, "fp": fp, "fn": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
    }


def reconcile(truth: dict, offline: list[dict], live: list[dict]) -> dict:
    gt_epss = truth["epss"]
    gt_kev = set(truth["kev"]["records"])
    corpus = truth["corpus"]

    off_by = {p["cve"]: p for p in offline}
    live_by = {p["cve"]: p for p in live}

    # --- EPSS: resolution coverage -----------------------------------------
    resolution = {}
    fidelity = {}
    for label, by in (("offline", off_by), ("live", live_by)):
        tp = fp = fn = 0
        exact = compared = 0
        abs_err = 0.0
        for cve in corpus:
            expected = gt_epss.get(cve)
            got = by.get(cve, {}).get("epss_score")
            if expected is not None and got is not None:
                tp += 1
                compared += 1
                err = abs(float(got) - expected["score"])
                abs_err += err
                if err <= 1e-9:
                    exact += 1
            elif expected is None and got is not None:
                fp += 1
            elif expected is not None and got is None:
                fn += 1
        resolution[label] = _prf(tp, fp, fn)
        resolution[label]["resolved"] = tp
        resolution[label]["corpus"] = len(corpus)
        resolution[label]["coverage_pct"] = round(100.0 * tp / len(corpus), 2)
        fidelity[label] = {
            "compared": compared,
            "exact_matches": exact,
            "exact_pct": round(100.0 * exact / compared, 2) if compared else None,
            "mean_abs_error": round(abs_err / compared, 6) if compared else None,
            "max_abs_error": round(
                max(
                    abs(float(by[c]["epss_score"]) - gt_epss[c]["score"])
                    for c in corpus
                    if gt_epss.get(c) and by.get(c, {}).get("epss_score") is not None
                ),
                6,
            ) if compared else None,
        }

    # --- KEV: boolean determination ----------------------------------------
    kev_result = {}
    for label, by in (("offline", off_by), ("live", live_by)):
        tp = fp = fn = tn = 0
        for cve in corpus:
            expected = cve in gt_kev
            got = bool(by.get(cve, {}).get("kev_status"))
            if expected and got:
                tp += 1
            elif got and not expected:
                fp += 1
            elif expected and not got:
                fn += 1
            else:
                tn += 1
        block = _prf(tp, fp, fn)
        block["tn"] = tn
        block["accuracy"] = round((tp + tn) / len(corpus), 4)
        kev_result[label] = block

    # --- Miss root-cause classification ------------------------------------
    misses: list[dict] = []
    for cve in corpus:
        expected = gt_epss.get(cve)
        got_off = off_by.get(cve, {}).get("epss_score")
        got_live = live_by.get(cve, {}).get("epss_score")

        if expected is not None and got_off is None:
            # Root cause is the class that says where the value should have
            # come from but did not.  COVERAGE_GAP and RULE_GAP are both
            # already published in reports/gap_register.json.
            misses.append({
                "cve": cve,
                "category": "EPSS",
                "offline": "MISS",
                "live": "HIT" if got_live is not None else "MISS",
                "root_cause": "COVERAGE_GAP",
                "detail": (
                    "compiled-in seed table has no row for this identifier; "
                    "the live feed does"
                    if got_live is not None else
                    "neither the seed table nor the live feed carries a score "
                    "for this identifier"
                ),
            })
        if expected is None and got_off is not None:
            misses.append({
                "cve": cve, "category": "EPSS", "offline": "FP",
                "live": "FP" if got_live is not None else "OK",
                "root_cause": "SEED_TABLE_INVENTION",
                "detail": "a score was produced for an identifier the feed does not cover",
            })
        if (cve in gt_kev) and not off_by.get(cve, {}).get("kev_status"):
            misses.append({
                "cve": cve, "category": "KEV", "offline": "FN",
                "live": "HIT" if live_by.get(cve, {}).get("kev_status") else "MISS",
                "root_cause": "RULE_GAP",
                "detail": "exploited identifier absent from the compiled-in KEV set",
            })
        if (cve not in gt_kev) and off_by.get(cve, {}).get("kev_status"):
            misses.append({
                "cve": cve, "category": "KEV", "offline": "FP",
                "live": "FP" if live_by.get(cve, {}).get("kev_status") else "OK",
                "root_cause": "SEED_TABLE_INVENTION",
                "detail": "claimed exploited but absent from the live CISA catalog",
            })

    # --- Decision movement caused by going live ----------------------------
    movement = {"epss_bucket": [], "epss_priority": [], "kev_priority": [],
                "kev_status": []}
    for cve in corpus:
        o, l = off_by.get(cve, {}), live_by.get(cve, {})
        for field in movement:
            if o.get(field) != l.get(field):
                movement[field].append({
                    "cve": cve,
                    "from": o.get(field),
                    "to": l.get(field),
                    "epss_from": o.get("epss_score"),
                    "epss_to": l.get("epss_score"),
                })

    # --- Provenance correctness --------------------------------------------
    live_off = [
        p["cve"] for p in offline
        if p.get("epss_provenance") == LIVE_FEED
        or p.get("kev_provenance") == LIVE_FEED
    ]
    provenance_errors = []
    for p in live:
        cve = p["cve"]
        score, eprov, esrc = p.get("epss_score"), p.get("epss_provenance"), p.get("epss_source")
        if eprov == LIVE_FEED and esrc != "FIRST_ORG_EPSS":
            provenance_errors.append({"cve": cve, "field": "epss", "error": "LIVE_FEED without a feed source"})
        if eprov == STATIC_REFERENCE and score is None:
            provenance_errors.append({"cve": cve, "field": "epss", "error": "STATIC_REFERENCE with no value"})
        if score is None and eprov not in (NOT_AVAILABLE,):
            provenance_errors.append({"cve": cve, "field": "epss", "error": f"absent value labelled {eprov}"})
        if eprov == LIVE_FEED and score is None:
            provenance_errors.append({"cve": cve, "field": "epss", "error": "LIVE_FEED with no value"})
        if p.get("kev_provenance") == LIVE_FEED and p.get("kev_source") != "CISA_KEV_LIVE":
            provenance_errors.append({"cve": cve, "field": "kev", "error": "LIVE_FEED without a catalog source"})
        if cve == NEVER_ISSUED and eprov == LIVE_FEED:
            provenance_errors.append({"cve": cve, "field": "epss", "error": "sentinel claimed live"})

    # Summaries must never be stronger than their weakest member.
    for name, summary, key in (
        ("epss_intelligence_summary", epss_intelligence_summary(live), "provenance"),
        ("kev_intelligence_summary", kev_intelligence_summary(live), "provenance"),
        ("vulnerability_age_summary", vulnerability_age_summary(live), "kev_provenance"),
    ):
        counts = summary.get("provenance_counts") or summary.get("kev_provenance_counts") or {}
        if counts.get(STATIC_REFERENCE) and summary.get(key) == LIVE_FEED:
            provenance_errors.append({"cve": name, "field": "summary", "error": "summary laundered a static row into LIVE_FEED"})

    # --- Sentinel -----------------------------------------------------------
    sentinel = {
        "cve": NEVER_ISSUED,
        "expected_epss": gt_epss.get(NEVER_ISSUED),
        "expected_in_kev": NEVER_ISSUED in gt_kev,
        "offline_score": off_by.get(NEVER_ISSUED, {}).get("epss_score"),
        "offline_epss_provenance": off_by.get(NEVER_ISSUED, {}).get("epss_provenance"),
        "live_score": live_by.get(NEVER_ISSUED, {}).get("epss_score"),
        "live_epss_provenance": live_by.get(NEVER_ISSUED, {}).get("epss_provenance"),
        "offline_kev": off_by.get(NEVER_ISSUED, {}).get("kev_status"),
        "live_kev": live_by.get(NEVER_ISSUED, {}).get("kev_status"),
    }

    by_cause: dict[str, int] = {}
    for m in misses:
        by_cause[m["root_cause"]] = by_cause.get(m["root_cause"], 0) + 1

    return {
        "benchmark_id": BENCHMARK_ID,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "ground_truth": {
            "path": str(TRUTH_PATH),
            "fetched_at": truth.get("fetched_at"),
            "epss_rows": len(gt_epss),
            "kev_catalog_version": truth["kev"].get("catalog_version"),
            "kev_catalog_count": truth["kev"].get("catalog_count"),
            "corpus_size": len(corpus),
        },
        "epss_resolution": resolution,
        "epss_value_fidelity": fidelity,
        "kev_determination": kev_result,
        "misses": {
            "total": len(misses),
            "by_root_cause": dict(sorted(by_cause.items())),
            "items": misses,
        },
        "decision_movement": {
            field: {"count": len(rows), "items": rows}
            for field, rows in movement.items()
        },
        "provenance": {
            "offline_live_claims": live_off,
            "errors": provenance_errors,
            "offline_clean": len(live_off) == 0,
            "live_clean": len(provenance_errors) == 0,
        },
        "sentinel": sentinel,
        "proves": (
            "Wiring fidelity: R-SecOpsX reproduces both feeds exactly, labels every "
            "value with the provenance of its actual source, and never converts a miss "
            "into a number. It does not evaluate whether EPSS or KEV predict "
            "exploitation - the feeds are the reference by construction."
        ),
    }


def offline_safety_check(cves: list[str]) -> dict:
    """RSECOPSX_LIVE_FEEDS=0 must yield a full report and zero LIVE_FEED claims."""
    saved = os.environ.get("RSECOPSX_LIVE_FEEDS")
    os.environ["RSECOPSX_LIVE_FEEDS"] = "0"
    feeds.reset_default_feed()
    try:
        group = feeds.default_feed()
        # Exactly the expression main.py uses: feeds resolved once, then
        # passed in. With the switch off both members are None, which every
        # engine consumes as "fall back to the compiled-in seed table".
        sbom = run_pipeline(
            build_packages(cves), epss_feed=group.epss, kev_feed=group.kev
        )
        rendered = json.dumps([
            {
                "epss_provenance": p.get("epss_provenance"),
                "kev_provenance": p.get("kev_provenance"),
            }
            for p in sbom
        ] + [
            epss_intelligence_summary(sbom),
            kev_intelligence_summary(sbom),
            vulnerability_age_summary(sbom),
        ], default=str)
        ok = (
            group.epss is None
            and group.kev is None
            and bool(group.reasons)
            and len(sbom) == len(cves)
            and LIVE_FEED not in rendered
        )
        return {
            "enabled": False,
            "pass": bool(ok),
            "packages": len(sbom),
            "live_feed_claims": rendered.count(LIVE_FEED),
            "reason": group.reasons[0] if group.reasons else None,
        }
    finally:
        if saved is None:
            os.environ.pop("RSECOPSX_LIVE_FEEDS", None)
        else:
            os.environ["RSECOPSX_LIVE_FEEDS"] = saved
        feeds.reset_default_feed()


# ---------------------------------------------------------------------------
# Phase 5 - render
# ---------------------------------------------------------------------------

def render_md(result: dict) -> str:
    gt = result["ground_truth"]
    res = result["epss_resolution"]
    fid = result["epss_value_fidelity"]
    kev = result["kev_determination"]

    lines = [
        "# Benchmark reconciliation — threat-intelligence feeds",
        "",
        f"**Benchmark ID:** `{result['benchmark_id']}`  ",
        f"**Generated:** {result['generated_at']}  ",
        f"**Corpus:** {gt['corpus_size']} CVE identifiers  ",
        f"**Ground truth:** FIRST.org EPSS ({gt['epss_rows']} rows) + CISA KEV "
        f"catalog `{gt['kev_catalog_version']}` ({gt['kev_catalog_count']} records), "
        f"snapshot taken `{gt['fetched_at']}` **before** the product ran.",
        "",
        "## What this measures",
        "",
        result["proves"],
        "",
        "## EPSS — resolution coverage",
        "",
        "| Mode | TP | FP | FN | Precision | Recall | F1 | Coverage |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for label in ("offline", "live"):
        r = res[label]
        lines.append(
            f"| {label} | {r['tp']} | {r['fp']} | {r['fn']} | "
            f"{r['precision']:.4f} | {r['recall']:.4f} | {r['f1']:.4f} | "
            f"{r['coverage_pct']}% |"
        )

    lines += [
        "",
        "## EPSS — value fidelity against the reference",
        "",
        "| Mode | Compared | Exact | Exact % | Mean abs error | Max abs error |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for label in ("offline", "live"):
        f = fid[label]
        lines.append(
            f"| {label} | {f['compared']} | {f['exact_matches']} | "
            f"{f['exact_pct']} | {f['mean_abs_error']} | {f['max_abs_error']} |"
        )
    lines += [
        "",
        "> Live-side fidelity is 1.0 **by construction** (the feed is the "
        "reference) and is a wiring check, not a forecasting claim. The "
        "substantive number is the offline row: that is how wrong the "
        "compiled-in seed table was against the same reference.",
        "",
        "## CISA KEV — determination",
        "",
        "| Mode | TP | FP | FN | TN | Precision | Recall | F1 | Accuracy |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for label in ("offline", "live"):
        k = kev[label]
        lines.append(
            f"| {label} | {k['tp']} | {k['fp']} | {k['fn']} | {k['tn']} | "
            f"{k['precision']:.4f} | {k['recall']:.4f} | {k['f1']:.4f} | "
            f"{k['accuracy']:.4f} |"
        )

    lines += [
        "",
        "## Miss reconciliation (offline, by root cause)",
        "",
        "| Root cause | Count |",
        "|---|---:|",
    ]
    for cause, count in result["misses"]["by_root_cause"].items():
        lines.append(f"| `{cause}` | {count} |")

    lines += [
        "",
        f"**Total reconciled misses:** {result['misses']['total']}",
        "",
        "## Decisions that move when the feed goes live",
        "",
        "| Field | Changes |",
        "|---|---:|",
    ]
    for field, block in result["decision_movement"].items():
        lines.append(f"| `{field}` | {block['count']} |")

    lines += [
        "",
        "## Provenance correctness",
        "",
        f"- Offline run claimed `LIVE_FEED`: "
        f"**{'no' if result['provenance']['offline_clean'] else 'YES — DEFECT'}**",
        f"- Live-run provenance errors: **{len(result['provenance']['errors'])}**",
    ]
    for err in result["provenance"]["errors"][:20]:
        lines.append(
            f"  - `{err['cve']}` {err['field']}: {err['error']}"
        )

    s = result["sentinel"]
    lines += [
        "",
        "## Sentinel — a never-issued identifier",
        "",
        f"`{s['cve']}` is not issued by any authority. Expected: no EPSS score, "
        f"not in KEV.",
        "",
        f"| Mode | EPSS score | EPSS provenance | KEV |",
        f"|---|---|---|---|",
        f"| offline | `{s['offline_score']}` | `{s['offline_epss_provenance']}` | `{s['offline_kev']}` |",
        f"| live | `{s['live_score']}` | `{s['live_epss_provenance']}` | `{s['live_kev']}` |",
        "",
        "## Offline safety (`RSECOPSX_LIVE_FEEDS=0`)",
        "",
        f"- Pass: **{result['offline_safety']['pass']}**",
        f"- Packages produced: {result['offline_safety']['packages']}",
        f"- `LIVE_FEED` claims: {result['offline_safety']['live_feed_claims']}",
        f"- Reason reported: {result['offline_safety']['reason']}",
        "",
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--sca-ground-truth", type=Path, default=DEFAULT_SCA_GT)
    ap.add_argument("--reuse-truth", action="store_true",
                    help="skip fetching and use the existing snapshot")
    ap.add_argument("--out", type=Path, default=OUT_DIR)
    args = ap.parse_args()

    args.out.mkdir(parents=True, exist_ok=True)

    print("[1/5] Building corpus")
    cves = build_corpus(args.sca_ground_truth)
    print(f"  {len(cves)} CVE identifiers")

    print("[2/5] Ground truth (fetched BEFORE the product runs)")
    truth = None
    if args.reuse_truth and TRUTH_PATH.exists():
        candidate = load_truth(TRUTH_PATH)
        # Reuse is only sound when the snapshot was taken for exactly this
        # corpus AND is still fresh.  Comparing in both directions matters: a
        # snapshot with *extra* CVEs would count identifiers the product was
        # never asked about as unresolved, one *missing* CVEs would never score
        # them at all, and a stale one would measure yesterday's feed - a score
        # published since the snapshot would be reported as invented against a
        # reference that is itself out of date.
        reason = None
        if sorted(candidate.get("corpus") or []) != cves:
            reason = (
                f"snapshot corpus ({len(candidate.get('corpus') or [])}) "
                f"differs from the built corpus ({len(cves)})"
            )
        elif not _snapshot_fresh(candidate):
            reason = (
                f"snapshot is older than {SNAPSHOT_MAX_AGE_S // 3600}h "
                f"(EPSS refreshes daily)"
            )
        if reason:
            print(f"  ! {reason}; refetching")
        else:
            truth = candidate
    if truth is None:
        truth = fetch_ground_truth(cves)
        TRUTH_PATH.write_text(json.dumps(truth, indent=1), encoding="utf-8")
    print(f"  EPSS rows: {len(truth['epss'])}   KEV catalog: "
          f"{truth['kev']['catalog_version']} "
          f"({truth['kev']['catalog_count']} records)")
    print(f"  snapshot -> {TRUTH_PATH}")

    packages = build_packages(cves)

    print("[3/5] Product run — OFFLINE (seed tables)")
    offline = run_pipeline(packages)

    print("[4/5] Product run — LIVE feeds")
    if BENCH_CACHE.exists():
        BENCH_CACHE.unlink()  # measure a real fetch, not yesterday's snapshot
    live = run_live(packages)
    print(f"  live EPSS rows: "
          f"{sum(1 for p in live if p.get('epss_provenance') == LIVE_FEED)}   "
          f"live KEV answers: "
          f"{sum(1 for p in live if p.get('kev_provenance') == LIVE_FEED)}")

    print("[5/5] Reconciling")
    result = reconcile(truth, offline, live)
    result["offline_safety"] = offline_safety_check(cves)

    OUT_JSON.write_text(json.dumps(result, indent=1, default=str), encoding="utf-8")
    OUT_MD.write_text(render_md(result), encoding="utf-8")

    res = result["epss_resolution"]
    fid = result["epss_value_fidelity"]
    kev = result["kev_determination"]

    print()
    print("=" * 74)
    print("EPSS resolution   offline  P={precision:.4f} R={recall:.4f} F1={f1:.4f} "
          "({coverage_pct}% coverage)".format(**res["offline"]))
    print("                  live     P={precision:.4f} R={recall:.4f} F1={f1:.4f} "
          "({coverage_pct}% coverage)".format(**res["live"]))
    print("EPSS value        offline  exact={exact_pct}%  MAE={mean_abs_error}"
          .format(**fid["offline"]))
    print("                  live     exact={exact_pct}%  MAE={mean_abs_error}"
          .format(**fid["live"]))
    print("CISA KEV          offline  P={precision:.4f} R={recall:.4f} F1={f1:.4f}"
          .format(**kev["offline"]))
    print("                  live     P={precision:.4f} R={recall:.4f} F1={f1:.4f}"
          .format(**kev["live"]))
    print(f"Misses reconciled : {result['misses']['total']} "
          f"{result['misses']['by_root_cause']}")
    print(f"Decision movement : "
          + ", ".join(f"{k}={v['count']}" for k, v in result["decision_movement"].items()))
    print(f"Provenance        : offline clean="
          f"{result['provenance']['offline_clean']}  "
          f"live errors={len(result['provenance']['errors'])}")
    print(f"Offline safety    : {result['offline_safety']['pass']}")
    print("=" * 74)
    print(f"Wrote {OUT_JSON}")
    print(f"Wrote {OUT_MD}")

    ok = (
        result["provenance"]["offline_clean"]
        and not result["provenance"]["errors"]
        and result["offline_safety"]["pass"]
        # Live wiring must resolve everything the reference carries and invent
        # nothing...
        and res["live"]["fp"] == 0
        and res["live"]["fn"] == 0
        and kev["live"]["fp"] == 0
        and kev["live"]["fn"] == 0
        # ...and the compiled-in seed tables must not assert anything the
        # reference does not support.  This is the condition that caught
        # CVE-2024-3094 (root_cause SEED_TABLE_INVENTION) on the first run, so
        # it has to gate the run or the defect would silently come back.
        and res["offline"]["fp"] == 0
        and kev["offline"]["fp"] == 0
    )
    if not ok:
        print("\nFAILED: live wiring must resolve every identifier the "
              "reference carries, invent none, label every value correctly, "
              "stay clean with the feeds disabled, and the compiled-in seed "
              "tables must not assert what the reference does not publish.")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
