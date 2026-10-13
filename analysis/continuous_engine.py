"""Continuous re-scan engine (Phase 5.3).

Gap-plan row 5.3: "scheduled re-scan + EPSS/KEV re-evaluation of stored
findings", verify: "re-run picks up new CVEs for old deps".

Two questions answered WITHOUT re-scanning code, from a stored
``clean_report.json``:

1. **Advisory re-check** ("new CVEs for old deps"): the stored SBOM
   inventory is re-enriched through the SAME advisory path a fresh scan
   uses (``enrich_packages_with_external_vulns`` → ``query_osv_batch``),
   and the fresh advisory identities are diffed against the stored
   ones. Identity = the full id+alias set on BOTH sides, so a re-issued
   advisory that merely gained an alias is NOT counted new (the V2.2
   lesson: one advisory can carry both a GHSA and several CVE ids).

2. **Intel re-evaluation** ("did anything get worse"): every stored
   vulnerability identity is checked against the CURRENT CISA KEV
   catalog and EPSS scores. Both sources are covered, because in this
   tool's model SCA CVEs live on ``sbom[].vulnerabilities`` while
   SAST/IaC/secrets findings live in ``findings[]`` — evaluating only
   one of them would silently evaluate nothing for the other.

Honesty properties:

* **Severity is never rewritten by intel.** Exploitation signals
  escalate the human's triage queue, not the scanner's recorded
  assessment; the summary says so in prose, because a consumer reading
  only ``severity`` would otherwise miss the escalation.
* A KEV hit is "newly" only when the stored report did not already
  record it (packages carry scan-time ``kev_status``; a hit the scan
  already knew is not news).
* A KEV miss against a FETCHED catalog is evidence (provenance
  LIVE_FEED on both branches — the whole catalog was consulted); a miss
  with only the seed table is an assumption (STATIC_REFERENCE). The
  distinction travels into the summary, copied from the KEV engine's
  own semantics.
* Advisory re-check failures are disclosed, never rendered as "no new
  CVEs" — "we could not ask" and "nothing new" are different answers
  and the artifact keeps them apart.
* GHSA-only identities are counted and disclosed: KEV and EPSS are
  CVE-keyed, so an advisory with no CVE alias cannot be re-evaluated.

CLI::

    python -m analysis.continuous_engine --report <clean_report.json>
        [--out DIR] [--offline] [--no-advisories] [--json]

Exit codes: 0 = re-evaluation completed (zero signals is still a
completed evaluation); 1 = the report could not be read or parsed.
"""
from __future__ import annotations

import argparse
import copy
import json
import sys
from pathlib import Path
from typing import Any

from analysis.epss_intelligence_engine import _epss_bucket
from analysis.intelligence_provenance import (
    LIVE_FEED,
    NOT_AVAILABLE,
    STATIC_REFERENCE,
)
from analysis.kev_intelligence_engine import (
    GHSA_TO_CVE_ALIAS,
    KNOWN_EXPLOITED_CVES,
    normalize_to_cve,
)
from scanner.vulnerability_intel import (
    ADVISORY_SERVICE_STATUS,
    enrich_packages_with_external_vulns,
)

CONTINUOUS_SCHEMA = "rsecopsx.continuous/v1"

# Score >= 0.50 — the two top EPSS buckets from the scan-time engine.
EPSS_HIGH_THRESHOLD = 0.50

_SEVERITY_POLICY = (
    "Intel signals never rewrite a finding's severity here: KEV/EPSS "
    "escalate the human triage queue, not the scanner's recorded "
    "assessment. Act on the signals, keep the audit trail."
)

# The fields a stored finding may carry a vulnerability identity in.
# SCA findings often keep the GHSA in rule_id while the CVE lives (or
# does not live) elsewhere — all candidates are consulted, and the
# resolver only ever returns a CVE (directly or through the GHSA alias
# map), so widening the candidates cannot fabricate identity.
_IDENTITY_KEYS = (
    "cve",
    "primary_vulnerability_id",
    "source_vulnerability_id",
    "advisory_id",
    "vulnerability_id",
    "id",
    "rule_id",
)


# ---------------------------------------------------------------------------
# Shared signal helpers (one semantics, two sources).
# ---------------------------------------------------------------------------

def _catalog_state(kev_feed: Any) -> tuple[bool, str, str]:
    """(catalog_ok, catalog_version, date_released), fail-safe."""
    catalog_ok = False
    if kev_feed is not None:
        try:
            catalog_ok = bool(kev_feed.catalog_loaded)
        except Exception:  # pragma: no cover - defensive
            catalog_ok = False

    version = released = ""
    if catalog_ok:
        try:
            version = kev_feed.catalog_version or ""
            released = kev_feed.date_released or ""
        except Exception:  # pragma: no cover - defensive
            version = released = ""
    return catalog_ok, version, released


def _kev_signal(cve: str | None, kev_feed: Any,
                catalog_ok: bool) -> tuple[bool, dict[str, Any] | None, str]:
    """(is_kev, record-dict|None, provenance) — seed fallback included."""
    provenance = LIVE_FEED if catalog_ok else STATIC_REFERENCE
    if not cve:
        return False, None, provenance

    live = kev_feed.lookup(cve) if (kev_feed and catalog_ok) else None
    record = live or KNOWN_EXPLOITED_CVES.get(cve)
    if record is None:
        return False, None, provenance

    if isinstance(record, dict):
        fields = {
            "date_added": record.get("kev_added_date"),
            "due_date": record.get("due_date"),
            "ransomware_use": record.get("ransomware_use"),
        }
    else:
        fields = {
            "date_added": record.date_added,
            "due_date": record.due_date,
            "ransomware_use": record.ransomware_use,
        }
    return True, {"cve": cve, **fields}, provenance


def _intel_entry(cve: str | None, *, kev_feed: Any, catalog_ok: bool,
                 scores: dict[str, Any]) -> dict[str, Any]:
    is_kev, kev_record, kev_prov = _kev_signal(cve, kev_feed, catalog_ok)

    entry: dict[str, Any] = {
        "cve": cve,
        "kev": is_kev,
        "kev_provenance": kev_prov,
        "epss_score": None,
        "epss_percentile": None,
        "epss_bucket": _epss_bucket(None),
        "epss_provenance": NOT_AVAILABLE,
    }
    if is_kev:
        entry["kev_record"] = kev_record

    score = scores.get(cve) if cve else None
    if score is not None:
        entry["epss_score"] = score.score
        entry["epss_percentile"] = score.percentile
        entry["epss_bucket"] = _epss_bucket(score.score)
        entry["epss_provenance"] = score.provenance
    return entry


def _batch_scores(cves: list[str], epss_feed: Any) -> dict[str, Any]:
    if epss_feed is None or not cves:
        return {}
    try:
        return epss_feed.scores_for(cves) or {}
    except Exception as exc:  # pragma: no cover - defensive
        try:
            epss_feed.last_error = f"{type(exc).__name__}: {exc}"
        except Exception:
            pass
        return {}


def _epss_as_of(scores: dict[str, Any]) -> str | None:
    for score in scores.values():
        if getattr(score, "as_of", None):
            return score.as_of
    return None


# ---------------------------------------------------------------------------
# Source 1: findings (SAST / IaC / secrets live here).
# ---------------------------------------------------------------------------

def _finding_candidate_ids(finding: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for key in _IDENTITY_KEYS:
        value = finding.get(key)
        if value:
            text = str(value).strip()
            if text and text not in values:
                values.append(text)
    return values


def _finding_cve(finding: dict[str, Any]) -> str | None:
    """CVE resolution over the finding's own candidate keys.

    Same two-branch logic as the KEV engine's ``normalize_to_cve`` (a
    CVE-prefixed id, or a GHSA the alias map resolves) — applied over
    the finding-level candidates, which include ``rule_id``: SCA findings
    often keep the advisory id there, and the package-level candidate
    list does not know that key.
    """
    for value in _finding_candidate_ids(finding):
        upper = value.upper()
        if upper.startswith("CVE-"):
            return upper
        if upper.startswith("GHSA-") and value in GHSA_TO_CVE_ALIAS:
            return GHSA_TO_CVE_ALIAS[value]
    return None


def _is_ghsa_only(candidates: list[str], cve: str | None) -> bool:
    """True when the finding carries a GHSA that no CVE alias resolves."""
    if cve:
        return False
    for value in candidates:
        upper = value.upper()
        if upper.startswith("GHSA-") and value not in GHSA_TO_CVE_ALIAS:
            return True
    return False


def reevaluate_findings(
    findings: list[dict[str, Any]],
    *,
    kev_feed: Any = None,
    epss_feed: Any = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Re-evaluate stored findings against current KEV/EPSS intel.

    Returns ``(findings_copy, summary)``. The caller's findings are never
    mutated (deepcopy contract, same as every enrichment in this repo).
    """
    catalog_ok, catalog_version, date_released = _catalog_state(kev_feed)
    working = copy.deepcopy(findings)

    # Pass 1: identities, then one batched EPSS call for every CVE seen.
    identities: list[str | None] = []
    cves: list[str] = []
    for finding in working:
        if not isinstance(finding, dict):
            identities.append(None)
            continue
        cve = _finding_cve(finding)
        identities.append(cve)
        if cve and cve not in cves:
            cves.append(cve)
    scores = _batch_scores(cves, epss_feed)

    newly_kev: list[dict[str, Any]] = []
    epss_high: list[dict[str, Any]] = []
    with_cve = 0
    ghsa_only = 0

    # Pass 2: attach per finding.
    for finding, cve in zip(working, identities):
        if not isinstance(finding, dict):
            continue

        candidates = _finding_candidate_ids(finding)
        if cve:
            with_cve += 1
        elif _is_ghsa_only(candidates, cve):
            ghsa_only += 1

        entry = _intel_entry(cve, kev_feed=kev_feed, catalog_ok=catalog_ok,
                             scores=scores)
        finding["intel_reevaluation"] = entry

        if not cve:
            continue
        ref = {
            "cve": cve,
            "rule_id": finding.get("rule_id"),
            "file": finding.get("file") or finding.get("path"),
            "source": "finding",
        }
        # "Newly" is relative to the stored report: a finding the scan
        # already marked exploited is not news.
        already_known = bool(
            finding.get("kev_status") or finding.get("actively_exploited"))
        if entry["kev"] and not already_known:
            newly_kev.append({**ref, **(entry.get("kev_record") or {})})

        stored_epss = _safe_float(finding.get("epss_score"))
        if (entry["epss_score"] is not None
                and entry["epss_score"] >= EPSS_HIGH_THRESHOLD
                and (stored_epss is None
                     or stored_epss < EPSS_HIGH_THRESHOLD)):
            epss_high.append({
                **ref,
                "score": entry["epss_score"],
                "percentile": entry["epss_percentile"],
                "bucket": entry["epss_bucket"],
            })

    return working, {
        "findings": len(findings),
        "with_cve_identity": with_cve,
        "no_cve_identity": len(findings) - with_cve,
        "ghsa_only": ghsa_only,
        "kev_hits": newly_kev,
        "epss_high": epss_high,
        "provenance": {
            "kev": LIVE_FEED if catalog_ok else STATIC_REFERENCE,
            "epss": LIVE_FEED if scores else NOT_AVAILABLE,
        },
        "kev_catalog": (
            {"version": catalog_version, "date_released": date_released}
            if catalog_ok else None
        ),
        "epss_as_of": _epss_as_of(scores),
        "live_feeds_used": bool(catalog_ok) or bool(scores),
        "severity_policy": _SEVERITY_POLICY,
    }


# ---------------------------------------------------------------------------
# Source 2: SBOM packages (SCA CVEs live here, not in findings[]).
# ---------------------------------------------------------------------------

def reevaluate_sbom_packages(
    packages: list[dict[str, Any]],
    *,
    kev_feed: Any = None,
    epss_feed: Any = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Same signals, package source. Never mutates the caller's list."""
    catalog_ok, catalog_version, date_released = _catalog_state(kev_feed)
    working = copy.deepcopy(packages)

    identities: list[str | None] = []
    cves: list[str] = []
    for pkg in working:
        cve = normalize_to_cve(pkg) if isinstance(pkg, dict) else None
        identities.append(cve)
        if cve and cve not in cves:
            cves.append(cve)
    scores = _batch_scores(cves, epss_feed)

    newly_kev: list[dict[str, Any]] = []
    epss_high: list[dict[str, Any]] = []
    with_cve = 0

    for pkg, cve in zip(working, identities):
        if not isinstance(pkg, dict):
            continue
        if cve:
            with_cve += 1

        entry = _intel_entry(cve, kev_feed=kev_feed, catalog_ok=catalog_ok,
                             scores=scores)
        pkg["intel_reevaluation"] = entry
        if not cve:
            continue

        ref = {
            "cve": cve,
            "name": pkg.get("name"),
            "version": pkg.get("version"),
            "source": "package",
        }
        already_known = bool(
            pkg.get("kev_status") or pkg.get("actively_exploited"))
        if entry["kev"] and not already_known:
            newly_kev.append({**ref, **(entry.get("kev_record") or {})})

        stored_epss = _safe_float(pkg.get("epss_score"))
        if (entry["epss_score"] is not None
                and entry["epss_score"] >= EPSS_HIGH_THRESHOLD
                and (stored_epss is None
                     or stored_epss < EPSS_HIGH_THRESHOLD)):
            epss_high.append({
                **ref,
                "score": entry["epss_score"],
                "percentile": entry["epss_percentile"],
                "bucket": entry["epss_bucket"],
            })

    return working, {
        "packages": len(packages),
        "with_cve_identity": with_cve,
        "no_cve_identity": len(packages) - with_cve,
        "kev_hits": newly_kev,
        "epss_high": epss_high,
        "provenance": {
            "kev": LIVE_FEED if catalog_ok else STATIC_REFERENCE,
            "epss": LIVE_FEED if scores else NOT_AVAILABLE,
        },
        "kev_catalog": (
            {"version": catalog_version, "date_released": date_released}
            if catalog_ok else None
        ),
        "epss_as_of": _epss_as_of(scores),
        "live_feeds_used": bool(catalog_ok) or bool(scores),
    }


def _safe_float(value: Any) -> float | None:
    try:
        return float(value) if value is not None else None
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Advisory re-check ("new CVEs for old deps").
# ---------------------------------------------------------------------------

def _vuln_identity_set(vulns: Any) -> set[str]:
    """Every id + alias a package's stored advisories claim."""
    ids: set[str] = set()
    for vuln in vulns or []:
        if not isinstance(vuln, dict):
            continue
        for key in ("cve", "advisory_id", "id"):
            value = vuln.get(key)
            if value:
                ids.add(str(value).upper())
        for alias in (vuln.get("aliases") or []):
            if alias:
                ids.add(str(alias).upper())
    return ids


def _primary_id(vuln: dict[str, Any]) -> str | None:
    value = vuln.get("cve") or vuln.get("advisory_id") or vuln.get("id")
    return str(value).upper() if value else None


def recheck_advisories(packages: list[dict[str, Any]]) -> dict[str, Any]:
    """Diff fresh advisory identities against the stored ones.

    Uses the exact enrichment path a fresh scan uses, so "new CVEs for
    old deps" means what it says: same question, same answers, later.
    """
    queryable = [
        p for p in packages
        if isinstance(p, dict) and p.get("name")
    ]
    if not queryable:
        return {
            "checked": False,
            "error": "stored report carries no named SBOM packages",
            "packages_queried": 0,
            "packages_with_new_advisories": 0,
            "new_advisory_count": 0,
            "new_advisories": [],
        }

    fresh = copy.deepcopy(queryable)
    try:
        enrich_packages_with_external_vulns(fresh)
    except Exception as exc:  # pragma: no cover - defensive fail-open
        return {
            "checked": False,
            "error": f"{type(exc).__name__}: {exc}",
            "packages_queried": len(queryable),
            "packages_with_new_advisories": 0,
            "new_advisory_count": 0,
            "new_advisories": [],
        }

    new_advisories: list[dict[str, Any]] = []
    new_total = 0

    for stored, current in zip(queryable, fresh):
        known = _vuln_identity_set(stored.get("vulnerabilities"))
        fresh_vulns = [
            v for v in (current.get("vulnerabilities") or [])
            if isinstance(v, dict)
        ]

        added = []
        for vuln in fresh_vulns:
            primary = _primary_id(vuln)
            # A re-issued advisory that merely gained an alias keeps its
            # primary id, so it never lands here (V2.2 alias lesson).
            if primary and primary not in known:
                added.append({
                    "cve": vuln.get("cve"),
                    "advisory_id": vuln.get("advisory_id") or vuln.get("id"),
                    "severity": vuln.get("severity"),
                    "cvss": vuln.get("cvss"),
                })

        if added:
            new_total += len(added)
            new_advisories.append({
                "name": stored.get("name"),
                "version": stored.get("version"),
                "ecosystem": stored.get("ecosystem"),
                "new_advisories": added,
            })

    status = dict(ADVISORY_SERVICE_STATUS or {})
    return {
        "checked": True,
        "error": None,
        "packages_queried": len(queryable),
        "packages_with_new_advisories": len(new_advisories),
        "new_advisory_count": new_total,
        "new_advisories": new_advisories,
        "advisory_service": {
            "service": status.get("service", "OSV"),
            "available": status.get("available"),
            "queries_attempted": status.get("queries_attempted"),
            "queries_answered": status.get("queries_answered"),
            "from_cache": status.get("from_cache"),
            "skipped_unresolvable": status.get("skipped_unresolvable"),
            "failures": status.get("failures", []),
        },
        "note": (
            "Fresh advisory identities diffed against the stored report "
            "through the scan's own enrichment path; identity includes "
            "every id and alias, so a re-issued advisory is not new."
        ),
    }


# ---------------------------------------------------------------------------
# Assembly + CLI.
# ---------------------------------------------------------------------------

def _merge_intel_summaries(findings_s: dict, packages_s: dict) -> dict:
    """One intel block: both sources, hits tagged with their source."""
    def _prov(key: str) -> str:
        if findings_s["provenance"][key] == LIVE_FEED:
            return LIVE_FEED
        return packages_s["provenance"][key]

    return {
        "findings": findings_s["findings"],
        "with_cve_identity": findings_s["with_cve_identity"],
        "no_cve_identity": findings_s["no_cve_identity"],
        "ghsa_only": findings_s["ghsa_only"],
        "packages": packages_s["packages"],
        "packages_with_cve_identity": packages_s["with_cve_identity"],
        "packages_without_cve_identity": packages_s["no_cve_identity"],
        "kev_hits": findings_s["kev_hits"] + packages_s["kev_hits"],
        "epss_high": findings_s["epss_high"] + packages_s["epss_high"],
        "provenance": {"kev": _prov("kev"), "epss": _prov("epss")},
        "kev_catalog": findings_s["kev_catalog"] or packages_s["kev_catalog"],
        "epss_as_of": findings_s["epss_as_of"] or packages_s["epss_as_of"],
        "live_feeds_used": bool(findings_s["live_feeds_used"]
                                or packages_s["live_feeds_used"]),
        "severity_policy": _SEVERITY_POLICY,
    }


def build_continuous_report(
    payload: dict[str, Any],
    *,
    kev_feed: Any = None,
    epss_feed: Any = None,
    recheck: bool = True,
) -> dict[str, Any]:
    """Build the continuous re-evaluation artifact from a stored payload."""
    working = copy.deepcopy(payload)

    findings, findings_summary = reevaluate_findings(
        working.get("findings") or [],
        kev_feed=kev_feed,
        epss_feed=epss_feed,
    )
    working["findings"] = findings

    packages, packages_summary = reevaluate_sbom_packages(
        working.get("sbom") or [],
        kev_feed=kev_feed,
        epss_feed=epss_feed,
    )
    working["sbom"] = packages

    advisory_summary = (
        recheck_advisories(working.get("sbom") or [])
        if recheck else {
            "checked": False,
            "error": "advisory re-check disabled (--no-advisories)",
            "packages_queried": 0,
            "packages_with_new_advisories": 0,
            "new_advisory_count": 0,
            "new_advisories": [],
        }
    )

    working["continuous_reevaluation"] = {
        "schema": CONTINUOUS_SCHEMA,
        "generated_from": "clean_report.json",
        "intel_reevaluation": _merge_intel_summaries(
            findings_summary, packages_summary),
        "advisory_recheck": advisory_summary,
    }
    return working


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m analysis.continuous_engine",
        description=(
            "Re-evaluate a stored clean_report.json: new advisories for "
            "the old inventory + current KEV/EPSS signals per finding "
            "and per SBOM package."
        ),
    )
    parser.add_argument("--report", required=True,
                        help="clean_report.json (or the directory containing it)")
    parser.add_argument("--out", default=None,
                        help="output path (default: Security_Continuous.json "
                             "beside the report)")
    parser.add_argument("--offline", action="store_true",
                        help="seed tables only; never touch a live feed")
    parser.add_argument("--no-advisories", action="store_true",
                        help="skip the OSV re-check (intel re-evaluation only)")
    parser.add_argument("--json", action="store_true",
                        help="print the summary block to stdout")
    args = parser.parse_args(argv)

    report_path = Path(args.report)
    if report_path.is_dir():
        report_path = report_path / "clean_report.json"

    try:
        payload = json.loads(report_path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"continuous_engine: cannot read {report_path}: {exc}",
              file=sys.stderr)
        return 1

    if not isinstance(payload, dict):
        print("continuous_engine: report is not a JSON object",
              file=sys.stderr)
        return 1

    kev_feed = epss_feed = None
    feeds_blocked: list[str] = []
    if not args.offline:
        try:
            from analysis.live_intel_feeds import default_feed

            feeds = default_feed()
            kev_feed = feeds.kev
            epss_feed = feeds.epss
            feeds_blocked = list(getattr(feeds, "reasons", []) or [])
        except Exception as exc:  # pragma: no cover - defensive fail-open
            feeds_blocked = [f"{type(exc).__name__}: {exc}"]

    report = build_continuous_report(
        payload,
        kev_feed=kev_feed,
        epss_feed=epss_feed,
        recheck=not args.no_advisories,
    )
    block = report["continuous_reevaluation"]
    if feeds_blocked:
        block["feeds_blocked"] = feeds_blocked

    out_path = Path(args.out) if args.out else (
        report_path.parent / "Security_Continuous.json")
    out_path.write_text(
        json.dumps(report, indent=2, default=str), encoding="utf-8")

    intel = block["intel_reevaluation"]
    advisory = block["advisory_recheck"]
    print(f"continuous_engine: {intel['findings']} findings + "
          f"{intel['packages']} packages re-evaluated "
          f"({intel['with_cve_identity'] + intel['packages_with_cve_identity']} "
          f"with CVE identity); "
          f"newly KEV: {len(intel['kev_hits'])}; "
          f"EPSS >= {EPSS_HIGH_THRESHOLD}: {len(intel['epss_high'])}")
    if advisory.get("checked"):
        print(f"continuous_engine: {advisory['packages_queried']} packages "
              f"re-checked; new advisories: {advisory['new_advisory_count']} "
              f"on {advisory['packages_with_new_advisories']} package(s)")
    else:
        print(f"continuous_engine: advisory re-check not performed "
              f"({advisory.get('error')})")
    print(f"continuous_engine: wrote {out_path}")

    if args.json:
        print(json.dumps(block, indent=2, default=str))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
