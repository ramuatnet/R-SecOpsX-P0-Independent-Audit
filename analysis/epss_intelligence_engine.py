from __future__ import annotations

from collections import Counter

from analysis.intelligence_provenance import (
    LIVE_FEED,
    NOT_AVAILABLE,
    STATIC_REFERENCE,
)
from analysis.live_intel_feeds import EPSSFeed


STATIC_EPSS_SCORES = {
    "CVE-2021-44228": 0.975,
    "CVE-2021-45046": 0.920,
    "CVE-2022-22965": 0.970,
    "CVE-2018-18074": 0.042,
    "CVE-2017-18342": 0.089,
    "CVE-2021-23337": 0.021,
    "CVE-2021-3749": 0.013,
    "CVE-2022-24999": 0.010,
}


def _get_cve(pkg: dict) -> str | None:
    cve = pkg.get("cve") or pkg.get("primary_vulnerability_id")

    if not cve:
        return None

    cve = str(cve).strip().upper()

    if cve.startswith("CVE-"):
        return cve

    return None


def _epss_bucket(score: float | None) -> str:
    if score is None:
        return "UNKNOWN"

    if score >= 0.90:
        return "VERY_HIGH_EXPLOIT_PROBABILITY"

    if score >= 0.50:
        return "HIGH_EXPLOIT_PROBABILITY"

    if score >= 0.10:
        return "MODERATE_EXPLOIT_PROBABILITY"

    if score >= 0.01:
        return "LOW_EXPLOIT_PROBABILITY"

    return "VERY_LOW_EXPLOIT_PROBABILITY"


def _epss_priority(score: float | None, kev: bool, reachable: bool, severity: str) -> str:
    sev = str(severity or "").upper()

    if kev and reachable:
        return "P0_IMMEDIATE"

    if score is not None and score >= 0.90:
        return "P0_IMMEDIATE"

    if reachable and sev in {"CRITICAL", "HIGH"}:
        return "P1_HIGH"

    if score is not None and score >= 0.10:
        return "P2_MEDIUM"

    return "P3_STANDARD"


def _reachable(pkg: dict) -> bool:
    return str(pkg.get("reachability_status") or "").upper() == "REACHABLE"


def enrich_epss_intelligence(sbom: list[dict],
                             feed: EPSSFeed | None = None) -> list[dict]:
    """Resolve EPSS for every package.

    ``feed`` is deliberately opt-in (G-001): passing ``None`` keeps the engine
    purely local and deterministic, so unit tests and air-gapped callers never
    reach for the network implicitly.  :mod:`main` supplies
    :func:`analysis.live_intel_feeds.default_feed` when live feeds are enabled.

    Precedence is live > upstream-provided > seed table > absent, and the
    provenance follows the winner so a live number can never be relabelled as
    static, nor a seed-table number as live.
    """
    live: dict[str, object] = {}
    if feed is not None:
        try:
            wanted = [c for c in (_get_cve(dict(p)) for p in sbom) if c]
            live = feed.scores_for(wanted) if wanted else {}
        except Exception as exc:  # pragma: no cover - defensive
            # A feed must never break a scan; fall back to local resolution.
            try:
                feed.last_error = f"{type(exc).__name__}: {exc}"
            except Exception:
                pass
            live = {}

    enriched = []

    for pkg in sbom:
        item = dict(pkg)

        cve = _get_cve(item)
        existing = item.get("epss")
        upstream_provenance = item.get("epss_provenance")

        score = None
        provenance = None
        source = "NONE"
        as_of = None

        # 1) Live feed wins outright — it is the authoritative daily snapshot.
        hit = live.get(cve) if cve else None
        if hit is not None and getattr(hit, "score", None) is not None:
            score = float(hit.score)
            provenance = LIVE_FEED
            source = "FIRST_ORG_EPSS"
            as_of = hit.as_of
        else:
            # 2) An upstream engine already labelled this value; keep it.
            if upstream_provenance == LIVE_FEED and existing is not None:
                try:
                    score = float(existing)
                    provenance, source = LIVE_FEED, "FIRST_ORG_EPSS"
                    as_of = item.get("epss_as_of")
                except (TypeError, ValueError):
                    score = None

            # 3) The SBOM's compiled-in advisory table.
            if score is None and existing is not None:
                try:
                    score = float(existing)
                except (TypeError, ValueError):
                    score = None
                if score is not None:
                    provenance, source = STATIC_REFERENCE, "STATIC_TABLE"

            # 4) The compiled-in 8-CVE seed table.
            if score is None and cve:
                seed = STATIC_EPSS_SCORES.get(cve)
                if seed is not None:
                    score = float(seed)
                    provenance, source = STATIC_REFERENCE, "STATIC_TABLE"

        if score is None:
            provenance, source = NOT_AVAILABLE, "NONE"

        bucket = _epss_bucket(score)

        item["epss_score"] = score
        item["epss_bucket"] = bucket
        item["epss_priority"] = _epss_priority(
            score,
            bool(item.get("kev_status")),
            _reachable(item),
            item.get("severity"),
        )
        item["epss_method"] = (
            "LIVE_FIRST_ORG_EPSS_V1"
            if provenance == LIVE_FEED
            else ("STATIC_OFFLINE_EPSS_V1"
                  if score is not None else "EPSS_NOT_AVAILABLE")
        )
        # G-003: epss_method is the engine's internal code and no reporter ever
        # read it, so the reader could not tell an offline table from a live
        # FIRST.org feed.  epss_provenance is the surfaced honesty label.
        item["epss_provenance"] = provenance
        item["epss_source"] = source
        item["epss_as_of"] = as_of

        enriched.append(item)

    return enriched


def epss_intelligence_summary(sbom: list[dict]) -> dict:
    bucket_counter = Counter()
    priority_counter = Counter()
    provenance_counter = Counter()
    source_counter = Counter()
    as_of_values: list[str] = []

    total_vulnerable = 0
    known_epss = 0
    very_high = 0
    p0 = 0

    for pkg in sbom:
        if not (pkg.get("cve") or pkg.get("advisory_id")):
            continue

        total_vulnerable += 1

        bucket = pkg.get("epss_bucket", "UNKNOWN")
        priority = pkg.get("epss_priority", "UNKNOWN")

        bucket_counter[bucket] += 1
        priority_counter[priority] += 1

        provenance = pkg.get("epss_provenance")
        if pkg.get("epss_score") is not None:
            known_epss += 1
            if provenance:
                provenance_counter[str(provenance)] += 1
                if provenance == LIVE_FEED and pkg.get("epss_as_of"):
                    as_of_values.append(str(pkg["epss_as_of"]))
        elif provenance:
            provenance_counter[str(provenance)] += 1

        source = pkg.get("epss_source")
        if source:
            source_counter[str(source)] += 1

        if bucket == "VERY_HIGH_EXPLOIT_PROBABILITY":
            very_high += 1

        if priority == "P0_IMMEDIATE":
            p0 += 1

    # Worst-case wins: the summary may never claim a stronger provenance than
    # the weakest value it contains, otherwise one static row would be
    # laundered into an all-live headline.
    n_live = provenance_counter.get(LIVE_FEED, 0)
    n_static = provenance_counter.get(STATIC_REFERENCE, 0)
    if n_static:
        provenance = STATIC_REFERENCE
    elif n_live:
        provenance = LIVE_FEED
    else:
        provenance = NOT_AVAILABLE

    return {
        "total_vulnerable_packages": total_vulnerable,
        "known_epss_packages": known_epss,
        "very_high_exploit_probability": very_high,
        "p0_immediate_packages": p0,
        "epss_buckets": dict(bucket_counter),
        "epss_priority_counts": dict(priority_counter),
        "summary_status": (
            "LIVE_FIRST_ORG_EPSS_V1"
            if provenance == LIVE_FEED
            else "STATIC_OFFLINE_EPSS_INTELLIGENCE_V1"
        ),
        # G-001: derived from the data, never asserted unconditionally.
        "provenance": provenance,
        "provenance_counts": dict(provenance_counter),
        "sources": dict(source_counter),
        "as_of": min(as_of_values) if as_of_values else None,
        "live_feeds_used": n_live > 0,
    }


if __name__ == "__main__":
    sample = [
        {
            "name": "log4j-core",
            "version": "2.14.1",
            "cve": "CVE-2021-44228",
            "severity": "Critical",
            "kev_status": True,
            "reachability_status": "REACHABLE",
        },
        {
            "name": "lodash",
            "version": "4.17.20",
            "cve": "CVE-2021-23337",
            "severity": "High",
            "kev_status": False,
            "reachability_status": "NOT_OBSERVED",
        },
        {
            "name": "ghsa-only",
            "version": "1.0.0",
            "cve": None,
            "advisory_id": "GHSA-test",
            "severity": "Medium",
        },
    ]

    import json

    enriched = enrich_epss_intelligence(sample)
    print(json.dumps(enriched, indent=2))
    print(json.dumps(epss_intelligence_summary(enriched), indent=2))