from __future__ import annotations

from collections import Counter

from analysis.intelligence_provenance import (
    LIVE_FEED,
    NOT_AVAILABLE,
    KEV_PROVENANCE,
    STATIC_REFERENCE,
)
from analysis.live_intel_feeds import KEVFeed


# Offline CISA KEV-style seed map.
# Expand over time from official KEV catalog.
KNOWN_EXPLOITED_CVES = {
    "CVE-2021-44228": {
        "vendor": "Apache",
        "product": "Log4j",
        "name": "Apache Log4j Remote Code Execution",
        "kev_added_date": "2021-12-10",
        "due_date": "2021-12-24",
        "ransomware_use": "Known",
    },
    "CVE-2021-45046": {
        "vendor": "Apache",
        "product": "Log4j",
        "name": "Apache Log4j Code Execution",
        "kev_added_date": "2021-12-10",
        "due_date": "2021-12-24",
        "ransomware_use": "Known",
    },
    "CVE-2022-22965": {
        "vendor": "Spring",
        "product": "Spring Framework",
        "name": "Spring Framework Remote Code Execution",
        "kev_added_date": "2022-04-04",
        "due_date": "2022-04-25",
        "ransomware_use": "Unknown",
    },
    "CVE-2017-5638": {
        "vendor": "Apache",
        "product": "Struts",
        "name": "Apache Struts Remote Code Execution",
        "kev_added_date": "2021-11-03",
        "due_date": "2022-05-03",
        "ransomware_use": "Known",
    },
    "CVE-2018-11776": {
        "vendor": "Apache",
        "product": "Struts",
        "name": "Apache Struts Remote Code Execution",
        "kev_added_date": "2021-11-03",
        "due_date": "2022-05-03",
        "ransomware_use": "Known",
    },
    "CVE-2023-34362": {
        "vendor": "Progress",
        "product": "MOVEit Transfer",
        "name": "MOVEit Transfer SQL Injection",
        "kev_added_date": "2023-06-02",
        "due_date": "2023-06-23",
        "ransomware_use": "Known",
    },
    "CVE-2023-3519": {
        "vendor": "Citrix",
        "product": "ADC/Gateway",
        "name": "Citrix ADC Remote Code Execution",
        "kev_added_date": "2023-07-19",
        "due_date": "2023-08-09",
        "ransomware_use": "Known",
    },
    "CVE-2024-3400": {
        "vendor": "Palo Alto Networks",
        "product": "PAN-OS",
        "name": "PAN-OS Command Injection",
        "kev_added_date": "2024-04-12",
        "due_date": "2024-04-19",
        "ransomware_use": "Unknown",
    },
    # CVE-2024-3094 (XZ Utils backdoor) was REMOVED here by the G-001/G-002
    # benchmark.  It is not, and has never been, in CISA's Known Exploited
    # Vulnerabilities catalog:
    #   * CISA's live catalog (version 2026.10.04, 1734 records) does not
    #     contain the identifier - checked twice, once by the benchmark
    #     (analysis/benchmark_intel_feeds.py, root cause SEED_TABLE_INVENTION)
    #     and once directly against the feed document.
    #   * CISA published an *alert* about it on 2024-03-29 ("Reported Supply
    #     Chain Compromise Affecting XZ Utils Data Compression Library"), which
    #     is not a KEV entry.  KEV requires reliable evidence of in-the-wild
    #     exploitation, and no such evidence was observed for this backdoor.
    # The previous entry also carried an invented kev_added_date / due_date in
    # CISA's own field format, presenting a fabricated catalog row as fact.
    # The CVE keeps its disclosure date (STATIC_CVE_DATES), its CVSS 10.0 and
    # its live EPSS score, so nothing about its risk is hidden - only the false
    # attribution to CISA is withdrawn.
}


# Deterministic fallback aliases for local corpora / advisory-only feeds.
# Keep this conservative; do not invent aliases.
GHSA_TO_CVE_ALIAS = {
    # Log4Shell GHSA commonly seen in Maven/GitHub advisory data.
    "GHSA-jfh8-c2jp-5v3q": "CVE-2021-44228",
    "GHSA-3pxv-7cmr-fjr4": "CVE-2021-44228",

    # Spring4Shell advisory aliases commonly observed.
    "GHSA-36p3-wjmg-h94x": "CVE-2022-22965",
    "GHSA-2rmj-mq67-h97g": "CVE-2022-22965",
}


def _candidate_ids(pkg: dict) -> list[str]:
    values = []

    for key in (
        "cve",
        "primary_vulnerability_id",
        "source_vulnerability_id",
        "advisory_id",
        "vulnerability_id",
        "id",
    ):
        value = pkg.get(key)
        if value:
            values.append(str(value).strip())

    for vuln in pkg.get("vulnerabilities", []) or []:
        if isinstance(vuln, dict):
            for key in ("cve", "id", "advisory_id"):
                value = vuln.get(key)
                if value:
                    values.append(str(value).strip())

    deduped = []
    for value in values:
        if value and value not in deduped:
            deduped.append(value)

    return deduped


def normalize_to_cve(pkg: dict) -> str | None:
    for value in _candidate_ids(pkg):
        upper = value.upper()

        if upper.startswith("CVE-"):
            return upper

        if upper.startswith("GHSA-") and value in GHSA_TO_CVE_ALIAS:
            return GHSA_TO_CVE_ALIAS[value]

    return None


def _reachable(pkg: dict) -> bool:
    return (
        str(pkg.get("reachability_status") or "").upper() == "REACHABLE"
        or str(pkg.get("reachability_priority") or "").upper()
        == "REACHABLE_VULNERABLE"
    )


def _kev_priority(pkg: dict, cve: str | None, is_kev: bool | None = None) -> str:
    if is_kev is None:
        is_kev = bool(cve) and cve in KNOWN_EXPLOITED_CVES
    if not is_kev:
        return "NO_KEV_SIGNAL"

    if _reachable(pkg):
        return "P0_REACHABLE_KEV"

    return "P1_KEV_REVIEW"


def enrich_kev_intelligence(sbom: list[dict],
                            feed: KEVFeed | None = None) -> list[dict]:
    """Resolve CISA KEV status for every package.

    ``feed`` is opt-in (G-002).  With a live catalog the lookup is a real
    question with a real answer: a miss against every row of the catalog is
    *evidence*, so ``kev_provenance`` is ``LIVE_FEED`` on **both** branches.
    Without one the behaviour is exactly the previous offline one — seed table
    included — so existing callers and tests are unaffected.
    """
    catalog_ok = False
    if feed is not None:
        try:
            catalog_ok = bool(feed.catalog_loaded)
        except Exception as exc:  # pragma: no cover - defensive
            try:
                feed.last_error = f"{type(exc).__name__}: {exc}"
            except Exception:
                pass
            catalog_ok = False

    catalog_version = ""
    date_released = ""
    if catalog_ok:
        try:
            catalog_version = feed.catalog_version or ""
            date_released = feed.date_released or ""
        except Exception:  # pragma: no cover - defensive
            catalog_version = ""
            date_released = ""

    enriched = []

    for pkg in sbom:
        item = dict(pkg)

        cve = normalize_to_cve(item)
        kev_record = KNOWN_EXPLOITED_CVES.get(cve) if cve else None

        item["normalized_cve"] = cve

        if catalog_ok:
            # Live: the whole catalog was consulted, so both branches are
            # observations rather than assumptions.
            live = feed.lookup(cve) if cve else None
            item["kev_status"] = bool(live)
            item["actively_exploited"] = bool(live)
            item["kev_provenance"] = LIVE_FEED if cve else NOT_AVAILABLE
            item["kev_source"] = "CISA_KEV_LIVE" if cve else "NONE"
            # Only claim a catalog version for an item a question was actually
            # asked about.  Attaching it unconditionally meant a payload where
            # nothing was consultable still published a catalog version next to
            # `kev: NOT_AVAILABLE` — a version of a catalog nothing was checked
            # against.  The static branch already did this correctly.
            item["kev_catalog_version"] = catalog_version if cve else None
            item["kev_as_of"] = date_released if cve else None
            if live:
                item["kev_vendor"] = live.vendor
                item["kev_product"] = live.product
                item["kev_vulnerability_name"] = live.name
                item["kev_added_date"] = live.date_added
                item["kev_due_date"] = live.due_date
                item["kev_ransomware_use"] = live.ransomware_use
                item["kev_method"] = "LIVE_CISA_KEV_V1"
            else:
                item["kev_method"] = (
                    "LIVE_CISA_KEV_NO_MATCH" if cve else "NO_VULNERABILITY_ID"
                )
                # A live miss must not inherit seed-table detail it never
                # matched, otherwise the report would pair a live "No" with
                # vendor/product fields from a different record.
                for _k in ("kev_vendor", "kev_product", "kev_vulnerability_name",
                           "kev_added_date", "kev_due_date", "kev_ransomware_use"):
                    item.pop(_k, None)
            is_kev = bool(live)
        else:
            # G-003: kev_status is a boolean against a tiny offline seed table
            # and had no provenance at all, so "kev_status: False" read as an
            # assertion that the CVE is absent from the live CISA KEV catalog.
            # It is not.  Provenance is STATIC_REFERENCE on both branches.
            item["kev_status"] = bool(kev_record)
            item["actively_exploited"] = bool(kev_record)
            item["kev_provenance"] = KEV_PROVENANCE if cve else NOT_AVAILABLE
            item["kev_source"] = "STATIC_TABLE" if cve else "NONE"
            item["kev_catalog_version"] = None
            item["kev_as_of"] = None
            is_kev = bool(kev_record)
            if kev_record:
                item["kev_vendor"] = kev_record.get("vendor")
                item["kev_product"] = kev_record.get("product")
                item["kev_vulnerability_name"] = kev_record.get("name")
                item["kev_added_date"] = kev_record.get("kev_added_date")
                item["kev_due_date"] = kev_record.get("due_date")
                item["kev_ransomware_use"] = kev_record.get("ransomware_use")
                item["kev_method"] = "STATIC_OFFLINE_CISA_KEV_V1"
            else:
                item["kev_method"] = "NO_KEV_MATCH"

        item["kev_priority"] = _kev_priority(item, cve, is_kev=is_kev)

        enriched.append(item)

    return enriched


def kev_intelligence_summary(sbom: list[dict]) -> dict:
    priority_counter = Counter()
    ransomware_counter = Counter()
    provenance_counter = Counter()
    source_counter = Counter()

    total_vulnerable = 0
    normalized_cve_count = 0
    kev_count = 0
    reachable_kev = 0
    ransomware_known = 0
    catalog_version = None
    as_of = None

    for pkg in sbom:
        if not (
            pkg.get("cve")
            or pkg.get("advisory_id")
            or pkg.get("primary_vulnerability_id")
            or pkg.get("normalized_cve")
        ):
            continue

        total_vulnerable += 1

        if pkg.get("normalized_cve"):
            normalized_cve_count += 1

        if pkg.get("kev_status"):
            kev_count += 1

        if pkg.get("kev_status") and _reachable(pkg):
            reachable_kev += 1

        priority_counter[pkg.get("kev_priority", "NO_KEV_SIGNAL")] += 1

        ransomware = pkg.get("kev_ransomware_use", "Unknown")
        ransomware_counter[ransomware] += 1

        if ransomware == "Known":
            ransomware_known += 1

        prov = pkg.get("kev_provenance")
        if prov:
            provenance_counter[str(prov)] += 1
        source = pkg.get("kev_source")
        if source:
            source_counter[str(source)] += 1
        if pkg.get("kev_catalog_version"):
            catalog_version = pkg["kev_catalog_version"]
        if pkg.get("kev_as_of"):
            as_of = pkg["kev_as_of"]

    # Worst-case wins: the summary may never claim a stronger provenance than
    # the weakest value it carries, otherwise one seed-table row would be
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
        "normalized_cve_packages": normalized_cve_count,
        "kev_packages": kev_count,
        "reachable_kev_packages": reachable_kev,
        "known_ransomware_use_packages": ransomware_known,
        "kev_priority_counts": dict(priority_counter),
        "ransomware_use_counts": dict(ransomware_counter),
        "summary_status": (
            "LIVE_CISA_KEV_V1"
            if provenance == LIVE_FEED
            else "STATIC_OFFLINE_CISA_KEV_V1"
        ),
        # G-003/G-002: surfaced, human-facing label for the summary block.
        "provenance": provenance,
        "provenance_counts": dict(provenance_counter),
        "sources": dict(source_counter),
        "catalog_version": catalog_version,
        "as_of": as_of,
        "live_feeds_used": n_live > 0,
    }


if __name__ == "__main__":
    sample = [
        {
            "name": "log4j-core",
            "version": "2.14.1",
            "advisory_id": "GHSA-3pxv-7cmr-fjr4",
            "severity": "Critical",
            "reachability_status": "REACHABLE",
        },
        {
            "name": "spring-web",
            "version": "5.3.17",
            "cve": "CVE-2022-22965",
            "severity": "Critical",
            "reachability_status": "NOT_OBSERVED",
        },
        {
            "name": "left-pad",
            "version": "1.3.0",
            "advisory_id": "GHSA-test",
            "severity": "Medium",
        },
    ]

    import json

    enriched = enrich_kev_intelligence(sample)
    print(json.dumps(enriched, indent=2))
    print(json.dumps(kev_intelligence_summary(enriched), indent=2))