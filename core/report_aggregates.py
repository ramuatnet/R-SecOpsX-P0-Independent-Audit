# -*- coding: utf-8 -*-
"""core/report_aggregates.py -- the single source of truth for report counts.

Why this exists (taskf.md DEF-A): one scan used to print three different
totals because each renderer read a different field -- metadata.total_findings
on covers, len(grouped) on Findings sheets, len(findings) on Technical
Evidence -- and the severity table summed a different population than the
rows beneath it.  This module computes every count ONCE from the payload's
own lists and proves the two identities that make a Summary reconcilable by
arithmetic:

    total_reported == sast_records + sca_vulnerable_packages
    sum(severity.combined.values()) == total_reported

What it refuses to do:
  * Collapse populations.  metadata.total_findings and grouped stay what
    they are; this module names them (taskf non-goal: never make
    total_findings equal len(grouped)).
  * Enforce legacy agreement.  consistency.legacy_metadata_total_matches
    is REPORTED, never folded into ``ok`` -- a pre-existing disagreement is
    the signal to look at, not a scan failure (taskf T-1.1).
  * Guess severity.  A vulnerable package with no published severity is
    unrated: it is counted in the Info bucket so the distribution sums, and
    severity.sca_unrated says how many.  Per-cell honesty about WHY a value
    is missing lives in core.value_state, not here.

Fail-loud contract (taskf T-1.3): when an enforced check fails, build()
logs an ERROR naming the failing checks and sets
metadata.aggregates_inconsistent = true.  It never raises -- the scan must
still produce artifacts -- but the flag travels into every provenance line
so a broken aggregate cannot hide.

Determinism: no timestamps, no network, no randomness.  The same payload
bytes in => the same aggregate bytes out.
"""
from __future__ import annotations

import logging
from typing import Any

_LOG = logging.getLogger(__name__)

SCHEMA = "rsecopsx.report_aggregates/v1"

#: The canonical severity vocabulary, in report order.  Defined here rather
#: than imported from core.analyzer so this module stays a pure leaf (no
#: circular import when analyzer builds the payload).
SEVERITIES: tuple[str, ...] = ("Critical", "High", "Medium", "Low", "Info")

#: Label AND unit for every exported field, keyed by its dotted path into
#: the aggregate.  Renderers label rows from this table -- a bare "Total
#: Findings" with no population name is banned (taskf ground rule 4), and
#: the unit is what makes "3 packages" never read as "3 findings".
COUNT_UNITS: dict[str, dict[str, str]] = {
    "counts.total_reported": {
        "label": "Total reported items",
        "unit": "items",
    },
    "counts.sast_records": {
        "label": "SAST records",
        "unit": "records",
    },
    "counts.sca_vulnerable_packages": {
        "label": "Vulnerable dependency packages",
        "unit": "packages",
    },
    "counts.grouped_records": {
        "label": "SAST findings (grouped records)",
        "unit": "records",
    },
    "severity.combined.Critical": {
        "label": "Combined severity: Critical", "unit": "items",
    },
    "severity.combined.High": {
        "label": "Combined severity: High", "unit": "items",
    },
    "severity.combined.Medium": {
        "label": "Combined severity: Medium", "unit": "items",
    },
    "severity.combined.Low": {
        "label": "Combined severity: Low", "unit": "items",
    },
    "severity.combined.Info": {
        "label": "Combined severity: Info", "unit": "items",
    },
    "severity.sca_unrated": {
        "label": "Vulnerable packages with no published severity",
        "unit": "packages",
    },
}

#: What the combined distribution counts.  Ships with the aggregate so the
#: severity table can print its own scope (taskf risk register: the scope
#: string travels with every table).
SEVERITY_SCOPE = (
    "SAST records plus unique vulnerable dependency packages; "
    "packages with no published severity are counted in Info "
    "(see severity.sca_unrated)"
)


def _as_int(value: Any, default: int = 0) -> int:
    """Lenient int for legacy metadata that may have crossed a JSON edge."""
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def _is_vulnerable_package(pkg: Any) -> bool:
    """The SCA population predicate, identical to build_report_payload's.

    cvss > 0 OR a CVE OR a vulnerability list.  A non-dict entry cannot
    prove itself clean, so it counts -- and, being unbucketable, it makes
    the severity identity fail loud rather than silently vanish.
    """
    if not isinstance(pkg, dict):
        return True
    try:
        cvss = float(pkg.get("cvss") or 0)
    except (TypeError, ValueError):
        cvss = 0.0
    return bool(cvss > 0 or pkg.get("cve") or pkg.get("vulnerabilities"))


def _normalize_severity(raw: Any) -> str:
    """Map any severity spelling onto the canonical five buckets.

    Unknown / absent / legacy sentinel values ("None", "N/A", "") land in
    Info so the distribution always sums -- the unrated count is reported
    separately instead of being dropped from the table.
    """
    text = str(raw or "").strip().title()
    return text if text in SEVERITIES else "Info"


def _bucket_findings(findings: list[Any]) -> dict[str, int]:
    dist = {s: 0 for s in SEVERITIES}
    for f in findings:
        if not isinstance(f, dict):
            # Population member that cannot be bucketed: leave the sum short
            # so consistency.ok goes False (fail loud, ground rule 12).
            continue
        dist[_normalize_severity(f.get("severity"))] += 1
    return dist


def _bucket_packages(packages: list[Any]) -> tuple[dict[str, int], int]:
    """Bucket the SCA population; return (dist, unrated_count).

    Unrated = a package whose severity did not map onto the canonical five
    (no published severity, or a legacy sentinel string).  It still lands
    in Info so sum(dist) == len(packages); sca_unrated keeps the absence
    visible instead of pretending it was Info.
    """
    dist = {s: 0 for s in SEVERITIES}
    unrated = 0
    for pkg in packages:
        if not isinstance(pkg, dict):
            continue  # unbucketable -> identity fails loud
        raw = str(pkg.get("severity")
                  or pkg.get("highest_vulnerability_severity") or "").strip()
        published = raw.title() in SEVERITIES
        dist[_normalize_severity(raw)] += 1
        if not published:
            # Absent, or a legacy sentinel ("Unknown"/"None"/"N/A") that had
            # to be normalized into Info -- counted, and counted as unrated.
            unrated += 1
    return dist, unrated


def value_at(aggregate: dict, path: str) -> Any:
    """Read a COUNT_UNITS dotted path out of an aggregate (``counts.x.y``)."""
    node: Any = aggregate
    for part in path.split("."):
        if not isinstance(node, dict):
            return None
        node = node.get(part)
    return node


def build(payload: dict) -> dict:
    """Compute the canonical aggregate for ``payload`` and return it.

    Callers store the result at ``payload["aggregates"]``.  On an enforced
    check failure this also sets ``metadata.aggregates_inconsistent`` and
    logs an ERROR -- reported loudly, never raised (taskf T-1.3).
    """
    meta = payload.get("metadata")
    if not isinstance(meta, dict):
        meta = {}
        payload["metadata"] = meta

    findings = payload.get("findings")
    findings = findings if isinstance(findings, list) else []
    grouped = payload.get("grouped")
    grouped = grouped if isinstance(grouped, list) else []
    sbom = payload.get("sbom")
    sbom = sbom if isinstance(sbom, list) else []

    sast_records = len(findings)
    grouped_records = len(grouped)
    vulnerable = [p for p in sbom if _is_vulnerable_package(p)]
    sca_vulnerable_packages = len(vulnerable)
    total_reported = sast_records + sca_vulnerable_packages

    sast_dist = _bucket_findings(findings)
    sca_dist, sca_unrated = _bucket_packages(vulnerable)
    combined = {s: sast_dist[s] + sca_dist[s] for s in SEVERITIES}

    checks = {
        "total_equals_sast_plus_sca": (
            total_reported == sast_records + sca_vulnerable_packages
        ),
        "combined_severity_sums_to_total": (
            sum(combined.values()) == total_reported
        ),
    }
    failing = [name for name, passed in checks.items() if not passed]

    # Reported, NOT enforced (taskf T-1.1): a stale metadata total is the
    # signal that some late pass moved the population, not a scan failure.
    if "total_findings" in meta:
        legacy_metadata_total_matches = (
            _as_int(meta.get("total_findings"), default=-1) == total_reported
        )
    else:
        legacy_metadata_total_matches = True  # nothing declared, nothing to disagree about

    aggregate = {
        "schema": SCHEMA,
        "counts": {
            "total_reported": total_reported,
            "sast_records": sast_records,
            "sca_vulnerable_packages": sca_vulnerable_packages,
            "grouped_records": grouped_records,
        },
        "severity": {
            "scope": SEVERITY_SCOPE,
            "combined": combined,
            "sast": sast_dist,
            "sca": sca_dist,
            "sca_unrated": sca_unrated,
        },
        "units": COUNT_UNITS,
        # The value metadata.severity_distribution used to carry, kept
        # verbatim so old and new can be diffed during the migration.
        "legacy_severity_distribution": meta.get("severity_distribution"),
        "consistency": {
            "ok": not failing,
            "checks": checks,
            "failing": list(failing),
            "legacy_metadata_total_matches": legacy_metadata_total_matches,
        },
    }

    if failing:
        meta["aggregates_inconsistent"] = True
        _LOG.error(
            "report aggregates inconsistent: %s "
            "(total_reported=%s sast=%s sca=%s combined_sum=%s)",
            ", ".join(failing), total_reported, sast_records,
            sca_vulnerable_packages, sum(combined.values()),
        )
    else:
        meta.pop("aggregates_inconsistent", None)

    return aggregate
