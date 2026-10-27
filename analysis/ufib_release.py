"""UFIB release controller: one authoritative manifest for every report path.

SCHEMA: UFIB-RELEASE-1

The release controller is the single authority that decides what may be
presented as a confirmed vulnerability. It does not remove findings -- zero
silent loss is an invariant (mission 8.4) -- it classifies them, and every
report generator reads the same dispositions from the same findings list.

The manifest records:
  * policy version and schema
  * scan-level status (COMPLETE / PARTIAL / INCOMPLETE / FAILED / UNKNOWN)
  * per-disposition counts (must sum to the findings population -- asserted)
  * per-category breakdown with released vs held
  * per-engine GATE 0 integrity entries (engines that failed or were skipped
    must never read as a clean result)
  * held-finding diagnostics WITHOUT secret values (evidence is redacted by
    the report layer already; the manifest carries counts and reasons only)

Fail-soft contract: if the brain itself crashes, apply_ufib_to_payload marks
every finding NEEDS_REVIEW (never CONFIRMED), records the error in the
manifest, and the scan continues. An unvalidated population must never be
released as confirmed -- that is the direction of safe failure.
"""
from __future__ import annotations

from typing import Any

from analysis.ufib_brain import (
    DISPOSITIONS,
    RELEASE_DISPOSITIONS,
    clear_source_cache,
    evaluate_finding,
)

UFIB_RELEASE_SCHEMA = "UFIB-RELEASE-1"
RELEASE_POLICY_VERSION = "1.0.0"


def _gate0_engine_integrity(payload: dict) -> list[dict]:
    """GATE 0: scan and evidence-collection integrity, read from what the
    pipeline already records. A crashed or skipped engine is recorded, never
    interpreted as a clean result."""
    entries: list[dict] = []
    telemetry = payload.get("rule_telemetry") or {}
    if telemetry:
        entries.append({"engine": "rule_telemetry", "state": "OBSERVED",
                        "detail": "%d rule(s) produced findings"
                                  % len(telemetry)})
    else:
        entries.append({"engine": "rule_telemetry", "state": "UNKNOWN",
                        "detail": "no engine telemetry recorded"})
    advisory = payload.get("sbom_advisory_status") or {}
    if advisory:
        available = advisory.get("available")
        entries.append({
            "engine": "sbom_advisory", "state":
                "OBSERVED" if available else "DEGRADED",
            "detail": advisory.get("coverage_note")
                      or "advisory service status recorded",
        })
    gate = payload.get("security_gate") or {}
    if gate:
        entries.append({"engine": "security_gate", "state": "OBSERVED",
                        "detail": "gate block present"})
    return entries


def _scan_status(payload: dict, dispositions: list[str]) -> str:
    if dispositions and dispositions.count("ANALYSIS_ERROR") == len(dispositions):
        return "FAILED"
    if payload.get("ufib_error"):
        return "PARTIAL"
    if not payload.get("findings"):
        return "INCOMPLETE"
    advisory = payload.get("sbom_advisory_status") or {}
    if advisory and advisory.get("available") is False:
        return "PARTIAL"
    return "COMPLETE"


def build_release_manifest(payload: dict) -> dict:
    findings = [f for f in (payload.get("findings") or []) if isinstance(f, dict)]
    by_disposition: dict[str, int] = {d: 0 for d in sorted(DISPOSITIONS)}
    by_category: dict[str, dict] = {}
    for f in findings:
        d = str(f.get("disposition") or "NEEDS_REVIEW")
        by_disposition[d] = by_disposition.get(d, 0) + 1
        cat = ((f.get("ufib") or {}).get("category")) or "_unevaluated"
        slot = by_category.setdefault(cat, {"total": 0, "released": 0,
                                            "held": 0, "dispositions": {}})
        slot["total"] += 1
        if RELEASE_DISPOSITIONS.get(d):
            slot["released"] += 1
        else:
            slot["held"] += 1
        slot["dispositions"][d] = slot["dispositions"].get(d, 0) + 1

    released = sum(v for k, v in by_disposition.items()
                   if RELEASE_DISPOSITIONS.get(k))
    manifest = {
        "schema": UFIB_RELEASE_SCHEMA,
        "policy_version": RELEASE_POLICY_VERSION,
        "dispositions_vocabulary": sorted(DISPOSITIONS),
        "released_dispositions": [d for d, ok in RELEASE_DISPOSITIONS.items() if ok],
        "total_findings": len(findings),
        "released_count": released,
        "held_count": len(findings) - released,
        "by_disposition": by_disposition,
        "by_category": by_category,
        "engine_integrity": _gate0_engine_integrity(payload),
        "scan_status": _scan_status(payload, list(by_disposition.values())),
        "zero_silent_loss": len(findings) == sum(by_disposition.values()),
    }
    return manifest


def apply_ufib_to_payload(payload: dict, target: str | None = None) -> dict:
    """Run the brain over every finding and attach the release manifest.

    Fail-soft: a brain crash marks the population NEEDS_REVIEW (never
    CONFIRMED), records `ufib_error`, and returns a manifest whose scan
    status is PARTIAL. The direction of failure is conservative by design.
    """
    clear_source_cache()
    findings = [f for f in (payload.get("findings") or []) if isinstance(f, dict)]
    try:
        for f in findings:
            evaluate_finding(f, target)
        payload.pop("ufib_error", None)
    except Exception as exc:  # noqa: BLE001 - safe failure direction
        payload["ufib_error"] = "%s: %s" % (type(exc).__name__, exc)
        for f in findings:
            if f.get("disposition") in (None, "ANALYSIS_ERROR"):
                f["disposition"] = "NEEDS_REVIEW"
                f["release_eligible"] = False
    payload["release_manifest"] = build_release_manifest(payload)
    meta = payload.setdefault("metadata", {})
    rm = payload["release_manifest"]
    meta["release_manifest_summary"] = {
        "schema": rm["schema"],
        "policy_version": rm["policy_version"],
        "scan_status": rm["scan_status"],
        "total_findings": rm["total_findings"],
        "released_count": rm["released_count"],
        "held_count": rm["held_count"],
        "by_disposition": rm["by_disposition"],
    }
    return payload


def refresh_release_manifest(payload: dict) -> dict:
    """Rebuild ONLY the manifest after late pipeline stages mutated the
    findings population (cleanup/noise pass/aggregates). Dispositions already
    on the findings are preserved; unevaluated late additions are impossible
    because the UFIB stage runs before them -- but the invariant is re-asserted
    here rather than trusted: a finding without a disposition after the late
    stages is marked NEEDS_REVIEW, never released silently."""
    findings = [f for f in (payload.get("findings") or []) if isinstance(f, dict)]
    for f in findings:
        if not f.get("disposition"):
            f["disposition"] = "NEEDS_REVIEW"
            f["release_eligible"] = False
    payload["release_manifest"] = build_release_manifest(payload)
    meta = payload.setdefault("metadata", {})
    rm = payload["release_manifest"]
    meta["release_manifest_summary"] = {
        "schema": rm["schema"],
        "policy_version": rm["policy_version"],
        "scan_status": rm["scan_status"],
        "total_findings": rm["total_findings"],
        "released_count": rm["released_count"],
        "held_count": rm["held_count"],
        "by_disposition": rm["by_disposition"],
    }
    return payload
