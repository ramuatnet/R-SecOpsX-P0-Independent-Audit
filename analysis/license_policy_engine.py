from __future__ import annotations

from collections import Counter

# One catalogue, one decision table.  This module used to carry its own
# narrower copies of the risk sets and decision rules; on a real scan
# (wrongsecrets, 2026-10-15) that divergence classified eight genuinely
# permissive npm components (BlueOak-1.0.0, Python-2.0, CC-BY-4.0 and three
# SPDX OR-expressions) as UNCLASSIFIED_LICENSE / REVIEW_REQUIRED while the
# report's category column -- derived from core.license_catalog via the
# package-intelligence pass -- called the same rows Permissive.  The policy
# engine is the FINAL decision layer, so it must read the authoritative
# catalogue rather than a stale subset of it.
from core import license_catalog

HIGH_RISK_LICENSES = license_catalog.HIGH_RISK_LICENSES
MEDIUM_RISK_LICENSES = license_catalog.MEDIUM_RISK_LICENSES
LOW_RISK_LICENSES = license_catalog.LOW_RISK_LICENSES

# One label for one engine.  The per-item method used to read
# "..._V3_QUALIFIED_EVIDENCE" while the summary of the SAME run read
# "..._V1", which an auditor (rightly) reported as "confirm which engine
# produced the final results".  The summary status is the prefix of the
# per-item method by construction.
POLICY_ENGINE_LABEL = "RULE_BASED_LICENSE_POLICY_V3"

UNKNOWN_VALUES = {
    "",
    "unknown",
    "none",
    "null",
    "not_found",
    "n/a",
}


def _normalize_license(value: str | None) -> str:
    if value is None:
        return "UNKNOWN"

    raw = str(value).strip()

    if raw.lower() in UNKNOWN_VALUES:
        return "UNKNOWN"

    aliases = {
        "apache 2": "Apache-2.0",
        "apache 2.0": "Apache-2.0",
        "apache license 2.0": "Apache-2.0",
        "mit license": "MIT",
        "bsd": "BSD-3-Clause",
        "gplv3": "GPL-3.0",
        "gpl3": "GPL-3.0",
        "agplv3": "AGPL-3.0",
        "lgplv3": "LGPL-3.0",
    }

    return aliases.get(raw.lower(), raw)


def _risk_for_license(license_id: str) -> tuple[str, str, str]:
    """Delegate to the authoritative catalogue (single source of truth)."""
    return license_catalog.license_risk(license_id)


def _policy_decision(risk: str, issue: str) -> str:
    """Delegate to the authoritative decision table."""
    return license_catalog.license_policy_decision(risk, issue)


def _requires_notice(license_id: str) -> bool:
    """Delegate to the catalogue's notice rules (compound-aware)."""
    return license_catalog.requires_notice(license_id)


def enrich_license_policy(sbom: list[dict]) -> list[dict]:
    """Apply license policy using qualified/resolved evidence when available.

    Evidence precedence is deliberately explicit:
      1. license_resolved (actual V10 resolver output)
      2. license_expression (qualified expression, when supplied)
      3. resolved_license (resolver-compatible alias)
      4. declared_license_normalized
      5. license / declared_license / concluded_license

    Declared and resolved values are retained separately for provenance.
    """
    enriched = []

    for pkg in sbom:
        item = dict(pkg)

        declared_raw = (
            item.get("declared_license")
            or item.get("license_declared")
            or item.get("declared_license_normalized")
            or item.get("license")
            or item.get("concluded_license")
        )
        declared_license = _normalize_license(declared_raw)

        resolution_status = str(item.get("license_resolution_status") or item.get("resolution_status") or "").strip()
        resolved_raw = (
            item.get("license_resolved")
            or item.get("license_expression")
            or item.get("resolved_license")
        )
        resolved_license = _normalize_license(resolved_raw)

        # A non-unknown resolved value is qualified evidence and takes
        # precedence over an UNKNOWN declared value.  Preserve the original
        # declaration and resolver provenance separately.
        use_resolved = resolved_license != "UNKNOWN"
        if use_resolved:
            license_id = resolved_license
            policy_source = "QUALIFIED_RESOLVED_EVIDENCE"
        else:
            license_id = declared_license
            policy_source = "DECLARED_OR_LOCAL_METADATA"

        risk, issue, reason = _risk_for_license(license_id)
        decision = _policy_decision(risk, issue)

        item["declared_license_normalized"] = declared_license
        item["resolved_license_normalized"] = resolved_license
        item["policy_license"] = license_id
        item["normalized_license"] = license_id
        item["license_risk"] = risk
        item["license_issue"] = issue
        item["license_policy_decision"] = decision
        item["license_reason"] = reason
        item["license_notice_required"] = _requires_notice(license_id)
        item["license_policy_source"] = policy_source
        item["license_policy_method"] = f"{POLICY_ENGINE_LABEL}_QUALIFIED_EVIDENCE"

        # Explicit provenance marker for the decision layer.
        if use_resolved:
            item["license_evidence_qualified"] = True
            item["license_evidence_resolution_status"] = resolution_status or "RESOLVED_EVIDENCE"
        else:
            item["license_evidence_qualified"] = False
            item["license_evidence_resolution_status"] = resolution_status or "NO_RESOLVED_EVIDENCE"

        enriched.append(item)

    return enriched


def license_policy_summary(sbom: list[dict]) -> dict:
    risk_counter = Counter()
    decision_counter = Counter()
    license_counter = Counter()
    issue_counter = Counter()

    total = 0
    notice_required = 0
    legal_review_required = 0
    unknown_license = 0

    for pkg in sbom:
        total += 1

        risk = pkg.get("license_risk", "UNKNOWN")
        decision = pkg.get("license_policy_decision", "UNKNOWN")
        license_id = pkg.get("normalized_license", "UNKNOWN")
        issue = pkg.get("license_issue", "UNKNOWN")

        risk_counter[risk] += 1
        decision_counter[decision] += 1
        license_counter[license_id] += 1
        issue_counter[issue] += 1

        if pkg.get("license_notice_required"):
            notice_required += 1

        if decision == "LEGAL_REVIEW_REQUIRED":
            legal_review_required += 1

        if license_id == "UNKNOWN":
            unknown_license += 1

    return {
        "total_components": total,
        "risk_counts": dict(risk_counter),
        "decision_counts": dict(decision_counter),
        "license_counts": dict(license_counter),
        "issue_counts": dict(issue_counter),
        "notice_required_components": notice_required,
        "legal_review_required_components": legal_review_required,
        "unknown_license_components": unknown_license,
        "summary_status": POLICY_ENGINE_LABEL,
    }


if __name__ == "__main__":
    sample = [
        {"name": "safe-lib", "version": "1.0.0", "license": "MIT"},
        {"name": "apache-lib", "version": "2.0.0", "license": "Apache-2.0"},
        {"name": "gpl-lib", "version": "3.0.0", "license": "GPL-3.0"},
        {"name": "agpl-lib", "version": "3.0.0", "license": "AGPL-3.0"},
        {"name": "unknown-lib", "version": "0.1.0", "license": "unknown"},
    ]

    import json

    enriched = enrich_license_policy(sample)
    print(json.dumps(enriched, indent=2))
    print(json.dumps(license_policy_summary(enriched), indent=2))