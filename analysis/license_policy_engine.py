from __future__ import annotations

from collections import Counter


HIGH_RISK_LICENSES = {
    "AGPL-3.0",
    "AGPL-3.0-only",
    "AGPL-3.0-or-later",
    "GPL-3.0",
    "GPL-3.0-only",
    "GPL-3.0-or-later",
    "SSPL-1.0",
    "BUSL-1.1",
    "Commons-Clause",
}

MEDIUM_RISK_LICENSES = {
    "GPL-2.0",
    "GPL-2.0-only",
    "GPL-2.0-or-later",
    "LGPL-2.1",
    "LGPL-2.1-only",
    "LGPL-2.1-or-later",
    "LGPL-3.0",
    "LGPL-3.0-only",
    "LGPL-3.0-or-later",
    "MPL-2.0",
    "EPL-2.0",
    "CDDL-1.0",
}

LOW_RISK_LICENSES = {
    "MIT",
    "Apache-2.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "ISC",
    "0BSD",
    "Unlicense",
    "CC0-1.0",
}

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
    if license_id == "UNKNOWN":
        return (
            "MEDIUM",
            "UNKNOWN_LICENSE",
            "License information is missing or unknown; legal review may be required.",
        )

    if license_id in HIGH_RISK_LICENSES:
        return (
            "HIGH",
            "RESTRICTIVE_OR_STRONG_COPYLEFT",
            "Restrictive or strong copyleft license detected; proprietary distribution may require legal review.",
        )

    if license_id in MEDIUM_RISK_LICENSES:
        return (
            "MEDIUM",
            "COPYLEFT_OR_RECIPROCAL_LICENSE",
            "Copyleft or reciprocal license detected; compatibility and attribution obligations should be reviewed.",
        )

    if license_id in LOW_RISK_LICENSES:
        return (
            "LOW",
            "PERMISSIVE_LICENSE",
            "Permissive license detected; attribution obligations may still apply.",
        )

    return (
        "MEDIUM",
        "UNCLASSIFIED_LICENSE",
        "License is not in the local policy catalog; review recommended.",
    )


def _policy_decision(risk: str, issue: str) -> str:
    if risk == "HIGH":
        return "LEGAL_REVIEW_REQUIRED"

    if issue in {"UNKNOWN_LICENSE", "UNCLASSIFIED_LICENSE"}:
        return "REVIEW_REQUIRED"

    if risk == "MEDIUM":
        return "APPROVE_WITH_CONDITIONS"

    return "ALLOW"


def _requires_notice(license_id: str) -> bool:
    return license_id in {
        "MIT",
        "Apache-2.0",
        "BSD-2-Clause",
        "BSD-3-Clause",
        "ISC",
        "MPL-2.0",
        "EPL-2.0",
    }


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
        item["license_policy_method"] = "RULE_BASED_LICENSE_POLICY_V3_QUALIFIED_EVIDENCE"

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
        "summary_status": "RULE_BASED_LICENSE_POLICY_V1",
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