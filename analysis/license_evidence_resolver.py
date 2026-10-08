"""
R-SecOpsX V10 License Evidence Resolver v1

Consumes the frozen, read-only License Evidence Resolver v2 evidence artifact.
Matching is exact on package name + version. No package-name inference is used.
"""

from __future__ import annotations

import json
from pathlib import Path
from collections import Counter


_EVIDENCE_FILE = (
    Path(__file__).resolve().parents[1]
    / "data"
    / "license_evidence"
    / "LICENSE_EVIDENCE_RESOLVER_V2.json"
)


def _load_evidence() -> dict:
    if not _EVIDENCE_FILE.exists():
        return {"components": []}
    with _EVIDENCE_FILE.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        return {"components": []}
    return data


def _evidence_index(data: dict) -> dict[tuple[str, str], dict]:
    index = {}
    for record in data.get("components", []) or []:
        if not isinstance(record, dict):
            continue
        package = str(record.get("package") or "").strip()
        version = str(record.get("version") or "").strip()
        if package and version:
            index[(package, version)] = dict(record)
    return index


# A sentinel, not a licence.  "UNKNOWN" is a non-empty *string*, so it defeats
# both `or`-chains and bare `if value:` guards -- which is how 48 components with
# no identifiable licence were reported as "Known / Canonical", marked
# "RESOLVED_FROM_CANONICAL_REPORT" and given an evidence source of
# "CANONICAL_REPORT".  Treat it as absence everywhere below.
_UNKNOWN_LICENSE_VALUES = frozenset(
    {"", "unknown", "none", "null", "n/a", "na", "noassertion", "-"}
)


def _is_unknown_license(value) -> bool:
    """True when *value* is an absence marker rather than a licence name."""
    return str(value or "").strip().lower() in _UNKNOWN_LICENSE_VALUES


def _canonical_category(pkg: dict) -> str:
    risk = str(pkg.get("license_risk") or "").upper()
    decision = str(pkg.get("license_policy_decision") or "").upper()
    if risk in {"LOW", "NONE"} and decision != "LEGAL_REVIEW_REQUIRED":
        return "Permissive"
    license_value = str(
        pkg.get("normalized_license")
        or pkg.get("declared_license")
        or pkg.get("license")
        or ""
    ).strip()
    # Without the sentinel guard this returns "Known / Canonical" precisely for
    # the components whose only value IS the sentinel.
    if license_value and not _is_unknown_license(license_value):
        return "Known / Canonical"
    return "Unknown"


def enrich_license_evidence(payload: dict) -> dict:
    """
    Attach canonical per-component license evidence.

    The existing license_policy_summary is intentionally left untouched.
    Evidence records are matched only by exact package/version identity.
    """
    data = _load_evidence()
    index = _evidence_index(data)
    components = payload.get("sbom", []) or []
    evidence_rows = []

    for pkg in components:
        if not isinstance(pkg, dict):
            continue

        name = str(pkg.get("name") or pkg.get("component") or "").strip()
        version = str(pkg.get("version") or pkg.get("current_version") or "").strip()
        declared = (
            pkg.get("declared_license")
            or pkg.get("license")
            or pkg.get("normalized_license")
            or "UNKNOWN"
        )
        key = (name, version)
        record = index.get(key)

        if record:
            raw = record.get("evidence_raw") or record.get("resolved_license")
            resolved = record.get("resolved_license")
            status = str(record.get("resolution_status") or "UNKNOWN")
            category = str(record.get("license_category") or "Unknown")

            # The frozen resolver v2 labels custom WAGMIT as Unknown. For
            # reporting semantics, preserve the raw expression and classify it
            # explicitly as custom/review rather than treating it as evidence
            # unavailable.
            if str(resolved or "").strip().upper() == "WAGMIT":
                category = "Custom / Review"
                status = "RESOLVED_CUSTOM_LICENSE"
            elif status == "REGISTRY_LOOKUP_FAILED":
                category = "Evidence Unavailable"
                status = "UNKNOWN_EVIDENCE_UNAVAILABLE"

            review_required = category in {
                "Composite / Review",
                "Custom / Review",
                "Evidence Unavailable",
                # `category` defaults to "Unknown" at line 92, so without this
                # an unclassified component is quietly marked as reviewed.
                "Unknown",
            }

            row = {
                "package": name,
                "version": version,
                "license_declared": declared,
                "license_resolved": resolved or "UNKNOWN",
                "license_expression": raw or "UNKNOWN",
                "license_category": category,
                "license_components": record.get("license_components") or [],
                "license_resolution_status": status,
                "license_evidence_source": record.get("evidence_source") or "NPM_REGISTRY",
                "license_evidence": record.get("evidence"),
                "license_evidence_raw": raw or "UNKNOWN",
                "license_provenance": {
                    "resolver": "R-SecOpsX License Evidence Resolver v2",
                    "registry_enabled": bool(record.get("registry_enabled")),
                    "repository_enabled": bool(record.get("repository_enabled")),
                },
                "license_review_required": review_required,
            }
        else:
            resolved = (
                pkg.get("normalized_license")
                or pkg.get("license")
                or pkg.get("declared_license")
                or "UNKNOWN"
            )
            row = {
                "package": name,
                "version": version,
                "license_declared": declared,
                "license_resolved": resolved,
                "license_expression": resolved,
                "license_category": _canonical_category(pkg),
                "license_components": [resolved] if resolved not in {"UNKNOWN", ""} else [],
                # Only claim a resolution/evidence source when one exists.  The
                # canonical report carried the sentinel for these components, so
                # "RESOLVED" and "CANONICAL_REPORT" were both fabrications.
                "license_resolution_status": (
                    "NO_LICENSE_EVIDENCE" if _is_unknown_license(resolved)
                    else "RESOLVED_FROM_CANONICAL_REPORT"
                ),
                "license_evidence_source": (
                    "--" if _is_unknown_license(resolved) else "CANONICAL_REPORT"
                ),
                "license_evidence": None,
                "license_evidence_raw": resolved,
                "license_provenance": {
                    "resolver": "R-SecOpsX canonical license policy",
                    "source": "canonical_report_payload",
                },
                # license_policy_engine emits REVIEW_REQUIRED for unknown
                # licences and LEGAL_REVIEW_REQUIRED for restrictive ones.
                # Matching only the latter reported 0 review-required
                # components directly beside 48 unknown ones.
                "license_review_required": str(
                    pkg.get("license_policy_decision") or ""
                ).upper() in {"REVIEW_REQUIRED", "LEGAL_REVIEW_REQUIRED"},
            }

        for key_name, value in row.items():
            if key_name == "package":
                continue
            pkg[key_name] = value
        # Backward-compatible aliases for downstream reporting integrations.
        pkg["license_evidence_source"] = row["license_evidence_source"]
        pkg["license_evidence_status"] = row["license_resolution_status"]
        evidence_rows.append(row)

    counts = Counter(row["license_category"] for row in evidence_rows)
    status_counts = Counter(row["license_resolution_status"] for row in evidence_rows)
    source_counts = Counter(row["license_evidence_source"] for row in evidence_rows)
    review_count = sum(1 for row in evidence_rows if row["license_review_required"])

    payload["license_evidence"] = evidence_rows
    payload["license_evidence_summary"] = {
        "total_components": len(evidence_rows),
        "category_counts": dict(counts),
        "resolution_status_counts": dict(status_counts),
        "evidence_source_counts": dict(source_counts),
        "review_required_components": review_count,
        "resolver": "R-SecOpsX License Evidence Resolver v2",
        "evidence_artifact": "LICENSE_EVIDENCE_RESOLVER_V2.json",
        "evidence_artifact_mode": "READ_ONLY_FROZEN",
    }
    return payload
