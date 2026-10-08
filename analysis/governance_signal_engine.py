from __future__ import annotations


SIGNAL_CATALOG = {
    "SECRET_MANAGEMENT_WEAKNESS": {
        "severity": "HIGH",
        "source": "secret_intelligence",
    },
    "PATCH_GOVERNANCE_WEAKNESS": {
        "severity": "HIGH",
        "source": "vulnerability_management",
    },
    "SUPPLY_CHAIN_GOVERNANCE_WEAKNESS": {
        "severity": "HIGH",
        "source": "dependency_intelligence",
    },
    "CLOUD_GOVERNANCE_WEAKNESS": {
        "severity": "HIGH",
        "source": "cloud_iac",
    },
    "CONTAINER_GOVERNANCE_WEAKNESS": {
        "severity": "HIGH",
        "source": "container_iac",
    },
    "API_GOVERNANCE_WEAKNESS": {
        "severity": "MEDIUM",
        "source": "api_security",
    },
    "LICENSE_GOVERNANCE_RISK": {
        "severity": "MEDIUM",
        "source": "license_intelligence",
    },
    "CRYPTOGRAPHIC_GOVERNANCE_WEAKNESS": {
        "severity": "MEDIUM",
        "source": "cbom",
    },
}


def _confidence_from_count(count: int) -> float:
    if count >= 10:
        return 0.95
    if count >= 5:
        return 0.90
    if count >= 2:
        return 0.82
    if count == 1:
        return 0.70
    return 0.0


def _add_signal(signals: list[dict], signal_id: str, evidence_count: int, reason: str, severity_override: str | None = None):
    if evidence_count <= 0:
        return

    meta = SIGNAL_CATALOG.get(signal_id, {})

    signals.append({
        "signal_id": signal_id,
        "severity": severity_override or meta.get("severity", "MEDIUM"),
        "confidence": _confidence_from_count(evidence_count),
        "source": meta.get("source", "unknown"),
        "evidence_count": evidence_count,
        "reason": reason,
    })


def derive_governance_signals(payload: dict) -> dict:
    findings = payload.get("findings", []) or []

    secret_summary = payload.get("secret_intelligence_summary", {}) or {}
    dependency_summary = payload.get("dependency_summary", {}) or {}
    reachability_vuln_summary = payload.get("reachability_vulnerability_summary", {}) or {}
    reachability_summary = payload.get("reachability_summary", {}) or {}

    signals = []

    total_secrets = secret_summary.get("total_secrets", 0)
    high_secret = secret_summary.get("high_blast_radius", 0)
    critical_secret = secret_summary.get("critical_blast_radius", 0)

    secret_severity = (
        "HIGH" if critical_secret > 0 or high_secret > 0 else
        "MEDIUM" if total_secrets > 0 else
        "LOW"
    )
    _add_signal(
        signals,
        "SECRET_MANAGEMENT_WEAKNESS",
        total_secrets,
        (
            f"{total_secrets} secrets classified; "
            f"{critical_secret} critical blast radius and "
            f"{high_secret} high blast radius."
        ),
        secret_severity,
    )

    reachable_vuln = reachability_vuln_summary.get("reachable_vulnerable_packages", 0)
    not_observed_vuln = reachability_vuln_summary.get("not_observed_vulnerable_packages", 0)

    _add_signal(
        signals,
        "PATCH_GOVERNANCE_WEAKNESS",
        reachable_vuln + not_observed_vuln,
        (
            f"{reachable_vuln} reachable vulnerable packages and "
            f"{not_observed_vuln} vulnerable packages not observed as referenced."
        )
    )

    vulnerable_direct = dependency_summary.get("vulnerable_direct_dependencies", 0)
    vulnerable_transitive = dependency_summary.get("vulnerable_transitive_dependencies", 0)

    _add_signal(
        signals,
        "SUPPLY_CHAIN_GOVERNANCE_WEAKNESS",
        vulnerable_direct + vulnerable_transitive,
        (
            f"{vulnerable_direct} vulnerable direct dependencies and "
            f"{vulnerable_transitive} vulnerable transitive dependencies."
        )
    )

    cloud_findings = [
        f for f in findings
        if (
            str(f.get("rule_id") or "").startswith(("TF_", "K8S_"))
            or "aws" in str(f).lower()
            or "azure" in str(f).lower()
            or "gcp" in str(f).lower()
            or "cloud" in str(f).lower()
        )
    ]

    _add_signal(
        signals,
        "CLOUD_GOVERNANCE_WEAKNESS",
        len(cloud_findings),
        f"{len(cloud_findings)} cloud or cloud-IaC governance indicators identified."
    )

    container_findings = [
        f for f in findings
        if (
            str(f.get("rule_id") or "").startswith("DOCKER_")
            or "docker" in str(f).lower()
            or "container" in str(f).lower()
            or "privileged" in str(f).lower()
        )
    ]

    _add_signal(
        signals,
        "CONTAINER_GOVERNANCE_WEAKNESS",
        len(container_findings),
        f"{len(container_findings)} container governance indicators identified."
    )

    api_findings = [
        f for f in findings
        if (
            f.get("vuln_type") in {"api_idor", "api_jwt_bypass", "ssrf"}
            or "jwt" in str(f).lower()
            or "idor" in str(f).lower()
        )
    ]

    _add_signal(
        signals,
        "API_GOVERNANCE_WEAKNESS",
        len(api_findings),
        f"{len(api_findings)} API security governance indicators identified."
    )

    crypto_findings = [
        f for f in findings
        if (
            f.get("vuln_type") == "weak_crypto"
            or "crypto" in str(f).lower()
            or "private key" in str(f).lower()
        )
    ]

    _add_signal(
        signals,
        "CRYPTOGRAPHIC_GOVERNANCE_WEAKNESS",
        len(crypto_findings),
        f"{len(crypto_findings)} cryptographic governance indicators identified."
    )

    license_findings = [
        f for f in findings
        if (
            "license" in str(f).lower()
            or "gpl" in str(f).lower()
            or "agpl" in str(f).lower()
            or "copyleft" in str(f).lower()
        )
    ]

    _add_signal(
        signals,
        "LICENSE_GOVERNANCE_RISK",
        len(license_findings),
        f"{len(license_findings)} license governance indicators identified."
    )

    return {
        "governance_signals": signals,
        "governance_signal_summary": {
            "total_signals": len(signals),
            "high_signals": sum(1 for s in signals if s.get("severity") == "HIGH"),
            "medium_signals": sum(1 for s in signals if s.get("severity") == "MEDIUM"),
            "low_signals": sum(1 for s in signals if s.get("severity") == "LOW"),
        }
    }


if __name__ == "__main__":
    sample_payload = {
        "secret_intelligence_summary": {
            "total_secrets": 12,
            "critical_blast_radius": 1,
            "high_blast_radius": 8,
        },
        "reachability_vulnerability_summary": {
            "reachable_vulnerable_packages": 3,
            "not_observed_vulnerable_packages": 2,
        },
        "dependency_summary": {
            "vulnerable_direct_dependencies": 4,
            "vulnerable_transitive_dependencies": 6,
        },
        "findings": [
            {"title": "Privileged Container", "rule_id": "K8S_PRIVILEGED_CONTAINER"},
            {"title": "Public S3 Bucket", "rule_id": "TF_PUBLIC_S3"},
            {"title": "Authentication Bypass via JWT Misconfiguration", "vuln_type": "api_jwt_bypass"},
            {"title": "Private Key Header", "vuln_type": "hardcoded_secret"},
            {"title": "MD5 Usage", "vuln_type": "weak_crypto"},
        ]
    }

    import json
    print(json.dumps(derive_governance_signals(sample_payload), indent=2))