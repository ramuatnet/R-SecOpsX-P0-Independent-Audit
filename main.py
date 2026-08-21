r"""
main.py  -  R-SecOpsX SAST v2.0  (branding: edit core/config.py)
"""
from __future__ import annotations

import argparse
import json
import multiprocessing
import os
import sys
import time
from pathlib import Path

from core.config import TOOL_NAME, TOOL_FULL
from core.path_utils import file_name, to_report_path
from scanner.abom import generate_abom
from scanner.aibom import generate_aibom
from scanner.apibom import generate_apibom
from scanner.cbom import generate_cbom
from scanner.iac_kubernetes import scan_kubernetes
from scanner.iac_terraform import scan_terraform
from scanner.mlbom import generate_mlbom
from scanner.iac_docker import scan_docker
from scanner.compliance_mapper import enrich_compliance, compliance_summary
from scanner.package_intelligence import enrich_report_payload
from scanner.dependency_intelligence import enrich_dependency_intelligence, dependency_summary
from scanner.secret_intelligence import (
    enrich_secret_intelligence,
    secret_intelligence_summary,
    apply_optional_live_secret_validation,
    scan_secret_intelligence,
)
from analysis.governance_signal_engine import derive_governance_signals
from analysis.executive_decision_engine import derive_executive_decision
from scanner.reachability import analyze_reachability
from analysis.framework_enrichment_engine import (
    enrich_framework_mappings,
    framework_mapping_summary,
)
from scanner.llm_security import scan_llm_file
from scanner.advanced_ai_security import scan_advanced_ai_file
from analysis.vulnerability_age_engine import (
    enrich_vulnerability_age,
    vulnerability_age_summary,
)
from analysis.license_policy_engine import (
    enrich_license_policy,
    license_policy_summary,
)
from analysis.epss_intelligence_engine import (
    enrich_epss_intelligence,
    epss_intelligence_summary,
)
from analysis.exploitability_decision_engine import (
    enrich_exploitability_decision,
    exploitability_summary,
)
from analysis.kev_intelligence_engine import (
    enrich_kev_intelligence,
    kev_intelligence_summary,
)
from analysis.legacy_protocol_engine import enrich_legacy_protocol_intelligence
from analysis.exposure_surface_engine import enrich_exposure_surface_intelligence
from analysis.supply_chain_trust_engine import enrich_supply_chain_trust
from analysis.runtime_artifact_integrity_engine import enrich_runtime_artifact_integrity
from analysis.data_flow_sensitivity_engine import enrich_data_flow_sensitivity
from analysis.data_flow_correlation_engine import enrich_data_flow_correlation
from analysis.identity_access_risk_engine import enrich_identity_access_risk
from analysis.identity_access_correlation_engine import enrich_identity_access_correlation
from analysis.auth_hardening_risk_engine import enrich_auth_hardening_risk
from analysis.auth_hardening_correlation_engine import enrich_auth_hardening_correlation
from analysis.ai_model_risk_engine import enrich_ai_model_risk
from analysis.business_logic_risk_engine import enrich_business_logic_risk
from analysis.business_logic_correlation_engine import enrich_business_logic_correlation
from analysis.crypto_misuse_engine import enrich_crypto_misuse
from analysis.secret_blast_radius_correlation_engine import enrich_secret_blast_radius_correlation
from analysis.api_abuse_risk_engine import enrich_api_abuse_risk
from analysis.api_abuse_engine import analyze_api_abuse
from analysis.security_control_coverage_engine import enrich_security_control_coverage
from analysis.release_readiness_engine import derive_release_readiness
from analysis.copyright_ip_compliance_engine import analyze_copyright_ip_compliance
from analysis.privacy_data_exposure_engine import enrich_privacy_data_exposure
from analysis.ioc_malware_intelligence_engine import enrich_ioc_malware_intelligence

from analysis.sbom_inventory_engine import build_sbom_full_inventory
from analysis.license_matrix_engine import build_license_matrix
from analysis.dependency_lineage_engine import build_dependency_lineage

def classify_issue_group(finding: dict) -> str:
    vuln_type = str(finding.get("vuln_type", "")).lower()
    rule_id = str(finding.get("rule_id", "")).lower()
    title = str(finding.get("title", "")).lower()

    # Preserve IaC classification before generic credential/AI matching.
    if (
        vuln_type.startswith("k8s_")
        or vuln_type.startswith("tf_")
        or vuln_type.startswith("iac_")
        or vuln_type.startswith("docker_")
        or rule_id.startswith("k8s_")
        or rule_id.startswith("tf_")
        or rule_id.startswith("docker_")
    ):
        return finding.get("issue_group") or "Infrastructure / IaC"

    if vuln_type == "hardcoded_secret" or any(x in title for x in [
        "token", "secret", "password", "private key", "access key",
        "connection string", "credential", "jwt",
    ]):
        return "Credentials"

    if "crypto" in vuln_type or "hash" in title or "md5" in title or "sha1" in title:
        return "Crypto"

    if "ai" in vuln_type or "llm" in title or "openai" in title:
        return "AI"

    if "iac" in vuln_type or "terraform" in title or "container" in title:
        return "Infrastructure / IaC"

    if "sql" in vuln_type or "command" in vuln_type or "code_injection" in vuln_type:
        return "Injection"

    if "ssrf" in vuln_type:
        return "SSRF"

    if "deserialization" in vuln_type:
        return "Deserialization"

    if "debug" in vuln_type:
        return "Security Misconfiguration"

    if "api" in vuln_type:
        return "API Security"

    return "Application Security"


_HERE = Path(os.path.abspath(__file__)).parent
os.chdir(str(_HERE))
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))
os.environ["MPLBACKEND"] = "Agg"


def _safe_print(text):
    try:
        print(text, flush=True)
    except UnicodeEncodeError:
        print(text.encode("ascii", errors="replace").decode("ascii"), flush=True)


def _banner():
    banner_title = f"{TOOL_FULL}  --  Security Scanner"
    line1 = f"|    {banner_title:<60}|"
    _safe_print(f"""
+--------------------------------------------------------------+
{line1}
|    SAST + SCA + Attack Path Correlation + Risk Scoring      |
+--------------------------------------------------------------+
""")


def _step(label, detail=""):
    msg = f"  >>  {label}"
    if detail:
        msg += f"  ({detail})"
    _safe_print(msg)


def _print_dist(dist):
    labels = {
        "Critical": "[CRIT]",
        "High": "[HIGH]",
        "Medium": "[MED] ",
        "Low": "[LOW] ",
        "Info": "[INFO]",
    }
    _safe_print("")
    _safe_print("  +--------------------------------------+")
    _safe_print("  |   SEVERITY DISTRIBUTION              |")
    _safe_print("  +--------------------------------------+")
    for sev in ["Critical", "High", "Medium", "Low", "Info"]:
        count = dist.get(sev, 0)
        bar = "#" * min(count, 20)
        _safe_print(f"  | {labels[sev]} {sev:<10}  {count:3d}  {bar:<20} |")
    _safe_print("  +--------------------------------------+")
    _safe_print("")


def _dedupe_findings(findings: list[dict]) -> list[dict]:
    seen = set()
    deduped = []

    for finding in findings:
        key = (
            finding.get("rule_id") or finding.get("vuln_type"),
            finding.get("file") or finding.get("file_path"),
            finding.get("line"),
            finding.get("snippet") or finding.get("evidence"),
        )

        if key in seen:
            continue

        seen.add(key)
        deduped.append(finding)

    return deduped



def _collect_secret_findings(findings: list[dict]) -> list[dict]:
    """
    Collect only secret-like findings for optional V4 live validation.

    This intentionally does not change the V3 finding schema. It only selects
    candidates after existing secret intelligence enrichment has completed.
    """
    secret_terms = (
        "secret",
        "credential",
        "api key",
        "apikey",
        "access key",
        "token",
        "password",
        "passwd",
        "pwd",
        "private key",
        "client secret",
        "connection string",
        "database url",
        "jdbc",
        "oauth",
        "jwt",
    )

    secret_vuln_types = {
        "hardcoded_secret",
        "secret_exposure",
        "jwt_secret",
        "connection_string",
        "oauth_client_secret",
        "database_connection_string",
        "database_connection_secret",
        "kafka_credential",
        "rabbitmq_credential",
        "spring_config_secret",
        "cloud_secret",
        "messaging_secret",
        "cloud_metadata_credential",
    }

    selected = []

    for finding in findings or []:
        if not isinstance(finding, dict):
            continue

        vuln_type = str(finding.get("vuln_type", "")).lower()
        if vuln_type in secret_vuln_types:
            selected.append(finding)
            continue

        haystack = " ".join(
            str(finding.get(k, ""))
            for k in (
                "rule_id",
                "title",
                "type",
                "secret_type",
                "description",
                "category",
                "issue_group",
                "snippet",
            )
        ).lower()

        if any(term in haystack for term in secret_terms):
            selected.append(finding)

    return selected


def _scan_llm_security(target: str) -> list[dict]:
    findings = []
    scan_ext = {
        ".py", ".js", ".ts", ".jsx", ".tsx",
        ".java", ".go", ".php", ".rb", ".cs",
        ".yml", ".yaml", ".json", ".txt", ".md",
        ".sh", ".ps1", ".bat"
    }

    skip_names = {
        "readme.md",
        "license.md",
        "changelog.md",
    }

    skip_parts = {
        "docs",
        "documentation",
        "examples",
        "tests",
        "test",
    }

    for path in Path(target).rglob("*"):
        if not path.is_file():
            continue

        if path.suffix.lower() not in scan_ext:
            continue

        name = path.name.lower()
        parts = {p.lower() for p in path.parts}

        if (
            name in skip_names
            or name.startswith("expected_")
            or "_expected" in name
            or name.endswith("_expected.json")
            or parts.intersection(skip_parts)
        ):
            continue

        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
            findings.extend(scan_llm_file(str(path), content))
        except Exception:
            continue

    return findings
    

def _scan_advanced_ai_security(target: str) -> list[dict]:
    findings = []
    scan_ext = {
        ".py", ".js", ".ts", ".jsx", ".tsx",
        ".java", ".go", ".php", ".rb", ".cs",
        ".yml", ".yaml", ".json", ".txt",
        ".sh", ".ps1", ".bat"
    }

    for path in Path(target).rglob("*"):
        if not path.is_file():
            continue

        if path.suffix.lower() not in scan_ext:
            continue

        name = path.name.lower()
        parts = {p.lower() for p in path.parts}

        if (
            name.startswith("expected_")
            or "_expected" in name
            or parts.intersection({"docs", "documentation", "examples", "tests", "test"})
        ):
            continue

        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
            findings.extend(scan_advanced_ai_file(str(path), content))
        except Exception:
            continue

    return findings
    

def _normalize_finding_paths(payload: dict, target: str) -> None:
        for finding in payload.get("findings", []):
            original = finding.get("file", "")

            finding["full_path"] = finding.get("full_path") or original
            finding["file"] = to_report_path(original, target)
            finding["file_name"] = file_name(original)

            finding["issue_group"] = classify_issue_group(finding)
            finding["issue_type"] = finding.get("title", "")
            finding["file_path"] = finding.get("file", "")

            for occ in finding.get("occurrences", []):
                occ_original = occ.get("file", "")
                occ_full_original = occ.get("full_path") or occ_original

                # Preserve each occurrence's own absolute path. Previously grouped
                # findings inherited the first finding's full_path, which caused
                # cross-file evidence to point to the wrong source file.
                if ":" in str(occ_full_original) or str(occ_full_original).startswith("/"):
                    occ["full_path"] = occ_full_original
                elif ":" in str(occ_original) or str(occ_original).startswith("/"):
                    occ["full_path"] = occ_original
                elif ":" not in str(occ.get("full_path", "")):
                    occ["full_path"] = finding.get("full_path", occ_original)

                occ["file"] = to_report_path(occ_original, target)
                occ["file_name"] = file_name(occ_original)
                occ["file_path"] = occ.get("file", "")

            finding["affected_files"] = sorted({
                occ.get("file", "")
                for occ in finding.get("occurrences", [])
                if occ.get("file")
        })
        
def _apply_iac_metadata(payload: dict) -> None:
    metadata = payload.setdefault("metadata", {})

    metadata["k8s_findings"] = sum(
        1 for finding in payload.get("findings", [])
        if str(finding.get("rule_id", "")).startswith("K8S_")
    )

    metadata["tf_findings"] = sum(
        1 for finding in payload.get("findings", [])
        if str(finding.get("rule_id", "")).startswith("TF_")
    )

    metadata["docker_findings"] = sum(
        1 for finding in payload.get("findings", [])
        if str(finding.get("rule_id", "")).startswith("DOCKER_")
    )

    metadata["iac_findings"] = (
        metadata.get("k8s_findings", 0)
        + metadata.get("tf_findings", 0)
        + metadata.get("docker_findings", 0)
    )


def _cleanup_report_noise(payload: dict) -> None:
    empty_list_fields = {
        "owasp_api_top10_2023",
        "owasp_llm_top10",
        "capec",
        "d3fend",
        "nist_csf_2_0",
        "nist_800_53",
        "iso_27001_2022",
        "pci_dss",
        "soc2",
        "hipaa",
        "gdpr",
        "dpdp",
        "remediation",
        "cwe",
        "mitre_attack",
        "owasp_top10_2021",
        "aliases",
        "fixed_versions",
        "indicators",
        "evidence",
        "chains_to",
        "likely_assets",
        "route_params",
        "mapped_frameworks",
        "memory_detected",
        "global_indicators",
    }

    def _clean_node(node):
        if isinstance(node, dict):
            if (
                node.get("taint_chain") == []
                and node.get("detection") != "ENTERPRISE_MULTI_LANGUAGE_TAINT_V1"
            ):
                node.pop("taint_chain", None)

            for key in empty_list_fields:
                if node.get(key) == []:
                    node.pop(key, None)

            for value in list(node.values()):
                _clean_node(value)

        elif isinstance(node, list):
            for item in node:
                _clean_node(item)

    _clean_node(payload)



def _valid_report_value(value) -> bool:
    if value is None:
        return False
    text = str(value).strip()
    return bool(text) and text.lower() not in {"none", "null", "unknown", "n/a", "na", ""}


def _safe_float(value, default: float = 0.0) -> float:
    try:
        return float(value)
    except Exception:
        return default


def _build_dependency_reporting_views(payload: dict) -> None:
    """Create stable report-facing dependency/CVE views without changing scanner findings."""
    sbom = payload.get("sbom", []) or []

    cve_rows = []
    advisory_rows = []
    reachable_vulnerable = []
    not_observed_vulnerable = []

    for pkg in sbom:
        cves = pkg.get("cve_list") or ([] if not pkg.get("cve") else [pkg.get("cve")])
        advisories = pkg.get("advisory_ids") or ([] if not pkg.get("advisory_id") else [pkg.get("advisory_id")])
        primary_id = (
            pkg.get("primary_vulnerability_id")
            or pkg.get("cve")
            or pkg.get("advisory_id")
        )

        row = {
            "package": pkg.get("name"),
            "name": pkg.get("name"),
            "version": pkg.get("version"),
            "ecosystem": pkg.get("ecosystem"),
            "dependency_type": pkg.get("dependency_type"),
            "purl": pkg.get("purl"),
            "primary_vulnerability_id": primary_id,
            "cve": pkg.get("cve"),
            "cve_list": cves,
            "advisory_id": pkg.get("advisory_id"),
            "advisory_ids": advisories,
            "cvss": pkg.get("cvss"),
            "cvss_score": pkg.get("cvss_score", pkg.get("cvss")),
            "cvss_available": pkg.get("cvss_available", pkg.get("cvss") is not None),
            "severity": pkg.get("severity"),
            "fixed_in": pkg.get("fixed_in") or pkg.get("fixed_versions"),
            "fixed_versions": pkg.get("fixed_versions"),
            "reachability_status": pkg.get("reachability_status"),
            "reachability_priority": pkg.get("reachability_priority"),
            "reachability_confidence": pkg.get("reachability_confidence"),
            "kev_status": pkg.get("kev_status"),
            "actively_exploited": pkg.get("actively_exploited"),
            "epss_score": pkg.get("epss_score"),
            "epss_bucket": pkg.get("epss_bucket"),
            "epss_priority": pkg.get("epss_priority"),
            "patch_urgency": pkg.get("patch_urgency"),
            "exploitability_decision": pkg.get("exploitability_decision"),
            "license": pkg.get("license"),
            "license_policy_decision": pkg.get("license_policy_decision"),
        }

        if _valid_report_value(primary_id) or cves or advisories:
            advisory_rows.append(row)

        for cve in cves:
            cve_row = dict(row)
            cve_row["cve"] = cve
            cve_rows.append(cve_row)

        if pkg.get("reachability_priority") == "REACHABLE_VULNERABLE":
            reachable_vulnerable.append(row)
        elif pkg.get("reachability_priority") == "NOT_OBSERVED_VULNERABLE":
            not_observed_vulnerable.append(row)

    def _dep_rank(item: dict) -> tuple:
        return (
            1 if item.get("kev_status") else 0,
            _safe_float(item.get("cvss")),
            _safe_float(item.get("epss_score")),
            1 if item.get("reachability_priority") == "REACHABLE_VULNERABLE" else 0,
        )

    payload["dependency_risk_register"] = sorted(advisory_rows, key=_dep_rank, reverse=True)
    payload["top_dependency_risks"] = payload["dependency_risk_register"][:25]
    payload["top_cves"] = sorted(cve_rows, key=_dep_rank, reverse=True)[:25]
    payload["reachable_vulnerable_packages"] = reachable_vulnerable
    payload["not_observed_vulnerable_packages"] = not_observed_vulnerable

    metadata = payload.setdefault("metadata", {})
    metadata["cve_count"] = len({r.get("cve") for r in cve_rows if _valid_report_value(r.get("cve"))})
    metadata["advisory_count"] = len({
        advisory
        for row in advisory_rows
        for advisory in (row.get("advisory_ids") or [])
        if _valid_report_value(advisory)
    })
    metadata["packages_with_cvss"] = sum(1 for row in advisory_rows if row.get("cvss") is not None)
    metadata["packages_missing_cvss"] = sum(1 for row in advisory_rows if row.get("cvss") is None)
    metadata["dependency_risk_register_count"] = len(advisory_rows)



# -----------------------------------------------------------------------------
# Final client-facing mapping normalization
# -----------------------------------------------------------------------------
FINAL_BUSINESS_IMPACT_BY_RULE = {
    "SPRING_SECURITY_CSRF_DISABLED": "Global CSRF disablement and broad permitAll rules can allow unauthorized state-changing requests, session abuse, and broken access-control outcomes.",
    "SPRING_SECURITY_BROAD_PERMITALL_EXPOSURE": "Broad permitAll exposure can make privileged routes reachable without authentication, increasing account takeover and unauthorized administration risk.",
    "SPRING_SECURITY_PERMITALL_EXPOSURE": "Broad permitAll exposure can make privileged routes reachable without authentication, increasing account takeover and unauthorized administration risk.",
    "MASS_ASSIGNMENT": "Mass assignment can let attackers set fields the UI never intended to expose, causing privilege escalation, tenant-boundary bypass, or business workflow abuse.",
    "SPRING_MVC_MASS_ASSIGNMENT": "Mass assignment can let attackers set privileged fields such as role, isAdmin, tenantId, account status, balance, or approval state.",
    "ASP_NET_MASS_ASSIGNMENT": "Overposting can let attackers set privileged model fields such as role, isAdmin, tenantId, account status, or approval state.",
    "GRAPHQL_INTROSPECTION_EXPOSURE": "GraphQL introspection in production can expose schema, object names, hidden mutations, and authorization-sensitive fields, accelerating API reconnaissance.",
    "GRAPHQL_RESOLVER_BOLA_IDOR": "A resolver that fetches objects by user-controlled IDs without ownership checks can expose or modify another user's or tenant's records.",
    "GRAPHQL_BOLA_IDOR": "GraphQL BOLA/IDOR can allow attackers to access unauthorized objects by changing IDs, tenant IDs, or resolver parameters.",
    "TENANT_ISOLATION_FAILURE": "Missing tenant-boundary enforcement can expose cross-tenant data, enable account takeover across tenants, and create severe confidentiality and compliance impact.",
    "PRIVILEGE_ESCALATION_INDICATOR": "Privilege escalation paths can allow a standard user or service to perform admin actions, modify roles, or bypass approval gates.",
    "WORKFLOW_BYPASS_INDICATOR": "Workflow bypass can allow unauthorized approval, state transition, duplicate action, refund, payment, coupon, or account changes outside the intended process.",
    "JAVA_REFLECTION_SET_ACCESSIBLE": "Reflection access override can bypass encapsulation and security checks, enabling unauthorized access to private fields or methods and weakening sandbox assumptions.",
    "DANGEROUS_REFLECTION_SETACCESSIBLE": "setAccessible(true) can bypass Java access controls and may support exploit chains where attacker-influenced class or method names are used.",
    "API_LOGIN_BRUTE_FORCE": "Login endpoints without rate limits or lockout protections can enable credential stuffing, brute force, account takeover, and authentication service degradation.",
    "API_OTP_BRUTE_FORCE": "OTP and MFA endpoints without throttling can enable OTP guessing, MFA bypass, and account takeover.",
    "API_PASSWORD_RESET_ABUSE": "Password reset endpoints without throttling can enable reset flooding, user enumeration, token spraying, and account recovery abuse.",
    "API_INVITE_ABUSE": "Invite endpoints without throttling can enable spam, account enumeration, and social-engineering abuse.",
    "API_COUPON_REPLAY": "Coupon or promotion endpoints without replay/idempotency controls can enable financial loss through repeated redemption or abuse automation.",
    "API_TOKEN_REFRESH_ABUSE": "Token refresh endpoints without throttling and reuse detection can enable token spray, session extension abuse, and account takeover persistence.",
    "API_PAYMENT_DUPLICATE_ACTION": "Payment or transfer endpoints without idempotency controls can enable duplicate charges, duplicate withdrawals, or transaction integrity failures.",
}

FINAL_COMPLIANCE_BY_RULE = {
    "TENANT_ISOLATION_FAILURE": {
        "pci_dss": "Req 7 / Req 8 - Access control and tenant data segregation",
        "nist": "AC-3 / AC-6 / SC-7",
        "nist_800_53": "AC-3 / AC-6 / SC-7",
        "iso27001": "A.5.15 / A.8.3 / A.8.20",
        "iso_27001": "A.5.15 / A.8.3 / A.8.20",
        "soc2": "CC6.1 / CC6.6 / CC7.2",
        "owasp": "A01:2021 - Broken Access Control",
        "cwe": "CWE-639",
        "mitre": "T1190",
    },
    "GRAPHQL_INTROSPECTION_EXPOSURE": {
        "pci_dss": "Req 6.2.4 - Secure API configuration",
        "nist": "CM-7 / AC-3 / SC-7",
        "nist_800_53": "CM-7 / AC-3 / SC-7",
        "iso27001": "A.8.9 / A.8.20",
        "iso_27001": "A.8.9 / A.8.20",
        "soc2": "CC6.6 / CC7.2",
        "owasp": "A05:2021 - Security Misconfiguration",
        "cwe": "CWE-200",
        "mitre": "T1595",
    },
    "GRAPHQL_RESOLVER_BOLA_IDOR": {
        "pci_dss": "Req 7 / Req 8 - Access control",
        "nist": "AC-3 / AC-6 / SI-10",
        "nist_800_53": "AC-3 / AC-6 / SI-10",
        "iso27001": "A.5.15 / A.8.3 / A.8.20",
        "iso_27001": "A.5.15 / A.8.3 / A.8.20",
        "soc2": "CC6.1 / CC6.6",
        "owasp": "A01:2021 - Broken Access Control",
        "cwe": "CWE-639",
        "mitre": "T1190",
    },
    "JAVA_REFLECTION_SET_ACCESSIBLE": {
        "pci_dss": "Req 6.2.4 - Secure coding and unsafe reflection prevention",
        "nist": "SI-10 / CM-7 / SA-11",
        "nist_800_53": "SI-10 / CM-7 / SA-11",
        "iso27001": "A.8.28 / A.8.29",
        "iso_27001": "A.8.28 / A.8.29",
        "soc2": "CC7.1 / CC7.2",
        "owasp": "A05:2021 - Security Misconfiguration",
        "cwe": "CWE-470",
        "mitre": "T1059",
    },
    "DANGEROUS_REFLECTION_SETACCESSIBLE": {
        "pci_dss": "Req 6.2.4 - Secure coding and unsafe reflection prevention",
        "nist": "SI-10 / CM-7 / SA-11",
        "nist_800_53": "SI-10 / CM-7 / SA-11",
        "iso27001": "A.8.28 / A.8.29",
        "iso_27001": "A.8.28 / A.8.29",
        "soc2": "CC7.1 / CC7.2",
        "owasp": "A05:2021 - Security Misconfiguration",
        "cwe": "CWE-470",
        "mitre": "T1059",
    },
}


def _final_rule_key(finding: dict) -> str:
    text = " ".join([
        str(finding.get("rule_id", "")),
        str(finding.get("title", "")),
        str(finding.get("vuln_type", "")),
    ]).upper().replace("-", "_").replace(" ", "_").replace("/", "_")

    if "TENANT_ISOLATION" in text:
        return "TENANT_ISOLATION_FAILURE"
    if "GRAPHQL" in text and ("INTROSPECTION" in text or "__SCHEMA" in text):
        return "GRAPHQL_INTROSPECTION_EXPOSURE"
    if "GRAPHQL" in text and ("BOLA" in text or "IDOR" in text or "RESOLVER" in text):
        return "GRAPHQL_RESOLVER_BOLA_IDOR"
    if "SETACCESSIBLE" in text or "SET_ACCESSIBLE" in text:
        return "JAVA_REFLECTION_SET_ACCESSIBLE"
    if "MASS_ASSIGNMENT" in text or "OVERPOSTING" in text:
        return "MASS_ASSIGNMENT"
    if "PERMITALL" in text or "PERMIT_ALL" in text:
        return "SPRING_SECURITY_BROAD_PERMITALL_EXPOSURE"
    if "CSRF" in text and "DISABLED" in text:
        return "SPRING_SECURITY_CSRF_DISABLED"
    if "LOGIN_BRUTE" in text or "API_LOGIN" in text:
        return "API_LOGIN_BRUTE_FORCE"
    if "OTP" in text or "MFA" in text:
        return "API_OTP_BRUTE_FORCE"
    if "PASSWORD_RESET" in text or "RESET_PASSWORD" in text or "FORGOT_PASSWORD" in text:
        return "API_PASSWORD_RESET_ABUSE"
    if "INVITE" in text or "INVITATION" in text:
        return "API_INVITE_ABUSE"
    if "COUPON" in text or "PROMO" in text or "REDEEM" in text or "VOUCHER" in text:
        return "API_COUPON_REPLAY"
    if "TOKEN_REFRESH" in text or "REFRESH_TOKEN" in text:
        return "API_TOKEN_REFRESH_ABUSE"
    if "PAYMENT" in text or "TRANSFER" in text or "IDEMPOTENCY" in text:
        return "API_PAYMENT_DUPLICATE_ACTION"
    return str(finding.get("rule_id", "")).upper()


def _is_empty_mapping(value) -> bool:
    text = str(value or "").strip().lower()
    return text in {"", "none", "null", "unknown", "n/a", "na", "not applicable"}


def _apply_final_mapping_normalization(payload: dict) -> dict:
    findings = payload.get("findings", []) or []
    if not isinstance(findings, list):
        return payload

    for finding in findings:
        if not isinstance(finding, dict):
            continue
        rule_key = _final_rule_key(finding)

        if rule_key in FINAL_BUSINESS_IMPACT_BY_RULE:
            finding["business_impact"] = FINAL_BUSINESS_IMPACT_BY_RULE[rule_key]

        comp = FINAL_COMPLIANCE_BY_RULE.get(rule_key)
        if comp:
            for key, value in comp.items():
                if _is_empty_mapping(finding.get(key)):
                    finding[key] = value

            controls = finding.setdefault("compliance_controls", {})
            if isinstance(controls, dict):
                if comp.get("owasp"):
                    controls["OWASP"] = [comp["owasp"]]
                if comp.get("cwe"):
                    controls["CWE"] = [comp["cwe"]]
                if comp.get("nist_800_53"):
                    controls["NIST 800-53"] = [x.strip() for x in comp["nist_800_53"].split("/")]
                if comp.get("pci_dss"):
                    controls["PCI DSS"] = [comp["pci_dss"]]
                if comp.get("iso_27001"):
                    controls["ISO 27001"] = [x.strip() for x in comp["iso_27001"].split("/")]
                if comp.get("soc2"):
                    controls["SOC 2"] = [x.strip() for x in comp["soc2"].split("/")]

        title = str(finding.get("title", "")).upper()
        vuln = str(finding.get("vuln_type", "")).upper()
        if rule_key == "TENANT_ISOLATION_FAILURE" or "TENANT_ISOLATION" in title or "TENANT_ISOLATION" in vuln:
            finding["issue_group"] = "Broken Access Control / Business Logic"
            if str(finding.get("framework", "")).lower() == "ai":
                finding["framework"] = "Application Security"
        elif "GRAPHQL" in title or "GRAPHQL" in vuln:
            finding["issue_group"] = "API Security / GraphQL"
            finding["framework"] = "graphql"
        elif "IDOR" in title or "BOLA" in title or vuln in {"IDOR", "BOLA"}:
            finding["issue_group"] = "Broken Access Control / Business Logic"

    return payload


def main():
    parser = argparse.ArgumentParser(description=TOOL_FULL)
    parser.add_argument(
        "target",
        nargs="?",
        default=str(_HERE / "sample_app"),
        help="Path to scan",
    )
    parser.add_argument(
        "--output-dir",
        "-o",
        default=str(_HERE / "reports"),
        help="Output directory",
    )
    parser.add_argument(
        "--workers",
        "-w",
        type=int,
        default=2,
        help="Parallel workers (default 2)",
    )
    parser.add_argument("--no-pdf", action="store_true")
    parser.add_argument("--no-excel", action="store_true")
    parser.add_argument(
        "--live-secrets",
        action="store_true",
        help="Enable optional live network validation of detected secrets. Disabled by default.",
    )
    parser.add_argument(
        "--live-secret-timeout",
        type=int,
        default=6,
        help="Timeout in seconds per live secret validation request. Default: 6.",
    )
    parser.add_argument(
        "--live-secret-max",
        type=int,
        default=50,
        help="Maximum number of detected secrets to live validate per scan. Default: 50.",
    )
    args = parser.parse_args()

    _banner()

    target = str(Path(os.path.abspath(args.target)))
    output_dir = Path(os.path.abspath(args.output_dir))
    output_dir.mkdir(parents=True, exist_ok=True)
    
    if not os.path.exists(target):
        _safe_print(f"  [ERROR] Target path does not exist: {target}")
        sys.exit(2)

    if not os.path.isdir(target):
        _safe_print(f"  [ERROR] Target path is not a directory: {target}")
        sys.exit(2)

    _safe_print(f"  Tool root : {_HERE}")
    _safe_print(f"  Target    : {target}")
    _safe_print(f"  Output    : {output_dir}")
    _safe_print(f"  Workers   : {args.workers}")
    _safe_print("")

    t0 = time.time()

    _step("Scanning codebase", f"regex + AST taint, {args.workers} workers")
    from scanner.sast import scan_directory

    raw = scan_directory(target, workers=args.workers)
    _safe_print(f"       => {len(raw)} raw findings in {time.time() - t0:.1f}s")

    _step("Generating SBOM & dependency analysis")
    from scanner.sbom import generate_sbom

    sbom = generate_sbom(target)
    vuln_deps = [d for d in sbom if d.get("cve")]
    _safe_print(f"       => {len(sbom)} packages, {len(vuln_deps)} with known CVEs")

    _step("Generating CBOM crypto inventory")
    cbom = generate_cbom(target)
    _safe_print(f"       => {len(cbom)} crypto assets identified")

    _step("Generating AI-BOM model/provider inventory")
    aibom = generate_aibom(target)
    _safe_print(f"       => {len(aibom)} AI assets identified")

    _step("Generating ML-BOM framework/model inventory")
    mlbom = generate_mlbom(target)
    _safe_print(f"       => {len(mlbom)} ML assets identified")

    _step("Generating API-BOM route inventory")
    apibom = generate_apibom(target)
    _safe_print(f"       => {len(apibom)} API routes identified")

    _step("Scanning API abuse controls")
    api_abuse_findings = []
    try:
        api_abuse_scan = analyze_api_abuse(target)
        if isinstance(api_abuse_scan, dict):
            api_abuse_findings = api_abuse_scan.get("api_abuse_findings", []) or []
        elif isinstance(api_abuse_scan, list):
            api_abuse_findings = api_abuse_scan
        _safe_print(f"       => {len(api_abuse_findings)} API abuse findings")
    except Exception as exc:
        _safe_print(f"       => API abuse scan failed: {exc}")

    _step("Generating ABOM agent inventory")
    abom = generate_abom(target)
    _safe_print(f"       => {len(abom)} AI agents identified")
    
    _step("Scanning OWASP LLM security rules")
    llm_findings = _scan_llm_security(target)
    _safe_print(f"       => {len(llm_findings)} OWASP LLM findings")
    
    _step("Scanning Advanced AI security rules")
    advanced_ai_findings = _scan_advanced_ai_security(target)
    _safe_print(f"       => {len(advanced_ai_findings)} Advanced AI findings")

    _step("Scanning Kubernetes IaC")
    k8s_findings = scan_kubernetes(target)
    _safe_print(f"       => {len(k8s_findings)} Kubernetes findings")

    _step("Scanning Terraform IaC")
    tf_findings = scan_terraform(target)
    _safe_print(f"       => {len(tf_findings)} Terraform findings")

    # --------------------------------------------------
    # Dockerfile IaC Analysis
    # --------------------------------------------------

    _step("Scanning Dockerfile IaC")
    docker_findings = scan_docker(target)
    _safe_print(f"       => {len(docker_findings)} Dockerfile findings")

    # --------------------------------------------------
    # Secret Intelligence Source Scan
    # V4 Phase 1 fix:
    # - V3 enrichment classified only existing findings.
    # - This explicitly adds scanner/secret_intelligence.py findings into raw.
    # - Live validation remains optional and is still controlled by --live-secrets.
    # --------------------------------------------------
    _step("Scanning Secret Intelligence")
    secret_scan_findings = []
    try:
        secret_scan_result = scan_secret_intelligence(target)
        if isinstance(secret_scan_result, dict):
            secret_scan_findings = secret_scan_result.get("secret_intelligence_findings", []) or []
        elif isinstance(secret_scan_result, list):
            secret_scan_findings = secret_scan_result
        _safe_print(f"       => {len(secret_scan_findings)} Secret Intelligence findings")
    except Exception as exc:
        _safe_print(f"       => Secret Intelligence scan failed: {exc}")

    _step("Deduplicating, scoring, correlating attack paths")

    raw.extend(k8s_findings)
    raw.extend(tf_findings)
    raw.extend(docker_findings)
    raw.extend(llm_findings)
    raw.extend(advanced_ai_findings)
    raw.extend(api_abuse_findings)
    raw.extend(secret_scan_findings)
    raw = _dedupe_findings(raw)

    from core.analyzer import build_report_payload

    payload = build_report_payload(raw, sbom, target)

    _normalize_finding_paths(payload, target)
    _apply_iac_metadata(payload)

    # --------------------------------------------------
    # Compliance + Secret Intelligence
    # --------------------------------------------------
    payload["findings"] = enrich_compliance(payload.get("findings", []))
    payload["compliance_summary"] = compliance_summary(payload.get("findings", []))

    payload["findings"] = enrich_secret_intelligence(payload.get("findings", []))
    
    payload["secret_intelligence_summary"] = secret_intelligence_summary(
        payload.get("findings", [])
    )

    secret_validation_candidates = _collect_secret_findings(payload.get("findings", []))
    secret_live_summary = apply_optional_live_secret_validation(
        secret_validation_candidates,
        enabled=bool(args.live_secrets),
        timeout=max(1, int(args.live_secret_timeout)),
        max_validations=max(0, int(args.live_secret_max)),
    )

    payload["secret_live_validation_summary"] = secret_live_summary
    payload["secret_intelligence_summary"]["live_validation_mode"] = secret_live_summary.get(
        "mode",
        "OFFLINE_ONLY_NOT_VALIDATED",
    )
    payload["secret_intelligence_summary"]["live_validated_secrets"] = secret_live_summary.get(
        "live_valid",
        0,
    )
    payload["secret_intelligence_summary"]["live_validation_status"] = secret_live_summary.get(
        "status",
        "SECRET_LIVE_VALIDATION_DISABLED",
    )

    _safe_print(
        "       => Secret Live Validation: "
        f"{secret_live_summary.get('validated', 0)} validated | "
        f"{secret_live_summary.get('live_valid', 0)} live | "
        f"{secret_live_summary.get('not_valid_or_revoked', 0)} revoked/invalid | "
        f"{secret_live_summary.get('unsupported', 0)} unsupported | "
        f"{secret_live_summary.get('no_secret_value', 0)} no-value | "
        f"{secret_live_summary.get('inconclusive', 0)} inconclusive | "
        f"{secret_live_summary.get('errors', 0)} errors | "
        f"{secret_live_summary.get('status', 'SECRET_LIVE_VALIDATION_DISABLED')}"
    )

    payload["secret_blast_radius_correlation_summary"] = enrich_secret_blast_radius_correlation(
        payload.get("findings", []),
        api_bom=payload.get("apibom", []),
        abom=payload.get("abom", []),
        aibom=payload.get("aibom", []),
    )
   
    payload["findings"] = enrich_framework_mappings(payload.get("findings", []))
    payload["framework_mapping_summary"] = framework_mapping_summary(
        payload.get("findings", [])
    )
    # --------------------------------------------------
    # BOM payload enrichment
    # --------------------------------------------------
    payload["cbom"] = cbom
    payload["aibom"] = aibom
    payload["mlbom"] = mlbom
    payload["apibom"] = apibom
    payload["abom"] = abom
    payload = enrich_report_payload(payload)

    # --------------------------------------------------
    # Dependency Intelligence -> Reachability -> Vulnerability Age
    # IMPORTANT: This order is required so later governance/executive
    # logic sees final dependency, reachability, and age intelligence.
    # --------------------------------------------------
    payload["sbom"] = enrich_dependency_intelligence(payload.get("sbom", []))
    dep_summary = dependency_summary(payload.get("sbom", []))
    payload["dependency_summary"] = dep_summary

    reachability_result = analyze_reachability(
        target,
        payload.get("sbom", [])
    )

    payload["sbom"] = reachability_result.get("sbom", payload.get("sbom", []))
    payload["reachability_summary"] = reachability_result.get("reachability_summary", {})
    payload["reachability_vulnerability_summary"] = reachability_result.get(
        "reachability_vulnerability_summary", {}
    )
    payload["reachability_references_count"] = reachability_result.get(
        "reachability_references_count", 0
    )

    payload["sbom"] = enrich_kev_intelligence(payload.get("sbom", []))
    payload["kev_intelligence_summary"] = kev_intelligence_summary(
        payload.get("sbom", [])
    )

    payload["sbom"] = enrich_vulnerability_age(payload.get("sbom", []))
    payload["vulnerability_age_summary"] = vulnerability_age_summary(
        payload.get("sbom", [])
    )
    
   

    payload["sbom"], payload["legacy_protocol_summary"] = enrich_legacy_protocol_intelligence(
        payload.get("sbom", []),
        findings=payload.get("findings", []),
        cbom=payload.get("cbom", []),
        api_bom=payload.get("apibom", []),
    )

    payload["sbom"], payload["exposure_surface_summary"] = enrich_exposure_surface_intelligence(
        payload.get("sbom", []),
        findings=payload.get("findings", []),
        api_bom=payload.get("apibom", []),
        abom=payload.get("abom", []),
    )
    
    payload["sbom"] = enrich_epss_intelligence(payload.get("sbom", []))
    payload["epss_intelligence_summary"] = epss_intelligence_summary(
        payload.get("sbom", [])
    )
    
    payload["sbom"] = enrich_exploitability_decision(payload.get("sbom", []))
    payload["exploitability_summary"] = exploitability_summary(
        payload.get("sbom", [])
    )
    
    payload["sbom"] = enrich_license_policy(payload.get("sbom", []))
    payload["license_policy_summary"] = license_policy_summary(
        payload.get("sbom", [])
    )
    payload["copyright_ip_compliance"] = analyze_copyright_ip_compliance(target)
    payload["copyright_ip_compliance_summary"] = payload["copyright_ip_compliance"].get(
        "summary", {}
    )
    
    
    
    payload["sbom"], payload["supply_chain_trust_summary"] = enrich_supply_chain_trust(
        payload.get("sbom", [])
    )
    
    payload["sbom"], payload["runtime_artifact_integrity_summary"] = enrich_runtime_artifact_integrity(
        payload.get("sbom", []),
        findings=payload.get("findings", []),
        abom=payload.get("abom", []),
        api_bom=payload.get("apibom", []),
    )
    
    payload["data_flow_sensitivity_summary"] = enrich_data_flow_sensitivity(
        payload.get("findings", []),
        api_bom=payload.get("apibom", []),
        abom=payload.get("abom", []),
    )
    
    correlation_input_findings = []
    correlation_input_findings.extend(payload.get("findings", []) or [])

    dfs = payload.get("data_flow_sensitivity_summary", {})

    if isinstance(dfs, dict):
        correlation_input_findings.extend(dfs.get("indicators", []) or [])
        correlation_input_findings.extend(dfs.get("findings", []) or [])
        correlation_input_findings.extend(dfs.get("sensitive_findings", []) or [])
        correlation_input_findings.extend(dfs.get("data_flow_indicators", []) or [])
        correlation_input_findings.extend(dfs.get("global_indicators", []) or [])

    payload["data_flow_correlation_summary"] = enrich_data_flow_correlation(
        correlation_input_findings,
        api_bom=payload.get("apibom", []),
        abom=payload.get("abom", []),
    )

    # --------------------------------------------------
    # Privacy + IOC / Backdoor Intelligence
    # --------------------------------------------------
    payload["privacy_data_exposure_summary"] = enrich_privacy_data_exposure(
        target,
        findings=payload.get("findings", []),
        api_bom=payload.get("apibom", []),
        data_flow_summary=payload.get("data_flow_sensitivity_summary", {}),
    )

    payload["ioc_malware_intelligence_summary"] = enrich_ioc_malware_intelligence(
        target,
        findings=payload.get("findings", []),
        sbom=payload.get("sbom", []),
    )

    pds = payload.get("privacy_data_exposure_summary", {})
    iocs = payload.get("ioc_malware_intelligence_summary", {})

    payload["metadata"]["privacy_data_exposure_status"] = pds.get("summary_status", "NOT_AVAILABLE")
    payload["metadata"]["privacy_data_exposure_indicators"] = pds.get("total_privacy_indicators", 0)
    payload["metadata"]["privacy_data_exposure_critical"] = pds.get("critical_privacy_indicators", 0)
    payload["metadata"]["privacy_data_exposure_high"] = pds.get("high_privacy_indicators", 0)
    payload["metadata"]["privacy_third_party_transfer_indicators"] = pds.get("third_party_transfer_indicators", 0)

    payload["metadata"]["ioc_malware_status"] = iocs.get("summary_status", "NOT_AVAILABLE")
    payload["metadata"]["ioc_malware_indicators"] = iocs.get("total_ioc_indicators", 0)
    payload["metadata"]["ioc_malware_critical"] = iocs.get("critical_ioc_indicators", 0)
    payload["metadata"]["ioc_malware_high"] = iocs.get("high_ioc_indicators", 0)
    payload["metadata"]["ioc_malware_behavior_indicators"] = iocs.get("malware_behavior_indicators", 0)

    _safe_print(
        "       => Privacy Data Exposure: "
        f"{pds.get('total_privacy_indicators', 0)} indicators | "
        f"{pds.get('critical_privacy_indicators', 0)} critical | "
        f"{pds.get('high_privacy_indicators', 0)} high | "
        f"third-party {pds.get('third_party_transfer_indicators', 0)} | "
        f"{pds.get('summary_status', 'NOT_AVAILABLE')}"
    )

    _safe_print(
        "       => IOC / Backdoor Intelligence: "
        f"{iocs.get('total_ioc_indicators', 0)} indicators | "
        f"{iocs.get('critical_ioc_indicators', 0)} critical | "
        f"{iocs.get('high_ioc_indicators', 0)} high | "
        f"behavior {iocs.get('malware_behavior_indicators', 0)} | "
        f"{iocs.get('summary_status', 'NOT_AVAILABLE')}"
    )
    
    payload["identity_access_risk_summary"] = enrich_identity_access_risk(
        payload.get("findings", []),
        api_bom=payload.get("apibom", []),
        abom=payload.get("abom", []),
        cbom=payload.get("cbom", []),
    )

    payload["identity_access_correlation_summary"] = enrich_identity_access_correlation(
        payload.get("findings", []),
        api_bom=payload.get("apibom", []),
        abom=payload.get("abom", []),
    )

    payload["auth_hardening_risk_summary"] = enrich_auth_hardening_risk(
        payload.get("findings", []),
        api_bom=payload.get("apibom", []),
        target=target,
    )
    
    payload["auth_hardening_correlation_summary"] = enrich_auth_hardening_correlation(
        payload.get("auth_hardening_risk_summary", {}),
        api_bom=payload.get("apibom", []),
    )
    
    
    
    payload["ai_model_risk_summary"] = enrich_ai_model_risk(
        payload.get("findings", []),
        aibom=payload.get("aibom", []),
        mlbom=payload.get("mlbom", []),
        abom=payload.get("abom", []),
    )



    payload["business_logic_risk_summary"] = enrich_business_logic_risk(
        payload.get("findings", []),
        api_bom=payload.get("apibom", []),
        abom=payload.get("abom", []),
    )
    
    payload["api_abuse_risk_summary"] = enrich_api_abuse_risk(
        payload.get("findings", []),
        api_bom=payload.get("apibom", []),
    )

    payload["business_logic_correlation_summary"] = enrich_business_logic_correlation(
        payload.get("business_logic_risk_summary", {}),
        api_abuse_summary=payload.get("api_abuse_risk_summary", {}),
        api_bom=payload.get("apibom", []),
    )


    payload["security_control_coverage_summary"] = enrich_security_control_coverage(
        payload.get("findings", []),
        api_bom=payload.get("apibom", []),
        cbom=payload.get("cbom", []),
        abom=payload.get("abom", []),
    )

    payload["crypto_misuse_summary"] = enrich_crypto_misuse(
        payload.get("findings", []),
        cbom=payload.get("cbom", []),
    )
    sis = payload.get("secret_intelligence_summary", {})
    reach = payload.get("reachability_summary", {})
    rv = payload.get("reachability_vulnerability_summary", {})
    vas = payload.get("vulnerability_age_summary", {})

    # --------------------------------------------------
    # Reachability-Aware Reporting Lists
    # --------------------------------------------------
    reachable_vulnerable_packages = []
    not_observed_vulnerable_packages = []

    for pkg in payload.get("sbom", []):
        item = {
            "name": pkg.get("name"),
            "version": pkg.get("version"),
            "dependency_type": pkg.get("dependency_type"),
            "cve": pkg.get("cve"),
            "license": pkg.get("license"),
            "reachability_status": pkg.get("reachability_status"),
            "reachability_priority": pkg.get("reachability_priority"),
            "reachability_confidence": pkg.get("reachability_confidence"),
            "reachability_method": pkg.get("reachability_method"),
            "published_date": pkg.get("published_date"),
            "vulnerability_age_days": pkg.get("vulnerability_age_days"),
            "vulnerability_age_bucket": pkg.get("vulnerability_age_bucket"),
            "kev_status": pkg.get("kev_status"),
            "actively_exploited": pkg.get("actively_exploited"),
            "outbreak_status": pkg.get("outbreak_status"),
            "patch_urgency": pkg.get("patch_urgency"),
        }

        if pkg.get("reachability_priority") == "REACHABLE_VULNERABLE":
            reachable_vulnerable_packages.append(item)

        elif pkg.get("reachability_priority") == "NOT_OBSERVED_VULNERABLE":
            not_observed_vulnerable_packages.append(item)

    payload["reachable_vulnerable_packages"] = reachable_vulnerable_packages
    payload["not_observed_vulnerable_packages"] = not_observed_vulnerable_packages

    # Stable CVE/CVSS/advisory views for PDF/XLS/SARIF/VEX/CycloneDX.
    _build_dependency_reporting_views(payload)
    reachable_vulnerable_packages = payload.get("reachable_vulnerable_packages", [])
    not_observed_vulnerable_packages = payload.get("not_observed_vulnerable_packages", [])

    # --------------------------------------------------
    # Fix Supply Chain insight using final reachability truth
    # --------------------------------------------------
    reachable_vuln = len(reachable_vulnerable_packages)

    updated_insights = []

    for insight in payload.get("insights", []):
        if insight.startswith("SUPPLY CHAIN:"):
            vuln_count = sum(
                1 for pkg in payload.get("sbom", [])
                if _safe_float(pkg.get("cvss")) >= 7.0
            )

            insight = (
                f"SUPPLY CHAIN: {vuln_count} dependency packages with CVSS >= 7.0 detected. "
                f"{reachable_vuln} vulnerable dependency packages were classified as reachable "
                "by the static reachability analysis. Upgrade affected packages to patched "
                "versions before release."
            )

        updated_insights.append(insight)

    payload["insights"] = updated_insights


    # --------------------------------------------------
    # Governance Signals + Executive Decision
    # IMPORTANT: This must run after Secret Intelligence, Framework
    # Enrichment, Dependency Intelligence, Reachability, Vulnerability
    # Age, and reachability-aware reporting lists.
    # --------------------------------------------------
    governance_result = derive_governance_signals(payload)

    payload["governance_signals"] = governance_result.get("governance_signals", [])
    payload["governance_signal_summary"] = governance_result.get(
        "governance_signal_summary", {}
    )

    payload["release_readiness"] = derive_release_readiness(payload)

    executive_decision = derive_executive_decision(
        governance_result,
        payload.get("release_readiness", {}),
    )
    payload["executive_decision"] = executive_decision

    gss = payload.get("governance_signal_summary", {})
    ed = payload.get("executive_decision", {})
    rrs = payload.get("release_readiness", {})
    # --------------------------------------------------
    # Metadata Counters
    # --------------------------------------------------
    payload["metadata"]["secret_intelligence_total"] = sis.get("total_secrets", 0)
    payload["metadata"]["secret_high_blast_radius"] = sis.get("high_blast_radius", 0)
    payload["metadata"]["secret_critical_blast_radius"] = sis.get(
        "critical_blast_radius", 0
    )
    payload["metadata"]["secret_validation_status"] = sis.get(
        "validation_status", "OFFLINE_ONLY_NOT_VALIDATED"
    )
    sls = payload.get("secret_live_validation_summary", {})
    payload["metadata"]["secret_live_validation_enabled"] = sls.get("enabled", False)
    payload["metadata"]["secret_live_validation_status"] = sls.get(
        "status", "SECRET_LIVE_VALIDATION_DISABLED"
    )
    payload["metadata"]["secret_live_validation_mode"] = sls.get(
        "mode", "OFFLINE_ONLY_NOT_VALIDATED"
    )
    payload["metadata"]["secret_live_validated"] = sls.get("validated", 0)
    payload["metadata"]["secret_live_valid"] = sls.get("live_valid", 0)
    payload["metadata"]["secret_live_no_secret_value"] = sls.get("no_secret_value", 0)
    payload["metadata"]["secret_live_inconclusive"] = sls.get("inconclusive", 0)
    payload["metadata"]["secret_live_errors"] = sls.get("errors", 0)

    payload["metadata"]["direct_dependencies"] = dep_summary["direct_dependencies"]
    payload["metadata"]["transitive_dependencies"] = dep_summary["transitive_dependencies"]
    payload["metadata"]["unknown_dependencies"] = dep_summary["unknown_dependencies"]
    payload["metadata"]["vulnerable_direct_dependencies"] = dep_summary[
        "vulnerable_direct_dependencies"
    ]
    payload["metadata"]["vulnerable_transitive_dependencies"] = dep_summary[
        "vulnerable_transitive_dependencies"
    ]

    payload["metadata"]["reachable_packages"] = reach.get("reachable_packages", 0)
    payload["metadata"]["not_observed_packages"] = reach.get("not_observed_packages", 0)
    payload["metadata"]["unknown_reachability_packages"] = reach.get("unknown_packages", 0)
    payload["metadata"]["direct_reachable_packages"] = reach.get("direct_reachable", 0)
    payload["metadata"]["transitive_reachable_packages"] = reach.get(
        "transitive_reachable", 0
    )
    payload["metadata"]["reachability_references_count"] = payload.get(
        "reachability_references_count", 0
    )

    kis = payload.get("kev_intelligence_summary", {})
    vas = payload.get("vulnerability_age_summary", {})
    eis = payload.get("epss_intelligence_summary", {})
    exs = payload.get("exploitability_summary", {})
    lps = payload.get("license_policy_summary", {})
    cips = payload.get("copyright_ip_compliance_summary", {})
    lgs = payload.get("legacy_protocol_summary", {})
    ess = payload.get("exposure_surface_summary", {})
    scts = payload.get("supply_chain_trust_summary", {})
    rais = payload.get("runtime_artifact_integrity_summary", {})
    dfss = payload.get("data_flow_sensitivity_summary", {})
    dfcs = payload.get("data_flow_correlation_summary", {})
    iars = payload.get("identity_access_risk_summary", {})
    iacs = payload.get("identity_access_correlation_summary", {})
    ahrs = payload.get("auth_hardening_risk_summary", {})
    ahcs = payload.get("auth_hardening_correlation_summary", {})
    amrs = payload.get("ai_model_risk_summary", {})
    blrs = payload.get("business_logic_risk_summary", {})
    blcs = payload.get("business_logic_correlation_summary", {})

    # Align business-logic executive summary when correlation engine has confirmed
    # business-logic signals but the standalone risk engine has no direct indicators.
    if (blrs.get("total_business_logic_indicators", 0) == 0 and
            blcs.get("total_business_logic_correlations", 0) > 0):
        blrs = dict(blrs)
        blrs["summary_status"] = "BUSINESS_LOGIC_RISK_IDENTIFIED_FROM_CORRELATION"
        blrs["total_business_logic_indicators"] = blcs.get("total_business_logic_correlations", 0)
        blrs["critical_business_logic_indicators"] = blcs.get("critical_business_logic_correlations", 0)
        blrs["high_business_logic_indicators"] = blcs.get("high_business_logic_correlations", 0)
        blrs["executive_relevant_indicators"] = blcs.get("executive_relevant_correlations", 0)
        blrs["by_context"] = {"file": blcs.get("total_business_logic_correlations", 0), "function": 0, "api_route": 0}
        payload["business_logic_risk_summary"] = blrs

    cms = payload.get("crypto_misuse_summary", {})
    sbrc = payload.get("secret_blast_radius_correlation_summary", {})
    aars = payload.get("api_abuse_risk_summary", {})
    sccs = payload.get("security_control_coverage_summary", {})
    
    payload["metadata"]["kev_status"] = kis.get(
        "summary_status",
        "NOT_AVAILABLE"
    )
    payload["metadata"]["kev_packages"] = kis.get(
        "kev_packages",
        0
    )
    payload["metadata"]["reachable_kev_packages"] = kis.get(
        "reachable_kev_packages",
        0
    )
    payload["metadata"]["known_ransomware_use_packages"] = kis.get(
        "known_ransomware_use_packages",
        0
    )

    payload["metadata"]["vulnerable_packages_with_age"] = vas.get(
        "known_age_packages", 0
    )
    payload["metadata"]["kev_packages"] = vas.get("kev_packages", 0)
    payload["metadata"]["reachable_kev_packages"] = vas.get(
        "reachable_kev_packages", 0
    )
    payload["metadata"]["legacy_high_risk_packages"] = vas.get(
        "legacy_high_risk_packages", 0
    )
    
    payload["metadata"]["exposure_surface_status"] = ess.get(
    "executive_status",
    "NOT_AVAILABLE"
    )

    payload["metadata"]["supply_chain_trust_status"] = scts.get(
        "summary_status",
        "NOT_AVAILABLE"
    )

    payload["metadata"]["supply_chain_trust_indicators"] = scts.get(
        "total_supply_chain_trust_indicators",
        0
    )

    payload["metadata"]["supply_chain_unpinned_dependencies"] = scts.get(
        "unpinned_dependencies",
        0
    )

    payload["metadata"]["supply_chain_git_dependencies"] = scts.get(
        "git_dependencies",
        0
    )

    payload["metadata"]["supply_chain_recent_packages"] = scts.get(
        "recent_packages",
        0
    )


    payload["metadata"]["runtime_artifact_integrity_status"] = rais.get(
        "summary_status",
        "NOT_AVAILABLE"
    )

    payload["metadata"]["runtime_artifact_integrity_indicators"] = rais.get(
        "total_artifact_integrity_indicators",
        0
    )

    payload["metadata"]["runtime_artifact_presence_indicators"] = rais.get(
        "total_artifact_presence_indicators",
        0
    )

    payload["metadata"]["runtime_artifact_unsigned"] = rais.get(
        "unsigned_artifacts",
        0
    )

    payload["metadata"]["runtime_artifact_tampered"] = rais.get(
        "tampered_artifacts",
        0
    )

    payload["metadata"]["runtime_artifact_packed"] = rais.get(
        "packed_binaries",
        0
    )

    payload["metadata"]["runtime_artifact_embedded_secrets"] = rais.get(
        "embedded_secret_artifacts",
        0
    )

    payload["metadata"]["runtime_artifact_provenance_gaps"] = rais.get(
        "provenance_gaps",
        0
    )

    payload["metadata"]["runtime_artifact_digest_pinning_gaps"] = rais.get(
        "digest_pinning_gaps",
        0
    )

    payload["metadata"]["runtime_artifact_checksum_gaps"] = rais.get(
        "checksum_gaps",
        0
    )

    payload["metadata"]["runtime_artifact_sbom_gaps"] = rais.get(
        "sbom_gaps",
        0
    )

    payload["metadata"]["runtime_artifact_global_integrity_indicators"] = rais.get(
        "global_artifact_integrity_indicators",
        0
    )

    payload["metadata"]["runtime_artifact_global_presence_indicators"] = rais.get(
        "global_artifact_presence_indicators",
        0
    )

    payload["metadata"]["runtime_artifact_executive_relevant_global"] = rais.get(
        "executive_relevant_global_indicators",
        0
    )
    
    payload["metadata"]["data_flow_sensitivity_status"] = dfss.get(
        "summary_status",
        "NOT_AVAILABLE"
    )

    payload["metadata"]["data_flow_sensitivity_indicators"] = dfss.get(
        "total_data_flow_sensitivity_indicators",
        0
    )

    payload["metadata"]["data_flow_sensitivity_critical"] = dfss.get(
        "critical_indicators",
        0
    )

    payload["metadata"]["data_flow_sensitivity_high"] = dfss.get(
        "high_indicators",
        0
    )

    payload["metadata"]["data_flow_sensitivity_executive_relevant"] = dfss.get(
        "executive_relevant_indicators",
        0
    )


    payload["metadata"]["data_flow_correlation_status"] = dfcs.get(
        "correlation_status",
        "NOT_AVAILABLE"
    )

    payload["metadata"]["data_flow_correlation_mode"] = dfcs.get(
        "correlation_mode",
        "NOT_AVAILABLE"
    )

    payload["metadata"]["data_flow_correlated_flows"] = dfcs.get(
        "total_correlated_flows",
        0
    )

    payload["metadata"]["data_flow_critical_correlated_flows"] = dfcs.get(
        "critical_correlated_flows",
        0
    )

    payload["metadata"]["data_flow_high_correlated_flows"] = dfcs.get(
        "high_correlated_flows",
        0
    )

    payload["metadata"]["data_flow_file_context_flows"] = dfcs.get(
        "by_context",
        {}
    ).get("file_context", 0)

    payload["metadata"]["data_flow_function_context_flows"] = dfcs.get(
        "by_context",
        {}
    ).get("function_context", 0)


    payload["metadata"]["component_exposure_indicators"] = ess.get(
        "component_exposure_indicators",
        0
    )

    payload["metadata"]["global_exposure_indicators"] = ess.get(
        "global_exposure_indicators",
        0
    )

    payload["metadata"]["executive_relevant_global_exposure"] = ess.get(
        "executive_relevant_global_indicators",
        0
    )
    
    
    
    payload["metadata"]["identity_access_risk_status"] = iars.get(
        "summary_status",
        "NOT_AVAILABLE"
    )

    payload["metadata"]["identity_access_indicators"] = iars.get(
        "total_identity_access_indicators",
        0
    )

    payload["metadata"]["identity_access_critical"] = iars.get(
        "critical_identity_access_indicators",
        0
    )

    payload["metadata"]["identity_access_high"] = iars.get(
        "high_identity_access_indicators",
        0
    )

    payload["metadata"]["identity_access_executive_relevant"] = iars.get(
        "executive_relevant_indicators",
        0
    )

    payload["metadata"]["identity_access_correlation_status"] = iacs.get(
        "summary_status",
        "NOT_AVAILABLE"
    )

    payload["metadata"]["identity_access_correlations"] = iacs.get(
        "total_identity_access_correlations",
        0
    )

    payload["metadata"]["identity_access_correlation_critical"] = iacs.get(
        "critical_identity_access_correlations",
        0
    )

    payload["metadata"]["identity_access_correlation_high"] = iacs.get(
        "high_identity_access_correlations",
        0
    )

    payload["metadata"]["identity_access_privileged_routes"] = iacs.get(
        "privileged_routes_observed",
        0
    )

    payload["metadata"]["identity_access_unauth_privileged_routes"] = iacs.get(
        "unauthenticated_privileged_routes",
        0
    )

    payload["metadata"]["auth_hardening_status"] = ahrs.get(
        "summary_status",
        "NOT_AVAILABLE"
    )

    payload["metadata"]["auth_hardening_indicators"] = ahrs.get(
        "total_auth_hardening_indicators",
        0
    )

    payload["metadata"]["auth_hardening_critical"] = ahrs.get(
        "critical_auth_hardening_indicators",
        0
    )

    payload["metadata"]["auth_hardening_high"] = ahrs.get(
        "high_auth_hardening_indicators",
        0
    )

    payload["metadata"]["auth_hardening_executive_relevant"] = ahrs.get(
        "executive_relevant_indicators",
        0
    )
    
    
    payload["metadata"]["ai_model_risk_status"] = amrs.get(
        "summary_status",
        "NOT_AVAILABLE"
    )

    payload["metadata"]["ai_model_risk_indicators"] = amrs.get(
        "total_ai_model_risk_indicators",
        0
    )

    payload["metadata"]["ai_model_risk_critical"] = amrs.get(
        "critical_ai_model_risk_indicators",
        0
    )

    payload["metadata"]["ai_model_risk_high"] = amrs.get(
        "high_ai_model_risk_indicators",
        0
    )

    payload["metadata"]["ai_model_risk_executive_relevant"] = amrs.get(
        "executive_relevant_indicators",
        0
    )
    
    
    payload["metadata"]["business_logic_risk_status"] = blrs.get(
        "summary_status",
        "NOT_AVAILABLE"
    )

    payload["metadata"]["business_logic_risk_indicators"] = blrs.get(
        "total_business_logic_indicators",
        0
    )

    payload["metadata"]["business_logic_risk_critical"] = blrs.get(
        "critical_business_logic_indicators",
        0
    )

    payload["metadata"]["business_logic_risk_high"] = blrs.get(
        "high_business_logic_indicators",
        0
    )

    payload["metadata"]["business_logic_risk_executive_relevant"] = blrs.get(
        "executive_relevant_indicators",
        0
    )

    payload["metadata"]["business_logic_file_context"] = blrs.get(
        "by_context",
        {}
    ).get("file", 0)

    payload["metadata"]["business_logic_function_context"] = blrs.get(
        "by_context",
        {}
    ).get("function", 0)

    payload["metadata"]["business_logic_api_route_context"] = blrs.get(
        "by_context",
        {}
    ).get("api_route", 0)
    
    
    
    payload["metadata"]["business_logic_correlation_status"] = blcs.get(
        "summary_status",
        "NOT_AVAILABLE"
    )

    payload["metadata"]["business_logic_correlations"] = blcs.get(
        "total_business_logic_correlations",
        0
    )

    payload["metadata"]["business_logic_correlation_critical"] = blcs.get(
        "critical_business_logic_correlations",
        0
    )

    payload["metadata"]["business_logic_correlation_high"] = blcs.get(
        "high_business_logic_correlations",
        0
    )

    payload["metadata"]["business_logic_correlation_executive_relevant"] = blcs.get(
        "executive_relevant_correlations",
        0
    )
    
    
    payload["metadata"]["api_abuse_risk_status"] = aars.get(
        "summary_status",
        "NOT_AVAILABLE"
    )

    payload["metadata"]["api_abuse_risk_indicators"] = aars.get(
        "total_api_abuse_indicators",
        0
    )

    payload["metadata"]["api_abuse_risk_critical"] = aars.get(
        "critical_api_abuse_indicators",
        0
    )

    payload["metadata"]["api_abuse_risk_high"] = aars.get(
        "high_api_abuse_indicators",
        0
    )

    payload["metadata"]["api_abuse_risk_unique"] = aars.get(
        "total_unique_api_abuse_indicators",
        0
    )

    payload["metadata"]["api_abuse_risk_executive_relevant"] = aars.get(
        "executive_relevant_indicators",
        0
    )

    payload["metadata"]["api_abuse_route_context"] = aars.get(
        "by_context",
        {}
    ).get("api_route_context", 0)
    
    
    payload["metadata"]["security_control_coverage_status"] = sccs.get(
        "defense_in_depth_status",
        "NOT_AVAILABLE"
    )

    payload["metadata"]["security_control_coverage_grade"] = sccs.get(
        "coverage_grade",
        "NOT_AVAILABLE"
    )

    payload["metadata"]["security_control_coverage_ratio"] = sccs.get(
        "coverage_ratio",
        0
    )

    payload["metadata"]["security_controls_observed"] = sccs.get(
        "controls_observed",
        0
    )

    payload["metadata"]["security_controls_not_observed"] = sccs.get(
        "controls_not_observed",
        0
    )

    payload["metadata"]["security_control_domains_observed"] = sccs.get(
        "domains_observed_count",
        0
    )

    payload["metadata"]["security_control_domains_not_observed"] = sccs.get(
        "domains_not_observed_count",
        0
    )

    payload["metadata"]["security_control_executive_relevant_gaps"] = sccs.get(
        "executive_relevant_gaps",
        0
    )
    
    
    
    payload["metadata"]["crypto_misuse_status"] = cms.get(
        "summary_status",
        "NOT_AVAILABLE"
    )

    payload["metadata"]["crypto_misuse_indicators"] = cms.get(
        "total_crypto_misuse_indicators",
        0
    )

    payload["metadata"]["crypto_misuse_critical"] = cms.get(
        "critical_crypto_misuse_indicators",
        0
    )

    payload["metadata"]["crypto_misuse_high"] = cms.get(
        "high_crypto_misuse_indicators",
        0
    )

    payload["metadata"]["crypto_misuse_executive_relevant"] = cms.get(
        "executive_relevant_indicators",
        0
    )
    
    
    
    
    

    payload["metadata"]["vulnerability_age_status"] = vas.get(
        "summary_status",
        "NOT_AVAILABLE"
    )
    
    payload["metadata"]["epss_status"] = eis.get(
    "summary_status",
    "NOT_AVAILABLE"
    )
    payload["metadata"]["known_epss_packages"] = eis.get(
        "known_epss_packages",
        0
    )
    payload["metadata"]["very_high_epss_packages"] = eis.get(
        "very_high_exploit_probability",
        0
    )
    payload["metadata"]["p0_immediate_packages"] = eis.get(
        "p0_immediate_packages",
        0
    )

    payload["metadata"]["exploitability_status"] = exs.get(
    "summary_status",
    "NOT_AVAILABLE"
    )
    payload["metadata"]["immediate_remediate_packages"] = exs.get(
        "immediate_remediate",
        0
    )
    payload["metadata"]["priority_patch_packages"] = exs.get(
        "priority_patch",
        0
    )
    
    payload["metadata"]["license_policy_status"] = lps.get(
    "summary_status",
    "NOT_AVAILABLE"
    )
    payload["metadata"]["license_notice_required_components"] = lps.get(
        "notice_required_components",
        0
    )

    payload["metadata"]["license_legal_review_required"] = lps.get(
        "legal_review_required_components",
        0
    )
    payload["metadata"]["license_unknown_components"] = lps.get(
        "unknown_license_components",
        0
    )
    payload["metadata"]["license_notice_required_components"] = lps.get(
        "notice_required_components",
        0
    )


    payload["metadata"]["vulnerable_packages"] = rv.get("vulnerable_packages", 0)
    payload["metadata"]["reachable_vulnerable_packages"] = rv.get(
        "reachable_vulnerable_packages", 0
    )
    payload["metadata"]["not_observed_vulnerable_packages"] = rv.get(
        "not_observed_vulnerable_packages", 0
    )
    payload["metadata"]["unknown_reachability_vulnerable_packages"] = rv.get(
        "unknown_reachability_vulnerable_packages", 0
    )

    payload["metadata"]["governance_signals_total"] = gss.get("total_signals", 0)
    payload["metadata"]["governance_high_signals"] = gss.get("high_signals", 0)
    payload["metadata"]["governance_medium_signals"] = gss.get("medium_signals", 0)
    payload["metadata"]["executive_decision"] = ed.get("executive_decision", "UNKNOWN")
    payload["metadata"]["executive_decision_priority"] = ed.get(
        "decision_priority", "UNKNOWN"
    )
    
    
    payload["metadata"]["release_readiness_decision"] = rrs.get(
        "release_decision",
        "UNKNOWN"
    )

    payload["metadata"]["release_readiness_priority"] = rrs.get(
        "release_priority",
        "UNKNOWN"
    )

    payload["metadata"]["release_readiness_confidence"] = rrs.get(
        "release_confidence",
        0
    )

    payload["metadata"]["release_readiness_blocking_gates"] = rrs.get(
        "blocking_gate_count",
        0
    )

    payload["metadata"]["release_readiness_review_gates"] = rrs.get(
        "review_gate_count",
        0
    )

    payload["metadata"]["release_readiness_status"] = rrs.get(
        "summary_status",
        "NOT_AVAILABLE"
    )
    
    payload["metadata"]["executive_decision_confidence"] = ed.get(
        "decision_confidence", 0
    )
    
    fms = payload.get("framework_mapping_summary", {})

    payload["metadata"]["framework_mapped_findings"] = fms.get("mapped_findings", 0)
    payload["metadata"]["framework_mapping_status"] = fms.get(
        "mapping_status",
        "NOT_AVAILABLE"
    )

    # --------------------------------------------------
    # Console Visibility
    # --------------------------------------------------
    
    _safe_print(
        "       => KEV Intelligence: "
        f"{kis.get('kev_packages', 0)} KEV | "
        f"{kis.get('reachable_kev_packages', 0)} reachable KEV | "
        f"{kis.get('known_ransomware_use_packages', 0)} ransomware-linked"
    )

    _safe_print(
        "       => Reachability Vulnerability Priority: "
        f"{rv.get('reachable_vulnerable_packages', 0)} reachable vulnerable | "
        f"{rv.get('not_observed_vulnerable_packages', 0)} not observed vulnerable | "
        f"{rv.get('unknown_reachability_vulnerable_packages', 0)} unknown"
    )


    _safe_print(
        "       => Vulnerability Age Intelligence: "
        f"{vas.get('kev_packages', 0)} KEV | "
        f"{vas.get('reachable_kev_packages', 0)} reachable KEV | "
        f"{vas.get('legacy_high_risk_packages', 0)} legacy high risk"
    )
    
    
    _safe_print(
        "       => Legacy Protocol Intelligence: "
        f"{lgs.get('component_legacy_indicators', 0)} component indicators | "
        f"{lgs.get('global_legacy_indicators', 0)} global indicators | "
        f"{lgs.get('executive_status', 'NOT_AVAILABLE')}"
    )

    _safe_print(
        "       => Exposure Surface Intelligence: "
        f"{ess.get('component_exposure_indicators', 0)} component indicators | "
        f"{ess.get('global_exposure_indicators', 0)} global indicators | "
        f"{ess.get('executive_status', 'NOT_AVAILABLE')}"
    )

    _safe_print(
        "       => EPSS Intelligence: "
        f"{eis.get('known_epss_packages', 0)} known EPSS | "
        f"{eis.get('very_high_exploit_probability', 0)} very high | "
        f"{eis.get('p0_immediate_packages', 0)} P0 immediate"
    )
    
    _safe_print(
        "       => Exploitability Decision: "
        f"{exs.get('immediate_remediate', 0)} immediate | "
        f"{exs.get('priority_patch', 0)} priority patch | "
        f"{exs.get('summary_status', 'NOT_AVAILABLE')}"
    )
    
    _safe_print(
          "       => SBOM License Policy: "
        f"{lps.get('legal_review_required_components', 0)} legal review | "
        f"{lps.get('unknown_license_components', 0)} unknown | "
        f"{lps.get('notice_required_components', 0)} notice required"
    )
    
    _safe_print(
         "       => Source/IP Compliance Scan: "
        f"{cips.get('copyright_ip_findings', 0)} findings | "
        f"{cips.get('critical', 0)} critical | "
        f"{cips.get('high', 0)} high | "
        f"{cips.get('decision', 'NO_COPYRIGHT_SIGNAL')}"
    )



    _safe_print(
        "       => Supply Chain Trust Intelligence: "
        f"{scts.get('total_supply_chain_trust_indicators', 0)} indicators | "
        f"{scts.get('high_affected_components', 0)} high affected | "
        f"{scts.get('summary_status', 'NOT_AVAILABLE')}"
    )


    _safe_print(
        "       => Runtime Artifact Integrity: "
        f"{rais.get('total_artifact_integrity_indicators', 0)} component integrity | "
        f"{rais.get('total_artifact_presence_indicators', 0)} component presence | "
        f"{rais.get('global_artifact_integrity_indicators', 0)} global integrity | "
        f"{rais.get('global_artifact_presence_indicators', 0)} global presence | "
        f"{rais.get('summary_status', 'NOT_AVAILABLE')}"
    )

    _safe_print(
        "       => Data Flow Sensitivity: "
        f"{dfss.get('total_data_flow_sensitivity_indicators', 0)} indicators | "
        f"{dfss.get('executive_relevant_indicators', 0)} executive relevant | "
        f"{dfss.get('summary_status', 'NOT_AVAILABLE')}"
    )

    dfc_context = dfcs.get("by_context", {})

    _safe_print(
        "       => Data Flow Correlation: "
        f"{dfcs.get('total_correlated_flows', 0)} correlated | "
        f"{dfcs.get('critical_correlated_flows', 0)} critical | "
        f"{dfcs.get('high_correlated_flows', 0)} high | "
        f"file {dfc_context.get('file_context', 0)} | "
        f"function {dfc_context.get('function_context', 0)} | "
        f"confirmed {dfcs.get('confirmed_flows', 0)} | "
        f"fallback_candidates {dfcs.get('fallback_candidate_flows', 0)} | "
        f"{dfcs.get('correlation_confidence', 'NOT_AVAILABLE')} | "
        f"{dfcs.get('correlation_mode', 'NOT_AVAILABLE')}"
    )
    
    
    _safe_print(
        "       => Identity Access Risk: "
        f"{iars.get('total_identity_access_indicators', 0)} indicators | "
        f"{iars.get('critical_identity_access_indicators', 0)} critical | "
        f"{iars.get('high_identity_access_indicators', 0)} high | "
        f"{iars.get('summary_status', 'NOT_AVAILABLE')}"
    )

    _safe_print(
        "       => Identity Access Correlation: "
        f"{iacs.get('total_identity_access_correlations', 0)} correlations | "
        f"{iacs.get('critical_identity_access_correlations', 0)} critical | "
        f"{iacs.get('high_identity_access_correlations', 0)} high | "
        f"privileged_routes {iacs.get('privileged_routes_observed', 0)} | "
        f"unauth_privileged {iacs.get('unauthenticated_privileged_routes', 0)} | "
        f"{iacs.get('summary_status', 'NOT_AVAILABLE')}"
    )

    _safe_print(
        "       => Auth Hardening Risk: "
        f"{ahrs.get('total_auth_hardening_indicators', 0)} indicators | "
        f"{ahrs.get('critical_auth_hardening_indicators', 0)} critical | "
        f"{ahrs.get('high_auth_hardening_indicators', 0)} high | "
        f"{ahrs.get('summary_status', 'NOT_AVAILABLE')}"
    )

    _safe_print(
        "       => Auth Hardening Correlation: "
        f"{ahcs.get('total_auth_hardening_correlations', 0)} correlations | "
        f"{ahcs.get('critical_auth_hardening_correlations', 0)} critical | "
        f"{ahcs.get('high_auth_hardening_correlations', 0)} high | "
        f"{ahcs.get('summary_status', 'NOT_AVAILABLE')}"
    )

    payload["metadata"]["auth_hardening_correlation_status"] = ahcs.get(
        "summary_status",
        "NOT_AVAILABLE"
    )

    payload["metadata"]["auth_hardening_correlations"] = ahcs.get(
        "total_auth_hardening_correlations",
        0
    )

    payload["metadata"]["auth_hardening_correlation_critical"] = ahcs.get(
        "critical_auth_hardening_correlations",
        0
    )

    payload["metadata"]["auth_hardening_correlation_high"] = ahcs.get(
        "high_auth_hardening_correlations",
        0
    )

    payload["metadata"]["auth_hardening_correlation_executive_relevant"] = ahcs.get(
        "executive_relevant_correlations",
        0
    )


    _safe_print(
        "       => AI Model Risk: "
        f"{amrs.get('total_ai_model_risk_indicators', 0)} indicators | "
        f"{amrs.get('critical_ai_model_risk_indicators', 0)} critical | "
        f"{amrs.get('high_ai_model_risk_indicators', 0)} high | "
        f"{amrs.get('summary_status', 'NOT_AVAILABLE')}"
    )



    bl_context = blrs.get("by_context", {})

    _safe_print(
        "       => Business Logic Risk: "
        f"{blrs.get('total_business_logic_indicators', 0)} indicators | "
        f"{blrs.get('critical_business_logic_indicators', 0)} critical | "
        f"{blrs.get('high_business_logic_indicators', 0)} high | "
        f"file {bl_context.get('file', 0)} | "
        f"function {bl_context.get('function', 0)} | "
        f"{blrs.get('summary_status', 'NOT_AVAILABLE')}"
    )


    _safe_print(
        "       => Business Logic Correlation: "
        f"{blcs.get('total_business_logic_correlations', 0)} correlations | "
        f"{blcs.get('critical_business_logic_correlations', 0)} critical | "
        f"{blcs.get('high_business_logic_correlations', 0)} high | "
        f"{blcs.get('summary_status', 'NOT_AVAILABLE')}"
    )

    api_context = aars.get("by_context", {})

    _safe_print(
        "       => API Abuse Risk: "
        f"{aars.get('total_api_abuse_indicators', 0)} indicators | "
        f"{aars.get('total_unique_api_abuse_indicators', 0)} unique | "
        f"{aars.get('critical_api_abuse_indicators', 0)} critical | "
        f"{aars.get('high_api_abuse_indicators', 0)} high | "
        f"api {api_context.get('api_route_context', 0)} | "
        f"{aars.get('summary_status', 'NOT_AVAILABLE')}"
    )

    _safe_print(
        "       => Security Control Coverage: "
        f"{sccs.get('coverage_grade', 'NOT_AVAILABLE')} | "
        f"{sccs.get('coverage_ratio', 0)} coverage | "
        f"{sccs.get('domains_observed_count', 0)} domains observed | "
        f"{sccs.get('domains_not_observed_count', 0)} gaps | "
        f"{sccs.get('defense_in_depth_status', 'NOT_AVAILABLE')}"
    )

    _safe_print(
        "       => Crypto Misuse: "
        f"{cms.get('total_crypto_misuse_indicators', 0)} indicators | "
        f"{cms.get('critical_crypto_misuse_indicators', 0)} critical | "
        f"{cms.get('high_crypto_misuse_indicators', 0)} high | "
        f"{cms.get('summary_status', 'NOT_AVAILABLE')}"
    )


    _safe_print(
        "       => Secret Intelligence: "
        f"{sis.get('total_secrets', 0)} secrets classified | "
        f"{sis.get('critical_blast_radius', 0)} critical blast radius | "
        f"{sis.get('high_blast_radius', 0)} high blast radius | "
        f"{sis.get('validation_status', 'OFFLINE_ONLY_NOT_VALIDATED')}"
    )
    
    
    _safe_print(
        "       => Secret Blast Radius Correlation: "
        f"{sbrc.get('total_secret_blast_radius_correlations', 0)} correlations | "
        f"{sbrc.get('total_unique_secret_blast_radius', 0)} unique | "
        f"{sbrc.get('critical_unique_secret_blast_radius', 0)} critical unique | "
        f"{sbrc.get('correlation_status', 'NOT_AVAILABLE')}"
    )

    _safe_print(
        "       => Framework Enrichment: "
        f"{fms.get('mapped_findings', 0)} findings mapped | "
        f"{fms.get('mapping_status', 'NOT_AVAILABLE')}"
    )

    _safe_print(
        "       => Reachability-Aware Reporting: "
        f"{len(reachable_vulnerable_packages)} reachable vulnerable listed | "
        f"{len(not_observed_vulnerable_packages)} not observed vulnerable listed"
    )

    _safe_print(
        "       => Governance Signals: "
        f"{gss.get('total_signals', 0)} total | "
        f"{gss.get('high_signals', 0)} high | "
        f"{gss.get('medium_signals', 0)} medium"
    )
    
    _safe_print(
        "       => Release Readiness: "
        f"{rrs.get('release_decision', 'UNKNOWN')} | "
        f"{rrs.get('release_priority', 'UNKNOWN')} | "
        f"{rrs.get('blocking_gate_count', 0)} blocking gates | "
        f"{rrs.get('review_gate_count', 0)} review gates | "
        f"confidence {rrs.get('release_confidence', 0)}"
    )


    _safe_print(
        "       => Executive Decision: "
        f"{ed.get('executive_decision', 'UNKNOWN')} | "
        f"{ed.get('decision_priority', 'UNKNOWN')} | "
        f"confidence {ed.get('decision_confidence', 0)}"
    )

    meta = payload["metadata"]
    dist = meta["severity_distribution"]
    risk = meta["risk_score"]
    total = meta["total_findings"]
    paths = len(payload.get("attack_paths", []))

    _safe_print(
        f"       => {total} unique findings | Risk: {risk}/100 | Attack Paths: {paths}"
    )

    _print_dist(dist)

    payload = _apply_final_mapping_normalization(payload)

    _cleanup_report_noise(payload)

    _step("Writing JSON report")
    json_path = output_dir / "clean_report.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, default=str)
    _safe_print(f"       => {json_path}")

    generated_files = ["clean_report.json"]

    if not args.no_pdf:
        _step("Generating PDF report")
        try:
            from reporting.pdf_report import generate_pdf_report

            pdf_path = output_dir / "Security_Report.pdf"
            generate_pdf_report(payload, str(pdf_path))
            generated_files.append(pdf_path.name)
            _safe_print(f"       => {pdf_path}")
        except Exception as exc:
            _safe_print(f"       => PDF failed: {exc}")

    if not args.no_excel:
        _step("Generating Excel reports")
        try:
            from reporting.excel_report import (
                generate_excel_report,
                generate_executive_excel_report,
                generate_technical_excel_report,
            )

            combined_xlsx = output_dir / "Security_Report.xlsx"
            executive_xlsx = output_dir / "Security_Executive_Report.xlsx"
            technical_xlsx = output_dir / "Security_Technical_Report.xlsx"

            generate_excel_report(payload, str(combined_xlsx))
            generated_files.append(combined_xlsx.name)
            _safe_print(f"       => {combined_xlsx}")

            generate_executive_excel_report(payload, str(executive_xlsx))
            generated_files.append(executive_xlsx.name)
            _safe_print(f"       => {executive_xlsx}")

            generate_technical_excel_report(payload, str(technical_xlsx))
            generated_files.append(technical_xlsx.name)
            _safe_print(f"       => {technical_xlsx}")

        except ImportError:
            # Backward compatibility for older excel_report.py builds.
            try:
                from reporting.excel_report import generate_excel_report

                combined_xlsx = output_dir / "Security_Report.xlsx"
                generate_excel_report(payload, str(combined_xlsx))
                generated_files.append(combined_xlsx.name)
                _safe_print(f"       => {combined_xlsx}")
                _safe_print(
                    "       => Executive/Technical XLS skipped: "
                    "update reporting\\excel_report.py to the latest reporting build"
                )
            except Exception as exc:
                _safe_print(f"       => Excel failed: {exc}")
        except Exception as exc:
            _safe_print(f"       => Excel failed: {exc}")

    _step("Generating SARIF report")
    try:
        from reporting.sarif_export import write_sarif_report

        sarif_path = output_dir / "Security_Report.sarif"
        write_sarif_report(payload, str(sarif_path))
        generated_files.append(sarif_path.name)
        _safe_print(f"       => {sarif_path}")
    except Exception as exc:
        _safe_print(f"       => SARIF failed: {exc}")

    _step("Generating VEX report")
    try:
        from reporting.vex_export import write_vex_report

        vex_path = output_dir / "Security_Report.vex.json"
        write_vex_report(payload, str(vex_path))
        generated_files.append(vex_path.name)
        _safe_print(f"       => {vex_path}")
    except Exception as exc:
        _safe_print(f"       => VEX failed: {exc}")

    _step("Generating CycloneDX report")
    try:
        from reporting.cyclonedx_export import write_cyclonedx_report

        cdx_path = output_dir / "Security_CycloneDX.json"
        write_cyclonedx_report(payload, str(cdx_path))
        generated_files.append(cdx_path.name)
        _safe_print(f"       => {cdx_path}")
    except Exception as exc:
        _safe_print(f"       => CycloneDX failed: {exc}")

    total_time = time.time() - t0
    _safe_print(f"\n  [DONE]  Scan complete in {total_time:.1f}s\n")
    _safe_print("  Output files:")

    for fname in generated_files:
        p = output_dir / fname
        if p.exists():
            _safe_print(f"       {fname:<35} ({p.stat().st_size / 1024:.1f} KB)")

    _safe_print("\n  INTELLIGENCE INSIGHTS:")
    for ins in payload.get("insights", []):
        _safe_print(f"    * {ins}")
    _safe_print("")


if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()
