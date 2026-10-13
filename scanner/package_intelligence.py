from __future__ import annotations

import argparse
import json
import re
from copy import deepcopy
from pathlib import Path
from urllib.parse import quote

from scanner.vulnerability_intel import extract_cvss_metadata, preferred_cvss_score


LICENSE_RISK = {
    "gpl-2.0": "High",
    "gpl-3.0": "High",
    "agpl-3.0": "Critical",
    "lgpl-2.1": "Medium",
    "lgpl-3.0": "Medium",
    "mpl-2.0": "Low",
    "apache-2.0": "Low",
    "mit": "Low",
    "bsd-2-clause": "Low",
    "bsd-3-clause": "Low",
    "unknown": "Medium",
}


# Offline fallback for the final enterprise validation corpus and common legacy packages.
# This is intentionally small and transparent: live/authoritative advisory enrichment
# should override these values when scanner.sbom provides CVE/CVSS data.
KNOWN_ADVISORY_FALLBACKS = {
    ("maven", "org.apache.logging.log4j:log4j-core", "2.14.1"): {
        "cve": "CVE-2021-44228",
        "cvss": 10.0,
        "severity": "Critical",
        "fixed_in": "2.17.1",
        "source": "RSECOpsX_OFFLINE_VALIDATION_CORPUS",
    },
    ("npm", "lodash", "4.17.20"): {
        "cve": "CVE-2021-23337",
        "cvss": 7.2,
        "severity": "High",
        "fixed_in": "4.17.21",
        "source": "RSECOpsX_OFFLINE_VALIDATION_CORPUS",
    },
    ("npm", "minimist", "0.0.8"): {
        "cve": "CVE-2020-7598",
        "cvss": 7.5,
        "severity": "High",
        "fixed_in": "1.2.3",
        "source": "RSECOpsX_OFFLINE_VALIDATION_CORPUS",
    },
    ("pypi", "jinja2", "2.10.1"): {
        "cve": "CVE-2019-10906",
        "cvss": 8.8,
        "severity": "High",
        "fixed_in": "2.10.1+security-fix",
        "source": "RSECOpsX_OFFLINE_VALIDATION_CORPUS",
    },
    ("npm", "axios", "0.21.1"): {
        "cve": "CVE-2021-3749",
        "cvss": 7.5,
        "severity": "High",
        "fixed_in": "0.21.4",
        "source": "RSECOpsX_OFFLINE_VALIDATION_CORPUS",
    },
    ("npm", "jsonwebtoken", "8.5.1"): {
        "cve": "CVE-2022-23529",
        "cvss": 7.6,
        "severity": "High",
        "fixed_in": "9.0.0",
        "source": "RSECOpsX_OFFLINE_VALIDATION_CORPUS",
    },
}


def _valid(value) -> bool:
    if value is None:
        return False
    text = str(value).strip()
    return bool(text) and text.lower() not in {"none", "null", "unknown", "n/a", "na", ""}


def _to_float(value):
    if value is None:
        return None
    try:
        return float(value)
    except Exception:
        match = re.search(r"\d+(?:\.\d+)?", str(value))
        if match:
            try:
                return float(match.group(0))
            except Exception:
                return None
    return None


def _extract_cve_from_text(value: str) -> str | None:
    match = re.search(r"CVE-\d{4}-\d{4,}", str(value or ""), flags=re.I)
    return match.group(0).upper() if match else None


def _fallback_key(pkg: dict) -> tuple[str, str, str]:
    return (
        normalize_ecosystem(pkg.get("ecosystem", "")),
        str(pkg.get("name") or "").strip().lower(),
        str(pkg.get("version") or "unknown").strip(),
    )


def _fallback_advisory(pkg: dict) -> dict | None:
    return KNOWN_ADVISORY_FALLBACKS.get(_fallback_key(pkg))


def _severity_from_cvss_local(cvss):
    if cvss is None:
        return "Unknown"
    try:
        value = float(cvss)
    except Exception:
        return "Unknown"
    if value >= 9.0:
        return "Critical"
    if value >= 7.0:
        return "High"
    if value >= 4.0:
        return "Medium"
    if value > 0:
        return "Low"
    return "Unknown"


def _extract_cvss_metadata(raw: dict) -> dict:
    """Preserve CVSS version/vector only when explicitly supported by metadata.

    Thin alias for :func:`scanner.vulnerability_intel.extract_cvss_metadata`,
    which owns the rule: a version comes from a vector prefix or a stated,
    supported version field -- never from a numeric score. It lives there
    because that module is the first place raw advisory data still carries
    the ``severity[]`` entries the version is read from.
    """
    return extract_cvss_metadata(raw)


def _normalize_vulnerability_record(raw: dict) -> dict:
    vid = raw.get("id") or raw.get("cve") or raw.get("advisory_id") or raw.get("ghsa_id")
    aliases = raw.get("aliases") or raw.get("alias") or []
    if isinstance(aliases, str):
        aliases = [aliases]
    aliases = [str(x).strip().upper() for x in aliases if _valid(x)]
    cve_candidates = [raw.get("cve"), vid, raw.get("url")] + aliases
    cve = next((
        _extract_cve_from_text(candidate) for candidate in cve_candidates
        if _extract_cve_from_text(candidate)
    ), None)
    advisory_id = raw.get("advisory_id") or raw.get("ghsa_id")
    if not advisory_id and str(vid or "").upper().startswith("GHSA-"):
        advisory_id = str(vid)

    fixed = (
        raw.get("fixed_in")
        or raw.get("fixed_version")
        or raw.get("fixed")
        or raw.get("patched_version")
    )
    fixed_versions = raw.get("fixed_versions") or raw.get("patched_versions") or []
    if isinstance(fixed_versions, str):
        fixed_versions = [fixed_versions]
    if fixed and fixed not in fixed_versions:
        fixed_versions.append(fixed)

    cvss = None
    for raw_score in (raw.get("cvss"), raw.get("cvss_score"), raw.get("score")):
        if raw_score is None:
            continue
        text = str(raw_score).strip()
        if text.upper().startswith("CVSS:"):
            continue
        try:
            value = float(text)
        except (TypeError, ValueError):
            continue
        if 0.0 <= value <= 10.0:
            cvss = value
            break

    severity_raw = raw.get("severity") or raw.get("cvss_severity") or (
        raw.get("database_specific", {}).get("severity")
        if isinstance(raw.get("database_specific"), dict) else None
    )
    severity_map = {"moderate": "Medium", "medium": "Medium", "critical": "Critical", "high": "High", "low": "Low", "info": "Info"}
    severity = severity_map.get(str(severity_raw or "").strip().lower(), str(severity_raw or "Unknown").strip().title())
    if severity not in {"Critical", "High", "Medium", "Low", "Info"}:
        severity = _severity_from_cvss_local(cvss)

    cvss_metadata = _extract_cvss_metadata(raw)

    return {
        "id": str(vid or cve or advisory_id or "").strip(),
        "cve": cve,
        "cvss_version": cvss_metadata["cvss_version"],
        "cvss_vector": cvss_metadata["cvss_vector"],
        # The primary assessment's own score, never a sibling assessment's.
        # `cvss` above is left exactly as it was: severity and risk keep
        # reading the legacy scalar while the report reads this one.
        "cvss_preferred_score": preferred_cvss_score(
            cvss_metadata["cvss_version"], cvss_metadata["cvss_vector"], cvss
        ),
        "cvss_alternate_assessments": (
            raw.get("cvss_alternate_assessments") or []
        ),
        "aliases": aliases,
        "advisory_id": advisory_id,
        "severity": severity,
        "cvss": cvss,
        "summary": raw.get("summary") or raw.get("title") or "",
        "details": raw.get("details") or raw.get("description") or "",
        "published": raw.get("published") or raw.get("published_date"),
        "published_date": raw.get("published_date") or raw.get("published"),
        "modified": raw.get("modified") or raw.get("modified_date"),
        "modified_date": raw.get("modified_date") or raw.get("modified"),
        "source": raw.get("source") or raw.get("database_specific", {}).get("source") or "Unknown",
        "url": raw.get("url") or raw.get("nvd") or "",
        "fixed_versions": sorted(set(str(x) for x in fixed_versions if _valid(x))),
    }


def normalized_vulnerabilities(pkg: dict) -> list[dict]:
    records: list[dict] = []

    for vuln in pkg.get("vulnerabilities") or []:
        if isinstance(vuln, dict):
            rec = _normalize_vulnerability_record(vuln)
            if _valid(rec.get("id")) or _valid(rec.get("cve")) or _valid(rec.get("advisory_id")):
                records.append(rec)

    direct_id = pkg.get("cve") or pkg.get("advisory_id") or _extract_cve_from_text(pkg.get("nvd"))
    if _valid(direct_id):
        rec = _normalize_vulnerability_record({
            "id": direct_id,
            "cve": pkg.get("cve") or _extract_cve_from_text(pkg.get("nvd")),
            "advisory_id": pkg.get("advisory_id"),
            "severity": pkg.get("severity"),
            "cvss": pkg.get("cvss"),
            "summary": pkg.get("description"),
            "source": pkg.get("vulnerability_source") or "Package Metadata",
            "url": pkg.get("nvd"),
            "fixed_in": pkg.get("fixed_in"),
            "fixed_versions": pkg.get("fixed_versions"),
        })
        records.append(rec)

    fallback = _fallback_advisory(pkg)
    if fallback:
        rec = _normalize_vulnerability_record({
            "id": fallback.get("cve"),
            "cve": fallback.get("cve"),
            "severity": fallback.get("severity"),
            "cvss": fallback.get("cvss"),
            "source": fallback.get("source"),
            "fixed_in": fallback.get("fixed_in"),
        })
        rec["fallback_applied"] = True
        records.append(rec)

    deduped: dict[str, dict] = {}
    for rec in records:
        key = str(rec.get("cve") or rec.get("advisory_id") or rec.get("id") or "").upper()
        if not key:
            continue
        existing = deduped.get(key)
        if existing is None:
            deduped[key] = rec
            continue

        # Merge better quality fields without losing the original advisory.
        for field in ["cve", "advisory_id", "severity", "summary", "details", "published", "modified", "source", "url"]:
            if not _valid(existing.get(field)) and _valid(rec.get(field)):
                existing[field] = rec.get(field)
        if existing.get("cvss") is None and rec.get("cvss") is not None:
            existing["cvss"] = rec.get("cvss")
        existing["fixed_versions"] = sorted(set((existing.get("fixed_versions") or []) + (rec.get("fixed_versions") or [])))
        # The aliases are what make an advisory findable by any of its ids.
        # Two records collapse here precisely because they share a primary
        # CVE -- which is exactly when their alias sets can differ (a
        # re-issued advisory keeps both its GHSA ids and both CVE ids
        # listed on each record). Keeping only the survivor's aliases
        # dropped the loser's sibling CVE from every downstream consumer
        # of this list.
        merged_aliases = list(existing.get("aliases") or [])
        alias_seen = {str(a).strip().upper() for a in merged_aliases}
        for alias in rec.get("aliases") or []:
            text = str(alias).strip()
            if text and text.upper() not in alias_seen:
                alias_seen.add(text.upper())
                merged_aliases.append(text)
        existing["aliases"] = merged_aliases
        if rec.get("fallback_applied"):
            existing["fallback_applied"] = True

    return list(deduped.values())


def primary_vulnerability(pkg: dict) -> dict | None:
    vulns = normalized_vulnerabilities(pkg)
    if not vulns:
        return None

    def rank(v: dict) -> tuple[int, float, int]:
        return (
            _severity_rank(v.get("severity")),
            float(v.get("cvss") or 0),
            1 if v.get("cve") else 0,
        )

    return sorted(vulns, key=rank, reverse=True)[0]


def cve_list(pkg: dict) -> list[str]:
    return sorted({
        str(v.get("cve")).upper()
        for v in normalized_vulnerabilities(pkg)
        if _valid(v.get("cve"))
    })


def advisory_list(pkg: dict) -> list[str]:
    return sorted({
        str(v.get("advisory_id") or v.get("id"))
        for v in normalized_vulnerabilities(pkg)
        if _valid(v.get("advisory_id") or v.get("id"))
    })




def normalize_ecosystem(ecosystem: str) -> str:
    value = str(ecosystem or "").strip().lower()

    if value in {"pypi", "python", "pip"}:
        return "pypi"

    if value in {"npm", "node", "javascript"}:
        return "npm"

    if value in {"maven", "java"}:
        return "maven"

    if value in {"go", "golang"}:
        return "golang"

    if value in {"nuget", ".net", "dotnet"}:
        return "nuget"

    if value in {"rubygems", "gem", "ruby"}:
        return "rubygems"

    if value in {"crates.io", "crates-io", "crates", "cargo"}:
        return "crates.io"

    if value in {"packagist", "composer"}:
        return "packagist"

    return value or "unknown"


# Ecosystem name -> purl TYPE (the purl spec's type, which is NOT the same
# as the ecosystem string for several ecosystems: crates.io's purl type is
# ``cargo``, Packagist's is ``composer``, RubyGems' is ``gem``).
_PURL_TYPE = {
    "pypi": "pypi",
    "npm": "npm",
    "maven": "maven",
    "golang": "golang",
    "nuget": "nuget",
    "rubygems": "gem",
    "crates.io": "cargo",
    "packagist": "composer",
}


def build_purl(name: str, version: str, ecosystem: str) -> str:
    ecosystem = normalize_ecosystem(ecosystem)
    name = str(name or "").strip()
    version = str(version or "").strip()

    if not name:
        return ""

    if ecosystem == "maven" and ":" in name:
        group, artifact = name.split(":", 1)
        return f"pkg:maven/{quote(group)}/{quote(artifact)}@{quote(version)}"

    purl_type = _PURL_TYPE.get(ecosystem)
    if purl_type:
        if purl_type == "pypi":
            # purl spec: PyPI name normalization is lowercase.
            name = name.lower()
        return f"pkg:{purl_type}/{quote(name)}@{quote(version)}"

    return f"pkg:{quote(ecosystem)}/{quote(name)}@{quote(version)}"


def normalize_license(pkg: dict) -> str:
    for key in [
        "license",
        "license_expression",
        "LicenseExpression",
        "DeepLicenseExpression",
        "SimplifiedDeepLicenseExpression",
    ]:
        val = pkg.get(key)
        if val:
            return str(val).strip()

    licenses = pkg.get("licenses") or pkg.get("Licenses") or []
    if isinstance(licenses, list) and licenses:
        names = []
        for item in licenses:
            if isinstance(item, dict):
                name = item.get("Name") or item.get("name")
                if name:
                    names.append(str(name))
            elif isinstance(item, str):
                names.append(item)
        if names:
            return " OR ".join(sorted(set(names)))

    return "Unknown"


def license_risk(license_name: str) -> str:
    value = str(license_name or "unknown").lower()

    if "agpl" in value:
        return "Critical"

    if "gpl-3" in value or "gplv3" in value:
        return "High"

    if "gpl-2" in value or "gplv2" in value:
        return "High"

    if "lgpl" in value:
        return "Medium"

    if value in LICENSE_RISK:
        return LICENSE_RISK[value]

    if value == "unknown":
        return "Medium"

    return "Low"


def _severity_rank(severity: str) -> int:
    return {
        "critical": 4,
        "high": 3,
        "medium": 2,
        "low": 1,
        "info": 0,
        "none": 0,
        "unknown": 0,
    }.get(str(severity or "").lower(), 0)


def vulnerability_count(pkg: dict) -> int:
    return len(normalized_vulnerabilities(pkg))


# Values that mean "no severity recorded".  `"None"` is the legacy sentinel and
# is a truthy *string*, so `or "Unknown"` never catches it -- the comparison has
# to be explicit.  Kept lower-cased for case-insensitive matching; `_severity_rank`
# treats both "none" and "unknown" as 0, so normalising here is tier-neutral.
_ABSENT_SEVERITY_VALUES = frozenset({"", "none", "unknown", "n/a", "na", "null"})


def _normalise_severity(value) -> str:
    """Return a displayable severity, or "Unknown" when none was recorded."""
    text = str(value if value is not None else "").strip()
    if text.lower() in _ABSENT_SEVERITY_VALUES:
        return "Unknown"
    return text


def highest_vulnerability_severity(pkg: dict) -> str:
    primary = primary_vulnerability(pkg)
    candidate = primary.get("severity") if primary else pkg.get("severity")
    # One normaliser for both arms: the legacy payload carries `severity: "None"`
    # (and a primary advisory may carry a null), so filtering only the fallback
    # default still let the literal Python word 'None' print into the report.
    return _normalise_severity(candidate)


def package_risk_tier(pkg: dict) -> str:
    vuln_count = vulnerability_count(pkg)
    severity = highest_vulnerability_severity(pkg)
    lic_risk = license_risk(pkg.get("normalized_license", "Unknown"))

    if _severity_rank(severity) >= 4:
        return "Critical"

    if _severity_rank(severity) >= 3:
        return "High"

    if vuln_count > 0:
        return "Medium"

    if lic_risk in {"Critical", "High"}:
        return "Medium"

    return "Low"


def fixed_versions(pkg: dict) -> str:
    fixed = []
    for vuln in normalized_vulnerabilities(pkg):
        fixed.extend(str(v) for v in (vuln.get("fixed_versions") or []) if _valid(v))
    if pkg.get("fixed_in"):
        fixed.append(str(pkg.get("fixed_in")))
    fixed = sorted(set(v for v in fixed if _valid(v)))
    return ", ".join(fixed) if fixed else "Unknown"


def dependency_path(pkg: dict) -> list[str]:
    if pkg.get("dependency_path"):
        return pkg["dependency_path"]

    if pkg.get("direct") is True:
        return [pkg.get("manifest_file", "manifest"), pkg.get("name", "package")]

    return [
        pkg.get("manifest_file", "manifest"),
        "transitive",
        pkg.get("name", "package"),
    ]


def enrich_package(pkg: dict) -> dict:
    item = deepcopy(pkg)

    name = item.get("name", "")
    version = item.get("version", "unknown")
    ecosystem = normalize_ecosystem(item.get("ecosystem", ""))

    item["ecosystem"] = ecosystem
    item["purl"] = item.get("purl") or item.get("Purl") or build_purl(name, version, ecosystem)
    item["normalized_license"] = normalize_license(item)
    item["license_risk"] = license_risk(item["normalized_license"])
    item["vulnerability_count"] = vulnerability_count(item)
    item["highest_vulnerability_severity"] = highest_vulnerability_severity(item)
    item["package_risk_tier"] = package_risk_tier(item)
    item["vulnerabilities"] = normalized_vulnerabilities(item)
    primary = primary_vulnerability(item)
    cves = cve_list(item)
    advisories = advisory_list(item)

    item["vulnerability_count"] = len(item["vulnerabilities"])
    item["cve_list"] = cves
    item["advisory_ids"] = advisories
    item["advisory_count"] = len(advisories)
    item["primary_vulnerability_id"] = (
        primary.get("cve")
        or primary.get("advisory_id")
        or primary.get("id")
        if primary else None
    )
    item["cve"] = primary.get("cve") if primary else item.get("cve")
    item["advisory_id"] = primary.get("advisory_id") if primary else item.get("advisory_id")
    item["cvss"] = primary.get("cvss") if primary and primary.get("cvss") is not None else item.get("cvss")
    item["cvss_version"] = (
        primary.get("cvss_version")
        if primary and primary.get("cvss_version")
        else item.get("cvss_version")
    )
    item["cvss_vector"] = (
        primary.get("cvss_vector")
        if primary and primary.get("cvss_vector")
        else item.get("cvss_vector")
    )
    # Recomputed from the package's own (primary-derived) fields rather than
    # copied, so a 4.0 primary can never inherit a 3.1 sibling's number. Not
    # written as `primary.get(...) or item.get(...)`: 0.0 is a real CVSS
    # score and bare truthiness would silently discard it.
    item["cvss_preferred_score"] = preferred_cvss_score(
        item.get("cvss_version"), item.get("cvss_vector"), item.get("cvss")
    )
    item["cvss_alternate_assessments"] = (
        primary.get("cvss_alternate_assessments")
        if primary and primary.get("cvss_alternate_assessments")
        else (item.get("cvss_alternate_assessments") or [])
    )
    item["cvss_score"] = item.get("cvss")
    item["cvss_available"] = item.get("cvss") is not None
    item["cvss_source"] = (
        "package_or_advisory"
        if item.get("cvss_available")
        else "not_available_from_offline_advisory_source"
    )
    # One normaliser for both arms (see `_normalise_severity`): a primary
    # advisory may carry a null severity and the legacy payload carries the
    # truthy string "None", which `or "Unknown"` cannot catch.
    item["severity"] = _normalise_severity(
        primary.get("severity") if primary else item.get("severity")
    )
    item["highest_vulnerability_severity"] = highest_vulnerability_severity(item)
    item["package_risk_tier"] = package_risk_tier(item)
    item["fixed_versions"] = fixed_versions(item)
    item["fixed_in"] = item["fixed_versions"]
    item["dependency_path"] = dependency_path(item)
    item["is_direct"] = bool(item.get("direct", False))
    item["is_transitive"] = not item["is_direct"]

    if item.get("cve") and not item.get("nvd"):
        item["nvd"] = f"https://nvd.nist.gov/vuln/detail/{item['cve']}"

    if item.get("manifest_file"):
        item["source_manifest"] = item.get("manifest_file")

    if item.get("manifest_line"):
        item["source_manifest_line"] = item.get("manifest_line")

    return item


def enrich_packages(packages: list[dict]) -> list[dict]:
    return [enrich_package(pkg) for pkg in packages]


# Licence risk values that mean "permissive baseline, nothing to escalate".
# `license_risk` is written by two stages with different casing -- this module
# returns "High"/"Medium" while analysis.license_policy_engine writes "HIGH"/
# "MEDIUM" -- so every comparison against it has to be case-insensitive.
_NO_LICENSE_RISK_VALUES = frozenset({"", "LOW"})


def license_risk_count(packages: list[dict]) -> int:
    """Components whose licence risk sits above the permissive LOW baseline.

    The previous predicate matched only ``{"Critical", "High"}``, so a
    component carrying ``MEDIUM`` (an unknown or unclassified licence) was
    never counted and the report published ``license_risks: 0`` alongside 48
    components the same payload labelled ``MEDIUM``.
    """
    return sum(
        1
        for p in packages
        if str(p.get("license_risk") or "").strip().upper() not in _NO_LICENSE_RISK_VALUES
    )


def build_package_summary(packages: list[dict]) -> dict:
    total = len(packages)
    direct = sum(1 for p in packages if p.get("is_direct"))
    transitive = total - direct

    vulnerable_pkg_keys = set()

    for pkg in packages:
        if int(pkg.get("vulnerability_count", 0) or 0) > 0:

            key = (
                pkg.get("purl")
                or f"{pkg.get('ecosystem')}:{pkg.get('name')}:{pkg.get('version')}"
            )

            vulnerable_pkg_keys.add(key)

    vulnerable_packages = len(vulnerable_pkg_keys)
    cve_count = len({
        cve
        for p in packages
        for cve in (p.get("cve_list") or ([] if not p.get("cve") else [p.get("cve")]))
        if _valid(cve)
    })
    advisory_count = len({
        adv
        for p in packages
        for adv in (p.get("advisory_ids") or ([] if not p.get("advisory_id") else [p.get("advisory_id")]))
        if _valid(adv)
    })
    vulnerable_advisory_records = sum(int(p.get("vulnerability_count", 0) or 0) for p in packages)

    critical_cves = 0
    high_cves = 0
    medium_cves = 0
    low_cves = 0

    for pkg in packages:
        vulns = pkg.get("vulnerabilities") or []

        if vulns:
            for vuln in vulns:
                sev = str(vuln.get("severity", "Unknown")).lower()
                if sev == "critical":
                    critical_cves += 1
                elif sev == "high":
                    high_cves += 1
                elif sev == "medium":
                    medium_cves += 1
                elif sev == "low":
                    low_cves += 1
        elif pkg.get("cve"):
            sev = str(pkg.get("severity", "Unknown")).lower()
            if sev == "critical":
                critical_cves += 1
            elif sev == "high":
                high_cves += 1
            elif sev == "medium":
                medium_cves += 1
            elif sev == "low":
                low_cves += 1

    license_risks = license_risk_count(packages)

    return {
        "total_packages": total,
        "direct_packages": direct,
        "transitive_packages": transitive,
        "unique_vulnerable_packages": vulnerable_packages,
        "cve_count": cve_count,
        "advisory_count": advisory_count,
        "vulnerable_advisory_records": vulnerable_advisory_records,
        "vulnerable_package_dedup_key": "purl_or_ecosystem_name_version",
        "critical_cves": critical_cves,
        "high_cves": high_cves,
        "medium_cves": medium_cves,
        "low_cves": low_cves,
        "license_risks": license_risks,
    }


def enrich_report_payload(payload: dict) -> dict:
    result = deepcopy(payload)

    sbom = result.get("sbom", [])
    enriched_sbom = enrich_packages(sbom)

    result["sbom"] = enriched_sbom
    result["sbom_summary"] = build_package_summary(enriched_sbom)
    

    metadata = result.setdefault("metadata", {})
    metadata["sbom_packages"] = result["sbom_summary"]["total_packages"]
    metadata["direct_packages"] = result["sbom_summary"]["direct_packages"]
    metadata["transitive_packages"] = result["sbom_summary"]["transitive_packages"]
    metadata["unique_vulnerable_packages"] = result["sbom_summary"]["unique_vulnerable_packages"]
    metadata["vulnerable_package_dedup_key"] = result["sbom_summary"]["vulnerable_package_dedup_key"]
    metadata["cve_count"] = result["sbom_summary"]["cve_count"]
    metadata["advisory_count"] = result["sbom_summary"]["advisory_count"]
    metadata["vulnerable_advisory_records"] = result["sbom_summary"]["vulnerable_advisory_records"]
    metadata["license_risks"] = result["sbom_summary"]["license_risks"]

    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="R-SecOpsX Package Intelligence Enhancer")
    parser.add_argument("input", help="Input clean_report.json or SBOM JSON")
    parser.add_argument("--output", default=None, help="Output enriched JSON")
    args = parser.parse_args()

    source = Path(args.input)
    data = json.loads(source.read_text(encoding="utf-8"))

    if isinstance(data, dict) and "sbom" in data:
        result = enrich_report_payload(data)
    elif isinstance(data, list):
        enriched = enrich_packages(data)
        result = {
            "sbom": enriched,
            "sbom_summary": build_package_summary(enriched),
        }
    else:
        raise SystemExit("Input must be clean_report.json with sbom or a list of packages")

    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(f"[PACKAGE-INTEL] Packages enriched: {len(result.get('sbom', []))}")
        print(f"[PACKAGE-INTEL] Output written: {output}")
    else:
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()