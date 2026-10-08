"""
analysis/sbom_inventory_engine.py

SBOM Full Inventory Engine.
Stdlib-only. Converts existing R-SecOpsX SBOM rows into an auditable package inventory.
"""
from __future__ import annotations

from typing import Any, Dict, List
import hashlib

UNKNOWN = {"", "none", "null", "unknown", "n/a", "na", "not applicable", "-"}


def _clean(value: Any, default: str = "") -> str:
    if value is None:
        return default
    text = str(value).strip()
    return default if text.lower() in UNKNOWN else text


def _first(pkg: Dict[str, Any], *keys: str, default: Any = "") -> Any:
    for key in keys:
        value = pkg.get(key)
        # "--" is the report's absence marker, not a value: without it a
        # component with no fix would surface `'--'` here where a list of
        # fixed versions is expected.
        if value not in (None, "", [], {}, "unknown", "Unknown", "UNKNOWN", "--"):
            return value
    return default


def _identity(pkg: Dict[str, Any]) -> str:
    eco = _clean(_first(pkg, "ecosystem", "type", default="unknown"), "unknown").lower()
    name = _clean(_first(pkg, "name", "package", "component", default="unknown"), "unknown")
    ver = _clean(_first(pkg, "version", default="unknown"), "unknown")
    return f"{eco}:{name}@{ver}"


def _fingerprint(pkg: Dict[str, Any]) -> str:
    raw = "|".join([
        _clean(_first(pkg, "ecosystem", "type", default="")),
        _clean(_first(pkg, "name", "package", "component", default="")),
        _clean(_first(pkg, "version", default="")),
        _clean(_first(pkg, "purl", "Purl", default="")),
    ])
    return hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()[:32]


def _vuln_ids(pkg: Dict[str, Any]) -> List[str]:
    values: List[str] = []
    for key in ("cve", "advisory_id", "primary_vulnerability_id", "vulnerability_id", "ghsa"):
        if pkg.get(key):
            values.append(str(pkg.get(key)).strip())

    for key in ("cve_list", "cves", "advisory_ids", "vulnerability_ids", "additional_cves"):
        value = pkg.get(key)
        if isinstance(value, list):
            values.extend(str(x).strip() for x in value if str(x).strip())
        elif isinstance(value, str) and value.strip():
            values.extend(x.strip() for x in value.split(",") if x.strip())

    vulns = pkg.get("vulnerabilities")
    if isinstance(vulns, list):
        for vuln in vulns:
            if isinstance(vuln, dict):
                vid = vuln.get("id") or vuln.get("cve") or vuln.get("advisory_id") or vuln.get("ghsa")
                if vid:
                    values.append(str(vid).strip())
            elif vuln:
                values.append(str(vuln).strip())

    return sorted(set(v for v in values if v and v.lower() not in UNKNOWN))


def _dependency_type(pkg: Dict[str, Any]) -> str:
    direct_flag = pkg.get("direct")
    dep_type = _clean(_first(pkg, "dependency_type", "type", "scope", default=""))
    if isinstance(direct_flag, bool):
        return "direct" if direct_flag else "transitive"
    if dep_type.lower() in {"direct", "root"}:
        return "direct"
    if dep_type.lower() in {"transitive", "indirect"}:
        return "transitive"
    try:
        if pkg.get("depth") is not None:
            return "direct" if int(pkg.get("depth")) <= 0 else "transitive"
    except Exception:
        pass
    return dep_type or "unknown"


def _depth(pkg: Dict[str, Any]) -> int | None:
    for key in ("depth", "dependency_depth", "level"):
        try:
            if pkg.get(key) not in (None, ""):
                return int(pkg.get(key))
        except Exception:
            pass
    chain = pkg.get("dependency_path") or pkg.get("dependency_chain") or pkg.get("path")
    if isinstance(chain, list):
        return max(0, len(chain) - 1)
    return 0 if _dependency_type(pkg) == "direct" else None


def build_sbom_full_inventory(sbom: List[Dict[str, Any]]) -> Dict[str, Any]:
    packages: List[Dict[str, Any]] = []

    for idx, pkg in enumerate(sbom or [], 1):
        if not isinstance(pkg, dict):
            continue

        vulnerabilities = _vuln_ids(pkg)
        license_value = _clean(
            _first(pkg, "license", "license_expression", "LicenseExpression",
                   "DeclaredLicenseExpression", default="unknown"),
            "unknown",
        )

        item = {
            "index": idx,
            "package_identity": _identity(pkg),
            "fingerprint": _fingerprint(pkg),
            "name": _clean(_first(pkg, "name", "package", "component", default="unknown"), "unknown"),
            "version": _clean(_first(pkg, "version", default="unknown"), "unknown"),
            "ecosystem": _clean(_first(pkg, "ecosystem", "type", default="unknown"), "unknown"),
            "language": _clean(_first(pkg, "language", "Language", default=""), ""),
            "dependency_type": _dependency_type(pkg),
            "direct": _dependency_type(pkg) == "direct",
            "depth": _depth(pkg),
            "scope": _clean(_first(pkg, "scope", default=""), ""),
            "purl": _clean(_first(pkg, "purl", "Purl", default=""), ""),
            "license": license_value,
            "vulnerable": bool(vulnerabilities),
            "vulnerability_ids": vulnerabilities,
            "primary_vulnerability_id": _clean(_first(pkg, "primary_vulnerability_id", "cve", "advisory_id", default=""), ""),
            "cvss": _first(pkg, "cvss", "cvss_score", default=None),
            "severity": _clean(_first(pkg, "severity", "cvss_severity", default=""), ""),
            "fixed_versions": _first(pkg, "fixed_versions", "fixed_in", default=[]),
            "reachability_status": _clean(_first(pkg, "reachability_status", default=""), ""),
            "reachability_priority": _clean(_first(pkg, "reachability_priority", default=""), ""),
            "reachability_confidence": _clean(_first(pkg, "reachability_confidence", default=""), ""),
            "kev_status": bool(_first(pkg, "kev_status", "actively_exploited", default=False)),
            "epss_score": _first(pkg, "epss_score", "epss", default=None),
            "patch_urgency": _clean(_first(pkg, "patch_urgency", default=""), ""),
            "parent": _clean(_first(pkg, "parent", "parent_package", "introduced_by", default=""), ""),
            "dependency_path": _first(pkg, "dependency_path", "dependency_chain", "path", default=[]),
            "source_manifest": _clean(_first(pkg, "source_manifest", "manifest", "file", default=""), ""),
        }
        packages.append(item)

    summary = {
        "schema": "SBOM_FULL_INVENTORY_V1",
        "total_packages": len(packages),
        "direct_packages": sum(1 for p in packages if p.get("dependency_type") == "direct"),
        "transitive_packages": sum(1 for p in packages if p.get("dependency_type") == "transitive"),
        "unknown_dependency_type": sum(1 for p in packages if p.get("dependency_type") == "unknown"),
        "vulnerable_packages": sum(1 for p in packages if p.get("vulnerable")),
        "licensed_packages": sum(1 for p in packages if p.get("license") != "unknown"),
        "unknown_license_packages": sum(1 for p in packages if p.get("license") == "unknown"),
        "ecosystems": sorted(set(p.get("ecosystem") for p in packages if p.get("ecosystem"))),
    }
    return {"summary": summary, "packages": packages}


build_full_inventory = build_sbom_full_inventory
