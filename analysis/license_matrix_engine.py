"""
analysis/license_matrix_engine.py

License Matrix Engine.
Stdlib-only. Converts SBOM package licenses into package -> license -> policy decision rows.
"""
from __future__ import annotations
try:
    from analysis.spans import WINDOW_24
except ImportError:  # FND-03: standalone, repo root not on path
    import sys as _fnd03_sys
    from pathlib import Path as _fnd03_path
    _fnd03_sys.path.insert(0, str(_fnd03_path(__file__).resolve().parents[1]))
    from analysis.spans import WINDOW_24

from typing import Any, Dict, List
import hashlib

PERMISSIVE = {"mit", "apache-2.0", "apache 2.0", "bsd", "bsd-2-clause", "bsd-3-clause", "isc", "psf", "python software foundation", "unlicense"}
REVIEW = {"mpl-2.0", "mpl 2.0"}
RESTRICTED = {"gpl", "agpl", "lgpl", "sspl", "commons clause", "elastic license", "polyform", "busl"}
UNKNOWN = {"", "none", "null", "unknown", "n/a", "na", "not applicable", "-"}


def _clean(value: Any, default: str = "") -> str:
    if value is None:
        return default
    text = str(value).strip()
    return default if text.lower() in UNKNOWN else text


def _first(pkg: Dict[str, Any], *keys: str, default: Any = "") -> Any:
    for key in keys:
        value = pkg.get(key)
        if value not in (None, "", [], {}, "unknown", "Unknown", "UNKNOWN"):
            return value
    return default


def _identity(pkg: Dict[str, Any]) -> str:
    eco = _clean(_first(pkg, "ecosystem", "type", default="unknown"), "unknown").lower()
    name = _clean(_first(pkg, "name", "package", "component", default="unknown"), "unknown")
    ver = _clean(_first(pkg, "version", default="unknown"), "unknown")
    return f"{eco}:{name}@{ver}"


def _fp(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()[:WINDOW_24]


def normalize_license(value: Any) -> str:
    return _clean(value, "unknown") or "unknown"


def classify_license(license_value: Any) -> Dict[str, Any]:
    license_text = normalize_license(license_value)
    lowered = license_text.lower()

    if lowered in UNKNOWN or lowered == "unknown":
        return {
            "classification": "UNKNOWN",
            "commercial_safe": False,
            "notice_required": False,
            "legal_review_required": True,
            "policy_reason": "License was not detected or not declared.",
        }

    if any(marker in lowered for marker in RESTRICTED):
        return {
            "classification": "RESTRICTED_OR_COPYLEFT",
            "commercial_safe": False,
            "notice_required": True,
            "legal_review_required": True,
            "policy_reason": "Copyleft or commercially restricted license marker detected.",
        }

    if any(marker in lowered for marker in REVIEW):
        return {
            "classification": "REVIEW_REQUIRED",
            "commercial_safe": False,
            "notice_required": True,
            "legal_review_required": True,
            "policy_reason": "License may be acceptable but requires legal review before redistribution.",
        }

    if any(marker in lowered for marker in PERMISSIVE):
        return {
            "classification": "PERMISSIVE",
            "commercial_safe": True,
            "notice_required": True,
            "legal_review_required": False,
            "policy_reason": "Permissive license detected; attribution/notice obligations may still apply.",
        }

    return {
        "classification": "MANUAL_REVIEW_REQUIRED",
        "commercial_safe": False,
        "notice_required": True,
        "legal_review_required": True,
        "policy_reason": "License detected but not in reviewed allow-list.",
    }


def build_license_matrix(sbom: List[Dict[str, Any]]) -> Dict[str, Any]:
    rows: List[Dict[str, Any]] = []

    for idx, pkg in enumerate(sbom or [], 1):
        if not isinstance(pkg, dict):
            continue

        license_value = normalize_license(
            _first(pkg, "license", "license_expression", "LicenseExpression",
                   "DeclaredLicenseExpression", "DeepLicenseExpression", default="unknown")
        )
        classification = classify_license(license_value)
        identity = _identity(pkg)

        rows.append({
            "index": idx,
            "package_identity": identity,
            "fingerprint": _fp(identity + "|" + license_value),
            "package": _clean(_first(pkg, "name", "package", "component", default="unknown"), "unknown"),
            "version": _clean(_first(pkg, "version", default="unknown"), "unknown"),
            "ecosystem": _clean(_first(pkg, "ecosystem", "type", default="unknown"), "unknown"),
            "purl": _clean(_first(pkg, "purl", "Purl", default=""), ""),
            "license": license_value,
            "declared_license": normalize_license(_first(pkg, "declared_license", "DeclaredLicenseExpression", default=license_value)),
            "deep_license": normalize_license(_first(pkg, "deep_license", "DeepLicenseExpression", default=license_value)),
            **classification,
        })

    summary = {
        "schema": "LICENSE_MATRIX_V1",
        "total_components": len(rows),
        "permissive": sum(1 for r in rows if r["classification"] == "PERMISSIVE"),
        "review_required": sum(1 for r in rows if r["classification"] in {"REVIEW_REQUIRED", "MANUAL_REVIEW_REQUIRED"}),
        "restricted_or_copyleft": sum(1 for r in rows if r["classification"] == "RESTRICTED_OR_COPYLEFT"),
        "unknown": sum(1 for r in rows if r["classification"] == "UNKNOWN"),
        "commercial_safe_components": sum(1 for r in rows if r["commercial_safe"]),
        "notice_required_components": sum(1 for r in rows if r["notice_required"]),
        "legal_review_required_components": sum(1 for r in rows if r["legal_review_required"]),
    }
    return {"summary": summary, "licenses": rows}


build_package_license_matrix = build_license_matrix
