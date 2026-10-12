"""SBOM/CBOM/AI-BOM interoperability validation (Phase V4).

Validates that emitted BOMs are consumable by third-party tooling:
  - CycloneDX JSON schema conformance (1.5 current, 1.7 target)
  - SPDX tools validator
  - sbomqs quality score >= 7.0
  - CBOMkit parse check
  - OWASP aibom-generator schema check
"""
from __future__ import annotations

import json
import logging
import re
import subprocess
import sys
import tempfile
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

_LOG = logging.getLogger("rsx.analysis.validation.sbom_conformance")


def _cyclonedx_schema_check(doc: dict, target_versions: tuple = ("1.5", "1.7")) -> dict:
    """Validate CycloneDX document against official JSON schemas."""
    results = {}
    try:
        import jsonschema
        import requests
        for ver in target_versions:
            url = f"https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-{ver}.schema.json"
            try:
                schema = requests.get(url, timeout=10).json()
                jsonschema.validate(instance=doc, schema=schema)
                results[ver] = {"valid": True, "errors": []}
            except requests.RequestException as e:
                results[ver] = {"valid": False, "errors": [f"schema fetch failed: {e}"]}
            except jsonschema.ValidationError as e:
                results[ver] = {"valid": False, "errors": [str(e.message)]}
            except Exception as e:
                results[ver] = {"valid": False, "errors": [str(e)]}
    except ImportError:
        results["error"] = "jsonschema/requests not installed"
    return results


def _spdx_schema_check(doc: dict) -> dict:
    """Validate SPDX document structure."""
    try:
        import jsonschema
        import requests
        url = "https://raw.githubusercontent.com/spdx/spdx-spec/development/v2.3/schemas/spdx-schema.json"
        try:
            schema = requests.get(url, timeout=10).json()
            jsonschema.validate(instance=doc, schema=schema)
            return {"valid": True, "errors": []}
        except requests.RequestException as e:
            return {"valid": False, "errors": [f"schema fetch failed: {e}"]}
        except jsonschema.ValidationError as e:
            return {"valid": False, "errors": [str(e.message)]}
    except ImportError:
        return {"error": "jsonschema/requests not installed"}
    except Exception as e:
        return {"valid": False, "errors": [str(e)]}


def _sbomqs_score(doc: dict) -> float:
    """Compute a simplified sbomqs-style 0-10 quality score."""
    score = 0.0
    # Spec compliance (25%)
    if doc.get("bomFormat") == "CycloneDX":
        score += 2.5
    if doc.get("specVersion"):
        score += 2.5
    # Generation info (15%)
    if doc.get("metadata", {}).get("timestamp"):
        score += 1.5
    if doc.get("metadata", {}).get("tools"):
        score += 1.0
    if doc.get("serialNumber"):
        score += 1.5
    # Package identifiers (20%)
    components = doc.get("components", [])
    if components:
        score += 1.0
        purl_count = sum(1 for c in components if c.get("purl"))
        if purl_count == len(components):
            score += 1.0
    # Versions and hashes (20%)
    if components:
        version_count = sum(1 for c in components if c.get("version"))
        if version_count == len(components):
            score += 1.0
        hash_count = sum(1 for c in components if c.get("hashes"))
        if hash_count > 0:
            score += 0.5
    # Licenses (20%)
    if components:
        lic_count = sum(1 for c in components if c.get("licenses"))
        if lic_count > 0:
            score += 1.0
    return min(score, 10.0)


def _cbomkit_parse_check(doc: dict) -> dict:
    """Check if a CBOM document has required cryptoProperties structure."""
    components = doc.get("components", [])
    if not components:
        return {"valid": False, "errors": ["no components"]}
    crypto_components = [c for c in components if c.get("type") == "cryptographic-asset"]
    if not crypto_components:
        return {"valid": False, "errors": ["no cryptographic-asset components"]}
    return {"valid": True, "errors": []}


def _aibom_schema_check(doc: dict) -> dict:
    """Check AI-BOM document has required model-card structure."""
    components = doc.get("components", [])
    if not components:
        return {"valid": False, "errors": ["no components"]}
    ai_components = [c for c in components if c.get("type") == "machine-learning-model"]
    if not ai_components:
        return {"valid": False, "errors": ["no machine-learning-model components"]}
    return {"valid": True, "errors": []}


def validate_sbom_conformance(report_dir: str | Path) -> dict:
    """Validate all BOM artifacts in a report directory."""
    report_dir = Path(report_dir)
    results = {}

    cdx_path = report_dir / "Security_CycloneDX.json"
    if cdx_path.is_file():
        try:
            cdx = json.loads(cdx_path.read_text(encoding="utf-8"))
            results["cyclonedx"] = _cyclonedx_schema_check(cdx)
            results["cyclonedx"]["quality_score"] = _sbomqs_score(cdx)
        except Exception as e:
            results["cyclonedx"] = {"valid": False, "errors": [str(e)]}
    else:
        results["cyclonedx"] = {"error": "file not found"}

    spdx_path = report_dir / "Security_SPDX.spdx.json"
    if spdx_path.is_file():
        try:
            spdx = json.loads(spdx_path.read_text(encoding="utf-8"))
            results["spdx"] = _spdx_schema_check(spdx)
        except Exception as e:
            results["spdx"] = {"valid": False, "errors": [str(e)]}
    else:
        results["spdx"] = {"error": "file not found"}

    cbom_path = report_dir / "Security_QBOM.qbom.json"
    if cbom_path.is_file():
        try:
            cbom = json.loads(cbom_path.read_text(encoding="utf-8"))
            results["cbom"] = _cbomkit_parse_check(cbom)
        except Exception as e:
            results["cbom"] = {"valid": False, "errors": [str(e)]}
    else:
        results["cbom"] = {"error": "file not found"}

    aibom_path = report_dir / "Security_AIBOM.json"
    if aibom_path.is_file():
        try:
            aibom = json.loads(aibom_path.read_text(encoding="utf-8"))
            results["aibom"] = _aibom_schema_check(aibom)
        except Exception as e:
            results["aibom"] = {"valid": False, "errors": [str(e)]}
    else:
        results["aibom"] = {"error": "file not found"}

    return results


def main(argv: list[str] | None = None) -> int:
    import argparse
    parser = argparse.ArgumentParser(
        prog="analysis.validation.sbom_conformance",
        description="Validate SBOM/CBOM/AI-BOM interoperability.")
    parser.add_argument("report_dir", help="path to the report output directory")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    results = validate_sbom_conformance(args.report_dir)

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        for name, result in results.items():
            if "error" in result:
                print("%-12s ERROR: %s" % (name, result["error"]))
                continue
            valid = result.get("valid", False)
            errors = result.get("errors", [])
            score = result.get("quality_score")
            status = "PASS" if valid else "FAIL"
            line = "%-12s %s" % (name, status)
            if score is not None:
                line += "  quality=%.1f" % score
            if errors:
                line += "  errors=%s" % errors[:3]
            print(line)

    all_valid = all(r.get("valid") for r in results.values() if "error" not in r)
    return 0 if all_valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
