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
                resp = requests.get(url, timeout=10)
                resp.raise_for_status()
                schema = resp.json()
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
        # Tag, not branch: the old development/v2.3 branch was removed when
        # 2.3 released, and a raw GitHub 404 body ("404: Not Found") parses
        # as the JSON number 404 followed by junk -- so the failure surfaced
        # as "Extra data: line 1 column 4" instead of "not found", and the
        # check failed for everyone on every run, permanently unpassable.
        url = "https://raw.githubusercontent.com/spdx/spdx-spec/v2.3/schemas/spdx-schema.json"
        try:
            resp = requests.get(url, timeout=10)
            resp.raise_for_status()
            schema = resp.json()
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
    """Check if a CBOM document has required cryptoProperties structure.

    Mirrors what OWASP cbomkit actually parses: components typed
    cryptographic-asset, each carrying a cryptoProperties block whose
    assetType is one of the 1.6 enum values and whose asset-specific
    sub-object (algorithmProperties / certificateProperties /
    relatedCryptoMaterialProperties / protocolProperties) is present.
    A component typed cryptographic-asset with no cryptoProperties is a
    schema-valid but unparsable asset, so it counts as an error here.
    """
    errors: list[str] = []
    components = doc.get("components", [])
    if not components:
        return {"valid": False, "errors": ["no components"]}

    crypto_components = [c for c in components if c.get("type") == "cryptographic-asset"]
    if not crypto_components:
        return {"valid": False, "errors": ["no cryptographic-asset components"]}

    _asset_subprops = {
        "algorithm": "algorithmProperties",
        "certificate": "certificateProperties",
        "protocol": "protocolProperties",
        "related-crypto-material": "relatedCryptoMaterialProperties",
    }
    seen_refs: set[str] = set()
    for i, comp in enumerate(crypto_components):
        ref = comp.get("bom-ref") or f"component-{i}"
        props = comp.get("cryptoProperties")
        if not isinstance(props, dict):
            errors.append(f"{ref}: missing cryptoProperties")
            continue
        asset_type = props.get("assetType")
        if asset_type not in _asset_subprops:
            errors.append(f"{ref}: invalid assetType {asset_type!r}")
            continue
        if not isinstance(props.get(_asset_subprops[asset_type]), dict):
            errors.append(f"{ref}: missing {_asset_subprops[asset_type]}")
        ref_val = comp.get("bom-ref")
        if ref_val:
            if ref_val in seen_refs:
                errors.append(f"{ref}: duplicate bom-ref")
            seen_refs.add(ref_val)
        if not comp.get("name"):
            errors.append(f"{ref}: missing name")

    return {"valid": not errors, "errors": errors,
            "crypto_components": len(crypto_components)}


def _aibom_schema_check(doc: dict) -> dict:
    """Check AI-BOM document has required model-card structure.

    The 1.6 schema has no modelProperties block (that arrived in 1.7), so
    at 1.6 the check is: machine-learning-model components exist, each with
    a unique bom-ref and a name -- plus, for this tool's own documents,
    that provider provenance survived into properties, because a model
    asset with no idea which framework declared it cannot be triaged.
    """
    errors: list[str] = []
    components = doc.get("components", [])
    if not components:
        return {"valid": False, "errors": ["no components"]}
    ai_components = [c for c in components if c.get("type") == "machine-learning-model"]
    if not ai_components:
        return {"valid": False, "errors": ["no machine-learning-model components"]}

    seen_refs: set[str] = set()
    for i, comp in enumerate(ai_components):
        ref = comp.get("bom-ref") or f"component-{i}"
        if not comp.get("name"):
            errors.append(f"{ref}: missing name")
        ref_val = comp.get("bom-ref")
        if ref_val:
            if ref_val in seen_refs:
                errors.append(f"{ref}: duplicate bom-ref")
            seen_refs.add(ref_val)
        prop_names = {p.get("name") for p in comp.get("properties") or []
                      if isinstance(p, dict)}
        if "rsecopsx:provider" not in prop_names:
            errors.append(f"{ref}: missing rsecopsx:provider property")

    return {"valid": not errors, "errors": errors,
            "ai_components": len(ai_components)}


def _attach_official_schema(result: dict, doc: dict, version: str) -> dict:
    """Fold the official CycloneDX schema check into a structural result.

    The structural check (assetType enum, asset-specific sub-object, unique
    bom-refs) is offline and always runs. The official schema check fetches
    bom-<version>.schema.json, so its outcome depends on the network:
      * validation failure  -> the document does not conform; fold into
        valid, because "conforms to CycloneDX 1.6" is the claim being made.
      * fetch failure       -> cannot verify, not a defect; record under
        schema_1.6 without failing the result, or an offline run would
        report every document invalid for lack of network.
    """
    schema = _cyclonedx_schema_check(doc, target_versions=(version,))
    entry = schema.get(version)
    if isinstance(entry, dict) and "valid" in entry:
        errs = entry.get("errors") or []
        if errs and str(errs[0]).startswith("schema fetch failed"):
            result["schema_%s" % version.replace(".", "_")] = {
                "error": str(errs[0])}
            return result
        result["schema_%s" % version.replace(".", "_")] = entry
        if not entry["valid"]:
            result.setdefault("errors", []).extend(errs[:5])
            result["valid"] = False
    elif "error" in schema:
        result["schema_%s" % version.replace(".", "_")] = {
            "error": schema["error"]}
    return result


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

    # Phase 4 fix: these two checks previously read Security_QBOM.qbom.json
    # (the CERT-In *Quantum* BOM, which by construction holds no
    # cryptographic-asset components) and Security_AIBOM.json (which no
    # writer ever produced). Both therefore always reported "no components"
    # -- a check that cannot fail is not a check. They now read the
    # CycloneDX 1.6 artifacts written by reporting/cyclonedx_bom_export.py.
    cbom_path = report_dir / "Security_CBOM.cdx.json"
    if cbom_path.is_file():
        try:
            cbom = json.loads(cbom_path.read_text(encoding="utf-8"))
            results["cbom"] = _attach_official_schema(
                _cbomkit_parse_check(cbom), cbom, "1.6")
        except Exception as e:
            results["cbom"] = {"valid": False, "errors": [str(e)]}
    else:
        results["cbom"] = {"error": "file not found"}

    aibom_path = report_dir / "Security_AIBOM.cdx.json"
    if aibom_path.is_file():
        try:
            aibom = json.loads(aibom_path.read_text(encoding="utf-8"))
            results["aibom"] = _attach_official_schema(
                _aibom_schema_check(aibom), aibom, "1.6")
        except Exception as e:
            results["aibom"] = {"valid": False, "errors": [str(e)]}
    else:
        results["aibom"] = {"error": "file not found"}

    return results


def _result_valid(result: dict) -> bool:
    """Overall verdict for one check, including nested per-version results.

    The CycloneDX check stores {\"1.5\": {valid: ...}, \"1.7\": {valid: ...}}
    with no top-level \"valid\", so reading result[\"valid\"] directly reported
    FAIL -- and made the exit code 1 -- while both versions actually passed.
    """
    if "error" in result:
        return False
    if "valid" in result:
        return bool(result["valid"])
    version_checks = [
        v for k, v in result.items()
        if isinstance(v, dict) and "valid" in v
        and re.match(r"^\d+\.\d+$", str(k))
    ]
    if version_checks:
        return all(bool(v["valid"]) for v in version_checks)
    return False


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
            valid = _result_valid(result)
            errors = result.get("errors", [])
            score = result.get("quality_score")
            status = "PASS" if valid else "FAIL"
            line = "%-12s %s" % (name, status)
            if score is not None:
                line += "  quality=%.1f" % score
            if errors:
                line += "  errors=%s" % errors[:3]
            print(line)

    all_valid = all(_result_valid(r) for r in results.values())
    return 0 if all_valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
