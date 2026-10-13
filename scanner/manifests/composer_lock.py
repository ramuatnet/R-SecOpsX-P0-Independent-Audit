"""composer.lock parser (Packagist / PHP ecosystem).

composer.lock uses JSON with "packages" (direct) and "packages-dev" sections.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path

_LOG = logging.getLogger("rsx.scanner.manifests.composer_lock")


def parse_composer_lock(filepath: str) -> list[dict]:
    """Parse composer.lock and extract pinned package versions."""
    pkgs = []
    try:
        data = json.loads(Path(filepath).read_text(encoding="utf-8-sig"))
        for section, is_direct in (("packages", True), ("packages-dev", False)):
            for pkg in data.get(section, []):
                name = pkg.get("name", "")
                version = pkg.get("version", "unknown")
                if not name:
                    continue
                # Normalize version: remove leading 'v' if present
                if version.startswith("v") and version[1:2].isdigit():
                    version = version[1:]
                # composer.lock records each package's licence as an SPDX
                # string list ("license": ["MIT"]); some tools emit a bare
                # string. Both shapes are accepted, first entry wins, exactly
                # as _parse_package_lock handles npm. Declared licences were
                # previously discarded, which made every Packagian package
                # show as "unknown" in the SBOM and the license policy.
                license_value = pkg.get("license") or pkg.get("licenses") or "unknown"
                if isinstance(license_value, list):
                    license_value = license_value[0] if license_value else "unknown"
                if isinstance(license_value, dict):
                    license_value = (
                        license_value.get("type")
                        or license_value.get("id")
                        or "unknown"
                    )
                pkgs.append({
                    "name": name,
                    "version": version,
                    "ecosystem": "Packagist",
                    "license": str(license_value),
                    "direct": is_direct,
                    "manifest_file": filepath,
                    "manifest_line": 1,
                })
    except Exception as e:
        _LOG.warning("composer.lock parse failed for %s: %s", filepath, e)

    return pkgs
