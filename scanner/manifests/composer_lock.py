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
                pkgs.append({
                    "name": name,
                    "version": version,
                    "ecosystem": "Packagist",
                    "license": "unknown",
                    "direct": is_direct,
                    "manifest_file": filepath,
                    "manifest_line": 1,
                })
    except Exception as e:
        _LOG.warning("composer.lock parse failed for %s: %s", filepath, e)

    return pkgs
