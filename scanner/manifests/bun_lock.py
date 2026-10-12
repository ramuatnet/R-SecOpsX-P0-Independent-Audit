"""bun.lock and deno.lock parsers (npm ecosystem).

bun.lock uses a JSON format with a "packages" object.
deno.lock uses a JSON format with a "packages" object containing specifiers.
"""
from __future__ import annotations

import json
import logging
import re
from pathlib import Path

_LOG = logging.getLogger("rsx.scanner.manifests.bun_lock")


def parse_bun_lock(filepath: str) -> list[dict]:
    """Parse bun.lock and extract pinned package versions."""
    pkgs = []
    try:
        data = json.loads(Path(filepath).read_text(encoding="utf-8-sig"))
        packages = data.get("packages", {})
        if isinstance(packages, dict):
            for name, meta in packages.items():
                if not isinstance(meta, dict):
                    continue
                version = str(meta.get("version", "unknown"))
                if version == "unknown":
                    # Try to extract from name like "lodash@4.17.21"
                    m = re.search(r"@(\d+\.\d+\.\d+.*)$", name)
                    if m:
                        version = m.group(1)
                pkgs.append({
                    "name": name.split("@")[0] if not name.startswith("@") else "@" + name.split("@")[1],
                    "version": version,
                    "ecosystem": "npm",
                    "license": "unknown",
                    "direct": False,
                    "manifest_file": filepath,
                    "manifest_line": 1,
                })
        elif isinstance(packages, list):
            # bun.lock can also use an array format
            for entry in packages:
                if not isinstance(entry, dict):
                    continue
                name = entry.get("name", "")
                version = str(entry.get("version", "unknown"))
                if name:
                    pkgs.append({
                        "name": name,
                        "version": version,
                        "ecosystem": "npm",
                        "license": "unknown",
                        "direct": False,
                        "manifest_file": filepath,
                        "manifest_line": 1,
                    })
    except Exception as e:
        _LOG.warning("bun.lock parse failed for %s: %s", filepath, e)

    return pkgs


def parse_deno_lock(filepath: str) -> list[dict]:
    """Parse deno.lock and extract pinned package versions."""
    pkgs = []
    try:
        data = json.loads(Path(filepath).read_text(encoding="utf-8-sig"))
        packages = data.get("packages", {})
        if isinstance(packages, dict):
            for specifier, meta in packages.items():
                if not isinstance(meta, dict):
                    continue
                # Deno specifiers look like "npm:lodash@^4.17.0"
                name = specifier.split("@")[0].replace("npm:", "")
                version = str(meta.get("version", "unknown"))
                if version == "unknown":
                    m = re.search(r"@(\d+\.\d+\.\d+.*)$", specifier)
                    if m:
                        version = m.group(1)
                if name:
                    pkgs.append({
                        "name": name,
                        "version": version,
                        "ecosystem": "npm",
                        "license": "unknown",
                        "direct": False,
                        "manifest_file": filepath,
                        "manifest_line": 1,
                    })
    except Exception as e:
        _LOG.warning("deno.lock parse failed for %s: %s", filepath, e)

    return pkgs
