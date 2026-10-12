"""Cargo.lock parser (crates.io / Rust ecosystem).

Cargo.lock uses TOML format with [[package]] sections containing
name, version, and dependencies.
"""
from __future__ import annotations

import logging
import re
from pathlib import Path

_LOG = logging.getLogger("rsx.scanner.manifests.cargo_lock")

try:
    import tomllib
except ImportError:
    tomllib = None


def parse_cargo_lock(filepath: str) -> list[dict]:
    """Parse Cargo.lock and extract pinned crate versions."""
    pkgs = []
    path = Path(filepath)

    if tomllib is not None:
        try:
            data = tomllib.loads(path.read_text(encoding="utf-8"))
            for pkg in data.get("package", []):
                name = pkg.get("name", "")
                version = pkg.get("version", "unknown")
                if not name:
                    continue
                pkgs.append({
                    "name": name,
                    "version": version,
                    "ecosystem": "crates.io",
                    "license": "unknown",
                    "direct": False,
                    "manifest_file": filepath,
                    "manifest_line": 1,
                })
            return pkgs
        except Exception as e:
            _LOG.warning("tomllib parse failed for %s: %s", filepath, e)

    # Fallback: regex-based parsing
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
        current_name = None
        current_version = "unknown"

        for line in text.splitlines():
            line = line.strip()
            if line == "[[package]]":
                if current_name:
                    pkgs.append({
                        "name": current_name,
                        "version": current_version,
                        "ecosystem": "crates.io",
                        "license": "unknown",
                        "direct": False,
                        "manifest_file": filepath,
                        "manifest_line": 1,
                    })
                current_name = None
                current_version = "unknown"
            elif line.startswith("name") and "=" in line:
                current_name = line.split("=", 1)[1].strip().strip('"').strip("'")
            elif line.startswith("version") and "=" in line:
                current_version = line.split("=", 1)[1].strip().strip('"').strip("'")

        if current_name:
            pkgs.append({
                "name": current_name,
                "version": current_version,
                "ecosystem": "crates.io",
                "license": "unknown",
                "direct": False,
                "manifest_file": filepath,
                "manifest_line": 1,
            })
    except Exception as e:
        _LOG.warning("regex parse failed for %s: %s", filepath, e)

    return pkgs
