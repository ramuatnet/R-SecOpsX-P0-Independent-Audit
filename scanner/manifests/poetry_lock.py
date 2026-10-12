"""Poetry and Pipfile lockfile parsers (PyPI ecosystem).

poetry.lock uses PEP 735 metadata with [[package]] sections.
Pipfile.lock uses JSON with "default" and "develop" sections.

Both resolve to exact versions, which is what the OSV advisory query needs.
"""
from __future__ import annotations

import json
import logging
import re
from pathlib import Path

_LOG = logging.getLogger("rsx.scanner.manifests.poetry_lock")

try:
    import tomllib
except ImportError:
    tomllib = None


def parse_poetry_lock(filepath: str) -> list[dict]:
    """Parse poetry.lock and extract pinned package versions."""
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
                    "ecosystem": "PyPI",
                    "license": "unknown",
                    "direct": not pkg.get("category", "") == "dev",
                    "manifest_file": filepath,
                    "manifest_line": 1,
                })
            return pkgs
        except Exception as e:
            _LOG.warning("tomllib parse failed for %s: %s", filepath, e)

    # Fallback: regex-based parsing for [[package]] sections
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
        current_name = None
        current_version = "unknown"
        current_dev = False

        for line in text.splitlines():
            line = line.strip()
            if line == "[[package]]":
                if current_name:
                    pkgs.append({
                        "name": current_name,
                        "version": current_version,
                        "ecosystem": "PyPI",
                        "license": "unknown",
                        "direct": not current_dev,
                        "manifest_file": filepath,
                        "manifest_line": 1,
                    })
                current_name = None
                current_version = "unknown"
                current_dev = False
            elif line.startswith("name") and "=" in line:
                current_name = line.split("=", 1)[1].strip().strip('"').strip("'")
            elif line.startswith("version") and "=" in line:
                current_version = line.split("=", 1)[1].strip().strip('"').strip("'")
            elif line.startswith("category") and "=" in line:
                current_dev = "dev" in line.split("=", 1)[1].strip().lower()

        if current_name:
            pkgs.append({
                "name": current_name,
                "version": current_version,
                "ecosystem": "PyPI",
                "license": "unknown",
                "direct": not current_dev,
                "manifest_file": filepath,
                "manifest_line": 1,
            })
    except Exception as e:
        _LOG.warning("regex parse failed for %s: %s", filepath, e)

    return pkgs


def parse_pipfile_lock(filepath: str) -> list[dict]:
    """Parse Pipfile.lock and extract pinned package versions."""
    pkgs = []
    try:
        data = json.loads(Path(filepath).read_text(encoding="utf-8-sig"))
        for section in ("default", "develop"):
            for name, meta in data.get(section, {}).items():
                version = str(meta.get("version", "unknown")).replace("==", "")
                if version == "unknown" or not version:
                    version = "unknown"
                pkgs.append({
                    "name": name,
                    "version": version,
                    "ecosystem": "PyPI",
                    "license": "unknown",
                    "direct": section == "default",
                    "manifest_file": filepath,
                    "manifest_line": 1,
                })
    except Exception as e:
        _LOG.warning("Pipfile.lock parse failed for %s: %s", filepath, e)

    return pkgs
