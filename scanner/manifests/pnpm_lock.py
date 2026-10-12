"""pnpm-lock.yaml parser (npm ecosystem).

pnpm lockfiles use a YAML structure with an `importers` section for direct
dependencies and a `packages` section for the full resolved tree.
"""
from __future__ import annotations

import logging
import re
from pathlib import Path

_LOG = logging.getLogger("rsx.scanner.manifests.pnpm_lock")


def parse_pnpm_lock(filepath: str) -> list[dict]:
    """Parse pnpm-lock.yaml and extract pinned package versions."""
    pkgs = []
    try:
        import yaml
        data = yaml.safe_load(Path(filepath).read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return pkgs

        # Direct dependencies from importers
        importers = data.get("importers", {})
        direct_names = set()
        for _path, importer in importers.items():
            if not isinstance(importer, dict):
                continue
            for section in ("dependencies", "devDependencies"):
                for name in (importer.get(section) or {}):
                    direct_names.add(name)

        # All packages from the packages section
        packages = data.get("packages", {})
        for pkg_key, meta in packages.items():
            if not isinstance(meta, dict):
                continue
            # pnpm keys look like "lodash@4.17.21" or "/lodash@4.17.21"
            name = pkg_key.split("@")[0].lstrip("/")
            if not name or name.startswith("link:"):
                continue
            version = str(meta.get("version", "unknown"))
            if version == "unknown":
                # Try to extract from the key
                m = re.search(r"@(\d+\.\d+\.\d+.*)$", pkg_key)
                if m:
                    version = m.group(1)
            pkgs.append({
                "name": name,
                "version": version,
                "ecosystem": "npm",
                "license": "unknown",
                "direct": name in direct_names,
                "manifest_file": filepath,
                "manifest_line": 1,
            })
    except ImportError:
        # Fallback: regex-based parsing
        try:
            text = Path(filepath).read_text(encoding="utf-8", errors="replace")
            for m in re.finditer(r'^\s+/?([^@\s]+)@(\d+\.\d+\.\d+[^:\s]*):', text, re.MULTILINE):
                name, version = m.group(1), m.group(2)
                if name.startswith("link:"):
                    continue
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
            _LOG.warning("pnpm-lock regex parse failed for %s: %s", filepath, e)
    except Exception as e:
        _LOG.warning("pnpm-lock parse failed for %s: %s", filepath, e)

    return pkgs
