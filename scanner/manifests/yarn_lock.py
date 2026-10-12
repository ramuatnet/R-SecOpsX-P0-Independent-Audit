"""yarn.lock parser (npm ecosystem).

Yarn v1 lockfiles use a custom format where each entry starts with a
comma-separated list of package specifiers, followed by resolved version,
integrity hash, and dependencies.
"""
from __future__ import annotations

import logging
import re
from pathlib import Path

_LOG = logging.getLogger("rsx.scanner.manifests.yarn_lock")


def parse_yarn_lock(filepath: str) -> list[dict]:
    """Parse yarn.lock (v1) and extract pinned package versions."""
    pkgs = []
    try:
        text = Path(filepath).read_text(encoding="utf-8", errors="replace")
        # Yarn v1 entries start with a specifier line like:
        # "lodash@^4.17.0", lodash@4.17.21:
        #   version "4.17.21"
        entry_re = re.compile(
            r'^(?:"([^"]+)"|([^:\n]+)):\s*\n\s+version\s+"([^"]+)"',
            re.MULTILINE
        )
        for m in entry_re.finditer(text):
            spec = m.group(1) or m.group(2) or ""
            version = m.group(3)
            # Extract package name from specifier
            # Handle scoped packages: @scope/name@range
            name = spec.split("@")[0]
            if spec.startswith("@"):
                # Scoped: @scope/name@range -> @scope/name
                parts = spec.split("@")
                if len(parts) >= 2:
                    name = "@" + parts[1]
            if not name:
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
        _LOG.warning("yarn.lock parse failed for %s: %s", filepath, e)

    return pkgs
