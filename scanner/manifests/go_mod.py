"""go.mod and go.sum parsers (Go ecosystem).

go.mod declares direct dependencies with `require` directives.
go.sum records exact versions and hashes for all dependencies (direct + transitive).
"""
from __future__ import annotations

import logging
import re
from pathlib import Path

_LOG = logging.getLogger("rsx.scanner.manifests.go_mod")


def parse_go_mod(filepath: str) -> list[dict]:
    """Parse go.mod and extract direct dependency declarations."""
    pkgs = []
    try:
        text = Path(filepath).read_text(encoding="utf-8", errors="replace")
        # Match require blocks and single-line requires:
        #   require (
        #     github.com/gin-gonic/gin v1.9.0
        #   )
        in_require = False
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("require ("):
                in_require = True
                continue
            if in_require and line == ")":
                in_require = False
                continue
            if in_require or line.startswith("require "):
                # Extract module path and version
                m = re.match(r'(?:require\s+)?(\S+)\s+(v\S+)', line)
                if m:
                    name, version = m.group(1), m.group(2)
                    pkgs.append({
                        "name": name,
                        "version": version,
                        "ecosystem": "Go",
                        "license": "unknown",
                        "direct": True,
                        "manifest_file": filepath,
                        "manifest_line": 1,
                    })
    except Exception as e:
        _LOG.warning("go.mod parse failed for %s: %s", filepath, e)

    return pkgs


def parse_go_sum(filepath: str) -> list[dict]:
    """Parse go.sum and extract exact pinned versions for all dependencies."""
    pkgs = []
    try:
        text = Path(filepath).read_text(encoding="utf-8", errors="replace")
        # go.sum lines: module version hash
        # github.com/gin-gonic/gin v1.9.0 h1:...
        # github.com/gin-gonic/gin v1.9.0/go.mod h1:...
        seen = set()
        for line in text.splitlines():
            parts = line.split()
            if len(parts) < 2:
                continue
            name = parts[0]
            version = parts[1]
            # Skip /go.mod hash entries
            if version.endswith("/go.mod"):
                continue
            key = (name, version)
            if key in seen:
                continue
            seen.add(key)
            pkgs.append({
                "name": name,
                "version": version,
                "ecosystem": "Go",
                "license": "unknown",
                "direct": False,
                "manifest_file": filepath,
                "manifest_line": 1,
            })
    except Exception as e:
        _LOG.warning("go.sum parse failed for %s: %s", filepath, e)

    return pkgs
