"""Gemfile.lock parser (RubyGems / Ruby ecosystem).

Gemfile.lock uses a custom format with GEM, PATH, and GIT sections,
each containing specs indented under a source declaration.
"""
from __future__ import annotations

import logging
import re
from pathlib import Path

_LOG = logging.getLogger("rsx.scanner.manifests.gemfile_lock")


def parse_gemfile_lock(filepath: str) -> list[dict]:
    """Parse Gemfile.lock and extract pinned gem versions."""
    pkgs = []
    try:
        text = Path(filepath).read_text(encoding="utf-8", errors="replace")
        # Gemfile.lock format:
        # GEM
        #   remote: https://rubygems.org/
        #   specs:
        #     rails (7.0.0)
        #       actioncable (= 7.0.0)
        #
        # We want the top-level gems (4-space indent) and their dependencies (6-space indent)
        in_specs = False
        current_section = None

        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            # Section headers
            if stripped in ("GEM", "PATH", "GIT", "PLUGIN"):
                current_section = stripped
                in_specs = False
                continue

            if stripped == "specs:":
                in_specs = True
                continue

            if not in_specs or current_section != "GEM":
                continue

            # Top-level gem: 4-space indent "    name (version)"
            # Dependency: 6-space indent "      name (version)"
            indent = len(line) - len(line.lstrip())
            m = re.match(r'^(\S+)\s+\(([^)]+)\)', stripped)
            if not m:
                continue

            name, version = m.group(1), m.group(2)
            # Skip version constraints like ">= 1.0" or "= 7.0.0"
            if version.startswith((">", "<", "=", "~", "!")):
                continue

            pkgs.append({
                "name": name,
                "version": version,
                "ecosystem": "RubyGems",
                "license": "unknown",
                "direct": indent <= 4,
                "manifest_file": filepath,
                "manifest_line": 1,
            })
    except Exception as e:
        _LOG.warning("Gemfile.lock parse failed for %s: %s", filepath, e)

    return pkgs
