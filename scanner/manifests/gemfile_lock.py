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
    declared: set[str] = set()
    try:
        text = Path(filepath).read_text(encoding="utf-8", errors="replace")
        # Gemfile.lock format:
        # GEM
        #   remote: https://rubygems.org/
        #   specs:
        #     rails (7.0.0)
        #       actioncable (= 7.0.0)
        #
        # DEPENDENCIES
        #   rails
        #
        # R1/W3 (GAP-09): the specs list is FLAT -- every resolved gem sits
        # at the same indent, declared and pulled-in alike -- so indentation
        # was never a direct/transitive signal (it stamped all 197
        # railsgoat specs direct). The authoritative declared set is the
        # DEPENDENCIES section; every other resolved spec stamps
        # direct=False and classifies through the evidence gate via
        # lockfile membership.
        in_specs = False
        current_section = None

        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            # Top-level section headers sit at column 0: GEM, PATH, GIT,
            # PLUGIN, PLATFORMS, DEPENDENCIES, BUNDLED WITH.
            if not line[:1].isspace():
                current_section = stripped
                in_specs = False
                continue

            if stripped == "specs:":
                in_specs = True
                continue

            if current_section == "DEPENDENCIES":
                # Declared gems are bare names, occasionally with a
                # trailing constraint: `rails (~> 7.0)`.
                m = re.match(r'^([^\s(]+)\s*(?:\(([^)]*)\))?\s*$', stripped)
                if m:
                    declared.add(m.group(1))
                continue

            if not in_specs or current_section != "GEM":
                continue

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
                # Stamped after the walk: DEPENDENCIES is declared after
                # specs in the file.
                "direct": False,
                "manifest_file": filepath,
                "manifest_line": 1,
            })
    except Exception as e:
        _LOG.warning("Gemfile.lock parse failed for %s: %s", filepath, e)

    # Direct = declared in DEPENDENCIES. Indentation is not a signal.
    for pkg in pkgs:
        pkg["direct"] = pkg["name"] in declared

    unresolved = declared - {pkg["name"] for pkg in pkgs}
    if unresolved:
        # Declared but not resolved in the GEM specs -- disclosed, never
        # invented as rows. GIT/PATH/PLUGIN specs are not collected by this
        # parser (a registered follow-up gap), so their gems surface here.
        _LOG.info(
            "Gemfile.lock %s: %d declared gem(s) unresolved in specs: %s",
            filepath, len(unresolved), ", ".join(sorted(unresolved)))

    return pkgs
