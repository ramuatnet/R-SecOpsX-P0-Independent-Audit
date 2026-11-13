"""Lockfile -> extractor dispatch (R2.1).

The one-walk index discovers lockfiles by name; main.py hands each discovered
file here instead of importing the npm engine directly. The npm path
delegates to the adapter (`npm_adapter.extract`), which wraps the unmodified
engine; each R2 ecosystem registers its own module.

Membership-only and not-yet-implemented formats answer with a disclosed
UNSUPPORTED envelope -- the registry never raises past main.py's existing
per-file error handling, and never fabricates edges for a format whose
evidence tier does not support them.
"""

from __future__ import annotations

from pathlib import Path

from analysis.lock_graph import contract
from analysis.lock_graph import gradle as _gradle
from analysis.lock_graph import maven as _maven
from analysis.lock_graph import npm_adapter
from analysis.lock_graph import pipfile
from analysis.lock_graph import poetry as _poetry_extractor
from analysis.lock_graph import uv as _uv_extractor
from analysis.lock_graph import yarn as _yarn_extractor

ENGINE = "LOCK_GRAPH_REGISTRY_V1"


#: filename -> extractor. Keys are exact lockfile names as they appear on
#: disk (Pipfile.lock is conventionally case-sensitive; the others lowercase).
REGISTRY = {
    "package-lock.json": npm_adapter.extract,
    "poetry.lock": _poetry_extractor.extract,
    "uv.lock": _uv_extractor.extract,
    "Pipfile.lock": pipfile.extract,
    # R2.2 (Java): resolved-evidence files carry verified edges; manifest
    # files answer with disclosed UNSUPPORTED envelopes -- a pom or build
    # script is direct declarations, never a resolved graph.
    "dependency-tree.txt": _maven.extract,
    "pom.xml": _maven.extract_manifest,
    "gradle-dependencies.txt": _gradle.extract,
    "gradle.lockfile": _gradle.extract_lockfile,
    "build.gradle": _maven.extract_manifest,
    "settings.gradle": _maven.extract_manifest,
    # R2.3 (JavaScript): yarn v1 entries carry per-instance dependencies;
    # Berry lockfiles answer with disclosed UNSUPPORTED envelopes.
    "yarn.lock": _yarn_extractor.extract,
}

LOCKFILE_NAMES = frozenset(REGISTRY)


def extract_for_file(lockfile_path: str) -> dict:
    name = Path(lockfile_path).name
    extractor = REGISTRY.get(name)
    if extractor is None:
        return contract.extraction_result(
            engine=ENGINE,
            source=str(lockfile_path),
            format_version="unknown",
            graph_status=contract.UNSUPPORTED_FORMAT,
            edges=[],
            limitations=[
                f"No graph extractor registered for '{name}'; membership "
                "parsers may still classify the format, but no verified "
                "edges are fabricated.",
            ],
        )
    return extractor(lockfile_path)
