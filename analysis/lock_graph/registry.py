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
from analysis.lock_graph import npm_adapter
from analysis.lock_graph import pipfile

ENGINE = "LOCK_GRAPH_REGISTRY_V1"


def _poetry(lockfile_path: str) -> dict:
    # R2.1 commit 2 replaces this stub with the real Poetry extractor.
    return contract.extraction_result(
        engine="POETRY_LOCK_GRAPH_V1",
        source=str(lockfile_path),
        format_version="poetry.lock",
        graph_status=contract.UNSUPPORTED_FORMAT,
        edges=[],
        limitations=["Poetry verified-edge extractor not enabled yet"],
    )


def _uv(lockfile_path: str) -> dict:
    # R2.1 commit 3 replaces this stub with the real uv extractor.
    return contract.extraction_result(
        engine="UV_LOCK_GRAPH_V1",
        source=str(lockfile_path),
        format_version="uv.lock",
        graph_status=contract.UNSUPPORTED_FORMAT,
        edges=[],
        limitations=["uv verified-edge extractor not enabled yet"],
    )


#: filename -> extractor. Keys are exact lockfile names as they appear on
#: disk (Pipfile.lock is conventionally case-sensitive; the others lowercase).
REGISTRY = {
    "package-lock.json": npm_adapter.extract,
    "poetry.lock": _poetry,
    "uv.lock": _uv,
    "Pipfile.lock": pipfile.extract,
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
