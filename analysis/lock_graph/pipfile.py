"""Pipfile.lock graph extraction: honest membership-only disclosure (R2.1).

Verified fact (R2.0 coverage matrix, GAP-R2-01): a Pipfile.lock records the
resolved default/develop package groups and their hashes -- it encodes NO
inter-package relationships. There is nothing in the format from which a
parent-child edge could be established, so this extractor fabricates nothing:

- edges: always empty;
- graph_status: UNSUPPORTED_FORMAT with the limitation disclosed;
- membership_packages: informational count of resolved group members.

Classification continues to flow through the existing membership parser
(`parse_pipfile_lock`, poetry_lock.py module) and the evidence gate -- that
path is untouched by this module.
"""

from __future__ import annotations

import json

from analysis.lock_graph.contract import (
    UNSUPPORTED_FORMAT,
    extraction_result,
)

ENGINE = "PIPFILE_LOCK_GRAPH_V1"

_LIMITATION = (
    "Pipfile.lock records resolved default/develop groups only and encodes "
    "no inter-package relationships; verified parent-child edges cannot be "
    "established from this format. Membership and group classification come "
    "from the manifest parser; nothing is inferred."
)


def extract(lockfile_path: str) -> dict:
    membership = 0
    try:
        data = json.loads(_read(lockfile_path))
        for group in ("default", "develop"):
            entries = data.get(group)
            if isinstance(entries, dict):
                membership += len(entries)
        return extraction_result(
            engine=ENGINE,
            source=str(lockfile_path),
            format_version=f"pipfile-lock (default+develop)",
            graph_status=UNSUPPORTED_FORMAT,
            edges=[],
            limitations=[_LIMITATION],
            membership_packages=membership,
        )
    except Exception as exc:
        return extraction_result(
            engine=ENGINE,
            source=str(lockfile_path),
            format_version="pipfile-lock",
            graph_status="EXTRACTION_ERROR",
            edges=[],
            limitations=[f"Pipfile.lock parse failed: {exc}"],
        )


def _read(lockfile_path: str) -> str:
    from pathlib import Path

    return Path(lockfile_path).read_text(encoding="utf-8", errors="replace")
