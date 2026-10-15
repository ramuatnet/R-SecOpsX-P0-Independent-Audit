"""uv.lock parser (PyPI ecosystem).

uv.lock is TOML with ``[[package]]`` tables (``name``/``version``/``source``),
the same shape poetry.lock uses for its package array. Direct-vs-transitive is
carried by the pyproject.toml parser via generate_sbom's declared_direct merge;
every registry package here is stamped ``direct=False`` so a lockfile alone
never over-claims ownership.

The project's own workspace/editable packages are skipped: they are not
external dependencies (autogen has two uv.locks whose editable entries are the
autogen package tree itself).
"""
from __future__ import annotations

import logging
import re
from pathlib import Path

_LOG = logging.getLogger("rsx.scanner.manifests.uv_lock")

try:
    import tomllib
except ImportError:  # pragma: no cover - python < 3.11
    tomllib = None


def _find_line(text: str, name: str) -> int:
    m = re.search(
        r'(?m)^[ \t]*name[ \t]*=[ \t]*"' + re.escape(name) + r'"',
        text,
    )
    return text[: m.start()].count("\n") + 1 if m else 1


def parse_uv_lock(filepath: str) -> list[dict]:
    """Parse uv.lock and extract pinned package versions."""
    path = Path(filepath)
    if tomllib is None:
        return []
    try:
        text = path.read_text(encoding="utf-8-sig", errors="replace")
        data = tomllib.loads(text)
    except Exception as exc:  # malformed lock must not abort the scan
        _LOG.debug("uv.lock parse failed for %s: %s", filepath, exc)
        return []

    pkgs = []
    for pkg in (data.get("package") or []):
        if not isinstance(pkg, dict):
            continue
        name = str(pkg.get("name") or "")
        if not name:
            continue
        source = str(pkg.get("source") or "")
        if "editable" in source or "virtual" in source or "workspace" in source:
            continue  # the project itself, not an external dependency
        pkgs.append({
            "name": name,
            "version": str(pkg.get("version") or "unknown"),
            "ecosystem": "PyPI",
            "license": "unknown",
            "direct": False,
            "manifest_file": path.name,
            "manifest_line": _find_line(text, name),
        })
    return pkgs
