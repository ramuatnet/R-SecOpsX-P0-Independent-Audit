"""pyproject.toml parser (PEP 621 / PEP 735 / poetry) -- PyPI ecosystem.

semantic-kernel ships 155 csproj + a PEP 621 python/pyproject.toml and autogen
ships 12 pyprojects; before this parser every declared dependency in them was
absent from the SBOM because only requirements*.txt, package.json and pom.xml
were read.

Version policy mirrors _resolve_pinned_version: only an exact ``==X.Y.Z`` pin
becomes a version. Ranges (``>=2.0,<3.0``, ``^1.2``, ``~2.0``) become
``unknown`` so the advisory query skips them rather than guessing -- the
lockfile parser (uv.lock / poetry.lock) then carries the resolved version and
the shared dedupe keeps one row.
"""
from __future__ import annotations

import logging
import re
from pathlib import Path

_LOG = logging.getLogger("rsx.scanner.manifests.pyproject_toml")

try:
    import tomllib
except ImportError:  # pragma: no cover - python < 3.11
    tomllib = None

# PEP 508 requirement name (before extras/specifier/marker).
_REQ_NAME = re.compile(r"^\s*([A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?)")
_EXACT_PIN = re.compile(r"==\s*([^\s;,\[\]]+)")


def _pinned_version(spec: str) -> str:
    """Exact ``==X.Y.Z`` pin, else ``unknown`` (range/loose/marker noise)."""
    raw = str(spec or "").strip()
    if not raw:
        return "unknown"
    m = _EXACT_PIN.search(raw)
    if m and "*" not in m.group(1):
        return m.group(1)
    return "unknown"


def _requirement_rows(entries, direct: bool, text: str, path: Path,
                      ecosystem: str = "PyPI") -> list[dict]:
    """One row per PEP 508 requirement string; local/VCS refs are skipped
    (same policy as the requirements.txt parser, which records them as
    local -- here they carry no registry identity to resolve)."""
    rows = []
    for entry in entries or []:
        if not isinstance(entry, str):
            continue  # inline-table include-group markers etc.
        name_m = _REQ_NAME.match(entry)
        if not name_m:
            continue
        name = name_m.group(1)
        rows.append({
            "name": name,
            "version": _pinned_version(entry),
            "ecosystem": ecosystem,
            "license": "unknown",
            "direct": direct,
            "manifest_file": path.name,
            "manifest_line": _find_line(text, name),
        })
    return rows


def _poetry_rows(table, direct: bool, text: str, path: Path) -> list[dict]:
    """Rows from a ``[tool.poetry.dependencies]``-style name -> spec table."""
    rows = []
    if not isinstance(table, dict):
        return rows
    for name, spec in table.items():
        name = str(name)
        if name.lower() == "python":
            continue
        if isinstance(spec, str):
            version, ecosystem = _pinned_version(spec), "PyPI"
        elif isinstance(spec, dict):
            if "path" in spec or "git" in spec or "url" in spec or "hg" in spec or "bzr" in spec:
                # Local/VCS dependency: no registry version to resolve.
                version, ecosystem = "unknown", "local"
            else:
                version = _pinned_version(str(spec.get("version") or ""))
                ecosystem = "PyPI"
        else:
            continue
        rows.append({
            "name": name,
            "version": version,
            "ecosystem": ecosystem,
            "license": "unknown",
            "direct": direct,
            "manifest_file": path.name,
            "manifest_line": _find_line(text, name),
        })
    return rows


def _find_line(text: str, name: str) -> int:
    """Best-effort 1-based line of the declaration; 1 when not locatable."""
    m = re.search(
        r'(?m)^[ \t]*["\']?' + re.escape(name) + r'["\']?[ \t]*[:=\]]',
        text,
    )
    return text[: m.start()].count("\n") + 1 if m else 1


def parse_pyproject_toml(filepath: str) -> list[dict]:
    """Parse pyproject.toml declared dependencies (direct) across the three
    convention families: PEP 621 ``[project]``, PEP 735
    ``[dependency-groups]`` (uv dev groups, transitive/dev) and poetry."""
    path = Path(filepath)
    if tomllib is None:
        return []
    try:
        text = path.read_text(encoding="utf-8-sig", errors="replace")
        data = tomllib.loads(text)
    except Exception as exc:  # malformed manifest must not abort the scan
        _LOG.debug("pyproject parse failed for %s: %s", filepath, exc)
        return []
    if not isinstance(data, dict):
        return []

    rows: list[dict] = []

    project = data.get("project") or {}
    if isinstance(project, dict):
        rows.extend(_requirement_rows(project.get("dependencies"), True, text, path))
        optional = project.get("optional-dependencies")
        if isinstance(optional, dict):
            for group_entries in optional.values():
                rows.extend(_requirement_rows(group_entries, True, text, path))

    # PEP 735 dependency groups (uv: [dependency-groups] dev = [...]).
    groups = data.get("dependency-groups")
    if isinstance(groups, dict):
        for group_entries in groups.values():
            rows.extend(_requirement_rows(group_entries, False, text, path))

    tool = data.get("tool") or {}
    if isinstance(tool, dict):
        poetry = tool.get("poetry") or {}
        if isinstance(poetry, dict):
            rows.extend(_poetry_rows(poetry.get("dependencies"), True, text, path))
            for gtable in (poetry.get("group") or {}).values():
                if isinstance(gtable, dict):
                    rows.extend(
                        _poetry_rows(gtable.get("dependencies"), False, text, path)
                    )
    return rows
