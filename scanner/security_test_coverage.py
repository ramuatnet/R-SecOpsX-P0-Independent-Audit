"""Feature 7 - Security Test Coverage Intelligence.

Conservative candidate-test evidence.
This module does not claim that a test executes a vulnerable sink.
"""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any
import os

_IGNORED_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "venv", ".venv",
    "env", ".env", "dist", "build", "target", "__pycache__",
    ".pytest_cache", ".mypy_cache", ".tox",
}


def _normalize_relative_path(path: Any) -> str:
    text = str(path or "").replace("\\", "/").strip()
    while text.startswith("./"):
        text = text[2:]
    return text


def _is_test(path: str) -> bool:
    p = _normalize_relative_path(path).lower()
    parts = [part for part in p.split("/") if part]
    if not parts:
        return False

    name = parts[-1]

    if "test" in parts or "tests" in parts:
        return True

    return (
        name.startswith("test_")
        or name.endswith("_test.py")
        or name.endswith("_test.js")
        or name.endswith("_test.ts")
        or name.endswith("_test.jsx")
        or name.endswith("_test.tsx")
        or ".test." in name
        or ".spec." in name
    )


def _ignored_relative_path(path: str) -> bool:
    parts = [
        part.lower()
        for part in _normalize_relative_path(path).split("/")
        if part
    ]
    return any(part in _IGNORED_DIRS for part in parts)


def _candidate_test_names(changed_path: str) -> set[str]:
    name = Path(_normalize_relative_path(changed_path)).name
    stem = Path(name).stem.lower()
    return {
        stem,
        f"{stem}_test",
        f"test_{stem}",
        f"{stem}.test",
        f"{stem}.spec",
    }


def _is_related_test(changed_path: str, test_path: str) -> bool:
    if not _is_test(test_path) or _ignored_relative_path(test_path):
        return False

    test_name = Path(_normalize_relative_path(test_path)).stem.lower()
    return test_name in _candidate_test_names(changed_path)


def _discover_test_paths(root: Path) -> list[str]:
    if not root.exists() or not root.is_dir():
        return []

    # T-0.2 (task.md): the one walk's index; _IGNORED_DIRS is walk policy
    # now. The rel-path filters below are engine semantics and stay.
    from core import file_index
    discovered: list[str] = []

    for candidate in file_index.index_for(root).files():
        rel = Path(os.path.relpath(candidate, root)).as_posix()
        if _ignored_relative_path(rel):
            continue
        if _is_test(rel):
            discovered.append(rel)

    return sorted(set(discovered))


def enrich_security_test_coverage(
    payload: dict[str, Any],
    project_root: str,
) -> dict[str, Any]:
    """Return conservative candidate-test evidence without mutating payload."""
    result = deepcopy(payload)

    change_intelligence = result.get("change_intelligence") or {}

    changed = sorted({
        _normalize_relative_path(item.get("path"))
        for item in (change_intelligence.get("files", []) or [])
        if isinstance(item, dict)
        and _normalize_relative_path(item.get("path"))
        and not _ignored_relative_path(item.get("path"))
    })

    root = Path(project_root)
    test_paths = _discover_test_paths(root)

    rows = []

    for path in changed:
        related = sorted(
            test_path
            for test_path in test_paths
            if _is_related_test(path, test_path)
        )

        rows.append({
            "changed_file": path,
            "candidate_test_files": related,
            "candidate_test_evidence": bool(related),
            "coverage_verified": False,
        })

    result["security_test_coverage"] = {
        "status": (
            "AVAILABLE"
            if change_intelligence.get("status") == "AVAILABLE"
            else "UNAVAILABLE"
        ),
        "changed_files": rows,
        "summary": {
            "changed_files": len(rows),
            "with_candidate_tests": sum(
                1
                for row in rows
                if row["candidate_test_evidence"]
            ),
            "test_files_discovered": len(test_paths),
        },
        "read_only": True,
        "execution_performed": False,
        "semantic_coverage_proven": False,
    }

    return result