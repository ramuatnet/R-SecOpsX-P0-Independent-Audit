"""setup.py parser -- PyPI ecosystem.

transformers declares its runtime dependencies ONLY in setup.py
(``install_requires = [deps["huggingface-hub"], deps["numpy"], ...]`` with the
requirement strings living in a module-level ``_deps`` list) while its
pyproject.toml carries no ``[project]`` table -- so all 9 runtime packages
were invisible to the SBOM and only 32 components from other manifests
survived. setup.py was never read at all.

The file is AST-parsed only; it is NEVER imported or executed (setup.py may
run arbitrary code at build time).

Version policy mirrors _resolve_pinned_version: only an exact ``==X.Y.Z``
pin becomes a version. Ranges (``>=1.17``, ``<3.0``) become ``unknown`` so
the advisory query skips them rather than guessing -- the lockfile parser
then carries the resolved version and the shared dedupe keeps one row.
"""
from __future__ import annotations

import ast
import logging
import re
from pathlib import Path

from scanner.manifests.pyproject_toml import _REQ_NAME, _find_line, _pinned_version

_LOG = logging.getLogger("rsx.scanner.manifests.setup_py")


def _module_assignments(tree: ast.AST) -> dict[str, ast.AST]:
    """name -> RHS for every module-level ``name = ...`` (simple names only)."""
    out: dict[str, ast.AST] = {}
    for node in getattr(tree, "body", []):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    out.setdefault(target.id, node.value)
    return out


def _string_list_requirements(node: ast.AST) -> dict[str, str]:
    """name(lower) -> requirement string for a module-level list of literals
    (transformers' ``_deps = ["numpy>=1.17", ...]``)."""
    table: dict[str, str] = {}
    if not isinstance(node, (ast.List, ast.Tuple)):
        return table
    for elt in node.elts:
        value = elt.value if isinstance(elt, ast.Constant) else None
        if not isinstance(value, str):
            continue
        m = _REQ_NAME.match(value)
        if m:
            table.setdefault(m.group(1).lower(), value)
    return table


def _requirement_strings(
    node: ast.AST,
    assignments: dict[str, ast.AST],
    table: dict[str, str],
) -> list[str]:
    """Flatten one ``install_requires`` RHS into PEP 508 strings.

    Handles the three static conventions seen in the wild:
      * list literals:          ``["pkg>=1.0", "other==2.0"]``
      * subscript references:   ``[deps["numpy"], REQUIRED_PKGS...]`` where
        ``deps["numpy"]`` resolves through the collected table (bare name
        fallback keeps the package even when the table is inline)
      * name reference:         ``install_requires = REQUIRED_PKGS``
      * split strings:          a triple-quoted blob with ``.splitlines()``
    """
    if isinstance(node, ast.Name):
        node = assignments.get(node.id, node)
    if isinstance(node, ast.Call):
        # ``"...".splitlines()`` / ``"...".split(",")`` on a literal blob.
        func = node.func
        if (
            isinstance(func, ast.Attribute)
            and isinstance(func.value, ast.Constant)
            and isinstance(func.value.value, str)
            and func.attr in {"splitlines", "split", "splitlines_keepends"}
        ):
            blob = func.value.value
            return [seg.strip() for seg in re.split(r"[\n,]", blob) if seg.strip()]
        # ``list(required)`` -- resolve the referenced name.
        if node.args and isinstance(node.args[0], ast.Name):
            return _requirement_strings(node.args[0], assignments, table)
        return []
    if isinstance(node, (ast.List, ast.Tuple)):
        strings: list[str] = []
        for elt in node.elts:
            if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                strings.append(elt.value)
            elif (
                isinstance(elt, ast.Subscript)
                and isinstance(elt.value, ast.Name)
                and isinstance(elt.slice, ast.Constant)
                and isinstance(elt.slice.value, str)
            ):
                key = elt.slice.value.lower()
                strings.append(table.get(key, elt.slice.value))
            elif isinstance(elt, (ast.List, ast.Tuple)):
                strings.extend(_requirement_strings(elt, assignments, table))
        return strings
    return []


def parse_setup_py(filepath: str) -> list[dict]:
    """Declared ``install_requires`` packages from a static setup.py."""
    path = Path(filepath)
    try:
        text = path.read_text(encoding="utf-8-sig", errors="replace")
        tree = ast.parse(text)
    except Exception as exc:  # malformed setup.py must not abort the scan
        _LOG.debug("setup.py parse failed for %s: %s", filepath, exc)
        return []

    assignments = _module_assignments(tree)

    # Requirement strings reachable by ``deps["name"]`` subscripts: every
    # module-level list literal of strings contributes (first wins).
    table: dict[str, str] = {}
    for rhs in assignments.values():
        for key, value in _string_list_requirements(rhs).items():
            table.setdefault(key, value)

    # Collect install_requires from ``install_requires = ...`` assignments and
    # from ``setup(install_requires=...)`` calls; dedupe by name.
    collected: list[str] = []
    assigned = assignments.get("install_requires")
    if assigned is not None:
        collected.extend(_requirement_strings(assigned, assignments, table))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        callee = func.id if isinstance(func, ast.Name) else getattr(func, "attr", "")
        if callee != "setup":
            continue
        for kw in node.keywords:
            if kw.arg == "install_requires":
                collected.extend(_requirement_strings(kw.value, assignments, table))

    rows: list[dict] = []
    seen: set[str] = set()
    for spec in collected:
        m = _REQ_NAME.match(str(spec))
        if not m:
            continue
        name = m.group(1)
        key = name.lower()
        if key in seen:
            continue
        seen.add(key)
        rows.append({
            "name": name,
            "version": _pinned_version(spec),
            "ecosystem": "PyPI",
            "license": "unknown",
            "direct": True,
            "manifest_file": path.name,
            "manifest_line": _find_line(text, name),
        })
    return rows
