"""Function-level Python reachability (Phase 3.4).

Package-level reachability (``scanner/reachability.py``) answers "is
this dependency imported anywhere". This module answers the sharper
question for PYTHON FINDINGS: is the FUNCTION containing this finding
reachable from an entry point?

Entry points:

* **route handlers** — any function/method carrying a Flask/FastAPI/
  blueprint-style route decorator (``@app.route``, ``@router.get``,
  ``@bp.post``, ...);
* **top-level code** — a module executes on import, so calls made at
  module level are entry edges;
* **``__main__`` guards** — everything reached from
  ``if __name__ == "__main__":``;
* **test functions** — ``test_*`` / ``*_test`` (pytest collects by
  name).

Statuses attached to findings (a finding must be a ``.py`` file
resolvable inside the scanned root AND carry a line to anchor on):

* ``REACHABLE_FUNCTION`` — a call path from a labeled entry point exists;
* ``TOP_LEVEL_CODE`` — outside any function (module-level code runs on
  import);
* ``UNREACHABLE_FUNCTION`` — inside a function with NO path from any
  entry point (dead code);
* ``UNKNOWN`` — unparseable file, unresolvable path, or no line
  (reason recorded, never guessed).

Honesty properties:

* **Informational only — status never rewrites severity.** A static
  call graph cannot see dynamic dispatch (``getattr``, plugin
  registries, decorator-generated routes, import-time side effects),
  so an automatic demotion of an ``UNREACHABLE_FUNCTION`` finding would
  be a false-negative factory. The status informs triage; the human
  decides. The summary carries this as prose, not folklore.
* Cross-module edges resolve only explicit in-project imports
  (``from x import y``, ``import x`` + ``x.y(...)``); anything else
  stays UNREACHABLE with its evidence — never silently upgraded.
* Syntax errors are counted AND listed per file, never silently
  skipped; a file that cannot be parsed cannot support a reachability
  claim about any line in it.
* The caller's payload/findings are never mutated (deepcopy contract).
"""
from __future__ import annotations

import ast
import copy
from pathlib import Path
from typing import Any

# Attribute names on a decorator that mark a route handler. Kept as a
# closed set: guessing "this decorator is probably a route" would mint
# entry points out of unrelated fluent APIs.
_ROUTE_DECORATOR_ATTRS = {
    "route", "get", "post", "put", "delete", "patch", "head", "options",
}

_SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", "venv", ".venv", "env",
    "dist", "build", "target", ".tox", ".pytest_cache", "coverage",
    ".next", ".cache", "quarantine", "backup",
}

_METHOD_NOTE = "python_ast_call_graph"

_STATUS_NOTE = (
    "Informational only: function reachability never rewrites severity. "
    "A static call graph cannot see dynamic dispatch (getattr, plugin "
    "registries, decorator-generated routes), so UNREACHABLE_FUNCTION "
    "informs triage rather than demoting a finding."
)


# ---------------------------------------------------------------------------
# Graph construction.
# ---------------------------------------------------------------------------

def _dotted_name(node: ast.AST) -> str | None:
    """'self.handler', 'app.route', 'escape' — for decorators/attrs."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return None


def _decorator_labels(dec: ast.AST) -> list[str]:
    """Route-decorator labels for one decorator expression."""
    target = dec.func if isinstance(dec, ast.Call) else dec
    name = _dotted_name(target)
    if not name:
        return []
    attr = name.rsplit(".", 1)[-1]
    if attr in _ROUTE_DECORATOR_ATTRS:
        return [name]
    return []


def _is_test_name(name: str) -> bool:
    """pytest's default ``test_*`` prefix PLUS the ``*_test`` suffix (a
    configurable ``python_functions`` pattern some projects enable)."""
    return name.startswith("test_") or name.endswith("_test")


class _FileIndex:
    """One parsed file: functions, spans, calls, imports, entries."""

    def __init__(self, relpath: str):
        self.relpath = relpath
        # qualname -> dict(start, end, calls, module_calls...)
        self.functions: dict[str, dict[str, Any]] = {}
        # Calls made at module level (outside any function).
        self.top_calls: list[dict] = []
        self.main_calls: list[dict] = []
        # import alias -> {"kind": "from"}|{"kind":"module","path":...}
        self.imports: dict[str, dict] = {}

    # -- collection ---------------------------------------------------------

    def _call_targets(self, node: ast.AST) -> list[dict]:
        """One entry per call site in this statement subtree."""
        targets: list[dict] = []
        for sub in ast.walk(node):
            if not isinstance(sub, ast.Call):
                continue
            func = sub.func
            if isinstance(func, ast.Name):
                targets.append({"name": func.id, "receiver": None})
            elif isinstance(func, ast.Attribute):
                receiver = (func.value.id
                            if isinstance(func.value, ast.Name) else None)
                targets.append({"name": func.attr, "receiver": receiver})
        return targets

    def _single_call_target(self, call: ast.Call) -> dict | None:
        func = call.func
        if isinstance(func, ast.Name):
            return {"name": func.id, "receiver": None}
        if isinstance(func, ast.Attribute):
            receiver = (func.value.id
                        if isinstance(func.value, ast.Name) else None)
            return {"name": func.attr, "receiver": receiver}
        return None

    def _executed_calls(self, stmts: list) -> list[dict]:
        """Calls that execute when these statements run.

        Never descends into function/method/lambda bodies: DEFINING a
        function does not execute it. Counting a function's internal
        calls as module-level entry calls would make nearly every
        function 'reachable' and the whole analysis vacuous (caught by
        the smoke fixture: an internal call seeded as top_level_call).
        Decorators of skipped defs are skipped too — route handlers are
        seeded directly via their decorator label instead, so no entry
        point is lost.
        """
        calls: list[dict] = []

        def visit(node: ast.AST) -> None:
            for sub in ast.iter_child_nodes(node):
                if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef,
                                    ast.Lambda)):
                    continue
                if isinstance(sub, ast.Call):
                    target = self._single_call_target(sub)
                    if target:
                        calls.append(target)
                visit(sub)

        for stmt in stmts:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            visit(stmt)
        return calls

    def _module_level(self, tree: ast.Module, relpath: str) -> None:
        top_stmts = []
        for stmt in tree.body:
            if (isinstance(stmt, ast.If)
                    and isinstance(stmt.test, ast.Compare)
                    and isinstance(stmt.test.left, ast.Name)
                    and stmt.test.left.id == "__name__"):
                self.main_calls.extend(self._executed_calls(stmt.body))
                continue
            top_stmts.append(stmt)
        self.top_calls.extend(self._executed_calls(top_stmts))

        for stmt in tree.body:
            if isinstance(stmt, (ast.Import, ast.ImportFrom)):
                self._collect_import(stmt)

    def _collect_import(self, stmt: ast.AST) -> None:
        if isinstance(stmt, ast.Import):
            for alias in stmt.names:
                local = alias.asname or alias.name.split(".")[0]
                self.imports[local] = {
                    "kind": "module",
                    "path": alias.name,
                }
        elif isinstance(stmt, ast.ImportFrom):
            level = stmt.level or 0
            module = stmt.module or ""
            for alias in stmt.names:
                if alias.name == "*":
                    continue
                self.imports[alias.asname or alias.name] = {
                    "kind": "from",
                    "module": module,
                    "level": level,
                    "name": alias.name,
                }

    def _function(self, node: ast.AST, qualname: str) -> None:
        calls = self._call_targets(node)
        labels: list[str] = []
        for dec in node.decorator_list:
            labels.extend(_decorator_labels(dec))

        entry_labels = []
        if labels:
            entry_labels.append("route_decorator")
        if _is_test_name(node.name):
            entry_labels.append("test_function")

        self.functions[qualname] = {
            "start": node.lineno,
            "end": getattr(node, "end_lineno", node.lineno) or node.lineno,
            "calls": calls,
            "entry_labels": entry_labels,
        }


def _index_with_qualnames(source: str, relpath: str) -> _FileIndex:
    """Parse once; qualify methods with their class name."""
    tree = ast.parse(source)
    index = _FileIndex(relpath)

    def qualify(node: ast.AST, prefix: str) -> None:
        for stmt in node.body if isinstance(node, ast.Module) else []:
            if isinstance(stmt, ast.ClassDef):
                for sub in stmt.body:
                    if isinstance(sub, (ast.FunctionDef,
                                        ast.AsyncFunctionDef)):
                        index._function(sub, f"{stmt.name}.{sub.name}")
                    elif isinstance(sub, ast.ClassDef):
                        qualify(sub, f"{prefix}{stmt.name}.")
            elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                index._function(stmt, stmt.name)

    qualify(tree, "")
    index._module_level(tree, relpath)
    return index


def build_call_graph(project_root: str | Path) -> dict[str, Any]:
    """Parse every Python file under the root into per-file indexes."""
    root = Path(project_root)
    indexes: dict[str, _FileIndex] = {}
    syntax_errors: list[dict] = []
    parsed = 0

    for path in sorted(root.rglob("*.py")):
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        relpath = path.relative_to(root).as_posix()
        try:
            # utf-8-sig, not utf-8: Windows-authored files often carry a
            # BOM, and ast.parse rejects the U+FEFF codepoint outright —
            # with plain utf-8 every finding in a BOM'd file would go
            # silently UNKNOWN instead of being analyzed.
            source = path.read_text(encoding="utf-8-sig", errors="ignore")
        except OSError:
            continue
        try:
            index = _index_with_qualnames(source, relpath)
        except SyntaxError as exc:
            syntax_errors.append({
                "file": relpath,
                "error": f"SyntaxError: {exc.msg} (line {exc.lineno})",
            })
            continue
        indexes[relpath] = index
        parsed += 1

    return {
        "root": str(root),
        "indexes": indexes,
        "syntax_errors": syntax_errors,
        "parsed_files": parsed,
    }


# ---------------------------------------------------------------------------
# Edges + reachability.
# ---------------------------------------------------------------------------

def _resolve_module(root: Path, importer_relpath: str, module: str,
                    level: int) -> str | None:
    """Module path (posix, relative to root) -> its file, or None."""
    base = Path(importer_relpath).parent
    if level:
        for _ in range(level - 1):
            base = base.parent
        module_path = (base / Path(module.replace(".", "/"))
                       ) if module else base
    else:
        module_path = Path(module.replace(".", "/"))

    posix = module_path.as_posix()
    for candidate in (f"{posix}.py", f"{posix}/__init__.py"):
        if (root / candidate).is_file():
            return candidate
    return None


def _edges(graph: dict[str, Any]) -> dict[tuple[str, str], set[tuple[str, str]]]:
    """(file, qualname) -> callee set, resolved within the project."""
    root = Path(graph["root"])
    indexes: dict[str, _FileIndex] = graph["indexes"]
    edges: dict[tuple[str, str], set[tuple[str, str]]] = {}

    def same_file_candidates(index: _FileIndex, target: dict) -> set[tuple[str, str]]:
        name = target["name"]
        found: set[tuple[str, str]] = set()
        for qualname in index.functions:
            bare = qualname.rsplit(".", 1)[-1]
            if bare == name:
                found.add((index.relpath, qualname))
        return found

    def cross_file_candidates(index: _FileIndex, target: dict) -> set[tuple[str, str]]:
        name = target["name"]
        receiver = target.get("receiver")
        found: set[tuple[str, str]] = set()

        if receiver is None:
            # from x import y ; y(...)
            info = index.imports.get(name)
            if info and info.get("kind") == "from":
                module_file = _resolve_module(
                    root, index.relpath, info.get("module", ""),
                    info.get("level", 0))
                # An unresolvable module resolves to nothing: no guessing
                # (same-file name matches are already covered by
                # same_file_candidates for every call).
                if module_file:
                    callee = indexes.get(module_file)
                    if callee and info.get("name") in callee.functions:
                        found.add((module_file, info["name"]))
            return found

        # alias.attr(...) where alias is an imported module.
        info = index.imports.get(receiver)
        if info and info.get("kind") == "module":
            module_file = _resolve_module(
                root, index.relpath, info.get("path", ""), 0)
            if module_file:
                callee = indexes.get(module_file)
                if callee and name in callee.functions:
                    found.add((module_file, name))
        return found

    for relpath, index in indexes.items():
        for qualname, meta in index.functions.items():
            resolved: set[tuple[str, str]] = set()
            for target in meta["calls"]:
                resolved |= same_file_candidates(index, target)
                resolved |= cross_file_candidates(index, target)
            resolved.discard((relpath, qualname))  # no self-edges
            edges[(relpath, qualname)] = resolved

    return edges


def _seed_entries(graph: dict[str, Any]) -> list[tuple[tuple[str, str], str]]:
    """Ordered (node, label) seeds: decorators seed their own function;
    module-level and __main__ calls seed their resolved callees."""
    indexes: dict[str, _FileIndex] = graph["indexes"]
    seeds: list[tuple[tuple[str, str], str]] = []
    for relpath in sorted(indexes):
        index = indexes[relpath]
        for qualname in sorted(index.functions):
            for label in index.functions[qualname]["entry_labels"]:
                seeds.append(((relpath, qualname), label))
        for label, calls in (("top_level_call", index.top_calls),
                             ("__main__", index.main_calls)):
            for target in calls:
                for callee in _seed_callees(index, target, indexes, graph):
                    seeds.append((callee, label))
    return seeds


def compute_reachable(graph: dict[str, Any]) -> dict[tuple[str, str], str]:
    """BFS from every entry point; value = the entry label that reached it."""
    edges = _edges(graph)

    # Deterministic BFS: seeds enter the queue in sorted order, and each
    # node keeps the FIRST label that reached it.
    reachable: dict[tuple[str, str], str] = {}
    queue: list[tuple[str, str]] = []
    for node, label in _seed_entries(graph):
        if node not in reachable:
            reachable[node] = label
            queue.append(node)

    cursor = 0
    while cursor < len(queue):
        node = queue[cursor]
        cursor += 1
        for callee in sorted(edges.get(node, ())):
            if callee not in reachable:
                reachable[callee] = reachable[node]
                queue.append(callee)

    return reachable


def _seed_callees(index: _FileIndex, target: dict,
                  indexes: dict[str, _FileIndex],
                  graph: dict[str, Any]) -> set[tuple[str, str]]:
    """Resolve one module-level call target to in-project functions."""
    root = Path(graph["root"])
    name = target["name"]
    receiver = target.get("receiver")
    found: set[tuple[str, str]] = set()

    for qualname in index.functions:
        if qualname.rsplit(".", 1)[-1] == name:
            found.add((index.relpath, qualname))

    if receiver is None:
        info = index.imports.get(name)
        if info and info.get("kind") == "from":
            module_file = _resolve_module(
                root, index.relpath, info.get("module", ""),
                info.get("level", 0))
            if module_file:
                callee = indexes.get(module_file)
                if callee and info.get("name") in callee.functions:
                    found.add((module_file, info["name"]))
    else:
        info = index.imports.get(receiver)
        if info and info.get("kind") == "module":
            module_file = _resolve_module(
                root, index.relpath, info.get("path", ""), 0)
            if module_file:
                callee = indexes.get(module_file)
                if callee and name in callee.functions:
                    found.add((module_file, name))
    return found


# ---------------------------------------------------------------------------
# Finding annotation.
# ---------------------------------------------------------------------------

def _finding_file(finding: dict[str, Any]) -> str:
    return str(finding.get("file") or finding.get("path") or "")


def _resolve_finding_file(root: Path, rel: str) -> str | None:
    """The finding's file as a root-relative posix path, if it exists."""
    candidate = Path(str(rel).replace("\\", "/"))
    if candidate.is_absolute():
        # Checked FIRST: pathlib's root / <absolute> discards the root and
        # would return the absolute path itself, leaking it through as a
        # bogus "relative" key that never matches the graph.
        try:
            if not candidate.is_file():
                return None
            return candidate.resolve().relative_to(root.resolve()).as_posix()
        except (ValueError, OSError):
            return None
    if (root / candidate).is_file():
        return candidate.as_posix()
    return None


def annotate_findings_reachability(payload: dict[str, Any],
                                   project_root: str | Path | None,
                                   *,
                                   findings_key: str = "findings",
                                   ) -> dict[str, Any]:
    """Attach function_reachability to Python findings; never mutates."""
    working = copy.deepcopy(payload)
    findings = [
        f for f in (working.get(findings_key) or []) if isinstance(f, dict)
    ]

    summary: dict[str, Any] = {
        "method": _METHOD_NOTE,
        "analyzed_files": 0,
        "parsed_files": 0,
        "syntax_errors": [],
        "functions": 0,
        "entry_points": {},
        "reachable_functions": 0,
        "findings_annotated": 0,
        "status_counts": {},
        "non_python_skipped": 0,
        "unresolved_files": 0,
        "missing_line": 0,
        "note": _STATUS_NOTE,
    }

    root = Path(project_root) if project_root else None
    if root is None or not root.is_dir():
        summary["status"] = "skipped"
        summary["reason"] = "target_directory_not_available"
        working["python_function_reachability"] = summary
        return working

    graph = build_call_graph(root)
    indexes = graph["indexes"]
    reachable = compute_reachable(graph)

    summary["status"] = "available"
    summary["analyzed_files"] = len(indexes)
    summary["parsed_files"] = graph["parsed_files"]
    summary["syntax_errors"] = graph["syntax_errors"]
    summary["functions"] = sum(len(ix.functions) for ix in indexes.values())
    # Distinct (node, label) seeds per label: a function called twice at
    # module level is ONE top-level entry, not two.
    seed_pairs = {(node, label) for node, label in _seed_entries(graph)}
    seed_counts: dict[str, int] = {}
    for _node, label in sorted(seed_pairs):
        seed_counts[label] = seed_counts.get(label, 0) + 1
    summary["entry_points"] = seed_counts
    summary["reachable_functions"] = len(reachable)

    status_counts: dict[str, int] = {}

    for finding in findings:
        rel = _finding_file(finding)
        if not rel.lower().endswith(".py"):
            summary["non_python_skipped"] += 1
            continue

        file_key = _resolve_finding_file(root, rel)
        if file_key is None:
            summary["unresolved_files"] += 1
            finding["function_reachability"] = {
                "status": "UNKNOWN",
                "reason": "file_not_in_project",
            }
            status_counts["UNKNOWN"] = status_counts.get("UNKNOWN", 0) + 1
            summary["findings_annotated"] += 1
            continue
        if file_key not in indexes:
            # The file exists but was not parsed (syntax error) — a file
            # that cannot be parsed cannot support any reachability claim
            # about a line in it; see summary["syntax_errors"].
            finding["function_reachability"] = {
                "status": "UNKNOWN",
                "reason": "file_failed_to_parse",
            }
            status_counts["UNKNOWN"] = status_counts.get("UNKNOWN", 0) + 1
            summary["findings_annotated"] += 1
            continue

        try:
            line = int(finding.get("line") or 0)
        except (TypeError, ValueError):
            line = 0
        if line <= 0:
            summary["missing_line"] += 1
            finding["function_reachability"] = {
                "status": "UNKNOWN",
                "reason": "finding_carries_no_line",
            }
            status_counts["UNKNOWN"] = status_counts.get("UNKNOWN", 0) + 1
            summary["findings_annotated"] += 1
            continue

        index = indexes[file_key]
        enclosing = _innermost_function(index, line)

        if enclosing is None:
            status = "TOP_LEVEL_CODE"
            entry: dict[str, Any] = {
                "status": status,
                "function": None,
                "detail": "module-level code executes on import",
            }
        else:
            node = (file_key, enclosing)
            if node in reachable:
                status = "REACHABLE_FUNCTION"
                entry = {
                    "status": status,
                    "function": enclosing,
                    "entry_point": reachable[node],
                }
            else:
                status = "UNREACHABLE_FUNCTION"
                entry = {
                    "status": status,
                    "function": enclosing,
                    "detail": ("no call path from any route handler, "
                               "top-level call, __main__ guard or test"),
                }

        finding["function_reachability"] = entry
        status_counts[status] = status_counts.get(status, 0) + 1
        summary["findings_annotated"] += 1

    summary["status_counts"] = status_counts
    working["python_function_reachability"] = summary
    return working


def _innermost_function(index: _FileIndex, line: int) -> str | None:
    """The function whose span contains the line, innermost wins."""
    best: tuple[int, str] | None = None
    for qualname, meta in index.functions.items():
        if meta["start"] <= line <= meta["end"]:
            span = meta["end"] - meta["start"]
            if best is None or span < best[0]:
                best = (span, qualname)
    return best[1] if best else None
