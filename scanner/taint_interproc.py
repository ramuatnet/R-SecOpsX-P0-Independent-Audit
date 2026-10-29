"""T-2.1 + T-2.2: summary-based interprocedural taint post-pass.

The worker pool analyzes one file at a time (``_python_ast_findings``), so a
value that crosses a module boundary -- route handler -> dao/model -- is
invisible: the caller's local is tainted, the callee's parameter is not, and
the sink lives in the callee.  Both T-2.2 measured targets are exactly this
shape (dvpwa ``sidi/dao/student.py::create()``, VAmPI
``models/user_model.py::get_user()``): H1 reported the build site and the
real SQL sink stayed dark.

This pass runs once per ``scan_directory`` (after the worker pool and the
J5 block) and closes the boundary in three steps:

  1. index    -- every scanned ``.py`` file: class-qualified def paths,
                 formal params, and import bindings (static AST walk,
                 sorted iteration, disclosed caps).
  2. harvest  -- one two-pass ``TaintVisitor`` run per file that imports
                 from this project (source-driven; decorator + OpenAPI
                 route params seeded): every cross-file call whose argument
                 is tainted with *network* provenance becomes an edge
                 (caller local -> callee parameter).  A5/G-035 extended
                 across files: ``sys.argv``/``input()`` edges are refused
                 exactly as the intra-procedural ``_seed_callee`` refuses
                 them, because the measured runner FNs came from letting
                 those cross a call.
  3. worklist -- per-function summaries (a throwaway visitor seeds every
                 parameter with a ``__param__`` marker) feed a fixed point
                 over (module, function, param): param -> cross-file call
                 -> next param, iterated to stability.  The state set is
                 finite and rounds are sorted, so recursion and mutual
                 recursion terminate on the first revisit.

Files that own a seeded parameter are then re-analyzed with the seeds
applied.  Rows whose taint chain carries the ``__param__`` marker are
appended (H1's ownership rule -- "tainted flows stay at the sink" -- keeps
the finding at the SQL sink), and an H1 build-site row the seeded run no
longer emits is dropped through ``filter_trace``, never silently.

Deliberate v1 limits, disclosed here and in the commit body:

  * Return-value propagation across a call is NOT implemented (G-013 (a)):
    ``x = other_module.fn(...)`` where fn's return carries a seeded param
    stays untracked; only argument bindings cross files.
  * Same-file calls remain the existing ``_seed_callee``'s job; edges are
    cross-file only.  ``petgraph`` is not adopted -- the offline
    no-required-deps invariant outranks a graph library, and the whole
    "call graph" here is a dict of tuples.
  * The pass runs at ``scan_directory`` only: ``scan_file`` stays
    intra-procedural.
  * OpenAPI (connexion) path/query parameters are discovered from spec
    files under the scan target and seeded inside THIS pass only; the
    worker's intra-procedural findings for connexion handlers are
    unchanged, and same-file rows only such a seed could produce are not
    appended (the marker filter).  A worker-side source integration is
    future work.
  * aiohttp's ``request.match_info`` path parameters are deliberately NOT
    added to TAINT_SOURCES; only ``request.post`` (the measured T-2.2
    payload path) is.
  * ``add_route``-style registration (aiohttp) is not parsed: a handler's
    path parameters are invisible to the route map, and only sources the
    visitor already understands (``await request.post()``) taint its body.
  * Caps (MAX_PY_FILES / MAX_CANDIDATE_FILES / MAX_SUMMARIES /
    MAX_SPECS): sorted iteration makes truncation deterministic, and a hit
    logs at debug level -- fail-open like the J5 layer.
"""
from __future__ import annotations

import ast
import json
import logging
from pathlib import Path
from typing import Callable, Optional

from core import file_index, filter_trace
from scanner.taint_engine import (
    TaintedVar,
    TaintVisitor,
    _formal_params,
    _function_map,
    _network_source,
    _network_taint,
    _route_handler_names,
    _route_param_map,
    _ROUTE_PARAM_RE,
    _taint_dicts,
)

_LOG = logging.getLogger(__name__)

#: Prefix every cross-file parameter seed carries in its taint chain.  The
#: reporting step keeps only rows whose chain contains one of these, which
#: is what separates interprocedural rows from the worker pool's output.
_MARKER = "__param__:"

#: filter_trace pass name for H1 build-site rows the seeded run owns.
_DROP_PASS = "interproc_taint_ownership"

#: H1's rule id: the build-site interpolation row whose ownership migrates
#: to the sink once the interprocedural chain reaches it.
_H1_RULE = "PY_SQL_INTERPOLATED_QUERY"

# Disclosed caps.  Sorted iteration makes hitting one deterministic; the
# scan still succeeds (fail-open) and records why at debug level.
MAX_PY_FILES = 4000
MAX_CANDIDATE_FILES = 2000
MAX_SUMMARIES = 1000
MAX_SPECS = 100

_HTTP_METHODS = frozenset({
    "get", "put", "post", "delete", "patch", "head", "options", "trace",
})

#: Seed state key: (module file key, class-qualified funcpath, param name).
_SeedKey = tuple[str, str, str]


# ---------------------------------------------------------------------------
# project index
# ---------------------------------------------------------------------------
class _Mod:
    """One scanned .py file, statically indexed."""

    __slots__ = ("path", "key", "funcs", "imports")

    def __init__(self, path: Path, key: str):
        self.path = path
        self.key = key                      # dotted, no .py, no /__init__
        # funcpath -> (def node, full formal params).  Class-qualified
        # (``Student.create``) so an attribute call resolves exactly.
        self.funcs: dict[str, tuple[ast.AST, list[str]]] = {}
        # local name -> (level, module-or-None, symbol-or-None), mirroring
        # TaintVisitor's import semantics (no-asname `import a.b` binds `a`).
        self.imports: dict[str, tuple[int, Optional[str], Optional[str]]] = {}


def _dotted_key(path: Path, target: Path) -> Optional[str]:
    try:
        rel = Path(path).resolve().relative_to(Path(target).resolve()).as_posix()
    except ValueError:
        return None
    if not rel.endswith(".py"):
        return None
    rel = rel[:-3]
    if rel.endswith("/__init__"):
        rel = rel[: -len("/__init__")]
    if not rel:
        return None  # top-level __init__.py belongs to no importable package
    return rel.replace("/", ".")


def _collect_funcs(node: ast.AST, prefix: str,
                   out: dict[str, tuple[ast.AST, list[str]]]) -> None:
    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
            key = prefix + child.name
            if key not in out:
                out[key] = (child, _formal_params(child))
            # Nested defs keep the same prefix: a function-local def is not
            # reachable as ``Class.nested`` at any call site, and the
            # unique-bare-name fallback in the resolver covers it.
            _collect_funcs(child, prefix, out)
        elif isinstance(child, ast.ClassDef):
            _collect_funcs(child, prefix + child.name + ".", out)
        else:
            _collect_funcs(child, prefix, out)


def _collect_imports(tree: ast.AST,
                     out: dict[str, tuple[int, Optional[str], Optional[str]]]
                     ) -> None:
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                local = alias.asname or alias.name.split(".")[0]
                mod = alias.name if alias.asname else alias.name.split(".")[0]
                out[local] = (0, mod, None)
        elif isinstance(node, ast.ImportFrom):
            if node.module is None and node.level == 0:
                continue
            for alias in node.names:
                if alias.name == "*":
                    continue  # star imports are unknowable, as in the engine
                local = alias.asname or alias.name
                out[local] = (node.level, node.module or "", alias.name)


def _build_index(target: Path, py_files: list[Path]) -> dict[str, _Mod]:
    index: dict[str, _Mod] = {}
    for path in py_files:
        key = _dotted_key(path, target)
        if key is None or key in index:
            continue  # first sorted path wins: deterministic on collision
        try:
            source = file_index.read_source(path)
        except OSError:
            continue
        if source is None:
            continue
        try:
            tree = ast.parse(source)
        except SyntaxError:
            continue
        mod = _Mod(path, key)
        _collect_funcs(tree, "", mod.funcs)
        _collect_imports(tree, mod.imports)
        index[key] = mod
    return index


# ---------------------------------------------------------------------------
# call resolution
# ---------------------------------------------------------------------------
def _resolve_module(level: int, modstr: Optional[str],
                    caller_key: str) -> Optional[str]:
    pkg = caller_key.rsplit(".", 1)[0] if "." in caller_key else ""
    if level == 0:
        return modstr or None
    segs = pkg.split(".") if pkg else []
    if level - 1 > len(segs):
        return None
    base = ".".join(segs[: len(segs) - (level - 1)])
    if modstr:
        return f"{base}.{modstr}" if base else modstr
    return base or None


class _Resolver:
    """Attribute/Name call target -> (file key, funcpath, params) | None."""

    def __init__(self, index: dict[str, _Mod], caller: _Mod):
        self._index = index
        self._caller = caller

    def __call__(self, func_node: ast.AST):
        parts: list[str] = []
        cur = func_node
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if not isinstance(cur, ast.Name):
            return None
        parts.append(cur.id)
        parts.reverse()
        head, rest = parts[0], parts[1:]
        imp = self._caller.imports.get(head)
        if imp is None:
            # Local/unresolved name: the intra-procedural engine owns it.
            return None
        level, modstr, symbol = imp
        base = _resolve_module(level, modstr, self._caller.key)
        if base is None:
            return None
        dotted_base = f"{base}.{symbol}" if symbol else base
        # Segment-wise so the longest-prefix scan can land on a FILE key:
        # ``from pkg.dao.student import Student`` yields the dotted base
        # ``pkg.dao.student.Student``, whose first three segments are the
        # file and whose fourth is the class the remainder walks into.
        segs = dotted_base.split(".") + rest
        # Longest file prefix wins; if that file does not contain the
        # remainder as a def path, fall back to shorter prefixes.
        for cut in range(len(segs) - 1, 0, -1):
            file_dot = ".".join(segs[:cut])
            mod = self._index.get(file_dot)
            if mod is None:
                continue
            funcpath = ".".join(segs[cut:])
            if not funcpath:
                continue
            entry = mod.funcs.get(funcpath)
            if entry is None:
                # Class-vs-module ambiguity: a unique bare name still
                # identifies the def (first-def-wins, like _function_map).
                bare = segs[-1]
                hits = [k for k in mod.funcs if k.rsplit(".", 1)[-1] == bare]
                if len(hits) == 1:
                    funcpath = hits[0]
                    entry = mod.funcs[funcpath]
            if entry is not None:
                return mod.key, funcpath, entry[1]
        return None


def _touches_project(mod: _Mod, top_levels: frozenset) -> bool:
    for level, modstr, _symbol in mod.imports.values():
        if level > 0:
            return True  # relative import: project-internal by construction
        head = (modstr or "").split(".")[0]
        if head and head in top_levels:
            return True
    return False


# ---------------------------------------------------------------------------
# openapi (connexion) route parameters
# ---------------------------------------------------------------------------
def _load_spec(text: str, is_json: bool):
    if is_json:
        return json.loads(text)
    try:
        import yaml  # type: ignore
        return yaml.safe_load(text)
    except ImportError:
        from core import mini_yaml
        return mini_yaml.loads(text)


def _openapi_route_params(target: Path,
                          index: dict[str, _Mod]
                          ) -> dict[str, dict[str, set[str]]]:
    """Scan target -> {file key: {func path: {param, ...}}}.

    A connexion operationId *is* the python dotted path to the handler, and
    the path template is what binds ``{username}`` -- the same attacker-
    input fact a Flask decorator declares, discovered where connexion keeps
    it.  Query parameters declared ``in: query`` count too; a ``$ref``'d
    parameter carries no name inline, so query $refs are skipped (path
    parameters still come from the template itself).
    """
    out: dict[str, dict[str, set[str]]] = {}
    try:
        specs = file_index.index_for(target).files(
            exts={".yml", ".yaml", ".json"})
    except Exception as exc:  # fail-open: no spec, no seed, scan continues
        _LOG.debug("interproc openapi discovery unavailable: %s", exc)
        return out
    for path in sorted(specs, key=str)[:MAX_SPECS]:
        try:
            source = file_index.read_source(path)
        except OSError:
            continue
        if not source or "operationId" not in source:
            continue
        try:
            data = _load_spec(source, path.suffix.lower() == ".json")
        except Exception as exc:
            _LOG.debug("interproc openapi spec unreadable (%s): %s",
                       path.name, exc)
            continue
        if not isinstance(data, dict) or not isinstance(data.get("paths"),
                                                         dict):
            continue
        for route, item in data["paths"].items():
            if not isinstance(item, dict):
                continue
            tmpl_params = {
                (m.group(1) or m.group(2).rsplit(":", 1)[-1])
                for m in _ROUTE_PARAM_RE.finditer(str(route))
            }
            path_level = [
                p for p in (item.get("parameters") or [])
                if isinstance(p, dict)
            ]
            for method, op in item.items():
                if method not in _HTTP_METHODS or not isinstance(op, dict):
                    continue
                opid = op.get("operationId")
                if not isinstance(opid, str) or "." not in opid:
                    continue
                params = set(tmpl_params)
                declared = path_level + [
                    p for p in (op.get("parameters") or [])
                    if isinstance(p, dict)
                ]
                for p in declared:
                    if p.get("in") in ("path", "query") and isinstance(
                            p.get("name"), str):
                        params.add(p["name"])
                if not params:
                    continue
                _record_operation(out, index, opid, params)
    return out


def _record_operation(out: dict[str, dict[str, set[str]]],
                      index: dict[str, _Mod], opid: str,
                      params: set[str]) -> None:
    segs = opid.split(".")
    # Longest prefix of the dotted operationId that is a scanned file key;
    # the remainder is the (possibly class-qualified) function path.  The
    # prefix must actually be an indexed file, so an over-long operationId
    # falls back to a shorter cut instead of dead-ending on a phantom key.
    for cut in range(len(segs) - 1, 0, -1):
        file_dot = ".".join(segs[:cut])
        func = ".".join(segs[cut:])
        if not func or file_dot not in index:
            continue
        out.setdefault(file_dot, {}).setdefault(func, set()).update(params)
        return


def _route_overlay(tree: ast.AST, file_key: str,
                   openapi: dict[str, dict[str, set[str]]]
                   ) -> dict[str, set[str]]:
    route = _route_param_map(tree)
    for fn, params in (openapi.get(file_key) or {}).items():
        route.setdefault(fn, set()).update(params)
    return route


# ---------------------------------------------------------------------------
# edge-harvesting visitor + two-pass runner
# ---------------------------------------------------------------------------
def _marker_of(tv: Optional[TaintedVar]) -> Optional[str]:
    if tv is None:
        return None
    for elem in (tv.source, *(tv.chain or ())):
        if isinstance(elem, str) and elem.startswith(_MARKER):
            return elem
    return None


def _parse_marker(marker: str):
    """``__param__:{file}#{funcpath}.{param}`` -> (file, funcpath, param)."""
    payload = marker[len(_MARKER):]
    file_dot, sep, rest = payload.partition("#")
    if not sep:
        return None
    funcpath, dot, param = rest.rpartition(".")
    if not file_dot or not dot or not funcpath or not param:
        return None
    return file_dot, funcpath, param


def _seed_tv(param: str, tfile: str, tfunc: str, prov: TaintedVar,
             lineno: int) -> TaintedVar:
    """Build the callee-side seed from caller-side provenance.

    The chain keeps every hop the value already took (including any
    ``__param__`` marker it crossed earlier) and appends this crossing's
    own marker, so reporting can both filter on markers and attribute an
    H1 build-site drop to the function that owns the sink.
    """
    own = f"{_MARKER}{tfile}#{tfunc}.{param}"
    tail = [e for e in prov.full_chain()[1:] if e != ""]
    return TaintedVar(param, prov.source, lineno or prov.lineno,
                      tail + [own], prov.sanitized_for)


class _EdgeVisitor(TaintVisitor):
    """TaintVisitor that records cross-file call edges as it walks.

    ``_edge_cb(kind, origin, target, provenance, lineno)`` is installed per
    run:

      * kind ``"seed"`` (initial harvest): the caller argument carried
        source/route taint; provenance is the caller's chain and the edge
        seeds the callee parameter directly.
      * kind ``"call"`` (summary extraction): the argument carries a
        ``__param__`` marker; origin is the seeded parameter being expanded
        and provenance is ignored -- the applicator rebuilds it from the
        live seed state so chains stay source-rooted.
    """

    _resolver: Optional["_Resolver"] = None
    _caller_key: str = ""
    _edge_cb: Optional[Callable] = None

    def visit_Call(self, node: ast.Call):
        if self._edge_cb is not None:
            try:
                self._harvest_edges(node, self._edge_cb)
            except Exception as exc:  # one bad shape must not kill the pass
                _LOG.debug("interproc edge harvest failed: %s", exc)
        super().visit_Call(node)

    def _harvest_edges(self, node: ast.Call, cb: Callable) -> None:
        if self._resolver is None:
            return
        resolved = self._resolver(node.func)
        if resolved is None:
            return
        tfile, tfunc, params = resolved
        if tfile == self._caller_key:
            return  # same-file calls stay with the intra _seed_callee
        # Argument->parameter pairing mirrors _seed_callee's zip so a
        # vararg/kwonly quirk behaves identically on both sides.
        pairs = list(zip(params, node.args))
        pairs += [(kw.arg, kw.value) for kw in node.keywords
                  if kw.arg is not None and kw.arg in params]
        for param, arg in pairs:
            prov = self._arg_provenance(arg)
            if prov is None:
                continue
            marker = _marker_of(prov)
            lineno = getattr(arg, "lineno", 0) or 0
            if marker is not None:
                parsed = _parse_marker(marker)
                if parsed is None:
                    continue
                cb("call", parsed, (tfile, tfunc, param), prov, lineno)
            else:
                cb("seed", None, (tfile, tfunc, param), prov, lineno)

    def _arg_provenance(self, arg: ast.AST) -> Optional[TaintedVar]:
        # Mirrors _seed_callee._source_of: tainted names first (chain
        # preserved), then a direct source expression.  Network provenance
        # only -- A5/G-035 extended across files.
        names = self._tainted_names_in(arg)
        if names:
            parent = self._lookup(names[0])
            if parent is not None and _network_taint(parent):
                return TaintedVar(names[0], parent.source,
                                  getattr(arg, "lineno", 0) or 0,
                                  parent.full_chain()[1:],
                                  parent.sanitized_for)
        srcs = self._source_exprs_in(arg)
        if srcs and _network_source(srcs[0]):
            return TaintedVar("", srcs[0], getattr(arg, "lineno", 0) or 0,
                              [], frozenset())
        return None


def _run_two_pass(source: str, filepath: str, file_key: str,
                  openapi: dict[str, dict[str, set[str]]],
                  interproc_seeds: Optional[dict[int, dict[str, TaintedVar]]]
                  = None,
                  resolver: Optional[_Resolver] = None,
                  edge_cb: Optional[Callable] = None) -> _EdgeVisitor:
    """The worker's exact two-pass construction, plus seeds/edge harvest."""
    tree = ast.parse(source)
    lines = source.splitlines()
    route = _route_overlay(tree, file_key, openapi)
    funcs = _function_map(tree)
    handlers = _route_handler_names(tree)
    # Pre-pass carries the same seeds: a function that RETURNS a seeded
    # parameter must publish that into _tainted_returns for call sites the
    # reporting pass has not reached yet (the forward-reference case the
    # two-pass structure exists for).
    pre = TaintVisitor(lines, filepath, route, funcs, handlers)
    if interproc_seeds:
        pre._interproc_seeds = interproc_seeds
    pre.visit(tree)
    visitor = _EdgeVisitor(lines, filepath, route, funcs, handlers)
    visitor._tainted_returns = dict(pre._tainted_returns)
    if interproc_seeds:
        visitor._interproc_seeds = interproc_seeds
    if resolver is not None:
        visitor._resolver = resolver
        visitor._caller_key = resolver._caller.key
    visitor._edge_cb = edge_cb
    visitor.visit(tree)
    return visitor


def _has_marker(chain) -> bool:
    if isinstance(chain, str):
        return _MARKER in chain
    if isinstance(chain, (list, tuple)):
        return any(_MARKER in e for e in chain if isinstance(e, str))
    return False


# ---------------------------------------------------------------------------
# the post-pass
# ---------------------------------------------------------------------------
def apply_interproc_taint(target, all_files, findings) -> None:
    """Mutate ``findings``: append marker rows, drop H1 rows they own.

    Called from ``scan_directory`` after the worker pool and the J5 block,
    before model-artifact analysis.  Fail-open: any unexpected error here
    is logged by the caller's guard and leaves the scan's other findings
    exactly as the engines produced them.
    """
    target = Path(target)
    py_files = sorted(
        {Path(f) for f in all_files if str(f).endswith(".py")},
        key=str)[:MAX_PY_FILES]
    if len(py_files) > MAX_PY_FILES:
        _LOG.debug("interproc: py file cap %d reached", MAX_PY_FILES)
    if not py_files:
        return
    index = _build_index(target, py_files)
    if not index:
        return
    top_levels = frozenset(k.split(".", 1)[0] for k in index)
    candidates = [index[k] for k in sorted(index)
                  if _touches_project(index[k], top_levels)]
    if len(candidates) > MAX_CANDIDATE_FILES:
        _LOG.debug("interproc: candidate file cap %d reached",
                   MAX_CANDIDATE_FILES)
        candidates = candidates[:MAX_CANDIDATE_FILES]
    if not candidates:
        # Nothing in this tree imports from the project, so no cross-file
        # edge can exist -- the Java/JS corpora return here untouched.
        return
    openapi = _openapi_route_params(target, index)

    seeds: dict[_SeedKey, TaintedVar] = {}

    # -- step 2: harvest edges from every source-driven caller -------------
    def _harvest_cb(kind: str, origin, target_triple, prov: TaintedVar,
                    lineno: int) -> None:
        if kind != "seed":
            return  # pre-seed runs never carry markers; defensive only
        tfile, tfunc, param = target_triple
        key = (tfile, tfunc, param)
        if key not in seeds:
            seeds[key] = _seed_tv(param, tfile, tfunc, prov, lineno)

    for mod in candidates:
        try:
            source = file_index.read_source(mod.path)
        except OSError:
            continue
        if not source:
            continue
        try:
            _run_two_pass(source, str(mod.path), mod.key, openapi,
                          resolver=_Resolver(index, mod),
                          edge_cb=_harvest_cb)
        except SyntaxError:
            continue
        except Exception as exc:
            _LOG.debug("interproc harvest failed for %s: %s", mod.key, exc)

    # -- step 3: worklist fixed point over (module, func, param) -----------
    summaries: dict[tuple[str, str], dict[str, list]] = {}
    cap_logged = False

    def _summary(tfile: str, tfunc: str) -> Optional[dict[str, list]]:
        key = (tfile, tfunc)
        if key in summaries:
            return summaries[key]
        if len(summaries) >= MAX_SUMMARIES:
            nonlocal cap_logged
            if not cap_logged:
                _LOG.debug("interproc: summary cap %d reached", MAX_SUMMARIES)
                cap_logged = True
            return None
        mod = index.get(tfile)
        if mod is None or tfunc not in mod.funcs:
            return None
        node, params = mod.funcs[tfunc]
        seeds_here = {
            node.lineno: {
                p: TaintedVar(
                    p, f"{_MARKER}{tfile}#{tfunc}.{p}", node.lineno, [],
                    frozenset())
                for p in params
            }
        }
        calls: dict[str, set] = {}

        def _cb(kind, origin, target_triple, _prov, _lineno):
            if kind != "call" or origin is None:
                return
            if origin[0] != tfile or origin[1] != tfunc:
                return
            calls.setdefault(origin[2], set()).add(target_triple)

        try:
            source = file_index.read_source(mod.path)
            if not source:
                return None
            _run_two_pass(source, str(mod.path), mod.key, openapi,
                          interproc_seeds=seeds_here,
                          resolver=_Resolver(index, mod), edge_cb=_cb)
        except SyntaxError:
            return None
        except Exception as exc:
            _LOG.debug("interproc summary failed for %s#%s: %s",
                       tfile, tfunc, exc)
            return None
        summary = {p: sorted(ts) for p, ts in sorted(calls.items())}
        summaries[key] = summary
        return summary

    def _expand(origin: _SeedKey) -> list[_SeedKey]:
        summary = _summary(origin[0], origin[1])
        if not summary:
            return []
        produced: list[_SeedKey] = []
        for tfile, tfunc, param in summary.get(origin[2], ()):
            key = (tfile, tfunc, param)
            if key in seeds:
                continue  # first-seen provenance wins; set is monotone
            seeds[key] = _seed_tv(param, tfile, tfunc, seeds[origin],
                                  seeds[origin].lineno)
            produced.append(key)
        return produced

    expanded: set[_SeedKey] = set()
    frontier: list[_SeedKey] = sorted(seeds)
    while frontier:
        next_frontier: list[_SeedKey] = []
        for key in sorted(frontier):  # sorted rounds: deterministic first-win
            if key in expanded:
                continue
            expanded.add(key)
            for fresh in _expand(key):
                if fresh not in expanded:
                    next_frontier.append(fresh)
        frontier = next_frontier

    if not seeds:
        return

    # -- final seeded re-analysis of every file that owns a parameter ------
    seeded_files = sorted({k[0] for k in seeds})
    appended: list[dict] = []
    owned_sql: set[tuple[str, str]] = set()
    seeded_h1: dict[str, set[int]] = {}
    seeds_by_file: dict[str, dict[int, dict[str, TaintedVar]]] = {}
    for (tfile, tfunc, param), tv in seeds.items():
        mod = index.get(tfile)
        if mod is None or tfunc not in mod.funcs:
            continue
        lineno = mod.funcs[tfunc][0].lineno
        seeds_by_file.setdefault(tfile, {}).setdefault(lineno, {})[param] = tv

    try:
        from scanner.ast_validators import apply_ast_validation
    except Exception:  # pragma: no cover - validator layer optional by design
        apply_ast_validation = None

    for tfile in seeded_files:
        mod = index.get(tfile)
        if mod is None:
            continue
        try:
            source = file_index.read_source(mod.path)
            if not source:
                continue
            visitor = _run_two_pass(source, str(mod.path), mod.key, openapi,
                                    interproc_seeds=seeds_by_file.get(tfile))
        except SyntaxError:
            continue
        except Exception as exc:
            _LOG.debug("interproc seeded re-run failed for %s: %s",
                       tfile, exc)
            continue
        rows = _taint_dicts(visitor.findings)
        seeded_h1[tfile] = {
            int(r.get("line") or 0) for r in rows
            if r.get("rule_id") == _H1_RULE
        }
        if apply_ast_validation is not None:
            try:
                rows = apply_ast_validation(rows, str(mod.path))
            except Exception:
                pass  # worker parity: validator doubt leaves rows untouched
        for row in rows:
            chain = row.get("taint_chain")
            if not _has_marker(chain):
                continue  # worker-equivalent row: the pool already reported it
            if row.get("vuln_type") == "sql_injection":
                for elem in chain or ():
                    if isinstance(elem, str) and elem.startswith(_MARKER):
                        parsed = _parse_marker(elem)
                        if parsed is not None:
                            owned_sql.add(
                                (parsed[0], parsed[1].rsplit(".", 1)[-1]))
            appended.append(row)

    # -- H1 ownership: drop only what the seeded run no longer emits AND a
    #    marker-chain sql row now reports at the sink ----------------------
    drops: list[dict] = []
    for row in findings:
        if not isinstance(row, dict) or row.get("rule_id") != _H1_RULE:
            continue
        try:
            fdot = _dotted_key(Path(str(row.get("file") or "")), target)
        except Exception:
            fdot = None
        if fdot is None or fdot not in seeded_h1:
            continue
        if int(row.get("line") or 0) in seeded_h1[fdot]:
            continue  # still an untainted interpolation: the worker owns it
        if (fdot, str(row.get("function") or "")) not in owned_sql:
            continue  # taint reached the build but no sink owns the flow
        filter_trace.record_finding_drop(
            row, _DROP_PASS,
            "H1 build-site row: the interprocedural seeded re-run of this "
            "file no longer emits it (the interpolated part is tainted), and "
            "a marker-chain sql_injection row at the sink now reports the "
            "same defect -- tainted flows stay at the sink")
        drops.append(row)

    if drops:
        drop_ids = {id(r) for r in drops}
        findings[:] = [r for r in findings if id(r) not in drop_ids]
    if appended:
        findings.extend(appended)
