"""Phase 3.4: function-level Python reachability.

WHAT THIS DELIVERS
------------------
Gap-plan row 3.4 (function-level Python reachability).
scanner/python_reachability.py parses the scanned root with the stdlib
ast module and answers, per PYTHON FINDING: is the function containing
this finding reachable from a labeled entry point (route decorator,
top-level call, __main__ guard, test function)?

WHAT THESE TESTS PIN
--------------------
* each entry kind seeds correctly, and -- the bug the smoke fixture
  caught -- calls INSIDE function bodies are NOT module-level entry
  calls (defining a function does not execute it; counting its
  internal calls as entries would make every function "reachable" and
  the analysis vacuous);
* transitive reachability through the call graph, cross-module edges
  via both import forms, class methods, async handlers;
* dead functions and dead methods report UNREACHABLE_FUNCTION with the
  evidence, and unresolvable imports never fabricate edges;
* syntax errors are disclosed per file and their findings get a
  distinct UNKNOWN reason (file_failed_to_parse, distinct from
  file_not_in_project);
* BOM-carrying files parse (utf-8-sig) -- with plain utf-8 every
  finding in a Windows-authored file would silently go UNKNOWN;
* INFORMATIONAL ONLY: severity is never rewritten by status;
* deepcopy + determinism contracts; non-Python findings untouched;
  missing target dir -> disclosed skip.
"""
from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scanner.python_reachability import (  # noqa: E402
    annotate_findings_reachability,
    build_call_graph,
    compute_reachable,
)

# ---------------------------------------------------------------------------
# Helpers.
# ---------------------------------------------------------------------------


def _write(root: Path, name: str, source: str, *, bom: bool = False) -> None:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    encoding = "utf-8-sig" if bom else "utf-8"
    path.write_text(source, encoding=encoding)


def _finding(rule, file="app.py", line=10, severity="High", **extra):
    f = {"rule_id": rule, "severity": severity, "file": file, "line": line}
    f.update(extra)
    return f


def _annotate(payload, root):
    return annotate_findings_reachability(payload, str(root))


def _status(payload_out, rule):
    finding = next(f for f in payload_out["findings"] if f["rule_id"] == rule)
    return finding["function_reachability"]


FLASK_APP = '''\
from flask import Flask

app = Flask(__name__)


def dead_helper(name):
    query = "SELECT * FROM users WHERE name = '" + name + "'"
    return query


def layer_two(name):
    return layer_one(name)


def layer_one(name):
    return "SELECT 1"


@app.route("/user")
def user():
    return layer_two("x")


if __name__ == "__main__":
    app.run()
'''


# ---------------------------------------------------------------------------
# Entry points and reachability statuses.
# ---------------------------------------------------------------------------


def test_route_handler_is_reachable_with_the_route_label(tmp_path):
    _write(tmp_path, "app.py", FLASK_APP)
    out = _annotate({"findings": [_finding("ROUTE", line=21)]}, tmp_path)
    entry = _status(out, "ROUTE")
    assert entry["status"] == "REACHABLE_FUNCTION"
    assert entry["function"] == "user"
    assert entry["entry_point"] == "route_decorator"


def test_transitive_call_chain_from_a_route_is_reachable(tmp_path):
    _write(tmp_path, "app.py", FLASK_APP)
    out = _annotate({"findings": [
        _finding("L1", line=12),   # layer_two body -> calls layer_one
        _finding("L2", line=16),   # layer_one body
    ]}, tmp_path)
    for rule in ("L1", "L2"):
        entry = _status(out, rule)
        assert entry["status"] == "REACHABLE_FUNCTION", rule
        assert entry["entry_point"] == "route_decorator", rule


def test_dead_function_is_reported_unreachable_with_evidence(tmp_path):
    _write(tmp_path, "app.py", FLASK_APP)
    out = _annotate({"findings": [_finding("DEAD", line=7)]}, tmp_path)
    entry = _status(out, "DEAD")
    assert entry["status"] == "UNREACHABLE_FUNCTION"
    assert entry["function"] == "dead_helper"
    assert "no call path" in entry["detail"]


def test_module_level_statement_is_top_level_code(tmp_path):
    _write(tmp_path, "app.py", FLASK_APP)
    out = _annotate({"findings": [_finding("TOP", line=1)]}, tmp_path)
    entry = _status(out, "TOP")
    assert entry["status"] == "TOP_LEVEL_CODE"
    assert entry["function"] is None


def test_top_level_call_seeds_its_callee(tmp_path):
    _write(tmp_path, "app.py", '''\
def startup():
    import sys
    return sys


start_result = startup()
''')
    out = _annotate({"findings": [_finding("START", line=2)]}, tmp_path)
    entry = _status(out, "START")
    assert entry["status"] == "REACHABLE_FUNCTION"
    assert entry["entry_point"] == "top_level_call"


def test_main_guard_seeds_its_calls(tmp_path):
    _write(tmp_path, "app.py", '''\
def run_app():
    return "running"


def unused():
    return "dead"


if __name__ == "__main__":
    run_app()
''')
    out = _annotate({"findings": [
        _finding("RUN", line=2), _finding("UNUSED", line=6),
    ]}, tmp_path)
    entry = _status(out, "RUN")
    assert entry["status"] == "REACHABLE_FUNCTION"
    assert entry["entry_point"] == "__main__"
    assert _status(out, "UNUSED")["status"] == "UNREACHABLE_FUNCTION"


def test_test_functions_are_entries(tmp_path):
    _write(tmp_path, "app.py", '''\
def test_something():
    return helper()


def helper():
    return "ok"


def ordinary():
    return "dead"
''')
    out = _annotate({"findings": [
        _finding("TEST", line=2), _finding("H", line=6), _finding("N", line=10),
    ]}, tmp_path)
    assert _status(out, "TEST")["entry_point"] == "test_function"
    assert _status(out, "H")["entry_point"] == "test_function"
    assert _status(out, "N")["status"] == "UNREACHABLE_FUNCTION"


def test_calls_inside_function_bodies_are_not_entry_calls(tmp_path):
    """The smoke-fixture bug, pinned: an internal call must NOT seed a
    top-level entry -- that would make every function reachable."""
    _write(tmp_path, "app.py", '''\
def outer():
    return inner()


def inner():
    return "ok"
''')
    graph = build_call_graph(tmp_path)
    index = graph["indexes"]["app.py"]
    assert index.top_calls == [], (
        "function bodies leaked into top-level entry calls")
    reachable = compute_reachable(graph)
    assert reachable == {}, "nothing in this file is an entry point"


# ---------------------------------------------------------------------------
# Cross-module edges, classes, async.
# ---------------------------------------------------------------------------


def test_from_import_cross_module_edge(tmp_path):
    _write(tmp_path, "app.py", '''\
from flask import Flask
from utils import dangerous

app = Flask(__name__)


@app.route("/x")
def handler():
    return dangerous("q")
''')
    _write(tmp_path, "utils.py", '''\
def dangerous(q):
    return q
''')
    out = _annotate({"findings": [_finding("XMOD", file="utils.py", line=2)]},
                    tmp_path)
    entry = _status(out, "XMOD")
    assert entry["status"] == "REACHABLE_FUNCTION"
    assert entry["entry_point"] == "route_decorator"
    assert entry["function"] == "dangerous"


def test_import_attribute_cross_module_edge(tmp_path):
    _write(tmp_path, "app.py", '''\
import utils


def boot():
    return utils.dangerous("q")


boot()
''')
    _write(tmp_path, "utils.py", '''\
def dangerous(q):
    return q


def never():
    return "dead"
''')
    out = _annotate({"findings": [
        _finding("OK", file="utils.py", line=2),
        _finding("NEVER", file="utils.py", line=6),
    ]}, tmp_path)
    assert _status(out, "OK")["status"] == "REACHABLE_FUNCTION"
    assert _status(out, "NEVER")["status"] == "UNREACHABLE_FUNCTION"


def test_relative_import_resolves_within_the_package(tmp_path):
    _write(tmp_path, "pkg/app.py", '''\
from .helpers import run


run()
''')
    _write(tmp_path, "pkg/helpers.py", '''\
def run():
    return "ok"


def unused():
    return "dead"
''')
    out = _annotate({"findings": [
        _finding("RUN", file="pkg/helpers.py", line=2),
        _finding("UNUSED", file="pkg/helpers.py", line=6),
    ]}, tmp_path)
    assert _status(out, "RUN")["status"] == "REACHABLE_FUNCTION"
    assert _status(out, "UNUSED")["status"] == "UNREACHABLE_FUNCTION"


def test_unresolvable_import_fabricates_no_edges(tmp_path):
    _write(tmp_path, "app.py", '''\
from pkg_missing import helper


helper()
''')
    graph = build_call_graph(tmp_path)
    reachable = compute_reachable(graph)
    assert reachable == {}, (
        "an unresolvable import must never be guessed into a live edge")


def test_route_decorator_on_a_class_method(tmp_path):
    _write(tmp_path, "app.py", '''\
from fastapi import APIRouter

router = APIRouter()


class Handlers:
    @router.get("/item")
    def item(self):
        return self.load()

    def load(self):
        return "loaded"

    def stale(self):
        return "dead"
''')
    out = _annotate({"findings": [
        _finding("ITEM", line=8), _finding("LOAD", line=11),
        _finding("STALE", line=14),
    ]}, tmp_path)
    item = _status(out, "ITEM")
    assert item["status"] == "REACHABLE_FUNCTION"
    assert item["function"] == "Handlers.item"
    assert _status(out, "LOAD")["status"] == "REACHABLE_FUNCTION"
    assert _status(out, "STALE")["status"] == "UNREACHABLE_FUNCTION"


def test_async_route_handler_is_an_entry(tmp_path):
    _write(tmp_path, "app.py", '''\
from fastapi import APIRouter

router = APIRouter()


@router.get("/a")
async def handler():
    return helper()


def helper():
    return "ok"
''')
    out = _annotate({"findings": [_finding("H", line=8)]}, tmp_path)
    entry = _status(out, "H")
    assert entry["status"] == "REACHABLE_FUNCTION"
    assert entry["entry_point"] == "route_decorator"


# ---------------------------------------------------------------------------
# Robustness: BOM, syntax errors, paths, non-Python, missing dir.
# ---------------------------------------------------------------------------


def test_bom_carrying_files_are_parsed(tmp_path):
    """utf-8-sig pin: ast.parse rejects U+FEFF, so a BOM'd file would
    otherwise silently lose every finding to UNKNOWN."""
    _write(tmp_path, "app.py", '''\
from flask import Flask

app = Flask(__name__)


@app.route("/b")
def handler():
    return "ok"
''', bom=True)
    out = _annotate({"findings": [_finding("BOM", line=8)]}, tmp_path)
    entry = _status(out, "BOM")
    assert entry["status"] == "REACHABLE_FUNCTION"
    assert out["python_function_reachability"]["syntax_errors"] == []


def test_syntax_errors_are_disclosed_and_get_a_distinct_reason(tmp_path):
    _write(tmp_path, "broken.py", "def f(:\n    pass\n")
    out = _annotate({"findings": [_finding("BROKEN", file="broken.py", line=1)]},
                    tmp_path)
    entry = _status(out, "BROKEN")
    assert entry["status"] == "UNKNOWN"
    assert entry["reason"] == "file_failed_to_parse"
    errors = out["python_function_reachability"]["syntax_errors"]
    assert len(errors) == 1
    assert errors[0]["file"] == "broken.py"
    assert "SyntaxError" in errors[0]["error"]


def test_file_outside_the_project_gets_the_not_in_project_reason(tmp_path):
    _write(tmp_path, "app.py", "x = 1\n")
    out = _annotate({"findings": [_finding("OUT", file="elsewhere.py")]},
                    tmp_path)
    assert _status(out, "OUT")["reason"] == "file_not_in_project"


def test_windows_separators_and_absolute_paths_resolve(tmp_path):
    _write(tmp_path, "sub/app.py", '''\
def handler():
    return "ok"
''')
    out = _annotate({"findings": [
        _finding("BS", file="sub\\app.py", line=2),
        _finding("ABS", file=str(tmp_path / "sub" / "app.py"), line=2),
    ]}, tmp_path)
    # Both paths resolve into sub/app.py: line 2 sits inside handler(),
    # which nothing calls -- resolution proven by the conclusive verdict.
    for rule in ("BS", "ABS"):
        entry = _status(out, rule)
        assert entry["status"] == "UNREACHABLE_FUNCTION", rule
        assert entry["function"] == "handler", rule


def test_findings_without_a_line_are_unknown_not_guessed(tmp_path):
    _write(tmp_path, "app.py", FLASK_APP)
    out = _annotate({"findings": [_finding("NOLINE", line=None)]}, tmp_path)
    entry = _status(out, "NOLINE")
    assert entry["status"] == "UNKNOWN"
    assert entry["reason"] == "finding_carries_no_line"


def test_non_python_findings_are_left_untouched(tmp_path):
    _write(tmp_path, "app.py", "x = 1\n")
    payload = {"findings": [_finding("JAVA", file="Main.java", line=10)]}
    snapshot = copy.deepcopy(payload)
    out = _annotate(payload, tmp_path)
    assert "function_reachability" not in out["findings"][0]
    assert out["python_function_reachability"]["non_python_skipped"] == 1
    assert payload == snapshot


def test_missing_target_directory_is_a_disclosed_skip(tmp_path):
    out = _annotate({"findings": [_finding("X")]}, tmp_path / "nope")
    summary = out["python_function_reachability"]
    assert summary["status"] == "skipped"
    assert summary["reason"] == "target_directory_not_available"


def test_none_target_is_a_disclosed_skip():
    out = annotate_findings_reachability({"findings": []}, None)
    assert out["python_function_reachability"]["status"] == "skipped"


# ---------------------------------------------------------------------------
# Contracts: severity, deepcopy, determinism, summary.
# ---------------------------------------------------------------------------


def test_status_never_rewrites_severity(tmp_path):
    _write(tmp_path, "app.py", FLASK_APP)
    out = _annotate({"findings": [_finding("DEAD", line=7, severity="Critical")]},
                    tmp_path)
    finding = next(f for f in out["findings"] if f["rule_id"] == "DEAD")
    assert finding["severity"] == "Critical"
    note = out["python_function_reachability"]["note"]
    assert "never rewrites severity" in note


def test_the_callers_payload_is_never_mutated(tmp_path):
    _write(tmp_path, "app.py", FLASK_APP)
    payload = {"findings": [_finding("ROUTE", line=21)]}
    snapshot = copy.deepcopy(payload)
    _annotate(payload, tmp_path)
    assert payload == snapshot


def test_annotation_is_deterministic(tmp_path):
    _write(tmp_path, "app.py", FLASK_APP)
    a = _annotate({"findings": [_finding("R", line=21)]}, tmp_path)
    b = _annotate({"findings": [_finding("R", line=21)]}, tmp_path)
    assert json.dumps(a, default=str, sort_keys=True) == \
        json.dumps(b, default=str, sort_keys=True)


def test_summary_counts_match_the_annotations(tmp_path):
    _write(tmp_path, "app.py", FLASK_APP)
    out = _annotate({"findings": [
        _finding("ROUTE", line=21), _finding("DEAD", line=7),
        _finding("TOP", line=1), _finding("JAVA", file="M.java", line=3),
    ]}, tmp_path)
    summary = out["python_function_reachability"]
    assert summary["status"] == "available"
    assert summary["analyzed_files"] == 1
    assert summary["functions"] == 4   # dead_helper, layer_two, layer_one, user
    assert summary["entry_points"] == {"route_decorator": 1}
    assert summary["findings_annotated"] == 3
    assert summary["status_counts"] == {
        "REACHABLE_FUNCTION": 1, "UNREACHABLE_FUNCTION": 1,
        "TOP_LEVEL_CODE": 1,
    }
    assert summary["non_python_skipped"] == 1
    assert summary["reachable_functions"] == 3  # user, layer_two, layer_one


def test_nested_functions_attribute_to_the_enclosing_function(tmp_path):
    """A finding in a nested def is anchored to the outer function --
    conservative in the right direction (outer reachable => inner may run)."""
    _write(tmp_path, "app.py", '''\
from flask import Flask

app = Flask(__name__)


@app.route("/n")
def handler():
    def inner():
        return "x"
    return inner()


def unused():
    return "dead"
''')
    out = _annotate({"findings": [_finding("NEST", line=8)]}, tmp_path)
    entry = _status(out, "NEST")
    assert entry["status"] == "REACHABLE_FUNCTION"
    assert entry["function"] == "handler"
