"""Regression contract for intermediate-variable taint flows.

Phase 4c closed three benchmark false negatives (bound superglobal in PHP,
aliased child_process in JavaScript) and one false positive (a local
constant named `query` being treated as a source).  Each test pins one side
of that trade so a future edit cannot silently buy recall with precision or
vice versa.

Benchmark reference: reports/benchmark_reconciliation.md
"""
from pathlib import Path
import sys
import textwrap

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scanner.taint_engine import (
    analyze_file,
    _scan_enterprise_text,
    _child_process_names,
    _project_child_process_alias,
    _call_arguments_are_dynamic,
)
from core.analyzer import _validate_security_evidence

NEW_RULES = {
    "TAINT_PHP_SQL_INJECTION",
    "TAINT_PHP_COMMAND_INJECTION",
    "TAINT_JS_CHILD_PROCESS_EXEC",
}


def _write(tmp_path: Path, name: str, source: str) -> Path:
    p = tmp_path / name
    p.write_text(textwrap.dedent(source), encoding="utf-8")
    return p


def _taint(tmp_path: Path, name: str, source: str) -> list[dict]:
    return list(analyze_file(str(_write(tmp_path, name, source))))


def _ent(tmp_path: Path, name: str, source: str, lang: str) -> list[dict]:
    text = textwrap.dedent(source)
    return _scan_enterprise_text(str(tmp_path / name), text, lang)


def _vulns(hits: list[dict]) -> set[str]:
    return {h.get("vuln_type") for h in hits}


def _lines(hits: list[dict], vuln: str) -> list[int]:
    return [int(h.get("line") or 0) for h in hits if h.get("vuln_type") == vuln]


# ---------------------------------------------------------------------------
# 1. Bare source tokens must not fire on a proven constant
# ---------------------------------------------------------------------------

def test_local_constant_named_query_is_not_a_source(tmp_path):
    """`query = "SELECT 1"` must not become taint by name collision.

    `query` is also the name of `req.query` and of a `**query` parameter, so
    the token stays a source everywhere except where the binding itself is a
    provably constant-only expression.
    """
    hits = _taint(tmp_path, "const_query.py", """
        def independent(c):
            query = "SELECT 1"
            c.execute(query)
        """)
    assert hits == []


def test_local_fstring_of_literals_named_query_is_not_a_source(tmp_path):
    hits = _taint(tmp_path, "const_fstring.py", """
        def independent(c):
            query = f"SELECT {1}"
            c.execute(query)
        """)
    assert hits == []


def test_module_level_constant_named_query_is_not_a_source(tmp_path):
    hits = _taint(tmp_path, "module_const.py", """
        query = "SELECT 1"
        c.execute(query)
        """)
    assert hits == []


def test_sibling_real_source_still_reported_next_to_constant(tmp_path):
    """The fix must only silence the constant, never its neighbours."""
    hits = _taint(tmp_path, "sibling.py", """
        def django_post(request, c):
            c.execute(request.POST["name"])

        def independent(request, c):
            query = "SELECT 1"
            c.execute(query)
        """)
    assert _lines(hits, "sql_injection") == [3]


# ---------------------------------------------------------------------------
# 2. Zero false-negative risk for the same tokens
# ---------------------------------------------------------------------------

def test_parameter_named_query_is_still_a_source(tmp_path):
    hits = _taint(tmp_path, "param_query.py", """
        def handler(query, c):
            c.execute(query)
        """)
    assert _lines(hits, "sql_injection") == [3]


def test_parameter_named_kwargs_is_still_a_source(tmp_path):
    hits = _taint(tmp_path, "param_kwargs.py", """
        def handler(**kwargs):
            c.execute(kwargs["q"])
        """)
    assert _lines(hits, "sql_injection") == [3]


def test_parameter_shadowing_a_module_constant_is_still_a_source(tmp_path):
    hits = _taint(tmp_path, "shadow.py", """
        query = "SELECT 1"

        def handler(query, c):
            c.execute(query)
        """)
    assert _lines(hits, "sql_injection") == [5]


def test_query_assigned_from_a_real_source_is_still_reported(tmp_path):
    hits = _taint(tmp_path, "real_source.py", """
        def handler(request, c):
            query = request.args.get("q")
            c.execute(query)
        """)
    assert _lines(hits, "sql_injection") == [4]


def test_constant_plus_attacker_input_is_still_reported(tmp_path):
    hits = _taint(tmp_path, "concat.py", """
        def handler(request, c):
            query = "SELECT * FROM t WHERE id=" + request.args.get("q")
            c.execute(query)
        """)
    assert _lines(hits, "sql_injection") == [4]


def test_constant_reassigned_from_a_source_is_still_reported(tmp_path):
    """Assigning a source after a constant must revoke the classification."""
    hits = _taint(tmp_path, "reassign.py", """
        def handler(request, c):
            query = "SELECT 1"
            query = request.args.get("q")
            c.execute(query)
        """)
    assert _lines(hits, "sql_injection") == [5]


def test_augmented_assignment_over_a_constant_is_still_reported(tmp_path):
    hits = _taint(tmp_path, "augassign.py", """
        def handler(request, c):
            query = "SELECT 1"
            query += request.args.get("q")
            c.execute(query)
        """)
    assert _lines(hits, "sql_injection") == [5]


def test_scope_resolution_is_innermost_first(tmp_path):
    """A parameter must win over an outer constant binding."""
    hits = _taint(tmp_path, "innermost.py", """
        def outer():
            query = "SELECT 1"

        def inner(query, c):
            c.execute(query)
        """)
    assert _lines(hits, "sql_injection") == [6]


# ---------------------------------------------------------------------------
# 3. PHP: intermediate-variable SQL and command injection
# ---------------------------------------------------------------------------

def test_php_bound_superglobal_reaches_sql_sink(tmp_path):
    hits = _ent(tmp_path, "sqli.php", """
        <?php
        $id = $_GET['id'];
        $db = new mysqli("localhost", "u", "p", "db");
        $db->query("SELECT * FROM t WHERE id = '" . $id . "'");
        """, "php")
    assert {h["rule_id"] for h in hits} & NEW_RULES
    assert _lines(hits, "sql_injection") == [5]


def test_php_bound_superglobal_reaches_shell_sink(tmp_path):
    hits = _ent(tmp_path, "cmdi.php", """
        <?php
        $id = $_GET['id'];
        system("echo " . $id);
        """, "php")
    assert _lines(hits, "command_injection") == [4]


def test_php_fixed_command_is_not_command_injection(tmp_path):
    hits = _ent(tmp_path, "fixed.php", """
        <?php
        $id = $_GET['id'];
        system("echo done");
        """, "php")
    assert _lines(hits, "command_injection") == []


def test_php_parameterised_statement_is_not_sql_injection(tmp_path):
    hits = _ent(tmp_path, "prepared.php", """
        <?php
        $id = $_GET['id'];
        $db->prepare("SELECT * FROM t WHERE id = ?");
        """, "php")
    assert _lines(hits, "sql_injection") == []


def test_php_constant_query_without_request_data_is_clean(tmp_path):
    hits = _ent(tmp_path, "static.php", """
        <?php
        $db->query("SELECT 1");
        """, "php")
    assert hits == []


# ---------------------------------------------------------------------------
# 4. JavaScript: aliased child_process
# ---------------------------------------------------------------------------

JS_ALIASED = """
    const cp = require('child_process');
    app.get('/r', (req, res) => {
        const id = req.query.id;
        cp.execSync('ls ' + id);
    });
    """


def test_js_aliased_child_process_with_bound_request_value(tmp_path):
    hits = _ent(tmp_path, "aliased.js", JS_ALIASED, "javascript")
    assert _lines(hits, "command_injection") == [5]


def test_js_namespace_import_alias_detected(tmp_path):
    hits = _ent(tmp_path, "ns.js", """
        import cp from 'child_process';
        app.get('/r', (req, res) => {
            const id = req.query.id;
            cp.exec('ls ' + id);
        });
        """, "javascript")
    assert _lines(hits, "command_injection") == [5]


def test_js_named_import_used_bare_is_detected(tmp_path):
    hits = _ent(tmp_path, "named.js", """
        import { execSync } from 'child_process';
        app.get('/r', (req, res) => {
            const id = req.query.id;
            execSync('ls ' + id);
        });
        """, "javascript")
    assert _lines(hits, "command_injection") == [5]


def test_js_regexp_exec_is_not_command_injection(tmp_path):
    """`re.exec(...)` must never be projected onto child_process."""
    hits = _ent(tmp_path, "regexp.js", """
        const re = /ls (.*)/;
        app.get('/r', (req, res) => {
            const id = req.query.id;
            const m = re.exec(id);
        });
        """, "javascript")
    assert _lines(hits, "command_injection") == []


def test_js_aliased_child_process_running_a_fixed_command_is_clean(tmp_path):
    hits = _ent(tmp_path, "fixed.js", """
        const cp = require('child_process');
        app.get('/r', (req, res) => {
            const id = req.query.id;
            cp.execSync('ls -la');
        });
        """, "javascript")
    assert _lines(hits, "command_injection") == []


def test_js_child_process_without_request_data_is_clean(tmp_path):
    hits = _ent(tmp_path, "norequest.js", """
        const cp = require('child_process');
        const id = "ls -la";
        cp.exec('ls ' + id);
        """, "javascript")
    assert hits == []


def test_js_unrelated_receiver_with_dynamic_args_is_clean(tmp_path):
    hits = _ent(tmp_path, "unrelated.js", """
        const re = /(.*)/;
        app.get('/r', (req, res) => {
            const id = req.query.id;
            util.exec(id);
        });
        """, "javascript")
    assert _lines(hits, "command_injection") == []


def test_child_process_alias_resolution_helpers():
    lines = [
        "const cp = require('child_process');",
        "import ns from 'child_process';",
        "import { execSync } from 'child_process';",
        "const re = /x/;",
    ]
    members, named = _child_process_names(lines)
    assert {"cp", "ns"} <= members
    assert "execSync" in named

    assert (_project_child_process_alias("cp.execSync(x);", members, named)
            == "child_process.execSync(x);")
    # An unresolved receiver is left alone, which is what makes the
    # concrete-sink validator reject it.
    assert (_project_child_process_alias("re.exec(x);", members, named)
            == "re.exec(x);")
    assert (_project_child_process_alias("execSync(x);", members, named)
            == "child_process.execSync(x);")


def test_dynamic_argument_heuristic():
    assert _call_arguments_are_dynamic('system("echo " . $id);')
    assert _call_arguments_are_dynamic("cp.execSync('ls ' + id);")
    assert _call_arguments_are_dynamic("c.execute(query);")
    assert not _call_arguments_are_dynamic('system("echo done");')
    assert not _call_arguments_are_dynamic('cp.execSync("ls -la");')
    assert not _call_arguments_are_dynamic('$db->prepare("... ?");')


# ---------------------------------------------------------------------------
# 5. EVIDEX must recognise the PHP command sink it can now report
# ---------------------------------------------------------------------------

def test_evidex_accepts_php_system_as_a_command_sink():
    """A finding the scanner emits must survive the evidence gate."""
    result = _validate_security_evidence({
        "vuln_type": "command_injection",
        "rule_id": "TAINT_PHP_COMMAND_INJECTION",
        "file": "index.php",
        "line": 5,
        "snippet": 'system("echo " . $id);',
        "taint_path": "$_GET -> system(",
        "description": "Source-to-sink indicator: $_GET reaches system(",
    }, require_sink=True)
    assert result["sink_present"] is True, result["reason"]
    assert result["sink_valid"] is True, result["reason"]
    assert result["valid"] is True, result["reason"]


def test_evidex_still_rejects_a_command_finding_without_a_sink():
    result = _validate_security_evidence({
        "vuln_type": "command_injection",
        "rule_id": "TAINT_PHP_COMMAND_INJECTION",
        "file": "index.php",
        "line": 5,
        "snippet": "$id = $_GET['id'];",
        "taint_path": "$_GET -> ?",
        "description": "source only",
    }, require_sink=True)
    assert result["valid"] is False
