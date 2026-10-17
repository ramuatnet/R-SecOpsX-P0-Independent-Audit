"""F8 (corpus FP regression from the F3 statement join): try-with-resources.

F3 added `_java_statement_text` -- a bounded logical-statement join -- so a
SQL/path sink whose ARGUMENTS wrap onto following lines still sees the
carrier (`jdbc.queryForObject(\n        sql, Long.class);`).  The join's
stop condition required a bracket-balanced line ending in `;`, but a
try-with-resources HEADER ends in `{`:

    PreparedStatement ps = conn.prepareStatement(sql)) {   <- statement end
    ps.setString(1, userInput);                            <- NEXT statement

The join therefore crossed into the block BODY and read
`setString(1, userInput)` -- a BOUND PARAMETER, the canonical safe
pattern -- as a sink argument: the golden corpus's SafeServlet.java L22
(a parameterised query, labelled safe) gained a spurious
JAVA_TAINT_SQL_INJECTION (corpus java FP 6 -> 7, measured pre/post
8ff9894..cbe8613).

The fix: a bracket-balanced statement ending in `{` is a complete
statement HEADER; its block body is never part of it.  Every measured
wrapped-argument shape still joins, because an argument continuation
cannot end in a block-open brace while its call is still open (depth > 0
keeps the loop alive until `;`).

Red-first protocol: the parameterised-try TN and the corpus SafeServlet
assertion must FAIL before the fix (they ARE the regression); the
wrapped-args TP, the tainted-try TP, and the if-header-wrap TP must PASS
in both phases (they pin the join's recall contract).

Measured: SafeServlet L22 (spurious at cbe8613) -> dark after; benchmark
findings A/B must hold 1415/1415 with 0/0 FP.
"""
from __future__ import annotations

import pathlib
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scanner.taint_engine import _scan_java_semantic  # noqa: E402

CORPUS_JAVA = ROOT / "tests" / "vuln-test-corpus" / "sast" / "java"

PRELUDE = """import javax.servlet.http.HttpServletRequest;
import java.sql.*;
"""

RULE = "JAVA_TAINT_SQL_INJECTION"


def line_findings(java_source: str) -> list:
    with tempfile.TemporaryDirectory(prefix="rsx_f8_") as tmp:
        p = pathlib.Path(tmp, "T.java")
        p.write_text(java_source, encoding="utf-8")
        return [f for f in _scan_java_semantic(str(p), java_source)
                if f.get("rule_id") == RULE]


def line_of(src: str, needle: str) -> int:
    return next(i for i, l in enumerate(src.splitlines(), 1)
                if needle in l)


# --- The regression (RED before the join fix) -----------------------------

def test_tn_parameterized_try_with_resources_stays_dark():
    """SafeServlet shape: prepareStatement(sql) with `sql` a `?`-literal,
    userInput bound through setString -- the body must not be join-bait."""
    src = PRELUDE + """
class T {
    void doPost(HttpServletRequest req) throws Exception {
        String userInput = req.getParameter("input");

        String sql = "SELECT * FROM users WHERE name = ?";
        try (Connection conn = DriverManager.getConnection(DB_URL, USER, PASS);
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, userInput);
            try (ResultSet rs = ps.executeQuery()) {
            }
        }
    }
}
"""
    sink_line = line_of(src, "conn.prepareStatement(sql)")
    rows = [f for f in line_findings(src)
            if int(f.get("line") or 0) == sink_line]
    assert not rows, f"parameterised query must stay dark at L{sink_line}: {rows}"


def test_corpus_safeservlet_l22_stays_dark():
    """The measured corpus regression: SafeServlet.java L22."""
    rows = [f for f in _scan_java_semantic(
                str(CORPUS_JAVA / "SafeServlet.java"),
                (CORPUS_JAVA / "SafeServlet.java").read_text(encoding="utf-8"))
            if f.get("rule_id") == RULE
            and str(f.get("file") or "").endswith("SafeServlet.java")
            and int(f.get("line") or 0) == 22]
    assert not rows, f"SafeServlet.java L22 regressed: {rows}"


# --- Recall guards (PASS in both phases) ----------------------------------

def test_tpd_wrapped_queryforobject_args_still_fire():
    """F3's measured shape: args wrap to the next line; `;` stop joins them."""
    src = PRELUDE + """
class T {
    void doPost(HttpServletRequest request) throws Exception {
        String param = request.getParameter("x");
        String sql = "SELECT userid from USERS where USERNAME='" + param + "'";
        Long results =
                org.owasp.benchmark.helpers.DatabaseHelper.JDBCtemplate.queryForObject(
                        sql, Long.class);
    }
}
"""
    sink_line = line_of(src, "queryForObject(")
    rows = [f for f in line_findings(src)
            if int(f.get("line") or 0) == sink_line]
    assert rows, "wrapped queryForObject(sql, ...) args must still be joined"


def test_tpd_tainted_arg_in_try_with_resources_still_fires():
    """The fix kills the BODY join, not the detection: a tainted `sql` in
    the header is still reported on the header line."""
    src = PRELUDE + """
class T {
    void doPost(HttpServletRequest req) throws Exception {
        String userInput = req.getParameter("input");

        String sql = "SELECT * FROM users WHERE name = '" + userInput + "'";
        try (Connection conn = DriverManager.getConnection(DB_URL, USER, PASS);
             PreparedStatement ps = conn.prepareStatement(sql)) {
            try (ResultSet rs = ps.executeQuery()) {
            }
        }
    }
}
"""
    sink_line = line_of(src, "conn.prepareStatement(sql)")
    rows = [f for f in line_findings(src)
            if int(f.get("line") or 0) == sink_line]
    assert rows, "tainted sql through prepareStatement must still report"


def test_tpd_if_header_wrap_ending_in_brace_still_fires():
    """An if-header whose call wraps ends `)` `{`: the `{`-stop may only
    fire AFTER the continuation is joined, never mid-call."""
    src = PRELUDE + """
class T {
    void doPost(HttpServletRequest request) throws Exception {
        String param = request.getParameter("x");
        String sql = "SELECT COUNT(*) FROM USERS WHERE NAME='" + param + "'";
        int c = 0;
        if (DatabaseHelper.JDBCtemplate.queryForObject(
                sql, Long.class) > 0) {
            c = 1;
        }
    }
}
"""
    sink_line = line_of(src, "queryForObject(")
    rows = [f for f in line_findings(src)
            if int(f.get("line") or 0) == sink_line]
    assert rows, "if-header wrapped call (ends `) {`) must still join args"
