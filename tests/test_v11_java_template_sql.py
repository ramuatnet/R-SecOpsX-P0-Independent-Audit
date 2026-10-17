"""F3 (Benchmark precision batch): Spring JdbcTemplate SQL sinks.

The BenchmarkJava oracle labels 98 true SQL-injection tests silent because
the line-layer SQL sink only matched plain JDBC names (prepareStatement /
executeQuery / execute / ...).  Every miss routes SQL through the Spring
JdbcTemplate family:

    DatabaseHelper.JDBCtemplate.queryForObject(sql, Long.class)
    DatabaseHelper.JdbcTemplate.batchUpdate(sql)
    jdbcTemplate.query(sql)

This is a sink-coverage extension, not a taint weakening: the existing
argument-aware gate (tainted identifier OR source expression, literal
masking, dead-name refinement) still decides whether a match reports.
The short names `query`/`update` are receiver-constrained so that
MessageDigest.update(taintedBytes) -- the weak-hash family's own shape,
107 benchmark occurrences -- can never be claimed as SQL execution.

Red-first protocol (F-batch): with the sink extension stashed, the three
TP tests must FAIL (miss = the measured detection failure) while the
three controls -- md.update, constant SQL, plain executeQuery -- must
PASS in both phases (they guard the receiver constraint and the taint
gate against over-extension).
"""
from __future__ import annotations

import pathlib
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scanner.taint_engine import _scan_java_semantic  # noqa: E402

SQL_PRELUDE = """import javax.servlet.http.HttpServletRequest;
"""

RULE = "JAVA_TAINT_SQL_INJECTION"


def line_findings(java_source: str, rule: str = RULE) -> list:
    with tempfile.TemporaryDirectory(prefix="rsx_f3_sql_") as tmp:
        p = pathlib.Path(tmp, "T.java")
        p.write_text(java_source, encoding="utf-8")
        return [f for f in _scan_java_semantic(str(p), java_source)
                if f.get("rule_id") == rule]


# --- TP shapes (RED before the sink extension) ---------------------------

def test_tpd_queryforobject_fires():
    """BenchmarkTest00025 shape: concat SQL through queryForObject."""
    src = SQL_PRELUDE + """
class T {
    public void doPost(HttpServletRequest request) throws Exception {
        String param = request.getParameter("x");
        String sql = "SELECT userid from USERS where USERNAME='foo' and PASSWORD='" + param + "'";
        Long results =
                org.owasp.benchmark.helpers.DatabaseHelper.JDBCtemplate.queryForObject(
                        sql, Long.class);
    }
}
"""
    assert len(line_findings(src)) == 1


def test_tpd_batchupdate_fires():
    """BenchmarkTest00194 shape: fully qualified batchUpdate(sql)."""
    src = SQL_PRELUDE + """
class T {
    public void doPost(HttpServletRequest request) throws Exception {
        String param = request.getParameter("x");
        String sql = "UPDATE USERS set PASSWORD='" + param + "' where USERID=5";
        org.owasp.benchmark.helpers.DatabaseHelper.JDBCtemplate.batchUpdate(sql);
    }
}
"""
    assert len(line_findings(src)) == 1


def test_tpd_receiver_query_fires():
    """Short name `query` fires only with a template-ish receiver."""
    src = SQL_PRELUDE + """
class T {
    public void doPost(HttpServletRequest request) throws Exception {
        String param = request.getParameter("x");
        String sql = "SELECT * from USERS where USERNAME='" + param + "'";
        org.springframework.jdbc.core.JdbcTemplate jdbcTemplate =
                new org.springframework.jdbc.core.JdbcTemplate();
        jdbcTemplate.query(sql);
    }
}
"""
    assert len(line_findings(src)) == 1


# --- Controls (PASS in both phases) --------------------------------------

def test_control_md_update_never_sql():
    """MessageDigest.update(tainted) is hash work, not SQL execution.

    Receiver 'md' carries no template/jdbc/dao/sql/tx marker, so the
    short-name branch must not match -- this guards the 107 benchmark
    md.update occurrences from becoming SQL findings.
    """
    src = SQL_PRELUDE + """
class T {
    public void doPost(HttpServletRequest request) throws Exception {
        String input = request.getParameter("x");
        java.security.MessageDigest md =
                java.security.MessageDigest.getInstance("SHA-256");
        md.update(input.getBytes());
    }
}
"""
    assert line_findings(src) == []


def test_control_constant_sql_stays_dark():
    """A template call with constant SQL has no tainted carrier."""
    src = SQL_PRELUDE + """
class T {
    public void doPost(HttpServletRequest request) throws Exception {
        String sql = "SELECT 1";
        org.owasp.benchmark.helpers.DatabaseHelper.JDBCtemplate.queryForList(sql);
    }
}
"""
    assert line_findings(src) == []


def test_control_plain_executequery_still_fires():
    """Plain JDBC coverage must survive the extension unchanged."""
    src = SQL_PRELUDE + """
class T {
    public void doPost(HttpServletRequest request) throws Exception {
        String param = request.getParameter("x");
        String sql = "SELECT * from USERS where NAME='" + param + "'";
        java.sql.Statement statement = conn.createStatement();
        statement.executeQuery(sql);
    }
}
"""
    assert len(line_findings(src)) == 1


# --- J5 project layer (logical statements already join wrapped lines) -----

def test_j5_tpd_multiline_queryformap():
    """BenchmarkTest00039 shape: wrapped sql definition + template sink."""
    src = SQL_PRELUDE + """
class T {
    public void doPost(HttpServletRequest request) throws Exception {
        String param = request.getParameter("x");
        String sql =
                "SELECT * from USERS where USERNAME='foo' and PASSWORD='"
                        + param + "'";
        java.util.Map<String, Object> row =
                org.owasp.benchmark.helpers.DatabaseHelper.JDBCtemplate.queryForMap(sql);
    }
}
"""
    from scanner.java_semantic_j5 import analyze_java_project
    with tempfile.TemporaryDirectory(prefix="rsx_f3_j5_") as tmp:
        pathlib.Path(tmp, "T.java").write_text(src, encoding="utf-8")
        hits = [f for f in analyze_java_project(tmp)
                if f.get("rule_id") == "JAVA_J5_SQL"]
    assert len(hits) == 1


def test_j3_tpd_cookie_rowset():
    """BenchmarkTest00033 shape: cookie source + queryForRowSet.

    J3 carries the cookie-value source model, so the template name had to
    land in the J3 jdbc sink for this family to be visible there too.
    """
    from scanner.taint_engine import _j3_scan_java_semantics
    src = SQL_PRELUDE + """
class T {
    public void doPost(HttpServletRequest request) throws Exception {
        javax.servlet.http.Cookie[] theCookies = request.getCookies();
        String param = "none";
        if (theCookies != null) {
            for (javax.servlet.http.Cookie theCookie : theCookies) {
                if (theCookie.getName().equals("T")) {
                    param = java.net.URLDecoder.decode(theCookie.getValue(), "UTF-8");
                    break;
                }
            }
        }
        String sql = "SELECT * from USERS where NAME='" + param + "'";
        org.owasp.benchmark.helpers.DatabaseHelper.JDBCtemplate.queryForRowSet(sql);
    }
}
"""
    with tempfile.TemporaryDirectory(prefix="rsx_f3_j3_") as tmp:
        p = pathlib.Path(tmp, "T.java")
        p.write_text(src, encoding="utf-8")
        hits = [f for f in _j3_scan_java_semantics(str(p), src)
                if f.get("rule_id") == "JAVA_J3_SQL_INJECTION"]
    assert len(hits) == 1


def test_results_of_template_query_never_become_xss():
    """A template return is a result set, not an SQL taint carrier.

    The security-return guard must cover the template family: without it
    `String results = ...queryForRowSet(sql)` inherits sql taint and the
    later println(results) reports XSS on an SQL test (the 21 wrong-CWE
    rows on the findings18 sqli misses).  SQL must fire, XSS must not --
    this test is RED in BOTH directions before the guard extension.
    """
    src = SQL_PRELUDE + """
class T {
    public void doPost(HttpServletRequest request) throws Exception {
        String param = request.getParameter("x");
        String sql = "SELECT * from USERS where NAME='" + param + "'";
        org.springframework.jdbc.core.rowset.SqlRowSet results =
                org.owasp.benchmark.helpers.DatabaseHelper.JDBCtemplate.queryForRowSet(sql);
        response.getWriter().println("Your results are: " + results);
    }
}
"""
    sql_hits = line_findings(src)
    xss = [f for f in line_findings(src, "JAVA_TAINT_XSS")]
    # line layer: SQL fires, results-taint must not exist for the xss sink
    assert len(sql_hits) == 1
    assert xss == []

    from scanner.java_semantic_j5 import analyze_java_project
    with tempfile.TemporaryDirectory(prefix="rsx_f3_guard_") as tmp:
        pathlib.Path(tmp, "T.java").write_text(src, encoding="utf-8")
        allf = analyze_java_project(tmp)
    assert any(f.get("rule_id") == "JAVA_J5_SQL" for f in allf)
    assert not any(str(f.get("cwe") or "").lower() == "cwe-79" for f in allf)


def test_tpd_addbatch_stages_tainted_sql():
    """BenchmarkTest00435 shape: statement.addBatch(sql) then executeBatch.

    Batch staging queues attacker SQL for execution; addBatch is JDBC
    Statement vocabulary, so the file-context gate keeps same-named
    staging calls outside JDBC code dark.
    """
    src = SQL_PRELUDE + """
class T {
    public void doPost(HttpServletRequest request) throws Exception {
        String param = request.getParameter("x");
        String sql = "SELECT * from USERS where NAME='" + param + "'";
        java.sql.Statement statement =
                org.owasp.benchmark.helpers.DatabaseHelper.getSqlStatement();
        statement.addBatch(sql);
        int[] counts = statement.executeBatch();
    }
}
"""
    assert len(line_findings(src)) == 1


def test_control_constant_addbatch_stays_dark():
    """Batch staging of constant SQL has no tainted carrier."""
    src = SQL_PRELUDE + """
class T {
    public void doPost(HttpServletRequest request) throws Exception {
        String sql = "SELECT 1";
        java.sql.Statement statement =
                org.owasp.benchmark.helpers.DatabaseHelper.getSqlStatement();
        statement.addBatch(sql);
        int[] counts = statement.executeBatch();
    }
}
"""
    assert line_findings(src) == []


def test_control_addbatch_without_jdbc_context_stays_dark():
    """The JDBC context gate: no Statement/java.sql/jdbc in file -> dark."""
    src = SQL_PRELUDE + """
class T {
    public void doPost(HttpServletRequest request) throws Exception {
        String param = request.getParameter("x");
        String job = "task-" + param;
        WorkQueue queue = new WorkQueue();
        queue.addBatch(job);
    }
}
"""
    assert line_findings(src) == []
