"""Benchmark FP0 closure — 2026-10-22, red-first suite (27 OWASP FPs).

Baseline measured before this file existed (findings33_gapfix rescore):
OVERALL 1415 found / 1415 true (100% recall) but fpT 27 = fpF 27 --
xpathi 20/20 negatives flagged (JAVA_XPATH_INJECTION) and sqli 7/232
negatives flagged (JAVA_JDBC_SQL_INTERMEDIATE_QUERY), both introduced by
the batch-10/Phase-B window rules.

Every negative test's kill proof, read from the benchmark sources, is
one of six families (the fixture below mirrors each shape 1:1):

* CONST-SELECT  -- a condition built only from local constant ints
  folds to a fixed truth value, so the tainted branch is dead and the
  only reaching definition of the concat operand is a string literal
  (ternary: BenchmarkTest00520/00683/00430/01013/01225/01735/02172;
  if/else: 00117/00118/01397/01479/01821/01893/01305/01307).
* CONST-SWITCH  -- the selector resolves to a constant char via
  ``guess.charAt(1)`` on a literal, so only one case is reachable and
  that case assigns a literal (01014/01562/01632/02173).
* MAP-CONST-KEY -- the operand's last definition is
  ``map.get("K")`` whose LAST put under the literal key ``K`` stored a
  literal (00116/00852).
* LIST-INDEX    -- the operand is ``list.get(i)`` with constant ``i``
  after a straight-line add/remove sequence whose element at ``i`` is a
  literal (01303/02370/02457).
* INTERPROC     -- the operand is the return of a same-file
  ``doSomething`` (inner-class ``new Test().doSomething(...)`` or a
  private static) whose own return value proves constant by the same
  machinery (all of the above reached through a call).
* FACTORY-CONST-ARG -- the operand is ``thing.doSomething(g)`` where
  ``thing`` comes from a nullary static factory and EVERY argument is a
  compile-time constant. The benchmark's ThingFactory can only build
  Thing1/Thing2 and BOTH implementations return their argument
  unchanged (helpers/Thing1.java:25 ``String r = i; return r;``,
  Thing2.java:25 ``new StringBuilder(i).toString()``); generically, a
  call that receives no attacker-controlled argument returns none
  unless the callee reads ambient request state, which no Java API
  does silently. (01961/01633.)

HONEST NON-SHIP pinned below: BenchmarkTest00941 (xpathi, oracle
real=false) wraps param in a Base64 ENCODE+DECODE roundtrip before the
concat. A roundtrip is the identity function -- the data is still
attacker-controlled -- so the oracle's label is the only thing "safe"
about it and the finding MUST keep firing. test_b64_roundtrip_keeps
pins that recall-over-oracle decision so it can never be "fixed"
away silently.

GRAMMAR CONTRACT (same as every ast_validators suite): every assertion
depends on the LOCAL tree_sitter_java wheel; absent -> parse() None ->
findings pass through -> these tests skip themselves.

Run: python -m pytest tests/test_benchmark_fp0_20261022.py -q
"""
from __future__ import annotations

import importlib.util
import shutil
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scanner import tree_sitter_support as ts  # noqa: E402

TS_INSTALLED = importlib.util.find_spec("tree_sitter") is not None
needs_java = pytest.mark.skipif(
    not TS_INSTALLED or not ts.grammar_available("java"),
    reason="optional tree-sitter java grammar not installed")

_HEAD = """package test;

import jakarta.servlet.*;
import jakarta.servlet.http.*;
import java.io.*;

public class %s extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        String param = req.getParameter("p");
%s
    }
%s
}
"""


def _java(name: str, body: str, tail: str = "") -> str:
    return _HEAD % (name, body, tail)


# ---------------------------------------------------------------------------
# XPath negatives (JAVA_XPATH_INJECTION must go dark)
# ---------------------------------------------------------------------------

XPATH_TERNARY = _java("XpathTernary", """
        String bar;
        int num = 106;
        bar = (7 * 18) + num > 200 ? "This_should_always_happen" : param;
        try {
            javax.xml.xpath.XPath xp =
                    javax.xml.xpath.XPathFactory.newInstance().newXPath();
            String expression = "/Employees/Employee[@emplid='" + bar + "']";
            xp.evaluate(expression);
        } catch (Exception e) {
            resp.getWriter().println("err");
        }
""")

XPATH_IFELSE = _java("XpathIfElse", """
        String bar;
        int num = 86;
        if ((7 * 42) - num > 200) bar = "This_should_always_happen";
        else bar = param;
        try {
            javax.xml.xpath.XPath xp =
                    javax.xml.xpath.XPathFactory.newInstance().newXPath();
            String expression = "/Employees/Employee[@emplid='" + bar + "']";
            xp.evaluate(expression);
        } catch (Exception e) {
            resp.getWriter().println("err");
        }
""")

XPATH_SWITCH = _java("XpathSwitch", """
        String bar;
        String guess = "ABC";
        char switchTarget = guess.charAt(1);
        switch (switchTarget) {
            case 'A':
                bar = param;
                break;
            case 'B':
                bar = "bob";
                break;
            default:
                bar = "fallback";
                break;
        }
        try {
            javax.xml.xpath.XPath xp =
                    javax.xml.xpath.XPathFactory.newInstance().newXPath();
            String expression = "/Employees/Employee[@emplid='" + bar + "']";
            xp.evaluate(expression);
        } catch (Exception e) {
            resp.getWriter().println("err");
        }
""")

XPATH_MAP_KEY = _java("XpathMapKey", """
        String bar = "safe!";
        java.util.HashMap<String, Object> map51005 = new java.util.HashMap<String, Object>();
        map51005.put("keyA-51005", "a_Value");
        map51005.put("keyB-51005", param);
        bar = (String) map51005.get("keyB-51005");
        bar = (String) map51005.get("keyA-51005");
        try {
            javax.xml.xpath.XPath xp =
                    javax.xml.xpath.XPathFactory.newInstance().newXPath();
            String expression = "/Employees/Employee[@emplid='" + bar + "']";
            xp.evaluate(expression);
        } catch (Exception e) {
            resp.getWriter().println("err");
        }
""")

XPATH_INTERPROC_TERNARY = _java(
    "XpathInterTernary", """
        String bar = new Test().doSomething(req, param);
        try {
            javax.xml.xpath.XPath xp =
                    javax.xml.xpath.XPathFactory.newInstance().newXPath();
            String expression = "/Employees/Employee[@emplid='" + bar + "']";
            xp.evaluate(expression);
        } catch (Exception e) {
            resp.getWriter().println("err");
        }
""", tail="""
    private class Test {
        public String doSomething(HttpServletRequest request, String param) {
            String bar;
            int num = 106;
            bar = (7 * 18) + num > 200 ? "This_should_always_happen" : param;
            return bar;
        }
    }
""")

XPATH_INTERPROC_LIST = _java(
    "XpathInterList", """
        String bar = doSomething(req, param);
        try {
            javax.xml.xpath.XPath xp =
                    javax.xml.xpath.XPathFactory.newInstance().newXPath();
            String expression = "/Employees/Employee[@emplid='" + bar + "']";
            xp.evaluate(expression);
        } catch (Exception e) {
            resp.getWriter().println("err");
        }
""", tail="""
    private static String doSomething(HttpServletRequest request, String param) {
        String bar = "alsosafe";
        if (param != null) {
            java.util.List<String> valuesList = new java.util.ArrayList<String>();
            valuesList.add("safe");
            valuesList.add(param);
            valuesList.add("moresafe");
            valuesList.remove(0);
            bar = valuesList.get(1);
        }
        return bar;
    }
""")

XPATH_INTERPROC_SWITCH = _java(
    "XpathInterSwitch", """
        String bar = new Test().doSomething(req, param);
        try {
            javax.xml.xpath.XPath xp =
                    javax.xml.xpath.XPathFactory.newInstance().newXPath();
            String expression = "/Employees/Employee[@emplid='" + bar + "']";
            xp.evaluate(expression);
        } catch (Exception e) {
            resp.getWriter().println("err");
        }
""", tail="""
    private class Test {
        public String doSomething(HttpServletRequest request, String param) {
            String bar;
            String guess = "ABC";
            char switchTarget = guess.charAt(1);
            switch (switchTarget) {
                case 'A':
                    bar = param;
                    break;
                case 'B':
                    bar = "bob";
                    break;
                default:
                    bar = "fallback";
                    break;
            }
            return bar;
        }
    }
""")

XPATH_FACTORY_ARG = _java(
    "XpathFactoryArg", """
        String bar = doSomething(req, param);
        try {
            javax.xml.xpath.XPath xp =
                    javax.xml.xpath.XPathFactory.newInstance().newXPath();
            String expression = "/Employees/Employee[@emplid='" + bar + "']";
            xp.evaluate(expression);
        } catch (Exception e) {
            resp.getWriter().println("err");
        }
""", tail="""
    private static String doSomething(HttpServletRequest request, String param) {
        org.owasp.benchmark.helpers.ThingInterface thing =
                org.owasp.benchmark.helpers.ThingFactory.createThing();
        String g31144 = "barbarians_at_the_gate";
        String bar = thing.doSomething(g31144);
        return bar;
    }
""")

# ---------------------------------------------------------------------------
# SQLi negatives (JAVA_JDBC_SQL_INTERMEDIATE_QUERY must go dark)
# ---------------------------------------------------------------------------

_SQLI_TERNARY_BODY = """
        String bar;
        int num = 106;
        bar = (7 * 18) + num > 200 ? "This_should_always_happen" : param;
        String sql = "SELECT * from USERS where USERNAME=? and PASSWORD='" + bar + "'";
        try {
            java.sql.Connection connection =
                    java.sql.DriverManager.getConnection("jdbc:h2:mem", "u", "p");
            java.sql.PreparedStatement statement =
                    connection.prepareStatement(sql, java.sql.Statement.RETURN_GENERATED_KEYS);
            statement.setString(1, "foo");
            statement.execute();
        } catch (java.sql.SQLException e) {
            resp.getWriter().println("err");
        }
"""

SQLI_TERNARY = _java("SqliTernary", _SQLI_TERNARY_BODY)

SQLI_IFELSE = _java("SqliIfElse", """
        String bar = new Test().doSomething(req, param);
        String sql = "SELECT * from USERS where USERNAME=? and PASSWORD='" + bar + "'";
        try {
            java.sql.Connection connection =
                    java.sql.DriverManager.getConnection("jdbc:h2:mem", "u", "p");
            java.sql.PreparedStatement statement =
                    connection.prepareStatement(sql, new int[] {1, 2});
            statement.setString(1, "foo");
            statement.execute();
        } catch (java.sql.SQLException e) {
            resp.getWriter().println("err");
        }
""", tail="""
    private class Test {
        public String doSomething(HttpServletRequest request, String param) {
            String bar;
            int num = 86;
            if ((7 * 42) - num > 200) bar = "This_should_always_happen";
            else bar = param;
            return bar;
        }
    }
""")

SQLI_INTERPROC_LIST = _java("SqliInterList", """
        String bar = new Test().doSomething(req, param);
        String sql = "SELECT * from USERS where USERNAME=? and PASSWORD='" + bar + "'";
        try {
            java.sql.Connection connection =
                    java.sql.DriverManager.getConnection("jdbc:h2:mem", "u", "p");
            java.sql.PreparedStatement statement =
                    connection.prepareStatement(sql, java.sql.Statement.RETURN_GENERATED_KEYS);
            statement.setString(1, "foo");
            statement.execute();
        } catch (java.sql.SQLException e) {
            resp.getWriter().println("err");
        }
""", tail="""
    private class Test {
        public String doSomething(HttpServletRequest request, String param) {
            String bar = "alsosafe";
            if (param != null) {
                java.util.List<String> valuesList = new java.util.ArrayList<String>();
                valuesList.add("safe");
                valuesList.add(param);
                valuesList.add("moresafe");
                valuesList.remove(0);
                bar = valuesList.get(1);
            }
            return bar;
        }
    }
""")

SQLI_INTERPROC_SWITCH = _java("SqliInterSwitch", """
        String bar = doSomething(req, param);
        String sql = "SELECT * from USERS where USERNAME=? and PASSWORD='" + bar + "'";
        try {
            java.sql.Connection connection =
                    java.sql.DriverManager.getConnection("jdbc:h2:mem", "u", "p");
            java.sql.PreparedStatement statement =
                    connection.prepareStatement(sql, java.sql.Statement.RETURN_GENERATED_KEYS);
            statement.setString(1, "foo");
            statement.execute();
        } catch (java.sql.SQLException e) {
            resp.getWriter().println("err");
        }
""", tail="""
    private static String doSomething(HttpServletRequest request, String param) {
        String bar;
        String guess = "ABC";
        char switchTarget = guess.charAt(1);
        switch (switchTarget) {
            case 'A':
                bar = param;
                break;
            case 'B':
                bar = "bob";
                break;
            default:
                bar = "fallback";
                break;
        }
        return bar;
    }
""")

SQLI_FACTORY_ARG = _java("SqliFactoryArg", """
        String bar = doSomething(req, param);
        String sql = "SELECT * from USERS where USERNAME=? and PASSWORD='" + bar + "'";
        try {
            java.sql.Connection connection =
                    java.sql.DriverManager.getConnection("jdbc:h2:mem", "u", "p");
            java.sql.PreparedStatement statement =
                    connection.prepareStatement(sql, java.sql.Statement.RETURN_GENERATED_KEYS);
            statement.setString(1, "foo");
            statement.execute();
        } catch (java.sql.SQLException e) {
            resp.getWriter().println("err");
        }
""", tail="""
    private static String doSomething(HttpServletRequest request, String param) {
        org.owasp.benchmark.helpers.ThingInterface thing =
                org.owasp.benchmark.helpers.ThingFactory.createThing();
        String g99523 = "barbarians_at_the_gate";
        String bar = thing.doSomething(g99523);
        return bar;
    }
""")

# ---------------------------------------------------------------------------
# Positive twins — the true-positive shape MUST keep firing (over-kill guards)
# ---------------------------------------------------------------------------

XPATH_VULN_DIRECT = _java("XpathVulnDirect", """
        try {
            javax.xml.xpath.XPath xp =
                    javax.xml.xpath.XPathFactory.newInstance().newXPath();
            String expression = "/Employees/Employee[@emplid='" + param + "']";
            xp.evaluate(expression);
        } catch (Exception e) {
            resp.getWriter().println("err");
        }
""")

XPATH_VULN_IFELSE = _java("XpathVulnIfElse", """
        String bar;
        int num = request.getParameter("n").length();
        if ((7 * 42) - num > 200) bar = "This_should_always_happen";
        else bar = param;
        try {
            javax.xml.xpath.XPath xp =
                    javax.xml.xpath.XPathFactory.newInstance().newXPath();
            String expression = "/Employees/Employee[@emplid='" + bar + "']";
            xp.evaluate(expression);
        } catch (Exception e) {
            resp.getWriter().println("err");
        }
""")

XPATH_VULN_INTERPROC = _java(
    "XpathVulnInter", """
        String bar = new Test().doSomething(req, param);
        try {
            javax.xml.xpath.XPath xp =
                    javax.xml.xpath.XPathFactory.newInstance().newXPath();
            String expression = "/Employees/Employee[@emplid='" + bar + "']";
            xp.evaluate(expression);
        } catch (Exception e) {
            resp.getWriter().println("err");
        }
""", tail="""
    private class Test {
        public String doSomething(HttpServletRequest request, String param) {
            return param;
        }
    }
""")

XPATH_VULN_MAP_TAINTED = _java("XpathVulnMap", """
        String bar = "safe!";
        java.util.HashMap<String, Object> map51005 = new java.util.HashMap<String, Object>();
        map51005.put("keyA-51005", "a_Value");
        map51005.put("keyB-51005", param);
        bar = (String) map51005.get("keyA-51005");
        bar = (String) map51005.get("keyB-51005");
        try {
            javax.xml.xpath.XPath xp =
                    javax.xml.xpath.XPathFactory.newInstance().newXPath();
            String expression = "/Employees/Employee[@emplid='" + bar + "']";
            xp.evaluate(expression);
        } catch (Exception e) {
            resp.getWriter().println("err");
        }
""")

XPATH_VULN_FACTORY_TAINTED = _java(
    "XpathVulnFactory", """
        String bar = doSomething(req, param);
        try {
            javax.xml.xpath.XPath xp =
                    javax.xml.xpath.XPathFactory.newInstance().newXPath();
            String expression = "/Employees/Employee[@emplid='" + bar + "']";
            xp.evaluate(expression);
        } catch (Exception e) {
            resp.getWriter().println("err");
        }
""", tail="""
    private static String doSomething(HttpServletRequest request, String param) {
        org.owasp.benchmark.helpers.ThingInterface thing =
                org.owasp.benchmark.helpers.ThingFactory.createThing();
        String bar = thing.doSomething(param);
        return bar;
    }
""")

SQLI_VULN_DIRECT = _java("SqliVulnDirect", """
        String sql = "SELECT * from USERS where USERNAME=? and PASSWORD='" + param + "'";
        try {
            java.sql.Connection connection =
                    java.sql.DriverManager.getConnection("jdbc:h2:mem", "u", "p");
            java.sql.PreparedStatement statement =
                    connection.prepareStatement(sql, java.sql.Statement.RETURN_GENERATED_KEYS);
            statement.setString(1, "foo");
            statement.execute();
        } catch (java.sql.SQLException e) {
            resp.getWriter().println("err");
        }
""")

SQLI_VULN_INTERPROC = _java("SqliVulnInter", """
        String bar = new Test().doSomething(req, param);
        String sql = "SELECT * from USERS where USERNAME=? and PASSWORD='" + bar + "'";
        try {
            java.sql.Connection connection =
                    java.sql.DriverManager.getConnection("jdbc:h2:mem", "u", "p");
            java.sql.PreparedStatement statement =
                    connection.prepareStatement(sql, java.sql.Statement.RETURN_GENERATED_KEYS);
            statement.setString(1, "foo");
            statement.execute();
        } catch (java.sql.SQLException e) {
            resp.getWriter().println("err");
        }
""", tail="""
    private class Test {
        public String doSomething(HttpServletRequest request, String param) {
            return param;
        }
    }
""")

SQLI_VULN_LIST_NONCONST_INDEX = _java("SqliVulnList", """
        String bar;
        java.util.List<String> valuesList = new java.util.ArrayList<String>();
        valuesList.add("safe");
        valuesList.add(param);
        valuesList.add("moresafe");
        bar = valuesList.get(param.length() % 3);
        String sql = "SELECT * from USERS where USERNAME=? and PASSWORD='" + bar + "'";
        try {
            java.sql.Connection connection =
                    java.sql.DriverManager.getConnection("jdbc:h2:mem", "u", "p");
            java.sql.PreparedStatement statement =
                    connection.prepareStatement(sql, java.sql.Statement.RETURN_GENERATED_KEYS);
            statement.setString(1, "foo");
            statement.execute();
        } catch (java.sql.SQLException e) {
            resp.getWriter().println("err");
        }
""")

#: BenchmarkTest00941's shape, verbatim modulo package: a Base64
#: ENCODE+DECODE roundtrip is the identity function, so the value is
#: still attacker-controlled and the finding MUST keep firing even
#: though the benchmark oracle labels the test negative. This is the
#: one of the 27 FPs we do not close -- pinned here as recall-over-
#: oracle so a future "fp0 chase" cannot silently suppress it.
SQLI_KEEP_B64 = _java("KeepB64", """
        String bar = "";
        if (param != null) {
            bar = new String(org.apache.commons.codec.binary.Base64.decodeBase64(
                    org.apache.commons.codec.binary.Base64.encodeBase64(param.getBytes())));
        }
        String sql = "SELECT * from USERS where USERNAME=? and PASSWORD='" + bar + "'";
        try {
            java.sql.Connection connection =
                    java.sql.DriverManager.getConnection("jdbc:h2:mem", "u", "p");
            java.sql.PreparedStatement statement =
                    connection.prepareStatement(sql, java.sql.Statement.RETURN_GENERATED_KEYS);
            statement.setString(1, "foo");
            statement.execute();
        } catch (java.sql.SQLException e) {
            resp.getWriter().println("err");
        }
""")


def _scan(source: str, name: str, rule: str) -> list[dict]:
    """Scan one hermetic fixture exactly the way the pipeline does."""
    from scanner.sast import scan_directory

    tmp = Path(tempfile.mkdtemp(prefix="rsx_fp0_"))
    try:
        target = tmp / name
        target.write_text(source, encoding="utf-8")
        rows = scan_directory(str(tmp))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return [f for f in rows
            if str(f.get("rule_id")) == rule
            and Path(str(f.get("file", ""))).name == name]


# ---------------------------------------------------------------------------
# Negatives — one test per kill-proof family (RED before the guard lands)
# ---------------------------------------------------------------------------

@needs_java
@pytest.mark.parametrize("source,name", [
    (XPATH_TERNARY, "XpathTernary.java"),
    (XPATH_IFELSE, "XpathIfElse.java"),
    (XPATH_SWITCH, "XpathSwitch.java"),
    (XPATH_MAP_KEY, "XpathMapKey.java"),
    (XPATH_INTERPROC_TERNARY, "XpathInterTernary.java"),
    (XPATH_INTERPROC_LIST, "XpathInterList.java"),
    (XPATH_INTERPROC_SWITCH, "XpathInterSwitch.java"),
    (XPATH_FACTORY_ARG, "XpathFactoryArg.java"),
])
def test_xpath_negative_shapes_go_dark(source, name):
    assert _scan(source, name, "JAVA_XPATH_INJECTION") == [], (
        "%s must not fire: the concat operand is provably constant" % name)


@needs_java
@pytest.mark.parametrize("source,name", [
    (SQLI_TERNARY, "SqliTernary.java"),
    (SQLI_IFELSE, "SqliIfElse.java"),
    (SQLI_INTERPROC_LIST, "SqliInterList.java"),
    (SQLI_INTERPROC_SWITCH, "SqliInterSwitch.java"),
    (SQLI_FACTORY_ARG, "SqliFactoryArg.java"),
])
def test_sqli_negative_shapes_go_dark(source, name):
    assert _scan(source, name, "JAVA_JDBC_SQL_INTERMEDIATE_QUERY") == [], (
        "%s must not fire: the query concat operand is provably constant"
        % name)


# ---------------------------------------------------------------------------
# Positive twins — kill-only guards must not silence the true-positive shape
# ---------------------------------------------------------------------------

@needs_java
@pytest.mark.parametrize("source,name", [
    (XPATH_VULN_DIRECT, "XpathVulnDirect.java"),
    (XPATH_VULN_IFELSE, "XpathVulnIfElse.java"),
    (XPATH_VULN_INTERPROC, "XpathVulnInter.java"),
    (XPATH_VULN_MAP_TAINTED, "XpathVulnMap.java"),
    (XPATH_VULN_FACTORY_TAINTED, "XpathVulnFactory.java"),
])
def test_xpath_positive_twins_keep_firing(source, name):
    assert _scan(source, name, "JAVA_XPATH_INJECTION"), (
        "%s is the true-positive shape and must keep firing" % name)


@needs_java
@pytest.mark.parametrize("source,name", [
    (SQLI_VULN_DIRECT, "SqliVulnDirect.java"),
    (SQLI_VULN_INTERPROC, "SqliVulnInter.java"),
    (SQLI_VULN_LIST_NONCONST_INDEX, "SqliVulnList.java"),
])
def test_sqli_positive_twins_keep_firing(source, name):
    assert _scan(source, name, "JAVA_JDBC_SQL_INTERMEDIATE_QUERY"), (
        "%s is the true-positive shape and must keep firing" % name)


@needs_java
def test_b64_roundtrip_keeps():
    """00941: encode+decode is the identity function -- NOT a sanitizer.

    The benchmark oracle labels BenchmarkTest00941 negative, but the
    source proves nothing: param survives the roundtrip byte-for-byte
    and reaches the XPath/SQL concat. Recall-over-oracle: the finding
    must keep firing.
    """
    rows = _scan(SQLI_KEEP_B64, "KeepB64.java",
                 "JAVA_JDBC_SQL_INTERMEDIATE_QUERY")
    assert rows, "a Base64 roundtrip must never be treated as a sanitizer"
