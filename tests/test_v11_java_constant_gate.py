"""E-batch: literal-word taint + proven-constant sink gates (Java layers).

Two measured defect classes behind 46 BenchmarkJava false positives
(findings15 baseline: 69 FP rows total):

E0 -- literal-word taint.  ``_j5_expr_hits``/``_expr_tainted`` matched
tainted NAMES as substrings of the whole expression INCLUDING string
literal contents, so the prose word "bar" inside
``new Object[] {"The streetz 4 Ms bar"}`` tainted the ``filters``
template array (chain ``parameter:filters -> filters -> ctx.search(``,
all 11 JAVA_J5_LDAP FPs) and ``write("Parameter value: " + bar)`` kept
a ``value`` hit (J5_XSS follow-ons).  The JAVA_TAINT_* line layer got
this fix in the B-batch (_B1_JAVA_TAINT_LITERAL_MASK); the J5 and J4
layers did not.  Concatenation flows are untouched: tainted variables
live OUTSIDE the quotes.

E1 -- J4 proven-constant sink gate.  J4's monotone mention model taints
``bar`` whenever a helper is CALLED with a tainted arg, regardless of
the helper folding its result to a constant (constant-true if/ternary
with int arithmetic, safe-key map round-trip): J4_LDAP 14 FP /
J4_XSS 13 FP.  The gate kills only when the shared evaluator
(scanner/multipart_flow.sink_value_proven_constant) proves EVERY
tainted carrier at the sink a constant at that line.

E3 -- line-layer severed-chain gate.  The JAVA_TAINT_* ProcessBuilder
``pb.start()`` branch had NO kill filter at all, so a builder whose
recorded evidence chain passes through a folded ``bar`` still fired
(TAINT_COMMAND_INJECTION 8 FP).  The chain is one linear evidence path:
any simple local on it proven constant at the sink severs it.

All proof gates honour ``gate_enabled()``: ``RSX_MULTIPART_FLOW=0``
restores the pre-gate behaviour.  E0 is a correctness fix (data vs
code), always on, like the B-batch literal mask it mirrors.

Load-bearing pairs (each suppression has a keeps-control that differs
by ONE edit -- the fold itself):
  * constant-true if / ternary -> suppressed; unfoldable condition -> keeps
  * map round-trip helper (safe final read) -> suppressed; passthrough
    helper -> keeps
  * template-array literal-word taint -> suppressed; real concat taint -> keeps
  * ProcessBuilder chain severed by the fold -> suppressed; raw bar -> keeps
"""
from __future__ import annotations

import pathlib
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scanner.java_semantic_j4 import analyze_java_j4  # noqa: E402
from scanner.java_semantic_j5 import analyze_java_project  # noqa: E402
from scanner.taint_engine import (  # noqa: E402
    _j3_scan_java_semantics,
    _scan_java_semantic,
)

LDAP_PRELUDE = """import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
"""


def j4_findings(java_source: str, rule: str) -> list:
    with tempfile.TemporaryDirectory(prefix="rsx_e_j4_") as tmp:
        p = pathlib.Path(tmp, "T.java")
        p.write_text(java_source, encoding="utf-8")
        return [f for f in analyze_java_j4(str(p), java_source)
                if f.get("rule_id") == rule]


def j5_findings(java_source: str, rule: str) -> list:
    with tempfile.TemporaryDirectory(prefix="rsx_e_j5_") as tmp:
        pathlib.Path(tmp, "T.java").write_text(java_source, encoding="utf-8")
        return [f for f in analyze_java_project(tmp)
                if f.get("rule_id") == rule]


def line_findings(java_source: str, rule: str) -> list:
    with tempfile.TemporaryDirectory(prefix="rsx_e_line_") as tmp:
        p = pathlib.Path(tmp, "T.java")
        p.write_text(java_source, encoding="utf-8")
        return [f for f in _scan_java_semantic(str(p), java_source)
                if f.get("rule_id") == rule]


def j3_findings(java_source: str, rule: str) -> list:
    with tempfile.TemporaryDirectory(prefix="rsx_e_j3_") as tmp:
        p = pathlib.Path(tmp, "T.java")
        p.write_text(java_source, encoding="utf-8")
        return [f for f in _j3_scan_java_semantics(str(p), java_source)
                if f.get("rule_id") == rule]


# BenchmarkTest00948 shape: the helper puts the tainted value in a map
# under keyB, then reads back keyA (the SAFE value) -- the last read wins
# and the returned constant cannot carry attacker data to the LDAP
# filter.  The 3-arg sink keeps this fixture J4-only (J5's own walk
# already folds it -- the J5 family needs the template-array shape).
LDAP_MAP_ROUNDTRIP = LDAP_PRELUDE + """
class T {
    public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String param = request.getParameter("x");
        String bar = new Test().doSomething(request, param);
        DirContext ctx = null;
        String base = "ou=users";
        SearchControls sc = new SearchControls();
        String filter = "(&(objectclass=person)(uid=" + bar + "))";
        ctx.search(base, filter, sc);
    }

    private class Test {
        public String doSomething(HttpServletRequest request, String param) {
            String bar = "safe!";
            java.util.HashMap<String, Object> map1 = new java.util.HashMap<String, Object>();
            map1.put("keyA", "a_Value");
            map1.put("keyB", param);
            bar = (String) map1.get("keyB");
            bar = (String) map1.get("keyA");
            return bar;
        }
    }
}
"""

# ONE edit from the shape above: the helper RETURNS the parameter.
LDAP_PASSTHROUGH_HELPER = LDAP_PRELUDE + """
class T {
    public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String param = request.getParameter("x");
        String bar = new Test().doSomething(request, param);
        DirContext ctx = null;
        String base = "ou=users";
        SearchControls sc = new SearchControls();
        String filter = "(&(objectclass=person)(uid=" + bar + "))";
        ctx.search(base, filter, sc);
    }

    private class Test {
        public String doSomething(HttpServletRequest request, String param) {
            return param;
        }
    }
}
"""

# BenchmarkTest01024 shape (the real J5_LDAP FP idiom): the helper folds
# bar to a constant (J5's own walk kills the filter flow), and the
# Object[] template array's literal "The streetz 4 Ms bar" used to taint
# `filters` through the prose word "bar" (E0).
LDAP_TEMPLATE_ARRAY = LDAP_PRELUDE + """
class T {
    public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String param = request.getParameter("x");
        String bar = new Test().doSomething(request, param);
        DirContext ctx = null;
        String base = "ou=users";
        SearchControls sc = new SearchControls();
        String filter = "(&(objectclass=person))(|(uid=" + bar + ")(street={0}))";
        Object[] filters = new Object[] {"The streetz 4 Ms bar"};
        ctx.search(base, filter, filters, sc);
    }

    private class Test {
        public String doSomething(HttpServletRequest request, String param) {
            String bar;
            int num = 86;
            if ((7 * 42) - num > 200) bar = "This_should_always_happen";
            else bar = param;
            return bar;
        }
    }
}
"""

# ONE edit from LDAP_TEMPLATE_ARRAY: the helper returns param, so the
# filter really carries attacker data (real concat flow -- keeps).
LDAP_TEMPLATE_ARRAY_RAW = LDAP_TEMPLATE_ARRAY.replace(
    """            String bar;
            int num = 86;
            if ((7 * 42) - num > 200) bar = "This_should_always_happen";
            else bar = param;
            return bar;""",
    "            return param;")

# BenchmarkTest01439 XSS shape: a literal containing the WORD "value"
# plus a real `value` variable sourced from getParameterValues -- the
# literal word used to keep the finding alive (E0).  The sink writes
# only the folded `bar`; `value` never reaches it.
XSS_LITERAL_WORD = """import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

class T {
    public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String param = request.getParameter("x");
        String bar;
        int num = 106;
        bar = (7 * 18) + num > 200 ? "This_should_always_happen" : param;
        String[] values = request.getParameterValues("v");
        String value = (values != null) ? values[0] : "";
        response.getWriter().write("Parameter value: " + bar);
    }
}
"""

# BenchmarkTest01053 shape: ternary with proven-true int condition.
XSS_TERNARY_CONST = """import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

class T {
    public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String param = request.getParameter("x");
        String bar;
        int num = 106;
        bar = (7 * 18) + num > 200 ? "This_should_always_happen" : param;
        response.getWriter().println(bar);
    }
}
"""

# ONE edit: the ternary condition is runtime-dependent.
XSS_TERNARY_UNFOLDABLE = """import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

class T {
    public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String param = request.getParameter("x");
        String bar;
        bar = param.length() > 2 ? "safe" : param;
        response.getWriter().println(bar);
    }
}
"""

# BenchmarkTest00396 shape: constant-folded bar inside a fixed argv
# array, routed through ProcessBuilder.command(args) -> start().
CMD_ARRAY_CONST = """import javax.servlet.http.HttpServletRequest;

class T {
    public void doPost(HttpServletRequest request) throws Exception {
        String param = request.getParameter("x");
        if (param == null) param = "";
        String bar;
        int num = 86;
        if ((7 * 42) - num > 200) bar = "This_should_always_happen";
        else bar = param;
        String a1 = "";
        String a2 = "";
        String osName = System.getProperty("os.name");
        if (osName.indexOf("Windows") != -1) { a1 = "cmd.exe"; a2 = "/c"; }
        else { a1 = "sh"; a2 = "-c"; }
        String[] args = {a1, a2, "echo " + bar};
        ProcessBuilder pb = new ProcessBuilder();
        pb.command(args);
        Process p = pb.start();
    }
}
"""

# BenchmarkTest00814 shape: folded bar added to a list, routed through
# ProcessBuilder.command(argList) -> start().
CMD_LIST_ADD_CONST = """import javax.servlet.http.HttpServletRequest;

class T {
    public void doPost(HttpServletRequest request) throws Exception {
        String param = request.getParameter("x");
        if (param == null) param = "";
        String bar;
        int num = 106;
        bar = (7 * 18) + num > 200 ? "This_should_always_happen" : param;
        java.util.List<String> argList = new java.util.ArrayList<String>();
        argList.add("echo");
        argList.add(bar);
        ProcessBuilder pb = new ProcessBuilder();
        pb.command(argList);
        Process p = pb.start();
    }
}
"""

# ONE edit from CMD_ARRAY_CONST: bar is the raw request value.
CMD_RAW_BAR = """import javax.servlet.http.HttpServletRequest;

class T {
    public void doPost(HttpServletRequest request) throws Exception {
        String param = request.getParameter("x");
        if (param == null) param = "";
        String bar = param;
        String a1 = "sh";
        String a2 = "-c";
        String[] args = {a1, a2, "echo " + bar};
        ProcessBuilder pb = new ProcessBuilder();
        pb.command(args);
        Process p = pb.start();
    }
}
"""


# --- E0: literal-word taint (J5 + J4) -------------------------------------

def test_j5_ldap_template_array_literal_word_suppressed():
    """The prose word "bar" inside a string literal must not taint the
    Object[] template array (BenchmarkTest01024 idiom, 11 FP on
    findings15)."""
    assert not j5_findings(LDAP_TEMPLATE_ARRAY, "JAVA_J5_LDAP")


def test_j5_ldap_template_array_raw_flow_keeps_control():
    """Control: the same file with a passthrough helper still reports --
    the filter REALLY carries attacker data."""
    assert j5_findings(LDAP_TEMPLATE_ARRAY_RAW, "JAVA_J5_LDAP")


def test_j5_xss_literal_word_suppressed():
    """"Parameter value: " must not keep a `value` hit alive
    (BenchmarkTest01439 idiom) once the folded bar carries no taint."""
    assert not j5_findings(XSS_LITERAL_WORD, "JAVA_J5_XSS")


# --- E1: J4 proven-constant sink gate --------------------------------------

def test_j4_ldap_map_roundtrip_helper_suppressed():
    """The helper returns the SAFE map key; filter folds to a constant."""
    assert not j4_findings(LDAP_MAP_ROUNDTRIP, "JAVA_J4_LDAP")


def test_j4_ldap_template_array_folded_helper_suppressed():
    """J4's mention model must not report when the helper folds the
    value AND the template array's literal word is data (E0+E1)."""
    assert not j4_findings(LDAP_TEMPLATE_ARRAY, "JAVA_J4_LDAP")


def test_j4_ldap_passthrough_helper_keeps_control():
    """Control: the same call with a passthrough helper still reports."""
    assert j4_findings(LDAP_PASSTHROUGH_HELPER, "JAVA_J4_LDAP")


def test_j4_xss_ternary_constant_suppressed():
    assert not j4_findings(XSS_TERNARY_CONST, "JAVA_J4_XSS")


def test_j4_xss_unfoldable_ternary_keeps_control():
    """Control: an unfoldable condition resurrects, never kills."""
    assert j4_findings(XSS_TERNARY_UNFOLDABLE, "JAVA_J4_XSS")


# --- E3: JAVA_TAINT_* line layer severed-chain gate ------------------------

def test_taint_cmd_processbuilder_array_constant_suppressed():
    assert not line_findings(CMD_ARRAY_CONST,
                             "JAVA_TAINT_COMMAND_INJECTION")


def test_taint_cmd_list_add_constant_suppressed():
    assert not line_findings(CMD_LIST_ADD_CONST,
                             "JAVA_TAINT_COMMAND_INJECTION")


def test_taint_cmd_raw_bar_keeps_control():
    assert line_findings(CMD_RAW_BAR, "JAVA_TAINT_COMMAND_INJECTION")


# --- E3: JAVA_J3_* layer severed-chain gate (dedup-unmasked rows) ----------

# BenchmarkTest01939/00571 shape: folded bar inside the SECOND of two
# argv arrays reaching Runtime.exec directly -- the J3 rows that
# surfaced at the exact former TAINT_CMD locations once the
# line-layer findings died (findings16: +5 J3_CMD on negatives),
# then died again under the E3-J3 gate + E5 walk fix (findings17/18).
J3_EXEC_ARRAY_CONST = """import javax.servlet.http.HttpServletRequest;

class T {
    public void doPost(HttpServletRequest request) throws Exception {
        String param = request.getParameter("x");
        String bar;
        int num = 86;
        if ((7 * 42) - num > 200) bar = "This_should_always_happen";
        else bar = param;
        String cmd = "echo";
        String[] args = {cmd};
        String[] argsEnv = {bar};
        Runtime r = Runtime.getRuntime();
        Process p = r.exec(args, argsEnv);
    }
}
"""

# ONE edit: bar is the raw request value.
J3_EXEC_RAW = """import javax.servlet.http.HttpServletRequest;

class T {
    public void doPost(HttpServletRequest request) throws Exception {
        String param = request.getParameter("x");
        String bar = param;
        String[] argsEnv = {bar};
        Runtime r = Runtime.getRuntime();
        Process p = r.exec(argsEnv);
    }
}
"""


def test_j3_cmd_exec_array_constant_suppressed():
    assert not j3_findings(J3_EXEC_ARRAY_CONST,
                           "JAVA_J3_COMMAND_INJECTION")


def test_j3_cmd_exec_raw_keeps_control():
    assert j3_findings(J3_EXEC_RAW, "JAVA_J3_COMMAND_INJECTION")


# --- E5: dead-walk array-initializer frame poison --------------------------

# BenchmarkTest00571 shape: TWO argv arrays in a row; the fold lands in
# the SECOND one.  _j5_dead_names counted the first array's {} as a
# BLOCK brace: its "}" popped a real frame and its "{" pushed a phantom
# cond frame, so the second array-init write lost kill rights and
# argsEnv stayed live -- the whole JAVA_J5_CMD dedup-release family
# (5 pre-existing + 6 unmasked rows on findings16).
CMD_TWO_ARRAYS_CONST = """import javax.servlet.http.HttpServletRequest;

class T {
    public void doPost(HttpServletRequest request) throws Exception {
        String param = request.getParameter("x");
        String bar;
        int num = 86;
        if ((7 * 42) - num > 200) bar = "This_should_always_happen";
        else bar = param;
        String cmd = "echo";
        String[] args = {cmd};
        String[] argsEnv = {bar};
        Runtime r = Runtime.getRuntime();
        Process p = r.exec(args, argsEnv);
    }
}
"""

# ONE edit: bar is the raw request value.
CMD_TWO_ARRAYS_RAW = CMD_TWO_ARRAYS_CONST.replace(
    """        String bar;
        int num = 86;
        if ((7 * 42) - num > 200) bar = "This_should_always_happen";
        else bar = param;""",
    "        String bar = param;")


def test_j5_cmd_two_arrays_fold_suppressed():
    """The folded bar must propagate its death through the SECOND
    array-init (frame stack poisoned by the first one pre-fix)."""
    assert not j5_findings(CMD_TWO_ARRAYS_CONST, "JAVA_J5_CMD")


def test_j5_cmd_two_arrays_raw_keeps_control():
    """Control: the same two arrays with raw bar still report."""
    assert CMD_TWO_ARRAYS_RAW != CMD_TWO_ARRAYS_CONST  # replace must bite
    assert j5_findings(CMD_TWO_ARRAYS_RAW, "JAVA_J5_CMD")


def test_j5_dead_walk_second_array_inherits_kill():
    """White-box: the dead-walk itself must mark the second
    array-initializer variable dead when its element folds."""
    from scanner.java_semantic_j5 import _j5_dead_names
    body = [
        '        String bar;',
        '        int num = 86;',
        '        if ((7 * 42) - num > 200) bar = "c";',
        '        else bar = param;',
        '        String[] args = {cmd};',
        '        String[] argsEnv = {bar};',
        '        Process p = r.exec(args, argsEnv);',
    ]
    taint = {"param", "bar", "args", "argsEnv", "cmd", "r"}
    dead = _j5_dead_names(body, 1, taint, 7, None, "command_injection",
                          None, None)
    assert "argsEnv" in dead


# --- kill switch -----------------------------------------------------------

def test_e_gate_honors_multipart_kill_switch(monkeypatch):
    """RSX_MULTIPART_FLOW=0 restores the pre-gate behaviour for the
    PROOF gates (E1/E3): the folded shapes fire again.  E0 is a
    correctness fix (data vs code) and stays on under the switch, like
    the B-batch JAVA_TAINT literal mask it mirrors."""
    monkeypatch.setenv("RSX_MULTIPART_FLOW", "0")
    assert j4_findings(LDAP_MAP_ROUNDTRIP, "JAVA_J4_LDAP")
    assert line_findings(CMD_ARRAY_CONST, "JAVA_TAINT_COMMAND_INJECTION")
