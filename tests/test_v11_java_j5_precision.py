"""Precision tests for the J5 kill-on-overwrite pass (_j5_dead_names).

The fixed-point taint set answers "was this name ever tainted in this
method"; it cannot answer "was it tainted HERE". BenchmarkJava exploits
that gap with negative oracles whose variable is overwritten with a safe
value (or assigned in an unreachable branch) before the sink -- measured
as 12/20 xpathi negative tests flagged, plus the cross-category J5_XSS
follow-on hits, before the kill pass existed.

The load-bearing tests here are the NEGATIVES (a kill pass that fires on
them is the FP bug returning) paired with their POSITIVE twins (a kill
pass that silences them is a silent miss -- strictly worse than the FP).
Each pair differs by one edit, mirroring the mutation-testing contract.

What must stay true:
  * a safe LAST write silences the sink; a tainted last write fires it
  * a constant-folded unreachable branch does not count as a write
    (both the if/else and ternary spellings, and both fold directions)
  * an unfoldable condition resurrects but never kills (conservative)
  * a conditional safe write (inside if/try-else frames) does not kill
  * a try/finally frame DOES grant kills -- benchmark wraps the sink
    path in try { ... } and refusing to see through it re-opens the FP
  * a helper that folds a constant and returns it lets the caller kill
    the assignment; a passthrough helper never does (safe_calls gate)
"""
from __future__ import annotations

import pathlib
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scanner.java_semantic_j5 import analyze_java_project  # noqa: E402

XPATH_PRELUDE = """import javax.servlet.http.HttpServletRequest;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathFactory;
import org.w3c.dom.Document;

class T {
    void doPost(HttpServletRequest request, Document doc) throws Exception {
"""


def xpath_flows(java_source: str) -> list:
    """Run the full J5 project analysis over one Java source file."""
    with tempfile.TemporaryDirectory(prefix="rsx_j5test_") as tmp:
        pathlib.Path(tmp, "T.java").write_text(java_source, encoding="utf-8")
        return [f for f in analyze_java_project(tmp)
                if f.get("rule_id") == "JAVA_J5_XPATH"]


def sink_tail(expression_line: str = 'bar') -> str:
    return """        XPath xp = XPathFactory.newInstance().newXPath();
        String expression = "/Employees/Employee[@emplid='" + %s + "']";
        xp.compile(expression).evaluate(doc, javax.xml.xpath.XPathConstants.NODESET);
    }
}
""" % expression_line


# ---------------------------------------------------------------------------
# 1. Overwrite idiom: collection round-trip ending in a safe key.
# ---------------------------------------------------------------------------

_OVERWRITE_BODY = """        String param = "noCookieValueSupplied";
        String header = request.getHeader("X-Data");
        if (header != null) {
            param = header;
        }
        String bar = "safe!";
        java.util.HashMap<String, Object> map = new java.util.HashMap<String, Object>();
        map.put("keyB", param);
        map.put("keyA", "a_Value");
        bar = (String) map.get("%(last_key)s");
        String expression = "/Employees/Employee[@emplid='" + bar + "']";
        XPath xp = XPathFactory.newInstance().newXPath();
        xp.compile(expression).evaluate(doc, javax.xml.xpath.XPathConstants.NODESET);
    }
}
"""


def test_overwrite_with_safe_key_is_quiet():
    """The negative oracle: last write selects the safe constant."""
    src = XPATH_PRELUDE + _OVERWRITE_BODY % {"last_key": "keyA"}
    assert xpath_flows(src) == []


def test_overwrite_with_tainted_key_fires():
    """One edit from the negative: the last write selects the taint."""
    src = XPATH_PRELUDE + _OVERWRITE_BODY % {"last_key": "keyB"}
    assert len(xpath_flows(src)) >= 1


def test_direct_source_overwrite_fires():
    """The last write IS a request source -- kill must not apply."""
    src = XPATH_PRELUDE + """        String param = request.getParameter("emplid");
        String bar = "safe!";
        bar = param;
""" + sink_tail()
    assert len(xpath_flows(src)) >= 1


def test_safe_overwrite_inside_try_kills():
    """try frames grant kills: if the sink ran, the safe write ran."""
    src = XPATH_PRELUDE + """        String param = request.getParameter("emplid");
        String bar = "safe!";
        try {
            bar = request.getParameter("other");
            bar = "hardcoded-safe";
            XPath xp = XPathFactory.newInstance().newXPath();
            String expression = "/Employees/Employee[@emplid='" + bar + "']";
            xp.compile(expression).evaluate(doc, javax.xml.xpath.XPathConstants.NODESET);
        } catch (Exception e) {
        }
    }
}
"""
    assert xpath_flows(src) == []


def test_conditional_safe_write_does_not_kill():
    """A write inside an if frame may not run -- it proves nothing."""
    src = XPATH_PRELUDE + """        String param = request.getParameter("emplid");
        String bar = param;
        if (request.getHeader("X") != null) {
            bar = "hardcoded-safe";
        }
""" + sink_tail()
    assert len(xpath_flows(src)) >= 1


# ---------------------------------------------------------------------------
# 2. Unreachable-branch idiom: if/else with a constant-foldable condition.
# ---------------------------------------------------------------------------

_IFELSE_BODY = """        String param = request.getParameter("emplid");
        String bar;
        int num = %(num)s;
        if ((7 * 42) - num > 200) bar = "This_should_always_happen";
        else bar = param;
        String expression = "/Employees/Employee[@emplid='" + bar + "']";
        XPath xp = XPathFactory.newInstance().newXPath();
        xp.compile(expression).evaluate(doc, javax.xml.xpath.XPathConstants.NODESET);
    }
}
"""


def test_folded_true_if_else_is_quiet():
    """Condition folds TRUE: the tainted else branch is dead code."""
    src = XPATH_PRELUDE + _IFELSE_BODY % {"num": "86"}
    assert xpath_flows(src) == []


def test_folded_false_if_else_fires():
    """Condition folds FALSE: the else branch is the TAKEN one."""
    src = XPATH_PRELUDE + _IFELSE_BODY % {"num": "106"}
    assert len(xpath_flows(src)) >= 1


def test_unfoldable_condition_resurrects():
    """The condition reads request data: both branches stay possible."""
    src = XPATH_PRELUDE + """        String param = request.getParameter("emplid");
        String bar;
        int num = Integer.parseInt(request.getHeader("X-Num"));
        if ((7 * 42) - num > 200) bar = "This_should_always_happen";
        else bar = param;
""" + sink_tail()
    assert len(xpath_flows(src)) >= 1


# ---------------------------------------------------------------------------
# 3. Unreachable-branch idiom: ternary spelling.
# ---------------------------------------------------------------------------

_TERNARY_BODY = """        String param = request.getParameter("emplid");
        String bar;
        int num = %(num)s;
        bar = (7 * 18) + num > 200 ? "This_should_always_happen" : param;
        String expression = "/Employees/Employee[@emplid='" + bar + "']";
        XPath xp = XPathFactory.newInstance().newXPath();
        xp.compile(expression).evaluate(doc, javax.xml.xpath.XPathConstants.NODESET);
    }
}
"""


def test_folded_true_ternary_is_quiet():
    src = XPATH_PRELUDE + _TERNARY_BODY % {"num": "106"}
    assert xpath_flows(src) == []


def test_folded_false_ternary_fires():
    src = XPATH_PRELUDE + _TERNARY_BODY % {"num": "12"}
    assert len(xpath_flows(src)) >= 1


# ---------------------------------------------------------------------------
# 4. Interprocedural: the helper decides, the caller carries the arg.
# ---------------------------------------------------------------------------

_CALLER = """        String param = request.getParameter("emplid");
        String bar = new Test().doSomething(request, param);
        String expression = "/Employees/Employee[@emplid='" + bar + "']";
        XPath xp = XPathFactory.newInstance().newXPath();
        xp.compile(expression).evaluate(doc, javax.xml.xpath.XPathConstants.NODESET);
    }
"""

_FOLDED_HELPER = """    public String doSomething(HttpServletRequest request, String param) {
        String bar;
        int num = 86;
        if ((7 * 42) - num > 200) bar = "This_should_always_happen";
        else bar = param;
        return bar;
    }
}
"""

_PASSTHROUGH_HELPER = """    public String doSomething(HttpServletRequest request, String param) {
        String bar;
        bar = param;
        return bar;
    }
}
"""


def test_caller_of_folding_helper_is_quiet():
    """The helper returns the folded constant; the tainted argument
    in the caller's call must not keep the assignment alive."""
    src = XPATH_PRELUDE + _CALLER + _FOLDED_HELPER
    assert xpath_flows(src) == []


def test_caller_of_passthrough_helper_fires():
    """Same caller, one edit in the helper: it returns its parameter."""
    src = XPATH_PRELUDE + _CALLER + _PASSTHROUGH_HELPER
    assert len(xpath_flows(src)) >= 1


def test_switch_helper_with_runtime_discriminant_fires():
    """Conservative boundary pinned: a switch discriminant that only
    constant folding of request-derived data could rule out keeps the
    tainted cases alive (01562's shape)."""
    src = XPATH_PRELUDE + _CALLER + """    public String doSomething(HttpServletRequest request, String param) {
        String bar;
        char switchTarget = param.charAt(0);
        switch (switchTarget) {
            case 'A':
            case 'C':
            case 'D':
                bar = param;
                break;
            default:
                bar = "bobs_your_uncle";
                break;
        }
        return bar;
    }
}
"""
    assert len(xpath_flows(src)) >= 1


# ---------------------------------------------------------------------------
# 5. The taint_engine line layer (JAVA_TAINT_*) shares the same discipline
#    through _java_dead_names -> _j5_dead_names.
# ---------------------------------------------------------------------------

def taint_rules(java_source: str) -> list:
    from scanner.taint_engine import _scan_java_semantic
    with tempfile.TemporaryDirectory(prefix="rsx_tainttest_") as tmp:
        path = pathlib.Path(tmp, "T.java")
        path.write_text(java_source, encoding="utf-8")
        return [f for f in _scan_java_semantic(str(path), java_source)
                if f.get("rule_id", "").startswith("JAVA_TAINT_")]


_TAINT_PRELUDE = """import javax.servlet.http.HttpServletResponse;
import java.io.PrintWriter;

class T {
    void doGet(HttpServletResponse response) throws Exception {
"""


def test_taint_layer_overwrite_quiet():
    """The line layer's tainted dict is flow-insensitive and file-global;
    the shared dead-walk must still silence the overwritten variable."""
    src = _TAINT_PRELUDE + """        String param = request.getParameter("q");
        String out2 = param;
        out2 = "hardcoded-safe";
        response.getWriter().write("<p>" + out2 + "</p>");
    }
}
"""
    assert taint_rules(src) == []


def test_taint_layer_overwrite_fires():
    """One edit from the quiet negative: the last write is the source."""
    src = _TAINT_PRELUDE + """        String param = request.getParameter("q");
        String out2 = "safe";
        out2 = param;
        response.getWriter().write("<p>" + out2 + "</p>");
    }
}
"""
    ids = {f["rule_id"] for f in taint_rules(src)}
    assert "JAVA_TAINT_XSS" in ids


def test_taint_layer_direct_source_at_sink_fires():
    """A source expression directly in the sink args bypasses the
    name-based dead-set entirely and must keep firing."""
    src = _TAINT_PRELUDE + """        response.getWriter().write("<p>" + request.getParameter("q") + "</p>");
    }
}
"""
    ids = {f["rule_id"] for f in taint_rules(src)}
    assert "JAVA_TAINT_XSS" in ids


# ---------------------------------------------------------------------------
# 6. Class-correct sanitizer recognition (_JAVA_SANITIZERS / vuln-keyed walk).
#    BenchmarkJava: encodeForHTML/htmlEscape/escapeHtml sit between source
#    and sink in 28/53 JAVA_TAINT_XSS and 34/52 JAVA_J5_XSS negative tests.
# ---------------------------------------------------------------------------

_XSS_PRELUDE = """import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

class T {
    void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
"""


def xss_flows(java_source: str) -> list:
    """Run the full J5 project analysis, keeping only the J5 XSS sink."""
    with tempfile.TemporaryDirectory(prefix="rsx_j5xss_") as tmp:
        pathlib.Path(tmp, "T.java").write_text(java_source, encoding="utf-8")
        return [f for f in analyze_java_project(tmp)
                if f.get("rule_id") == "JAVA_J5_XSS"]


def test_j5_sanitized_value_is_quiet():
    """bar = encodeForHTML(param) then print(bar): the wrap is correct
    for xss, so the write kills exactly like a constant."""
    src = _XSS_PRELUDE + """        String param = request.getParameter("q");
        String bar = org.owasp.esapi.ESAPI.encoder().encodeForHTML(param);
        response.getWriter().print(bar);
    }
}
"""
    assert xss_flows(src) == []


def test_j5_unsanitized_twin_fires():
    """One edit from the quiet negative: the wrap is gone."""
    src = _XSS_PRELUDE + """        String param = request.getParameter("q");
        String bar = param;
        response.getWriter().print(bar);
    }
}
"""
    assert len(xss_flows(src)) >= 1


def test_j5_wrong_context_encoder_still_fires():
    """URL encoding is deliberately NOT an xss sanitizer (mirrors the
    Python table's urllib.parse.quote exclusion): javascript: and
    percent-sequences survive it."""
    src = _XSS_PRELUDE + """        String param = request.getParameter("q");
        String bar = java.net.URLEncoder.encode(param, "UTF-8");
        response.getWriter().print(bar);
    }
}
"""
    assert len(xss_flows(src)) >= 1


def test_j5_source_wrapped_at_declaration_is_quiet():
    """The source call sits INSIDE the wrap, so it is blanked before the
    source-resurrection check: the written value is encoded output."""
    src = _XSS_PRELUDE + """        String bar = org.owasp.esapi.ESAPI.encoder().encodeForHTML(
                request.getParameter("q"));
        response.getWriter().print(bar);
    }
}
"""
    assert xss_flows(src) == []


def test_taint_layer_sanitized_value_is_quiet():
    src = _TAINT_PRELUDE + """        String param = request.getParameter("q");
        String bar = org.springframework.web.util.HtmlUtils.htmlEscape(param);
        response.getWriter().write("<p>" + bar + "</p>");
    }
}
"""
    assert [f for f in taint_rules(src) if f["rule_id"] == "JAVA_TAINT_XSS"] == []


def test_taint_layer_unsanitized_twin_fires():
    src = _TAINT_PRELUDE + """        String param = request.getParameter("q");
        String bar = param;
        response.getWriter().write("<p>" + bar + "</p>");
    }
}
"""
    ids = {f["rule_id"] for f in taint_rules(src)}
    assert "JAVA_TAINT_XSS" in ids


# ---------------------------------------------------------------------------
# 7. Folded switch: a constant discriminant (``guess.charAt(1)``) executes
#    exactly one case group -- matching case, else default (javac). The
#    taken group's writes kill; untaken groups neither resurrect nor kill.
#    BenchmarkJava pathtraver negatives are built this way (00131/00136:
#    ``String guess = "ABC"; char switchTarget = guess.charAt(1);``).
# ---------------------------------------------------------------------------


def _switch_src(guess: str, cases: str) -> str:
    return _XSS_PRELUDE + f"""        String param = request.getParameter("q");
        String bar;
        String guess = "{guess}";
        char switchTarget = guess.charAt(1); // condition 'B', safe
        switch (switchTarget) {{
{cases}
        }}
        response.getWriter().print(bar);
    }}
}}
"""


_CASES_STANDARD = """            case 'A':
                bar = param;
                break;
            case 'B':
                bar = "bob";
                break;
            default:
                bar = "unknown";
                break;"""


def test_j5_folded_switch_const_group_kills():
    """guess="ABC" -> charAt(1)='B' -> only case 'B' runs -> bar is a
    constant at the sink. The trailing comment on the discriminant line
    must not refuse the fold (masked statements)."""
    assert xss_flows(_switch_src("ABC", _CASES_STANDARD)) == []


def test_j5_folded_switch_taken_tainted_fires():
    """One character from the quiet negative: guess="AAC" selects
    case 'A', whose body assigns the tainted param."""
    assert len(xss_flows(_switch_src("AAC", _CASES_STANDARD))) >= 1


def test_j5_folded_switch_untaken_group_after_taken_does_not_resurrect():
    """The untaken ``bar = param`` group comes AFTER the taken const
    group: a naive linear walk would let it undo the kill."""
    cases = """            case 'B':
                bar = "bob";
                break;
            case 'A':
                bar = param;
                break;"""
    assert xss_flows(_switch_src("ABC", cases)) == []


def test_j5_unfoldable_switch_still_fires():
    """Runtime discriminant: no group is provably taken, so no group
    kills and the tainted branch keeps the finding (conservative)."""
    src = _XSS_PRELUDE + """        String param = request.getParameter("q");
        String bar;
        switch (System.nanoTime()) {
            case 1:
                bar = param;
                break;
            default:
                bar = "unknown";
                break;
        }
        response.getWriter().print(bar);
    }
}
"""
    assert len(xss_flows(src)) >= 1


def test_taint_layer_folded_switch_quiet():
    """The line layers share the walk: flow-insensitive taint sees bar
    tainted from case 'A', the dead-walk proves only case 'B' runs."""
    src = _TAINT_PRELUDE + """        String param = request.getParameter("q");
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
                bar = "unknown";
                break;
        }
        response.getWriter().write("<p>" + bar + "</p>");
    }
}
"""
    assert [f for f in taint_rules(src)
            if f["rule_id"] == "JAVA_TAINT_XSS"] == []


# ---------------------------------------------------------------------------
# 8. Sink-local argument extraction: the sink finding takes the argument
#    list of the MATCHED call, not the first/last paren of the statement.
#    "r.exec(args, env, new java.io.File(user.dir))" used to hand the File
#    sink exec's tainted args (misattributed CWE-22 on cmdi tests).
# ---------------------------------------------------------------------------

def path_flows(java_source: str) -> list:
    """Run the full J5 project analysis, keeping only the J5 path sink."""
    with tempfile.TemporaryDirectory(prefix="rsx_j5path_") as tmp:
        pathlib.Path(tmp, "T.java").write_text(java_source, encoding="utf-8")
        return [f for f in analyze_java_project(tmp)
                if f.get("rule_id") == "JAVA_J5_PATH"]


def test_j5_sibling_call_taint_does_not_bleed_into_file_sink():
    """bar is tainted, but only in exec's argument list; the File sink's
    own argument is System.getProperty("user.dir") -- no path finding."""
    src = _XSS_PRELUDE + """        String param = request.getParameter("q");
        String bar = param;
        String[] args = {"ping", "-n", "1"};
        Runtime r = Runtime.getRuntime();
        r.exec(args, bar, new java.io.File(System.getProperty("user.dir")));
    }
}
"""
    assert path_flows(src) == []


def test_j5_taint_inside_file_args_still_fires():
    """Tight extraction must not over-tighten: taint in the File call's
    own argument list still fires the path sink."""
    src = _XSS_PRELUDE + """        String param = request.getParameter("q");
        String bar = param;
        java.io.File f = new java.io.File(
                org.owasp.benchmark.helpers.Utils.TESTFILES_DIR + bar);
    }
}
"""
    assert len(path_flows(src)) >= 1


def test_j5_paren_inside_string_literal_does_not_truncate_args():
    """The balanced close is quote-aware: a '(' inside a string literal
    must not end the argument scan before bar is seen."""
    src = _XSS_PRELUDE + """        String param = request.getParameter("q");
        String bar = param;
        java.io.File f = new java.io.File("(" + bar);
    }
}
"""
    assert len(path_flows(src)) >= 1


# ---------------------------------------------------------------------------
# 9. Sanitizer wrap DIRECTLY at the sink: the assignment-side walk never
#    sees it, so the sink extraction must blank the wrap itself. Plus the
#    commons-lang `escapeHtml` table entry (00389) and its unescaper twin.
# ---------------------------------------------------------------------------

def test_j5_sink_direct_sanitizer_is_quiet():
    # Single line deliberately: a non-assignment line yields as its own
    # (possibly unbalanced) statement, and empty args would make this
    # pass vacuously instead of exercising the sink-side blanking.
    src = _XSS_PRELUDE + """        String param = request.getParameter("q");
        response.getWriter().print(org.owasp.esapi.ESAPI.encoder().encodeForHTML(param));
    }
}
"""
    assert xss_flows(src) == []


def test_j5_sink_unsanitized_twin_fires():
    src = _XSS_PRELUDE + """        String param = request.getParameter("q");
        response.getWriter().print(param);
    }
}
"""
    assert len(xss_flows(src)) >= 1


def test_taint_layer_sink_direct_sanitizer_is_quiet():
    src = _TAINT_PRELUDE + """        String param = request.getParameter("q");
        response.getWriter().write(org.owasp.esapi.ESAPI.encoder().encodeForHTML(param));
    }
}
"""
    assert [f for f in taint_rules(src)
            if f["rule_id"] == "JAVA_TAINT_XSS"] == []


def test_taint_layer_sink_unsanitized_twin_fires():
    src = _TAINT_PRELUDE + """        String param = request.getParameter("q");
        response.getWriter().write(param);
    }
}
"""
    assert "JAVA_TAINT_XSS" in {f["rule_id"] for f in taint_rules(src)}


def test_commons_lang_escapeHtml_kills_for_both_layers():
    """00389: org.apache.commons.lang.StringEscapeUtils.escapeHtml --
    the plain name, neither [34]."""
    src = _XSS_PRELUDE + """        String param = request.getParameter("q");
        String bar = org.apache.commons.lang.StringEscapeUtils.escapeHtml(param);
        response.getWriter().println(bar);
    }
}
"""
    assert xss_flows(src) == []
    assert [f for f in taint_rules(src)
            if f["rule_id"] == "JAVA_TAINT_XSS"] == []


def test_unescapeHtml_does_not_kill():
    """An unescaper is the opposite of a sanitizer: the table pattern
    must not match escapeHtml inside unescapeHtml."""
    src = _XSS_PRELUDE + """        String param = request.getParameter("q");
        String bar = org.apache.commons.lang.StringEscapeUtils.unescapeHtml(param);
        response.getWriter().println(bar);
    }
}
"""
    assert len(xss_flows(src)) >= 1
    assert "JAVA_TAINT_XSS" in {f["rule_id"] for f in taint_rules(src)}


# ---------------------------------------------------------------------------
# 10. File-local call knowledge for the line layer
#     (_j5_file_call_knowledge): the helper decides, the caller's
#     sink receives.  BenchmarkJava's dominant JAVA_TAINT_XSS negatives
#     (01053 folded ternary, 01048/01659 helper-contained htmlEscape)
#     put the fold or the escape INSIDE doSomething; the J5 layer had
#     safe_calls for them, the line layer was called with None.
# ---------------------------------------------------------------------------

_TAINT_CALLER = """        String param = request.getParameter("q");
        String bar = new Test().doSomething(request, param);
        response.getWriter().println(bar);
    }

"""

_TAINT_FOLDED = """    private class Test {
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

_TAINT_PASSTHROUGH = """    private class Test {
        public String doSomething(HttpServletRequest request, String param) {
            String bar;
            bar = param;
            return bar;
        }
    }
}
"""

_TAINT_SANITIZE = """    private class Test {
        public String doSomething(HttpServletRequest request, String param) {
            String bar = org.apache.commons.lang.StringEscapeUtils.escapeHtml(param);
            return bar;
        }
    }
}
"""

_KNOWN = ("doSomething", 2)


def test_file_knowledge_fold_helper_is_safe_everywhere():
    from scanner.java_semantic_j5 import _j5_file_call_knowledge
    safe, san = _j5_file_call_knowledge(_TAINT_PRELUDE + _TAINT_CALLER + _TAINT_FOLDED)
    assert _KNOWN in safe
    # Agnostic-clean implies clean for every class.
    assert _KNOWN in san["xss"]


def test_file_knowledge_passthrough_helper_knows_nothing():
    from scanner.java_semantic_j5 import _j5_file_call_knowledge
    safe, san = _j5_file_call_knowledge(
        _TAINT_PRELUDE + _TAINT_CALLER + _TAINT_PASSTHROUGH)
    assert _KNOWN not in safe
    assert _KNOWN not in san["xss"]


def test_file_knowledge_sanitizer_helper_is_xss_only():
    """htmlEscape drops taint for xss and only for xss: path traversal
    must keep the helper's return live."""
    from scanner.java_semantic_j5 import _j5_file_call_knowledge
    safe, san = _j5_file_call_knowledge(
        _TAINT_PRELUDE + _TAINT_CALLER + _TAINT_SANITIZE)
    assert _KNOWN not in safe
    assert _KNOWN in san["xss"]


def test_taint_layer_fold_helper_return_is_quiet():
    """01053: the fold lives in the callee; the caller's println(bar)
    must be quieted by the callee's dead-refined returns."""
    src = _TAINT_PRELUDE + _TAINT_CALLER + _TAINT_FOLDED
    assert [f for f in taint_rules(src)
            if f["rule_id"] == "JAVA_TAINT_XSS"] == []


def test_taint_layer_fold_helper_twin_fires():
    """One edit in the helper: it returns its parameter."""
    src = _TAINT_PRELUDE + _TAINT_CALLER + _TAINT_PASSTHROUGH
    assert "JAVA_TAINT_XSS" in {f["rule_id"] for f in taint_rules(src)}


def test_taint_layer_sanitizer_helper_return_is_quiet():
    """01048/01659: htmlEscape sits in the callee's return path."""
    src = _TAINT_PRELUDE + _TAINT_CALLER + _TAINT_SANITIZE
    assert [f for f in taint_rules(src)
            if f["rule_id"] == "JAVA_TAINT_XSS"] == []


def test_taint_layer_sanitizer_helper_twin_fires():
    """The unsanitized callee keeps firing."""
    src = _TAINT_PRELUDE + _TAINT_CALLER + _TAINT_PASSTHROUGH
    assert "JAVA_TAINT_XSS" in {f["rule_id"] for f in taint_rules(src)}


def test_taint_layer_sanitizer_helper_still_taints_path_sink():
    """Per-vuln guard: the SAME htmlEscape helper cannot silence a path
    sink -- the knowledge union is rebuilt with the sink's class, and
    'xss' is the only class the helper proved."""
    src = _TAINT_PRELUDE + """        String param = request.getParameter("q");
        String bar = new Test().doSomething(request, param);
        java.nio.file.Path p = java.nio.file.Paths.get(org.owasp.benchmark.helpers.Utils.TESTFILES_DIR + bar);
    }

""" + _TAINT_SANITIZE
    assert "JAVA_TAINT_PATH_TRAVERSAL" in {
        f["rule_id"] for f in taint_rules(src)}


# ---------------------------------------------------------------------------
# 11. The inline-control assignment strip (_j5_inline_assignment): a write
#     behind ``if (cond)`` / ``else`` on ONE line must keep the callee's
#     return -- and therefore the caller's sink -- alive. Without it the
#     main loop never tainted the local, returns looked empty, and
#     knowledge called the helper clean (01179: knowledge killed a real
#     flow that only J5's different scope happened to keep reporting).
# ---------------------------------------------------------------------------

_TAINT_INLINE_IF_HELPER = """    private class Test {
        public String doSomething(HttpServletRequest request, String param) {
            String bar = "";
            if (param != null) bar = param.split(" ")[0];
            return bar;
        }
    }
}
"""


def test_file_knowledge_inline_if_helper_knows_nothing():
    from scanner.java_semantic_j5 import _j5_file_call_knowledge
    safe, san = _j5_file_call_knowledge(
        _TAINT_PRELUDE + _TAINT_CALLER + _TAINT_INLINE_IF_HELPER)
    assert _KNOWN not in safe
    assert _KNOWN not in san["xss"]


def test_taint_layer_inline_if_helper_return_fires():
    """The same helper, end to end: the split still carries the payload
    (01179 is an xss POSITIVE -- a space-free payload survives)."""
    src = _TAINT_PRELUDE + _TAINT_CALLER + _TAINT_INLINE_IF_HELPER
    assert "JAVA_TAINT_XSS" in {f["rule_id"] for f in taint_rules(src)}


def test_folded_inline_if_else_helper_still_quiet():
    """Strip must not break the fold: when the condition folds TRUE the
    else-write is dead code and the helper still returns a constant."""
    src = _TAINT_PRELUDE + _TAINT_CALLER + """    private class Test {
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
    assert [f for f in taint_rules(src)
            if f["rule_id"] == "JAVA_TAINT_XSS"] == []
