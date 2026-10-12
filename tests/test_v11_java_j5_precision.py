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
