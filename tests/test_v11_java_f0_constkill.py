"""F0 (precision batch): const-prop kills for the 7 remaining FP rows.

findings22 still reports 7 oracle-negative rows (fpF 7, fpRate 0.5%):

  JAVA_J4_XSS            4  01051/01176/01265/02048
  JAVA_TAINT_XSS         2  01479/02370 (xpathi negatives)
  JAVA_J3_TRUST_BOUNDARY 1  01207

All seven are provably safe flows the shared order-aware walk
(``_j5_dead_names``) ALREADY proves dead -- but three emitters never ask:

1. J3's dedicated session-store loop
   (`X.getSession().setAttribute(IDENT, ...)`) emits from its
   flow-insensitive dict with no dead-refine, so 01207's ``bar`` -- whose
   helper's last write reads an untouched map key -- survives there while
   the line layer correctly kills it.
2. J4 never consults the walk at all; its E1 proven-constant gate cannot
   see through the array carrier (``obj``) or the ``bar.length()`` alias,
   so its four folded-helper flows keep firing -- and J4_XSS has ZERO rows
   on positives, only these four negatives.
3. The walk itself cannot kill the 01479/02370 result-node carrier:
   ``org.w3c.dom.Element value = nodeList.item(i)`` sits in a for-frame
   (resurrect-only), and the name ``value`` stays live in the
   flow-insensitive dict from a DISJOINT earlier binding
   (``String value = values[i]`` in the parameter loop).  Both names are
   legal Java -- sibling scopes -- but the walk is name-based, so the
   live String binding leaks into the Element binding.  Fix: a
   DECLARATION whose initializer carries no live taint (and no source)
   records a scope-guarded kill candidate that applies only when the sink
   lies inside the declaration's own frame stack.  Every later write to
   the name supersedes the candidate, so the last-write discipline is
   preserved; a sink outside the frame simply keeps its name (conservative
   direction).  In legal Java a nested same-name declaration while the
   outer binding is in scope does not compile, so a candidate can only
   describe the binding the sink actually sees.

Kill-only discipline: every new kill requires proof (no live taint in the
initializer, no request source, sink inside the declaration's scope).  No
rule is weakened, no finding suppressed without proof.

Red-first protocol: the six FP tests must FAIL before the fixes (the
measured row reproduces); the four true-positive guards -- passthrough
helper, folded-TRUE tainted branch, direct session store, live result-loop
carrier -- must PASS in both phases.
"""
from __future__ import annotations

import pathlib
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scanner.taint_engine import analyze_file  # noqa: E402

PRELUDE = """import java.util.Map;
import java.util.HashMap;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
"""


def cwes(java_source: str, cwe: str) -> list:
    with tempfile.TemporaryDirectory(prefix="rsx_f0_") as tmp:
        p = pathlib.Path(tmp) / "T.java"
        p.write_text(PRELUDE + java_source, encoding="utf-8")
        return [f for f in (analyze_file(str(p)) or [])
                if str(f.get("cwe") or "").lower() == cwe]


# --- FP reproductions (RED before the F0 fixes) ----------------------------

def test_f0_j4_ternary_fold_printf_dark():
    """01051: helper ternary folds to a constant (num=106 -> 232 > 200)."""
    src = """
class T {
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws Exception {
        String param = "";
        if (request.getHeader("Referer") != null) {
            param = request.getHeader("Referer");
        }
        param = java.net.URLDecoder.decode(param, "UTF-8");
        String bar = new Test().doSomething(request, param);
        Object[] obj = {bar, "b"};
        response.getWriter().printf("Formatted like: %1$s and %2$s.", obj);
    }

    public static class Test {
        public String doSomething(HttpServletRequest request, String param) {
            String bar;
            int num = 106;
            bar = (7 * 18) + num > 200 ? "This_should_always_happen" : param;
            return bar;
        }
    }
}
"""
    assert not cwes(src, "cwe-79"), "folded-ternary helper must stay dark"


def test_f0_j4_switch_fold_printf_dark():
    """01176: switch discriminant 'B' folds to the constant branch."""
    src = """
class T {
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws Exception {
        String param = "";
        java.util.Enumeration<String> headers = request.getHeaders("Referer");
        if (headers != null && headers.hasMoreElements()) {
            param = headers.nextElement();
        }
        param = java.net.URLDecoder.decode(param, "UTF-8");
        String bar = new Test().doSomething(request, param);
        Object[] obj = {"a", bar};
        response.getWriter().printf(java.util.Locale.US, "Formatted like: %1$s and %2$s.", obj);
    }

    public static class Test {
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
                case 'C':
                case 'D':
                    bar = param;
                    break;
                default:
                    bar = "bob's your uncle";
                    break;
            }
            return bar;
        }
    }
}
"""
    assert not cwes(src, "cwe-79"), "folded-switch helper must stay dark"


def test_f0_j4_ifelse_fold_write_dark():
    """01265: folded if/else helper -> bar.length() alias -> write(...)."""
    src = """
class T {
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws Exception {
        String param = request.getParameter("BenchmarkTest01265");
        if (param == null) param = "";
        String bar = new Test().doSomething(request, param);
        int length = -1;
        if (bar != null) {
            length = bar.length();
            response.getWriter().write(bar.toCharArray(), 0, length);
        }
    }

    public static class Test {
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
    assert not cwes(src, "cwe-79"), "folded if/else helper must stay dark"


def test_f0_j4_reflection_const_dark():
    """02048: propagator chain whose RETURN actually uses a constant."""
    src = """
class T {
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws Exception {
        String param = "";
        java.util.Enumeration<String> headers = request.getHeaders("Referer");
        if (headers != null && headers.hasMoreElements()) {
            param = headers.nextElement();
        }
        param = java.net.URLDecoder.decode(param, "UTF-8");
        String bar = doSomething(request, param);
        Object[] obj = {"a", bar};
        response.getWriter().printf(java.util.Locale.US, "Formatted like: %1$s and %2$s.", obj);
    }

    private static String doSomething(HttpServletRequest request, String param) {
        String a96053 = param;
        StringBuilder b96053 = new StringBuilder(a96053);
        b96053.append(" SafeStuff");
        String g96053 = "barbarians_at_the_gate";
        String bar = new Thing().doSomething(g96053);
        return bar;
    }

    public static class Thing {
        public String doSomething(String in) { return in; }
    }
}
"""
    assert not cwes(src, "cwe-79"), "const-reflection helper must stay dark"


def test_f0_line_xpath_node_collision_dark():
    """01479: disjoint-scope `value` name collision -> result-node print."""
    src = """
class T {
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws Exception {
        String param = "";
        boolean flag = true;
        java.util.Enumeration<String> names = request.getParameterNames();
        while (names.hasMoreElements() && flag) {
            String name = (String) names.nextElement();
            String[] values = request.getParameterValues(name);
            if (values != null) {
                for (int i = 0; i < values.length && flag; i++) {
                    String value = values[i];
                    if (value.equals("BenchmarkTest01479")) {
                        param = name;
                        flag = false;
                    }
                }
            }
        }
        String bar = new Test().doSomething(request, param);
        try {
            javax.xml.xpath.XPathFactory xpf = javax.xml.xpath.XPathFactory.newInstance();
            javax.xml.xpath.XPath xp = xpf.newXPath();
            String expression = "/Employees/Employee[@emplid='" + bar + "']";
            org.w3c.dom.NodeList nodeList =
                    (org.w3c.dom.NodeList)
                            xp.compile(expression)
                                    .evaluate(null, javax.xml.xpath.XPathConstants.NODESET);
            for (int i = 0; i < 1; i++) {
                org.w3c.dom.Element value = (org.w3c.dom.Element) nodeList.item(i);
                response.getWriter().println(value.getTextContent() + "<br/>");
            }
        } catch (Exception e) {
            throw new ServletException(e);
        }
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
    assert not cwes(src, "cwe-79"), "result-node print with folded helper must stay dark"


def test_f0_j3_session_after_folded_map_dark():
    """01207: helper's last write reads an untouched map key (null)."""
    src = """
class T {
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws Exception {
        String param = "";
        java.util.Enumeration<String> headers = request.getHeaders("BenchmarkTest01207");
        if (headers != null && headers.hasMoreElements()) {
            param = headers.nextElement();
        }
        param = java.net.URLDecoder.decode(param, "UTF-8");
        String bar = new Test().doSomething(request, param);
        request.getSession().setAttribute(bar, "10340");
    }

    public static class Test {
        public String doSomething(HttpServletRequest request, String param) {
            java.util.Map<String, String> map95902 = new java.util.HashMap<String, String>();
            String bar = "safe!";
            map95902.put("keyB-95902", param);
            bar = (String) map95902.get("keyB-95902");
            bar = (String) map95902.get("keyA-95902");
            return bar;
        }
    }
}
"""
    assert not cwes(src, "cwe-501"), "session store after untouched-key read must stay dark"


# --- True-positive guards (must PASS in both phases) -----------------------

def test_tp_helper_passthrough_printf_still_detected():
    """Helper returns its tainted argument: the flow is real."""
    src = """
class T {
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws Exception {
        String param = request.getParameter("x");
        String bar = new Test().doSomething(request, param);
        Object[] obj = {"a", bar};
        response.getWriter().printf(java.util.Locale.US, "Formatted like: %1$s.", obj);
    }

    public static class Test {
        public String doSomething(HttpServletRequest request, String param) {
            String bar = param;
            return bar;
        }
    }
}
"""
    assert cwes(src, "cwe-79"), "passthrough helper must stay detected"


def test_tp_folded_true_tainted_branch_still_detected():
    """Folded-TRUE branch IS the tainted write: proof keeps the finding."""
    src = """
class T {
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws Exception {
        String param = request.getParameter("x");
        String bar = new Test().doSomething(request, param);
        response.getWriter().println(bar);
    }

    public static class Test {
        public String doSomething(HttpServletRequest request, String param) {
            String bar;
            int num = 10;
            if ((7 * 42) - num > 200) bar = param;
            else bar = "This_should_never_run";
            return bar;
        }
    }
}
"""
    assert cwes(src, "cwe-79"), "folded-TRUE tainted branch must stay detected"


def test_tp_session_param_still_detected():
    """Direct tainted session store keeps its finding after the J3 refine."""
    src = """
class T {
    protected void doPost(HttpServletRequest request) throws Exception {
        String param = request.getParameter("x");
        request.getSession().setAttribute("userid", param);
    }
}
"""
    assert cwes(src, "cwe-501"), "direct session store must stay detected"


def test_tp_result_loop_live_carrier_still_detected():
    """Declaration initializer WITH live taint: no kill candidate exists."""
    src = """
class T {
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws Exception {
        String[] values = request.getParameterValues("x");
        if (values != null) {
            for (int i = 0; i < values.length; i++) {
                String v = values[i];
                response.getWriter().println(v);
            }
        }
    }
}
"""
    assert cwes(src, "cwe-79"), "live result-loop carrier must stay detected"
