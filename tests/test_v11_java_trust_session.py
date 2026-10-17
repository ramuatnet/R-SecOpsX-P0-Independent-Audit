"""F1 (recall batch): session-store trust-boundary sinks (CWE-501).

The BenchmarkJava oracle labels 71 of 83 trust-boundary true tests silent in
findings20.  Every miss stores request-derived data in the HTTP session:

    request.getSession().putValue("userid", param);     // value position
    request.getSession().putValue(bar, "10340");        // key position
    request.getSession().setAttribute("userid", bar);   // value position
    request.getSession().setAttribute(bar, "10340");    // key position

Only `X.getSession().setAttribute(IDENT, ...)` (key position alone) was
modeled, and only in the J3 layer -- `putValue` and the value position had
no sink at all, so 45 putValue + 26 setAttribute oracle-positives stayed
dark.  This fix adds the session-store sink to the line layer, whose generic
argument scan reads BOTH argument positions and whose order-aware dead-name
walk (shared with J4/J5) still kills a carrier whose last write before the
sink is provably constant.

The header-name fixtures exposed a second gap in that walk: its
resurrection table (_J5_SOURCE_RE / _SOURCE_RE in java_semantic_j5.py)
knew every request-source family EXCEPT getHeaderNames, so
`headers = request.getHeaderNames()` was committed as a constant-safe
write and the entire downstream chain died at the sink filter.  The two
tables now include it, mirroring _JAVA_SOURCE_PATTERNS -- resurrecting a
real source is recall, never a weakening of any kill.

Red-first protocol: with the sink stashed, the five TP tests must FAIL
(miss = the measured detection failure); the four controls -- constant last
write, folded ternary, cross-method const return, sanitized-then-const --
must PASS in both phases.
"""
from __future__ import annotations

import pathlib
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scanner.taint_engine import analyze_file  # noqa: E402

PRELUDE = """import java.util.Map;
import java.util.List;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import javax.servlet.http.HttpServletRequest;
"""

TRUST_RULE = "cwe-501"


def cwes(java_source: str, cwe: str) -> list:
    with tempfile.TemporaryDirectory(prefix="rsx_f1_") as tmp:
        p = pathlib.Path(tmp) / "T.java"
        p.write_text(PRELUDE + java_source, encoding="utf-8")
        return [f for f in (analyze_file(str(p)) or [])
                if str(f.get("cwe") or "").lower() == cwe]


# --- TP shapes (RED before the session-store sink) -------------------------

def test_tpd_putvalue_value_position_fires():
    """BenchmarkTest00031: values[0] via if-prefix -> putValue value arg."""
    src = """
class T {
    public void doPost(HttpServletRequest request) throws Exception {
        String[] values = request.getParameterValues("BenchmarkTest00031");
        String param = "";
        if (values != null) param = values[0];
        request.getSession().putValue("userid", param);
    }
}
"""
    assert cwes(src, TRUST_RULE), "putValue value position stayed dark"


def test_tpd_putvalue_key_position_fires():
    """BenchmarkTest00321: header-name source -> escape -> putValue key arg."""
    src = """
class T {
    public void doPost(HttpServletRequest request) throws Exception {
        String param = "";
        Enumeration<String> headers = request.getHeaderNames();
        if (headers != null) {
            param = headers.nextElement();
        }
        param = java.net.URLDecoder.decode(param, "UTF-8");
        String bar = org.apache.commons.lang.StringEscapeUtils.escapeHtml(param);
        request.getSession().putValue(bar, "10340");
    }
}
"""
    assert cwes(src, TRUST_RULE), "putValue key position stayed dark"


def test_tpd_setattribute_value_position_fires():
    """BenchmarkTest00324: htmlEscape(param) -> setAttribute value arg."""
    src = """
class T {
    public void doPost(HttpServletRequest request) throws Exception {
        String param = "";
        Enumeration<String> headers = request.getHeaderNames();
        if (headers != null) {
            param = headers.nextElement();
        }
        param = java.net.URLDecoder.decode(param, "UTF-8");
        String bar = org.springframework.web.util.HtmlUtils.htmlEscape(param);
        request.getSession().setAttribute("userid", bar);
    }
}
"""
    assert cwes(src, TRUST_RULE), "setAttribute value position stayed dark"


def test_tpd_setattribute_conditional_key_fires():
    """BenchmarkTest00326: folded-TRUE if/else bar as setAttribute key."""
    src = """
class T {
    public void doPost(HttpServletRequest request) throws Exception {
        int num = 196;
        String param = "";
        Enumeration<String> headers = request.getHeaderNames();
        if (headers != null) {
            param = headers.nextElement();
        }
        param = java.net.URLDecoder.decode(param, "UTF-8");
        String bar;
        if ((500 / 42) + num > 200) bar = param;
        else bar = "This should never happen";
        request.getSession().setAttribute(bar, "10340");
    }
}
"""
    assert cwes(src, TRUST_RULE), "conditional key carrier stayed dark"


def test_tpd_foreach_cookie_putvalue_fires():
    """BenchmarkTest00098: for-each cookies -> decode -> escape -> value arg."""
    src = """
class T {
    public void doPost(HttpServletRequest request) throws Exception {
        String param = "noCookieValueSupplied";
        javax.servlet.http.Cookie[] theCookies = request.getCookies();
        if (theCookies != null) {
            for (javax.servlet.http.Cookie theCookie : theCookies) {
                if (theCookie.getName().equals("BenchmarkTest00098")) {
                    param = java.net.URLDecoder.decode(theCookie.getValue(), "UTF-8");
                    break;
                }
            }
        }
        String bar = org.apache.commons.lang.StringEscapeUtils.escapeHtml(param);
        request.getSession().putValue("userid", bar);
    }
}
"""
    assert cwes(src, TRUST_RULE), "for-each cookie -> putValue stayed dark"


# --- Controls (must PASS in both red and green phases) --------------------

def test_tn_const_last_write_stays_dark():
    """bar overwritten with a constant before the session store."""
    src = """
class T {
    public void doPost(HttpServletRequest request) throws Exception {
        String param = request.getParameter("x");
        String bar = param;
        bar = "safe_const_771204";
        request.getSession().putValue("userid", bar);
    }
}
"""
    assert not cwes(src, TRUST_RULE), "const last write must stay dark"


def test_tn_folded_ternary_stays_dark():
    """(7*42)-num>200 with num=10 folds TRUE -> constant branch stored."""
    src = """
class T {
    public void doPost(HttpServletRequest request) throws Exception {
        int num = 10;
        String param = request.getParameter("x");
        String bar = (7 * 42) - num > 200 ? "bobs_your_uncle" : param;
        request.getSession().setAttribute("userid", bar);
    }
}
"""
    assert not cwes(src, TRUST_RULE), "folded ternary must stay dark"


def test_tn_crossmethod_const_return_stays_dark():
    """Callee's last write is a constant, so the stored value is safe."""
    src = """
class T {
    public void doPost(HttpServletRequest request) throws Exception {
        String param = request.getParameter("x");
        String bar = new Test().doSomething(request, param);
        request.getSession().setAttribute("userid", bar);
    }

    public static class Test {
        public String doSomething(HttpServletRequest request, String param) {
            String bar = param;
            bar = "safe_const_884312";
            return bar;
        }
    }
}
"""
    assert not cwes(src, TRUST_RULE), "cross-method const return must stay dark"


def test_tn_sanitized_then_const_stays_dark():
    """escapeHtml chain that provably ends in a constant store."""
    src = """
class T {
    public void doPost(HttpServletRequest request) throws Exception {
        String param = request.getParameter("x");
        String bar = org.apache.commons.lang.StringEscapeUtils.escapeHtml(param);
        bar = "safe_const_330159";
        request.getSession().putValue("userid", bar);
    }
}
"""
    assert not cwes(src, TRUST_RULE), "sanitized-then-const must stay dark"
