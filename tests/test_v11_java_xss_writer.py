"""F6 (recall batch): response-writer VARIABLE sinks (CWE-79).

findings21 leaves exactly 9 xss true tests silent (237/246).  Every one of
the nine writes to the HTTP response through a *writer variable*:

    Object[] obj = {"a", bar};
    java.io.PrintWriter out = response.getWriter();
    out.format(java.util.Locale.US, "Formatted like: %1$s and %2$s.", obj);

while all 244 detected xss tests call the chained form
`response.getWriter().print(...)` directly.  Both the line layer's xss sink
and J4's only match the chained form, so a file whose response output goes
through a declared `PrintWriter out` has NO xss sink at all -- the carrier
chain is irrelevant because nothing ever looks at it.

This fix collects the file's response-writer variables
(`PrintWriter <name> = response.getWriter()`) and admits
`<name>.print|println|printf|format|write(...)` as an xss sink for THAT
file.  The receiver must be a declared response writer, so
`formatter.format(...)`, `String.format(...)` and every other receiver stay
exactly as dark as before; `System.out.print(...)` is textually excluded
even when a local `out` writer exists (its receiver is `System.out`, not
the writer).  Argument-aware reporting, the order-aware dead-name walk and
the severed-chain kill all apply unchanged -- a constant argument, a folded
carrier or a provably-constant last write still stays dark.

Red-first protocol: with the sink change stashed, the four TP tests must
FAIL (the measured detection failure); the four controls -- constant
argument, non-writer receiver, System.out while a writer exists, constant
last write through the array carrier -- must PASS in both phases.
"""
from __future__ import annotations

import pathlib
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scanner.taint_engine import analyze_file  # noqa: E402

PRELUDE = """import java.util.List;
import java.util.ArrayList;
import java.util.Map;
import java.util.HashMap;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
"""

XSS_RULE = "cwe-79"


def cwes(java_source: str, cwe: str) -> list:
    with tempfile.TemporaryDirectory(prefix="rsx_f6_") as tmp:
        p = pathlib.Path(tmp) / "T.java"
        p.write_text(PRELUDE + java_source, encoding="utf-8")
        return [f for f in (analyze_file(str(p)) or [])
                if str(f.get("cwe") or "").lower() == cwe]


# --- TP shapes (RED before the writer-variable sink) -----------------------

def test_tpd_writer_format_list_array_carrier_fires():
    """BenchmarkTest00711: values[0] -> list add/get -> Object[] -> out.format."""
    src = """
class T {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) {
        String[] values = request.getParameterValues("BenchmarkTest00711");
        String param;
        if (values != null && values.length > 0) param = values[0];
        else param = "";
        String bar = "";
        if (param != null) {
            java.util.List<String> valuesList = new java.util.ArrayList<String>();
            valuesList.add(param);
            bar = valuesList.get(0);
        }
        Object[] obj = {"a", bar};
        java.io.PrintWriter out = response.getWriter();
        out.format(java.util.Locale.US, "Formatted like: %1$s and %2$s.", obj);
    }
}
"""
    assert cwes(src, XSS_RULE), "writer-var format (list+array carrier) stayed dark"


def test_tpd_writer_format_crossmethod_map_carrier_fires():
    """BenchmarkTest01335: helper map put/get -> bar -> Object[] -> out.format."""
    src = """
class T {
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws Exception {
        String[] values = request.getParameterValues("BenchmarkTest01335");
        String param = "";
        if (values != null) param = values[0];
        String bar = new Test().doSomething(request, param);
        Object[] obj = {"a", bar};
        java.io.PrintWriter out = response.getWriter();
        out.format(java.util.Locale.US, "Formatted like: %1$s and %2$s.", obj);
    }

    public static class Test {
        public String doSomething(HttpServletRequest request, String param) {
            java.util.Map<String, String> map45376 = new java.util.HashMap<String, String>();
            String bar = "safe!";
            map45376.put("keyB-45376", param);
            bar = (String) map45376.get("keyB-45376");
            return bar;
        }
    }
}
"""
    assert cwes(src, XSS_RULE), "writer-var format (cross-method map) stayed dark"


def test_tpd_writer_format_plain_bar_fires():
    """BenchmarkTest02221: helper StringBuilder replace -> bar -> out.format."""
    src = """
class T {
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws Exception {
        String[] values = request.getParameterValues("BenchmarkTest02221");
        String param = "";
        if (values != null) param = values[0];
        String bar = doSomething(request, param);
        Object[] obj = {"a", bar};
        java.io.PrintWriter out = response.getWriter();
        out.format(java.util.Locale.US, "Formatted like: %1$s and %2$s.", obj);
    }

    private static String doSomething(HttpServletRequest request, String param) {
        String bar = param;
        if (param != null && param.length() > 1) {
            StringBuilder sbxyz71523 = new StringBuilder(param);
            bar = sbxyz71523.replace(param.length() - "Z".length(), param.length(), "Z").toString();
        }
        return bar;
    }
}
"""
    assert cwes(src, XSS_RULE), "writer-var format (plain bar) stayed dark"


def test_tpd_writer_println_bar_fires():
    """Same sink family, the println verb: declared writer, direct carrier."""
    src = """
class T {
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws Exception {
        String param = request.getParameter("x");
        String bar = param;
        java.io.PrintWriter out = response.getWriter();
        out.println(bar);
    }
}
"""
    assert cwes(src, XSS_RULE), "writer-var println stayed dark"


# --- Controls (must PASS in both red and green phases) ---------------------

def test_tn_writer_format_const_arg_stays_dark():
    """Declared writer, but the formatted argument is a literal."""
    src = """
class T {
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws Exception {
        String param = request.getParameter("x");
        java.io.PrintWriter out = response.getWriter();
        out.format(java.util.Locale.US, "Formatted like: %1$s and %2$s.", "safe_const_913755");
        out.println("static footer");
    }
}
"""
    assert not cwes(src, XSS_RULE), "constant format argument must stay dark"


def test_tn_nonwriter_receiver_format_stays_dark():
    """java.util.Formatter.format is not response output -- receiver gate."""
    src = """
class T {
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws Exception {
        String param = request.getParameter("x");
        java.util.Formatter fmt = new java.util.Formatter(response.getOutputStream());
        fmt.format("%s", param);
    }
}
"""
    assert not cwes(src, XSS_RULE), "non-writer receiver must stay dark"


def test_tn_system_out_print_with_writer_present_stays_dark():
    """System.out.print shadows the local writer name textually, not really."""
    src = """
class T {
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws Exception {
        String param = request.getParameter("x");
        java.io.PrintWriter out = response.getWriter();
        System.out.print(param);
    }
}
"""
    assert not cwes(src, XSS_RULE), "System.out.print must stay dark"


def test_tn_writer_format_const_last_write_stays_dark():
    """Carrier proven constant before the sink: dead-name kill must hold."""
    src = """
class T {
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws Exception {
        String param = request.getParameter("x");
        String bar = param;
        bar = "safe_const_552018";
        Object[] obj = {"a", bar};
        java.io.PrintWriter out = response.getWriter();
        out.format(java.util.Locale.US, "Formatted like: %1$s and %2$s.", obj);
    }
}
"""
    assert not cwes(src, XSS_RULE), "const last write through array carrier must stay dark"
