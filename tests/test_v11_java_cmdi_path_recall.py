"""F4/F5 (recall batch): ProcessBuilder constructor carriers + header-name sources.

The BenchmarkJava oracle labels 20 command-injection and 12 path-traversal
true tests silent in findings19.  Measured miss shapes:

F4 cmdi (all route through ``new ProcessBuilder(list/array)`` or a
parameterMap/parameterNames source before ``pb.start()``/``pb.command``):

    argList.add("echo " + bar);
    ProcessBuilder pb = new ProcessBuilder(argList);   <- no builder state
    Process p = pb.start();

    Map<String, String[]> map = request.getParameterMap();   <- source absent
    String[] values = map.get("BenchmarkTest00480");

    m.put("keyB", param);  bar = (String) m.get("keyB");     <- element model
    valuesList.add(param); bar = valuesList.get(0);          <- index model

F5 pathtraver (ALL 12 share one source gap):

    Enumeration<String> names = request.getHeaderNames();   <- source absent
    String name = (String) names.nextElement();
    param = name;   // header NAME as the parameter
    File f = new java.io.File(Utils.TESTFILES_DIR, bar);   <- qualified sink

Fixes under test (line layer + J3, plus the J5 project walk):
- sources: getHeaderNames / getParameterMap / getParameterValues /
  getParameterNames enter _JAVA_SOURCE_PATTERNS (shared by line layer + J3).
- builder state: `pb = new ProcessBuilder(arg)` joins tainted_objects /
  collections whenever the argument carries taint or collection state.
- element models: literal-key map put/get (last write per key) and
  literal-index list add/remove/get (exact oracle shift semantics).
- path sinks accept the optional package qualifier (the J5 fix, mirrored).

Red-first protocol: with these edits stashed the seven TP tests must FAIL
(miss = the measured detection failure); the six controls -- const last
write, wrong map key, list index after remove(const), const list, folded
ternary over a header-name source -- must PASS in both phases.
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

CMD_RULE = "cwe-78"
PATH_RULE = "cwe-22"


def cwes(java_source: str, cwe: str) -> list:
    with tempfile.TemporaryDirectory(prefix="rsx_f45_") as tmp:
        p = pathlib.Path(tmp) / "T.java"
        p.write_text(PRELUDE + java_source, encoding="utf-8")
        return [f for f in (analyze_file(str(p)) or [])
                if str(f.get("cwe") or "").lower() == cwe]


# --- F4 TP shapes (RED before the constructor/source/model fixes) ---------

def test_tpd_processbuilder_constructor_list_fires():
    """BenchmarkTest00731 shape: direct bar, list carrier, constructor."""
    src = """
class T {
    public void doPost(HttpServletRequest request) throws Exception {
        String param = request.getParameter("BenchmarkTest00731");
        String bar = param;
        List<String> argList = new ArrayList<String>();
        argList.add("cmd.exe");
        argList.add("/c");
        argList.add("sh");
        argList.add("-c");
        argList.add("echo " + bar);
        ProcessBuilder pb = new ProcessBuilder(argList);
        Process p = pb.start();
    }
}
"""
    assert cwes(src, CMD_RULE), "constructor+list carrier stayed dark (F4)"


def test_tpd_processbuilder_constructor_array_fires():
    """BenchmarkTest01430 shape: parameterNames source + String[] argv."""
    src = """
class T {
    public void doPost(HttpServletRequest request) throws Exception {
        String param = "";
        Enumeration<String> names = request.getParameterNames();
        while (names.hasMoreElements()) {
            String name = (String) names.nextElement();
            param = name;
        }
        String bar = new Test().doSomething(request, param);
        String[] args = {"cmd.exe", "/c", "sh", "-c", "echo " + bar};
        ProcessBuilder pb = new ProcessBuilder(args);
        Process p = pb.start();
    }
    static String doSomething(HttpServletRequest request, String param) { return param; }
}
"""
    assert cwes(src, CMD_RULE), "constructor+array carrier stayed dark (F4)"


def test_tpd_parametermap_source_command_form_fires():
    """BenchmarkTest00480 shape: parameterMap source + pb.command(...)."""
    src = """
class T {
    public void doPost(HttpServletRequest request) throws Exception {
        int num = 106;
        Map<String, String[]> map = request.getParameterMap();
        String[] values = map.get("BenchmarkTest00480");
        String param = values[0];
        String bar = (7 * 42) - num > 200 ? "This should never happen" : param;
        List<String> argList = new ArrayList<String>();
        argList.add("cmd.exe");
        argList.add("/c");
        argList.add("sh");
        argList.add("-c");
        argList.add("echo " + bar);
        ProcessBuilder pb = new ProcessBuilder();
        pb.command(argList);
        Process p = pb.start();
    }
}
"""
    assert cwes(src, CMD_RULE), "parameterMap source + command form stayed dark (F4)"


def test_tpd_map_literal_key_carrier_fires():
    """BenchmarkTest00816 shape: put(param at keyB) / get(keyB) element flow."""
    src = """
class T {
    public void doPost(HttpServletRequest request) throws Exception {
        String queryString = request.getQueryString();
        String param = queryString.substring(1);
        Map<String, String> m = new HashMap<String, String>();
        m.put("keyB-34260", param);
        String bar = (String) m.get("keyB-34260");
        List<String> argList = new ArrayList<String>();
        argList.add("cmd.exe");
        argList.add("/c");
        argList.add("sh");
        argList.add("-c");
        argList.add("echo " + bar);
        ProcessBuilder pb = new ProcessBuilder(argList);
        Process p = pb.start();
    }
}
"""
    assert cwes(src, CMD_RULE), "map literal-key element flow stayed dark (F4)"


def test_tpd_list_index_carrier_fires():
    """BenchmarkTest01601 shape: add/remove/get index arithmetic -> sink."""
    src = """
class T {
    public void doPost(HttpServletRequest request) throws Exception {
        String param = request.getParameter("BenchmarkTest01601");
        List<String> valuesList = new ArrayList<String>();
        valuesList.add("safe!");
        valuesList.add(param);
        valuesList.add("moresafe!");
        valuesList.remove(0);
        String bar = valuesList.get(0);
        List<String> argList = new ArrayList<String>();
        argList.add("cmd.exe");
        argList.add("/c");
        argList.add("sh");
        argList.add("-c");
        argList.add("echo " + bar);
        ProcessBuilder pb = new ProcessBuilder(argList);
        Process p = pb.start();
    }
}
"""
    assert cwes(src, CMD_RULE), "list index model stayed dark (F4)"


# --- F5 TP shapes (RED before the header-name source + qualified sink) ----

def test_tpd_headernames_source_path_fires():
    """BenchmarkTest00215 shape: header NAME enumeration into qualified File."""
    src = """
class T {
    public void doPost(HttpServletRequest request) throws Exception {
        String param = "";
        Enumeration<String> names = request.getHeaderNames();
        while (names.hasMoreElements()) {
            String name = (String) names.nextElement();
            if (name.startsWith("Benchmark")) {
                param = name;
            }
        }
        String bar = param;
        java.io.File f = new java.io.File("/tmp/benchfiles", bar);
        f.createNewFile();
    }
}
"""
    assert cwes(src, PATH_RULE), "header-name source + qualified File stayed dark (F5)"


def test_tpd_headernames_list_path_fires():
    """BenchmarkTest01116 shape: header names -> list element -> qualified File."""
    src = """
class T {
    public void doPost(HttpServletRequest request) throws Exception {
        String param = "";
        Enumeration<String> names = request.getHeaderNames();
        while (names.hasMoreElements()) {
            String name = (String) names.nextElement();
            param = name;
        }
        List<String> valuesList = new ArrayList<String>();
        valuesList.add("safe!");
        valuesList.add(param);
        valuesList.remove(0);
        String bar = valuesList.get(0);
        java.io.File f = new java.io.File("/tmp/benchfiles", bar);
        f.createNewFile();
    }
}
"""
    assert cwes(src, PATH_RULE), "header names + list element stayed dark (F5)"


# --- Round 2 TP shapes (RED: conditional prefix / for-each / long wrap) --

def test_tpd_conditional_prefix_assignment_fires():
    """BenchmarkTest00731 exact param shape: if/else statement-form assigns."""
    src = """
class T {
    public void doPost(HttpServletRequest request) throws Exception {
        String[] values = request.getParameterValues("BenchmarkTest00731");
        String param;
        if (values != null && values.length > 0) param = values[0];
        else param = "";
        String bar = param;
        List<String> argList = new ArrayList<String>();
        argList.add("cmd.exe");
        argList.add("/c");
        argList.add("sh");
        argList.add("-c");
        argList.add("echo " + bar);
        ProcessBuilder pb = new ProcessBuilder(argList);
        Process p = pb.start();
    }
}
"""
    assert cwes(src, CMD_RULE), "if/else statement-form assignment stayed dark"


def test_tpd_parametermap_values_carrier_fires():
    """parameterMap source -> get(name) -> decode(vals[0]) carrier chain."""
    src = """
class T {
    public void doPost(HttpServletRequest request) throws Exception {
        String param = "noCookieValueSupplied";
        java.util.Map<String, String[]> theCookies = request.getParameterMap();
        if (theCookies != null) {
            String name = "BenchmarkTest00077";
            String[] vals = theCookies.get(name);
            if (vals != null && vals.length > 0) {
                param = java.net.URLDecoder.decode(vals[0], "UTF-8");
            }
        }
        String bar = param;
        List<String> argList = new ArrayList<String>();
        argList.add("cmd.exe");
        argList.add("/c");
        argList.add("sh");
        argList.add("-c");
        argList.add("echo " + bar);
        ProcessBuilder pb = new ProcessBuilder(argList);
        Process p = pb.start();
    }
}
"""
    assert cwes(src, CMD_RULE), "parameterMap->values[0] carrier stayed dark"


def test_tpd_foreach_cookie_element_fires():
    """BenchmarkTest00077 shape: for-each over tainted cookies -> decode."""
    src = """
class T {
    public void doPost(HttpServletRequest request) throws Exception {
        String param = "noCookieValueSupplied";
        javax.servlet.http.Cookie[] theCookies = request.getCookies();
        if (theCookies != null) {
            for (javax.servlet.http.Cookie theCookie : theCookies) {
                if (theCookie.getName().equals("BenchmarkTest00077")) {
                    param = java.net.URLDecoder.decode(theCookie.getValue(), "UTF-8");
                    break;
                }
            }
        }
        String bar = param;
        List<String> argList = new ArrayList<String>();
        argList.add("cmd.exe");
        argList.add("/c");
        argList.add("sh");
        argList.add("-c");
        argList.add("echo " + bar);
        ProcessBuilder pb = new ProcessBuilder(argList);
        Process p = pb.start();
    }
}
"""
    assert cwes(src, CMD_RULE), "for-each element taint stayed dark"


def test_tpd_long_wrapped_uri_carrier_fires():
    """BenchmarkTest00218 shape: +bar sits beyond the 6-line join cap."""
    src = """
class T {
    public void doPost(HttpServletRequest request) throws Exception {
        String param = "";
        Enumeration<String> names = request.getHeaderNames();
        while (names.hasMoreElements()) {
            String name = (String) names.nextElement();
            param = name;
        }
        String bar = param;
        java.net.URI fileURI =
                java.net.URI.create(
                        org.owasp.benchmark.helpers.Utils.TESTFILES_DIR
                                .replace('\\\\', java.io.File.separatorChar)
                                .replace('%', java.io.File.separatorChar)
                                .replace('/', java.io.File.separatorChar)
                                .replace('?', java.io.File.separatorChar)
                                .replace('*', java.io.File.separatorChar)
                                .replace(':', java.io.File.separatorChar)
                                .replace('|', java.io.File.separatorChar)
                                .replace('"', java.io.File.separatorChar)
                                + bar);
        java.io.File fileTarget = new java.io.File(fileURI);
        fileTarget.createNewFile();
    }
}
"""
    assert cwes(src, PATH_RULE), "long wrapped URI carrier stayed dark"


def test_tpd_wrapper_getTheParameter_fires():
    """BenchmarkTest01517/02411/02412/02414 shape: `scr.getTheParameter`
    wrapper source (J5's _J5_WRAPPER_SOURCE_RE) mirrored into the shared
    java source table so the line layer and J3 see it too."""
    src = """
class T {
    public void doPost(HttpServletRequest request) throws Exception {
        SourceControl scr = new SourceControl();
        String param = scr.getTheParameter("BenchmarkTest02414");
        if (param == null) param = "";
        String bar = doSomething(request, param);
        List<String> argList = new ArrayList<String>();
        argList.add("cmd.exe");
        argList.add("/c");
        argList.add("sh");
        argList.add("-c");
        argList.add("echo " + bar);
        ProcessBuilder pb = new ProcessBuilder(argList);
        Process p = pb.start();
    }
    static String doSomething(HttpServletRequest request, String param) {
        return param;
    }
}
"""
    assert cwes(src, CMD_RULE), "getTheParameter wrapper source stayed dark"


# --- Round 2 controls ------------------------------------------------------

def test_tn_crossmethod_map_return_stays_dark():
    """01118/01409/01991 shape: callee's last write is a safe map get(keyA)
    after put(keyB, param); the returned value is provably safe, so the
    outer qualified File/Paths sink must stay dark (J3.2c dead-refine)."""
    src = """
class T {
    public void doPost(HttpServletRequest request) throws Exception {
        String param = "";
        Enumeration<String> names = request.getHeaderNames();
        while (names.hasMoreElements()) {
            String name = (String) names.nextElement();
            param = name;
        }
        String bar = new Test().doSomething(request, param);
        String fileName = org.owasp.benchmark.helpers.Utils.TESTFILES_DIR + bar;
        java.nio.file.Path path = java.nio.file.Paths.get(fileName);
        java.io.InputStream is = java.nio.file.Files.newInputStream(path);
        is.close();
    }

    public static class Test {
        public String doSomething(HttpServletRequest request, String param) {
            String bar = "safe!";
            Map<String, String> m = new HashMap<String, String>();
            m.put("keyA-1", "a_Value");
            m.put("keyB-1", param);
            m.put("keyC", "another_Value");
            bar = (String) m.get("keyB-1");
            bar = (String) m.get("keyA-1");
            return bar;
        }
    }
}
"""
    assert not cwes(src, PATH_RULE), (
        "cross-method const map return must stay dark (J3.2c refine)")


def test_tn_ifelse_folded_const_stays_dark():
    """00216-negative twin: if/(500/42)+num>200 folds FALSE with num=106,
    so the else constant is the last write and must kill the sink."""
    src = """
class T {
    public void doPost(HttpServletRequest request) throws Exception {
        int num = 106;
        String param = "";
        Enumeration<String> names = request.getHeaderNames();
        while (names.hasMoreElements()) {
            String name = (String) names.nextElement();
            param = name;
        }
        String bar;
        if ((500 / 42) + num > 200) bar = param;
        else bar = "safe_const_447190";
        List<String> argList = new ArrayList<String>();
        argList.add("cmd.exe");
        argList.add("/c");
        argList.add("echo " + bar);
        ProcessBuilder pb = new ProcessBuilder(argList);
        Process p = pb.start();
    }
}
"""
    assert not cwes(src, CMD_RULE), "folded if/else const must stay dark"

def test_tn_const_last_write_path_stays_dark():
    """bar overwritten with a constant before the qualified File sink."""
    src = """
class T {
    public void doPost(HttpServletRequest request) throws Exception {
        String param = request.getParameter("x");
        String bar = param;
        bar = "safe_const_918273";
        java.io.File f = new java.io.File("/tmp/benchfiles", bar);
        f.createNewFile();
    }
}
"""
    assert not cwes(src, PATH_RULE), "const last write must stay dark"


def test_tn_map_wrong_key_stays_dark():
    """put(param, keyB) then get(keyA): per-key state must not bleed."""
    src = """
class T {
    public void doPost(HttpServletRequest request) throws Exception {
        String param = request.getParameter("x");
        Map<String, String> m = new HashMap<String, String>();
        m.put("keyB", param);
        String bar = (String) m.get("keyA");
        java.io.File f = new java.io.File("/tmp/benchfiles", bar);
        f.createNewFile();
    }
}
"""
    assert not cwes(src, PATH_RULE), "wrong-key map read must stay dark"


def test_tn_list_index_after_remove_stays_dark():
    """remove(0) shifts indices: get(1) is the constant element."""
    src = """
class T {
    public void doPost(HttpServletRequest request) throws Exception {
        String param = request.getParameter("x");
        List<String> valuesList = new ArrayList<String>();
        valuesList.add("safe!");
        valuesList.add(param);
        valuesList.add("moresafe!");
        valuesList.remove(0);
        String bar = valuesList.get(1);
        List<String> argList = new ArrayList<String>();
        argList.add("cmd.exe");
        argList.add("/c");
        argList.add("sh");
        argList.add("-c");
        argList.add("echo " + bar);
        ProcessBuilder pb = new ProcessBuilder(argList);
        Process p = pb.start();
    }
}
"""
    assert not cwes(src, CMD_RULE), "shifted-constant list read must stay dark"


def test_tn_constructor_const_list_stays_dark():
    """A builder seeded only with literal arguments never starts as a sink."""
    src = """
class T {
    public void doPost(HttpServletRequest request) throws Exception {
        List<String> argList = new ArrayList<String>();
        argList.add("cmd.exe");
        argList.add("/c");
        ProcessBuilder pb = new ProcessBuilder(argList);
        Process p = pb.start();
    }
}
"""
    assert not cwes(src, CMD_RULE), "const list constructor must stay dark"


def test_tn_headernames_folded_ternary_stays_dark():
    """Header-name source but the ternary folds to the constant branch."""
    src = """
class T {
    public void doPost(HttpServletRequest request) throws Exception {
        int num = 10;
        String param = "";
        Enumeration<String> names = request.getHeaderNames();
        while (names.hasMoreElements()) {
            String name = (String) names.nextElement();
            param = name;
        }
        String bar = (7 * 42) - num > 200 ? "bobs_your_uncle" : param;
        java.io.File f = new java.io.File("/tmp/benchfiles", bar);
        f.createNewFile();
    }
}
"""
    assert not cwes(src, PATH_RULE), "folded ternary over header source must stay dark"


def test_tn_parametermap_const_bar_stays_dark():
    """parameterMap source with a straight-line constant overwrite."""
    src = """
class T {
    public void doPost(HttpServletRequest request) throws Exception {
        Map<String, String[]> map = request.getParameterMap();
        String[] values = map.get("BenchmarkTest00001");
        String param = values[0];
        String bar = param;
        bar = "safe_const_552331";
        List<String> argList = new ArrayList<String>();
        argList.add("cmd.exe");
        argList.add("/c");
        argList.add("sh");
        argList.add("-c");
        argList.add("echo " + bar);
        ProcessBuilder pb = new ProcessBuilder(argList);
        Process p = pb.start();
    }
}
"""
    assert not cwes(src, CMD_RULE), "parameterMap const overwrite must stay dark"
