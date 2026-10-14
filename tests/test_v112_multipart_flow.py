"""V1.12a — TAINT_MULTIPART_TRAVERSAL kill-only-on-proof data-flow gate.

The multipart window rule matches any ``filename``-shaped token near any
``File(``-shaped token, so its src and sink anchors are the most generic in
the engine. Three layers keep it honest, and each one is pinned here:

* EVALUATOR — ``scanner.multipart_flow.is_proven_constant`` against the
  exact archetypes observed in the OWASP Benchmark findings dump: nine
  KILL shapes (the value provably folds to a constant: literal
  reassignment, constant-folding ternary/if-else, safe-key map overwrite,
  index-sensitive list reads, literal-returning same-file helpers,
  reflective helper dispatch) and eleven KEEP shapes (every TP: tainted
  params, request sources, loop-carried values, Base64 round-trips,
  opaque try/catch). ``RSX_MULTIPART_FLOW=0`` disables the gate, and no
  input — binary garbage, empty source, unknown variable, out-of-range
  line — may raise.
* ENGINE WIRING — ``_multipart_flow_proves_constant`` (the hook the
  emission site consults) and ``_is_concrete_path_sink`` (method
  declarations such as ``public IActionResult File([FromQuery] string
  filename)`` are not sinks).
* AST GUARD KILL — ``scanner.ast_validators`` resolves the
  guarded-but-tainted shape the flow gate cannot: Java
  ``if (safe) { use } else { return; }`` (exit in the ALTERNATIVE, and
  only for findings inside the proven region) and C#
  ``if (bad) return;`` (exit in the consequence). Executed against the
  real golden-corpus fixtures, so measurement and test cannot drift.

Only ever KILL: no layer can make the rule fire, and every ambiguity
returns the finding byte-identical. Grammar-dependent tests skip on boxes
without the optional wheels (CI stays green stdlib-only).
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

from scanner.multipart_flow import gate_enabled, is_proven_constant
from scanner import tree_sitter_support as ts

SAST_CORPUS = Path("tests/vuln-test-corpus/sast")

TS_INSTALLED = importlib.util.find_spec("tree_sitter") is not None
needs_java = pytest.mark.skipif(
    not TS_INSTALLED or not ts.grammar_available("java"),
    reason="java grammar unavailable")
needs_csharp = pytest.mark.skipif(
    not TS_INSTALLED or not ts.grammar_available("csharp"),
    reason="csharp grammar unavailable")


# ---------------------------------------------------------------------------
# Layer 1 — the evaluator, against the benchmark/corpus archetypes
# ---------------------------------------------------------------------------

#: (name, expect_proven, source, variable, query line)
ARCHETYPES = [
    # --- KILL: the value provably folds to a constant (benchmark FPs) ----
    ("fp-literal-reassign", True, """
public void doPost(HttpServletRequest request, HttpServletResponse response) {
    String param = request.getParameter("x");
    String bar;
    bar = "bob's your uncle";
    String fileName = null;
    fileName = org.owasp.benchmark.helpers.Utils.TESTFILES_DIR + bar;
    fis = new java.io.FileInputStream(new java.io.File(fileName));
}
""", "fileName", 8),
    ("fp-ternary-const", True, """
public void doPost(HttpServletRequest request, HttpServletResponse response) {
    String param = request.getParameter("x");
    String bar;
    int num = 106;
    bar = (7 * 18) + num > 200 ? "This_should_always_happen" : param;
    String fileName = null;
    fileName = org.owasp.benchmark.helpers.Utils.TESTFILES_DIR + bar;
    fis = new java.io.FileInputStream(new java.io.File(fileName));
}
""", "fileName", 9),
    ("fp-map-overwrite", True, """
public void doPost(HttpServletRequest request, HttpServletResponse response) {
    String param = request.getParameter("x");
    String bar;
    java.util.Map<String, Object> map53289 = new java.util.HashMap<String, Object>();
    map53289.put("keyA-53289", "a_Value");
    map53289.put("keyB-53289", param);
    bar = (String) map53289.get("keyB-53289");
    bar = (String) map53289.get("keyA-53289");
    String fileName = org.owasp.benchmark.helpers.Utils.TESTFILES_DIR + bar;
    java.nio.file.Path path = java.nio.file.Paths.get(fileName);
}
""", "fileName", 12),
    ("fp-helper-list", True, """
public void doPost(HttpServletRequest request, HttpServletResponse response)
        throws ServletException, IOException {
    String param = request.getParameter("x");
    String bar = new Test().doSomething(request, param);
    String fileName = null;
    fileName = org.owasp.benchmark.helpers.Utils.TESTFILES_DIR + bar;
    fis = new java.io.FileInputStream(new java.io.File(fileName));
}

private class Test {
    public String doSomething(HttpServletRequest request, String param)
            throws ServletException, IOException {
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
""", "fileName", 8),
    ("fp-ifelse-const", True, """
public void doPost(HttpServletRequest request, HttpServletResponse response) {
    String param = request.getParameter("x");
    String bar;
    int num = 86;
    if ((7 * 42) - num > 200) bar = "This_should_always_happen";
    else bar = param;
    String fileName = null;
    java.io.FileInputStream fis = null;
    try {
        fileName = org.owasp.benchmark.helpers.Utils.TESTFILES_DIR + bar;
        fis = new java.io.FileInputStream(new java.io.File(fileName));
    } catch (IOException e) { e.printStackTrace(); }
}
""", "fileName", 11),
    ("fp-aslist-literal", True, """
public void doPost(HttpServletRequest request, HttpServletResponse response) {
    String param = request.getParameter("x");
    java.util.List<String> valuesList = java.util.Arrays.asList("safe", "safertoo");
    String bar = valuesList.get(0);
    String fileName = Utils.TESTFILES_DIR + bar;
    fis = new java.io.FileInputStream(new java.io.File(fileName));
}
""", "fileName", 7),
    ("fp-try-literal", True, """
public void doPost(HttpServletRequest request, HttpServletResponse response)
        throws ServletException, IOException {
    String param = request.getParameter("x");
    String bar;
    bar = "bob's your uncle";
    String fileName = null;
    java.io.FileInputStream fis = null;
    try {
        fileName = org.owasp.benchmark.helpers.Utils.TESTFILES_DIR + bar;
        fis = new java.io.FileInputStream(new java.io.File(fileName));
    } catch (IOException e) {
        System.out.println("oops");
    }
}
""", "fileName", 10),
    ("fp-loop-default-ternary", True, """
public void doPost(HttpServletRequest request, HttpServletResponse response) {
    String param = "noCookieValueSupplied";
    javax.servlet.http.Cookie[] theCookies = request.getCookies();
    if (theCookies != null) {
        for (javax.servlet.http.Cookie theCookie : theCookies) {
            if (theCookie.getName().equals("BenchmarkTest00063")) {
                param = java.net.URLDecoder.decode(theCookie.getValue(), "UTF-8");
                break;
            }
        }
    }
    String bar;
    int num = 106;
    bar = (7 * 18) + num > 200 ? "This_should_always_happen" : param;
    String fileName = null;
    fileName = org.owasp.benchmark.helpers.Utils.TESTFILES_DIR + bar;
    fis = new java.io.FileInputStream(new java.io.File(fileName));
}
""", "fileName", 18),
    ("fp-reflection-helper", True, """
public void doPost(HttpServletRequest request, HttpServletResponse response)
        throws Exception {
    String param = request.getParameter("x");
    Object thing = Class.forName("org.owasp.benchmark.testcode.BenchmarkTest00866$Test")
            .newInstance();
    java.lang.reflect.Method method = thing.getClass()
            .getMethod("doSomething", HttpServletRequest.class, String.class);
    String bar = (String) method.invoke(thing, request, param);
    String fileName = null;
    fileName = Utils.TESTFILES_DIR + bar;
    fis = new java.io.FileInputStream(new java.io.File(fileName));
}

private static class Test {
    public String doSomething(HttpServletRequest request, String param) {
        return "a constant value";
    }
}
""", "fileName", 10),
    # --- KEEP: tainted value reaches the sink (every TP must survive) -----
    ("tp-ternary-param", False, """
public void doPost(HttpServletRequest request, HttpServletResponse response) {
    String param = request.getParameter("x");
    String bar;
    int num = 106;
    bar = (7 * 42) - num > 200 ? "This should never happen" : param;
    String fileName = null;
    fileName = org.owasp.benchmark.helpers.Utils.TESTFILES_DIR + bar;
    fis = new java.io.FileInputStream(new java.io.File(fileName));
}
""", "fileName", 9),
    ("tp-map-single-get", False, """
public void doPost(HttpServletRequest request, HttpServletResponse response) {
    String param = request.getParameter("x");
    String bar;
    java.util.Map<String, Object> map77232 = new java.util.HashMap<String, Object>();
    map77232.put("keyA-77232", "a-Value");
    map77232.put("keyB-77232", param);
    bar = (String) map77232.get("keyB-77232");
    String fileName = null;
    fileName = org.owasp.benchmark.helpers.Utils.TESTFILES_DIR + bar;
    fis = new java.io.FileInputStream(new java.io.File(fileName));
}
""", "fileName", 12),
    ("tp-helper-param", False, """
public void doPost(HttpServletRequest request, HttpServletResponse response)
        throws ServletException, IOException {
    String param = request.getParameter("x");
    String bar = new Test().doSomething(request, param);
    String fileName = null;
    fileName = org.owasp.benchmark.helpers.Utils.TESTFILES_DIR + bar;
    fis = new java.io.FileInputStream(new java.io.File(fileName));
}

private class Test {
    public String doSomething(HttpServletRequest request, String param)
            throws ServletException, IOException {
        String bar;
        int num = 196;
        if ((500 / 42) + num > 200) bar = param;
        else bar = "This should never happen";
        return bar;
    }
}
""", "fileName", 8),
    ("tp-base64-roundtrip", False, """
public void doPost(HttpServletRequest request, HttpServletResponse response)
        throws ServletException, IOException {
    String param = request.getParameter("x");
    if (param == null) param = "";
    String bar = "";
    if (param != null) {
        bar = new String(org.apache.commons.codec.binary.Base64.decodeBase64(
                org.apache.commons.codec.binary.Base64.encodeBase64(
                        param.getBytes())));
    }
    String fileName = null;
    fileName = org.owasp.benchmark.helpers.Utils.TESTFILES_DIR + bar;
    fis = new java.io.FileInputStream(new java.io.File(fileName));
}
""", "fileName", 15),
    ("tp-ifelse-param", False, """
public void doPost(HttpServletRequest request, HttpServletResponse response) {
    String param = request.getParameter("x");
    String bar;
    int num = 86;
    if ((7 * 18) + num > 200) bar = param;
    else bar = "This should never happen";
    String fileName = null;
    java.io.FileInputStream fis = null;
    try {
        fileName = org.owasp.benchmark.helpers.Utils.TESTFILES_DIR + bar;
        fis = new java.io.FileInputStream(new java.io.File(fileName));
    } catch (IOException e) { e.printStackTrace(); }
}
""", "fileName", 11),
    ("corpus-cs-param", False, """
[ApiController]
public class UploadController : Controller {
    [HttpGet("file")]
    public IActionResult File([FromQuery] string filename) {
        var path = Path.Combine(@"C:\\Uploads", filename);
        return PhysicalFile(path, "text/plain");
    }
}
""", "filename", 6),
    ("corpus-java-request", False, """
protected void doGet(HttpServletRequest req, HttpServletResponse resp)
        throws ServletException, IOException {
    String fileName = req.getParameter("file");
    if (fileName != null && !fileName.contains("..")) {
        File f = new File("/var/www/uploads/" + fileName);
    }
}
""", "fileName", 4),
    ("tp-loop-carried", False, """
public void doPost(HttpServletRequest request, HttpServletResponse response) {
    String bar = "";
    String[] values = new String[]{"a", "b"};
    for (int i = 0; i < values.length; i++) {
        bar = values[i];
    }
    String fileName = null;
    fileName = Utils.TESTFILES_DIR + bar;
    fis = new java.io.FileInputStream(new java.io.File(fileName));
}
""", "fileName", 9),
    ("tp-aslist-param", False, """
public void doPost(HttpServletRequest request, HttpServletResponse response) {
    String param = request.getParameter("x");
    java.util.List<String> valuesList = java.util.Arrays.asList(param, "safe");
    String bar = valuesList.get(0);
    String fileName = Utils.TESTFILES_DIR + bar;
    fis = new java.io.FileInputStream(new java.io.File(fileName));
}
""", "fileName", 7),
    ("tp-try-tainted", False, """
public void doPost(HttpServletRequest request, HttpServletResponse response)
        throws ServletException, IOException {
    String param = request.getParameter("BenchmarkTest00001");
    String fileName = null;
    java.io.FileInputStream fis = null;
    try {
        fileName = org.owasp.benchmark.helpers.Utils.TESTFILES_DIR + param;
        fis = new java.io.FileInputStream(new java.io.File(fileName));
    } catch (IOException e) {
        System.out.println("oops");
    }
}
""", "fileName", 8),
    ("tp-separate-class", False, """
public void doPost(HttpServletRequest request, HttpServletResponse response) {
    org.owasp.benchmark.helpers.SeparateClassRequest scr =
            new org.owasp.benchmark.helpers.SeparateClassRequest(request);
    String param = scr.getTheValue("BenchmarkTest00867");
    String bar = "";
    bar = Utils.TESTFILES_DIR + param;
    String fileName = bar;
    fis = new java.io.FileInputStream(new java.io.File(fileName));
}
""", "fileName", 7),
    # --- round 2: constant-selector switch (BenchmarkTest00132/02201) ----
    ("fp-switch-const-selector", True, """
public void doPost(HttpServletRequest request, HttpServletResponse response) {
    String param = request.getParameter("x");
    String bar;
    String guess = "ABC";
    char switchTarget = guess.charAt(1); // 'B'
    switch (switchTarget) {
        case 'A':
            bar = param;
            break;
        case 'B':
            bar = "bob";
            break;
        default:
            bar = param;
    }
    String fileName = null;
    fileName = org.owasp.benchmark.helpers.Utils.TESTFILES_DIR + bar;
    fis = new java.io.FileInputStream(new java.io.File(fileName));
}
""", "fileName", 18),
    ("fp-helper-switch", True, """
public void doPost(HttpServletRequest request, HttpServletResponse response) {
    String param = request.getParameter("x");
    String bar = new Test().doSomething(request, param);
    String fileName = null;
    fileName = org.owasp.benchmark.helpers.Utils.TESTFILES_DIR + bar;
    fis = new java.io.FileInputStream(new java.io.File(fileName));
}

private class Test {
    public String doSomething(HttpServletRequest request, String param) {
        String bar;
        String guess = "ABC";
        char t = guess.charAt(1); // 'B'
        switch (t) {
            case 'A':
                bar = param;
                break;
            case 'B':
                bar = "bob";
                break;
            default:
                bar = param;
        }
        return bar;
    }
}
""", "fileName", 7),
    ("tp-switch-tainted-case", False, """
public void doPost(HttpServletRequest request, HttpServletResponse response) {
    String param = request.getParameter("x");
    String bar;
    String guess = "ABC";
    char switchTarget = guess.charAt(1); // 'B' — reached case is tainted
    switch (switchTarget) {
        case 'A':
            bar = "bob";
            break;
        case 'B':
            bar = param;
            break;
        default:
            bar = "bob";
    }
    String fileName = null;
    fileName = org.owasp.benchmark.helpers.Utils.TESTFILES_DIR + bar;
    fis = new java.io.FileInputStream(new java.io.File(fileName));
}
""", "fileName", 18),
    ("tp-switch-opaque-selector", False, """
public void doPost(HttpServletRequest request, HttpServletResponse response) {
    String param = request.getParameter("x");
    String bar;
    switch (param) {
        case "A":
            bar = "safe";
            break;
        default:
            bar = param;
    }
    String fileName = null;
    fileName = org.owasp.benchmark.helpers.Utils.TESTFILES_DIR + bar;
    fis = new java.io.FileInputStream(new java.io.File(fileName));
}
""", "fileName", 14),
    ("tp-opaque-receiver-hazard", False, """
public void doPost(HttpServletRequest request, HttpServletResponse response) {
    javax.servlet.http.Cookie[] theCookies = request.getCookies();
    javax.servlet.http.Cookie theCookie = theCookies[0];
    String name = theCookie.getName();
    String fileName = null;
    fileName = org.owasp.benchmark.helpers.Utils.TESTFILES_DIR + name;
    fis = new java.io.FileInputStream(new java.io.File(fileName));
}
""", "fileName", 8),
]


@pytest.mark.parametrize(
    "expect, source, var, at_line",
    [c[1:] for c in ARCHETYPES],
    ids=[c[0] for c in ARCHETYPES],
)
def test_evaluator_archetype(expect, source, var, at_line):
    assert is_proven_constant(source, var, at_line) == expect


def test_kill_switch_disables_the_gate(monkeypatch):
    monkeypatch.setenv("RSX_MULTIPART_FLOW", "0")
    # The literal-reassignment shape would otherwise be PROVEN constant.
    name, expect, source, var, at_line = ARCHETYPES[0]
    assert expect is True
    assert is_proven_constant(source, var, at_line) is False
    monkeypatch.delenv("RSX_MULTIPART_FLOW")
    assert gate_enabled() is True


def test_gate_enabled_reads_env(monkeypatch):
    monkeypatch.setenv("RSX_MULTIPART_FLOW", "off")
    assert gate_enabled() is False
    monkeypatch.setenv("RSX_MULTIPART_FLOW", "1")
    assert gate_enabled() is True


def test_never_raises_on_hostile_input():
    name, expect, source, var, at_line = ARCHETYPES[0]
    # empty source / unknown var / out-of-range lines
    assert is_proven_constant("", "fileName", 8) is False
    assert is_proven_constant(source, "", at_line) is False
    assert is_proven_constant(source, "no_such_var", at_line) is False
    assert is_proven_constant(source, var, 0) is False
    # far past the end still terminates with a verdict
    assert is_proven_constant(source, var, 10 ** 6) in (True, False)
    # binary / control-character garbage
    garbage = "\x00\x01\x80\x9f" + "﻿ funky { ] ; ( ) " * 50
    assert is_proven_constant(garbage, "fileName", 10) in (True, False)


# ---------------------------------------------------------------------------
# Layer 2 — taint_engine wiring
# ---------------------------------------------------------------------------

def test_path_sink_rejects_method_declarations():
    from scanner.taint_engine import _is_concrete_path_sink
    # The corpus false anchors: signatures that merely LOOK like sinks.
    assert _is_concrete_path_sink(
        "        public IActionResult File([FromQuery] string filename)") is False
    assert _is_concrete_path_sink(
        "        public IActionResult File([FromQuery] string filename) {") is False
    assert _is_concrete_path_sink(
        "    public void open(String name) throws IOException {") is False
    # Real sinks are expressions.
    assert _is_concrete_path_sink(
        '            var path = Path.Combine(@"C:\\Uploads", filename);') is True
    assert _is_concrete_path_sink(
        "    fis = new java.io.FileInputStream(new java.io.File(fileName));"
    ) is True
    assert _is_concrete_path_sink(
        "        paths.put(key, Paths.get(value));") is True


class _SrcMatch:
    """Minimal stand-in for the src regex match object."""

    def __init__(self, text: str):
        self._text = text

    def group(self, idx: int = 0) -> str:
        return self._text


def test_proves_constant_hook_kills_and_keeps():
    from scanner.taint_engine import _multipart_flow_proves_constant
    fp_source, tp_source = ARCHETYPES[0][2], ARCHETYPES[9][2]
    # sink line 8 -> 0-based index 7
    assert _multipart_flow_proves_constant(
        fp_source, None, _SrcMatch("fileName"), 7) is True
    assert _multipart_flow_proves_constant(
        tp_source, None, _SrcMatch("fileName"), 8) is False
    # unidentifiable subject -> never kill
    assert _multipart_flow_proves_constant(
        fp_source, None, _SrcMatch(""), 7) is False
    assert _multipart_flow_proves_constant(
        fp_source, None, _SrcMatch("), "), 7) is False


def test_proves_constant_hook_honours_kill_switch(monkeypatch):
    from scanner.taint_engine import _multipart_flow_proves_constant
    fp_source = ARCHETYPES[0][2]
    monkeypatch.setenv("RSX_MULTIPART_FLOW", "0")
    assert _multipart_flow_proves_constant(
        fp_source, None, _SrcMatch("fileName"), 7) is False


# ---------------------------------------------------------------------------
# Layer 3 — AST guard kill on the real golden-corpus fixtures
# ---------------------------------------------------------------------------

def _multipart_finding(path: Path, line: int, subject: str, snippet: str) -> dict:
    return {
        "rule_id": "TAINT_MULTIPART_TRAVERSAL",
        "title": "Multipart file name traversal",
        "vuln_type": "path_traversal",
        "severity": "High",
        "language": "java",
        "file": str(path),
        "line": line,
        "snippet": snippet,
        "source_expr": subject,
        "group_key": f"TAINT_MULTIPART_TRAVERSAL|{path}|{line}",
    }


@needs_csharp
def test_cs_guarded_combination_killed():
    """SafeController.cs: ``if (bad) return BadRequest();`` before the
    ``Path.Combine`` anchor — guard-dominance KILL."""
    from scanner.ast_validators import apply_ast_validation
    target = SAST_CORPUS / "dotnet" / "SafeController.cs"
    finding = _multipart_finding(
        target, 69, "filename",
        'var path = Path.Combine(@"C:\\Uploads", filename);')
    assert apply_ast_validation([finding], str(target)) == []


@needs_csharp
def test_cs_unguarded_combination_kept():
    """VulnerableController.cs has no guard: the finding must survive."""
    from scanner.ast_validators import apply_ast_validation
    target = SAST_CORPUS / "dotnet" / "VulnerableController.cs"
    finding = _multipart_finding(
        target, 54, "filename",
        'var path = Path.Combine(@"C:\\Uploads", filename);')
    assert apply_ast_validation([finding], str(target)) == [finding]


@needs_java
def test_java_else_exit_guard_killed():
    """SafeServlet.java: ``if (safe) { use } else { return; }`` — the
    exit lives in the ALTERNATIVE and the finding sits INSIDE the
    proven region, so the guarded-but-tainted subject is KILLed."""
    from scanner.ast_validators import apply_ast_validation
    target = SAST_CORPUS / "java" / "SafeServlet.java"
    finding = _multipart_finding(
        target, 46, "fileName",
        'File f = new File("/var/www/uploads/" + fileName);')
    assert apply_ast_validation([finding], str(target)) == []


@needs_java
def test_java_unguarded_tainted_kept():
    from scanner.ast_validators import apply_ast_validation
    target = SAST_CORPUS / "java" / "VulnerableServlet.java"
    finding = _multipart_finding(
        target, 38, "fileName",
        'File f = new File("/var/www/uploads/" + fileName);')
    assert apply_ast_validation([finding], str(target)) == [finding]


@needs_java
def test_else_exit_guard_does_not_protect_outside_region(tmp_path):
    """An else-branch exit only governs the consequence it wraps: a
    finding AFTER the whole statement sits on the bad path and must
    keep."""
    from scanner.ast_validators import apply_ast_validation
    target = tmp_path / "AfterGuard.java"
    target.write_text(
        "public class AfterGuard {\n"
        "    void go(String fileName) {\n"
        "        if (fileName != null && !fileName.contains(\"..\")) {\n"
        "            touch();\n"
        "        } else {\n"
        "            return;\n"
        "        }\n"
        "        java.io.File f =\n"
        "                new java.io.File(\"/var/www/uploads/\" + fileName);\n"
        "    }\n"
        "    void touch() {}\n"
        "}\n",
        encoding="utf-8")
    finding = _multipart_finding(
        target, 8, "fileName",
        'new java.io.File("/var/www/uploads/" + fileName);')
    assert apply_ast_validation([finding], str(target)) == [finding]


def test_subject_without_identifier_keeps(tmp_path):
    """No extractable subject -> the guard layer never even looks."""
    from scanner.ast_validators import apply_ast_validation
    target = tmp_path / "NoSubject.java"
    target.write_text("class NoSubject {}\n", encoding="utf-8")
    finding = _multipart_finding(target, 1, "", "")
    finding["source_expr"] = ";;"
    assert apply_ast_validation([finding], str(target)) == [finding]


# ---------------------------------------------------------------------------
# WIRING — end-to-end through sast.scan_directory
# ---------------------------------------------------------------------------

@needs_java
def test_scan_directory_drops_guarded_multipart_fp():
    from scanner.sast import scan_directory
    results = scan_directory(str(SAST_CORPUS / "java"))
    by_file = {}
    for f in results:
        if str(f.get("rule_id")) == "TAINT_MULTIPART_TRAVERSAL":
            by_file.setdefault(Path(f["file"]).name, []).append(f)
    # SafeServlet's guarded shape is gone entirely...
    assert "SafeServlet.java" not in by_file
    # ...while the unguarded vulnerable fixture keeps its finding.
    vuln = by_file.get("VulnerableServlet.java", [])
    assert vuln and all("line" in f for f in vuln)


def test_kill_switch_is_total(monkeypatch):
    """RSX_MULTIPART_FLOW=0 restores engine-default behaviour everywhere."""
    monkeypatch.setenv("RSX_MULTIPART_FLOW", "0")
    for name, expect, source, var, at_line in ARCHETYPES:
        assert is_proven_constant(source, var, at_line) is False, name


# ---------------------------------------------------------------------------
# Round 2 — opaque-call propagation and cross-file literal-return helpers
# ---------------------------------------------------------------------------

_APP_SRC = """public class App {
    public void go() {
        Scr s = new Scr(request);
        String param = s.getTheValue("x");
        String bar = param;
        String fileName = null;
        fileName = org.owasp.benchmark.helpers.Utils.TESTFILES_DIR + bar;
        fis = new java.io.FileInputStream(new java.io.File(fileName));
    }
}
"""

_SCR_SAFE = """public class Scr {
    public Scr(String k) {
    }

    public String getTheValue(String p) {
        return "bar";
    }
}
"""

_SCR_TAINTED = """public class Scr {
    public Scr(String k) {
    }

    public String getTheValue(String p) {
        return p;
    }
}
"""


def _sink_line(source: str) -> int:
    return next(i for i, line in enumerate(source.splitlines(), 1)
                if "FileInputStream(new" in line)


def test_crossfile_literal_return_kills(tmp_path):
    """A same-tree helper class with a single literal ``return`` proves the
    call constant (the benchmark's ``SeparateClassRequest.getTheValue``)."""
    app = tmp_path / "App.java"
    app.write_text(_APP_SRC, encoding="utf-8")
    (tmp_path / "Scr.java").write_text(_SCR_SAFE, encoding="utf-8")
    assert is_proven_constant(
        _APP_SRC, "fileName", _sink_line(_APP_SRC),
        filepath=str(app)) is True


def test_crossfile_non_literal_return_keeps(tmp_path):
    app = tmp_path / "App.java"
    app.write_text(_APP_SRC, encoding="utf-8")
    (tmp_path / "Scr.java").write_text(_SCR_TAINTED, encoding="utf-8")
    assert is_proven_constant(
        _APP_SRC, "fileName", _sink_line(_APP_SRC),
        filepath=str(app)) is False


def test_crossfile_missing_class_keeps(tmp_path):
    app = tmp_path / "App.java"
    app.write_text(_APP_SRC, encoding="utf-8")
    assert is_proven_constant(
        _APP_SRC, "fileName", _sink_line(_APP_SRC),
        filepath=str(app)) is False
    # ...and with no filepath at all (the engine default for e.g. snippets).
    assert is_proven_constant(
        _APP_SRC, "fileName", _sink_line(_APP_SRC)) is False


def _const_arg_call_source(arg_expr: str) -> str:
    return f"""public class App {{
    public void go() {{
        String param = request.getParameter("x");
        String bar = Helper.wrap({arg_expr});
        String fileName = null;
        fileName = org.owasp.benchmark.helpers.Utils.TESTFILES_DIR + bar;
        fis = new java.io.FileInputStream(new java.io.File(fileName));
    }}
}}
"""


def test_opaque_class_call_with_const_args_is_constant():
    source = _const_arg_call_source('"literal"')
    assert is_proven_constant(
        source, "fileName", _sink_line(source)) is True


def test_opaque_class_call_with_tainted_arg_keeps():
    source = _const_arg_call_source("param")
    assert is_proven_constant(
        source, "fileName", _sink_line(source)) is False
