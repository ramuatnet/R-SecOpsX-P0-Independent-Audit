"""V1.12b — JAVA_PATH_TRAVERSAL_FILE kill-only-on-proof value gate.

The rule's window regex matches the substring ``filename`` (case-
insensitively) inside a variable NAME such as ``fileName``, or the token
``path`` inside an assignment target — it asks nothing about the value that
reaches ``Paths.get``/``new File``. Measured against the BenchmarkJava
oracle (findings13 attribution), that produced 16 firings on negative tests
and ZERO true positives: every firing was a call whose argument provably
folds to a compile-time constant (map strong update, switch pruning on a
folded selector, constant ternary, literal-returning helper).

The gate is a single layer, pinned here against the exact archetype shapes:

* ENGINE WIRING — ``scanner.sast._java_path_arg_proven_constant`` (the hook
  ``scan_file`` consults before emitting the finding) must KILL exactly the
  proven-constant argument lists and KEEP every unprovable one: tainted
  params, request sources, concat-of-tainted, qualified helper calls,
  unbalanced parens, pure literals, evaluator-off.

``RSX_MULTIPART_FLOW=0`` disables the shared evaluator and therefore this
gate. No input may raise: the helper returns False on every failure.

Only ever KILL: no layer can make the rule fire, and every ambiguity
returns the finding byte-identical.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

from scanner.multipart_flow import gate_enabled
from scanner.sast import (
    _java_path_arg_proven_constant,
    scan_file,
)

SAST_CORPUS = Path("tests/vuln-test-corpus/sast")

TS_INSTALLED = importlib.util.find_spec("tree_sitter") is not None


# ---------------------------------------------------------------------------
# Layer 1 — the gate helper, against the benchmark/corpus argument shapes
# ---------------------------------------------------------------------------

import re as _re

_RULE = _re.compile(
    r"new\s+File\s*\([^)]*(?:request|getParameter|path|filename)"
    r"|Paths\.get\s*\([^)]*(?:request|getParameter|path|filename)",
    _re.I | _re.M | _re.S)


def _match_of(source: str):
    m = _RULE.search(source)
    assert m is not None, "archetype must contain a JAVA_PATH_TRAVERSAL_FILE match"
    return m


#: (name, expect_killed, source)
ARCHETYPES = [
    # --- KILL: the argument provably folds to a constant (the 16 FPs) ----
    ("fp-bare-ident-safe", True, """
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
"""),
    ("fp-switch-pruned", True, """
public void doPost(HttpServletRequest request, HttpServletResponse response) {
    String param = request.getParameter("x");
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
            bar = "bob's your uncle";
            break;
    }
    String fileName = org.owasp.benchmark.helpers.Utils.TESTFILES_DIR + bar;
    java.nio.file.Path path = java.nio.file.Paths.get(fileName);
}
"""),
    ("fp-ternary-const", True, """
public void doPost(HttpServletRequest request, HttpServletResponse response) {
    String param = request.getHeader("x");
    String bar;
    int num = 106;
    bar = (7 * 18) + num > 200 ? "This_should_always_happen" : param;
    String fileName = org.owasp.benchmark.helpers.Utils.TESTFILES_DIR + bar;
    java.nio.file.Path path = java.nio.file.Paths.get(fileName);
}
"""),
    ("fp-helper-list", True, """
public void doPost(HttpServletRequest request, HttpServletResponse response) {
    String param = request.getParameter("x");
    String bar = new Test().doSomething(request, param);
    String fileName = org.owasp.benchmark.helpers.Utils.TESTFILES_DIR + bar;
    java.nio.file.Path path = java.nio.file.Paths.get(fileName);
}

private class Test {
    public String doSomething(HttpServletRequest request, String param) {
        String bar = "alsosafe";
        java.util.List<String> valuesList = new java.util.ArrayList<String>();
        valuesList.add("safe");
        valuesList.add(param);
        valuesList.add("moresafe");
        valuesList.remove(0);
        bar = valuesList.get(1);
        return bar;
    }
}
"""),
    # --- KEEP: every true-positive / unprovable shape --------------------
    ("tp-tainted-ident", False, """
public void doPost(HttpServletRequest request, HttpServletResponse response) {
    String param = request.getParameter("file");
    String fileName = org.owasp.benchmark.helpers.Utils.TESTFILES_DIR + param;
    java.nio.file.Path path = java.nio.file.Paths.get(fileName);
}
"""),
    ("tp-concat-tainted", False, """
public void doPost(HttpServletRequest request, HttpServletResponse response) {
    String fileName = request.getParameter("file");
    java.nio.file.Path path = java.nio.file.Paths.get("/base/" + fileName);
}
"""),
    ("tp-method-param", False, """
public void read(String filename) {
    java.nio.file.Path path = java.nio.file.Paths.get(filename);
}
"""),
    ("tp-qualified-call", False, """
public void doPost(HttpServletRequest request, HttpServletResponse response) {
    String param = request.getParameter("file");
    String fileName = org.owasp.benchmark.helpers.Utils.TESTFILES_DIR + param;
    java.nio.file.Path path = java.nio.file.Paths.get(Utils.resolve(fileName));
}
"""),
    ("keep-pure-literal", False, """
public void go() {
    java.nio.file.Path path = java.nio.file.Paths.get("path/to/file");
}
"""),
    ("keep-unbalanced-parens", False, """
public void go() {
    java.nio.file.Path path = java.nio.file.Paths.get(fileName
}
"""),
    ("keep-no-identifier", False, """
public void go() {
    java.io.File f = new File("filename");
}
"""),
    ("keep-unknown-var", False, """
public void go() {
    java.nio.file.Path path = java.nio.file.Paths.get(mysteryFileName);
}
"""),
]


@pytest.mark.parametrize("name,killed,source", ARCHETYPES,
                         ids=[a[0] for a in ARCHETYPES])
def test_archetype_gate(name, killed, source):
    """Each archetype is killed only when its argument provably folds."""
    match = _match_of(source)
    proven = _java_path_arg_proven_constant(source, match, "<archetype>")
    assert proven is killed, name


def test_gate_is_disabled_with_kill_switch(monkeypatch):
    """RSX_MULTIPART_FLOW=0 disables the shared evaluator, hence the gate."""
    monkeypatch.setenv("RSX_MULTIPART_FLOW", "0")
    assert gate_enabled() is False
    source = ARCHETYPES[0][2]
    match = _match_of(source)
    assert _java_path_arg_proven_constant(source, match, "<archetype>") is False


def test_gate_survives_hostile_input():
    """No input may raise: the helper returns False on every failure."""
    cases = [
        "",                                  # empty source
        "\x00\x01\x02binary",                # binary garbage
        "Paths.get(",                        # truncated call
        "new File(" + "(" * 200,            # deeply unbalanced
        "Paths.get(" + '"' * 100,           # unterminated string
        "Paths.get(a",                       # no closing paren
    ]
    for src in cases:
        m = _RULE.search(src)
        if m is None:
            m = _match_of("Paths.get(fileName)")  # any match object
        assert _java_path_arg_proven_constant(src, m, None) in (True, False)


def test_gate_never_accepts_request_sourced_ident():
    """A request-derived identifier inside the args must never prove."""
    src = """
public void doPost(HttpServletRequest request) {
    String fileName = request.getParameter("f");
    java.nio.file.Path path = java.nio.file.Paths.get(fileName);
}
"""
    m = _match_of(src)
    assert _java_path_arg_proven_constant(src, m, "<tp>") is False


# ---------------------------------------------------------------------------
# Layer 2 — wiring through scanner.sast.scan_file against the golden corpus
# ---------------------------------------------------------------------------

def _rule_hits(path: Path) -> list[dict]:
    return [f for f in scan_file(str(path))
            if f.get("rule_id") == "JAVA_PATH_TRAVERSAL_FILE"]


def test_corpus_vulnerable_fixture_keeps_path_finding():
    """VulnerableServlet's tainted-concat TP must survive the gate."""
    target = SAST_CORPUS / "java" / "VulnerableServlet.java"
    hits = _rule_hits(target)
    assert [h.get("line") for h in hits] == [38]


def test_corpus_safe_fixture_untouched_by_value_gate():
    """SafeServlet's guarded finding is NOT provable by value (the guard
    layer's job, not the evaluator's) -- the value gate must not claim it."""
    target = SAST_CORPUS / "java" / "SafeServlet.java"
    assert len(_rule_hits(target)) == 1


# ---------------------------------------------------------------------------
# Honesty — the gate only ever KILLs, and only via the shared evaluator
# ---------------------------------------------------------------------------

def test_kill_direction_is_structural():
    """The helper has no code path that turns a finding INTO a finding: it
    is consulted only to skip emission, never to add. In scan_file the gate
    sits inside the enterprise-rule loop and precedes that loop's append."""
    from scanner import sast
    import inspect
    src = inspect.getsource(sast.scan_file)
    gate_at = src.index("_java_path_arg_proven_constant")
    # The enterprise loop's append is the LAST append in scan_file.
    append_at = src.rindex("findings.append(_make_finding(rule, filepath, lineno, snippet, language))")
    assert gate_at < append_at
    # And the guard is a `continue`, i.e. it can only remove.
    guard_region = src[gate_at:append_at]
    assert "continue" in guard_region
