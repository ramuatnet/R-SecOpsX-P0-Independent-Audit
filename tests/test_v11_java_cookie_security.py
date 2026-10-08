"""Tests for the cookie-security rule, including the variant it REPLACED.

The load-bearing tests here are negative. A cookie rule that fires on every
`new Cookie(` is trivially useless, and the rejected XSS rule in the same module
is the cautionary example: it lifted recall and fired on 86 of 209 benign cases.

What must stay true:
  * one hardened cookie must not mask an insecure one (this is the bug in the
    method-scoped version, and BenchmarkTest00087 reproduces it exactly)
  * a cookie that is never added to a response is not a response-cookie concern
  * the rule never claims the cookie reaches a browser insecurely
"""
from __future__ import annotations

import pathlib
import re
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scanner.java_web_servlets import (  # noqa: E402
    _methods,
    scan_java_cookie_security,
    scan_java_web_servlets,
)

BENCHMARK_ROOT = pathlib.Path(r"D:\Data\Code test\prodtest\BenchmarkJava-master")
TESTCODE = (BENCHMARK_ROOT / "src" / "main" / "java" / "org" / "owasp"
            / "benchmark" / "testcode")


def ids(src: str):
    return [f["rule_id"] for f in scan_java_cookie_security(src, "T.java")]


# ===========================================================================
# The bug the variable scope exists to prevent
# ===========================================================================

def test_one_hardened_cookie_does_not_mask_an_insecure_one():
    """BenchmarkTest00087's exact shape: one hardened, one not."""
    src = (
        'void f(){\n'
        '  userCookie = new Cookie("a","b");\n'
        '  userCookie.setSecure(true);\n'
        '  response.addCookie(userCookie);\n'
        '  Cookie cookie = new Cookie("SomeCookie", str);\n'
        '  cookie.setSecure(false);\n'
        '  cookie.setHttpOnly(true);\n'
        '  response.addCookie(cookie);\n'
        '}')
    hits = scan_java_cookie_security(src, "T.java")
    assert len(hits) == 1, hits
    assert "cookie" in hits[0]["description"]


def test_qualified_cookie_constructor_is_matched():
    src = ('void f(){\n'
           '  javax.servlet.http.Cookie c = new javax.servlet.http.Cookie("n","v");\n'
           '  response.addCookie(c);\n'
           '}')
    assert len(scan_java_cookie_security(src, "T.java")) == 1


def test_explicit_setsecure_false_is_named_in_the_reason():
    src = ('void f(){\n'
           '  Cookie c = new Cookie("n","v");\n'
           '  c.setSecure(false);\n'
           '  response.addCookie(c);\n'
           '}')
    hit = scan_java_cookie_security(src, "T.java")[0]
    assert "setSecure(false)" in hit["description"]


def test_absent_setsecure_is_reported_as_absence_not_as_exploit():
    src = ('void f(){\n'
           '  Cookie c = new Cookie("n","v");\n'
           '  response.addCookie(c);\n'
           '}')
    hit = scan_java_cookie_security(src, "T.java")[0]
    assert "no setSecure(true)" in hit["description"]
    assert "ABSENCE OF HARDENING" in hit["note"]


# ===========================================================================
# NEGATIVE: must not fire
# ===========================================================================

def test_hardened_cookie_is_not_reported():
    src = ('void f(){\n'
           '  Cookie c = new Cookie("n","v");\n'
           '  c.setSecure(true);\n'
           '  response.addCookie(c);\n'
           '}')
    assert scan_java_cookie_security(src, "T.java") == []


def test_httponly_alone_does_not_suppress_but_secure_does():
    """Only Secure is asserted. HttpOnly is a secondary attribute, so a cookie
    with HttpOnly but no Secure is still reported -- the assertion must match the
    claim."""
    src = ('void f(){\n'
           '  Cookie c = new Cookie("n","v");\n'
           '  c.setHttpOnly(true);\n'
           '  response.addCookie(c);\n'
           '}')
    assert len(scan_java_cookie_security(src, "T.java")) == 1


def test_cookie_never_added_to_a_response_is_not_reported():
    src = ('void f(){\n'
           '  Cookie c = new Cookie("n","v");\n'
           '  c.setDomain("example.com");\n'
           '}')
    assert scan_java_cookie_security(src, "T.java") == []


def test_cookie_on_a_different_variable_does_not_suppress():
    """NEGATIVE: hardening must be per variable, not merely present in the body."""
    src = ('void f(){\n'
           '  Cookie a = new Cookie("a","v");\n'
           '  Cookie b = new Cookie("b","v");\n'
           '  b.setSecure(true);\n'
           '  response.addCookie(a);\n'
           '  response.addCookie(b);\n'
           '}')
    hits = scan_java_cookie_security(src, "T.java")
    assert len(hits) == 1
    assert "'a'" in hits[0]["description"]


def test_unrelated_java_produces_nothing():
    src = ('public class T {\n'
           '  public void doGet(HttpServletRequest request,\n'
           '                    HttpServletResponse response) {\n'
           '    String p = request.getParameter("x");\n'
           '    response.getWriter().println(p);\n'
           '  }\n'
           '}')
    assert scan_java_cookie_security(src, "T.java") == []


def test_empty_source_is_safe():
    assert scan_java_cookie_security("", "T.java") == []
    assert scan_java_cookie_security(None, "T.java") == []


# ===========================================================================
# Method parsing
# ===========================================================================

def test_method_without_an_access_modifier_is_parsed():
    """The original pattern demanded an access modifier, so `void f(){}` parsed
    as no method at all."""
    assert len(list(_methods("void f(){ int x=1; }"))) == 1


@pytest.mark.parametrize("prefix", [
    "public", "private", "protected", "static", "public static", "public final",
    "protected final synchronized", "",
])
def test_accepted_method_prefixes(prefix):
    assert len(list(_methods(f"{prefix} void f(){{ int x=1; }}"))) == 1


def test_nested_braces_do_not_truncate_the_body():
    src = 'void f(){ if (x) { y(); } } void g(){ z(); }'
    names = [n for n, _ in _methods(src)]
    assert names == ["f", "g"], names


# ===========================================================================
# The claim this rule does not make
# ===========================================================================

def test_finding_never_claims_browser_reachability():
    src = ('void f(){\n  Cookie c = new Cookie("n","v");\n'
           '  response.addCookie(c);\n}')
    hit = scan_java_cookie_security(src, "T.java")[0]
    blob = (hit["description"] + hit["note"] + hit["title"]).lower()
    assert "does not claim the cookie reaches a browser" in blob
    assert hit["confidence"] == "MEDIUM"
    assert hit["semantic_scope"] == "VARIABLE_SCOPED"


def test_finding_carries_both_cwe_ids():
    src = ('void f(){\n  Cookie c = new Cookie("n","v");\n'
           '  response.addCookie(c);\n}')
    hit = scan_java_cookie_security(src, "T.java")[0]
    assert "CWE-614" in hit["cwe_ids"]


# ===========================================================================
# The rejected XSS rule must stay rejected
# ===========================================================================

def test_the_rejected_xss_rule_is_absent_from_production_source():
    """NEGATIVE and load-bearing.

    A rejected rule left in the tree is worse than no rule: it will be enabled by
    a later edit, or shipped by a caller that imports the old name. The alias
    exists only so the old import name resolves to the cookie rule.
    """
    assert scan_java_web_servlets is scan_java_cookie_security
    src = (ROOT / "scanner" / "java_web_servlets.py").read_text(encoding="utf-8")
    assert "JAVA_WEB_RESPONSE_WRITE_UNENCODED" not in src, (
        "the XSS rule was rejected at FPR 0.4115 and must not return")
    for f in (ROOT / "scanner" / "sast.py",):
        t = f.read_text(encoding="utf-8")
        assert "JAVA_WEB_RESPONSE_WRITE_UNENCODED" not in t, (
            f"{f.name} still wires the rejected XSS rule")


def test_the_rejection_is_documented_with_its_numbers():
    src = (ROOT / "scanner" / "java_web_servlets.py").read_text(encoding="utf-8")
    assert "0.4115" in src, "the rejected variant's FPR must stay on record"
    assert "0.0000" in src, "the blind variant's recall must stay on record"


def test_no_duplicate_findings_on_one_line():
    src = ('void f(){\n  Cookie c = new Cookie("n","v");\n'
           '  Cookie d = new Cookie("m","w");\n'
           '  response.addCookie(c); response.addCookie(d);\n}')
    hits = scan_java_cookie_security(src, "T.java")
    keys = [(h["rule_id"], h["line"]) for h in hits]
    assert len(keys) == len(set(keys))


# ===========================================================================
# Against the real corpus, when present
# ===========================================================================

@pytest.mark.skipif(not TESTCODE.exists(), reason="corpus not present")
def test_real_declared_vulnerable_cookie_cases_are_detected():
    """Scored against the oracle, not a text heuristic.

    A first version filtered files on `"securecookie" in text`, which also matches
    the 31 declared-BENIGN cases -- and correctly not firing on those is the rule
    WORKING, so it reported 3/5 and would have been misread as a defect. Reading
    expectedresults-1.2.csv separates the populations and lets the test assert both
    directions: every declared-vulnerable case detected, and zero detections among
    declared-benign cases.
    """
    csvs = list(BENCHMARK_ROOT.rglob("expectedresults*.csv"))
    if not csvs:
        pytest.skip("oracle CSV not present")

    rows = []
    for raw in csvs[0].read_text(encoding="utf-8", errors="replace").splitlines():
        raw = raw.strip()
        # The header line is a prose comment, not a header row.
        if not raw or raw.startswith("#"):
            continue
        parts = [x.strip() for x in raw.split(",")]
        if len(parts) == 4 and re.fullmatch(r"BenchmarkTest\d{5}", parts[0]):
            rows.append((parts[0], parts[1], parts[2].lower() == "true"))

    vul = [t for t, c, v in rows if c == "securecookie" and v]
    ben = [t for t, c, v in rows if c == "securecookie" and not v]
    assert vul and ben, "oracle should carry both polarities for securecookie"

    def fired(test: str) -> bool:
        f = TESTCODE / (test + ".java")
        return f.exists() and bool(scan_java_cookie_security(
            f.read_text(encoding="utf-8", errors="replace")))

    tp = sum(1 for t in vul if fired(t))
    fp = sum(1 for t in ben if fired(t))
    assert tp == len(vul), f"recall {tp}/{len(vul)} -- a declared-vulnerable case missed"
    assert fp == 0, f"{fp} false positives on {len(ben)} declared-benign cases"
