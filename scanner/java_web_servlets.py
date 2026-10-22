"""Java servlet cookie-security rules (CWE-614 / CWE-1004).

WHAT SHIPPED, AND WHAT DELIBERATELY DID NOT
-------------------------------------------
One rule ships: cookie hardening. It measures recall 1.0000 (36 of 36 declared
BenchmarkJava cases) with false-positive rate 0.0000 (0 of 31 declared-benign
cases).

A second rule for CWE-79 XSS was written, measured, and REJECTED. It is not in
this file, and the reason is recorded here so nobody re-adds it without the
numbers:

    variant                          recall    FPR
    permissive (transitive taint)     0.5569   0.4115   <- rejected
    strict (single-hop taint)        0.0000   0.0000   <- detects nothing

The permissive variant lifts XSS recall from the then-current 0.2358 (58 of
246, the G-101 baseline recorded in docs/gap_analysis.md) but fires on 86 of
209 declared-benign cases. Trading 137 true findings for 86 false ones is not a
fix, and shipping it would have improved the headline recall number while
degrading the tool. The strict variant is precise because it is blind:
BenchmarkJava never assigns a variable directly from a request source
(`String param = ""` then `param = values[0]`), so single-hop taint matches
nothing at all. Recall 0.0000 is not a pass.

MEASUREMENT RECONCILIATION (2026-10-22, G24)
--------------------------------------------
The "XSS is an OPEN gap" reading is STALE at the tool level and remains true
only for THIS module, which still deliberately ships no XSS rule. The G-101
0.2358 figure is a historical point-in-time baseline (58 of 246, taken when
overall BenchmarkJava recall was 0.6064 after the G-100 path-traversal fix);
it predates the Java taint layer that now covers the servlet XSS shape.
Measured on the current pipeline (benchmark dump findings34_fp0.json,
2026-10-22): xss 246 found of 246 expected-vulnerable, 246 CWE-aligned, fpT 0
and fpF 0 over 209 declared-benign cases, every one of the 246 rows emitted by
`JAVA_TAINT_XSS` as CWE-79. Re-deriving these numbers needs
`python -m analysis.validation.owasp_benchmark --benchmark-dir <clone>`; they
come from the taint engine, not from a servlet-window rule, which is why the
rejected designs above were never needed. Do not read the paragraph above as a
claim that the product still misses servlet XSS.

THE COOKIE RULE, AND WHY IT IS VARIABLE-SCOPED
----------------------------------------------
The first version asked "does this method set setSecure(true) anywhere?" and found
0 of 36. Reading BenchmarkTest00087 showed why, and it is a general lesson:

    userCookie = new Cookie(...);  userCookie.setSecure(true);   <- hardened
    Cookie cookie = new Cookie(...); cookie.setSecure(false);    <- NOT hardened

A method-level check sees the hardened cookie and suppresses the finding, hiding
the one that is actually wrong. So the check is per VARIABLE: a cookie is reported
when its own variable is explicitly set insecure, or when that variable reaches
`response.addCookie` with no `setSecure(true)` on it.

WHAT THIS RULE CLAIMS, PRECISELY
--------------------------------
It reports that the Secure flag is not set on this cookie variable in this method.
It does NOT claim the cookie reaches a browser over an insecure channel, and it
does not claim a vulnerability was exploited. A source scan can observe the
absence of hardening; it cannot observe the transport. Severity is MEDIUM and
confidence MEDIUM for that reason, and the `note` travels with every finding so
the limit cannot be lost downstream.

This closes G-099, which recorded that the product had no cookie rule at all: 0
rule ids containing COOKIE and 0 references to CWE-614 or CWE-1004.
"""
from __future__ import annotations

import re

# A cookie constructor, qualified or not: `new Cookie(`, `new java.io.Cookie(`.
_COOKIE_NEW_RE = re.compile(
    r"(?P<var>[A-Za-z_$][\w$]*)\s*=\s*"
    r"(?:new\s+(?:[A-Za-z_$][\w$]*\s*\.\s*)*)?"
    r"(?:[A-Za-z_$][\w$]*\s*\.\s*)*Cookie\s*\(",
    re.I,
)

_ADD_COOKIE_RE = re.compile(
    r"\b(?:response|resp|httpResponse)\s*\.\s*addCookie\s*\(", re.I)


def _methods(source: str):
    """Yield (name, body) per method.

    The access modifier is OPTIONAL. An earlier version required
    public/private/protected, so a package-private or plain `void f(){...}` parsed
    as no method at all and two unit guards failed for a reason that had nothing
    to do with the rules under test. Static and other modifiers are permitted in
    any order.
    """
    pattern = re.compile(
        r"(?:(?:public|private|protected|static|final|synchronized|abstract|"
        r"native|default|strictfp)\s+)*"
        r"[\w$<>,\[\]\s\.]+?\s+"
        r"(?P<name>[A-Za-z_$][\w$]*)\s*\([^)]*\)\s*(?:throws\s[\w$.,\s]*)?\{",
        re.S)
    for m in pattern.finditer(source):
        start = m.end() - 1
        depth = 0
        for i in range(start, len(source)):
            if source[i] == "{":
                depth += 1
            elif source[i] == "}":
                depth -= 1
                if depth == 0:
                    yield m.group("name"), source[start + 1:i]
                    break


def _line_of(source: str, pos: int) -> int:
    return source.count("\n", 0, max(0, pos)) + 1


def _line_text(source: str, pos: int) -> str:
    """The source line containing `pos`, stripped.

    Every other engine ships the offending source line as `snippet`, and the
    report pipeline depends on it in two separate places:

      * `_root_cause_key()` falls back to `vuln_type|_normalise_sink(snippet)`,
        so a finding without a snippet has an empty sink and shares one root
        cause with every other finding of its type -- in this file's case, all
        36 cookie findings collapsed into a single key.
      * `_apply_evidex_validation()` checks each occurrence's snippet; an empty
        one marks the occurrence `evidence_valid = False`, and `enrich_finding()`
        then returns `{}` at core/analyzer.py, discarding the finding entirely.

    The second is the reason this rule shipped while reporting nothing: the
    rules ran, produced 36 true positives, and every one was dropped at intake.
    """
    if pos < 0 or pos >= len(source):
        return ""
    start = source.rfind("\n", 0, pos) + 1
    end = source.find("\n", pos)
    if end < 0:
        end = len(source)
    return source[start:end].strip()


def scan_java_cookie_security(source: str, path: str = "") -> list:
    """Per-variable cookie hardening check. CWE-614 / CWE-1004."""
    if not source:
        return []
    out: list = []

    for name, body in _methods(source):
        if not _ADD_COOKIE_RE.search(body):
            # A cookie never added to a response is not a response-cookie concern.
            continue
        offset = source.find(body)
        base_line = _line_of(source, offset) if offset >= 0 else 1

        for m in _COOKIE_NEW_RE.finditer(body):
            var = m.group("var")
            escaped = re.escape(var)

            # Scoped to THIS variable. A method-level check would let one hardened
            # cookie mask another that is left insecure, which is exactly what
            # BenchmarkTest00087 does.
            if re.search(rf"\b{escaped}\s*\.\s*setSecure\s*\(\s*true\s*\)",
                         body, re.I):
                continue

            explicit_false = re.search(
                rf"\b{escaped}\s*\.\s*setSecure\s*\(\s*false\s*\)", body, re.I)
            reason = (
                f"cookie variable '{var}' is explicitly set with setSecure(false)"
                if explicit_false else
                f"cookie variable '{var}' reaches the response with no "
                f"setSecure(true) on that variable")

            line = base_line + body.count("\n", 0, m.start())
            # Absolute position of this match, so the snippet is the line the
            # cookie is actually constructed on rather than some other line of
            # the same method.
            snippet = _line_text(source, offset + m.start() if offset >= 0
                                 else m.start())
            out.append({
                "rule_id": "JAVA_WEB_COOKIE_MISSING_SECURITY_FLAGS",
                "vuln_type": "insecure_cookie_configuration",
                "cwe": "CWE-614",
                "cwe_ids": ["CWE-614", "CWE-1004"],
                "title": "Response cookie set without the Secure flag",
                # SEVERITY_ORDER and CONFIDENCE_RANK are title-case.  Shipping
                # "MEDIUM" put a stray non-canonical key into
                # severity_distribution, sorted the finding to rank 99 in
                # group_by_severity, and made CONFIDENCE_RANK miss (0, not 2).
                "severity": "Medium",
                "file": path,
                "line": line,
                # Required for intake: see _line_text above.
                "snippet": snippet,
                # Deduplicate on (vuln_type, file, line) -- the contract the
                # wiring comment in sast.py states.  Without a group_key the
                # root-cause key is `vuln_type|sink`, so every cookie finding
                # in every file merges into a single root cause.
                "group_key": (f"java-web-servlet|insecure_cookie_configuration"
                              f"|{path}|{line}"),
                "description": f"method {name}(): {reason}",
                "evidence_type": "pattern-detected",
                "evidence": reason,
                "confidence": "Medium",
                "semantic_scope": "VARIABLE_SCOPED",
                "note": (
                    "ABSENCE OF HARDENING, not proven exploitability. This reports "
                    "that the Secure flag is not set on this cookie variable in "
                    "this method. It does NOT claim the cookie reaches a browser "
                    "over an insecure channel, which a static source scan cannot "
                    "establish. CWE-1004 (HttpOnly) is tracked on the same finding "
                    "as a secondary attribute; only Secure is asserted."),
            })

    seen = set()
    uniq = []
    for f in out:
        key = (f["rule_id"], f.get("file"), f.get("line"))
        if key in seen:
            continue
        seen.add(key)
        uniq.append(f)
    return uniq


# Backwards-compatible alias. The XSS rule that used to live here was REJECTED at
# FPR 0.4115; see the module docstring for the measurements and the reason.
scan_java_web_servlets = scan_java_cookie_security