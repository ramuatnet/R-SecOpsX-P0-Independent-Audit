"""Phase 0 task 0.3 -- the servlet-rules guard must report, and must not lose
the J5 findings with it.

Before the fix the guard called _safe_print(), which is not defined in
scanner/sast.py.  The resulting NameError escaped to the outer
`except Exception: pass`, so the diagnostic was never printed *and* the
`_servlet_findings = []` assignment was skipped -- which made the J5 merge
raise UnboundLocalError, silently dropping every cross-file Java finding.

Measured on the live code before the fix: a forced servlet failure returned
zero findings and printed nothing.  These tests pin both halves of that.
"""
import sys
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Importing main installs the console handler that _safe_print() routes
# through.  Without it the "rsx" logger exists only as an auto-created
# parent, so the record would propagate to root and the test would be
# checking a path the running tool never takes.
import main  # noqa: E402,F401  (installs rsx console logging)

import scanner.sast as sast  # noqa: E402


@pytest.fixture()
def forced_servlet_failure(monkeypatch, tmp_path):
    """Fail the servlet-rules import and make J5 return a sentinel finding."""
    (tmp_path / "x.java").write_text("class X {}", encoding="utf-8")

    # A module with no `scan_java_web_servlets` attribute makes
    # `from scanner.java_web_servlets import scan_java_web_servlets` raise.
    monkeypatch.setitem(
        sys.modules, "scanner.java_web_servlets",
        types.ModuleType("scanner.java_web_servlets"),
    )

    j5 = types.ModuleType("scanner.java_semantic_j5")
    j5.analyze_java_project = lambda p: [{
        "vuln_type": "J5_SENTINEL", "file": "sentinel.java", "line": 1,
        "sink_call": "probe()", "title": "t", "severity": "High",
    }]
    monkeypatch.setitem(sys.modules, "scanner.java_semantic_j5", j5)
    return tmp_path


def _code_lines(path):
    """Source lines with comments removed, so an assertion about a *call*
    cannot be satisfied by a comment that spells the name out."""
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        stripped = line.split("#", 1)[0]
        if stripped.strip():
            yield stripped


def test_a_servlet_failure_no_longer_swallows_the_j5_findings(
        forced_servlet_failure, capsys):
    findings = sast.scan_directory(str(forced_servlet_failure), workers=1)
    seen = [f.get("vuln_type") for f in findings]
    assert "J5_SENTINEL" in seen, seen


def test_the_servlet_failure_is_reported_on_the_console(
        forced_servlet_failure, capsys):
    sast.scan_directory(str(forced_servlet_failure), workers=1)
    assert "servlet rules unavailable" in capsys.readouterr().out


def test_the_servlet_guard_does_not_call_an_undefined_name():
    lines = list(_code_lines(ROOT / "scanner" / "sast.py"))
    assert not [l for l in lines if "_safe_print(" in l]
    assert [l for l in lines if "_LOG.warning(" in l]


def test_the_bare_swallow_in_the_semical_layer_is_logged():
    lines = list(_code_lines(ROOT / "scanner" / "sast.py"))
    assert [l for l in lines if "_LOG.debug(" in l]
