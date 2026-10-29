"""T-4.3: fix validation (apply patch -> re-scan -> fix_confirmed).

Covers: the strict unified-diff applier (exact context, path-escape and
cap rejection, no partial writes), the root-relative finding matcher,
test discovery, and the full validate_fix verdict table (happy path,
no-op patch, broken fix, red baseline, missing tests) plus CLI plumbing.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from analysis.repro import fix_validation as fv

# --- fixture target: an H1 SQL-interpolation finding + tiny test suite -----
VULN_CODE_LINE = (
    '''    q = "SELECT * FROM users WHERE id = '%s'" % {"user_id": user_id}'''
)
FIX_CODE_LINE = '''    q = "SELECT * FROM users WHERE id = %s"'''
APP_VULN = (
    "def make_query(user_id):\n"
    + VULN_CODE_LINE + "\n"
    + "    return q\n"
)
PASSING_TEST = (
    "from app import make_query\n"
    "\n"
    "def test_query_builds():\n"
    '    q = make_query("7")\n'
    '    assert "users" in str(q)\n'
)
FAILING_TEST = "assert 1 == 2\n"

HAPPY_PATCH = (
    "--- a/app.py\n"
    "+++ b/app.py\n"
    "@@ -1,3 +1,3 @@\n"
    " def make_query(user_id):\n"
    "-" + VULN_CODE_LINE + "\n"
    "+" + FIX_CODE_LINE + "\n"
    "     return q\n"
)


def _write_target(root: Path, with_test: str = "pass") -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "app.py").write_text(APP_VULN, encoding="utf-8")
    if with_test == "pass":
        (root / "test_app.py").write_text(PASSING_TEST, encoding="utf-8")
    elif with_test == "fail":
        (root / "test_app.py").write_text(FAILING_TEST, encoding="utf-8")
    return root


def _finding_for(target: Path) -> dict:
    return {
        "rule_id": "PY_SQL_INTERPOLATED_QUERY",
        "vuln_type": "sql_injection",
        "file": str(target / "app.py"),
        "line": 2,
        "severity": "High",
    }


# --- applier unit tests -----------------------------------------------------
def test_parse_rejects_path_escape_headers():
    for header in ("--- a/../../evil.py\n+++ b/../../evil.py\n",
                   "--- /abs/x.py\n+++ /abs/y.py\n"):
        with pytest.raises(fv.FixApplyError) as ei:
            fv.parse_unified_diff(
                header + "@@ -1 +1 @@\n-x\n+y\n")
        assert ei.value.reason == "PATH_ESCAPE"


def test_parse_respects_hunk_cap(monkeypatch):
    monkeypatch.setattr(fv, "MAX_PATCH_HUNKS", 1)
    diff = ("--- a/x\n+++ b/x\n@@ -1 +1 @@\n-a\n+b\n"
            "--- a/y\n+++ b/y\n@@ -1 +1 @@\n-c\n+d\n")
    with pytest.raises(fv.FixApplyError) as ei:
        fv.parse_unified_diff(diff)
    assert ei.value.reason == "TOO_MANY_HUNKS"


def test_parse_added_line_starting_with_plus_is_not_a_header(tmp_path):
    # "+ added text '++flag'" renders as "+++flag" in the body; the count
    # based parser must treat it as content, then still see the next file
    # header as a header.
    (tmp_path / "a.py").write_text("x\n", encoding="utf-8")
    (tmp_path / "b.py").write_text("keep\n", encoding="utf-8")
    diff = (
        "--- a/a.py\n"
        "+++ b/a.py\n"
        "@@ -1 +1,3 @@\n"
        " x\n"
        "+++flag = True\n"
        "+z\n"
        "--- a/b.py\n"
        "+++ b/b.py\n"
        "@@ -1 +1 @@\n"
        " keep\n"
    )
    changed = fv.apply_unified_diff(tmp_path, diff)
    assert (tmp_path / "a.py").read_text(encoding="utf-8") == \
        "x\n++flag = True\nz\n"
    # the real second header after the "+++flag" content line was parsed
    assert {c["path"] for c in changed} == {"a.py", "b.py"}
    assert (tmp_path / "b.py").read_text(encoding="utf-8") == "keep\n"


def test_apply_exact_context_patch(tmp_path):
    (tmp_path / "app.py").write_text(APP_VULN, encoding="utf-8")
    changed = fv.apply_unified_diff(tmp_path, HAPPY_PATCH)
    assert changed == [{"path": "app.py", "action": "modify"}]
    assert (tmp_path / "app.py").read_text(encoding="utf-8") == (
        "def make_query(user_id):\n" + FIX_CODE_LINE + "\n    return q\n"
    )


def test_wrong_context_fails_with_no_partial_write(tmp_path):
    (tmp_path / "a.py").write_text("x\n", encoding="utf-8")
    (tmp_path / "b.py").write_text("real\n", encoding="utf-8")
    diff = (
        "--- a/a.py\n"
        "+++ b/a.py\n"
        "@@ -1 +1 @@\n"
        "-x\n"
        "+y\n"
        "--- a/b.py\n"
        "+++ b/b.py\n"
        "@@ -1 +1 @@\n"
        "-wrong\n"
        "+z\n"
    )
    with pytest.raises(fv.FixApplyError) as ei:
        fv.apply_unified_diff(tmp_path, diff)
    assert ei.value.reason == "APPLY_FAILED"
    # a.py was verified first -- but no write happened at all
    assert (tmp_path / "a.py").read_text(encoding="utf-8") == "x\n"
    assert (tmp_path / "b.py").read_text(encoding="utf-8") == "real\n"


def test_apply_create_and_delete(tmp_path):
    (tmp_path / "keep.py").write_text("line1\nline2\n", encoding="utf-8")
    diff = (
        "--- a/keep.py\n"
        "+++ /dev/null\n"
        "@@ -1,2 +0,0 @@\n"
        "-line1\n"
        "-line2\n"
        "--- /dev/null\n"
        "+++ b/new.py\n"
        "@@ -0,0 +1,2 @@\n"
        "+alpha\n"
        "+beta\n"
    )
    changed = fv.apply_unified_diff(tmp_path, diff)
    assert {c["path"]: c["action"] for c in changed} == {
        "keep.py": "delete", "new.py": "create"}
    assert not (tmp_path / "keep.py").exists()
    assert (tmp_path / "new.py").read_text(encoding="utf-8") == \
        "alpha\nbeta\n"


# --- matcher + test discovery unit tests ------------------------------------
def test_finding_present_matches_across_copy_roots(tmp_path):
    # finding.file is absolute under ORIG; scan rows come from a private
    # copy under a different root -- they must still match by the
    # target-relative suffix signature.
    target = _write_target(tmp_path / "orig")
    copy = _write_target(tmp_path / "rsx_fix_copy")
    finding = _finding_for(target)  # absolute path under orig/
    rows = [{"rule_id": "PY_SQL_INTERPOLATED_QUERY",
             "file": str(copy / "app.py"), "line": 99}]
    hits = fv.finding_present(rows, finding, target=target)
    assert len(hits) == 1 and hits[0]["line"] == 99
    # wrong rule / wrong file never match
    assert fv.finding_present(
        [{"rule_id": "OTHER", "file": str(copy / "app.py")}],
        finding, target=target) == []
    assert fv.finding_present(
        [{"rule_id": "PY_SQL_INTERPOLATED_QUERY",
          "file": str(copy / "other.py")}],
        finding, target=target) == []


def test_new_findings_reports_only_pairs_absent_before():
    before = [{"rule_id": "R1", "file": "a.py"},
              {"rule_id": "R2", "file": "b.py"}]
    after = [{"rule_id": "R1", "file": "a.py"},      # surviving
             {"rule_id": "R2", "file": "c.py"},      # new pair
             {"rule_id": "R3", "file": "d.py"}]      # new rule
    added = fv._new_findings(before, after)
    assert {(a["rule_id"], a["file"]) for a in added} == {
        ("R2", "c.py"), ("R3", "d.py")}


def test_detect_test_cmd_flat_layout_and_missing(tmp_path):
    (tmp_path / "test_x.py").write_text("def test_x():\n    pass\n",
                                        encoding="utf-8")
    assert fv._detect_test_cmd(tmp_path) == fv._pytest_cmd()
    empty = tmp_path / "empty"
    empty.mkdir()
    assert fv._detect_test_cmd(empty) is None


# --- full verdict table (validate_fix) --------------------------------------
def test_validate_fix_happy_path(tmp_path):
    target = _write_target(tmp_path / "tgt")
    report = fv.validate_fix(target, HAPPY_PATCH, _finding_for(target))
    assert report["schema"] == fv.FIX_REPORT_SCHEMA
    assert report["fix_confirmed"] is True
    assert report["patch_applied"] is True
    assert report["finding_cleared"] is True
    assert report["tests_passed"] is True
    assert report["before"]["present"] is True
    assert report["after"]["present"] is False
    assert report["tests_before"]["passed"] is True
    assert report["tests_after"]["passed"] is True
    assert report["new_findings"]["count"] == 0
    assert report["files_changed"] == [{"path": "app.py",
                                        "action": "modify"}]
    assert len(report["patch_sha256"]) == 64
    json.dumps(report)  # must be serializable for fix_report.json
    # the real target was never mutated
    assert VULN_CODE_LINE in (target / "app.py").read_text(
        encoding="utf-8")


def test_validate_fix_noop_patch_keeps_finding(tmp_path):
    target = _write_target(tmp_path / "tgt")
    noop = (
        "--- a/app.py\n"
        "+++ b/app.py\n"
        "@@ -1,3 +1,4 @@\n"
        "+# harmless comment\n"
        " def make_query(user_id):\n"
        "-" + VULN_CODE_LINE + "\n"
        "+" + VULN_CODE_LINE + "\n"
        "     return q\n"
    )
    report = fv.validate_fix(target, noop, _finding_for(target))
    assert report["patch_applied"] is True
    assert report["finding_cleared"] is False
    assert report["fix_confirmed"] is False
    assert any(r.startswith("FINDING_STILL_PRESENT")
               for r in report["reasons"])


def test_validate_fix_broken_fix_fails_tests(tmp_path):
    target = _write_target(tmp_path / "tgt")
    broken = (
        "--- a/app.py\n"
        "+++ b/app.py\n"
        "@@ -1,3 +1,3 @@\n"
        " def make_query(user_id):\n"
        "-" + VULN_CODE_LINE + "\n"
        '+' + FIX_CODE_LINE[:-1] + '  # broken\n'  # drops the closing }
        "     return q\n"
    )
    report = fv.validate_fix(target, broken, _finding_for(target))
    assert report["patch_applied"] is True
    assert report["tests_passed"] is False
    assert report["fix_confirmed"] is False
    assert any(r.startswith("TESTS_FAILED_AFTER")
               for r in report["reasons"])


def test_validate_fix_red_baseline_cannot_demonstrate_still(tmp_path):
    target = _write_target(tmp_path / "tgt", with_test="fail")
    report = fv.validate_fix(target, HAPPY_PATCH, _finding_for(target))
    assert report["patch_applied"] is True
    assert report["finding_cleared"] is True
    assert report["tests_passed"] is None
    assert report["fix_confirmed"] is False
    assert any(r.startswith("TESTS_BROKEN_BASELINE")
               for r in report["reasons"])


def test_validate_fix_no_tests_is_not_confirmed(tmp_path):
    target = _write_target(tmp_path / "tgt", with_test=None)
    report = fv.validate_fix(target, HAPPY_PATCH, _finding_for(target))
    assert report["patch_applied"] is True
    assert report["finding_cleared"] is True
    assert report["tests_passed"] is None
    assert report["fix_confirmed"] is False
    assert any(r.startswith("TESTS_NOT_FOUND")
               for r in report["reasons"])


# --- CLI --------------------------------------------------------------------
def test_cli_reports_absent_finding_and_writes_report(tmp_path):
    target = _write_target(tmp_path / "tgt")
    patch = tmp_path / "p.diff"
    patch.write_text(HAPPY_PATCH, encoding="utf-8")
    finding = tmp_path / "f.json"
    finding.write_text(json.dumps({"rule_id": "NO_SUCH_RULE",
                                   "file": "app.py"}), encoding="utf-8")
    out = tmp_path / "report.json"
    rc = fv.main(["--target", str(target), "--patch", str(patch),
                  "--finding", str(finding), "--out", str(out)])
    assert rc == 1
    rep = json.loads(out.read_text(encoding="utf-8"))
    assert rep["schema"] == fv.FIX_REPORT_SCHEMA
    assert rep["fix_confirmed"] is False
    assert any(r.startswith("FINDING_ABSENT_BEFORE")
               for r in rep["reasons"])
