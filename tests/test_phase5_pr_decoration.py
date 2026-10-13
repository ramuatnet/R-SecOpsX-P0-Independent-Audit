"""Phase 5.1: PR decoration — comment body + the GitHub Action contract.

WHAT THIS DELIVERS
------------------
Gap-plan row 5.1 ("GitHub Action + PR decoration"). Three pieces:

* reporting/pr_decoration.py builds Security_PR_Comment.md offline and
  deterministically — all comment semantics are testable without a
  runner;
* .github/actions/rsecopsx-scan/action.yml is the composite action: it
  runs the scan, uploads SARIF (continue-on-error so private-repo GHAS
  limits never mask the verdict), publishes artifacts, and dumb-pipes
  the pre-built comment into a sticky PR upsert;
* validation.yml gains a PR-only pr-scan job (deliberately not in
  ci-matrix's needs — a needs-edge onto a skipped job skips the
  dependent job, which would silence ci-matrix on every push).

WHAT THESE TESTS PIN
--------------------
* comment structure: marker, target, counts table in the fixed severity
  scale order, capped top-findings table that discloses how many it
  withheld, snippet section labelled template/never-applied;
* table safety: pipes escaped, newlines flattened, cells length-capped;
* redaction (PEM never reaches the comment), determinism, size limit
  with a deterministic hard-cut fallback;
* the cross-artifact contracts a drift would silently break: the
  Action's SARIF path must be a file main.py writes, its marker must
  equal pr_decoration.MARKER, its comment filename must be the artifact
  main.py writes, and the workflow must gate pr-scan to pull_request.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from reporting.pr_decoration import (  # noqa: E402
    COMMENT_FILENAME,
    MARKER,
    TOP_FINDINGS_CAP,
    build_pr_comment,
    write_pr_comment,
)

ACTION_PATH = ROOT / ".github" / "actions" / "rsecopsx-scan" / "action.yml"
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "validation.yml"
MAIN_SOURCE = (ROOT / "main.py").read_text(encoding="utf-8")


def _finding(rule_id="SQL_INJECTION", severity="High", file="app.py", line=10,
             description="Untrusted input reached the sink.", **extra):
    finding = {
        "rule_id": rule_id,
        "severity": severity,
        "file": file,
        "line": line,
        "description": description,
    }
    finding.update(extra)
    return finding


def _payload(*findings, target="/repo/app", tool="R-SecOpsX SAST v2.0"):
    return {
        "metadata": {"tool": tool, "target": target,
                     "scan_date": "2026-10-13T00:00:00Z"},
        "findings": list(findings),
    }


# ---------------------------------------------------------------------------
# Comment structure.
# ---------------------------------------------------------------------------

def test_header_carries_marker_target_and_counts():
    body = build_pr_comment(
        _payload(_finding(), _finding("XSS", "Low", file="p.js", line=3)))
    assert body.startswith(MARKER)
    assert "## R-SecOpsX scan summary" in body
    assert "`/repo/app`" in body
    assert "R-SecOpsX SAST v2.0" in body
    assert "**Findings:** 2" in body


def test_counts_table_follows_the_fixed_severity_scale_order():
    body = build_pr_comment(
        _payload(_finding(severity="Low"), _finding(severity="Critical"),
                 _finding(severity="High")))
    critical = body.index("| 🔴 Critical | 1 |")
    high = body.index("| 🟠 High | 1 |")
    low = body.index("| 🟢 Low | 1 |")
    assert critical < high < low, "counts must follow the scale, not payload order"


def test_unknown_severity_bucket_is_reported_not_dropped():
    body = build_pr_comment(_payload(_finding(severity="SomeReviewState")))
    assert "SomeReviewState" in body


def test_top_findings_table_is_capped_and_discloses_the_withholding():
    findings = [_finding(rule_id=f"R{i}", severity="Low") for i in range(30)]
    body = build_pr_comment(_payload(*findings))
    data_rows = [
        line for line in body.splitlines()
        if line.startswith("| R") and not line.startswith("| Rule")
    ]
    assert len(data_rows) == TOP_FINDINGS_CAP
    assert "…and 10 more finding(s) not shown here" in body


def test_table_cells_are_pipe_safe_single_line_and_capped():
    body = build_pr_comment(
        _payload(_finding(rule_id="A|B", description="x | y\nz" + "w" * 400)))
    row = [line for line in body.splitlines() if line.startswith("| A")][0]
    assert "A\\|B" in row
    assert "x \\| y z" in row
    assert "\n" not in row
    assert "..." in row


def test_empty_findings_states_it_plainly():
    body = build_pr_comment(_payload())
    assert "**No findings.**" in body
    assert "### Top findings" in body


def test_artifact_list_is_complete():
    body = build_pr_comment(_payload(_finding()))
    for name in ("clean_report.json", "Security_Report.sarif",
                 "Security_Findings_Webhook.json",
                 "Security_Jira_Import.csv",
                 "Security_DefectDojo_Import.json"):
        assert f"`{name}`" in body


# ---------------------------------------------------------------------------
# Fix snippets section.
# ---------------------------------------------------------------------------

def test_snippets_are_labelled_templates_never_applied():
    snippet = {"kind": "parameterized_query", "language": "python",
               "before": "q = f\"SELECT {name}\"",
               "after": "cur.execute('SELECT * FROM t WHERE n=?', (name,))",
               "template": True, "applied": False}
    body = build_pr_comment(_payload(_finding(fix_snippet=snippet)))
    assert "### Fix snippets (templates — never applied)" in body
    assert "`parameterized_query` (python)" in body
    assert "**template, human review required**" in body
    assert "Before:" in body and "After:" in body
    assert "cur.execute('SELECT * FROM t WHERE n=?', (name,))" in body


def test_snippet_section_absent_when_no_finding_carries_one():
    body = build_pr_comment(_payload(_finding()))
    assert "### Fix snippets" not in body


def test_snippet_list_is_capped():
    snippet = {"kind": "k", "language": "python", "before": "a", "after": "b"}
    findings = [_finding(rule_id=f"R{i}", fix_snippet=snippet)
                for i in range(8)]
    body = build_pr_comment(_payload(*findings))
    assert body.count("**template, human review required**") == 5
    assert "…and 3 more snippet(s)" in body


# ---------------------------------------------------------------------------
# Safety: redaction, determinism, size limit.
# ---------------------------------------------------------------------------

def test_pem_never_reaches_the_comment():
    body = build_pr_comment(
        _payload(_finding(
            description="leaked: -----BEGIN RSA PRIVATE KEY-----\nMIIEpAIB\n"
                        "-----END RSA PRIVATE KEY-----")))
    assert "PRIVATE KEY" not in body
    assert "MIIEpAIB" not in body


def test_comment_is_deterministic():
    payload = _payload(_finding("A"), _finding("B", "Critical"))
    assert build_pr_comment(payload) == build_pr_comment(payload)


def test_size_limit_is_honored_with_a_deterministic_hard_cut():
    huge = _finding(description="d" * 100000)
    body = build_pr_comment(_payload(huge), max_chars=60000)
    assert len(body) <= 60000

    tiny = build_pr_comment(_payload(huge), max_chars=200)
    assert len(tiny) <= 200
    assert tiny.endswith("<!-- truncated -->\n")


def test_write_pr_comment_writes_and_reports(tmp_path):
    path = tmp_path / COMMENT_FILENAME
    summary = write_pr_comment(
        _payload(_finding(fix_snippet={"kind": "k", "language": "python",
                                       "before": "a", "after": "b"})),
        str(path))
    assert path.read_text(encoding="utf-8") == build_pr_comment(
        _payload(_finding(fix_snippet={"kind": "k", "language": "python",
                                       "before": "a", "after": "b"})))
    assert summary["file"] == COMMENT_FILENAME
    assert summary["findings"] == 1
    assert summary["snippets_listed"] == 1
    assert summary["bytes"] > 0
    assert summary["marker"] == MARKER


# ---------------------------------------------------------------------------
# Action / workflow contracts (drift here breaks silently on a runner).
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def action():
    return yaml.safe_load(ACTION_PATH.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def workflow():
    return yaml.safe_load(WORKFLOW_PATH.read_text(encoding="utf-8"))


def test_action_is_a_composite_with_the_documented_inputs(action):
    assert action["runs"]["using"] == "composite"
    assert set(action["inputs"]) >= {
        "target", "output-dir", "fail-on", "python-version",
        "comment", "github-token",
    }


def test_action_runs_the_scan_and_threads_the_gate(action):
    run_steps = [s.get("run", "") for s in action["runs"]["steps"]]
    joined = "\n".join(run_steps)
    assert "python main.py" in joined
    assert "-o" in joined
    assert "--fail-on" in joined
    assert "--no-pdf" in joined and "--no-excel" in joined


def test_action_uploads_sarif_artifact_and_decorates(action):
    uses = [s.get("uses", "") for s in action["runs"]["steps"]]
    assert "github/codeql-action/upload-sarif@v3" in uses
    assert "actions/upload-artifact@v4" in uses
    assert "actions/github-script@v7" in uses


def test_action_sarif_path_is_a_file_main_py_actually_writes(action):
    """The runner-side hazard: upload-sarif failing on a name nobody writes."""
    upload = next(
        s for s in action["runs"]["steps"]
        if "upload-sarif" in str(s.get("uses", ""))
    )
    sarif_file = upload["with"]["sarif_file"]
    name = sarif_file.rsplit("/", 1)[-1]
    assert name == "Security_Report.sarif"
    assert f'"{name}"' in MAIN_SOURCE, (
        f"main.py no longer writes {name}; the Action would upload nothing"
    )


def test_action_comment_marker_and_filename_match_the_builder(action):
    script = "\n".join(
        str(s.get("with", {}).get("script", ""))
        for s in action["runs"]["steps"]
    )
    assert "const marker = '<!-- rsecopsx-scan-comment -->';" in script
    assert "'<!-- rsecopsx-scan-comment -->'" == f"'{MARKER}'"
    assert COMMENT_FILENAME in script
    assert f'"{COMMENT_FILENAME}"' in MAIN_SOURCE, (
        f"main.py no longer writes {COMMENT_FILENAME}; the Action would "
        "post the fallback body on every PR"
    )
    assert "updateComment" in script and "createComment" in script


def test_action_posting_is_pull_request_only(action):
    decorate = next(
        s for s in action["runs"]["steps"]
        if "github-script" in str(s.get("uses", ""))
    )
    condition = decorate["if"]
    assert "github.event_name == 'pull_request'" in condition
    assert "always()" in condition, (
        "a failing --fail-on gate must not suppress the comment"
    )


def test_workflow_has_a_pull_request_only_pr_scan_job(workflow):
    jobs = workflow["jobs"]
    pr_scan = jobs["pr-scan"]
    assert pr_scan["if"] == "github.event_name == 'pull_request'"
    uses = [s.get("uses", "") for s in pr_scan["steps"]]
    assert "actions/checkout@v4" in uses
    assert any(u.startswith("./.github/actions/rsecopsx-scan") for u in uses)
    assert pr_scan["permissions"]["pull-requests"] == "write"
    assert pr_scan["permissions"]["security-events"] == "write"


def test_pr_scan_is_deliberately_out_of_ci_matrix_needs(workflow):
    """A needs-edge onto a skipped job skips the dependent job, so listing
    pr-scan would silence ci-matrix on every push event."""
    assert "pr-scan" not in workflow["jobs"]["ci-matrix"]["needs"]
