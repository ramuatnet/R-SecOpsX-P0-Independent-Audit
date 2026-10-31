"""T-9.8 ticket integration -- tracker-profiled issue drafts (task.md §12).

Gates pinned here (task.md section 12 PHASE 9 "ticket/webhook
integrations"):

* drafts are OFFLINE payload projections per tracker profile
  (generic / jira / github / linear) -- no SDK, no API client, no
  network; delivery rides the existing T-8.2 webhook surface;
* identity IS ``analysis.feedback.finding_key`` (rule_id, file
  normalized forward-slashes+lowercase, int line) -- the same finding
  across scans drafts to the same content-addressed ``tkt_`` key, and a
  Windows-spelled path drafts identically to its POSIX spelling;
* transitions vs a previous drafts document are exactly
  new|unchanged|updated|closed (payload digest diff) -- never
  fabricated when --previous is absent (empty lists + not_provided);
* severity tables are deterministic defaults, never guesses: unknown
  severity keeps the raw string and omits/neutralizes priority;
* rows without identity / non-object rows are ANNOTATED skips;
* deterministic + order-independent; default run zero-I/O with exactly
  two not_provided skips; CLI rc0 (skip rows are the loud surface) /
  rc2 usage; offline AST pin.
"""
from __future__ import annotations

import ast
import json
import pathlib

import pytest

from analysis.tickets import (
    MAX_FINDINGS, PROFILES, SCHEMA, build, issue_for, ticket_key,
)
from analysis.tickets.connect import main as tickets_main
from analysis.tickets import model as tickets_model
from analysis.feedback.model import finding_key

REPO = pathlib.Path(__file__).resolve().parents[1]


def _finding(**over):
    base = {
        "rule_id": "TAINT_SQL_INJECTION",
        "file": "app/db.py",
        "line": 42,
        "title": "SQL injection reaches sink",
        "severity": "High",
        "cwe": "CWE-89",
        "owasp": "A03:2021 - Injection",
        "accuracy": {"verdict": "TRUE_POSITIVE"},
        "disposition": "CONFIRMED",
        "evidence": ["validated sink", "req -> q -> cur"],
        "description": "request flows into cursor.execute",
    }
    base.update(over)
    return base


def _payload(*findings):
    return {"metadata": {"tool": "R-SecOpsX SAST v2.1"},
            "findings": list(findings)}


# ---------------------------------------------------------------------------
# A. model contracts
# ---------------------------------------------------------------------------


def test_default_document_is_zero_io_with_two_not_provided_skips():
    doc = build(None)
    assert doc["schema"] == SCHEMA
    assert doc["profile"] == "generic"
    assert doc["issues"] == []
    assert doc["transitions"] == {"new": [], "unchanged": [],
                                  "updated": [], "closed": []}
    assert doc["skips"] == [
        {"reason": "not_provided", "source": "findings"},
        {"reason": "not_provided", "source": "previous"},
    ]
    assert doc["stats"]["issues"] == 0
    assert "as_of" not in doc


def test_generic_profile_shape_and_body_lines():
    doc = build(_payload(_finding()))
    (issue,) = doc["issues"]
    assert issue["profile"] == "generic"
    assert issue["severity"] == "high"
    assert issue["priority"] == "Critical"
    assert issue["status"] == "open"
    assert issue["summary"].startswith("[high] TAINT_SQL_INJECTION "
                                       "app/db.py:42")
    assert "SQL injection reaches sink" in issue["summary"]
    body = issue["body"]
    assert "request flows into cursor.execute" in body
    assert "- validated sink" in body and "- req -> q -> cur" in body
    assert "Verdict: TRUE_POSITIVE" in body
    assert "Disposition: CONFIRMED" in body
    assert "CWE: CWE-89" in body
    assert "OWASP: A03:2021 - Injection" in body
    assert issue["labels"] == ["rsecopsx", "high", "TAINT_SQL_INJECTION",
                               "true_positive"]
    assert issue["identity"] == {"rule_id": "TAINT_SQL_INJECTION",
                                 "file": "app/db.py", "line": 42}


def test_ticket_key_is_content_addressed_on_normalized_identity():
    a = build(_payload(_finding()))["issues"][0]["key"]
    # same finding, Windows spelling + case variance -> same key
    b = build(_payload(_finding(file=r"APP\DB.PY")))["issues"][0]["key"]
    assert a == b
    assert a.startswith("tkt_") and len(a) == 4 + 12  # 12 hex chars
    # different line -> different identity -> different key
    c = build(_payload(_finding(line=43)))["issues"][0]["key"]
    assert c != a
    # identity itself matches T-7.2 finding_key exactly
    row = _finding()
    identity = finding_key(row)
    assert ticket_key(identity) == a


def test_priority_tables_are_pinned_deterministic_defaults():
    jira = {}
    linear = {}
    for sev in ("critical", "high", "medium", "low", "info"):
        row = _finding(severity=sev.upper())
        jira[sev] = issue_for(row, "jira")["fields"]["priority"]["name"]
        linear[sev] = issue_for(row, "linear")["priority"]
    assert jira == {"critical": "Blocker", "high": "Critical",
                    "medium": "Major", "low": "Minor", "info": "Trivial"}
    assert linear == {"critical": 1, "high": 2, "medium": 3, "low": 4,
                      "info": 0}


def test_jira_profile_shape():
    issue = issue_for(_finding(), "jira")
    fields = issue["fields"]
    assert fields["issuetype"] == {"name": "Bug"}
    assert fields["priority"] == {"name": "Critical"}
    assert "TAINT_SQL_INJECTION" in fields["labels"]
    assert fields["summary"] == issue_for(_finding(),
                                          "generic")["summary"]
    assert "Disposition: CONFIRMED" in fields["description"]
    assert "title" not in issue          # jira nests under fields


def test_github_profile_never_invents_priority():
    issue = issue_for(_finding(), "github")
    assert issue["title"] == issue_for(_finding(), "generic")["summary"]
    assert "Disposition: CONFIRMED" in issue["body"]
    assert "labels" in issue
    assert "priority" not in issue
    assert "fields" not in issue


def test_linear_profile_shape_and_priority():
    issue = issue_for(_finding(), "linear")
    assert issue["priority"] == 2         # high
    assert "labels" not in issue          # team-scoped: omitted
    assert "Disposition: CONFIRMED" in issue["description"]
    assert issue["title"].startswith("[high]")


def test_unknown_severity_never_guessed():
    row = _finding(severity="Interesting")
    generic = issue_for(row, "generic")
    assert generic["severity"] == "interesting"
    assert generic["priority"] is None               # honest null
    jira = issue_for(row, "jira")
    assert "priority" not in jira["fields"]          # omitted, not faked
    linear = issue_for(row, "linear")
    assert "priority" not in linear


def test_row_junk_is_annotated_never_dropped():
    payload = [42, {"title": "no identity"}, _finding()]
    doc = build(payload)
    assert len(doc["issues"]) == 1
    reasons = [(s["reason"], s.get("count")) for s in doc["skips"]]
    assert ("finding_rows_not_objects", 1) in reasons
    assert ("finding_rows_missing_identity", 1) in reasons
    # 2 findings skips + the previous not_provided row
    assert doc["stats"]["skipped"] == 3


def test_cap_findings_is_a_disclosed_skip(monkeypatch):
    monkeypatch.setattr(tickets_model, "MAX_FINDINGS", 2)
    payload = [_finding(line=1), _finding(line=2), _finding(line=3)]
    doc = build(payload)
    assert len(doc["issues"]) == 2
    assert any(s["reason"] == "cap_findings_2" for s in doc["skips"])
    # the module-level export used by tests is untouched by the patch
    assert MAX_FINDINGS == 5000


def test_transitions_are_exact_sets_by_digest():
    first = build(_payload(
        _finding(rule_id="KEEP", file="a.py", line=1),
        _finding(rule_id="EDIT", file="b.py", line=2),
        _finding(rule_id="GONE", file="c.py", line=3),
    ))
    second = build(_payload(
        _finding(rule_id="KEEP", file="a.py", line=1),
        _finding(rule_id="EDIT", file="b.py", line=2,
                 title="renamed title"),       # payload digest changes
        _finding(rule_id="FRESH", file="d.py", line=4),
    ), previous=first)
    tr = second["transitions"]
    keys = {it["identity"]["rule_id"]: it["key"]
            for it in first["issues"]}
    now = {it["identity"]["rule_id"]: it["key"]
           for it in second["issues"]}
    assert tr["unchanged"] == [keys["KEEP"]]
    assert tr["updated"] == [keys["EDIT"]]
    assert tr["closed"] == [keys["GONE"]]
    assert tr["new"] == [now["FRESH"]]
    assert second["stats"]["transitions"] == {"closed": 1, "new": 1,
                                              "unchanged": 1, "updated": 1}


def test_previous_shape_problems_are_loud_skips():
    # absent -> not_provided (covered in the default test)
    wrong = build(_payload(_finding()),
                  previous={"schema": "something.else/v1", "issues": []})
    assert {"reason": "previous_wrong_schema",
            "source": "previous"} in wrong["skips"]
    assert wrong["transitions"]["new"] == []     # never fabricated
    not_obj = build(_payload(_finding()), previous=[1, 2])
    assert {"reason": "previous_not_object",
            "source": "previous"} in not_obj["skips"]
    bad_list = build(_payload(_finding()),
                     previous={"schema": SCHEMA, "issues": "nope"})
    assert {"reason": "previous_issues_not_a_list",
            "source": "previous"} in bad_list["skips"]


def test_build_is_order_independent_byte_identical():
    rows = [_finding(rule_id="R1", file="x.py", line=1),
            _finding(rule_id="R2", file="y.py", line=2),
            _finding(rule_id="R3", file="z.py", line=3)]
    a = json.dumps(build(_payload(*rows)), sort_keys=True)
    b = json.dumps(build(_payload(*reversed(rows))), sort_keys=True)
    assert a == b


def test_extract_rows_accepts_list_findings_object_and_rejects_junk():
    from analysis.tickets.model import _extract_rows
    assert _extract_rows([1])[0] == [1]
    assert _extract_rows({"findings": [1]})[0] == [1]
    assert _extract_rows({"rule_id": "R", "file": "f"})[0] == [
        {"rule_id": "R", "file": "f"}]
    rows, skip = _extract_rows("not a payload")
    assert rows is None
    assert skip == {"reason": "findings_bad_shape", "source": "findings"}
    doc = build("not a payload")
    assert {"reason": "findings_bad_shape",
            "source": "findings"} in doc["skips"]


def test_as_of_is_optional_echo():
    assert "as_of" not in build(None)
    assert build(None, as_of="2026-10-31T00:00:00Z")["as_of"] == \
        "2026-10-31T00:00:00Z"


def test_cross_profile_identity_and_severity_agree():
    row = _finding()
    issues = {p: issue_for(row, p) for p in PROFILES}
    keys = {it["key"] for it in issues.values()}
    assert len(keys) == 1
    assert {it["severity"] for it in issues.values()} == {"high"}
    assert {it["status"] for it in issues.values()} == {"open"}
    assert {json.dumps(it["identity"], sort_keys=True)
            for it in issues.values()} == {
        json.dumps({"rule_id": "TAINT_SQL_INJECTION", "file": "app/db.py",
                    "line": 42}, sort_keys=True)}
    assert issues["generic"]["summary"] == issues["jira"]["fields"][
        "summary"] == issues["github"]["title"] == issues["linear"][
        "title"]


def test_offline_ast_pin_on_both_modules():
    for rel in ("analysis/tickets/model.py", "analysis/tickets/connect.py"):
        src = (REPO / rel).read_text(encoding="utf-8")
        tree = ast.parse(src)
        banned = {"urllib", "socket", "requests", "boto3", "http",
                  "subprocess"}
        top = []
        for node in tree.body:
            if isinstance(node, ast.Import):
                top.extend(a.name for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                top.append(node.module)
        assert not (set(top) & banned), (rel, top)
        for token in ("urllib", "boto3", "requests", "os.environ",
                      "http.client", "socket."):
            assert token not in src, (rel, token)


# ---------------------------------------------------------------------------
# B. CLI
# ---------------------------------------------------------------------------


def test_cli_default_run_is_stdout_rc0_byte_identical(capsys):
    assert tickets_main([]) == 0
    first = capsys.readouterr().out
    assert first.endswith("\n")
    doc = json.loads(first)
    assert doc["schema"] == SCHEMA
    assert [s["reason"] for s in doc["skips"]] == ["not_provided",
                                                   "not_provided"]
    assert tickets_main([]) == 0
    assert capsys.readouterr().out == first


def test_cli_out_writes_document(tmp_path):
    out = tmp_path / "drafts.json"
    assert tickets_main(["--profile", "jira",
                         "--out", str(out)]) == 0
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["profile"] == "jira"
    assert out.read_text(encoding="utf-8").endswith("\n")


def test_cli_usage_errors_are_rc2(tmp_path):
    with pytest.raises(SystemExit) as eu:
        tickets_main(["--as-of", "not-a-date"])
    assert eu.value.code == 2
    with pytest.raises(SystemExit) as eu:
        tickets_main(["--profile", "jira-you-track",
                      "--out", str(tmp_path / "x.json")])
    assert eu.value.code == 2


def test_cli_bad_finding_file_is_a_skip_not_a_crash(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{nope", encoding="utf-8")
    out = tmp_path / "drafts.json"
    assert tickets_main(["--finding", str(bad),
                         "--out", str(out)]) == 0
    doc = json.loads(out.read_text(encoding="utf-8"))
    reasons = [s["reason"] for s in doc["skips"]]
    assert any(r.startswith("json_decode_error:") for r in reasons)
    assert doc["issues"] == []


def test_cli_bad_previous_file_reports_both_rows(tmp_path):
    missing = tmp_path / "gone.json"
    out = tmp_path / "drafts.json"
    assert tickets_main(["--finding", str(tmp_path / "nope.json"),
                         "--previous", str(missing),
                         "--out", str(out)]) == 0
    doc = json.loads(out.read_text(encoding="utf-8"))
    reasons = [s["reason"] for s in doc["skips"]]
    assert any(r.startswith("unreadable:") for r in reasons)   # findings
    assert "previous_not_object" in reasons                    # marker
    # a FAILED previous load never reads as "not_provided"
    assert not any("previous" == s["reason"] and
                   s["reason"] == "not_provided" for s in doc["skips"]
                   if s["source"] == "previous" and
                   s["reason"] == "not_provided")
    assert doc["transitions"] == {"new": [], "unchanged": [],
                                  "updated": [], "closed": []}


def test_cli_end_to_end_transitions_between_scans(tmp_path):
    f1 = tmp_path / "scan1.json"
    f1.write_text(json.dumps(_payload(
        _finding(rule_id="KEEP", file="a.py", line=1),
        _finding(rule_id="OLD", file="b.py", line=2),
    )), encoding="utf-8")
    drafts1 = tmp_path / "drafts1.json"
    assert tickets_main(["--finding", str(f1),
                         "--out", str(drafts1)]) == 0
    f2 = tmp_path / "scan2.json"
    f2.write_text(json.dumps(_payload(
        _finding(rule_id="KEEP", file="a.py", line=1),
        _finding(rule_id="NEW", file="c.py", line=3),
    )), encoding="utf-8")
    drafts2 = tmp_path / "drafts2.json"
    assert tickets_main(["--finding", str(f2),
                         "--previous", str(drafts1),
                         "--out", str(drafts2)]) == 0
    doc = json.loads(drafts2.read_text(encoding="utf-8"))
    tr = doc["transitions"]
    assert len(tr["new"]) == 1 and len(tr["unchanged"]) == 1
    assert len(tr["closed"]) == 1 and tr["updated"] == []


# ---------------------------------------------------------------------------
# C. integration with existing surfaces
# ---------------------------------------------------------------------------


def test_report_payload_shape_produces_filed_shaped_drafts():
    doc = build(_payload(
        _finding(finding_id="f-001"),
        _finding(rule_id="HARDCODED_SECRET", file="conf/settings.py",
                 line=3, severity="Critical", accuracy=None,
                 disposition=None, evidence=[], description=None,
                 cwe="CWE-798", owasp=None),
    ))
    assert doc["stats"]["by_severity"] == {"critical": 1, "high": 1}
    by_rule = {it["identity"]["rule_id"]: it for it in doc["issues"]}
    # honest nulls: absent verdict/disposition/evidence never fabricated
    secret = by_rule["HARDCODED_SECRET"]
    assert "Verdict:" not in secret["body"]
    assert "Disposition:" not in secret["body"]
    assert "Evidence:" not in secret["body"]
    assert secret["labels"] == ["rsecopsx", "critical",
                                "HARDCODED_SECRET"]
    taint = by_rule["TAINT_SQL_INJECTION"]
    assert "Verdict: TRUE_POSITIVE" in taint["body"]


def test_no_serve_import_and_webhook_surface_left_alone():
    """The ticket half composes with T-8.2 webhooks, never mutates it."""
    src = (REPO / "analysis" / "tickets" / "model.py").read_text(
        encoding="utf-8")
    assert "analysis.serve" not in src
    # the webhook delivery surface still exists for delivering drafts
    from analysis.serve import events as serve_events
    assert hasattr(serve_events, "deliver_events")
