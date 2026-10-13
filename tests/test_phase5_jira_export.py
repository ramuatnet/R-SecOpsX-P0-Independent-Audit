"""Phase 5.4: Jira import CSV export.

WHAT THIS DELIVERS
------------------
Gap-plan row 5.4 ("Jira ticket push for critical findings", verify: ticket
created). A scan cannot create tickets -- that needs credentials and is
a write to someone else's tracker -- so the honest deliverable is the
artifact Jira's CSV importer consumes: Security_Jira_Import.csv, one row
per finding, in the documented import format. The module docstring
records the live-push path for the CI step instead of faking it.

WHAT THESE TESTS PIN
--------------------
* 1:1 row mapping: every finding becomes exactly one row, in payload
  order -- no dedupe, no severity filtering (the artifact must not
  disagree with the report it was derived from);
* priority mapping onto Jira's five-value scale, unmapped severity ->
  Lowest (an unknown priority name fails the whole import);
* label sanitization (Jira labels carry no spaces) and summary/description
  truncation to Jira's column limits;
* the redaction guarantee: PEM material in a finding's description never
  reaches the CSV;
* byte-level format: utf-8-sig BOM, documented column set, multi-line
  descriptions round-trip through the csv module.
"""
from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from reporting.jira_export import (  # noqa: E402
    JIRA_CSV_FIELDS,
    build_jira_import_rows,
    severity_to_jira_priority,
    write_jira_export,
)


def _finding(rule_id="SQL_INJECTION", severity="High", file="svc/User.py",
             line=42, **extra):
    finding = {
        "rule_id": rule_id,
        "severity": severity,
        "file": file,
        "line": line,
        "description": "Untrusted input reached the SQL sink.",
        "remediation": "Use parameterized queries.",
        "cwe": "CWE-89",
    }
    finding.update(extra)
    return finding


def _write(payload, tmp_path):
    path = tmp_path / "Security_Jira_Import.csv"
    summary = write_jira_export(payload, str(path))
    return path, summary


# ---------------------------------------------------------------------------
# Priority mapping.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("severity,expected", [
    ("Critical", "Highest"),
    ("HIGH", "High"),
    ("medium", "Medium"),
    ("Low", "Low"),
    ("Informational", "Lowest"),
    ("", "Lowest"),
    (None, "Lowest"),
    ("somereviewstate", "Lowest"),
])
def test_priority_maps_onto_jiras_five_value_scale(severity, expected):
    assert severity_to_jira_priority(severity) == expected


# ---------------------------------------------------------------------------
# Row mapping.
# ---------------------------------------------------------------------------

def test_one_row_per_finding_in_payload_order(tmp_path):
    findings = [
        _finding("A", "High"),
        _finding("B", "Critical"),
        _finding("C", "Low"),
    ]
    path, summary = _write({"findings": findings}, tmp_path)

    with open(path, encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))

    assert len(rows) == 3 == summary["findings"]
    assert [r["Summary"].split(" in ")[0] for r in rows] == ["A", "B", "C"]
    assert summary["by_priority"] == {"High": 1, "Highest": 1, "Low": 1}


def test_non_dict_findings_are_skipped():
    rows = build_jira_import_rows(
        {"findings": [_finding("A"), "not-a-finding", None, _finding("B")]})
    assert len(rows) == 2


def test_empty_findings_yields_header_only_csv(tmp_path):
    path, summary = _write({"findings": []}, tmp_path)
    with open(path, encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert rows == []
    assert summary["findings"] == 0
    assert summary["by_priority"] == {}


def test_csv_uses_the_documented_column_set(tmp_path):
    path, _ = _write({"findings": [_finding()]}, tmp_path)
    with open(path, encoding="utf-8-sig", newline="") as handle:
        reader = csv.reader(handle)
        header = next(reader)
    assert tuple(header) == JIRA_CSV_FIELDS


def test_csv_is_utf8_with_bom_for_excel_preview(tmp_path):
    path, _ = _write({"findings": [_finding(description="pw: café ✓")]},
                     tmp_path)
    raw = path.read_bytes()
    assert raw.startswith(b"\xef\xbb\xbf")


def test_multiline_description_round_trips_through_the_csv_module(tmp_path):
    finding = _finding(description="line one\nline two\n\nline three")
    path, _ = _write({"findings": [finding]}, tmp_path)
    with open(path, encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert rows[0]["Description"].startswith("line one\nline two")
    assert "Remediation: Use parameterized queries." in rows[0]["Description"]
    assert "Location: svc/User.py:42" in rows[0]["Description"]
    assert "CWE: CWE-89" in rows[0]["Description"]


# ---------------------------------------------------------------------------
# Truncation to Jira's column limits.
# ---------------------------------------------------------------------------

def test_summary_is_truncated_to_jira_limit(tmp_path):
    long_rule = "RULE_" + "x" * 400
    path, _ = _write({"findings": [_finding(rule_id=long_rule)]}, tmp_path)
    with open(path, encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows[0]["Summary"]) == 255
    assert rows[0]["Summary"].endswith("...")


def test_description_is_capped(tmp_path):
    path, _ = _write({"findings": [_finding(description="d" * 20000)]},
                     tmp_path)
    with open(path, encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows[0]["Description"]) <= 8000


# ---------------------------------------------------------------------------
# Labels and redaction.
# ---------------------------------------------------------------------------

def test_labels_carry_rule_and_cwe_without_spaces(tmp_path):
    path, _ = _write({"findings": [_finding(rule_id="SQL INJECTION")]},
                     tmp_path)
    with open(path, encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    labels = rows[0]["Labels"].split(" ")
    assert "rsecopsx" in labels
    assert "SQL-INJECTION" in labels
    assert "CWE-89" in labels
    assert all(" " not in label for label in labels)


def test_pem_never_reaches_the_csv(tmp_path):
    finding = _finding(
        description="leaked: -----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAK\n"
                    "-----END RSA PRIVATE KEY-----")
    path, _ = _write({"findings": [finding]}, tmp_path)
    text = path.read_text(encoding="utf-8-sig")
    assert "PRIVATE KEY" not in text
    assert "MIIEpAIBAAK" not in text


# ---------------------------------------------------------------------------
# Determinism and integration surface.
# ---------------------------------------------------------------------------

def test_export_is_deterministic(tmp_path):
    payload = {"findings": [_finding("A"), _finding("B", "Critical")]}
    first = tmp_path / "a.csv"
    second = tmp_path / "b.csv"
    write_jira_export(payload, str(first))
    write_jira_export(payload, str(second))
    assert first.read_bytes() == second.read_bytes()


def test_summary_block_reports_the_contract(tmp_path):
    _, summary = _write({"findings": [_finding()]}, tmp_path)
    assert summary["file"] == "Security_Jira_Import.csv"
    assert summary["live_push"] is False
    assert "Jira CSV import" in summary["format"]
    assert json.dumps(summary)  # summary is JSON-serializable
