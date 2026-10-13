"""Jira import export (Phase 5.4).

Writes ``Security_Jira_Import.csv`` in Jira's documented CSV import
format (Atlassian Cloud / Data Center: Issues > Import from CSV). The
importer requires Issue Type, Summary, Description and Priority; the
remaining columns below are optional fields Jira recognizes.

Design honesty:

* One row per finding, 1:1 with clean_report.json -- no dedupe, no
  severity filtering. A consumer who wants only criticals filters in
  Jira; silently dropping rows would make the artifact disagree with
  the report it was derived from.
* Priority mapping is Jira's five-value scale (Highest / High / Medium /
  Low / Lowest). A severity that does not map lands on Lowest, never on
  a made-up priority name -- Jira rejects unknown priorities at import
  time and the whole file fails.
* The payload is the redacted canonical report, and the text fields are
  PEM-redacted again on the way out, so the CSV inherits the same
  non-republication guarantee as every other artifact.
* No live push. Creating tickets is a write to someone else's tracker
  and needs credentials; the artifact IS the contract. A CI step (or
  the Phase 5.1 GitHub Action) uploads it with ``jira import`` or the
  REST API -- documented here, never attempted from a scan.
"""
from __future__ import annotations

import csv
from pathlib import Path
from typing import Any

from core.redaction import redact_pem_deep

# Jira's CSV importer: Issue Type / Summary / Description / Priority are
# required; Labels and the version columns are recognized optionals.
# Affects/Fix Version/s are left empty on purpose -- the version names
# live in the TARGET Jira project, which a scan cannot know; inventing
# them would fail the import.
JIRA_CSV_FIELDS = (
    "Issue Type",
    "Summary",
    "Description",
    "Priority",
    "Labels",
    "Affects Version/s",
    "Fix Version/s",
)

# Jira's five-value priority scale. Anything unmapped becomes Lowest
# (see module docstring -- an unknown priority name fails the import).
_JIRA_PRIORITY_BY_SEVERITY = {
    "critical": "Highest",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
}

# Jira labels may not contain spaces.
_INVALID_LABEL_CHARS = (" ",)


def severity_to_jira_priority(severity: Any) -> str:
    """Map a finding severity onto Jira's five-value priority scale."""
    value = str(severity or "").strip().lower()
    return _JIRA_PRIORITY_BY_SEVERITY.get(value, "Lowest")


def _jira_label(value: Any) -> str:
    """Make a value safe for a Jira label (no spaces, non-empty)."""
    text = str(value or "").strip()
    for char in _INVALID_LABEL_CHARS:
        text = text.replace(char, "-")
    return text


def _finding_summary(finding: dict[str, Any]) -> str:
    """``RULE_ID in file:line`` -- the shape a triager scans for."""
    rule = str(
        finding.get("rule_id") or finding.get("vuln_type") or "finding"
    ).strip()
    file_name = str(finding.get("file") or finding.get("path") or "")
    file_name = file_name.replace("\\", "/").rsplit("/", 1)[-1] or "unknown"
    line = finding.get("line")
    location = f"{file_name}:{line}" if line not in (None, "") else file_name
    summary = f"{rule} in {location}"
    # Jira's summary column is 255 characters; truncate with a marker
    # rather than letting the importer reject the row.
    if len(summary) > 255:
        summary = summary[:252] + "..."
    return summary


def _finding_description(finding: dict[str, Any]) -> str:
    """Description + remediation + location, capped for Jira's column."""
    parts = []

    description = finding.get("description") or finding.get("message") \
        or finding.get("title") or ""
    if description:
        parts.append(str(description).strip())

    remediation = finding.get("remediation") or ""
    if remediation:
        parts.append(f"Remediation: {str(remediation).strip()}")

    location = finding.get("file") or finding.get("path") or ""
    line = finding.get("line")
    if location:
        where = f"{location}:{line}" if line not in (None, "") else str(location)
        parts.append(f"Location: {where}")

    cwe = finding.get("cwe")
    if cwe:
        parts.append(f"CWE: {cwe}")

    text = "\n\n".join(parts)
    # Jira's description column caps near 32k; 8k keeps the CSV reviewable.
    if len(text) > 8000:
        text = text[:7997] + "..."
    return redact_pem_deep(text)


def build_jira_import_rows(payload: dict[str, Any]) -> list[dict[str, str]]:
    """One CSV row per finding, in payload order (see module docstring)."""
    rows: list[dict[str, str]] = []
    findings = payload.get("findings") or []

    for finding in findings:
        if not isinstance(finding, dict):
            continue

        rule = str(
            finding.get("rule_id") or finding.get("vuln_type") or ""
        ).strip()
        cwe = str(finding.get("cwe") or "").strip()

        labels = ["rsecopsx"]
        if rule:
            labels.append(_jira_label(rule))
        if cwe:
            labels.append(_jira_label(cwe))

        rows.append(
            {
                "Issue Type": "Bug",
                "Summary": redact_pem_deep(_finding_summary(finding)),
                "Description": _finding_description(finding),
                "Priority": severity_to_jira_priority(finding.get("severity")),
                "Labels": " ".join(labels),
                "Affects Version/s": "",
                "Fix Version/s": "",
            }
        )

    return rows


def write_jira_export(payload: dict[str, Any], path: str) -> dict[str, Any]:
    """Write the Jira CSV import artifact; return a small summary.

    Fail-open by contract: the caller wraps this in try/except like the
    other exporters, so a CSV problem never fails a scan.
    """
    rows = build_jira_import_rows(payload)

    by_priority: dict[str, int] = {}
    for row in rows:
        priority = row["Priority"]
        by_priority[priority] = by_priority.get(priority, 0) + 1

    # utf-8-sig: the BOM keeps Excel from mangling non-ASCII findings
    # when a human previews the CSV before importing it into Jira.
    with open(path, "w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(JIRA_CSV_FIELDS))
        writer.writeheader()
        writer.writerows(rows)

    return {
        "file": Path(path).name,
        "findings": len(rows),
        "by_priority": by_priority,
        "columns": list(JIRA_CSV_FIELDS),
        "format": "Jira CSV import (Issue Type, Summary, Description, "
                  "Priority, Labels, Affects Version/s, Fix Version/s)",
        "live_push": False,
    }
