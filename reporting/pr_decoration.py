"""PR decoration comment (Phase 5.1).

Writes ``Security_PR_Comment.md``: the markdown body the Phase 5.1 GitHub
Action posts (and sticky-updates) on a pull request. The body is assembled
here -- offline, deterministically, fully tested -- and the Action's
github-script step is a dumb pipe that upserts whatever this file says.
All semantics therefore live where they can be tested without a runner.

Honesty properties:

* the comment states it is generated from the PEM-redacted canonical
  report, and the assembled body runs through ``redact_pem_deep`` on the
  way out anyway (defense-in-depth, same as every exporter);
* the top-findings table is capped and says how many findings it
  withheld, so a quiet-looking comment can never be mistaken for a
  quiet scan;
* fix snippets are labelled **template - never applied; human review
  required**: the comment never implies the PR was fixed;
* when ``--fail-on`` trips, the scan exits nonzero and the Action's
  ``if: always()`` steps still post this comment -- the comment carries
  the counts, the gate carries the verdict.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from core.redaction import redact_pem_deep

# The Action finds/updates its own comment by this marker, so each PR
# carries exactly one R-SecOpsX comment no matter how many pushes it sees.
MARKER = "<!-- rsecopsx-scan-comment -->"
COMMENT_FILENAME = "Security_PR_Comment.md"

# GitHub's comment limit is 65536 chars; leave headroom.
DEFAULT_MAX_CHARS = 60000
TOP_FINDINGS_CAP = 20
SNIPPETS_CAP = 5

_SEVERITY_ORDER = ("Critical", "High", "Medium", "Low", "Informational")
_SEVERITY_DOT = {
    "Critical": "\U0001f534",   # red circle
    "High": "\U0001f7e0",       # orange circle
    "Medium": "\U0001f7e1",     # yellow circle
    "Low": "\U0001f7e2",        # green circle
    "Informational": "\u26aa",  # white circle
}

# Every artifact a consumer might want after reading the comment.
_ARTIFACT_LIST = (
    "clean_report.json",
    "Security_Report.sarif",
    "Security_Findings_Webhook.json",
    "Security_Jira_Import.csv",
    "Security_DefectDojo_Import.json",
)


def _cell(value: Any, limit: int = 120) -> str:
    """One markdown-table cell: single-line, pipe-safe, length-capped."""
    text = str(value if value is not None else "")
    text = text.replace("\r\n", " ").replace("\n", " ").replace("|", "\\|")
    if len(text) > limit:
        text = text[: limit - 3] + "..."
    return text


def _location(finding: dict[str, Any]) -> str:
    file_name = str(finding.get("file") or finding.get("path") or "?")
    file_name = file_name.replace("\\", "/")
    line = finding.get("line")
    return f"{file_name}:{line}" if line not in (None, "") else file_name


def _severity_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    """Counts keyed by severity, in report order of the fixed scale."""
    counts: dict[str, int] = {}
    for finding in findings:
        severity = str(finding.get("severity") or "Unknown")
        counts[severity] = counts.get(severity, 0) + 1
    return counts


def _counts_table(counts: dict[str, int]) -> str:
    lines = ["| Severity | Count |", "| --- | --- |"]
    seen = set()
    for severity in _SEVERITY_ORDER:
        if severity in counts:
            seen.add(severity)
            dot = _SEVERITY_DOT[severity]
            lines.append(f"| {dot} {severity} | {counts[severity]} |")
    for severity, count in counts.items():
        if severity not in seen:
            lines.append(f"| {_cell(severity, 40)} | {count} |")
    return "\n".join(lines)


def _top_findings_table(findings: list[dict[str, Any]], cap: int) -> str:
    if cap <= 0:
        return "_Top-findings table withheld to fit the comment size limit._"
    shown = findings[:cap]
    lines = [
        "| Rule | Severity | Location | Description |",
        "| --- | --- | --- | --- |",
    ]
    for finding in shown:
        rule = finding.get("rule_id") or finding.get("vuln_type") or "finding"
        severity = finding.get("severity") or "?"
        dot = _SEVERITY_DOT.get(str(severity), "")
        description = (
            finding.get("description") or finding.get("message") or ""
        )
        lines.append(
            f"| {_cell(rule)} | {dot} {_cell(severity, 20)} "
            f"| {_cell(_location(finding))} | {_cell(description)} |"
        )
    withheld = len(findings) - len(shown)
    if withheld > 0:
        lines.append("")
        lines.append(
            f"_…and {withheld} more finding(s) not shown here "
            "(report order) — see the artifacts below._"
        )
    return "\n".join(lines)


def _snippets_section(findings: list[dict[str, Any]], cap: int) -> str:
    with_snippets = [f for f in findings if f.get("fix_snippet")]
    if not with_snippets or cap <= 0:
        return ""
    shown = with_snippets[:cap]
    parts = ["### Fix snippets (templates — never applied)", ""]
    for finding in shown:
        snippet = finding["fix_snippet"]
        rule = finding.get("rule_id") or finding.get("vuln_type") or "finding"
        parts.append(
            f"**{_cell(rule, 100)}** @ {_cell(_location(finding), 150)} — "
            f"`{_cell(snippet.get('kind'), 60)}` "
            f"({_cell(snippet.get('language'), 30)}) "
            f"· **template, human review required**"
        )
        parts.append("")
        parts.append("Before:")
        parts.append("")
        parts.append("```\n" + str(snippet.get("before") or "") + "\n```")
        parts.append("")
        parts.append("After:")
        parts.append("")
        parts.append("```\n" + str(snippet.get("after") or "") + "\n```")
        parts.append("")
    withheld = len(with_snippets) - len(shown)
    if withheld > 0:
        parts.append(f"_…and {withheld} more snippet(s) in the artifacts._")
        parts.append("")
    return "\n".join(parts)


def build_pr_comment(
    payload: dict[str, Any],
    max_chars: int = DEFAULT_MAX_CHARS,
) -> str:
    """Assemble the comment body. Deterministic; PEM-redacted on exit."""
    findings = [
        f for f in (payload.get("findings") or []) if isinstance(f, dict)
    ]
    metadata = payload.get("metadata") or {}
    target = str(metadata.get("target") or "?")
    tool = str(metadata.get("tool") or "R-SecOpsX")
    counts = _severity_counts(findings)

    header = (
        f"{MARKER}\n"
        "## R-SecOpsX scan summary\n"
        "\n"
        f"**Target:** `{_cell(target, 300)}` · **Tool:** {_cell(tool, 80)} "
        f"· **Findings:** {len(findings)}\n"
    )

    if findings:
        body_counts = "\n" + _counts_table(counts) + "\n"
    else:
        body_counts = "\n**No findings.**\n"

    footer = (
        "\n### Artifacts\n"
        "\n"
        + ", ".join(f"`{name}`" for name in _ARTIFACT_LIST)
        + "\n"
        "\n---\n"
        "*Generated by R-SecOpsX from the PEM-redacted canonical report. "
        "Fix snippets are templates — never applied; human review "
        "required.*"
    )

    # Adaptive sizing: shrink the top-findings table, then the snippet
    # list, before ever considering a hard cut. Deterministic at every
    # step -- same payload, same body.
    top_cap = min(TOP_FINDINGS_CAP, len(findings))
    snippet_cap = SNIPPETS_CAP
    while True:
        body = (
            header
            + body_counts
            + "\n### Top findings\n\n"
            + _top_findings_table(findings, top_cap)
            + "\n"
            + _snippets_section(findings, snippet_cap)
            + footer
        )
        if len(body) <= max_chars:
            return redact_pem_deep(body)
        if top_cap > 0:
            top_cap = max(0, top_cap // 2)
        elif snippet_cap > 0:
            snippet_cap = max(0, snippet_cap // 2)
        else:
            # Pathological payload (single finding with an enormous
            # description): cut at the limit rather than post a comment
            # GitHub will reject outright.
            return redact_pem_deep(
                body[: max_chars - 32] + "\n<!-- truncated -->\n"
            )


def write_pr_comment(
    payload: dict[str, Any],
    path: str,
    max_chars: int = DEFAULT_MAX_CHARS,
) -> dict[str, Any]:
    """Write the comment artifact; return a small summary."""
    body = build_pr_comment(payload, max_chars=max_chars)
    Path(path).write_text(body, encoding="utf-8")

    findings = [
        f for f in (payload.get("findings") or []) if isinstance(f, dict)
    ]
    snippets_listed = min(
        SNIPPETS_CAP,
        sum(1 for f in findings if f.get("fix_snippet")),
    )
    return {
        "file": Path(path).name,
        "findings": len(findings),
        "top_listed": min(TOP_FINDINGS_CAP, len(findings)),
        "snippets_listed": snippets_listed,
        "bytes": len(body.encode("utf-8")),
        "marker": MARKER,
    }
