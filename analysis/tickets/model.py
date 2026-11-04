"""Ticket integration core -- scan findings projected to issue drafts.

task.md section 12 PHASE 9 "ticket/webhook integrations": the webhook
half already exists (T-8.2 deliver_events posts event JSON to registered
hooks); this is the TICKET half -- ready-to-file issue drafts per
tracker profile, plus cross-scan transitions.

Design (offline invariant):

* NO tracker SDK, NO API client -- profiles are pure JSON payload
  projections (generic / jira / github / linear).  Delivery of a draft
  is intentionally left to the existing T-8.2 webhook POST surface;
  no tracker-specific transport is adopted (disclosed).
* Identity is ``analysis.feedback.finding_key`` VERBATIM (rule_id,
  file normalized to forward slashes + lowercase, int line) -- a
  finding's ticket key is content-addressed from that identity, so the
  same finding across scans always drafts to the same ``tkt_`` id and
  a re-scan never files a duplicate.
* Severity normalizes to the shared vocabulary
  (critical|high|medium|low|info); an unknown severity string is kept
  verbatim (lowercased) and the profile's priority field is OMITTED
  rather than guessed (priority tables are deterministic defaults,
  never authoritative vendor mappings -- disclosed).
* Transitions against a previous drafts document are
  new|unchanged|updated|closed (key-set + payload digest diff).
  Without ``--previous`` transitions stay EMPTY LISTS plus a
  ``not_provided`` skip -- "everything is new" is never fabricated.
* Rows that are not objects, or lack a usable identity, are ANNOTATED
  into ``skips[]`` (machine-readable reason, index) -- never silently
  dropped.  Bounded: MAX_FINDINGS per input (cap skip row, disclosed).
* Deterministic: no clocks, no uuids; issues sorted by key; same
  inputs in any order -> byte-identical output (test-pinned).
  ``--as-of`` is optional and only echoed when supplied.
"""
from __future__ import annotations
try:
    from analysis.spans import WINDOW_12
except ImportError:  # FND-03: standalone, repo root not on path
    import sys as _fnd03_sys
    from pathlib import Path as _fnd03_path
    _fnd03_sys.path.insert(0, str(_fnd03_path(__file__).resolve().parents[2]))
    from analysis.spans import WINDOW_12

import hashlib
import json

from analysis.feedback.model import finding_key

SCHEMA = "rsecopsx.ticket_drafts/v1"

PROFILES = ("generic", "jira", "github", "linear")
SEVERITIES = ("critical", "high", "medium", "low", "info")

MAX_FINDINGS = 5000

# Deterministic default tables (NOT vendor-authoritative; disclosed).
_JIRA_PRIORITY = {
    "critical": "Blocker",
    "high": "Critical",
    "medium": "Major",
    "low": "Minor",
    "info": "Trivial",
}
_LINEAR_PRIORITY = {
    "critical": 1,   # urgent
    "high": 2,       # high
    "medium": 3,     # medium
    "low": 4,        # low
    "info": 0,       # no priority
}


def _norm_severity(raw):
    """Shared severity vocabulary, or the raw string lowercased."""
    if not raw:
        return None
    text = str(raw).strip().lower()
    return text if text in SEVERITIES else text


def _finding_identity(row: dict):
    """T-7.2 identity tuple, or None when rule_id/file are missing."""
    return finding_key(row)


def ticket_key(identity) -> str:
    """Content-addressed draft id from the T-7.2 identity tuple."""
    canon = json.dumps(list(identity), sort_keys=True, ensure_ascii=True,
                       separators=(",", ":"))
    return "tkt_" + hashlib.sha256(canon.encode("utf-8")).hexdigest()[:WINDOW_12]


def _summary(row: dict, severity) -> str:
    rule_id = str(row.get("rule_id") or "")
    file = str(row.get("file") or "")
    line = row.get("line")
    where = f"{file}:{line}" if line is not None else file
    head = f"[{severity}] {rule_id} {where}".strip()
    title = str(row.get("title") or "").strip()
    return f"{head} - {title}" if title else head


def _body(row: dict) -> str:
    lines = []
    desc = row.get("description")
    if desc:
        lines.append(str(desc))
    evidence = row.get("evidence")
    if isinstance(evidence, list) and evidence:
        lines.append("Evidence:")
        lines.extend(f"- {e}" for e in evidence)
    acc = row.get("accuracy")
    if isinstance(acc, dict) and acc.get("verdict"):
        lines.append(f"Verdict: {acc['verdict']}")
    disp = row.get("disposition")
    if disp:
        lines.append(f"Disposition: {disp}")
    for label, field in (("CWE", "cwe"), ("OWASP", "owasp")):
        if row.get(field):
            lines.append(f"{label}: {row[field]}")
    return "\n".join(lines)


def _labels(row: dict, severity) -> list:
    labels = ["rsecopsx", severity]
    rule_id = row.get("rule_id")
    if rule_id:
        labels.append(str(rule_id))
    acc = row.get("accuracy")
    if isinstance(acc, dict) and acc.get("verdict"):
        labels.append(str(acc["verdict"]).lower())
    out, seen = [], set()
    for label in labels:
        if label not in seen:
            seen.add(label)
            out.append(label)
    return out


def issue_for(row: dict, profile: str) -> dict:
    """Project one finding row into a tracker-profiled issue draft.

    Caller guarantees identity (finding_key non-None); rows here are
    dicts.  Every profile carries {key, identity, profile, severity,
    status="open"}; field NAMES follow the tracker (generic summary/
    body, jira fields.*, github title/body, linear title/description).
    GitHub carries no priority (the tracker has none); linear uses its
    integer scale; unknown severity never guesses -- generic carries an
    honest null, jira/linear omit the field entirely.
    """
    identity = _finding_identity(row)
    severity = _norm_severity(row.get("severity")) or "unknown"
    summary = _summary(row, severity)
    body = _body(row)
    labels = _labels(row, severity)
    key = ticket_key(identity)
    ident = {"rule_id": identity[0], "file": identity[1],
             "line": identity[2]}
    base = {"key": key, "identity": ident, "profile": profile,
            "severity": severity, "status": "open"}
    if profile == "generic":
        return {**base, "summary": summary, "body": body,
                "labels": labels, "priority": _JIRA_PRIORITY.get(severity)}
    if profile == "jira":
        fields = {"summary": summary, "description": body,
                  "issuetype": {"name": "Bug"}, "labels": labels}
        prio = _JIRA_PRIORITY.get(severity)
        if prio is not None:             # omitted when severity unknown
            fields["priority"] = {"name": prio}
        return {**base, "fields": fields}
    if profile == "github":
        # GitHub issues have no priority field -- the projection simply
        # does not carry one (never invented).
        return {**base, "title": summary, "body": body, "labels": labels}
    if profile == "linear":
        # Linear takes integer priorities; labels are omitted (team-
        # scoped in the product -- not ours to invent here).
        out = {**base, "title": summary, "description": body}
        prio = _LINEAR_PRIORITY.get(severity)
        if prio is not None:
            out["priority"] = prio
        return out
    raise ValueError(f"unknown_profile:{profile}")


def _digest(issue: dict) -> str:
    canon = json.dumps(issue, sort_keys=True, ensure_ascii=True,
                       separators=(",", ":"))
    return "sha256:" + hashlib.sha256(canon.encode("utf-8")).hexdigest()


def _extract_rows(payload):
    """list | {findings: [...]} | object (T-7.1 _extract_rows shape)."""
    if isinstance(payload, list):
        return payload, None
    if isinstance(payload, dict):
        inner = payload.get("findings")
        if isinstance(inner, list):
            return inner, None
        return [payload], None
    return None, {"reason": "findings_bad_shape", "source": "findings"}


def build_findings(payload, profile: str) -> tuple[list, list, list]:
    """(issues, skips, identities) for one findings payload."""
    rows, shape_skip = _extract_rows(payload)
    skips = [shape_skip] if shape_skip is not None else []
    if rows is None:
        return [], skips, []
    if len(rows) > MAX_FINDINGS:
        skips.append({"reason": f"cap_findings_{MAX_FINDINGS}",
                      "source": "findings"})
        rows = rows[:MAX_FINDINGS]
    issues, identities, bad_objects, missing_identity = [], [], 0, 0
    for i, row in enumerate(rows):
        if not isinstance(row, dict):
            bad_objects += 1
            continue
        identity = _finding_identity(row)
        if identity is None:
            missing_identity += 1
            continue
        issues.append(issue_for(row, profile))
        identities.append(identity)
    if bad_objects:
        skips.append({"reason": "finding_rows_not_objects",
                      "source": "findings", "count": bad_objects})
    if missing_identity:
        skips.append({"reason": "finding_rows_missing_identity",
                      "source": "findings", "count": missing_identity})
    issues.sort(key=lambda it: it["key"])
    identities.sort(key=lambda k: json.dumps(list(k)))
    return issues, skips, identities


def transitions_for(current: list, previous) -> tuple[dict, list]:
    """(transitions, skip-or-None) against a previous drafts document."""
    if previous is None:
        return ({"new": [], "unchanged": [], "updated": [], "closed": []},
                {"reason": "not_provided", "source": "previous"})
    if not isinstance(previous, dict):
        return ({"new": [], "unchanged": [], "updated": [], "closed": []},
                {"reason": "previous_not_object", "source": "previous"})
    if previous.get("schema") != SCHEMA:
        return ({"new": [], "unchanged": [], "updated": [], "closed": []},
                {"reason": "previous_wrong_schema", "source": "previous"})
    prev_issues = previous.get("issues")
    if not isinstance(prev_issues, list):
        return ({"new": [], "unchanged": [], "updated": [], "closed": []},
                {"reason": "previous_issues_not_a_list",
                 "source": "previous"})
    prev_digest, prev_order = {}, []
    for issue in prev_issues:
        if isinstance(issue, dict) and issue.get("key"):
            prev_digest[issue["key"]] = _digest(issue)
            prev_order.append(issue["key"])
    now = {it["key"]: _digest(it) for it in current}
    new = sorted(k for k in now if k not in prev_digest)
    closed = sorted(k for k in prev_digest if k not in now)
    unchanged = sorted(k for k in now
                       if k in prev_digest and now[k] == prev_digest[k])
    updated = sorted(k for k in now
                     if k in prev_digest and now[k] != prev_digest[k])
    return ({"new": new, "unchanged": unchanged, "updated": updated,
             "closed": closed}, None)


def build(payload, previous=None, profile: str = "generic",
          as_of=None) -> dict:
    """Assemble the ticket-drafts document (pure, deterministic)."""
    if profile not in PROFILES:
        raise ValueError(f"unknown_profile:{profile}")
    if payload is None:
        issues, skips = [], [
            {"reason": "not_provided", "source": "findings"}]
    else:
        issues, skips, _ = build_findings(payload, profile)
    transitions, tskip = transitions_for(issues, previous)
    if tskip is not None:
        skips.append(tskip)
    skips.sort(key=lambda s: (str(s.get("source", "")),
                              str(s.get("reason", ""))))
    by_severity = {}
    for issue in issues:
        by_severity[issue["severity"]] = by_severity.get(
            issue["severity"], 0) + 1
    doc = {
        "schema": SCHEMA,
        "profile": profile,
        "issues": issues,
        "transitions": transitions,
        "skips": skips,
        "stats": {
            "issues": len(issues),
            "by_severity": by_severity,
            "transitions": {k: len(v) for k, v in
                            sorted(transitions.items())},
            "skipped": sum(int(s.get("count", 1)) for s in skips),
        },
    }
    if as_of is not None:
        doc["as_of"] = as_of
    return doc
