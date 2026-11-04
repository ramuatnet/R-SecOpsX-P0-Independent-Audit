"""T-0.1: machine-readable audit trail for every filter decision.

task.md ground rule 3 (BINDING):

    No silent drops. Every filter pass must *annotate*, never *delete*.
    A finding removed from clean_report.json must carry a machine-readable
    reason.

Two mechanisms implement it:

  * ``annotate_occurrence_drop`` -- an occurrence is removed from a finding
    that STAYS in the report. The entry lands on the finding's own
    ``filter_trace`` list, so clean_report.json itself explains the loss.
  * ``record_finding_drop`` -- a finding is removed from the report
    population entirely (or merged into a surviving twin). The entry lands
    in the per-scan drop ledger; ``--explain-drops`` serializes the ledger
    to ``drops.json`` next to clean_report.json.

Design constraints:
  * No project imports -- scanner/, core/ and main.py all use this module,
    so it must never import any of them (no cycles).
  * Thread-safe: the shell-sink taint gate annotates from worker threads.
  * Deterministic: ledger rows are sorted at document-build time so
    drops.json is byte-identical across runs (ground rule 10).
"""
from __future__ import annotations

import threading
from typing import Any, Optional

TRACE_FIELD = "filter_trace"
DROPS_SCHEMA = "rsecopsx.filter_drops/v1"

#: Every value a filter_trace entry's "decision" field may take.
DECISIONS = frozenset({
    "drop_finding",     # finding removed from the report population
    "drop_occurrence",  # occurrence removed from a finding that survives
    "merged",           # finding folded into a surviving twin (dedup)
    "kept_after_path_repair",  # judgement: kept, but its anchor was rewritten
    "regex_budget_exceeded",   # FND-05: scan-integrity notice, not a discard
})


def _occurrence_ref(occ: Any) -> dict:
    """Identify a removed occurrence without copying its whole payload."""
    if not isinstance(occ, dict):
        return {"file": None, "line": None, "kind": type(occ).__name__}
    return {
        "file": occ.get("file") or occ.get("file_path") or occ.get("full_path"),
        "line": occ.get("line"),
    }


def _finding_ref(finding: Any) -> dict:
    if not isinstance(finding, dict):
        return {"kind": type(finding).__name__}
    occurrences = finding.get("occurrences")
    return {
        "rule_id": finding.get("rule_id"),
        "vuln_type": finding.get("vuln_type"),
        "title": finding.get("title"),
        "severity": finding.get("severity"),
        "file": finding.get("file") or finding.get("file_path"),
        "line": finding.get("line"),
        "instances": len(occurrences) if isinstance(occurrences, list)
        else finding.get("instances"),
    }


def annotate(finding: Any, pass_name: str, decision: str,
             reason: str, evidence_ref: Optional[dict] = None) -> dict:
    """Append one machine-readable decision entry to a finding's trace."""
    if not isinstance(finding, dict):
        return {}
    entry: dict = {"pass": pass_name, "decision": decision, "reason": reason}
    if evidence_ref is not None:
        entry["evidence_ref"] = evidence_ref
    finding.setdefault(TRACE_FIELD, []).append(entry)
    return entry


def annotate_occurrence_drop(finding: Any, pass_name: str, occ: Any,
                             reason: str) -> dict:
    """An occurrence was removed from a finding that stays in the report."""
    return annotate(finding, pass_name, "drop_occurrence", reason,
                    _occurrence_ref(occ))


class DropLedger:
    """Per-scan record of findings removed from the report population."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.entries: list[dict] = []

    def record(self, finding: Any, pass_name: str, reason: str,
               decision: str = "drop_finding") -> dict:
        entry = {
            "pass": pass_name,
            "decision": decision,
            "reason": reason,
        }
        entry.update(_finding_ref(finding))
        if isinstance(finding, dict):
            entry["filter_trace"] = list(finding.get(TRACE_FIELD) or [])
        with self._lock:
            self.entries.append(entry)
        return entry

    def count(self) -> int:
        with self._lock:
            return len(self.entries)


_LEDGER: Optional[DropLedger] = None
_LEDGER_LOCK = threading.Lock()


def begin_scan() -> DropLedger:
    """Reset the ledger for a new scan (called from main())."""
    global _LEDGER
    with _LEDGER_LOCK:
        _LEDGER = DropLedger()
        return _LEDGER


def current_ledger() -> DropLedger:
    """The active ledger; lazily created so direct callers still record."""
    global _LEDGER
    with _LEDGER_LOCK:
        if _LEDGER is None:
            _LEDGER = DropLedger()
        return _LEDGER


def record_finding_drop(finding: Any, pass_name: str, reason: str,
                        decision: str = "drop_finding") -> dict:
    """A finding left the report population; annotate it and the ledger."""
    annotate(finding, pass_name, decision, reason)
    return current_ledger().record(finding, pass_name, reason, decision)


def record_scan_violation(stage: str, reason: str, *, rule_id: Any = None,
                          path: Any = None, line: Any = None) -> dict:
    """FND-05: a scan-integrity notice on the canonical ledger view.

    Not a population discard: no candidate left the report because of it,
    so ``attach_to_payload`` partitions these rows out of the FND-01
    arithmetic while still putting them on ``payload["filter_trace"]``
    (canonical ``{stage, rule, path, line, reason}``).  A regex budget
    breach that yields zero matches would otherwise be the exact silent
    loss ground rule 3 forbids -- the finding is never even seen.
    """
    row = {
        "pass": stage,
        "decision": stage,
        "reason": reason,
        "rule_id": rule_id,
        "file": path,
        "line": line,
    }
    ledger = current_ledger()
    with ledger._lock:
        ledger.entries.append(row)
    return row


def _count_occurrence_drops(payload: dict) -> int:
    total = 0
    for finding in (payload or {}).get("findings") or []:
        if not isinstance(finding, dict):
            continue
        total += sum(
            1 for e in finding.get(TRACE_FIELD) or []
            if isinstance(e, dict) and e.get("decision") == "drop_occurrence"
        )
    return total


def build_drops_document(payload: dict) -> dict:
    """Serialize the ledger for --explain-drops (drops.json).

    Rows are sorted (pass, rule_id, file, line, title) so the document is
    byte-identical across runs of the same input -- drop *order* depends on
    worker-thread scheduling and must not leak into the artifact.

    FND-05: scan-integrity notices (``decision == stage`` rows such as
    ``regex_budget_exceeded``) are NOT findings removed -- they get their
    own sorted ``violations`` section so the summary counts stay honest
    and the artifact stays deterministic either way.
    """
    ledger = current_ledger()

    def _key(row: dict):
        return (
            str(row.get("pass") or ""),
            str(row.get("rule_id") or ""),
            str(row.get("file") or ""),
            str(row.get("line") or ""),
            str(row.get("title") or ""),
        )

    with ledger._lock:
        all_rows = sorted((dict(r) for r in ledger.entries), key=_key)

    def _is_violation(row: dict) -> bool:
        return row.get("decision") == "regex_budget_exceeded"

    rows = [r for r in all_rows if not _is_violation(r)]
    violations = [r for r in all_rows if _is_violation(r)]

    doc = {
        "schema": DROPS_SCHEMA,
        "summary": {
            "total_findings_removed": len(rows),
            "by_pass": _count_by(rows, "pass"),
            "by_decision": _count_by(rows, "decision"),
            "occurrence_drops_on_reported_findings":
                _count_occurrence_drops(payload or {}),
        },
        "drops": rows,
    }
    if violations:
        # additive (ftasks non-goal: schema changes are additive only)
        doc["violations"] = violations
    return doc


def _count_by(rows: list[dict], field: str) -> dict:
    out: dict[str, int] = {}
    for row in rows:
        key = str(row.get(field) or "")
        out[key] = out.get(key, 0) + 1
    return dict(sorted(out.items()))


def attach_to_payload(payload: dict, raw_candidates: int) -> list[dict]:
    """FND-01: materialise the population-level drop ledger onto the payload.

    ``payload["filter_trace"]`` is the always-on canonical view of every
    candidate that left the report population: one flat entry per discard
    carrying exactly ``{stage, rule, path, line, reason}``.  It is built
    from the per-scan ledger, so it costs no second bookkeeping path.

    Occurrence-level drops stay where T-0.1 put them -- on each surviving
    finding's own ``filter_trace`` and in ``drops.json`` -- because an
    occurrence drop does not consume a raw candidate; only population
    discards (drop_finding / merged) do.

    FND-05: scan-integrity notices (``regex_budget_exceeded`` rows from
    ``record_scan_violation``) ride along on the same canonical list --
    they are breaches a reader must see -- but they never consumed a raw
    candidate, so the arithmetic below counts drops only.

    Sets ``metadata.raw_candidates`` and asserts the accounting identity::

        len(drops) + len(findings) == raw_candidates
        # where drops = [e for e in filter_trace
        #               if e["stage"] != "regex_budget_exceeded"]

    A breach means some pass removed a candidate without going through
    ``record_finding_drop`` -- a silent drop, which ftasks ground rule 3
    forbids.  The assertion is the kill switch: the scan fails loudly
    instead of shipping a report whose counts cannot be reconciled.
    """
    if not isinstance(payload.get("metadata"), dict):
        payload["metadata"] = {}
    meta = payload["metadata"]

    ledger = current_ledger()
    with ledger._lock:
        rows = [dict(r) for r in ledger.entries]

    trace: list[dict] = []
    for row in rows:
        path = (row.get("file") or row.get("file_path")
                or row.get("full_path"))
        trace.append({
            "stage": row.get("pass"),
            "rule": row.get("rule_id"),
            "path": path,
            "line": row.get("line"),
            "reason": row.get("reason"),
        })

    # FND-05 partition: violations are notices, not discards.  Drops keep
    # ledger order (FND-01 behaviour); violations sort by (rule, path,
    # line) so their arrival order (thread timing) never leaks into the
    # artifact.
    violations = [e for e in trace if e["stage"] == "regex_budget_exceeded"]
    drops = [e for e in trace if e["stage"] != "regex_budget_exceeded"]
    violations.sort(key=lambda e: (str(e.get("rule") or ""),
                                   str(e.get("path") or ""),
                                   str(e.get("line") or "")))

    findings = payload.get("findings")
    n_findings = len(findings) if isinstance(findings, list) else 0

    payload["filter_trace"] = drops + violations
    meta["raw_candidates"] = int(raw_candidates)

    total = len(drops) + n_findings
    if total != int(raw_candidates):
        raise AssertionError(
            "FND-01 silent-drop breach: len(drops)=%d + "
            "len(findings)=%d = %d != raw_candidates=%d"
            % (len(drops), n_findings, total, int(raw_candidates))
        )
    return payload["filter_trace"]
