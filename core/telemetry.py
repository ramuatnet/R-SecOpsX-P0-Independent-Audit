"""Structured scan telemetry document (T-14.3, task.md section 14).

task.md section 14 "Observability" asks for structured scan telemetry
covering stage timings, drop counts and regex timeouts. The three
ingredients already existed in fragments (the _SCAN_TIMING stage table
printed at scan end, the per-scan drop ledger behind --explain-drops,
the regex-budget collector behind metadata.regex_budget) -- this module
is the single pure builder that assembles them into one
machine-readable artifact, telemetry.json, written beside
clean_report.json only when --telemetry is passed.

Pure and offline: no I/O, no clocks -- callers supply the three plain
dicts (main.py reads them from the already-computed scan_timing, the
filter_trace ledger summary and regex_budget.current().as_metadata()).
Wall-clock durations ride inside by design (they are the measurement);
the artifact is flag-gated precisely so the default output directory
stays byte-identical without it.

NOT ADOPTED: n/a for this item -- task.md names no library/tool here.
"""
from __future__ import annotations

TELEMETRY_SCHEMA = "rsecopsx.scan_telemetry/v1"


def build_document(scan_timing: dict | None = None,
                   drops_summary: dict | None = None,
                   regex_meta: dict | None = None) -> dict:
    """Assemble the telemetry document from the three scan ledgers.

    Defensive by contract (report-time artifacts must never raise):
    missing keys become nulls/empty lists, non-dict stage rows are
    skipped WITH a machine-readable count (ground rule 3 -- never a
    silent drop), and the input dicts are never mutated.
    """
    timing = scan_timing or {}
    raw_stages = timing.get("stages") or []
    stages: list[dict] = []
    skipped = 0
    for row in raw_stages:
        if isinstance(row, dict):
            stages.append(dict(row))
        else:
            skipped += 1
    return {
        "schema": TELEMETRY_SCHEMA,
        "scan": {
            "started_at": timing.get("started_at"),
            "completed_at": timing.get("completed_at"),
            "total_seconds": timing.get("total_seconds"),
            "total_duration": timing.get("total_duration"),
            "stages_skipped_not_objects": skipped,
        },
        "stages": stages,
        "drops": dict(drops_summary or {}),
        "regex": dict(regex_meta or {}),
    }
