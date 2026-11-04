"""T-7.2: feedback store model (pure stdlib).

Durable analyst + scan state per finding key (rule_id, normalized
file, line):

  triage        tp | fp | wontfix (task.md vocabulary, unknown is a
                machine-readable skip, never recorded);
  verification  reproduced | disproven | unverified (T-7.1 vocab);
  fix_state     open | fixed (set by fix/reopen events, then driven
                by re-scan transitions in analysis.feedback.delta);
  confidence    starts 1.0; every FP event HALVES it (floored at
                FLOOR_CONFIDENCE); a later TP restores it to 1.0;
                wontfix and verification never move it.  Updated
                incrementally at application time so history caps
                cannot corrupt it;
  history       append-only event log (capped at MAX_HISTORY with a
                disclosed truncation flag -- never a silent drop).

Events are plain dicts: {type, outcome, rule_id, file, line,
[at?, note?]} with type in triage/verification/fix/reopen.
Identical inputs -> identical store.  Never raises: every rejected
event is an annotated skip row.
"""
from __future__ import annotations
try:
    from analysis.spans import WINDOW_M1
except ImportError:  # FND-03: standalone, repo root not on path
    import sys as _fnd03_sys
    from pathlib import Path as _fnd03_path
    _fnd03_sys.path.insert(0, str(_fnd03_path(__file__).resolve().parents[2]))
    from analysis.spans import WINDOW_M1

from datetime import datetime, timezone

SCHEMA = "rsecopsx.feedback_store/v1"
MAX_STORE_FINDINGS = 5000
MAX_HISTORY = 50
MAX_EVENTS = 5000
FLOOR_CONFIDENCE = 0.05

TRIAGE_VOCAB = ("tp", "fp", "wontfix")
VERIFICATION_VOCAB = ("reproduced", "disproven", "unverified")
EVENT_TYPES = ("triage", "verification", "fix", "reopen")


def _as_dt(value, default_now: bool = True) -> datetime:
    """Normalize a timestamp to aware UTC (mirrors scoring)."""
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, str):
        text = value.strip()
        if text.endswith(("Z", "z")):
            text = text[:WINDOW_M1] + "+00:00"
        dt = datetime.fromisoformat(text)
    elif value is None and default_now:
        dt = datetime.now(timezone.utc)
    else:
        raise ValueError(f"unparseable timestamp: {value!r}")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _safe_line(value) -> int:
    """line -> int, anything unparseable becomes 0 (identity stays
    usable; two identical 0-line rows then collide as duplicates)."""
    if isinstance(value, bool):
        return 0
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return 0
    return 0


def finding_key(row):
    """(rule_id, normalized file, line) or None when identity is
    missing.  File paths normalize case and separators so a re-scan
    with a different root spelling still matches the same key."""
    if not isinstance(row, dict):
        return None
    rule_id = row.get("rule_id")
    file = row.get("file")
    if not (isinstance(rule_id, str) and rule_id):
        return None
    if not (isinstance(file, str) and file):
        return None
    norm = file.replace("\\", "/").lower()
    return (rule_id, norm, _safe_line(row.get("line")))


def empty_store(as_of: datetime | str | None = None) -> dict:
    return {"schema": SCHEMA,
            "as_of": _as_dt(as_of).isoformat(),
            "findings": []}


def score_inputs_for(row) -> tuple[dict, dict]:
    """Store row -> (context, feedback) for analysis.scoring.

    verification feeds the scoring modifier; triage feeds the
    scoring feedback delta (fp -> -2.0, tp -> +0.5, wontfix 0.0).
    Confidence is deliberately NOT a score modifier (disclosed:
    T-7.1 has no confidence factor).
    """
    if not isinstance(row, dict):
        return {}, {}
    ctx: dict = {}
    fb: dict = {}
    ver = row.get("verification")
    if isinstance(ver, str) and ver:
        ctx["verification"] = ver
    tri = row.get("triage")
    if isinstance(tri, str) and tri:
        fb["triage"] = tri
    return ctx, fb


def append_history(row: dict, entry: dict) -> bool:
    """Append one history entry; False = cap hit (row flagged
    history_truncated, caller records the cap skip)."""
    hist = row.setdefault("history", [])
    if len(hist) >= MAX_HISTORY:
        row["history_truncated"] = True
        return False
    hist.append(entry)
    return True


def _skip(stage: str, target, reason: str, detail: dict | None = None):
    return {"stage": stage, "target": str(target), "reason": reason,
            "detail": detail or {}}


def _sorted_skips(skips: list[dict]) -> list[dict]:
    skips.sort(key=lambda s: (str(s.get("stage", "")),
                              str(s.get("target", "")),
                              str(s.get("reason", ""))))
    return skips


def _extract_events(payload) -> tuple[list, dict | None]:
    if isinstance(payload, list):
        return payload, None
    if isinstance(payload, dict) and isinstance(payload.get("events"),
                                                 list):
        return payload["events"], None
    return [], _skip("feedback", "events", "bad_events_shape")


def _get_or_create(rows: dict, key, event: dict) -> dict | None:
    row = rows.get(key)
    if row is not None:
        return row
    if len(rows) >= MAX_STORE_FINDINGS:
        return None
    row = {"rule_id": str(event.get("rule_id")),
           "file": str(event.get("file")),
           "line": _safe_line(event.get("line")),
           "triage": None, "verification": None, "fix_state": None,
           "confidence": 1.0, "fp_count": 0, "history": []}
    rows[key] = row
    return row


def apply_events(store: dict, payload, as_of) -> tuple[dict, list[dict]]:
    """Apply triage/verification/fix/reopen events -> (store, skips).

    The returned store carries an events_applied count for THIS call
    (per-call, not cumulative -- the persisted artifact stores it in
    stats).  Input store is never mutated.
    """
    as_dt = _as_dt(as_of)
    skips: list[dict] = []
    rows: dict = {}
    for old in (store.get("findings") or []):
        key = finding_key(old)
        if key is not None and key not in rows:
            rows[key] = dict(old)
            rows[key]["history"] = list(old.get("history") or [])

    events, shape_skip = _extract_events(payload)
    if shape_skip is not None:
        skips.append(shape_skip)
        events = []
    bad = [e for e in events if not isinstance(e, dict)]
    if bad:
        skips.append(_skip("feedback", "events",
                           "event_rows_not_objects",
                           {"count": len(bad)}))
        events = [e for e in events if isinstance(e, dict)]
    if len(events) > MAX_EVENTS:
        skips.append(_skip("feedback", "events",
                           f"cap_events_{MAX_EVENTS}",
                           {"total": len(events)}))
        events = events[:MAX_EVENTS]

    applied = 0
    for event in events:
        etype = event.get("type")
        if etype not in EVENT_TYPES:
            skips.append(_skip("feedback", "events",
                               "event_type_unknown",
                               {"type": repr(etype)}))
            continue
        key = finding_key(event)
        if key is None:
            skips.append(_skip("feedback", "events",
                               "event_missing_identity", {}))
            continue
        at = event.get("at")
        if at is None:
            at_dt = as_dt
        else:
            try:
                at_dt = _as_dt(at, default_now=False)
            except (ValueError, TypeError):
                skips.append(_skip("feedback", str(event.get("rule_id")),
                                   "event_bad_at", {"at": repr(at)}))
                continue
        row = _get_or_create(rows, key, event)
        if row is None:
            skips.append(_skip("feedback", str(key[0]),
                               f"cap_store_findings_{MAX_STORE_FINDINGS}",
                               {"rule_id": key[0]}))
            continue
        outcome = event.get("outcome")
        if etype in ("triage", "verification"):
            vocab = (TRIAGE_VOCAB if etype == "triage"
                     else VERIFICATION_VOCAB)
            if not (isinstance(outcome, str)
                    and outcome.strip().lower() in vocab):
                reason = ("event_outcome_unknown" if etype == "triage"
                          else "event_verification_unknown")
                skips.append(_skip("feedback", str(key[0]), reason,
                                   {"outcome": repr(outcome)}))
                continue
            value = outcome.strip().lower()
        elif etype == "fix":
            value = "fixed"
        else:  # reopen
            value = "open"

        # -- state transitions (confidence is incremental so a
        #    history cap can never corrupt it) -------------------
        if etype == "triage":
            row["triage"] = value
            if value == "fp":
                row["confidence"] = max(
                    FLOOR_CONFIDENCE, row["confidence"] * 0.5)
                row["fp_count"] = row.get("fp_count", 0) + 1
            elif value == "tp":
                row["confidence"] = 1.0
        elif etype == "verification":
            row["verification"] = value
        else:
            row["fix_state"] = value

        entry = {"type": etype, "outcome": value,
                 "as_of": at_dt.isoformat(),
                 "detail": {"note": str(event.get("note") or "")}}
        if not append_history(row, entry):
            skips.append(_skip("feedback", str(key[0]),
                               f"cap_history_{MAX_HISTORY}",
                               {"rule_id": key[0]}))
        applied += 1

    findings = sorted(rows.values(),
                      key=lambda r: finding_key(r))
    return ({"schema": SCHEMA, "as_of": as_dt.isoformat(),
             "findings": findings, "events_applied": applied},
            _sorted_skips(skips))
