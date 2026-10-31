"""T-7.2: feedback store ingest + CLI (offline, zero-I/O default).

  python -m analysis.feedback.connect [--store s.json] [--events e.json]
      [--old old_scan.json] [--new new_scan.json] [--context c.json]
      [--as-of ISO] [--out out.json]

One artifact out (stdout or --out), rsecopsx.feedback_store/v1:
{schema, as_of, findings[], deltas[], alerts[], skips[], stats}.

  --events   triage/verification/fix/reopen events applied to the
             loaded store (or a fresh store);
  --old/--new  both = re-scan: deltas + regression alerts computed
             and store fix-states updated (one side only =
             rescan_needs_both skip, never a crash);
  --context  shared modifier context for score deltas (optional --
             absence is not a skip).

No inputs = zero-I/O byte-identical document (with a fixed --as-of):
findings/deltas/alerts empty, every input surface an explicit
not_provided skip.  Inputs are bounded (64MiB); unreadable or
unparseable files are skip rows, never raises.  Identical inputs ->
identical bytes.
"""
from __future__ import annotations

import argparse
import json
import sys

from analysis.feedback import model
from analysis.feedback.delta import rescan

MAX_INPUT_BYTES = 64 * 1024 * 1024


def _skip(stage: str, target, reason: str, detail: dict | None = None):
    return {"stage": stage, "target": str(target), "reason": reason,
            "detail": detail or {}}


def _load(path: str, target: str):
    """Read + parse one JSON file -> (data, skip).  Never raises."""
    try:
        with open(path, "rb") as fh:
            raw = fh.read(MAX_INPUT_BYTES + 1)
    except OSError as exc:
        return None, _skip("feedback", target,
                           f"{type(exc).__name__}:{path}")
    if len(raw) > MAX_INPUT_BYTES:
        return None, _skip("feedback", target, "input_too_large",
                           {"path": path, "max_bytes": MAX_INPUT_BYTES})
    try:
        return json.loads(raw.decode("utf-8")), None
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return None, _skip("feedback", target,
                           f"json_decode_error:{path}",
                           {"error": type(exc).__name__})


def _store_from_payload(data):
    """Validated store state -> (store, skip|None)."""
    if not isinstance(data, dict):
        return model.empty_store(), _skip("feedback", "store",
                                          "bad_store_shape")
    if data.get("schema") != model.SCHEMA:
        return model.empty_store(), _skip(
            "feedback", "store", "wrong_schema",
            {"expected": model.SCHEMA,
             "got": data.get("schema")})
    if not isinstance(data.get("findings"), list):
        return model.empty_store(), _skip("feedback", "store",
                                          "bad_store_shape")
    return {"schema": model.SCHEMA,
            "as_of": data.get("as_of"),
            "findings": data["findings"]}, None


def _sanitize_store_rows(store: dict) -> tuple[dict, list[dict]]:
    """Drop unusable store rows with annotated skips (never silent)."""
    skips: list[dict] = []
    kept = []
    bad = 0
    missing = 0
    seen = set()
    dupes = 0
    for row in store.get("findings") or []:
        if not isinstance(row, dict):
            bad += 1
            continue
        key = model.finding_key(row)
        if key is None:
            missing += 1
            continue
        if key in seen:
            dupes += 1
            continue
        seen.add(key)
        kept.append(row)
    if bad:
        skips.append(_skip("feedback", "store",
                           "store_rows_not_objects", {"count": bad}))
    if missing:
        skips.append(_skip("feedback", "store",
                           "store_rows_missing_identity",
                           {"count": missing}))
    if dupes:
        skips.append(_skip("feedback", "store", "duplicate_keys",
                           {"count": dupes}))
    store = dict(store)
    store["findings"] = kept
    return store, skips


def _load_store(path: str | None, as_of=None):
    """Store file -> (store, skips).  Missing --store is itself a
    disclosed not_provided skip (fresh store)."""
    if path is None:
        return model.empty_store(as_of), [
            _skip("feedback", "store", "not_provided")]
    data, skip = _load(path, "store")
    if skip is not None:
        return model.empty_store(as_of), [skip]
    store, shape_skip = _store_from_payload(data)
    skips = [shape_skip] if shape_skip else []
    store, row_skips = _sanitize_store_rows(store)
    skips.extend(row_skips)
    return store, skips


def _load_mapping(path: str | None, target: str):
    """Optional JSON object file -> (dict, skip|None); absence is
    not a skip (shared modifiers are optional by design)."""
    if path is None:
        return {}, None
    data, skip = _load(path, target)
    if skip is not None:
        return {}, skip
    if not isinstance(data, dict):
        return {}, _skip("feedback", target, "payload_not_object",
                         {"path": path})
    return data, None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m analysis.feedback.connect",
        description="Feedback store: triage/verification/fix state, "
                    "FP confidence decay, re-scan score deltas and "
                    "regression alerts.")
    parser.add_argument("--store", help="store JSON to load and "
                        "update (fresh store when absent)")
    parser.add_argument("--events", help="event list JSON "
                        "(triage/verification/fix/reopen)")
    parser.add_argument("--old", help="previous scan findings JSON")
    parser.add_argument("--new", help="re-scan findings JSON")
    parser.add_argument("--context", help="shared scoring modifier "
                        "context JSON object")
    parser.add_argument("--as-of", help="ISO timestamp (deterministic "
                        "when provided)")
    parser.add_argument("--out", help="write the artifact here "
                        "instead of stdout")
    args = parser.parse_args(argv)

    as_dt = None
    if args.as_of is not None:
        try:
            as_dt = model._as_dt(args.as_of, default_now=False)
        except (ValueError, TypeError) as exc:
            print(f"error: unparseable --as-of {args.as_of!r}: {exc}",
                  file=sys.stderr)
            return 2
    else:
        as_dt = model._as_dt(None)

    skips: list[dict] = []

    store0, sk = _load_store(args.store, as_dt)
    skips.extend(sk)

    events_payload = None
    if args.events is None:
        skips.append(_skip("feedback", "events", "not_provided"))
    else:
        events_payload, sk = _load(args.events, "events")
        if sk is not None:
            skips.append(sk)
            events_payload = None

    if args.old is None:
        skips.append(_skip("feedback", "old", "not_provided"))
        old_payload = None
    else:
        old_payload, sk = _load(args.old, "old")
        if sk is not None:
            skips.append(sk)
            old_payload = None
    if args.new is None:
        skips.append(_skip("feedback", "new", "not_provided"))
        new_payload = None
    else:
        new_payload, sk = _load(args.new, "new")
        if sk is not None:
            skips.append(sk)
            new_payload = None

    context, sk = _load_mapping(args.context, "context")
    if sk is not None:
        skips.append(sk)

    # -- events ---------------------------------------------------
    if events_payload is not None:
        store1, ev_skips = model.apply_events(store0, events_payload,
                                              as_dt)
        skips.extend(ev_skips)
    else:
        store1 = store0
    events_applied = int(store1.get("events_applied", 0))

    # -- re-scan --------------------------------------------------
    by_kind = {"new": 0, "fixed": 0, "persistent": 0, "regressed": 0}
    score_delta_total = 0.0
    deltas: list[dict] = []
    alerts: list[dict] = []
    final_store = store1
    if old_payload is not None and new_payload is not None:
        result = rescan(store0, store1, old_payload, new_payload,
                        context, as_dt)
        deltas = result["deltas"]
        alerts = result["alerts"]
        skips.extend(result["skips"])
        by_kind = result["stats"]["by_kind"]
        score_delta_total = result["stats"]["score_delta_total"]
        final_store = result["store"]
    elif args.old is not None or args.new is not None:
        skips.append(_skip("feedback", "rescan", "rescan_needs_both"))

    skips.sort(key=lambda s: (str(s.get("stage", "")),
                              str(s.get("target", "")),
                              str(s.get("reason", ""))))
    artifact = {
        "schema": model.SCHEMA,
        "as_of": as_dt.isoformat(),
        "findings": final_store.get("findings") or [],
        "deltas": deltas,
        "alerts": alerts,
        "skips": skips,
        "stats": {"findings": len(final_store.get("findings") or []),
                  "events_applied": events_applied,
                  "deltas": len(deltas), "alerts": len(alerts),
                  "by_kind": by_kind,
                  "score_delta_total": score_delta_total,
                  "skips": len(skips)},
    }
    text = json.dumps(artifact, indent=2, sort_keys=True) + "\n"
    if args.out:
        with open(args.out, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
