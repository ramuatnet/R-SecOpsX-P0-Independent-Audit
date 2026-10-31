"""T-7.2: re-scan deltas + regression alerts (pure).

`rescan(store_before, store_after, old, new, context, as_of)` joins
two finding payloads against the feedback store and returns
{deltas, alerts, store, skips, stats}:

kinds (per key -- rule_id, normalized file, line):
  new         present now, absent before (or regressed, below)
  fixed       present before, absent now
  persistent  in both
  regressed   present now, absent before, AND the store says the
              finding was FIXED -- surfaces as an alert too

score deltas (scored through the T-7.1 scoring service with the
same as_of):  persistent = new - prev;  fixed = -prev (risk
removed);  new/regressed = +score (risk added).  prev is scored
against store_before feedback, new against store_after -- so an FP
recorded in the SAME batch shows up as an honest -2.0-class score
delta.  Identical inputs -> identical deltas.

alerts: regressed (previously fixed, back again) and fp_reappears
(triaged FP, fired again -- carries the decayed confidence).  New
findings are deltas, not alerts (disclosed).

Store transitions applied: fixed -> fix_state fixed, regressed ->
fix_state open (both get a `rescan` history event); a brand-new key
creates an open row (cap-disclosed).  Rows are explainable
(explanation + evidence on every delta and alert), sorted by key.
"""
from __future__ import annotations

from analysis.feedback import model
from analysis.scoring.score import score_finding


def _skip(stage: str, target, reason: str, detail: dict | None = None):
    return {"stage": stage, "target": str(target), "reason": reason,
            "detail": detail or {}}


def _sorted_skips(skips: list[dict]) -> list[dict]:
    skips.sort(key=lambda s: (str(s.get("stage", "")),
                              str(s.get("target", "")),
                              str(s.get("reason", ""))))
    return skips


def _extract(payload, side: str) -> tuple[dict, list[dict]]:
    """Payload -> {key: row} with annotated drops (never silent)."""
    skips: list[dict] = []
    if payload is None:
        return {}, [_skip("feedback", side, f"{side}_payload_missing")]
    if isinstance(payload, list):
        rows = payload
    elif isinstance(payload, dict) and isinstance(payload.get("findings"),
                                                   list):
        rows = payload["findings"]
    else:
        return {}, [_skip("feedback", side,
                          f"{side}_bad_findings_shape")]
    bad = [r for r in rows if not isinstance(r, dict)]
    if bad:
        skips.append(_skip("feedback", side,
                           f"{side}_rows_not_objects",
                           {"count": len(bad)}))
    no_identity = [r for r in rows
                   if isinstance(r, dict) and model.finding_key(r)
                   is None]
    if no_identity:
        skips.append(_skip("feedback", side,
                           f"{side}_rows_missing_identity",
                           {"count": len(no_identity)}))
    mapping: dict = {}
    dupes = 0
    for row in rows:
        if not isinstance(row, dict):
            continue
        key = model.finding_key(row)
        if key is None:
            continue
        if key in mapping:
            dupes += 1
            continue
        mapping[key] = row
    if dupes:
        skips.append(_skip("feedback", side, "duplicate_keys",
                           {"side": side, "count": dupes}))
    return mapping, skips


def _store_map(store: dict | None) -> dict:
    out: dict = {}
    for row in (store or {}).get("findings") or []:
        key = model.finding_key(row)
        if key is not None:
            out[key] = row
    return out


def _score(row: dict, shared_ctx: dict, store_row, as_of) -> float:
    """Score one scan row with store-derived context/feedback (the
    shared context sits under store state; a row's inline
    score_context/score_feedback still win -- T-7.1 contract)."""
    store_ctx, store_fb = model.score_inputs_for(store_row)
    ctx = {**shared_ctx, **store_ctx}
    scored = score_finding(row, context=ctx, feedback=store_fb,
                           as_of=as_of)
    return scored["score"]


def rescan(store_before: dict, store_after: dict, old_payload,
           new_payload, context: dict, as_of) -> dict:
    """Join two scans with the store -> deltas, alerts, store2, skips,
    stats.  store_before = pre-events state (scores prev against it);
    store_after = post-events state (scores new + drives alerts)."""
    as_dt = model._as_dt(as_of)
    shared_ctx = context if isinstance(context, dict) else {}
    skips: list[dict] = []

    old_map, old_skips = _extract(old_payload, "old")
    new_map, new_skips = _extract(new_payload, "new")
    skips.extend(old_skips)
    skips.extend(new_skips)
    prev_store = _store_map(store_before)
    next_store = _store_map(store_after)

    # store2 starts as a copy of store_after (never mutate inputs)
    store2: dict = {}
    for key, row in next_store.items():
        copied = dict(row)
        copied["history"] = list(row.get("history") or [])
        store2[key] = copied

    deltas: list[dict] = []
    alerts: list[dict] = []
    by_kind = {"new": 0, "fixed": 0, "persistent": 0, "regressed": 0}
    score_total = 0.0

    for key in sorted(set(old_map) | set(new_map)):
        in_old = key in old_map
        in_new = key in new_map
        row0 = prev_store.get(key)
        row1 = next_store.get(key)
        display = new_map[key] if in_new else old_map[key]
        rid = str(display.get("rule_id") or "")
        file = str(display.get("file") or "")
        line = model._safe_line(display.get("line"))

        if in_new and not in_old:
            kind = ("regressed"
                    if row0 is not None
                    and row0.get("fix_state") == "fixed"
                    else "new")
        elif in_old and not in_new:
            kind = "fixed"
        else:
            kind = "persistent"
        by_kind[kind] += 1

        prev_score = _score(old_map[key], shared_ctx, row0,
                            as_dt) if in_old else None
        new_score = _score(new_map[key], shared_ctx, row1,
                           as_dt) if in_new else None
        if kind == "persistent":
            score_delta = round(new_score - prev_score, 1)
        elif kind == "fixed":
            score_delta = round(-prev_score, 1)
        else:  # new / regressed add their score to the rollup
            score_delta = round(new_score, 1)
        score_total += score_delta
        confidence = float((row1 or row0 or {}).get("confidence", 1.0))
        triage = (row1 or row0 or {}).get("triage")
        verification = (row1 or row0 or {}).get("verification")
        fix_state = (row0 or row1 or {}).get("fix_state")

        where = f"{rid} at {file}:{line}"
        if kind == "new":
            explanation = (f"Finding {where} appears in this re-scan "
                           f"and was not present in the previous scan; "
                           f"score {new_score}, confidence "
                           f"{confidence}.")
        elif kind == "regressed":
            explanation = (f"Finding {where} appears again after "
                           f"being FIXED in the feedback store -- "
                           f"regression; score {new_score}, "
                           f"confidence {confidence}.")
        elif kind == "fixed":
            explanation = (f"Finding {where} was present in the "
                           f"previous scan and is absent now; "
                           f"previous score {prev_score} removed "
                           f"from the rollup.")
        elif score_delta == 0.0:
            explanation = (f"Finding {where} present in both scans; "
                           f"score {prev_score} unchanged "
                           f"(delta 0.0).")
        else:
            explanation = (f"Finding {where} present in both scans; "
                           f"score {prev_score} -> {new_score} "
                           f"(delta {score_delta}).")

        deltas.append({
            "rule_id": rid, "file": file, "line": line, "kind": kind,
            "prev_score": prev_score, "score": new_score,
            "score_delta": score_delta, "confidence": confidence,
            "explanation": explanation,
            "evidence": {"in_old_scan": in_old, "in_new_scan": in_new,
                         "triage": triage,
                         "verification": verification,
                         "fix_state": fix_state},
        })

        if kind == "regressed":
            alerts.append({
                "rule_id": rid, "file": file, "line": line,
                "reason": "regressed", "confidence": confidence,
                "explanation": (f"Regression: {where} was marked "
                                f"FIXED in the feedback store but "
                                f"appears in this re-scan "
                                f"(score {new_score}, confidence "
                                f"{confidence})."),
                "evidence": {"kind": kind, "score": new_score},
            })
        if in_new and isinstance(triage, str) and triage == "fp":
            alerts.append({
                "rule_id": rid, "file": file, "line": line,
                "reason": "fp_reappears", "confidence": confidence,
                "explanation": (f"{where} was triaged FP but appears "
                                f"in this re-scan (score {new_score}, "
                                f"confidence {confidence})."),
                "evidence": {"kind": kind, "score": new_score},
            })

        # -- store transitions -----------------------------------
        if kind == "fixed":
            target = store2.get(key)
            if target is None:
                if len(store2) >= model.MAX_STORE_FINDINGS:
                    skips.append(_skip(
                        "feedback", rid,
                        f"cap_store_findings_"
                        f"{model.MAX_STORE_FINDINGS}",
                        {"rule_id": rid}))
                    continue
                target = {"rule_id": rid, "file": file, "line": line,
                          "triage": None, "verification": None,
                          "fix_state": None, "confidence": 1.0,
                          "fp_count": 0, "history": []}
                store2[key] = target
            target["fix_state"] = "fixed"
            if not model.append_history(target, {
                    "type": "rescan", "outcome": "fixed",
                    "as_of": as_dt.isoformat(),
                    "detail": {"in_old_scan": True,
                               "in_new_scan": False}}):
                skips.append(_skip(
                    "feedback", rid,
                    f"cap_history_{model.MAX_HISTORY}",
                    {"rule_id": rid}))
        elif kind == "regressed":
            target = store2.get(key)
            if target is not None:
                target["fix_state"] = "open"
                if not model.append_history(target, {
                        "type": "rescan", "outcome": "regressed",
                        "as_of": as_dt.isoformat(),
                        "detail": {"in_old_scan": False,
                                   "in_new_scan": True}}):
                    skips.append(_skip(
                        "feedback", rid,
                        f"cap_history_{model.MAX_HISTORY}",
                        {"rule_id": rid}))
        elif kind == "new" and key not in store2:
            if len(store2) >= model.MAX_STORE_FINDINGS:
                skips.append(_skip(
                    "feedback", rid,
                    f"cap_store_findings_{model.MAX_STORE_FINDINGS}",
                    {"rule_id": rid}))
            else:
                store2[key] = {"rule_id": rid, "file": file,
                               "line": line, "triage": None,
                               "verification": None,
                               "fix_state": "open",
                               "confidence": 1.0, "fp_count": 0,
                               "history": []}

    deltas.sort(key=lambda d: (d["rule_id"], d["file"], d["line"]))
    alerts.sort(key=lambda a: (a["rule_id"], a["file"], a["line"],
                               a["reason"]))
    findings = sorted(store2.values(),
                      key=lambda r: model.finding_key(r))
    stats = {"old_rows": len(old_map), "new_rows": len(new_map),
             "by_kind": by_kind, "alerts": len(alerts),
             "score_delta_total": round(score_total, 2)}
    return {"deltas": deltas, "alerts": alerts,
            "store": {"schema": model.SCHEMA,
                      "as_of": as_dt.isoformat(),
                      "findings": findings},
            "skips": _sorted_skips(skips), "stats": stats}
