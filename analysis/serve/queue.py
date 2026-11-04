"""T-8.2 serve queue -- enqueue, run, drain, cron tick.

State machine (only run_job moves it):

    queued/failed --attempts<cap--> running --> done | failed

Every skip is annotated with a machine-readable reason -- never a
silent drop.  Determinism rules the tests pin:

* drain order is (created_at, target, id) -- alphabetical target is the
  tiebreak, so same-instant batches run in a reproducible order;
* run_job RE-READS attempts from the backend before incrementing (a
  stale dict would let two drains both see attempts=0 and double-run);
* cron first tick establishes the cursor and enqueues NOTHING (no
  backfill of history the service never observed); later ticks walk
  occurrences one minute-window at a time, capped per tick, and each
  occurrence gets its OWN content-addressed job id (re-ticking the
  same window is a no-op because the id already exists).
"""
from __future__ import annotations
try:
    from analysis.spans import WINDOW_12, WINDOW_300
except ImportError:  # FND-03: standalone, repo root not on path
    import sys as _fnd03_sys
    from pathlib import Path as _fnd03_path
    _fnd03_sys.path.insert(0, str(_fnd03_path(__file__).resolve().parents[2]))
    from analysis.spans import WINDOW_12, WINDOW_300

import hashlib

from .model import (MAX_ATTEMPTS, MAX_CRON_OCCURRENCES, MAX_ENQUEUE_BATCH,
                    MAX_RUN_PER_DRAIN, MAX_SCHEDULES, CronExpr, job_id_for,
                    validate_job)


def enqueue_jobs(backend, rows, now, tenant=None) -> "tuple[list, list]":
    """Validate + insert a batch; annotate every skip.

    ``tenant`` (T-9.2) comes from the credential, never from the row --
    validate_job stamps it and rebuilds the id canon with it.
    """
    if not isinstance(rows, list):
        rows = [rows]
    jobs, skips = [], []
    for i, row in enumerate(rows):
        if i >= MAX_ENQUEUE_BATCH:
            skips.append({"index": i, "reason": f"cap_enqueue_{MAX_ENQUEUE_BATCH}"})
            continue
        job, err = validate_job(row, tenant=tenant)
        if err is not None:
            skips.append({"index": i, "reason": err})
            continue
        if backend.job(job["id"]) is not None:
            skips.append({"index": i, "reason": f"job_exists:{job['id']}"})
            continue
        backend.enqueue_job(job, now)
        backend.append_event("job.enqueued",
                             {"job_id": job["id"], "target": job["target"]},
                             at=now, tenant=job.get("tenant") or "")
        jobs.append(job)
    return jobs, skips


def run_job(backend, job, runner, now) -> dict:
    """Run one job to a terminal state; attempts re-read from storage."""
    current = backend.job(job["id"]) or job
    # T-9.2: the re-read row carries the tenant column; a fallback dict
    # without one is unscoped ("")
    scope = current.get("tenant") or ""
    attempts = int(current.get("attempts") or 0) + 1
    backend.update_job(job["id"], status="running", attempts=attempts, now=now)
    backend.append_event("job.started", {"job_id": job["id"]}, at=now,
                         tenant=scope)
    try:
        result = runner(job)
        ok = bool(result.get("ok")) if isinstance(result, dict) else bool(result)
        detail = (result.get("detail") if isinstance(result, dict) else None)
    except Exception as exc:  # noqa: BLE001 -- terminal state, annotated
        err = f"{type(exc).__name__}: {exc}"[:WINDOW_300]
        backend.update_job(job["id"], status="failed", last_error=err, now=now)
        backend.append_event("job.failed",
                             {"job_id": job["id"], "error": err}, at=now,
                             tenant=scope)
        return backend.job(job["id"])
    if ok:
        backend.update_job(job["id"], status="done", now=now)
        backend.append_event("job.completed",
                             {"job_id": job["id"], "detail": detail}, at=now,
                             tenant=scope)
    else:
        err = f"runner_not_ok: {detail}"[:WINDOW_300]
        backend.update_job(job["id"], status="failed", last_error=err, now=now)
        backend.append_event("job.failed",
                             {"job_id": job["id"], "error": err}, at=now,
                             tenant=scope)
    return backend.job(job["id"])


def drain(backend, runner, now, limit=MAX_RUN_PER_DRAIN):
    """Run queued/failed jobs under the attempt cap, deterministically."""
    ran = done = failed = 0
    skips = []
    runnable = []
    for job in backend.list_jobs():
        if job["status"] not in ("queued", "failed"):
            continue
        if int(job.get("attempts") or 0) >= MAX_ATTEMPTS:
            skips.append({"reason": f"attempts_exhausted:{job['id']}"})
            continue
        runnable.append(job)
    runnable.sort(key=lambda j: (j.get("created_at") or 0.0,
                                 j.get("target") or "", j["id"]))
    for job in runnable[:limit]:
        run_job(backend, job, runner, now)
        ran += 1
        after = backend.job(job["id"])
        if after["status"] == "done":
            done += 1
        else:
            failed += 1
    return ran, {"ran": ran, "done": done, "failed": failed}, skips


def _schedule_id(row, tenant=None) -> str:
    # T-9.2: the T-8.2 canon (cron|target|out) is FROZEN for unscoped
    # schedules; a tenant joins only when non-empty so two tenants may
    # schedule the same cron+target without colliding on the primary key
    canon = f"{row.get('cron')}|{row.get('target')}|{row.get('out')}"
    if tenant:
        canon = f"{canon}|{tenant}"
    return "sch_" + hashlib.sha256(canon.encode("utf-8")).hexdigest()[:WINDOW_12]


def add_schedule(backend, rows, now, tenant=None) -> "tuple[list, list]":
    """Validate + insert cron schedules; annotate every skip.

    ``tenant`` (T-9.2) comes from the credential, never from the row --
    the client cannot post its way into another tenant's schedule.
    """
    if not isinstance(rows, list):
        rows = [rows]
    good, skips = [], []
    existing = {s["id"] for s in backend.schedules()}
    for i, row in enumerate(rows):
        if len(existing) >= MAX_SCHEDULES:
            skips.append({"index": i, "reason": f"cap_schedules_{MAX_SCHEDULES}"})
            continue
        if not isinstance(row, dict):
            skips.append({"index": i, "reason": "schedule_not_object"})
            continue
        if "cron" not in row:
            skips.append({"index": i, "reason": "cron_missing"})
            continue
        try:
            CronExpr.parse(row["cron"])
        except ValueError as exc:
            # one stable reason token; the parse message rides as detail
            skips.append({"index": i, "reason": "cron_invalid",
                          "detail": str(exc)})
            continue
        if not row.get("target"):
            skips.append({"index": i, "reason": "target_missing"})
            continue
        sched = {"id": _schedule_id(row, tenant), "cron": row["cron"],
                 "target": row["target"], "out": row.get("out"),
                 "created_at": now, "last_tick": None}
        if tenant:
            sched["tenant"] = tenant    # absent key for legacy/unscoped
        if sched["id"] in existing:
            skips.append({"index": i, "reason": f"schedule_exists:{sched['id']}"})
            continue
        backend.insert_schedule(sched, now)
        existing.add(sched["id"])
        good.append(sched)
    return good, skips


def cron_tick(backend, now) -> dict:
    """Advance every schedule to the current minute; enqueue occurrences."""
    floor = int(now) // 60 * 60
    enqueued = 0
    capped = False
    skips = []
    for sched in backend.schedules():
        expr = CronExpr.parse(sched["cron"])
        if sched.get("last_tick") is None:
            # first tick: cursor only, never backfill observed history
            backend.set_last_tick(sched["id"], floor)
            continue
        cursor = int(sched["last_tick"])
        occurrences = []
        try:
            o = expr.next_after(cursor)
        except ValueError:
            o = None
        while o is not None and o <= floor:
            occurrences.append(o)
            if len(occurrences) > MAX_CRON_OCCURRENCES:
                break
            try:
                o = expr.next_after(o)
            except ValueError:
                break
        overflow = len(occurrences) > MAX_CRON_OCCURRENCES
        take = occurrences[:MAX_CRON_OCCURRENCES]
        for occ in take:
            # T-9.2: occurrence ids inherit the schedule's tenant so two
            # tenants' crons never collide; the ticker itself still walks
            # EVERY schedule (global by design -- disclosed)
            row = {"target": sched["target"], "out": sched.get("out")}
            scope = sched.get("tenant") or ""
            if scope:
                row["tenant"] = scope
            jid = job_id_for(row, occurrence=occ)
            if backend.job(jid) is None:
                job = {"id": jid, "target": sched["target"],
                       "out": sched.get("out"), "status": "queued",
                       "attempts": 0, "last_error": None}
                if scope:
                    job["tenant"] = scope
                backend.enqueue_job(job, float(occ))
                backend.append_event(
                    "job.cron_enqueued",
                    {"job_id": jid, "schedule_id": sched["id"],
                     "occurrence": occ}, at=float(now), tenant=scope)
                enqueued += 1
        if overflow:
            capped = True
            skips.append({"schedule_id": sched["id"],
                          "reason": f"cap_cron_occurrences_{MAX_CRON_OCCURRENCES}",
                          "more_pending": True})
        backend.set_last_tick(sched["id"], floor)
    return {"enqueued": enqueued,
            "capped_at": MAX_CRON_OCCURRENCES if capped else None,
            "skips": skips}
