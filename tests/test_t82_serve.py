"""T-8.2 serve mode -- red-first acceptance tests (task.md section 11).

Contracts pinned here BEFORE any product code exists:

* model -- job/status/event vocabularies, deterministic job ids, cron
  (5-field, UTC, Vixie dom/dow OR rule), SSE framing bytes, webhook
  payload bytes, caps as constants (behaviour tested, not literals);
* storage -- SQLite backend (stdlib, injectable :memory:), event log
  ordering, and the SQLite->Postgres seam failing LOUD with a
  machine-readable reason (Postgres itself is PHASE 9);
* queue -- enqueue/validate, run_job state machine with an attempt cap,
  deterministic drain order, cron tick (first tick never backfills;
  occurrences capped; occurrence-scoped job ids);
* events -- SSE replay + bounded follow, webhook delivery with an
  INJECTABLE sender (network never happens unless a sender is given),
  retry with bounded backoff, URL scheme validation, dry-run default,
  and webhook kinds excluded from webhook delivery (no recursion);
* api -- pure router (status/headers/bytes), axum disclosure line
  (petgraph precedent), 404/405/400/413 shapes;
* pins -- axum "not adopted" greppable, AST top-level import pin (the
  real sender may import urllib INSIDE a function -- never at module
  level: default import does zero I/O);
* cli -- zero-I/O default with exactly 3 not_provided skips and
  byte-identical artifacts under a fixed --as-of, enqueue/drain/events
  artifacts, rc 2 on bad --as-of, --deliver loopback opt-in, and one
  live serve smoke on 127.0.0.1 (loopback only).
"""
import ast
import json
import pathlib
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

import pytest

from analysis.serve import (
    DOC_SCHEMA,
    EVENT_KINDS,
    JOB_STATUSES,
    MAX_ATTEMPTS,
    MAX_ENQUEUE_BATCH,
    MAX_WEBHOOKS,
    SCHEMA,
    CronExpr,
    add_schedule,
    cron_tick,
    deliver_events,
    drain,
    enqueue_jobs,
    job_id_for,
    route,
    run_job,
    sse_frame,
    validate_job,
    webhook_payload,
)
from analysis.serve import api as serve_api
from analysis.serve import model as serve_model
from analysis.serve import storage as serve_storage
from analysis.serve.connect import main as serve_cli
from analysis.serve.events import follow_events, sse_replay
from analysis.serve.storage import SqliteBackend, open_backend

REPO = pathlib.Path(__file__).resolve().parent.parent

# ---------------------------------------------------------------------------
# A. model
# ---------------------------------------------------------------------------


def test_job_statuses_and_event_kinds_vocabulary():
    assert JOB_STATUSES == ("queued", "running", "done", "failed")
    assert EVENT_KINDS == (
        "job.enqueued", "job.started", "job.completed", "job.failed",
        "job.cron_enqueued", "webhook.delivered", "webhook.failed",
    )
    assert SCHEMA == "rsecopsx.serve/v1"
    assert DOC_SCHEMA == "rsecopsx.serve_doc/v1"


def test_validate_job_shapes_and_error_strings():
    job, err = validate_job({"target": "app/", "out": "o/"})
    assert err is None
    assert job["target"] == "app/" and job["out"] == "o/"
    assert job["status"] == "queued" and job["attempts"] == 0
    assert job["last_error"] is None
    _, err = validate_job(["not", "an", "object"])
    assert err == "job_not_object"
    _, err = validate_job({})
    assert err == "target_missing"
    _, err = validate_job({"target": 42})
    assert err == "target_not_a_string"


def test_job_id_is_deterministic_and_occurrence_scoped():
    a = job_id_for({"target": "app/"})
    b = job_id_for({"target": "app/"})
    assert a == b and a.startswith("job_")
    c = job_id_for({"target": "app/"}, occurrence=1_000_020)
    d = job_id_for({"target": "app/"}, occurrence=1_000_080)
    assert c != a and c != d and c.startswith("job_")


def test_cron_next_after_and_utc_minute_alignment():
    # anchored INSIDE 2001-01-09T01:46:40Z (t=10**6 is 1970, not 2001 --
    # fixed in bring-up: the arithmetic must come from datetime, not a
    # hand-rolled epoch constant)
    from datetime import datetime, timezone
    t0 = int(datetime(2001, 1, 9, 1, 46, 40,
                      tzinfo=timezone.utc).timestamp())
    # every-minute cron next fires 01:47:00
    assert CronExpr.parse("* * * * *").next_after(t0) == t0 + 20
    # Daily midnight: computed with datetime, not with the implementation.
    want = int(datetime(2001, 1, 10, tzinfo=timezone.utc).timestamp())
    assert CronExpr.parse("0 0 * * *").next_after(t0) == want
    # Sunday: dow 7 must equal dow 0.
    sun0 = CronExpr.parse("0 0 * * 0").next_after(t0)
    sun7 = CronExpr.parse("0 0 * * 7").next_after(t0)
    assert sun0 == sun7
    # Vixie rule: dom AND dow restricted -> EITHER matches.  From
    # 2001-01-09 (Tue) the Monday boundary 2001-01-15 comes before the
    # next 1st (2001-02-01); an AND rule would wait for Feb 1.
    either = CronExpr.parse("0 0 1 * 1").next_after(t0)
    assert either == int(
        datetime(2001, 1, 15, tzinfo=timezone.utc).timestamp())


def test_cron_leap_day_is_bounded():
    from datetime import datetime, timezone
    start = int(datetime(2026, 6, 1, tzinfo=timezone.utc).timestamp())
    got = CronExpr.parse("0 0 29 2 *").next_after(start)
    assert got == int(datetime(2028, 2, 29, tzinfo=timezone.utc).timestamp())


def test_cron_parse_errors_are_strings():
    for bad in ("* * * *", "60 * * * *", "* * * * 8", "a * * * *", "",
                "* * 32 * *", "* * * 13 *"):
        with pytest.raises(ValueError):
            CronExpr.parse(bad)


def test_sse_frame_exact_bytes():
    got = sse_frame('{"a": 1}', event="job.enqueued", id=7)
    assert got == b'id: 7\nevent: job.enqueued\ndata: {"a": 1}\n\n'
    multi = sse_frame("line1\nline2")
    assert multi == b"data: line1\ndata: line2\n\n"


def test_webhook_payload_is_canonical_bytes():
    row = {"seq": 3, "kind": "job.enqueued", "at": 10.0,
           "payload": {"job_id": "job_abc"}}
    body = webhook_payload(row)
    assert isinstance(body, bytes)
    assert body.endswith(b"\n")
    parsed = json.loads(body)
    assert parsed["schema"] == "rsecopsx.serve_event/v1"
    assert parsed["seq"] == 3 and parsed["kind"] == "job.enqueued"
    # canonical: sort_keys + compact separators -> exact bytes stable
    again = webhook_payload(dict(row))
    assert body == again


def test_enqueue_batch_cap_is_annotated_not_silent():
    backend = SqliteBackend(":memory:")
    rows = [{"target": f"t{i}"} for i in range(MAX_ENQUEUE_BATCH + 2)]
    jobs, skips = enqueue_jobs(backend, rows, now=1000.0)
    assert len(jobs) == MAX_ENQUEUE_BATCH
    assert any(s["reason"] == f"cap_enqueue_{MAX_ENQUEUE_BATCH}"
               for s in skips)
    backend.close()


# ---------------------------------------------------------------------------
# B. storage
# ---------------------------------------------------------------------------


def test_sqlite_backend_job_roundtrip_and_event_order():
    backend = open_backend(":memory:")
    jobs, skips = enqueue_jobs(backend, [{"target": "a"}, {"target": "b"}],
                               now=1000.0)
    assert skips == [] and len(jobs) == 2
    stored = backend.list_jobs()
    assert [j["id"] for j in stored] == sorted(j["id"] for j in stored)
    jid = stored[0]["id"]
    backend.update_job(jid, status="done", attempts=1, now=1005.0)
    again = backend.job(jid)
    assert again["status"] == "done" and again["attempts"] == 1
    for i in range(3):
        backend.append_event("job.enqueued", {"i": i}, at=1000.0 + i)
    rows = backend.events_since(0, limit=10)
    # seqs 1-2 are the enqueue_jobs job.enqueued events; the manual loop
    # lands at 3-5 (bring-up fix: the first draft forgot the enqueue
    # events when numbering the expected seqs)
    assert [r["seq"] for r in rows] == [1, 2, 3, 4, 5]
    assert rows[2]["payload"] == {"i": 0}
    assert rows[0]["kind"] == "job.enqueued" and "job_id" in rows[0]["payload"]
    backend.close()


def test_events_since_clamps_to_limit():
    backend = SqliteBackend(":memory:")
    for i in range(5):
        backend.append_event("job.enqueued", {"i": i}, at=float(i))
    rows = backend.events_since(0, limit=2)
    assert len(rows) == 2 and rows[-1]["seq"] == 2
    backend.close()


def test_postgres_backend_fails_loud_with_machine_reason(monkeypatch):
    # force the driver-absent path so the assertion is box-independent
    import sys as _sys
    monkeypatch.setitem(_sys.modules, "psycopg", None)
    with pytest.raises(serve_storage.BackendUnavailable) as ei:
        open_backend("postgres://user:pw@host/db")
    assert ei.value.reason == "postgres_driver_missing"
    assert "PHASE 9" in str(ei.value)


def test_open_backend_routes_sqlite_urls(tmp_path):
    p = tmp_path / "rsx_t82_jobs.db"
    b = open_backend(f"sqlite:///{p.as_posix()}")
    assert isinstance(b, SqliteBackend)
    b.close()
    assert p.exists()


# ---------------------------------------------------------------------------
# C. queue + scheduler
# ---------------------------------------------------------------------------


def test_enqueue_validation_failures_are_annotated():
    backend = SqliteBackend(":memory:")
    jobs, skips = enqueue_jobs(
        backend, [{"target": "ok"}, {"target": ""}, 7, {}], now=1.0)
    assert len(jobs) == 1
    reasons = sorted(s["reason"] for s in skips)
    assert reasons == ["job_not_object", "target_empty", "target_missing"]
    backend.close()


def test_run_job_done_and_failed_transitions():
    backend = SqliteBackend(":memory:")
    (job,), _ = enqueue_jobs(backend, [{"target": "x"}], now=1.0)
    run_job(backend, job, lambda j: {"ok": True, "detail": "fine"}, now=2.0)
    got = backend.job(job["id"])
    assert got["status"] == "done" and got["attempts"] == 1
    kinds = [e["kind"] for e in backend.events_since(0, limit=10)]
    assert "job.started" in kinds and "job.completed" in kinds

    def boom(j):
        raise RuntimeError("nope")

    run_job(backend, job, boom, now=3.0)
    got = backend.job(job["id"])
    assert got["status"] == "failed" and got["attempts"] == 2
    assert "nope" in got["last_error"]
    backend.close()


def test_attempt_cap_exhaustion_is_skipped_not_retried_forever():
    backend = SqliteBackend(":memory:")
    (job,), _ = enqueue_jobs(backend, [{"target": "x"}], now=1.0)

    def always_fail(j):
        raise RuntimeError("still broken")

    for i in range(MAX_ATTEMPTS):
        run_job(backend, job, always_fail, now=10.0 + i)
    assert backend.job(job["id"])["attempts"] == MAX_ATTEMPTS
    ran, stats, skips = drain(backend, runner=always_fail, now=20.0)
    assert stats["ran"] == 0
    assert any(f"attempts_exhausted:{job['id']}" in s["reason"]
               for s in skips)
    backend.close()


def test_drain_order_and_stats_are_deterministic():
    backend = SqliteBackend(":memory:")
    rows = [{"target": "b"}, {"target": "a"}, {"target": "c"}]
    enqueue_jobs(backend, rows, now=5.0)
    seen = []
    ran, stats, skips = drain(
        backend, runner=lambda j: seen.append(j["target"]) or {"ok": True},
        now=6.0)
    assert stats == {"ran": 3, "done": 3, "failed": 0}
    assert sorted(seen) == seen and set(seen) == {"a", "b", "c"}
    backend.close()


def test_cron_tick_no_backfill_then_one_occurrence_per_window():
    from datetime import datetime, timezone
    backend = SqliteBackend(":memory:")
    t0 = int(datetime(2026, 10, 31, 12, 0, tzinfo=timezone.utc).timestamp())
    add_schedule(backend, [{"cron": "*/15 * * * *", "target": "app/"}],
                 now=float(t0))
    # first tick: establishes the cursor, enqueues NOTHING (no backfill)
    stats1 = cron_tick(backend, now=float(t0 + 60))
    assert stats1["enqueued"] == 0
    # 16 minutes later: exactly one 15-minute boundary passed
    stats2 = cron_tick(backend, now=float(t0 + 16 * 60))
    assert stats2["enqueued"] == 1
    jobs = backend.list_jobs()
    assert len(jobs) == 1
    occ = t0 + 15 * 60
    assert jobs[0]["id"] == job_id_for({"target": "app/"}, occurrence=occ)
    # same window re-tick: nothing new
    stats3 = cron_tick(backend, now=float(t0 + 16 * 60 + 30))
    assert stats3["enqueued"] == 0
    backend.close()


def test_cron_occurrence_backfill_is_capped():
    from datetime import datetime, timezone
    backend = SqliteBackend(":memory:")
    t0 = int(datetime(2026, 1, 1, tzinfo=timezone.utc).timestamp())
    add_schedule(backend, [{"cron": "0 0 * * *", "target": "app/"}],
                 now=float(t0))
    cron_tick(backend, now=float(t0 + 60))          # cursor set
    stats = cron_tick(backend, now=float(t0 + 40 * 86400))  # 40 dailies
    assert stats["enqueued"] == stats["capped_at"]
    assert stats["capped_at"] < 40
    assert any("cap_cron_occurrences" in s["reason"]
               for s in stats["skips"])
    backend.close()


def test_add_schedule_validation_errors():
    backend = SqliteBackend(":memory:")
    good, skips = add_schedule(
        backend, [{"cron": "* * * * *", "target": "t"},
                  {"cron": "nope", "target": "t"},
                  {"target": "t"}, {"cron": "* * * * *"}], now=1.0)
    assert len(good) == 1
    reasons = sorted(s["reason"] for s in skips)
    assert reasons == ["cron_invalid", "cron_missing", "target_missing"]
    backend.close()


# ---------------------------------------------------------------------------
# D. events: SSE + webhooks
# ---------------------------------------------------------------------------


def test_sse_replay_frames_from_cursor():
    backend = SqliteBackend(":memory:")
    for i in range(3):
        backend.append_event("job.enqueued", {"i": i}, at=float(i))
    # since=2 -> only seq 3 (payload {"i": 2}) comes back
    frames = sse_replay(backend, since=2, limit=10)
    assert all(f.endswith(b"\n\n") for f in frames)
    assert b'"i": 2' in b"".join(frames)
    assert b'"i": 1' not in b"".join(frames)
    backend.close()


def test_follow_events_emits_new_rows_until_deadline():
    backend = SqliteBackend(":memory:")
    backend.append_event("job.enqueued", {"i": 0}, at=1.0)
    state = {"now": 10.0, "polled": 0}
    appended = []

    def fake_sleep(s):
        state["now"] += s                # injected clock advances on sleep
        if not appended:
            backend.append_event("job.completed", {"i": 1}, at=2.0)
            appended.append(True)

    gen = follow_events(backend, since=0,
                        deadline=state["now"] + 1.0,
                        now_fn=lambda: state["now"],
                        sleep_fn=fake_sleep, poll_s=0.25)
    rows = list(gen)
    assert [r["kind"] for r in rows] == ["job.enqueued", "job.completed"]
    backend.close()


def test_webhook_delivery_uses_injected_sender_only():
    backend = SqliteBackend(":memory:")
    wh_id = backend.register_webhook("http://127.0.0.1/hook")
    seq = backend.append_event("job.enqueued", {"job_id": "j1"}, at=1.0)
    calls = []

    def sender(url, body, headers):
        calls.append((url, body, headers))
        return 200

    stats = deliver_events(backend, sender=sender, now=2.0, sleep_fn=lambda s: None)
    assert stats["delivered"] >= 1 and len(calls) == 1
    url, body, headers = calls[0]
    assert url == "http://127.0.0.1/hook"
    assert headers["Content-Type"] == "application/json"
    parsed = json.loads(body)
    assert parsed["seq"] == seq
    deliveries = backend.deliveries()
    assert all(d["status"] == 200 for d in deliveries)
    # second pass: nothing left to deliver (idempotent)
    stats2 = deliver_events(backend, sender=sender, now=3.0,
                            sleep_fn=lambda s: None)
    assert stats2["attempted"] == 0 and len(calls) == 1
    backend.close()


def test_webhook_retry_backoff_then_terminal_failure():
    backend = SqliteBackend(":memory:")
    backend.register_webhook("http://127.0.0.1/hook")
    backend.append_event("job.enqueued", {"i": 0}, at=1.0)
    sleeps = []

    def bad_sender(url, body, headers):
        raise OSError("refused")

    stats = deliver_events(backend, sender=bad_sender, now=2.0,
                           sleep_fn=sleeps.append)
    assert stats["failed"] >= 1
    assert sleeps == [1, 2]           # bounded backoff between attempts
    deliveries = backend.deliveries()
    assert all(d["attempts"] == MAX_ATTEMPTS for d in deliveries)
    backend.close()


def test_webhook_scheme_validation_and_webhook_kind_exclusion():
    backend = SqliteBackend(":memory:")
    # file:// rejected at registration
    with pytest.raises(serve_storage.WebhookInvalid) as ei:
        backend.register_webhook("file:///etc/passwd")
    assert ei.value.reason == "webhook_url_invalid_scheme"
    wid = backend.register_webhook("http://ok.example/hook")
    backend.append_event("job.enqueued", {"i": 0}, at=1.0)
    # webhook outcome events are NEVER delivered to webhooks (no recursion)
    backend.append_event("webhook.delivered", {"seq": 1}, at=2.0)
    backend.append_event("job.completed", {"i": 2}, at=3.0)
    delivered_seqs = []

    def sender(url, body, headers):
        delivered_seqs.append(json.loads(body)["seq"])
        return 200

    deliver_events(backend, sender=sender, now=4.0, sleep_fn=lambda s: None)
    assert 1 in delivered_seqs and 3 in delivered_seqs
    kinds_delivered = {r["kind"] for r in
                       (backend.events_since(0, limit=100))
                       if r["seq"] in delivered_seqs}
    assert "webhook.delivered" not in kinds_delivered
    assert backend.webhooks()[0]["id"] == wid
    backend.close()


def test_dry_run_never_calls_sender():
    backend = SqliteBackend(":memory:")
    backend.register_webhook("http://ok.example/hook")
    backend.append_event("job.enqueued", {"i": 0}, at=1.0)

    def sender(url, body, headers):
        raise AssertionError("dry run must not send")

    stats = deliver_events(backend, sender=sender, now=2.0,
                           sleep_fn=lambda s: None, dry=True)
    assert stats["dry"] >= 1 and stats["delivered"] == 0
    assert all(d["status"] == "dry" for d in backend.deliveries())
    backend.close()


def test_webhook_registration_cap_is_annotated():
    backend = SqliteBackend(":memory:")
    for i in range(MAX_WEBHOOKS):
        backend.register_webhook(f"http://h.example/{i}")
    with pytest.raises(serve_storage.WebhookInvalid) as ei:
        backend.register_webhook("http://h.example/overflow")
    assert ei.value.reason == f"cap_webhooks_{MAX_WEBHOOKS}"
    backend.close()


# ---------------------------------------------------------------------------
# E. api router
# ---------------------------------------------------------------------------


def _json(body):
    return json.loads(body)


def test_api_health_shape():
    backend = SqliteBackend(":memory:")
    status, headers, body = route(backend, "GET", "/v1/health", {}, b"")
    assert status == 200
    assert headers["Content-Type"] == "application/json"
    assert _json(body)["status"] == "ok"
    assert _json(body)["schema"] == SCHEMA
    backend.close()


def test_api_enqueue_get_and_missing_job():
    backend = SqliteBackend(":memory:")
    status, _, body = route(backend, "POST", "/v1/jobs", {},
                            json.dumps({"target": "app/"}).encode())
    assert status == 201
    job = _json(body)["job"]
    status, _, body = route(backend, "GET", f"/v1/jobs/{job['id']}", {}, b"")
    assert status == 200 and _json(body)["job"]["target"] == "app/"
    status, _, body = route(backend, "GET", "/v1/jobs/job_nope", {}, b"")
    assert status == 404 and _json(body)["error"] == "job_not_found"
    status, _, body = route(backend, "GET", "/v1/jobs", {}, b"")
    assert status == 200 and len(_json(body)["jobs"]) == 1
    backend.close()


def test_api_route_and_method_errors():
    backend = SqliteBackend(":memory:")
    status, _, body = route(backend, "GET", "/v1/nope", {}, b"")
    assert status == 404 and _json(body)["error"] == "route_not_found"
    status, _, _ = route(backend, "DELETE", "/v1/health", {}, b"")
    assert status == 405
    backend.close()


def test_api_bad_json_and_body_cap():
    backend = SqliteBackend(":memory:")
    status, _, body = route(backend, "POST", "/v1/jobs", {}, b"{nope")
    assert status == 400 and _json(body)["error"] == "bad_json"
    status, _, body = route(backend, "POST", "/v1/jobs", {},
                            b'{"target": ""}')
    assert status == 400 and _json(body)["error"] == "target_empty"
    from analysis.serve.model import MAX_BODY_BYTES
    status, _, body = route(backend, "POST", "/v1/jobs", {},
                            b"x" * (MAX_BODY_BYTES + 1))
    assert status == 413 and _json(body)["error"] == "body_too_large"
    backend.close()


def test_api_events_endpoint_is_sse():
    backend = SqliteBackend(":memory:")
    backend.append_event("job.enqueued", {"i": 1}, at=1.0)
    status, headers, body = route(backend, "GET", "/v1/events",
                                  {"since": "0"}, b"")
    assert status == 200
    assert headers["Content-Type"] == "text/event-stream"
    assert body.startswith(b"id: 1\n") and body.endswith(b"\n\n")
    status, _, _ = route(backend, "GET", "/v1/events", {"since": "junk"}, b"")
    assert status == 400
    backend.close()


def test_api_schedules_and_webhooks_routes():
    backend = SqliteBackend(":memory:")
    status, _, body = route(
        backend, "POST", "/v1/schedules", {},
        json.dumps({"cron": "* * * * *", "target": "app/"}).encode())
    assert status == 201 and _json(body)["schedule"]["cron"] == "* * * * *"
    status, _, body = route(
        backend, "POST", "/v1/schedules", {},
        json.dumps({"cron": "nope", "target": "app/"}).encode())
    assert status == 400 and _json(body)["error"] == "cron_invalid"
    status, _, body = route(
        backend, "POST", "/v1/webhooks", {},
        json.dumps({"url": "ftp://x/h"}).encode())
    assert status == 400 and _json(body)["error"] == "webhook_url_invalid_scheme"
    status, _, body = route(
        backend, "POST", "/v1/webhooks", {},
        json.dumps({"url": "https://hooks.example/x"}).encode())
    assert status == 201 and _json(body)["webhook"]["id"].startswith("wh_")
    backend.close()


# ---------------------------------------------------------------------------
# F. pins: axum disclosure + AST offline pin + package surface
# ---------------------------------------------------------------------------


def test_axum_disclosure_is_one_greppable_line():
    # petgraph precedent: task.md names axum -> the repo does NOT adopt it,
    # disclosed where the API lives.
    text = serve_api.__doc__ or ""
    lowered = text.lower()
    assert "axum" in lowered
    assert "not adopted" in lowered


def test_ast_top_level_imports_stay_offline():
    """Module-level imports must never pull the network stack.

    The real webhook sender imports urllib INSIDE its callable (opt-in),
    so the token ban used by scoring/feedback cannot apply here -- this
    AST pin checks the stronger structural property instead: importing
    analysis.serve does zero I/O setup.
    """
    banned = {"urllib", "socket", "requests", "boto3", "http", "os",
              "subprocess"}
    for src in sorted((REPO / "analysis" / "serve").glob("*.py")):
        tree = ast.parse(src.read_text(encoding="utf-8"))
        for node in tree.body:
            if isinstance(node, ast.Import):
                names = {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom):
                names = {(node.module or "").split(".")[0]}
            else:
                continue
            assert not (names & banned), (
                f"{src.name} top-level import {names & banned}")


def test_package_surface_and_no_submodule_shadow():
    import analysis.serve as pkg

    assert pkg.SCHEMA == SCHEMA
    assert callable(pkg.route) and callable(pkg.enqueue_jobs)
    assert pkg.CronExpr is CronExpr
    assert pkg.model is serve_model          # submodule, not shadowed
    assert pkg.storage is serve_storage
    assert pkg.api is serve_api
    for name in ("model", "storage", "queue", "events", "api", "connect"):
        __import__(f"analysis.serve.{name}")


# ---------------------------------------------------------------------------
# G. CLI
# ---------------------------------------------------------------------------


def _run_cli(args, cwd=None):
    return subprocess.run(
        [sys.executable, "-m", "analysis.serve.connect", *args],
        capture_output=True, text=True, cwd=cwd or REPO, timeout=120)


def test_cli_default_run_is_zero_io_with_three_skips(tmp_path):
    out = tmp_path / "rsx_t82_doc.json"
    r = _run_cli(["--as-of", "2026-10-31T00:00:00", "--out", str(out)])
    assert r.returncode == 0, r.stderr
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["schema"] == DOC_SCHEMA
    assert doc["jobs"] == [] and doc["events"] == []
    assert sorted(s["reason"] for s in doc["skips"]) == [
        "not_provided:db", "not_provided:enqueue", "not_provided:webhooks"]
    # byte-identical across runs with the same fixed --as-of
    out2 = tmp_path / "rsx_t82_doc2.json"
    r2 = _run_cli(["--as-of", "2026-10-31T00:00:00", "--out", str(out2)])
    assert r2.returncode == 0
    assert out.read_bytes() == out2.read_bytes()


def test_cli_enqueue_drain_dry_and_events_artifact(tmp_path):
    db = tmp_path / "rsx_t82_jobs.db"
    jobs_file = tmp_path / "rsx_t82_enqueue.json"
    jobs_file.write_text(json.dumps([{"target": "app/"}]), encoding="utf-8")
    out = tmp_path / "rsx_t82_doc.json"
    r = _run_cli(["--db", str(db), "--enqueue", str(jobs_file),
                  "--drain", "--runner", "dry", "--events",
                  "--as-of", "2026-10-31T00:00:00", "--out", str(out)])
    assert r.returncode == 0, r.stderr
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert len(doc["jobs"]) == 1
    assert doc["jobs"][0]["status"] == "done"
    assert doc["stats"]["enqueued"] == 1 and doc["stats"]["ran"] == 1
    kinds = [e["kind"] for e in doc["events"]]
    assert "job.enqueued" in kinds and "job.completed" in kinds
    # events-only readback, byte-stable under the same --as-of
    out2 = tmp_path / "rsx_t82_events.json"
    r2 = _run_cli(["--db", str(db), "--events", "--since", "0",
                   "--as-of", "2026-10-31T00:00:00", "--out", str(out2)])
    assert r2.returncode == 0, r2.stderr
    doc2 = json.loads(out2.read_text(encoding="utf-8"))
    assert doc2["events"] == doc["events"]
    out2b = tmp_path / "rsx_t82_events2.json"
    _run_cli(["--db", str(db), "--events", "--since", "0",
              "--as-of", "2026-10-31T00:00:00", "--out", str(out2b)])
    assert out2.read_bytes() == out2b.read_bytes()


def test_cli_missing_enqueue_file_is_a_skip_not_a_crash(tmp_path):
    db = tmp_path / "rsx_t82_jobs.db"
    out = tmp_path / "rsx_t82_doc.json"
    r = _run_cli(["--db", str(db), "--enqueue",
                  str(tmp_path / "rsx_t82_absent.json"),
                  "--as-of", "2026-10-31T00:00:00", "--out", str(out)])
    assert r.returncode == 0, r.stderr
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert any("enqueue_file_missing" in s["reason"] for s in doc["skips"])


def test_cli_bad_as_of_exits_2(tmp_path):
    out = tmp_path / "rsx_t82_doc.json"
    r = _run_cli(["--as-of", "not-a-date", "--out", str(out)])
    assert r.returncode == 2


def test_cli_add_schedule_and_cron_tick(tmp_path):
    db = tmp_path / "rsx_t82_jobs.db"
    sch = tmp_path / "rsx_t82_sch.json"
    sch.write_text(json.dumps([{"cron": "* * * * *", "target": "app/"}]),
                   encoding="utf-8")
    # first tick: cursor only, no backfill enqueue
    out1 = tmp_path / "rsx_t82_doc1.json"
    r = _run_cli(["--db", str(db), "--add-schedule", str(sch),
                  "--cron-tick", "2026-10-31T12:00:00",
                  "--as-of", "2026-10-31T12:00:00", "--out", str(out1)])
    assert r.returncode == 0, r.stderr
    doc1 = json.loads(out1.read_text(encoding="utf-8"))
    assert doc1["stats"]["cron_enqueued"] == 0
    assert len(doc1["schedules"]) == 1
    # 90s later: exactly the 12:01 boundary has passed -> one occurrence job
    out2 = tmp_path / "rsx_t82_doc2.json"
    r = _run_cli(["--db", str(db), "--add-schedule", str(sch),
                  "--cron-tick", "2026-10-31T12:01:30",
                  "--as-of", "2026-10-31T12:01:30", "--events",
                  "--out", str(out2)])
    assert r.returncode == 0, r.stderr
    doc2 = json.loads(out2.read_text(encoding="utf-8"))
    assert doc2["stats"]["cron_enqueued"] == 1
    assert len(doc2["jobs"]) == 1
    occ = int(datetime(2026, 10, 31, 12, 1, tzinfo=timezone.utc).timestamp())
    assert doc2["jobs"][0]["id"] == job_id_for(
        {"target": "app/"}, occurrence=occ)
    assert "job.cron_enqueued" in [e["kind"] for e in doc2["events"]]


def test_cli_deliver_is_network_optin_against_loopback(tmp_path):
    """--deliver posts to a loopback receiver; without it, nothing sends."""
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    received = []

    class Recv(BaseHTTPRequestHandler):
        def do_POST(self):
            n = int(self.headers.get("Content-Length") or 0)
            received.append(self.rfile.read(n))
            self.send_response(200)
            self.end_headers()

        def log_message(self, *a):
            pass

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Recv)
    port = httpd.server_address[1]
    t = threading.Thread(target=httpd.handle_request, daemon=True)
    t.start()
    try:
        db = tmp_path / "rsx_t82_wh.db"
        wh = tmp_path / "rsx_t82_hooks.json"
        wh.write_text(json.dumps([{"url": f"http://127.0.0.1:{port}/hook"}]),
                      encoding="utf-8")
        jobs_file = tmp_path / "rsx_t82_enqueue.json"
        jobs_file.write_text(json.dumps([{"target": "app/"}]),
                             encoding="utf-8")
        out = tmp_path / "rsx_t82_doc.json"
        # first: same inputs but NO --deliver -> zero posts (dry default)
        _run_cli(["--db", str(db), "--enqueue", str(jobs_file),
                  "--webhooks", str(wh),
                  "--as-of", "2026-10-31T00:00:00", "--out", str(out)])
        assert received == []          # without --deliver: no network
        # then: --deliver -> exactly one POST with the canonical body
        out2 = tmp_path / "rsx_t82_doc2.json"
        r = _run_cli(["--db", str(db), "--webhooks", str(wh), "--deliver",
                      "--as-of", "2026-10-31T00:00:00", "--out", str(out2)])
        assert r.returncode == 0, r.stderr
        t.join(timeout=10)
        assert len(received) == 1
        parsed = json.loads(received[0])
        assert parsed["schema"] == "rsecopsx.serve_event/v1"
        doc = json.loads(out2.read_text(encoding="utf-8"))
        assert any(d["status"] == 200 for d in doc["deliveries"])
    finally:
        httpd.server_close()


def test_cli_serve_live_smoke_on_loopback(tmp_path):
    db = tmp_path / "rsx_t82_serve.db"
    ready = tmp_path / "rsx_t82_ready.txt"
    proc = subprocess.Popen(
        [sys.executable, "-m", "analysis.serve.connect",
         "--db", str(db), "--serve", "--serve-port", "0",
         "--serve-ready-file", str(ready)],
        cwd=REPO, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        deadline = time.time() + 30
        addr = None
        while time.time() < deadline:
            if ready.exists() and ready.read_text(encoding="utf-8").strip():
                addr = ready.read_text(encoding="utf-8").strip()
                break
            if proc.poll() is not None:
                raise AssertionError(
                    f"serve exited early: {proc.stderr.read()[:400]}")
            time.sleep(0.1)
        assert addr, "serve never announced its address"
        base = f"http://{addr}"
        with urllib.request.urlopen(base + "/v1/health",
                                    timeout=10) as resp:
            assert resp.status == 200
            assert json.loads(resp.read())["status"] == "ok"
        req = urllib.request.Request(
            base + "/v1/jobs", method="POST",
            data=json.dumps({"target": "app/"}).encode(),
            headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            assert resp.status == 201
            job = json.loads(resp.read())["job"]
        with urllib.request.urlopen(base + f"/v1/jobs/{job['id']}",
                                    timeout=10) as resp:
            assert resp.status == 200
        # bounded live follow (1s) exercises the server's SSE loop, not
        # just the buffered replay
        with urllib.request.urlopen(base + "/v1/events?since=0&follow=1",
                                    timeout=10) as resp:
            assert "text/event-stream" in resp.headers.get("Content-Type", "")
            assert b"data:" in resp.read()
        # unknown route over the wire
        try:
            urllib.request.urlopen(base + "/v1/nope", timeout=10)
            raise AssertionError("expected 404")
        except urllib.error.HTTPError as he:
            assert he.code == 404
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()


def test_cli_scan_runner_builds_the_real_command(tmp_path):
    from analysis.serve.connect import scan_command
    fix = tmp_path / "rsx_t82_fixture"
    fix.mkdir()
    (fix / "a.py").write_text("x = 1\n", encoding="utf-8")
    outdir = tmp_path / "rsx_t82_out"
    argv = scan_command({"target": str(fix), "out": str(outdir)})
    assert argv[0] == sys.executable
    assert argv[1].endswith("main.py")
    assert argv[2] == str(fix)
    i = argv.index("--output-dir")
    assert argv[i + 1] == str(outdir)
    assert argv[-3:] == ["--quiet", "--no-pdf", "--no-excel"]
