"""T-8.2 serve API -- pure router: (backend, method, path, query, body)
in, (status, headers, bytes) out.  No sockets here; serve() in connect
wraps it in stdlib http.server.

axum is NOT adopted: task.md names an axum/rsecopsx-server binary, but
the offline no-required-deps invariant and in-suite testability outrank
a web framework (petgraph precedent) -- this router keeps the HTTP
surface so a later rsecopsx-server swap stays shape-compatible.

Route table (all under /v1):

    GET    /v1/health          200 {status,schema}
    POST   /v1/jobs            201 {job} | 400 (validation)
    GET    /v1/jobs[?status=]  200 {jobs} | 400 bad_status
    GET    /v1/jobs/{id}       200 {job} | 404 job_not_found
    POST   /v1/schedules       201 {schedule} | 400 cron_invalid...
    POST   /v1/webhooks        201 {webhook} | 400 url/scheme/cap
    GET    /v1/events?since=   200 text/event-stream | 400 bad_since

Unknown path -> 404 route_not_found; known path, wrong method -> 405.
Every JSON body is canonical (sort_keys, ensure_ascii) so artifacts
and wire bytes agree.  Request bodies are capped at MAX_BODY_BYTES
before parsing (413 body_too_large) -- untrusted input, bounded.

Auth (T-9.1): serve() takes an optional AuthConfig; with auth=None the
API is open (flag-off, t82 behaviour byte-identical).  With auth set
every request is gated by required_role/verify BEFORE the 413 cap and
the router (headers only, nothing read off the wire); /v1/health stays
open.  Non-loopback bind WITHOUT auth refuses to start
(ValueError auth_required_for_non_loopback).  An optional audit_fn
receives one fixed-shape audit_entry per request (allowed and denied);
exceptions from an audit sink are not swallowed by the auth layer.

Tenancy (T-9.2): route() gains an optional ``tenant`` kwarg threaded
from the verified principal's "tenant" key (see auth.py) to every
storage call.  A scoped principal only ever sees its own jobs, events,
schedules and webhooks; a cross-tenant job id is a 404 (no existence
oracle), and client-posted "tenant" body keys are dropped by
validate_job.  tenant=None (no auth, or an unscoped credential) keeps
the single-tenant view -- flag-off behaviour unchanged.
"""
from __future__ import annotations

import json
import time

from .auth import ROLE_RANK, audit_entry, required_role, verify
from .model import (JOB_STATUSES, MAX_BODY_BYTES, SCHEMA, sse_frame)
from .queue import add_schedule, enqueue_jobs
from .events import sse_replay
from .storage import WebhookInvalid

_JSON = {"Content-Type": "application/json"}
_SSE = {"Content-Type": "text/event-stream"}

_ROUTES = {
    ("GET", "/v1/health"),
    ("GET", "/v1/jobs"),
    ("POST", "/v1/jobs"),
    ("GET", "/v1/schedules"),
    ("POST", "/v1/schedules"),
    ("GET", "/v1/webhooks"),
    ("POST", "/v1/webhooks"),
    ("GET", "/v1/events"),
}


def _ok(status: int, doc) -> "tuple[int, dict, bytes]":
    return (status, _JSON,
            (json.dumps(doc, sort_keys=True, ensure_ascii=True) + "\n"
             ).encode("utf-8"))


def _err(status: int, error: str, **extra):
    doc = {"error": error}
    doc.update(extra)
    return _ok(status, doc)


def route(backend, method: str, path: str, query: dict, body: bytes,
          now_fn=time.time, tenant=None) -> "tuple[int, dict, bytes]":
    """Dispatch one request; pure -- no sockets, no clock unless given.

    ``tenant`` (T-9.2): None = unscoped (legacy/operator); a string
    scopes every storage call in this dispatch to that tenant.
    """
    if len(body) > MAX_BODY_BYTES:
        return _err(413, "body_too_large", cap=MAX_BODY_BYTES)
    method = method.upper()

    if path == "/v1/health":
        if method != "GET":
            return _err(405, "method_not_allowed")
        return _ok(200, {"status": "ok", "schema": SCHEMA})

    if path == "/v1/jobs":
        if method == "POST":
            try:
                row = json.loads(body)
            except (ValueError, UnicodeDecodeError):
                return _err(400, "bad_json")
            jobs, skips = enqueue_jobs(backend, [row], now=now_fn(),
                                       tenant=tenant)
            if jobs:
                return _ok(201, {"job": jobs[0]})
            reason = skips[0]["reason"] if skips else "job_rejected"
            return _err(400, reason)
        if method == "GET":
            status_f = query.get("status")
            if status_f is not None and status_f not in JOB_STATUSES:
                return _err(400, "bad_status", allowed=list(JOB_STATUSES))
            return _ok(200, {"jobs": backend.list_jobs(status=status_f,
                                                       tenant=tenant)})
        return _err(405, "method_not_allowed")

    if path.startswith("/v1/jobs/"):
        if method != "GET":
            return _err(405, "method_not_allowed")
        job = backend.job(path[len("/v1/jobs/"):], tenant=tenant)
        if job is None:
            # cross-tenant id lands here too -- a 404, never a 403, so
            # a scoped caller cannot probe other tenants' job ids
            return _err(404, "job_not_found")
        return _ok(200, {"job": job})

    if path == "/v1/schedules":
        if method == "POST":
            try:
                row = json.loads(body)
            except (ValueError, UnicodeDecodeError):
                return _err(400, "bad_json")
            good, skips = add_schedule(backend, [row], now=now_fn(),
                                       tenant=tenant)
            if good:
                return _ok(201, {"schedule": good[0]})
            reason = skips[0]["reason"] if skips else "schedule_rejected"
            detail = skips[0].get("detail") if skips else None
            if detail:
                return _err(400, reason, detail=detail)
            return _err(400, reason)
        if method == "GET":
            return _ok(200, {"schedules": backend.schedules(tenant=tenant)})
        return _err(405, "method_not_allowed")

    if path == "/v1/webhooks":
        if method == "POST":
            try:
                row = json.loads(body)
            except (ValueError, UnicodeDecodeError):
                return _err(400, "bad_json")
            url = row.get("url") if isinstance(row, dict) else None
            if not url:
                return _err(400, "url_missing")
            try:
                wh_id = backend.register_webhook(url, tenant=tenant)
            except WebhookInvalid as exc:
                return _err(400, exc.reason)
            return _ok(201, {"webhook": {"id": wh_id, "url": url}})
        if method == "GET":
            return _ok(200, {"webhooks": backend.webhooks(tenant=tenant)})
        return _err(405, "method_not_allowed")

    if path == "/v1/events":
        if method != "GET":
            return _err(405, "method_not_allowed")
        raw_since = query.get("since", "0")
        try:
            since = int(raw_since)
        except (TypeError, ValueError):
            return _err(400, "bad_since")
        frames = sse_replay(backend, since=since, tenant=tenant)
        return (200, _SSE, b"".join(frames))

    if (method, path) not in _ROUTES and path in {p for _, p in _ROUTES}:
        return _err(405, "method_not_allowed")
    return _err(404, "route_not_found")


def serve(backend, host="127.0.0.1", port=0, ready_file=None, runner=None,
          tick_s=1.0, follow_cap_s=10, auth=None, audit_fn=None) -> None:
    """Blocking loopback server: route + background cron/drain ticker.

    Binds 127.0.0.1 by default (loopback only).  ``auth=None`` keeps the
    API open -- flag-off behaviour, byte-identical to T-8.2 -- but a
    non-loopback host with no auth refuses to start (guard below): the
    RBAC hole the old docstring warned about is closed, not papered over.
    ``runner=None`` means DRY: the ticker marks jobs done without
    spawning scans -- --runner scan is the explicit opt-in and lives in
    connect.scan_runner.  ``audit_fn`` receives one audit_entry per
    request (allowed and denied; actor/role null when anonymous or
    health); sink exceptions are not swallowed here.
    """
    if auth is None and host not in ("127.0.0.1", "localhost", "::1"):
        # before bind: a refused start is cheaper than an open door
        raise ValueError("auth_required_for_non_loopback")

    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from urllib.parse import parse_qs
    import time as _time

    from .events import _row_frame, follow_events
    from .queue import cron_tick, drain
    from .model import MAX_BODY_BYTES

    def _dry_runner(job):
        return {"ok": True, "detail": "dry"}

    active_runner = runner or _dry_runner

    class _Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"   # close-delimited SSE streaming
        daemon_threads = True

        def log_message(self, *args):   # silent: no stdout spam
            pass

        def _read_body(self) -> bytes:
            n = int(self.headers.get("Content-Length") or 0)
            if n <= 0:
                return b""
            return self.rfile.read(n)

        def _send(self, status, headers, payload: bytes) -> None:
            self.send_response(status)
            for k, v in headers.items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def _handle(self, method: str) -> None:
            parts = self.path.split("?", 1)
            path = parts[0]
            query = {k: v[0] for k, v in parse_qs(parts[1]).items()} \
                if len(parts) == 2 else {}

            def _audit(status, decision, actor, role, reason):
                if audit_fn is not None:
                    audit_fn(audit_entry(
                        method=method, path=path, status=status,
                        decision=decision, actor=actor, role=role,
                        reason=reason, ts=_time.time()))

            # AUTH GATE first: headers only, health is open, nothing
            # else is looked at until the caller is entitled to it
            actor = role = None
            tenant_scope = None     # T-9.2: None = unscoped view
            need = required_role(method, path)
            if auth is not None and need is not None:
                principal, why = verify(auth,
                                        self.headers.get("Authorization"),
                                        now=_time.time())
                if principal is None:
                    _audit(401, "denied", None, None, why)
                    self._send(*_err(401, "unauthorized", reason=why))
                    self.close_connection = True
                    return
                actor, role = principal["actor"], principal["role"]
                if ROLE_RANK[role] < ROLE_RANK[need]:
                    _audit(403, "denied", actor, role, "insufficient_role")
                    self._send(*_err(403, "forbidden", required=need))
                    self.close_connection = True
                    return
                tenant_scope = principal.get("tenant")  # None = operator

            declared = int(self.headers.get("Content-Length") or 0)
            if declared > MAX_BODY_BYTES:
                # bounded: reject BEFORE reading the untrusted body
                _audit(413, "allowed", actor, role, None)
                self._send(*_err(413, "body_too_large",
                                 cap=MAX_BODY_BYTES))
                self.close_connection = True
                return
            body = self._read_body() if method == "POST" else b""
            follow = 0
            if path == "/v1/events" and method == "GET":
                try:
                    follow = max(0, min(int(query.get("follow", "0")),
                                        int(follow_cap_s)))
                except ValueError:
                    follow = 0
                if follow > 0:
                    _audit(200, "allowed", actor, role, None)
                    self._stream_events(query, tenant_scope)
                    return
            status, headers, payload = route(
                backend, method, path, query, body, now_fn=_time.time,
                tenant=tenant_scope)
            _audit(status, "allowed", actor, role, None)
            self._send(status, headers, payload)

        def _stream_events(self, query: dict, tenant=None) -> None:
            try:
                since = int(query.get("since", "0"))
            except ValueError:
                self._send(*_err(400, "bad_since"))
                return
            follow = max(0, min(int(query.get("follow", "0")),
                                int(follow_cap_s)))
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()          # no Content-Length: close-delimited
            cursor = since
            for row in backend.events_since(since, limit=1000,
                                            tenant=tenant):
                self.wfile.write(_row_frame(row))
                self.wfile.flush()
                cursor = row["seq"]     # follow starts AFTER the replay
            deadline = _time.time() + follow
            for row in follow_events(backend, since=cursor,
                                     deadline=deadline,
                                     now_fn=_time.time,
                                     sleep_fn=_time.sleep,
                                     tenant=tenant):
                self.wfile.write(_row_frame(row))
                self.wfile.flush()

        def do_GET(self):
            self._handle("GET")

        def do_POST(self):
            self._handle("POST")

        def do_DELETE(self):
            self._handle("DELETE")

    server = ThreadingHTTPServer((host, port), _Handler)
    if ready_file:
        # announce AFTER bind (port is real once port=0 resolved),
        # BEFORE the loops, so a caller can poll for readiness
        with open(ready_file, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(f"{server.server_address[0]}:{server.server_address[1]}\n")

    def _tick_loop():
        while True:
            try:
                cron_tick(backend, now=_time.time())
                drain(backend, runner=active_runner, now=_time.time())
            except Exception:  # noqa: BLE001 -- ticker must survive
                pass
            _time.sleep(tick_s)

    import threading
    threading.Thread(target=_tick_loop, daemon=True).start()
    try:
        server.serve_forever()
    finally:
        server.server_close()
