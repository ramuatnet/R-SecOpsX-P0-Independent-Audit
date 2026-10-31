"""T-8.2 serve storage -- SQLite backend + the SQLite->Postgres seam.

Stdlib sqlite3 only (offline no-required-deps).  The backend is
thread-safe (ThreadingHTTPServer + the background tick thread share one
connection; an RLock serialises every statement).  Postgres is PHASE 9
(task.md): open_backend("postgres://...") fails LOUD with the machine
reason ``postgres_driver_missing`` instead of silently degrading -- a
deployment that meant to point at Postgres must never wake up on a
throwaway SQLite file.

Webhook URL validation is MANUAL string parsing on purpose: the real
sender may import urllib lazily, but storage must never pull the
network stack at import time, and scheme/netloc checks are three
string ops.  file:// and friends are rejected at REGISTRATION, so a
bad hook can never sit in the table waiting for a delivery attempt.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading

from .model import MAX_WEBHOOKS


class BackendUnavailable(Exception):
    """Requested backend cannot be opened; .reason is machine-readable."""

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason


class WebhookInvalid(Exception):
    """Webhook registration rejected; .reason is machine-readable."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _webhook_scheme_ok(url) -> bool:
    """http/https with a non-empty netloc -- no urllib, pure strings."""
    if not isinstance(url, str) or "://" not in url:
        return False
    scheme, rest = url.split("://", 1)
    if scheme not in ("http", "https"):
        return False
    netloc = rest.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    return bool(netloc)


def _coerce_delivery_status(value):
    """SQLite TEXT round-trip: numeric strings back to int, else as-is."""
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return value
    return value


class SqliteBackend:
    """ jobs/schedules/events/webhooks/deliveries in one SQLite file. """

    def __init__(self, path: str) -> None:
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock, self._conn:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS jobs (
                    id TEXT PRIMARY KEY, target TEXT, out TEXT,
                    status TEXT, attempts INTEGER, last_error TEXT,
                    created_at REAL, updated_at REAL);
                CREATE TABLE IF NOT EXISTS schedules (
                    id TEXT PRIMARY KEY, cron TEXT, target TEXT, out TEXT,
                    created_at REAL, last_tick REAL);
                CREATE TABLE IF NOT EXISTS events (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    kind TEXT, payload TEXT, at REAL);
                CREATE TABLE IF NOT EXISTS webhooks (
                    id TEXT PRIMARY KEY, url TEXT, active INTEGER);
                CREATE TABLE IF NOT EXISTS deliveries (
                    event_seq INTEGER, webhook_id TEXT,
                    attempts INTEGER, status TEXT, at REAL,
                    PRIMARY KEY (event_seq, webhook_id));
                """)

    # -- jobs ------------------------------------------------------------
    def enqueue_job(self, job: dict, now: float) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO jobs (id, target, out, status, attempts,"
                " last_error, created_at, updated_at)"
                " VALUES (?,?,?,?,?,?,?,?)",
                (job["id"], job["target"], job["out"], job["status"],
                 job["attempts"], job["last_error"], now, now))

    def job(self, job_id: str):
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
        return dict(row) if row is not None else None

    def list_jobs(self, status=None) -> "list[dict]":
        with self._lock:
            if status is None:
                rows = self._conn.execute(
                    "SELECT * FROM jobs ORDER BY id").fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT * FROM jobs WHERE status = ? ORDER BY id",
                    (status,)).fetchall()
        return [dict(r) for r in rows]

    def update_job(self, job_id, *, status=None, attempts=None,
                   last_error=None, now=0.0) -> None:
        sets, params = [], []
        if status is not None:
            sets.append("status = ?")
            params.append(status)
        if attempts is not None:
            sets.append("attempts = ?")
            params.append(attempts)
        if last_error is not None:
            sets.append("last_error = ?")
            params.append(last_error)
        sets.append("updated_at = ?")
        params.append(now)
        params.append(job_id)
        with self._lock, self._conn:
            self._conn.execute(
                f"UPDATE jobs SET {', '.join(sets)} WHERE id = ?", params)

    # -- events ----------------------------------------------------------
    def append_event(self, kind: str, payload, at: float) -> int:
        with self._lock, self._conn:
            cur = self._conn.execute(
                "INSERT INTO events (kind, payload, at) VALUES (?,?,?)",
                (kind, json.dumps(payload, sort_keys=True,
                                  ensure_ascii=True, separators=(",", ":")),
                 at))
            return int(cur.lastrowid)

    def events_since(self, since: int, limit: int = 1000) -> "list[dict]":
        with self._lock:
            rows = self._conn.execute(
                "SELECT seq, kind, payload, at FROM events"
                " WHERE seq > ? ORDER BY seq LIMIT ?",
                (int(since), int(limit))).fetchall()
        out = []
        for r in rows:
            out.append({"seq": r["seq"], "kind": r["kind"],
                        "payload": json.loads(r["payload"]), "at": r["at"]})
        return out

    # -- schedules -------------------------------------------------------
    def insert_schedule(self, sched: dict, now: float) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO schedules (id, cron, target, out,"
                " created_at, last_tick) VALUES (?,?,?,?,?,?)",
                (sched["id"], sched["cron"], sched["target"], sched["out"],
                 now, None))

    def schedules(self) -> "list[dict]":
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM schedules ORDER BY id").fetchall()
        return [dict(r) for r in rows]

    def set_last_tick(self, schedule_id: str, floor: int) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE schedules SET last_tick = ? WHERE id = ?",
                (float(floor), schedule_id))

    # -- webhooks + deliveries -------------------------------------------
    def register_webhook(self, url: str) -> str:
        if not _webhook_scheme_ok(url):
            raise WebhookInvalid("webhook_url_invalid_scheme")
        wh_id = "wh_" + hashlib.sha256(
            url.encode("utf-8")).hexdigest()[:12]
        with self._lock, self._conn:
            existing = self._conn.execute(
                "SELECT id FROM webhooks WHERE id = ?", (wh_id,)).fetchone()
            if existing is None:
                count = self._conn.execute(
                    "SELECT COUNT(*) AS n FROM webhooks").fetchone()["n"]
                if count >= MAX_WEBHOOKS:
                    raise WebhookInvalid(f"cap_webhooks_{MAX_WEBHOOKS}")
                self._conn.execute(
                    "INSERT INTO webhooks (id, url, active) VALUES (?,?,1)",
                    (wh_id, url))
        return wh_id

    def webhooks(self) -> "list[dict]":
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM webhooks WHERE active = 1 ORDER BY id"
            ).fetchall()
        return [dict(r) for r in rows]

    def delivery_recorded(self, event_seq: int, webhook_id: str):
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM deliveries WHERE event_seq = ?"
                " AND webhook_id = ?", (event_seq, webhook_id)).fetchone()
        if row is None:
            return None
        out = dict(row)
        out["status"] = _coerce_delivery_status(out["status"])
        return out

    def upsert_delivery(self, event_seq: int, webhook_id: str,
                        attempts: int, status, at: float) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO deliveries (event_seq, webhook_id, attempts,"
                " status, at) VALUES (?,?,?,?,?)"
                " ON CONFLICT(event_seq, webhook_id) DO UPDATE SET"
                " attempts=excluded.attempts, status=excluded.status,"
                " at=excluded.at",
                (event_seq, webhook_id, attempts, str(status), at))

    def deliveries(self) -> "list[dict]":
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM deliveries"
                " ORDER BY event_seq, webhook_id").fetchall()
        out = []
        for r in rows:
            row = dict(r)
            row["status"] = _coerce_delivery_status(row["status"])
            out.append(row)
        return out

    def close(self) -> None:
        with self._lock:
            self._conn.close()


def open_backend(url: str):
    """Route a DB URL to a backend; postgres fails LOUD (PHASE 9)."""
    if isinstance(url, str) and (
            url == ":memory:" or url.startswith("sqlite:")):
        path = url
        if path.startswith("sqlite:///"):
            path = path[len("sqlite:///"):]
        elif path.startswith("sqlite:"):
            path = path[len("sqlite:"):]
        return SqliteBackend(path or ":memory:")
    if isinstance(url, str) and (
            url.startswith("postgres://") or url.startswith("postgresql://")):
        try:
            import psycopg  # noqa: F401  (lazy: PHASE 9 wiring)
        except ImportError:
            raise BackendUnavailable(
                "postgres_driver_missing",
                "postgres backend requires psycopg, wired in PHASE 9"
                " (task.md); use sqlite:// or a bare path meanwhile")
        raise BackendUnavailable(
            "postgres_not_implemented",
            "postgres backend lands in PHASE 9 (task.md)")
    return SqliteBackend(url)
