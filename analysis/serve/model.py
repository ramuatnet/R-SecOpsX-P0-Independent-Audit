"""T-8.2 serve mode -- pure contracts: jobs, events, cron, framing.

Everything here is deterministic and side-effect free (injectable clocks
only where time is needed), so the queue, the HTTP router and the CLI
all pin the same vocabularies:

* job status vocabulary ``queued|running|done|failed`` (a job only ever
  moves queued/failed -> running -> done/failed, and only run_job does
  the moving);
* event kinds for the log that feeds both the SSE stream and webhooks;
* deterministic job ids -- content-addressed, and cron occurrences are
  scoped by their scheduled minute so every tick enqueues a NEW id
  (idempotent re-submit of a plain job keeps one id instead);
* 5-field cron in UTC (local timezones are NOT evaluated -- disclosed),
  Vixie dom/dow semantics (both restricted -> EITHER matches), bounded
  to an 8-year search horizon so a never-matching expression raises
  instead of spinning;
* SSE framing and webhook payload bytes are canonical (sort_keys,
  compact separators) so replay and delivery are byte-stable.

Caps live here as named constants; tests assert behaviour at the cap,
never the literal, so raising a bound cannot silently break a gate.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone

SCHEMA = "rsecopsx.serve/v1"
DOC_SCHEMA = "rsecopsx.serve_doc/v1"
EVENT_SCHEMA = "rsecopsx.serve_event/v1"

JOB_STATUSES = ("queued", "running", "done", "failed")
EVENT_KINDS = (
    "job.enqueued",
    "job.started",
    "job.completed",
    "job.failed",
    "job.cron_enqueued",
    "webhook.delivered",
    "webhook.failed",
)

# Event kinds that are delivery bookkeeping -- never sent TO webhooks
# (otherwise a delivery outcome would enqueue its own delivery, forever).
WEBHOOK_EXCLUDED_KINDS = frozenset({"webhook.delivered", "webhook.failed"})

MAX_ENQUEUE_BATCH = 100
MAX_SCHEDULES = 50
MAX_WEBHOOKS = 20
MAX_EVENTS_REPLAY = 1000
MAX_ATTEMPTS = 3
MAX_BODY_BYTES = 1_048_576          # 1 MiB request body cap (untrusted)
MAX_RUN_PER_DRAIN = 50
MAX_CRON_OCCURRENCES = 10           # per tick, per schedule (disclosed)
CRON_HORIZON_DAYS = 8 * 366         # never-matching expr -> ValueError

# 5-field cron: minute hour day-of-month month day-of-week (UTC minutes).
_CRON_FIELDS = (
    ("minute", 0, 59),
    ("hour", 0, 23),
    ("day_of_month", 1, 31),
    ("month", 1, 12),
    ("day_of_week", 0, 7),          # 7 == Sunday, normalised to 0
)


def validate_job(row, tenant=None) -> "tuple[dict, str | None]":
    """Normalise a job row, or explain in one machine-readable string.

    T-9.2: ``tenant`` comes ONLY from the credential (the route layer
    passes the principal's scope) -- a "tenant" key posted in the body
    is ignored, because this function rebuilds the row from known keys
    and stamps the parameter, never a client-supplied field.
    """
    if not isinstance(row, dict):
        return {}, "job_not_object"
    if "target" not in row:
        return {}, "target_missing"
    target = row["target"]
    if not isinstance(target, str):
        return {}, "target_not_a_string"
    if not target.strip():
        return {}, "target_empty"
    out = row.get("out")
    if out is not None and not isinstance(out, str):
        return {}, "out_not_a_string"
    id_row = {"target": target, "out": out}
    if tenant:
        id_row["tenant"] = tenant
    job = {
        "id": job_id_for(id_row),
        "target": target,
        "out": out,
        "status": "queued",
        "attempts": 0,
        "last_error": None,
    }
    if tenant:
        job["tenant"] = tenant          # absent for legacy/flag-off rows
    return job, None


def job_id_for(row, occurrence=None) -> str:
    """Content-addressed id; cron occurrences scope by scheduled minute.

    T-9.2: a NON-EMPTY row["tenant"] joins the canon so two tenants can
    enqueue the same target without colliding on the primary key; rows
    without a tenant (or with "") keep the exact T-8.2 digest -- flag-off
    discipline pinned by a recomputed-legacy-digest test.
    """
    canon_row = {"target": row.get("target"), "out": row.get("out"),
                 "occurrence": occurrence}
    if row.get("tenant"):
        canon_row["tenant"] = row["tenant"]
    canon = json.dumps(canon_row, sort_keys=True, ensure_ascii=True,
                       separators=(",", ":"))
    return "job_" + hashlib.sha256(canon.encode("utf-8")).hexdigest()[:12]


class CronExpr:
    """Parsed 5-field cron. UTC minutes only; local tz NOT evaluated."""

    def __init__(self, expr: str, sets) -> None:
        self.expr = expr
        # sets = (minutes, hours, doms, months, dows) as frozensets
        self.minutes, self.hours, self.doms, self.months, self.dows = sets

    @classmethod
    def parse(cls, expr: str) -> "CronExpr":
        if not isinstance(expr, str):
            raise ValueError(f"cron_not_a_string: {expr!r}")
        parts = expr.split()
        if len(parts) != 5:
            raise ValueError(
                f"cron_field_count: expected 5 fields, got {len(parts)}")
        sets = []
        for raw, (name, lo, hi) in zip(parts, _CRON_FIELDS):
            sets.append(cls._parse_field(raw, name, lo, hi))
        # dow 7 -> 0 (Sunday alias) -- do it after range validation
        minutes, hours, doms, months, dows = sets
        if 7 in dows:
            dows = frozenset((dows - {7}) | {0})
        return cls(expr, (minutes, hours, doms, months, dows))

    @staticmethod
    def _parse_field(raw: str, name: str, lo: int, hi: int) -> frozenset:
        out: "set[int]" = set()
        for piece in raw.split(","):
            if not piece:
                raise ValueError(f"cron_field_invalid:{name}:{raw}")
            step = 1
            if "/" in piece:
                piece, step_s = piece.split("/", 1)
                if not step_s.isdigit() or int(step_s) < 1:
                    raise ValueError(f"cron_field_invalid:{name}:{raw}")
                step = int(step_s)
            if "-" in piece:
                a_s, b_s = piece.split("-", 1)
                if not (a_s.lstrip("+").isdigit() and b_s.lstrip("+").isdigit()):
                    raise ValueError(f"cron_field_invalid:{name}:{raw}")
                a, b = int(a_s), int(b_s)
                if not (lo <= a <= hi and lo <= b <= hi) or a > b:
                    raise ValueError(f"cron_field_range:{name}:{raw}")
                vals = range(a, b + 1)
            elif piece == "*":
                vals = range(lo, hi + 1)
            elif piece.lstrip("+").isdigit():
                v = int(piece)
                if not lo <= v <= hi:
                    raise ValueError(f"cron_field_range:{name}:{raw}")
                vals = (v,)
            else:
                raise ValueError(f"cron_field_invalid:{name}:{raw}")
            # step semantics: start at range base, take every step-th value
            # ("*/15" -> 0,15,30,45; "10-30/10" -> 10,20,30)
            out.update(list(vals)[::step] if step > 1 else vals)
        return frozenset(out)

    @property
    def _dom_any(self) -> bool:
        return self.doms == frozenset(range(1, 32))

    @property
    def _dow_any(self) -> bool:
        return self.dows == frozenset(range(0, 7))

    def _day_matches(self, year: int, month: int, day: int) -> bool:
        if month not in self.months:
            return False
        dt = datetime(year, month, day, tzinfo=timezone.utc)
        cron_dow = (dt.weekday() + 1) % 7        # cron Sun=0 .. Sat=6
        dom_hit = day in self.doms
        dow_hit = cron_dow in self.dows
        if self._dom_any and self._dow_any:
            return True
        if self._dom_any:
            return dow_hit
        if self._dow_any:
            return dom_hit
        # Vixie: both restricted -> EITHER matches
        return dom_hit or dow_hit

    def next_after(self, t: float) -> int:
        """First matching minute boundary strictly after ``t`` (UTC)."""
        lower = int(t)
        start = datetime.fromtimestamp(lower, tz=timezone.utc)
        day = start.date()
        hours = sorted(self.hours)
        minutes = sorted(self.minutes)
        for _ in range(CRON_HORIZON_DAYS + 1):
            if self._day_matches(day.year, day.month, day.day):
                midnight = datetime(day.year, day.month, day.day,
                                    tzinfo=timezone.utc).timestamp()
                for h in hours:
                    base = midnight + h * 3600
                    for m in minutes:
                        ts = int(base + m * 60)
                        if ts > lower:
                            return ts
            day = day + timedelta(days=1)
        raise ValueError(f"cron_never_matches_within_horizon: {self.expr}")


def sse_frame(payload, event=None, id=None) -> bytes:
    """One SSE frame: optional id/event lines, then data lines, blank end."""
    lines: "list[str]" = []
    if id is not None:
        lines.append(f"id: {id}")
    if event is not None:
        lines.append(f"event: {event}")
    for data_line in str(payload).split("\n"):
        lines.append(f"data: {data_line}")
    return ("\n".join(lines) + "\n\n").encode("utf-8")


def webhook_payload(row: dict) -> bytes:
    """Canonical webhook body for one event-log row (byte-stable)."""
    doc = {
        "schema": EVENT_SCHEMA,
        "seq": row.get("seq"),
        "kind": row.get("kind"),
        "at": row.get("at"),
        "payload": row.get("payload"),
    }
    return (json.dumps(doc, sort_keys=True, ensure_ascii=True,
                       separators=(",", ":")) + "\n").encode("utf-8")
