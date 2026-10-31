"""T-8.2 serve mode -- jobs, schedules, SSE/webhook events, HTTP API.

Public surface is the contract tests pin: vocabularies (SCHEMA,
JOB_STATUSES, EVENT_KINDS), caps (MAX_ENQUEUE_BATCH, MAX_WEBHOOKS,
MAX_ATTEMPTS), the model primitives (validate_job, job_id_for,
CronExpr, sse_frame, webhook_payload), queue verbs (enqueue_jobs,
run_job, drain, add_schedule, cron_tick), event verbs (deliver_events)
and the pure router (route).

Submodules are imported AS submodules (``from . import model`` ...) so
``analysis.serve.model`` stays reachable; a plain
``from .model import *`` would shadow the name and break
``pkg.model is model``.
"""
from . import api, connect, events, model, queue, storage  # noqa: F401
from .api import route, serve
from .events import RealSender, deliver_events, follow_events, sse_replay
from .model import (DOC_SCHEMA, EVENT_KINDS, JOB_STATUSES, MAX_ATTEMPTS,
                    MAX_BODY_BYTES, MAX_ENQUEUE_BATCH, MAX_EVENTS_REPLAY,
                    MAX_SCHEDULES, MAX_WEBHOOKS, SCHEMA, CronExpr,
                    job_id_for, sse_frame, validate_job, webhook_payload)
from .queue import (add_schedule, cron_tick, drain, enqueue_jobs, run_job)
from .storage import BackendUnavailable, SqliteBackend, WebhookInvalid, open_backend

__all__ = [
    "DOC_SCHEMA", "EVENT_KINDS", "JOB_STATUSES", "MAX_ATTEMPTS",
    "MAX_ENQUEUE_BATCH", "MAX_WEBHOOKS", "SCHEMA", "CronExpr",
    "add_schedule", "cron_tick", "deliver_events", "drain",
    "enqueue_jobs", "job_id_for", "route", "run_job", "sse_frame",
    "validate_job", "webhook_payload",
]
