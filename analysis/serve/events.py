"""T-8.2 serve events -- SSE replay/follow + webhook delivery.

The event log is the single spine: SSE subscribers and webhook
receivers both read the same rows, so what a browser saw and what a
hook got can never diverge.

Delivery discipline:

* sender is INJECTED -- deliver_events(sender=None, dry=False) raises
  instead of reaching for the network; the real sender lives in
  RealSender and imports urllib INSIDE the callable (the AST offline
  pin requires zero network imports at module level);
* dry-run is the DEFAULT: with no --deliver the CLI records status=dry
  rows and never posts; a later real pass REPLACES dry rows (they are
  placeholders, not receipts), while real receipts are terminal -- the
  second pass over an already-delivered log attempts nothing;
* webhook.delivered / webhook.failed are bookkeeping: they are never
  delivered TO webhooks (that would recurse), and outcome events
  appended during a pass are snapshotted out of the iteration;
* retry backoff is bounded: attempts capped at MAX_ATTEMPTS, sleeps
  1s then 2s between attempts -- a persistently failing hook gets three
  tries and a terminal status, never an unbounded loop.
"""
from __future__ import annotations

import json

from .model import (MAX_ATTEMPTS, MAX_EVENTS_REPLAY, WEBHOOK_EXCLUDED_KINDS,
                    sse_frame, webhook_payload)


def _row_frame(row: dict) -> bytes:
    body = json.dumps({"seq": row["seq"], "kind": row["kind"],
                       "at": row["at"], "payload": row["payload"]},
                      sort_keys=True, ensure_ascii=True)
    return sse_frame(body, event=row["kind"], id=row["seq"])


def sse_replay(backend, since: int, limit: int = MAX_EVENTS_REPLAY,
               tenant=None):
    """Frames for rows after ``since`` (exclusive cursor), oldest first.

    ``tenant`` (T-9.2): None = every tenant (legacy/operator view);
    a string filters the log to that tenant's rows only.
    """
    return [_row_frame(r) for r in backend.events_since(
        since, limit=limit, tenant=tenant)]


def follow_events(backend, since: int, deadline: float, now_fn, sleep_fn,
                  poll_s: float = 0.25, tenant=None):
    """Yield new rows until the wall-clock deadline (inclusive poll)."""
    cursor = int(since)
    while True:
        rows = backend.events_since(cursor, limit=MAX_EVENTS_REPLAY,
                                    tenant=tenant)
        for row in rows:
            cursor = row["seq"]
            yield row
        if now_fn() >= deadline:
            return
        sleep_fn(poll_s)


class RealSender:
    """Opt-in HTTP POST; urllib is imported HERE, never at module level."""

    def __call__(self, url: str, body: bytes, headers: dict) -> int:
        import urllib.error
        import urllib.request
        req = urllib.request.Request(url, data=body, headers=headers,
                                     method="POST")
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return int(resp.status)
        except urllib.error.HTTPError as exc:  # non-2xx: surface the code
            return int(exc.code)
        except urllib.error.URLError as exc:   # unreachable: raise loudly
            raise OSError(f"webhook_unreachable: {exc.reason}") from exc


def deliver_events(backend, sender, now, sleep_fn, dry=False,
                   max_attempts=MAX_ATTEMPTS) -> dict:
    """Deliver non-bookkeeping events to every registered webhook."""
    if sender is None and not dry:
        raise ValueError("deliver_events requires a sender or dry=True")
    stats = {"attempted": 0, "delivered": 0, "failed": 0, "dry": 0}
    hooks = backend.webhooks()
    if not hooks:
        return stats
    # snapshot: outcome events appended below must not feed this pass
    events = [e for e in backend.events_since(0, limit=MAX_EVENTS_REPLAY)
              if e["kind"] not in WEBHOOK_EXCLUDED_KINDS]
    for ev in events:
        for hook in hooks:
            # T-9.2: exact tenant match -- a hook only ever sees its own
            # tenant's events (legacy "" == "" keeps single-tenant as-is)
            if (hook.get("tenant") or "") != (ev.get("tenant") or ""):
                continue
            prior = backend.delivery_recorded(ev["seq"], hook["id"])
            if prior is not None and prior.get("status") != "dry":
                continue  # real receipt is terminal; dry is replaceable
            body = webhook_payload(ev)
            headers = {"Content-Type": "application/json"}
            if dry:
                backend.upsert_delivery(ev["seq"], hook["id"],
                                        attempts=1, status="dry", at=now)
                stats["dry"] += 1
                continue
            stats["attempted"] += 1
            code = None
            for attempt in range(1, max_attempts + 1):
                try:
                    code = int(sender(hook["url"], body, headers))
                    if 200 <= code < 300:
                        break
                except Exception:  # noqa: BLE001 -- retried, then terminal
                    code = None
                if attempt < max_attempts:
                    sleep_fn(attempt)          # bounded backoff: 1s, 2s
            if code is not None and 200 <= code < 300:
                backend.upsert_delivery(ev["seq"], hook["id"],
                                        attempts=attempt, status=code, at=now)
                backend.append_event(
                    "webhook.delivered",
                    {"seq": ev["seq"], "webhook_id": hook["id"],
                     "status": code}, at=now,
                    tenant=ev.get("tenant") or "")
                stats["delivered"] += 1
            else:
                backend.upsert_delivery(ev["seq"], hook["id"],
                                        attempts=max_attempts, status=-1,
                                        at=now)
                backend.append_event(
                    "webhook.failed",
                    {"seq": ev["seq"], "webhook_id": hook["id"],
                     "status": code}, at=now,
                    tenant=ev.get("tenant") or "")
                stats["failed"] += 1
    return stats
