"""T-8.1 watch mode -- event model and debouncing.

Pure, injectable-time core (task.md section 11 PHASE 8): OS watchers
deliver raw file events; this module decides *when* a batch of events is
ready to be re-scanned (quiet-window debounce with a max-wait force
flush so a hot file cannot starve the flush forever) and bounds how many
pending events may accumulate (overflow is an annotated skip, never a
silent drop -- ground rule 4).

Times are epoch seconds (float).  ``debounce_ms`` / ``max_wait_ms`` are
milliseconds because that is the conventional knob unit for watch
delegates; the conversion happens once, here.
"""
from __future__ import annotations
try:
    from analysis.spans import WINDOW_200, WINDOW_80
except ImportError:  # FND-03: standalone, repo root not on path
    import sys as _fnd03_sys
    from pathlib import Path as _fnd03_path
    _fnd03_sys.path.insert(0, str(_fnd03_path(__file__).resolve().parents[2]))
    from analysis.spans import WINDOW_200, WINDOW_80

import time
from typing import Any, Callable

# Artifact schema for the incremental re-scan document (kept in model so
# CLI, incremental core and tests all pin the same string).
SCHEMA = "rsecopsx.watch_scan/v1"

EVENT_KINDS = ("created", "modified", "deleted", "renamed")

DEFAULT_DEBOUNCE_MS = 250
DEFAULT_MAX_WAIT_MS = 2000
DEFAULT_MAX_PENDING = 5000

# Sub-millisecond tolerance on the quiet-window comparison: callers do
# arithmetic like ``1.10 + 0.100`` which is 1-ulp long in IEEE doubles;
# without slack a flush could miss its window by 1e-13 ms and wait one
# extra poll tick.  Never applied to the churn (force) comparison, which
# is intentionally strict.
_QUIET_EPS_MS = 1e-6


class ChangeBuffer:
    """Debounced, bounded pending-event buffer.

    Semantics (each asserted in tests/test_t81_watch.py):

    * per-path coalescing -- a repeat event for a path already pending
      replaces it (latest event wins);
    * ``due(now)`` -- True when the quiet window has elapsed since the
      newest pending event (``now - last_at >= debounce``), or when
      events have churned for longer than ``max_wait`` without ever
      going quiet (anti-starvation force flush: a file written in a hot
      loop would otherwise never satisfy the quiet window);
    * ``flush(now)`` -- returns due events sorted by path, clears them,
      and is idempotent (second flush with nothing pending -> []);
    * overflow beyond ``max_pending`` distinct paths -> annotated skip
      row ``cap_pending_N`` (reason embeds the limit), never silent;
    * fully deterministic: same inputs + same clock -> same outputs.

    ``now_fn`` exists so tests can inject a clock; every method also
    accepts an explicit ``now`` which wins over the clock.
    """

    def __init__(
        self,
        debounce_ms: int = DEFAULT_DEBOUNCE_MS,
        max_wait_ms: int = DEFAULT_MAX_WAIT_MS,
        now_fn: Callable[[], float] = time.time,
        max_pending: int = DEFAULT_MAX_PENDING,
    ) -> None:
        if int(debounce_ms) < 0 or int(max_wait_ms) < 0:
            raise ValueError("debounce_ms and max_wait_ms must be >= 0")
        if int(max_pending) < 1:
            raise ValueError("max_pending must be >= 1")
        self.debounce_ms = int(debounce_ms)
        self.max_wait_ms = int(max_wait_ms)
        self.max_pending = int(max_pending)
        self.now_fn = now_fn
        # path -> latest event dict; insertion order = first-seen order.
        self._pending: "dict[str, dict[str, Any]]" = {}
        # Oldest event `at` seen since the last real flush.  Tracked
        # OUTSIDE the coalescing map on purpose: a hot file collapses to
        # one pending entry, and the force-flush clock must keep running
        # from the first arrival even as that entry is replaced.
        self._first_at: float | None = None
        self._skips: "list[dict[str, Any]]" = []

    # -- introspection -------------------------------------------------
    def pending(self) -> "list[dict[str, Any]]":
        return list(self._pending.values())

    def skips(self) -> "list[dict[str, Any]]":
        return list(self._skips)

    def __len__(self) -> int:
        return len(self._pending)

    # -- ingest --------------------------------------------------------
    def add(self, event: "dict[str, Any]") -> None:
        """Enqueue one event; coalesce repeats for the same path.

        Events without a path (or that are not dicts, or with an unknown
        kind) are recorded as annotated skips -- annotating, never
        deleting silently.
        """
        if not isinstance(event, dict):
            self._skips.append({
                "reason": "event_not_object",
                "event": repr(event)[:WINDOW_200],
            })
            return
        path = event.get("path")
        if not isinstance(path, str) or not path:
            self._skips.append({
                "reason": "event_missing_path",
                "event": repr(event)[:WINDOW_200],
            })
            return
        kind = event.get("kind")
        if kind not in EVENT_KINDS:
            self._skips.append({
                "reason": "event_kind_unknown",
                "path": path,
                "kind": repr(kind)[:WINDOW_80],
            })
            return
        at = event.get("at")
        if not isinstance(at, (int, float)):
            at = self.now_fn()
        norm = dict(event)
        norm["at"] = float(at)
        if path in self._pending:
            # Coalesce: latest event for this path wins outright (its
            # `at` refreshes the quiet-window clock for this path).
            # `first_at` only ever moves backwards, never resets.
            self._pending[path] = norm
            if self._first_at is None or norm["at"] < self._first_at:
                self._first_at = norm["at"]
            return
        if len(self._pending) >= self.max_pending:
            # Disclosed overflow: the limit is part of the reason string
            # so a consumer can see which cap was hit.  Skipped events
            # do not move the force-flush clock -- they were never
            # accepted.
            self._skips.append({
                "reason": f"cap_pending_{self.max_pending}",
                "path": path,
                "kind": kind,
            })
            return
        if self._first_at is None or norm["at"] < self._first_at:
            self._first_at = norm["at"]
        self._pending[path] = norm

    # -- scheduling ----------------------------------------------------
    def due(self, now: float | None = None) -> bool:
        """True when the pending set is ready to flush."""
        if not self._pending:
            return False
        now = self.now_fn() if now is None else float(now)
        last_at = max(float(e["at"]) for e in self._pending.values())
        # Quiet window: nothing new for debounce_ms.
        if (now - last_at) * 1000.0 + _QUIET_EPS_MS >= self.debounce_ms:
            return True
        # Force flush: events have churned for longer than max_wait
        # without a quiet gap (hot-file anti-starvation).  Strict: at
        # exactly max_wait the buffer is not yet forced.
        if self._first_at is not None:
            if (last_at - self._first_at) * 1000.0 > self.max_wait_ms:
                return True
        return False

    def flush(self, now: float | None = None) -> "list[dict[str, Any]]":
        """Return due events sorted by path and clear them.

        Idempotent: if nothing is due (or nothing pending), returns [].
        """
        now = self.now_fn() if now is None else float(now)
        if not self._pending:
            return []
        if not self.due(now):
            return []
        events = sorted(self._pending.values(),
                        key=lambda e: str(e.get("path") or ""))
        self._pending.clear()
        self._first_at = None
        return events
