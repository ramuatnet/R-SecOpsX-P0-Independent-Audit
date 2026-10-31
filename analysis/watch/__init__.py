"""T-8.1 watch mode: OS-native watchers, debounce, incremental re-scan.

Public surface (pinned by tests/test_t81_watch.py):

  * :class:`IncrementalScanner` -- prime once (the ONE tree walk), then
    ``apply(events)`` re-scans only the changed paths; ``document()``
    is the artifact (schema ``rsecopsx.watch_scan/v1``).
  * :func:`prime_and_watch` -- the one-shot convenience: prime, apply a
    batch of events, return the document.
  * :class:`ChangeBuffer` -- the debounced, bounded pending-event
    buffer (quiet window + max-wait force flush).
  * :func:`open_watcher` -- best native watcher for this host, else the
    disclosed poll fallback.
  * submodules ``model`` / ``incremental`` / ``watcher`` / ``connect``
    stay reachable as attributes -- this file must never bind a plain
    name over a submodule of the same name (the shadow trap: assigning
    ``model = something`` here would break ``analysis.watch.model``
    imports for every later consumer).

No I/O at import; offline by construction.
"""
from analysis.watch import connect as connect          # noqa: F401
from analysis.watch import incremental as incremental  # noqa: F401
from analysis.watch import model as model              # noqa: F401
from analysis.watch import watcher as watcher          # noqa: F401
from analysis.watch.incremental import (               # noqa: F401
    IncrementalScanner,
    default_scan_fn,
)
from analysis.watch.model import (                     # noqa: F401
    DEFAULT_DEBOUNCE_MS,
    EVENT_KINDS,
    SCHEMA,
    ChangeBuffer,
)
from analysis.watch.watcher import (                   # noqa: F401
    POLL_LIMITATIONS,
    open_watcher,
)

__all__ = [
    "ChangeBuffer",
    "DEFAULT_DEBOUNCE_MS",
    "EVENT_KINDS",
    "IncrementalScanner",
    "POLL_LIMITATIONS",
    "SCHEMA",
    "connect",
    "default_scan_fn",
    "incremental",
    "model",
    "open_watcher",
    "prime_and_watch",
    "watcher",
]


def prime_and_watch(target, events, *, scan_fn=None, as_of=None,
                    debounce_ms=DEFAULT_DEBOUNCE_MS) -> dict:
    """Prime ``target`` once, apply ``events``, return the document.

    The convenience entry point: identical semantics to driving
    :class:`IncrementalScanner` by hand (prime -> buffer -> flush ->
    apply), just without the ceremony.  ``events`` is any iterable of
    event dicts (``{path, kind, at?}``); caller-side validation skips
    ride the document the same way the CLI's do.
    """
    scanner = IncrementalScanner(target, scan_fn=scan_fn)
    scanner.prime()
    events = list(events or [])
    if events:
        buf = ChangeBuffer(debounce_ms=debounce_ms)
        for ev in events:
            buf.add(ev)
        for row in buf.skips():
            scanner.note_skip(row)
        newest = max([float(e.get("at") or 0.0)
                      for e in buf.pending()] or [0.0])
        flushed = buf.flush(newest + debounce_ms / 1000.0 + 1e-3)
        if flushed:
            scanner.apply(flushed)
    return scanner.document(as_of=as_of)
