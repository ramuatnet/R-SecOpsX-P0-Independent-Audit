"""T-8.1 watch mode -- the CLI (``python -m analysis.watch.connect``).

Two modes, one artifact schema (``rsecopsx.watch_scan/v1``):

  * ``--events-from FILE``: deterministic mode.  Read a JSON list of
    events, prime the target once, apply the batch, write the document.
    Identical inputs produce byte-identical output (no wall clock
    leaks into the artifact -- ``as_of`` is caller-supplied).  A
    missing/unreadable events file is an annotated skip row and exit 0,
    never a crash.
  * ``--duration SECONDS``: runtime mode.  Open the best native watcher,
    run the debounce/apply loop for the bounded duration (resource
    bound: the loop cannot outlive the deadline), drain anything still
    pending at the end, always write the artifact.

Exit codes: 0 success (including "nothing happened"), 2 for a malformed
``--as-of`` (argparse's own usage errors are also 2).  Everything the
run skipped -- bad events, absent files, native parse failures -- lands
in ``doc["skips"]`` with a machine-readable reason (ground rule 3).

Offline by construction: stdlib only, no network modules.
"""
from __future__ import annotations
try:
    from analysis.spans import WINDOW_300
except ImportError:  # FND-03: standalone, repo root not on path
    import sys as _fnd03_sys
    from pathlib import Path as _fnd03_path
    _fnd03_sys.path.insert(0, str(_fnd03_path(__file__).resolve().parents[2]))
    from analysis.spans import WINDOW_300

import argparse
import datetime as _dt
import json
import sys
import time

from analysis.watch.incremental import IncrementalScanner
from analysis.watch.model import DEFAULT_DEBOUNCE_MS, SCHEMA, ChangeBuffer


def _parse_as_of(value: "str | None") -> "str | None":
    if value is None:
        return None
    try:
        _dt.datetime.fromisoformat(value)
    except ValueError:
        raise SystemExit(
            f"error: invalid --as-of {value!r} "
            "(expected an ISO-8601 timestamp, e.g. "
            "2026-10-31T12:00:00+00:00)")
    return value


def _load_events(path: str) -> "tuple[list, list]":
    """Read the scripted events file -> (events, skips)."""
    import os
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        return [], [{"reason": f"events_file_missing:{os.path.abspath(path)}",
                     "detail": "no events applied; artifact written with "
                               "the primed baseline only"}]
    except (OSError, ValueError) as exc:
        return [], [{"reason": f"events_file_unreadable:{type(exc).__name__}",
                     "detail": str(exc)[:WINDOW_300]}]
    if not isinstance(data, list):
        return [], [{"reason": "events_file_not_a_list",
                     "detail": f"expected a JSON list, got "
                               f"{type(data).__name__}"}]
    return data, []


def _apply_batch(scanner: IncrementalScanner, events: "list",
                 pre_skips: "list[dict] | None" = None) -> dict:
    """Apply one flushed batch; caller-side skips ride the document via
    ``note_skip`` (they were not produced by apply itself)."""
    if pre_skips:
        for row in pre_skips:
            scanner.note_skip(row)
    return scanner.apply(events)


def _write_doc(path: str, doc: dict) -> None:
    # sort_keys keeps the artifact byte-stable across runs and hosts.
    text = json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text + "\n")


def run_events_from(target: str, events_path: str, as_of, out: str,
                    debounce_ms: int) -> int:
    """Deterministic scripted mode (see module docstring)."""
    events, skips = _load_events(events_path)
    scanner = IncrementalScanner(target)
    scanner.prime()
    if events:
        # Route through the real ChangeBuffer so scripted events get the
        # same debounce/coalesce semantics as live ones; the batch is
        # forced due at the newest event's timestamp + debounce.
        buf = ChangeBuffer(debounce_ms=debounce_ms)
        for ev in events:
            buf.add(ev)
        skips.extend(buf.skips())
        newest = max([float(e.get("at") or 0.0)
                      for e in buf.pending()] or [0.0])
        due_at = newest + debounce_ms / 1000.0 + 1e-3
        flushed = buf.flush(due_at)
        _apply_batch(scanner, flushed, pre_skips=skips)
    else:
        # Nothing to apply -- the skips still have to ride the artifact.
        for row in skips:
            scanner.note_skip(row)
    _write_doc(out, scanner.document(as_of=as_of))
    return 0


def run_duration(target: str, duration_s: float, as_of, out: str,
                 debounce_ms: int) -> int:
    """Bounded runtime mode: watch for ``duration_s`` seconds, then
    drain and write.  The deadline is the resource bound (ground rule
    on untrusted/long inputs): the loop cannot outlive it."""
    from analysis.watch.watcher import open_watcher

    scanner = IncrementalScanner(target)
    files = scanner.prime()
    watcher = open_watcher(target, files)
    buf = ChangeBuffer(debounce_ms=debounce_ms)
    deadline = time.monotonic() + max(0.0, float(duration_s))
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            now = time.time()
            for ev in watcher.poll(now=now):
                buf.add(ev)
            if buf.due(now):
                _apply_batch(scanner, buf.flush(now))
            # sleep is bounded by the deadline -- never overshoot it
            time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))
        # final drain: force anything still pending through the buffer
        if len(buf):
            tail = buf.flush(time.time() + debounce_ms / 1000.0 + 1.0)
            if tail:
                _apply_batch(scanner, tail)
    finally:
        disclosure = watcher.disclosure()
        watcher.close()
        for row in disclosure:
            scanner.note_skip(row)
    _write_doc(out, scanner.document(as_of=as_of))
    return 0


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(
        prog="analysis.watch.connect",
        description="R-SecOpsX watch mode: incremental re-scan of "
                    "changed files only (never a full tree re-walk).")
    ap.add_argument("target", help="directory or file to watch")
    ap.add_argument("--events-from", metavar="FILE",
                    help="apply a scripted JSON event list (deterministic)")
    ap.add_argument("--duration", type=float, default=0.0, metavar="SECONDS",
                    help="runtime watch window (bounded); 0 = no runtime "
                         "loop")
    ap.add_argument("--debounce-ms", type=int, default=DEFAULT_DEBOUNCE_MS,
                    help=f"quiet-window debounce (default "
                         f"{DEFAULT_DEBOUNCE_MS})")
    ap.add_argument("--as-of", metavar="ISO8601",
                    help="artifact timestamp (required for determinism "
                         "checks; validated, exit 2 when malformed)")
    ap.add_argument("--out", required=True, metavar="FILE",
                    help="artifact path (JSON, schema rsecopsx.watch_scan/v1)")
    args = ap.parse_args(argv)

    # Validate --as-of BEFORE any work: exit 2 with a clear message.
    # SystemExit(2) would swallow the message, so print and return.
    try:
        _parse_as_of(args.as_of)
    except SystemExit as exc:
        print(str(exc), file=sys.stderr)
        return 2
    if args.debounce_ms < 0:
        print("error: --debounce-ms must be >= 0", file=sys.stderr)
        return 2

    if args.events_from:
        return run_events_from(args.target, args.events_from, args.as_of,
                               args.out, args.debounce_ms)
    if args.duration > 0:
        return run_duration(args.target, args.duration, args.as_of,
                            args.out, args.debounce_ms)
    # Neither mode: prime + write an empty-but-valid artifact (the
    # runtime smoke in the gate always passes one of the two flags;
    # this keeps `--out` alone from being an error).
    scanner = IncrementalScanner(args.target)
    scanner.prime()
    _write_doc(args.out, scanner.document(as_of=args.as_of))
    return 0


if __name__ == "__main__":
    sys.exit(main())
