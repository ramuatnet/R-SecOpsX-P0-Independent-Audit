"""T-8.2 serve CLI -- ``python -m analysis.serve.connect``.

One entry, many verbs (watch-mode precedent: the mode entry is the
module CLI, not a main.py flag).  The artifact doc is the audit trail:
what was enqueued, ran, ticked, delivered -- with machine-readable
skip reasons for everything that did NOT happen.

Network discipline: the default run does ZERO I/O.  No --db -> a
static doc with exactly the three not_provided skips (db, enqueue,
webhooks).  With a --db but no --deliver, webhook delivery is DRY --
rows are recorded, nothing posts.  --deliver is the opt-in that
swaps in RealSender.  --serve spawns the loopback server; its ticker
runs the DRY runner unless --runner scan was given (scan itself is a
subprocess, imported lazily inside the runner -- never at module
level).

Backend failures are LOUD: postgres:// (PHASE 9) exits rc 1 with the
machine reason on stderr, never a silent fallback to a local file.

Auth flags (T-9.1): --auth-file is validated EAGERLY (rc 2 on any
authoring error, even without --serve -- a broken config must fail the
deploy, not the first request).  --audit-log appends canonical JSONL
(flush per line) and is only consumed with --serve; without --serve it
creates NO file (zero-I/O default preserved).  --serve-host defaults to
127.0.0.1; binding elsewhere without --auth-file is rc 2
(auth_required_for_non_loopback, guard lives in api.serve before bind).

Tenancy (T-9.2): NO new flags -- the tenant surface is the credential
itself (a "tenant" key on a token entry, or a JWT tenant claim; see
auth.py).  Scoped callers get a tenant-filtered API; unscoped
credentials remain cross-tenant operators.  The CLI doc/schema is
unchanged (zero-I/O default still emits no tenant key).
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
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from .api import serve
from .auth import AuthInvalid, load_auth_file
from .events import RealSender, deliver_events
from .model import DOC_SCHEMA
from .queue import add_schedule, cron_tick, drain, enqueue_jobs
from .storage import BackendUnavailable, WebhookInvalid, open_backend

REPO = Path(__file__).resolve().parents[2]

_STAT_KEYS = ("enqueued", "ran", "done", "failed", "cron_enqueued",
              "delivered", "dry")


def scan_command(job: dict) -> "list[str]":
    """Argv for a real scan -- shape pinned by test, never spawned here."""
    return [sys.executable, str(REPO / "main.py"),
            str(job.get("target") or ""),
            "--output-dir", str(job.get("out") or ""),
            "--quiet", "--no-pdf", "--no-excel"]


def scan_runner(job: dict) -> dict:
    """Opt-in runner: spawn the real engine (subprocess stays lazy)."""
    import subprocess
    proc = subprocess.run(scan_command(job), capture_output=True, text=True,
                          timeout=3600)
    if proc.returncode == 0:
        return {"ok": True, "detail": "rc=0"}
    return {"ok": False, "detail": f"rc={proc.returncode}"[:WINDOW_300]}


def _dry_runner(job: dict) -> dict:
    return {"ok": True, "detail": "dry"}


def _parse_as_of(raw):
    """Naive ISO is treated as UTC; --as-of bad -> SystemExit(2)."""
    if raw is None:
        return time.time()
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError:
        print(f"bad --as-of: {raw!r} (expected ISO-8601)", file=sys.stderr)
        raise SystemExit(2)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def _read_rows(path: Path):
    """Read a JSON list file; raises FileNotFoundError/ValueError upward."""
    return json.loads(path.read_text(encoding="utf-8"))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="analysis.serve.connect",
                                 description="R-SecOpsX serve mode")
    ap.add_argument("--db")
    ap.add_argument("--enqueue")
    ap.add_argument("--drain", action="store_true")
    ap.add_argument("--runner", choices=("dry", "scan"), default="dry")
    ap.add_argument("--add-schedule")
    ap.add_argument("--cron-tick")
    ap.add_argument("--events", action="store_true")
    ap.add_argument("--since", default="0")
    ap.add_argument("--webhooks")
    ap.add_argument("--deliver", action="store_true")
    ap.add_argument("--serve", action="store_true")
    ap.add_argument("--serve-port", type=int, default=0)
    ap.add_argument("--serve-ready-file")
    ap.add_argument("--auth-file")
    ap.add_argument("--audit-log")
    ap.add_argument("--serve-host", default="127.0.0.1")
    ap.add_argument("--as-of")
    ap.add_argument("--out")
    args = ap.parse_args(argv)

    # eager even without --serve: a broken auth file fails the deploy
    auth_cfg = None
    if args.auth_file:
        try:
            auth_cfg = load_auth_file(args.auth_file)
        except AuthInvalid as exc:
            print(f"auth error: {exc.reason}", file=sys.stderr)
            return 2

    now = _parse_as_of(args.as_of)
    skips = []
    stats = {k: 0 for k in _STAT_KEYS}
    jobs: "list[dict]" = []
    schedules: "list[dict]" = []
    deliveries: "list[dict]" = []
    events: "list[dict]" = []

    if not args.db:
        # zero-I/O default: one skip per absent input, sorted, stable
        for name in ("db", "enqueue", "webhooks"):
            skips.append({"reason": f"not_provided:{name}"})
    else:
        try:
            backend = open_backend(args.db)
        except BackendUnavailable as exc:
            print(f"backend unavailable: {exc.reason}: {exc}",
                  file=sys.stderr)
            return 1

        if args.enqueue:
            try:
                rows = _read_rows(Path(args.enqueue))
            except FileNotFoundError:
                skips.append({"reason":
                              f"enqueue_file_missing:{Path(args.enqueue).resolve()}"})
            except (ValueError, UnicodeDecodeError):
                skips.append({"reason": "enqueue_unreadable:json"})
            else:
                enqueued, eskip = enqueue_jobs(backend, rows, now=now)
                stats["enqueued"] = len(enqueued)
                skips.extend(eskip)

        if args.add_schedule:
            try:
                rows = _read_rows(Path(args.add_schedule))
            except FileNotFoundError:
                skips.append({"reason":
                              f"schedule_file_missing:{Path(args.add_schedule).resolve()}"})
            except (ValueError, UnicodeDecodeError):
                skips.append({"reason": "schedule_unreadable:json"})
            else:
                good, sskip = add_schedule(backend, rows, now=now)
                schedules = good
                skips.extend(sskip)

        if args.cron_tick:
            try:
                tick_at = _parse_as_of(args.cron_tick)
            except SystemExit:
                raise
            stats["cron_enqueued"] = cron_tick(backend, now=tick_at)["enqueued"]

        if args.drain:
            runner = scan_runner if args.runner == "scan" else _dry_runner
            _ran, dstats, dskip = drain(backend, runner=runner, now=now)
            stats["ran"] = dstats["ran"]
            stats["done"] = dstats["done"]
            stats["failed"] = dstats["failed"]
            skips.extend(dskip)

        if args.webhooks:
            try:
                rows = _read_rows(Path(args.webhooks))
            except FileNotFoundError:
                skips.append({"reason":
                              f"webhooks_file_missing:{Path(args.webhooks).resolve()}"})
            except (ValueError, UnicodeDecodeError):
                skips.append({"reason": "webhooks_unreadable:json"})
            else:
                for row in rows:
                    url = row.get("url") if isinstance(row, dict) else None
                    if not url:
                        skips.append({"reason": "webhook_url_missing"})
                        continue
                    try:
                        backend.register_webhook(url)
                    except WebhookInvalid as exc:
                        skips.append({"reason": exc.reason, "url": url})

        # --deliver is the network opt-in; without it, delivery is DRY
        dstats = deliver_events(
            backend, sender=RealSender() if args.deliver else None,
            now=now, sleep_fn=time.sleep, dry=not args.deliver)
        stats["delivered"] = dstats["delivered"]
        stats["dry"] = dstats["dry"]

        if args.serve:
            audit_fn = None
            if args.audit_log:
                # append-only JSONL, flush per line: a crash must not
                # cost audit rows; sink errors propagate (no swallow)
                import threading
                _audit_lock = threading.Lock()
                _audit_fh = open(args.audit_log, "a", encoding="utf-8",
                                 newline="\n")

                def audit_fn(entry):
                    line = json.dumps(entry, sort_keys=True,
                                      ensure_ascii=True)
                    with _audit_lock:
                        _audit_fh.write(line + "\n")
                        _audit_fh.flush()
            try:
                serve(backend, host=args.serve_host,
                      port=args.serve_port,
                      ready_file=args.serve_ready_file,
                      runner=scan_runner if args.runner == "scan" else None,
                      auth=auth_cfg, audit_fn=audit_fn)
            except ValueError as exc:
                # guard refused the bind (e.g. non-loopback, no auth)
                print(f"serve error: {exc}", file=sys.stderr)
                return 2

        jobs = backend.list_jobs()
        schedules = schedules or backend.schedules()
        deliveries = backend.deliveries()
        if args.events:
            try:
                since = int(args.since)
            except ValueError:
                print(f"bad --since: {args.since!r}", file=sys.stderr)
                return 2
            events = backend.events_since(since, limit=1000)
        backend.close()

    doc = {"schema": DOC_SCHEMA, "jobs": jobs, "schedules": schedules,
           "events": events, "deliveries": deliveries, "stats": stats,
           "skips": sorted(skips, key=lambda s: s["reason"])}
    text = json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(text, encoding="utf-8", newline="\n")
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
