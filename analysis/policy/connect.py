"""CLI for the T-8.3 policy-as-code gate.

    python -m analysis.policy.connect --policy FILE --report FILE \
        [--as-of ISO] [--out FILE]

Geometry (locked by tests/test_t83_policy.py):

* default run (no --policy, no --report) performs ZERO I/O: result is
  null and exactly two sorted ``not_provided`` skips are reported;
* rc 0 -- gate passed or nothing to evaluate;
* rc 1 -- the policy gate FAILED (report still written, CI reads the
  artifact for the blocking rows);
* rc 2 -- usage error: unreadable/invalid policy, missing or malformed
  report, bad --as-of (nothing is guessed);
* output is canonical JSON (indent=2, sort_keys, ASCII, LF) so a fixed
  --as-of yields byte-identical documents.
"""
from __future__ import annotations
try:
    from analysis.spans import WINDOW_M1
except ImportError:  # FND-03: standalone, repo root not on path
    import sys as _fnd03_sys
    from pathlib import Path as _fnd03_path
    _fnd03_sys.path.insert(0, str(_fnd03_path(__file__).resolve().parents[2]))
    from analysis.spans import WINDOW_M1

import argparse
import json
import pathlib
import sys
import time
from datetime import datetime, timezone

from .model import DOC_SCHEMA, PolicyInvalid, evaluate, load_policy_file, \
    rows_from_payload


def _parse_as_of(text):
    if text is None:
        return time.time()
    value = text.strip()
    if value.endswith("Z"):
        value = value[:WINDOW_M1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        print(f"policy: bad --as-of {text!r} "
              f"(expected ISO-8601, e.g. 2026-10-31T00:00:00)",
              file=sys.stderr)
        raise SystemExit(2)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp()


def _read_report(path):
    try:
        text = pathlib.Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        print(f"policy: report unreadable {path}: {exc}", file=sys.stderr)
        raise SystemExit(2)
    try:
        payload = json.loads(text)
    except ValueError as exc:
        print(f"policy: report is not valid JSON {path}: {exc}",
              file=sys.stderr)
        raise SystemExit(2)
    if not isinstance(payload, dict):
        print(f"policy: report is not a JSON object {path}", file=sys.stderr)
        raise SystemExit(2)
    return payload


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="python -m analysis.policy.connect",
        description="Evaluate a scan report against a policy file "
                    "(fail_on rung, scope, exclusions, SLA, required "
                    "evidence). Zero I/O with no arguments.")
    parser.add_argument("--policy", metavar="FILE", default=None,
                        help="policy YAML (rsecopsx.policy/v1)")
    parser.add_argument("--report", metavar="FILE", default=None,
                        help="clean_report.json to evaluate")
    parser.add_argument("--as-of", metavar="ISO", default=None,
                        help="fixed evaluation timestamp (UTC if naive)")
    parser.add_argument("--out", metavar="FILE", default=None,
                        help="write the document here instead of stdout")
    args = parser.parse_args(argv)

    as_of = _parse_as_of(args.as_of)
    skips = []
    policy = None
    payload = None

    if args.policy is None:
        skips.append({"reason": "not_provided:policy"})
    else:
        try:
            policy = load_policy_file(args.policy)
        except PolicyInvalid as exc:
            print(f"policy: {exc.reason} ({args.policy})", file=sys.stderr)
            return 2

    if args.report is None:
        skips.append({"reason": "not_provided:report"})
    else:
        payload = _read_report(args.report)

    result = None
    if policy is not None and payload is not None:
        result = evaluate(policy, rows_from_payload(payload), as_of)

    if result is None:
        stats = {"passed": None, "blocking": 0, "rows": 0}
    else:
        stats = {"passed": result["passed"],
                 "blocking": result["counts"]["blocking"],
                 "rows": len(result["rows"])}

    doc = {
        "schema": DOC_SCHEMA,
        "as_of": as_of,
        "result": result,
        "stats": stats,
        "skips": sorted(skips, key=lambda s: s["reason"]),
    }
    text = json.dumps(doc, indent=2, sort_keys=True,
                      ensure_ascii=True) + "\n"
    if args.out:
        pathlib.Path(args.out).write_text(text, encoding="utf-8",
                                          newline="\n")
    else:
        sys.stdout.write(text)

    if result is not None and not result["passed"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
