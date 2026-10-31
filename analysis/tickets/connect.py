"""CLI for the ticket integration -- ``python -m analysis.tickets.connect``.

task.md section 12 PHASE 9 "ticket/webhook integrations".

    python -m analysis.tickets.connect \\
        [--finding FILE] [--previous DRAFTS.json] \\
        [--profile generic|jira|github|linear] \\
        [--as-of ISO8601] [--out FILE]

Exit codes: 0 = document emitted (stdout, or --out with a trailing
newline); 2 = usage / unparseable --as-of.  Load problems are
MACHINE-READABLE SKIP ROWS inside the artifact (scoring/feedback
precedent -- the document is the loud surface, rc stays 0): the default
run (no inputs) is zero-I/O with exactly two ``not_provided`` skips.
Inputs are bounded at 64 MiB (resource bound, ground rule 12).

No network, no tracker client: drafts are payload projections for the
existing T-8.2 webhook surface to deliver.
"""
from __future__ import annotations

import argparse
import json
import sys

from analysis.tickets.model import PROFILES, SCHEMA, build

MAX_INPUT_BYTES = 64 * 1024 * 1024


def _load(path: str, source: str):
    """Read + parse one JSON file -> (data, skip).  Never raises."""
    try:
        with open(path, "rb") as fh:
            raw = fh.read(MAX_INPUT_BYTES + 1)
    except OSError as exc:
        return None, {"reason": f"unreadable:{type(exc).__name__}:{path}",
                      "source": source}
    if len(raw) > MAX_INPUT_BYTES:
        return None, {"reason": f"input_too_large:{path}",
                      "source": source}
    try:
        return json.loads(raw.decode("utf-8")), None
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return None, {"reason": f"json_decode_error:{type(exc).__name__}"
                                f":{path}",
                      "source": source}


def _valid_iso(value: str) -> str:
    from datetime import datetime
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "--as-of must be ISO-8601: %s" % exc) from exc
    return value


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m analysis.tickets.connect",
        description="Draft tracker issues from scan findings offline "
                    "(task.md section 12 PHASE 9).")
    parser.add_argument("--finding", metavar="FILE",
                        help="finding payload JSON (list, "
                             "{findings: [...]}, or object)")
    parser.add_argument("--previous", metavar="FILE",
                        help="prior ticket_drafts document to diff "
                             "transitions against")
    parser.add_argument("--profile", choices=PROFILES, default="generic",
                        help="tracker payload projection (default: "
                             "generic)")
    parser.add_argument("--as-of", type=_valid_iso, default=None,
                        help="ISO-8601 instant echoed into the document "
                             "(optional; output stays deterministic "
                             "given the flag)")
    parser.add_argument("--out", metavar="FILE",
                        help="write the document here instead of stdout")
    args = parser.parse_args(argv)

    payload, previous = None, None
    load_skips = []
    if args.finding is None:
        pass                     # build() emits findings not_provided
    else:
        payload, skip = _load(args.finding, "findings")
        if skip is not None:
            load_skips.append(skip)
            payload = None
    if args.previous is not None:
        previous, skip = _load(args.previous, "previous")
        if skip is not None:
            load_skips.append(skip)
            # Non-dict marker (not None): transitions stay empty with a
            # previous_not_object row -- a FAILED load must never read
            # as "no previous provided".
            previous = "load_failed"

    doc = build(payload, previous=previous, profile=args.profile,
                as_of=args.as_of)
    if load_skips:
        doc["skips"].extend(load_skips)
        doc["skips"].sort(key=lambda s: (str(s.get("source", "")),
                                         str(s.get("reason", ""))))
        doc["stats"]["skipped"] = sum(
            int(s.get("count", 1)) for s in doc["skips"])

    text = json.dumps(doc, sort_keys=True, indent=2,
                      ensure_ascii=True) + "\n"
    if args.out:
        with open(args.out, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
