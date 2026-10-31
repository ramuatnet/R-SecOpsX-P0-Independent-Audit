"""T-7.1: scoring ingest + CLI (offline, zero-I/O by default).

Mirrors analysis.graph.connect: file ingest for the finding payload
(shared context/feedback JSON are optional), schema/shape problems
become machine-readable skips, and the CLI is byte-identical for
identical inputs.

  python -m analysis.scoring.connect --finding findings.json \\
      [--context ctx.json] [--feedback fb.json] \\
      [--as-of 2026-10-31T12:00:00Z] [--explain-score] [--out o.json]

--explain-score emits the full rows (per-factor signed contributions,
base provenance, feedback delta, raw, clamped); without it each row is
compacted to {rule_id, score, band}.  With no --finding the artifact
is a zero-I/O {scores: [], skips: [not_provided]} document -- same
inputs (incl. --as-of) produce identical output bytes.

Inputs are bounded (MAX_INPUT_BYTES per file); oversized, unreadable,
or unparseable files are skip rows, never raises.
"""
from __future__ import annotations

import argparse
import json
import sys

from analysis.scoring.score import SCHEMA, _as_dt, score_findings

MAX_INPUT_BYTES = 64 * 1024 * 1024


def _load(path: str, target: str):
    """Read + parse one JSON file -> (data, skip).  Never raises."""
    try:
        with open(path, "rb") as fh:
            raw = fh.read(MAX_INPUT_BYTES + 1)
    except OSError as exc:
        return None, {"stage": "scoring", "target": target,
                      "reason": f"{type(exc).__name__}:{path}",
                      "detail": {}}
    if len(raw) > MAX_INPUT_BYTES:
        return None, {"stage": "scoring", "target": target,
                      "reason": "input_too_large",
                      "detail": {"path": path,
                                 "max_bytes": MAX_INPUT_BYTES}}
    try:
        return json.loads(raw.decode("utf-8")), None
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return None, {"stage": "scoring", "target": target,
                      "reason": f"json_decode_error:{path}",
                      "detail": {"error": type(exc).__name__}}


def _load_mapping(path: str | None, target: str):
    """Optional JSON object file -> (dict, skip)."""
    if path is None:
        return {}, None
    data, skip = _load(path, target)
    if skip is not None:
        return {}, skip
    if not isinstance(data, dict):
        return {}, {"stage": "scoring", "target": target,
                    "reason": "payload_not_object",
                    "detail": {"path": path}}
    return data, None


def collect_scores(finding: str | None = None,
                   context: str | None = None,
                   feedback: str | None = None,
                   explain: bool = False,
                   as_of=None) -> dict:
    """Build the score artifact from optional files (default zero-I/O)."""
    skips: list[dict] = []
    rows = []
    payload = None
    if finding is None:
        skips.append({"stage": "scoring", "target": "findings",
                      "reason": "not_provided", "detail": {}})
    else:
        payload, skip = _load(finding, "findings")
        if skip is not None:
            skips.append(skip)
            payload = None
    ctx, skip = _load_mapping(context, "context")
    if skip is not None:
        skips.append(skip)
    fb, skip = _load_mapping(feedback, "feedback")
    if skip is not None:
        skips.append(skip)
    if payload is not None:
        art = score_findings(payload, context=ctx, feedback=fb,
                             as_of=as_of, explain=explain)
        rows = art["scores"]
        skips.extend(art["skips"])
        as_of_text = art["as_of"]
    else:
        as_of_text = _as_dt(as_of).isoformat()
    skips.sort(key=lambda s: (str(s.get("stage", "")),
                              str(s.get("target", "")),
                              str(s.get("reason", ""))))
    return {
        "schema": SCHEMA,
        "as_of": as_of_text,
        "scores": rows,
        "skips": skips,
        "stats": {"scored": len(rows), "skips": len(skips)},
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m analysis.scoring.connect",
        description="Deterministic, explainable finding scores "
                    "(base = CVSS4 + signed modifier contributions "
                    "+ feedback).")
    parser.add_argument("--finding", help="finding payload JSON "
                        "(list, {findings: [...]}, or object)")
    parser.add_argument("--context", help="shared modifier context "
                        "JSON object")
    parser.add_argument("--feedback", help="shared feedback JSON "
                        "object")
    parser.add_argument("--as-of", help="ISO timestamp for age "
                        "decay (deterministic when provided)")
    parser.add_argument("--explain-score", action="store_true",
                        help="emit per-factor signed contributions "
                             "for every score")
    parser.add_argument("--out", help="write the artifact here "
                        "instead of stdout")
    args = parser.parse_args(argv)

    as_of = None
    if args.as_of is not None:
        try:
            as_of = _as_dt(args.as_of, default_now=False)
        except (ValueError, TypeError) as exc:
            print(f"error: unparseable --as-of {args.as_of!r}: {exc}",
                  file=sys.stderr)
            return 2
    art = collect_scores(finding=args.finding, context=args.context,
                         feedback=args.feedback,
                         explain=args.explain_score, as_of=as_of)
    text = json.dumps(art, indent=2, sort_keys=True) + "\n"
    if args.out:
        with open(args.out, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
