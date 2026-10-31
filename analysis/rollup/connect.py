"""T-9.3 org rollup CLI -- ``python -m analysis.rollup.connect``.

D-1 producer: ``--org-rollup manifests/*.json`` collator (pure CLI,
offline) + schema validator.  The only I/O is reading the manifest
files it was handed and writing the ``--out`` document; there is no
network stage, no clock (``--as-of`` is injected, fixed default), and
argument order never changes the output bytes (the shell may expand
the glob in any order -- the collator sorts).

Exit codes: 0 written (or zero-I/O default), 1 input problem (machine
reason per line on stderr, NO partial artifact -- a rollup that
half-wrote would be imported as if it were complete), 2 usage (missing
--out, malformed --as-of).  With no ``--org-rollup`` the default run is
zero-I/O: an empty document with exactly one ``not_provided`` skip.
"""
from __future__ import annotations

import argparse
import datetime
import glob
import json
import pathlib
import sys

from .model import (RollupInvalid, build_rollup, validate_manifest,
                    validate_rollup)

DEFAULT_AS_OF = "1970-01-01T00:00:00Z"


def _as_of_ok(raw) -> bool:
    """True when raw parses as an ISO-8601 timestamp (Z accepted)."""
    try:
        datetime.datetime.fromisoformat(str(raw).strip().replace("Z",
                                                                 "+00:00"))
    except ValueError:
        return False
    return True


def _expand(patterns) -> "list[str]":
    """Expand shell-style patterns in-process (sorted, offline).

    A pattern that matches nothing falls through as the literal path so
    the missing file surfaces as a loud manifest_unreadable error
    instead of a silently shorter rollup.
    """
    out: "list[str]" = []
    for raw in patterns:
        if any(ch in raw for ch in "*?["):
            matches = sorted(glob.glob(raw))
            out.extend(matches or [raw])
        else:
            out.append(raw)
    return out


def _write(out_path, doc) -> int:
    payload = json.dumps(doc, sort_keys=True, ensure_ascii=True,
                         indent=2) + "\n"
    pathlib.Path(out_path).write_text(payload, encoding="utf-8",
                                      newline="\n")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="analysis.rollup.connect",
        description="Collate per-repo scan manifests into org_rollup.json "
                    "(pure, offline; D-1).")
    parser.add_argument("--org-rollup", nargs="+", default=[],
                        metavar="MANIFEST",
                        help="per-repo scan manifest JSON files "
                             "(shell glob expands to many)")
    parser.add_argument("--out", required=True,
                        help="path of the org_rollup.json to write")
    parser.add_argument("--as-of", default=DEFAULT_AS_OF,
                        help="rollup as-of timestamp, ISO-8601 "
                             "(default fixed, keeps runs byte-stable)")
    args = parser.parse_args(argv)

    if not _as_of_ok(args.as_of):
        print(f"org rollup error: as-of must be ISO-8601: {args.as_of}",
              file=sys.stderr)
        return 2

    paths = _expand(args.org_rollup)
    if not paths:
        # zero-I/O default: empty rollup + exactly one not_provided skip
        doc = build_rollup([], as_of=args.as_of)
        doc["skips"] = [{"reason": "not_provided", "source": "org_rollup"}]
        return _write(args.out, doc)

    errors: "list[str]" = []
    manifests: "list[dict]" = []
    for path in paths:
        try:
            text = pathlib.Path(path).read_text(encoding="utf-8")
        except OSError:
            errors.append(f"{path}: manifest_unreadable:{path}")
            continue
        try:
            man = json.loads(text)
        except ValueError:
            errors.append(f"{path}: manifest_bad_json:{path}")
            continue
        reason = validate_manifest(man)
        if reason is not None:
            errors.append(f"{path}: {reason}")
            continue
        manifests.append(man)
    if errors:
        # every problem listed, then refuse -- no partial artifact
        for line in sorted(errors):
            print(f"org rollup error: {line}", file=sys.stderr)
        return 1
    try:
        doc = build_rollup(manifests, as_of=args.as_of)
    except RollupInvalid as exc:
        print(f"org rollup error: {exc.reason}", file=sys.stderr)
        return 1
    reason = validate_rollup(doc)
    if reason is not None:
        print(f"org rollup error: {reason}", file=sys.stderr)
        return 1
    return _write(args.out, doc)


if __name__ == "__main__":
    raise SystemExit(main())
