"""CLI for the SBOM/VEX service -- ``python -m analysis.vex.connect``.

task.md section 12 PHASE 9 "SBOM/VEX service".  Zero runtime deps, zero
network.  Exit codes: 0 = artifact written, 1 = every fatal input error
collected and printed (``vex service error: <reason>`` lines, NO partial
output), 2 = argparse usage.

    python -m analysis.vex.connect \
        [--vex FILE ...] [--sbom FILE ...] \
        [--vulnerability ID ...] [--component REF ...] [--status S] \
        [--as-of ISO8601] --out FILE

Every input path is stat-capped at 64 MiB (resource bound, ground
rule 12) -> fatal ``input_too_large:<path>``.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from analysis.vex.model import (
    SCHEMA, VEX_STATUSES, VexInvalid, build, normalize_vex_doc,
)
from scanner.sbom_reader import SbomReadError, read_sbom

MAX_INPUT_BYTES = 64 * 1024 * 1024


def _load_json(path: str, label: str) -> dict:
    p = Path(path)
    if not p.is_file():
        raise VexInvalid("%s_file_does_not_exist:%s" % (label, path))
    if p.stat().st_size > MAX_INPUT_BYTES:
        raise VexInvalid("input_too_large:%s" % path)
    try:
        text = p.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeDecodeError) as exc:
        raise VexInvalid("%s_unreadable:%s: %s"
                         % (label, path, type(exc).__name__)) from exc
    try:
        doc = json.loads(text)
    except ValueError as exc:
        raise VexInvalid("%s_not_json:%s: %s" % (label, path, exc)) from exc
    if not isinstance(doc, dict):
        raise VexInvalid("%s_not_an_object:%s" % (label, path))
    return doc


def _load_vex(path: str) -> dict:
    return _load_json(path, "vex")


def _load_sbom(path: str) -> dict:
    p = Path(path)
    if not p.is_file():
        raise VexInvalid("sbom_file_does_not_exist:%s" % path)
    if p.stat().st_size > MAX_INPUT_BYTES:
        raise VexInvalid("input_too_large:%s" % path)
    try:
        return read_sbom(path)
    except SbomReadError as exc:
        raise VexInvalid("sbom_read_error:%s" % exc) from exc


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
        prog="python -m analysis.vex.connect",
        description="Ingest VEX statements + SBOM components and query "
                    "them offline (task.md section 12 PHASE 9).")
    parser.add_argument("--vex", action="append", default=[],
                        metavar="FILE",
                        help="VEX document (R-SecOpsX statements, "
                             "CycloneDX vulnerabilities, or OpenVEX); "
                             "repeatable")
    parser.add_argument("--sbom", action="append", default=[],
                        metavar="FILE",
                        help="SBOM (CycloneDX or SPDX JSON, via "
                             "scanner.sbom_reader); repeatable")
    parser.add_argument("--vulnerability", action="append", default=[],
                        metavar="ID",
                        help="query statements by vulnerability id "
                             "(case-insensitive); repeatable")
    parser.add_argument("--component", action="append", default=[],
                        metavar="REF",
                        help="query by bom-ref, purl, name@version, or "
                             "name; repeatable")
    parser.add_argument("--status", choices=VEX_STATUSES,
                        help="query statements by canonical status")
    parser.add_argument("--as-of", type=_valid_iso, default=None,
                        help="ISO-8601 instant echoed into the artifact "
                             "(optional; output stays deterministic "
                             "given the flag)")
    parser.add_argument("--out", required=True, metavar="FILE",
                        help="output JSON artifact path")
    args = parser.parse_args(argv)

    errors: list[str] = []
    vex_docs: list = []
    for path in args.vex:
        try:
            vex_docs.append((path, _load_vex(path)))
        except VexInvalid as exc:
            errors.append(exc.reason)
    sbom_docs: list = []
    for path in args.sbom:
        try:
            sbom_docs.append((path, _load_sbom(path)))
        except VexInvalid as exc:
            errors.append(exc.reason)

    # Document-shape errors are per-doc and also collected, so one bad
    # --vex input never masks another (rc1 prints every reason).
    for path, doc in vex_docs:
        try:
            normalize_vex_doc(doc, path)
        except VexInvalid as exc:
            errors.append(exc.reason)

    if errors:
        for reason in sorted(errors):
            print("vex service error: %s" % reason)
        return 1

    specs: list = []
    for vid in args.vulnerability:
        specs.append(("vulnerability", vid))
    for ref in args.component:
        specs.append(("component", ref))
    if args.status:
        specs.append(("status", args.status))

    # Row junk is annotated into skips[] by build(); document-level shape
    # errors were already collected above.  Keep a defensive catch so a
    # build-time VexInvalid can never escape as a traceback.
    try:
        doc_out = build(vex_docs, sbom_docs, specs, as_of=args.as_of)
    except VexInvalid as exc:
        print("vex service error: %s" % exc.reason)
        return 1

    out = Path(args.out)
    text = json.dumps(doc_out, sort_keys=True, indent=2,
                      ensure_ascii=True) + "\n"
    out.write_text(text, encoding="utf-8", newline="\n")
    stats = doc_out["stats"]
    print("vex service: wrote %s (schema %s, %d statements, %d components, "
          "%d conflicts)" % (out, SCHEMA, stats["statements"],
                             stats["components"], stats["conflicts"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
