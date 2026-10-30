"""T-6.4: asset-graph ingest + CLI.

Offline by construction: file reads only -- no network, no
credentials (pinned by a source-level test in
tests/test_t64_asset_graph.py).  ``collect_graph`` loads the four
optional artifacts (ASM inventory, cloud posture, IAM analysis, code
findings); any failure is a machine-readable skip, never a raise, and
the join still runs over whatever was obtained.  Default run (no
inputs) is zero-I/O and byte-identical.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone

from analysis.asm.collect import ASM_SCHEMA
from analysis.cloud.connect import SCHEMA as CLOUD_SCHEMA
from analysis.graph import links, model, paths as gpaths
from analysis.iam.connect import SCHEMA as IAM_SCHEMA

MAX_INPUT_BYTES = 64 * 1024 * 1024

_EXPECTED = (("asm", ASM_SCHEMA), ("cloud", CLOUD_SCHEMA),
             ("iam", IAM_SCHEMA))
_FILE_STAGES = ("asm", "cloud", "iam", "findings")


def _now(as_of: datetime | None) -> datetime:
    dt = as_of or datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def build_graph(asm: dict | None = None, cloud: dict | None = None,
                iam: dict | None = None, findings: list | None = None,
                as_of: datetime | None = None) -> dict:
    """Pure join: parsed artifacts -> rsecopsx.asset_graph/v1.

    ``findings`` is a list of code-finding dicts (the scan payload's
    rows); asm/cloud/iam are the parsed artifacts or None.  Sorted
    everywhere; identical inputs -> byte-identical output.
    """
    dt = _now(as_of)
    skips: list[dict] = []
    ext_nodes, s = model.external_nodes(asm)
    skips += s
    res_nodes, s = model.resource_nodes(cloud, iam)
    skips += s
    find_nodes, index, s = model.finding_nodes(findings, iam, cloud)
    skips += s
    nodes = ext_nodes + res_nodes + find_nodes
    if len(nodes) > model.MAX_NODES:
        skips.append({"stage": "graph", "target": "nodes",
                      "reason": f"cap_nodes_{model.MAX_NODES}",
                      "detail": {"total": len(nodes)}})
        nodes = nodes[:model.MAX_NODES]
        kept_ids = {n["id"] for n in nodes}
        ext_nodes = [n for n in ext_nodes if n["id"] in kept_ids]
        res_nodes = [n for n in res_nodes if n["id"] in kept_ids]
        index = [e for e in index if e["id"] in kept_ids]
    nodes.sort(key=lambda n: n["id"])
    edge_rows, s = links.derive_edges(ext_nodes, res_nodes, index)
    skips += s
    path_rows, s = gpaths.enumerate_paths(ext_nodes, res_nodes, index,
                                          edge_rows)
    skips += s
    skips.sort(key=lambda sk: (str(sk.get("stage", "")),
                               str(sk.get("target", "")),
                               str(sk.get("reason", ""))))
    by_kind = {"external": 0, "resource": 0, "finding": 0}
    for n in nodes:
        by_kind[n["kind"]] = by_kind.get(n["kind"], 0) + 1
    return {
        "schema": model.SCHEMA,
        "as_of": dt.astimezone(timezone.utc).isoformat()
                 .replace("+00:00", "Z"),
        "nodes": nodes,
        "edges": edge_rows,
        "attack_paths": path_rows,
        "skips": skips,
        "stats": {"nodes": len(nodes), "edges": len(edge_rows),
                  "attack_paths": len(path_rows),
                  "by_kind": by_kind, "skips": len(skips)},
    }


def _load(path: str, stage: str):
    """(doc_or_None, skip_or_None)."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
    except OSError as exc:
        return None, {"stage": stage, "target": str(path),
                      "reason": f"{type(exc).__name__}: {exc}"[:200]}
    if len(text) > MAX_INPUT_BYTES:
        return None, {"stage": stage, "target": str(path),
                      "reason": f"input_too_large_{MAX_INPUT_BYTES}",
                      "detail": {"bytes": len(text)}}
    try:
        doc = json.loads(text)
    except ValueError as exc:
        return None, {"stage": stage, "target": str(path),
                      "reason": f"JSONDecodeError: {exc}"[:200]}
    return doc, None


def collect_graph(files: dict | None = None,
                  as_of: datetime | None = None) -> dict:
    """Load the four optional artifacts and join them.

    ``files`` keys: asm / cloud / iam (rsecopsx artifacts, schema
    checked) / findings (payload dict or bare list).  Missing or
    unloadable inputs are skip rows, never raises.
    """
    files = files or {}
    docs: dict = {"asm": None, "cloud": None, "iam": None}
    findings_rows = None
    skips: list[dict] = []
    for stage, schema in _EXPECTED:
        path = files.get(stage)
        if not path:
            skips.append({"stage": stage, "target": stage,
                          "reason": "not_provided"})
            continue
        doc, skip = _load(path, stage)
        if skip is not None:
            skips.append(skip)
            continue
        if not isinstance(doc, dict) or doc.get("schema") != schema:
            skips.append({"stage": stage, "target": str(path),
                          "reason": "wrong_schema",
                          "detail": {
                              "expected": schema,
                              "got": doc.get("schema")
                                     if isinstance(doc, dict)
                                     else type(doc).__name__}})
            continue
        docs[stage] = doc
    path = files.get("findings")
    if not path:
        skips.append({"stage": "findings", "target": "findings",
                      "reason": "not_provided"})
    else:
        doc, skip = _load(path, "findings")
        if skip is not None:
            skips.append(skip)
        else:
            rows = doc if isinstance(doc, list) else (
                doc.get("findings") if isinstance(doc, dict) else None)
            if isinstance(rows, list):
                findings_rows = rows
            else:
                skips.append({"stage": "findings", "target": str(path),
                              "reason": "bad_findings_shape"})
    graph = build_graph(asm=docs["asm"], cloud=docs["cloud"],
                        iam=docs["iam"], findings=findings_rows,
                        as_of=as_of)
    graph["skips"] = sorted(
        skips + graph["skips"],
        key=lambda sk: (str(sk.get("stage", "")),
                        str(sk.get("target", "")),
                        str(sk.get("reason", ""))))
    graph["stats"]["skips"] = len(graph["skips"])
    return graph


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="python -m analysis.graph.connect",
        description="Build the rsecopsx.asset_graph/v1 artifact from "
                    "offline ASM / cloud / IAM artifacts + code "
                    "findings.  No inputs = offline deterministic run.")
    ap.add_argument("--asm", default=None, help="ASM inventory JSON")
    ap.add_argument("--cloud", default=None, help="cloud posture JSON")
    ap.add_argument("--iam", default=None, help="IAM analysis JSON")
    ap.add_argument("--findings", default=None,
                    help="code findings JSON (payload dict or bare list)")
    ap.add_argument("--as-of", default=None,
                    help="ISO-8601 timestamp (inject for determinism)")
    ap.add_argument("--out", default=None, help="write artifact here")
    args = ap.parse_args(list(argv) if argv is not None else None)
    as_of = None
    if args.as_of:
        try:
            as_of = datetime.fromisoformat(
                str(args.as_of).replace("Z", "+00:00"))
        except ValueError:
            print(f"bad --as-of: {args.as_of!r}", file=sys.stderr)
            return 2
    files = {k: getattr(args, k) for k in _FILE_STAGES
             if getattr(args, k)}
    graph = collect_graph(files=files, as_of=as_of)
    text = json.dumps(graph, indent=2, sort_keys=True) + "\n"
    if args.out:
        with open(args.out, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
    else:
        print(text, end="")
    return 0


if __name__ == "__main__":      # pragma: no cover
    raise SystemExit(main())
