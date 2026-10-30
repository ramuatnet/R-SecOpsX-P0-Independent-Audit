"""T-6.4: unified asset graph -- nodes (pure stdlib).

Joins three offline artifacts into one node set:

  external  rsecopsx.asm_inventory/v1   hosts + storage probes
  resource  rsecopsx.cloud_posture/v1   inventory resources
            rsecopsx.iam_analysis/v1    IAM principals
  finding   code findings (scan payload rows, source=code)
            IAM findings attached to principals (source=iam)
            cloud CIS findings attached to resources (source=cis)

Attack paths are exactly the task.md chain "external asset ->
internal resource -> code finding" (see paths.py); IAM/CIS findings
attach as nodes+edges but are not path termini.  Every node carries
compact evidence attrs; caps surface as skip rows, never silent
drops.  Deterministic: sorted everywhere.
"""
from __future__ import annotations

import json

from analysis.cloud.model import ABSENT

SCHEMA = "rsecopsx.asset_graph/v1"
MAX_NODES = 5000
MAX_EDGES = 20000
MAX_FINDINGS = 10000
MAX_IDENTIFIERS_PER_RESOURCE = 12
MIN_IDENT_LEN = 3
MAX_HAYSTACK = 8000


def _as_str(value) -> str:
    return "" if value is None else str(value)


def external_nodes(asm_doc) -> tuple[list[dict], list[dict]]:
    """ASM hosts + storage hits -> external nodes."""
    nodes: list[dict] = []
    skips: list[dict] = []
    if not isinstance(asm_doc, dict):
        return nodes, skips
    for h in asm_doc.get("hosts") or []:
        if not isinstance(h, dict):
            continue
        name = _as_str(h.get("host")).strip().lower()
        if not name:
            continue
        ports_doc = h.get("ports") if isinstance(h.get("ports"), dict) \
            else {}
        open_ports = sorted({int(p["port"])
                             for p in ports_doc.get("open") or []
                             if isinstance(p, dict)
                             and str(p.get("port", "")).isdigit()})
        techs = sorted({_as_str(t.get("sig_id"))
                        for t in h.get("techs") or []
                        if isinstance(t, dict) and t.get("sig_id")})
        nodes.append({
            "id": f"ext:host:{name}",
            "kind": "external",
            "subkind": "host",
            "label": name,
            "attrs": {
                "addresses": sorted({_as_str(a)
                                     for a in h.get("addresses") or []}),
                "open_ports": open_ports,
                "admin": sorted({_as_str(a)
                                 for a in h.get("admin") or []}),
                "techs": techs,
                "takeover": h.get("takeover"),
            },
        })
    storage = (asm_doc.get("storage") or {}).get("results") \
        if isinstance(asm_doc.get("storage"), dict) else None
    for r in storage or []:
        if not isinstance(r, dict):
            continue
        provider = _as_str(r.get("provider"))
        name = _as_str(r.get("name"))
        if not provider or not name:
            continue
        nodes.append({
            "id": f"ext:storage:{provider}:{name}",
            "kind": "external",
            "subkind": "storage",
            "label": f"{provider}:{name}",
            "attrs": {
                "provider": provider,
                "name": name,
                "public": bool(r.get("public")),
                "posture": _as_str(r.get("posture")),
                "evidence": _as_str(r.get("evidence")),
            },
        })
    nodes.sort(key=lambda n: n["id"])
    return nodes, skips


def resource_nodes(cloud_doc, iam_doc) -> tuple[list[dict], list[dict]]:
    """Cloud inventory resources + IAM principals -> resource nodes."""
    nodes: list[dict] = []
    skips: list[dict] = []
    if isinstance(cloud_doc, dict):
        inventory = cloud_doc.get("inventory")
        rows = inventory.get("resources") \
            if isinstance(inventory, dict) else None
        for r in rows or []:
            if not isinstance(r, dict):
                continue
            provider = _as_str(r.get("provider"))
            rtype = _as_str(r.get("type"))
            rid = _as_str(r.get("id"))
            if not provider or not rtype or not rid:
                continue
            config = r.get("config") if isinstance(r.get("config"), dict) \
                else {}
            nodes.append({
                "id": f"res:{provider}:{rtype}:{rid}",
                "kind": "resource",
                "subkind": rtype,
                "label": f"{provider}/{rtype}:{rid}",
                "attrs": {
                    "provider": provider,
                    "type": rtype,
                    "service": _as_str(r.get("service")),
                    "region": _as_str(r.get("region")),
                    "rid": rid,
                    "name": _as_str(r.get("name")),
                    "public_ip": _as_str(config.get("public_ip")),
                    "arn": _as_str(config.get("arn")),
                },
            })
    if isinstance(iam_doc, dict):
        for p in iam_doc.get("principals") or []:
            if not isinstance(p, dict):
                continue
            arn = _as_str(p.get("arn"))
            if not arn:
                continue
            nodes.append({
                "id": f"res:iam:{arn}",
                "kind": "resource",
                "subkind": "principal",
                "label": f"iam/principal:{arn}",
                "attrs": {
                    "provider": "iam",
                    "type": "principal",
                    "service": "iam",
                    "region": "",
                    "rid": arn,
                    "name": _as_str(p.get("name")),
                    "public_ip": "",
                    "arn": arn,
                },
            })
    nodes.sort(key=lambda n: n["id"])
    return nodes, skips


def _haystack(row: dict) -> str:
    """Lowercased, size-capped text a resource identifier can match in."""
    evidence = row.get("evidence")
    try:
        ev = json.dumps(evidence, sort_keys=True,
                        default=str) if evidence else ""
    except (TypeError, ValueError):
        ev = _as_str(evidence)
    parts = [row.get("title"), row.get("rule_id"), row.get("vuln_type"),
             row.get("description"), row.get("snippet"), row.get("file"),
             ev]
    return " ".join(_as_str(p) for p in parts if p).lower()[:MAX_HAYSTACK]


def finding_nodes(code_findings, iam_doc,
                  cloud_doc) -> tuple[list[dict], list[dict], list[dict]]:
    """(nodes, index, skips).  Index rows back link derivation: code
    entries carry the haystack; iam/cis entries carry subject /
    resource_id.  Invalid rows are annotated, never silently dropped."""
    skips: list[dict] = []
    nodes: list[dict] = []
    index: list[dict] = []
    kept: list[dict] = []
    invalid = 0
    for row in code_findings or []:
        if isinstance(row, dict):
            kept.append(row)
        else:
            invalid += 1
    if invalid:
        skips.append({"stage": "graph", "target": "findings",
                      "reason": "finding_rows_not_objects",
                      "detail": {"count": invalid}})
    if len(kept) > MAX_FINDINGS:
        skips.append({"stage": "graph", "target": "findings",
                      "reason": f"cap_findings_{MAX_FINDINGS}",
                      "detail": {"total": len(kept)}})
        kept = kept[:MAX_FINDINGS]
    seen: set[str] = set()

    def _add(node: dict, entry: dict) -> None:
        base = node["id"]
        nid = base
        n = 2
        while nid in seen:
            nid = f"{base}#{n}"
            n += 1
        seen.add(nid)
        node["id"] = nid
        nodes.append(node)
        index.append(dict(entry, id=nid))

    for row in kept:
        rule_id = _as_str(row.get("rule_id"))
        file = _as_str(row.get("file"))
        try:
            line = int(row.get("line") or 0)
        except (TypeError, ValueError):
            line = 0
        _add({
            "id": f"find:code:{rule_id}:{file}:{line}",
            "kind": "finding",
            "subkind": "code",
            "label": f"{rule_id or 'finding'}@{file or '?'}:{line}",
            "attrs": {"source": "code", "rule_id": rule_id,
                      "file": file, "line": line,
                      "severity": _as_str(row.get("severity")),
                      "title": _as_str(row.get("title"))},
        }, {"source": "code", "haystack": _haystack(row)})
    if isinstance(iam_doc, dict):
        for row in iam_doc.get("findings") or []:
            if not isinstance(row, dict) or row.get("kind") != "finding":
                continue
            check_id = _as_str(row.get("check_id"))
            subject = _as_str(row.get("subject"))
            _add({
                "id": f"find:iam:{check_id}:{subject}",
                "kind": "finding",
                "subkind": "iam",
                "label": check_id,
                "attrs": {"source": "iam", "check_id": check_id,
                          "subject": subject,
                          "explanation":
                              _as_str(row.get("explanation"))},
            }, {"source": "iam", "subject": subject,
                "check_id": check_id})
    if isinstance(cloud_doc, dict):
        for row in cloud_doc.get("findings") or []:
            if not isinstance(row, dict) or row.get("kind") != "finding":
                continue
            check_id = _as_str(row.get("check_id"))
            rid = _as_str(row.get("resource_id"))
            provider = _as_str(row.get("provider"))
            _add({
                "id": f"find:cis:{check_id}:{rid}",
                "kind": "finding",
                "subkind": "cis",
                "label": check_id,
                "attrs": {"source": "cis", "check_id": check_id,
                          "resource_id": rid, "provider": provider,
                          "explanation":
                              _as_str(row.get("explanation"))},
            }, {"source": "cis", "resource_id": rid,
                "provider": provider, "check_id": check_id})
    nodes.sort(key=lambda n: n["id"])
    index.sort(key=lambda e: e["id"])
    return nodes, index, skips
