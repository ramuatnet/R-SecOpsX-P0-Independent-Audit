"""T-6.4: graph link derivation (pure stdlib).

Six edge families, every edge explainable with evidence (ground rule
11):

  host_ip           external host address == resource public_ip;
  bucket_name       external storage name == cloud storage resource,
                    provider-mapped (aws_s3->aws, gcs->gcp,
                    azure_blob->azure) -- a same-named bucket on
                    another cloud is a DIFFERENT bucket, never linked;
  finding_mention    a resource identifier appears as a whole token in
                    the code-finding text.  Token boundaries exclude
                    alphanumeric AND hyphen, so "acme" never matches
                    inside "acme-prod" or "webserver";
  iam_subject       IAM finding subject == IAM principal ARN;
  cis_subject       cloud CIS finding resource_id == resource id;
  identity          cloud identity resource ARN == IAM principal ARN.

Caps (MAX_EDGES, MAX_IDENTIFIERS_PER_RESOURCE) surface as skip rows,
never silent drops.  Deterministic: edges sorted (from, to, kind).
"""
from __future__ import annotations

import re

from analysis.graph import model

_PROVIDERS = {"aws_s3": "aws", "gcs": "gcp", "azure_blob": "azure"}


def _token_match(haystack: str, ident: str) -> bool:
    """Whole-token match: boundaries are non-alphanumeric AND non-hyphen
    so an identifier never matches as a substring of a longer token."""
    pattern = (r"(?<![a-z0-9-])" + re.escape(ident.lower())
               + r"(?![a-z0-9-])")
    return re.search(pattern, haystack) is not None


def identifiers_for(res: dict) -> list[str]:
    """Resource identifiers in fixed order (rid, name, public_ip, arn),
    empty/ABSENT/short values dropped, deduped."""
    attrs = res.get("attrs") or {}
    out: list[str] = []
    for key in ("rid", "name", "public_ip", "arn"):
        val = str(attrs.get(key) or "")
        if (not val or val == model.ABSENT
                or len(val) < model.MIN_IDENT_LEN):
            continue
        if val not in out:
            out.append(val)
    return out


def derive_edges(external: list[dict], resources: list[dict],
                 finding_index: list[dict]) -> tuple[list[dict],
                                                     list[dict]]:
    """(edges, skips), sorted, every edge explainable."""
    skips: list[dict] = []
    edges: list[dict] = []

    def add(frm: str, to: str, kind: str, evidence: dict,
            explanation: str) -> None:
        edges.append({"from": frm, "to": to, "kind": kind,
                      "evidence": evidence, "explanation": explanation})

    res_by_id = {n["id"]: n for n in resources}

    # -- external host -> resource (shared public IP) --------------------
    for host in external:
        if host.get("subkind") != "host":
            continue
        for addr in (host.get("attrs") or {}).get("addresses") or []:
            for res in resources:
                if (res.get("attrs") or {}).get("public_ip") == addr:
                    add(host["id"], res["id"], "host_ip",
                        {"matched_ip": addr},
                        f"External host {host['label']} resolves to "
                        f"{addr}, which is the public IP of resource "
                        f"{res['label']}.")

    # -- external storage -> cloud bucket (provider-scoped name) ---------
    for node in external:
        if node.get("subkind") != "storage":
            continue
        attrs = node.get("attrs") or {}
        asm_provider = str(attrs.get("provider") or "")
        cloud_provider = _PROVIDERS.get(asm_provider)
        name = str(attrs.get("name") or "")
        if not cloud_provider or not name:
            continue
        for res in resources:
            rattrs = res.get("attrs") or {}
            if (rattrs.get("provider") == cloud_provider
                    and rattrs.get("type") == "storage"
                    and name in (rattrs.get("rid"), rattrs.get("name"))):
                add(node["id"], res["id"], "bucket_name",
                    {"name": name, "asm_provider": asm_provider,
                     "cloud_provider": cloud_provider,
                     "public": bool(attrs.get("public")),
                     "posture": str(attrs.get("posture") or "")},
                    f"Externally probed bucket {node['label']} matches "
                    f"cloud storage resource {res['label']} "
                    f"(observed {attrs.get('posture') or 'unknown'}).")

    # -- resource -> code finding (identifier token in finding text) -----
    code_entries = [e for e in finding_index
                    if e.get("source") == "code"]
    for res in resources:
        idents = identifiers_for(res)
        if len(idents) > model.MAX_IDENTIFIERS_PER_RESOURCE:
            skips.append(
                {"stage": "graph", "target": res["id"],
                 "reason": f"cap_identifiers_"
                           f"{model.MAX_IDENTIFIERS_PER_RESOURCE}",
                 "detail": {"total": len(idents)}})
            idents = idents[:model.MAX_IDENTIFIERS_PER_RESOURCE]
        for entry in code_entries:
            haystack = entry.get("haystack") or ""
            matched = sorted(i for i in idents
                             if i.lower() in haystack
                             and _token_match(haystack, i))
            if matched:
                add(res["id"], entry["id"], "finding_mention",
                    {"identifiers": matched, "finding": entry["id"]},
                    f"Code finding {entry['id']} references resource "
                    f"{res['label']} via identifier(s) "
                    f"{', '.join(matched)}.")

    # -- IAM / CIS findings attach to their subject resource -------------
    for entry in finding_index:
        source = entry.get("source")
        if source == "iam":
            subject = str(entry.get("subject") or "")
            res = res_by_id.get(f"res:iam:{subject}")
            if subject and res is not None:
                add(res["id"], entry["id"], "iam_subject",
                    {"subject": subject,
                     "check_id": str(entry.get("check_id") or "")},
                    f"IAM finding {entry['id']} is raised against "
                    f"principal {res['label']}.")
        elif source == "cis":
            rid = str(entry.get("resource_id") or "")
            provider = str(entry.get("provider") or "")
            for res in resources:
                rattrs = res.get("attrs") or {}
                if (rid and rattrs.get("rid") == rid
                        and (not provider
                             or rattrs.get("provider") == provider)):
                    add(res["id"], entry["id"], "cis_subject",
                        {"resource_id": rid,
                         "check_id": str(entry.get("check_id") or "")},
                        f"Cloud finding {entry['id']} is raised "
                        f"against resource {res['label']}.")
                    break

    # -- cloud identity <-> IAM principal (same ARN) ---------------------
    for res in resources:
        attrs = res.get("attrs") or {}
        arn = str(attrs.get("arn") or "")
        if attrs.get("type") == "identity" and arn:
            other = res_by_id.get(f"res:iam:{arn}")
            if other is not None:
                add(res["id"], other["id"], "identity", {"arn": arn},
                    f"Cloud identity resource {res['label']} is the "
                    f"IAM principal {other['label']}.")

    edges.sort(key=lambda e: (e["from"], e["to"], e["kind"]))
    if len(edges) > model.MAX_EDGES:
        skips.append({"stage": "graph", "target": "edges",
                      "reason": f"cap_edges_{model.MAX_EDGES}",
                      "detail": {"total": len(edges)}})
        edges = edges[:model.MAX_EDGES]
    skips.sort(key=lambda s: (str(s.get("stage", "")),
                              str(s.get("target", "")),
                              str(s.get("reason", ""))))
    return edges, skips
