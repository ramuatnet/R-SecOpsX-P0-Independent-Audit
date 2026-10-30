"""T-6.4: attack-path enumeration (pure stdlib).

task.md: "External asset -> internal resource -> code finding.  This
produces real attack paths."  A path is exactly two hops:

  ext --(host_ip | bucket_name)--> resource
      --(finding_mention)--> code finding

IAM/CIS findings attach to the graph (edges in links.py) but are NOT
path termini -- the chain ends at CODE findings per the task.md
wording; disclosed here rather than silently narrowed.  Bounded
(MAX_PATHS) with a skip row; sorted by path tuple so two runs emit
identical lists.
"""
from __future__ import annotations

MAX_PATHS = 500

_EXT_KINDS = ("host_ip", "bucket_name")


def enumerate_paths(external: list[dict], resources: list[dict],
                    finding_index: list[dict],
                    edges: list[dict]) -> tuple[list[dict], list[dict]]:
    """(attack_paths, skips), sorted by node tuple, capped."""
    skips: list[dict] = []
    ext_ids = {n["id"] for n in external}
    res_ids = {n["id"] for n in resources}
    code_ids = {e["id"] for e in finding_index
                if e.get("source") == "code"}
    labels = {n["id"]: n["label"]
              for n in list(external) + list(resources)}
    first: dict[str, list[dict]] = {}
    second: dict[str, list[dict]] = {}
    for e in edges:
        if (e["kind"] in _EXT_KINDS and e["from"] in ext_ids
                and e["to"] in res_ids):
            first.setdefault(e["from"], []).append(e)
        elif (e["kind"] == "finding_mention" and e["from"] in res_ids
                and e["to"] in code_ids):
            second.setdefault(e["from"], []).append(e)
    paths: list[dict] = []
    for ext in sorted(first):
        for e1 in sorted(first[ext], key=lambda e: (e["to"], e["kind"])):
            for e2 in sorted(second.get(e1["to"], ()),
                             key=lambda e: (e["to"], e["kind"])):
                matched = sorted(e2["evidence"].get("identifiers", ()))
                hop1 = e1["evidence"].get("matched_ip") \
                    or e1["evidence"].get("name") or ""
                paths.append({
                    "path": [ext, e1["to"], e2["to"]],
                    "edges": [e1["kind"], e2["kind"]],
                    "explanation": (
                        f"External asset {labels.get(ext, ext)} links "
                        f"to resource {labels.get(e1['to'], e1['to'])} "
                        f"via {e1['kind']}"
                        + (f" (matched {hop1})" if hop1 else "")
                        + f"; code finding {e2['to']} references that "
                        f"resource via {', '.join(matched)}."),
                    "evidence": {"identifiers": matched,
                                 "matched": e1["evidence"]},
                })
    paths.sort(key=lambda p: tuple(p["path"]))
    if len(paths) > MAX_PATHS:
        skips.append({"stage": "graph", "target": "attack_paths",
                      "reason": f"cap_paths_{MAX_PATHS}",
                      "detail": {"total": len(paths)}})
        paths = paths[:MAX_PATHS]
    return paths, skips
