"""T-6.3: privilege-escalation graph (pure stdlib).

task.md names ``petgraph`` for escalation paths.  ``petgraph`` is NOT adopted:
the offline no-required-deps invariant outranks a graph
library, exactly as in scanner/taint_interproc.py (T-2.1 precedent) --
the whole graph here is a dict of tuples plus a bounded BFS.

Nodes are principals (user/role ARNs) plus a virtual ``admin`` node.
Edges are observed capability transfers, each with a primitive label:

  assume-role                sts:AssumeRole covers the role AND the
                             role's trust policy accepts the principal
                             (conditions are NOT evaluated; the edge is
                             marked ``conditioned`` and disclosed);
  passrole-run               iam:PassRole covers the role AND the
                             principal holds a compute-creation action;
  impersonate-access-key     iam:CreateAccessKey covers the user;
  impersonate-login-profile  iam:Update/CreateLoginProfile covers the
                             user;
  wildcard-admin             Allow Action * on Resource *;
  self-attach-policy/role    attach/put policy covering the principal
                             itself;
  policy-version-takeover    CreatePolicyVersion+SetDefaultPolicyVersion
                             on one statement covering a managed policy
                             attached to the principal.

Bounded: MAX_PRINCIPALS (build), MAX_DEPTH (search); both disclosed as
skips, never silent.  Deterministic: sorted nodes/edges/neighbours.
"""
from __future__ import annotations

import fnmatch
from collections import deque

from analysis.iam import policy

MAX_PRINCIPALS = 500
MAX_DEPTH = 6

COMPUTE_ACTIONS = ("lambda:createfunction", "ec2:runinstances",
                   "cloudformation:createstack", "glue:createdevendpoint",
                   "sagemaker:createnotebookinstance",
                   "emr:addinstanceclusters", "ecs:runtask",
                   "batch:submitjob")


def _covering(eff: dict, action: str) -> list[dict]:
    """Allow statements granting ``action`` (wildcard patterns match)."""
    out = []
    for s in eff.get("allow_stmts", ()):
        if s["actions"] and any(fnmatch.fnmatchcase(action, p)
                                for p in s["actions"]):
            out.append(s)
        elif (not s["actions"] and s["not_actions"]
              and action not in s["not_actions"]):
            out.append(s)
    return out


def _res_covers(stmt: dict, target: str) -> bool:
    return any(fnmatch.fnmatchcase(target, r)
               for r in stmt.get("resources", ()))


def _covers(eff: dict, action: str, target: str | None = None) -> bool:
    stmts = _covering(eff, action)
    if target is None:
        return bool(stmts)
    return any(_res_covers(s, target) for s in stmts)


def _trust_accepts(trust, principal_arn: str,
                   account: str | None) -> tuple[bool, bool]:
    """Does the role trust policy accept this principal?
    -> (accepts, conditioned).  Conditions are not evaluated."""
    te = policy.trust_entries(trust)
    if te["anonymous"]:
        return True, te["condition"]
    for entry in te["aws"]:
        if entry == principal_arn:
            return True, te["condition"]
        if account and entry == account and entry.isdigit():
            return True, te["condition"]
        if account and entry == f"arn:aws:iam::{account}:root":
            return True, te["condition"]
        if (account and entry.endswith(":root")
                and policy.account_of(entry) == account):
            return True, te["condition"]
    return False, te["condition"]


def build_graph(model: dict, eff: dict) -> dict:
    """Adjacency graph over principals (+ virtual admin node)."""
    principals = sorted(model.get("principals", ()),
                        key=lambda p: p["arn"])
    skips: list[dict] = []
    if len(principals) > MAX_PRINCIPALS:
        skips.append({"stage": "iam", "target": "graph",
                      "reason": f"principal_cap_{MAX_PRINCIPALS}",
                      "detail": {"total": len(principals)}})
        principals = principals[:MAX_PRINCIPALS]
    account = model.get("account_id")
    edges: set[tuple] = set()

    def add(frm: str, to: str, label: str, conditioned: bool = False) -> None:
        edges.add((frm, to, label, bool(conditioned)))

    for p in principals:
        e = eff.get(p["arn"], {})
        allow = e.get("allow", set())
        stmts = e.get("allow_stmts", ())
        # -- admin edges ------------------------------------------------
        if ("*" in allow and any("*" in s["actions"] and "*" in s["resources"]
                                 for s in stmts)):
            add(p["arn"], "admin", "wildcard-admin")
        attach = (("iam:attachuserpolicy", "iam:putuserpolicy")
                  if p["kind"] == "user" else
                  ("iam:attachrolepolicy", "iam:putrolepolicy"))
        label = ("self-attach-policy" if p["kind"] == "user"
                 else "self-attach-role")
        for act in attach:
            if any(_res_covers(s, p["arn"]) for s in _covering(e, act)):
                add(p["arn"], "admin", label)
                break
        for s in stmts:
            if any(fnmatch.fnmatchcase("iam:createpolicyversion", a)
                   for a in s["actions"]) and any(
                    fnmatch.fnmatchcase("iam:setdefaultpolicyversion", a)
                    for a in s["actions"]):
                if any(_res_covers(s, m) for m in p.get("managed") or ()):
                    add(p["arn"], "admin", "policy-version-takeover")
                    break
        # -- transfers to other principals ------------------------------
        for q in principals:
            if q["arn"] == p["arn"]:
                continue
            if q["kind"] == "role":
                if _covers(e, "sts:assumerole", q["arn"]):
                    ok, cond = _trust_accepts(q.get("trust"), p["arn"],
                                              account)
                    if ok:
                        add(p["arn"], q["arn"], "assume-role", cond)
                if (_covers(e, "iam:passrole", q["arn"])
                        and any(_covers(e, c) for c in COMPUTE_ACTIONS)):
                    add(p["arn"], q["arn"], "passrole-run")
            else:
                if _covers(e, "iam:createaccesskey", q["arn"]):
                    add(p["arn"], q["arn"], "impersonate-access-key")
                if (_covers(e, "iam:updateloginprofile", q["arn"])
                        or _covers(e, "iam:createloginprofile", q["arn"])):
                    add(p["arn"], q["arn"], "impersonate-login-profile")

    edge_rows = [{"from": a, "to": b, "label": c, "conditioned": d}
                 for a, b, c, d in sorted(edges)]
    nodes = sorted([p["arn"] for p in principals] + ["admin"])
    return {"nodes": nodes, "edges": edge_rows, "skips": skips}


def find_paths(graph: dict) -> dict:
    """Shortest admin-reaching path per principal (bounded BFS).

    Deterministic: adjacency and starts are sorted, so the first path
    found is stable run-to-run."""
    adj: dict[str, list] = {}
    for e in graph["edges"]:
        adj.setdefault(e["from"], []).append((e["to"], e["label"]))
    for key in adj:
        adj[key].sort()
    paths: list[dict] = []
    skips: list[dict] = []
    for start in sorted(n for n in graph["nodes"] if n != "admin"):
        queue = deque([(start, [start], [])])
        seen = {start}
        found = None
        truncated = False
        while queue:
            node, npath, elabels = queue.popleft()
            if node == "admin":
                found = (npath, elabels)
                break
            if len(elabels) >= MAX_DEPTH:
                if adj.get(node):
                    truncated = True
                continue
            for nxt, label in adj.get(node, ()):
                if nxt in seen:
                    continue
                seen.add(nxt)
                queue.append((nxt, npath + [nxt], elabels + [label]))
        if found:
            paths.append({"principal": start, "path": found[0],
                          "edges": found[1]})
        elif truncated:
            skips.append({"stage": "iam", "target": start,
                          "reason": f"depth_cap_{MAX_DEPTH}"})
    return {"paths": paths, "skips": skips}
