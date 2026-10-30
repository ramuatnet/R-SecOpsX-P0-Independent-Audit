"""T-6.3: IAM judgement registry (pure).

Five families from task.md, every judgement explainable (ground rule
11) and every missing input a machine-readable gap, never a pass:

  iam.over_permissive      Allow with Action * (or NotAction) on
                           Resource *;
  iam.wildcard_actions     wildcard action patterns, graded
                           (full/service/prefix), bounded listing;
  iam.cross_account_trust  trust policy principals outside the account
                           (or anonymous "*"); service principals are
                           fine; without an account id the check is a
                           gap, not a guess;
  iam.unused_permissions   granted services never present in the
                           last-accessed usage feed; absent feed is a
                           gap (insufficient_data);
  iam.escalation_path      graph paths to the virtual admin node
                           (see escalation.py for the primitive table).

Graph/parse caps surface as gap rows (kind=gap, reason=cap_*) so a
truncated analysis can never read as a clean one.
"""
from __future__ import annotations

from datetime import datetime

from analysis.iam import escalation, policy

MAX_WILDCARDS_LISTED = 50
MAX_UNUSED_LISTED = 50


def _finding(check_id: str, subject: str, explanation: str,
             evidence: dict, remediation: str) -> dict:
    return {"kind": "finding", "check_id": check_id, "subject": subject,
            "explanation": explanation, "evidence": evidence,
            "remediation": remediation}


def _gap(check_id: str, target: str,
         reason: str = "insufficient_data") -> dict:
    return {"kind": "gap", "check_id": check_id, "target": target,
            "reason": reason}


def _over_permissive(eff: dict) -> list[dict]:
    out = []
    for arn in sorted(eff):
        for s in eff[arn]["allow_stmts"]:
            full = "*" in s["actions"] or bool(s["not_actions"])
            if not full or "*" not in s["resources"]:
                continue
            out.append(_finding(
                "iam.over_permissive", arn,
                "An Allow statement grants the wildcard action set "
                "(Action * or NotAction) over Resource *, i.e. "
                "administrator-equivalent access"
                + (" with a condition applied (condition semantics "
                   "are not evaluated here)" if s["condition"] else "")
                + ".",
                {"policy": s.get("source", ""),
                 "actions": sorted(s["actions"]),
                 "resources": sorted(s["resources"]),
                 "not_action": bool(s["not_actions"]),
                 "conditioned": bool(s["condition"])},
                "Scope the statement to the specific actions and "
                "resources the workload needs; prefer a permissions "
                "boundary for privilege containment."))
    return out


def _wildcard_actions(eff: dict) -> list[dict]:
    out = []
    for arn in sorted(eff):
        wild = eff[arn]["wildcards"]
        if not wild:
            continue
        listed = wild[:MAX_WILDCARDS_LISTED]
        out.append(_finding(
            "iam.wildcard_actions", arn,
            "Granted action patterns contain wildcards; each one "
            "covers more surface than the workload should need.",
            {"wildcards": listed,
             "truncated": len(wild) > MAX_WILDCARDS_LISTED},
            "Replace wildcard patterns with the explicit action "
            "list actually required."))
    return out


def _cross_account_trust(model: dict) -> tuple[list[dict], list[dict]]:
    out: list[dict] = []
    gaps: list[dict] = []
    account = model.get("account_id")
    for p in sorted(model.get("principals", ()),
                    key=lambda p: p["arn"]):
        if not p.get("trust"):
            continue
        te = policy.trust_entries(p["trust"])
        foreign = sorted({acct for entry in te["aws"]
                          for acct in [entry if entry.isdigit()
                                       and len(entry) == 12
                                       else policy.account_of(entry)]
                          if acct and account and acct != account})
        if te["anonymous"]:
            out.append(_finding(
                "iam.cross_account_trust", p["arn"],
                "The trust policy allows the anonymous principal "
                '("*"): any AWS principal can assume this role subject '
                "to its identity policies.",
                {"anonymous": True, "conditioned": te["condition"]},
                "Replace the wildcard principal with the specific "
                "accounts or roles that need to assume this role."))
        elif foreign:
            out.append(_finding(
                "iam.cross_account_trust", p["arn"],
                "The trust policy accepts principals from account(s) "
                f"{', '.join(foreign)}, outside this account"
                + (" (a condition is present but its semantics are "
                   "not evaluated here)" if te["condition"] else "")
                + ".",
                {"foreign_accounts": foreign,
                 "conditioned": te["condition"]},
                "Confirm the cross-account relationship is intended; "
                "scope the trust policy and add explicit conditions "
                "(ExternalId, PrincipalOrgID) where possible."))
        elif te["aws"] and not account:
            gaps.append(_gap("iam.cross_account_trust", p["arn"]))
    return out, gaps


def _unused_permissions(model: dict, eff: dict) -> tuple[list[dict],
                                                         list[dict]]:
    out: list[dict] = []
    usage = model.get("usage")
    if not isinstance(usage, dict):
        return out, [_gap("iam.unused_permissions", "usage")]
    for arn in sorted(eff):
        allow = eff[arn]["allow"]
        granted = {a.split(":", 1)[0] for a in allow if ":" in a}
        used = {str(s).lower() for s in usage.get(arn, ())}
        unused = sorted(granted - used)
        if not unused:
            continue
        evidence = {"unused_services": unused[:MAX_UNUSED_LISTED],
                    "truncated": len(unused) > MAX_UNUSED_LISTED}
        if "*" in allow:
            evidence["full_wildcard"] = True
        out.append(_finding(
            "iam.unused_permissions", arn,
            "Service prefixes granted to this principal never appear "
            "in the last-accessed usage feed.",
            evidence,
            "Remove the unused service permissions (or convert them "
            "to a temporary elevation flow)."))
    return out, []


def run_checks(model: dict, as_of: datetime) -> tuple[list[dict],
                                                      list[dict]]:
    """(findings, gaps), sorted, every finding explainable."""
    eff = policy.effective_for(model)
    findings: list[dict] = []
    gaps: list[dict] = []
    findings += _over_permissive(eff)
    findings += _wildcard_actions(eff)
    f, g = _cross_account_trust(model)
    findings += f
    gaps += g
    f, g = _unused_permissions(model, eff)
    findings += f
    gaps += g
    # escalation graph (caps disclosed as gaps, never silent)
    graph = escalation.build_graph(model, eff)
    paths = escalation.find_paths(graph)
    for s in graph["skips"] + paths["skips"]:
        gaps.append(_gap("iam.escalation_graph", s.get("target", ""),
                         s.get("reason", "insufficient_data")))
    for p in paths["paths"]:
        findings.append(_finding(
            "iam.escalation_path", p["principal"],
            "This principal can reach administrator-equivalent access "
            f"via the {p['edges'][-1]!r} primitive "
            f"({' -> '.join(p['path'])}).",
            {"path": p["path"], "edges": p["edges"],
             "primitive": p["edges"][-1]},
            "Break the chain: remove the intermediate grant (pass "
            "role, assume role, self-attach) that turns the current "
            "permissions into admin."))
    findings.sort(key=lambda f: (f["check_id"], f["subject"],
                                 f["explanation"]))
    gaps.sort(key=lambda g: (g["check_id"], g.get("target", ""),
                             g["reason"]))
    return findings, gaps
