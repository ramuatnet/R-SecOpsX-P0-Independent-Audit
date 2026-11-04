"""T-6.3: IAM policy documents -> normalized grants (pure).

Input is the ``iam:GetAccountAuthorizationDetails`` response shape
(users / groups / roles / customer-managed policies, policy documents
URL-encoded JSON exactly as the query protocol returns them).  Three
tasks, all pure stdlib:

  * ``parse_policy``     -- Statement list -> normalized records
                            (lowercase actions, Condition presence);
  * ``build_model``      -- op pages -> principals / groups / policies
                            (sorted, bounded, caps disclosed);
  * ``effective_for``    -- per-principal effective grants: inline +
                            group + attached managed (customer docs
                            from the capture, AWS-managed from a small
                            EXACT built-in table; anything else is
                            recorded as ``unknown_managed`` -- never
                            silently treated as no access).

Deny subtraction is per-action-string with fnmatch semantics; a
pattern-vs-pattern deny cannot be decided cheaply and is DISCLOSED as
a ``wildcard_deny`` note, never silently applied.
"""
from __future__ import annotations
try:
    from analysis.spans import WINDOW_200
except ImportError:  # FND-03: standalone, repo root not on path
    import sys as _fnd03_sys
    from pathlib import Path as _fnd03_path
    _fnd03_sys.path.insert(0, str(_fnd03_path(__file__).resolve().parents[2]))
    from analysis.spans import WINDOW_200

import fnmatch
import json
import urllib.parse
import xml.etree.ElementTree as ET
from typing import Any

MAX_STATEMENTS_PER_POLICY = 100
MAX_PRINCIPALS = 500

# Cap records from the most recent parse_policy call (disclosure
# surface: the statement cap must never be a silent drop).
LAST_CAPS: list[dict] = []

# AWS managed policies whose documents are exactly representable.
# Anything outside this table and the capture is ``unknown_managed``.
AWS_MANAGED: dict[str, dict] = {
    "arn:aws:iam::aws:policy/AdministratorAccess": {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "*",
                       "Resource": "*"}]},
    "arn:aws:iam::aws:policy/IAMFullAccess": {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "iam:*",
                       "Resource": "*"}]},
}

_KW_CANON = {"Action": "actions", "NotAction": "not_actions",
             "Resource": "resources", "NotResource": "not_resources",
             "Effect": "effect", "Sid": "sid"}


def _as_list(value) -> list:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value]
    return [str(value)]


def classify_action(action: str) -> str:
    """Wildcard tier: full '*' | service 'svc:*' | prefix 'svc:Get*' |
    none."""
    a = str(action).strip().lower()
    if a == "*":
        return "full"
    if a.endswith(":*"):
        return "service"
    if "*" in a or "?" in a:
        return "prefix"
    return "none"


def arn_matches(pattern: str, arn: str) -> bool:
    """IAM-style ARN match (* and ? wildcards, case-sensitive)."""
    return fnmatch.fnmatchcase(str(arn), str(pattern))


def account_of(arn) -> str | None:
    """12-digit account id from an ARN, else None."""
    parts = str(arn).split(":")
    if len(parts) >= 5 and parts[0] == "arn" and parts[4].isdigit():
        return parts[4]
    return None


def _norm_stmt(raw: dict) -> dict:
    actions: list[str] = []
    not_actions: list[str] = []
    resources: list[str] = []
    not_resources: list[str] = []
    effect = "allow"
    sid = ""
    condition = False
    principal = None
    for key, value in raw.items():
        canon = _KW_CANON.get(str(key), None)
        k = canon or str(key)
        if k == "actions":
            actions += [a.lower() for a in _as_list(value)]
        elif k == "not_actions":
            not_actions += [a.lower() for a in _as_list(value)]
        elif k == "resources":
            resources += _as_list(value)
        elif k == "not_resources":
            not_resources += _as_list(value)
        elif k == "effect":
            effect = str(value).strip().lower() or "allow"
        elif k == "sid":
            sid = str(value)
        elif k.lower() == "condition" or k == "Condition":
            condition = True
        elif str(key) in ("Principal", "principal"):
            principal = value
    return {"effect": effect, "actions": actions,
            "not_actions": not_actions, "resources": resources,
            "not_resources": not_resources, "sid": sid,
            "condition": condition, "principal": principal}


def parse_policy(*docs) -> list[dict]:
    """One policy (dict or JSON string) or several -> normalized
    statement records, capped at MAX_STATEMENTS_PER_POLICY with a
    disclosure record in LAST_CAPS."""
    LAST_CAPS.clear()
    out: list[dict] = []
    for doc in docs:
        if isinstance(doc, str):
            try:
                doc = json.loads(urllib.parse.unquote(doc))
            except (ValueError, RecursionError):
                doc = json.loads(doc)
        if not isinstance(doc, dict):
            raise ValueError("policy document is not an object")
        raw_stmts = doc.get("Statement", doc.get("statement", []))
        if isinstance(raw_stmts, dict):
            raw_stmts = [raw_stmts]
        for raw in raw_stmts:
            if len(out) >= MAX_STATEMENTS_PER_POLICY:
                LAST_CAPS.append(
                    {"reason": f"statement_cap_{MAX_STATEMENTS_PER_POLICY}",
                     "dropped": True})
                return out
            if isinstance(raw, dict):
                out.append(_norm_stmt(raw))
    return out


def trust_entries(doc) -> dict:
    """Principal values from a (raw) trust policy:
    {aws: [...], service: [...], federated: [...], anonymous: bool,
     condition: bool}.  Accepts canonical AWS keys."""
    res = {"aws": [], "service": [], "federated": [],
           "anonymous": False, "condition": False}
    if not doc:
        return res
    stmts = doc.get("Statement", doc.get("statement", [])) \
        if isinstance(doc, dict) else []
    if isinstance(stmts, dict):
        stmts = [stmts]
    for raw in stmts:
        if not isinstance(raw, dict):
            continue
        effect = str(raw.get("Effect", raw.get("effect",
                                               "Allow"))).lower()
        if effect != "allow":
            continue
        if raw.get("Condition", raw.get("condition")):
            res["condition"] = True
        principal = raw.get("Principal", raw.get("principal"))
        if principal == "*":
            res["anonymous"] = True
            continue
        if not isinstance(principal, dict):
            continue
        for kind, key in (("aws", "AWS"), ("service", "Service"),
                          ("federated", "Federated")):
            value = principal.get(key, principal.get(key.lower()))
            res[kind] += _as_list(value)
    return res


def _decode_doc(value) -> dict:
    """Policy document as dict: already-decoded JSON, a JSON string, or
    the URL-encoded form the query protocol returns."""
    if isinstance(value, dict):
        return value
    if not isinstance(value, str):
        raise ValueError("policy document is not decodable")
    text = urllib.parse.unquote(value)
    try:
        doc = json.loads(text)
    except (ValueError, RecursionError):
        doc = json.loads(value)
    if not isinstance(doc, dict):
        raise ValueError("policy document is not an object")
    return doc


def _xml(page: str) -> ET.Element:
    root = ET.fromstring(page)
    for el in root.iter():
        if isinstance(el.tag, str):
            el.tag = el.tag.rsplit("}", 1)[-1]
    return root


def _member_docs(member: ET.Element, list_tag: str) -> dict:
    """{PolicyName: doc} from a *PolicyList element."""
    docs: dict[str, dict] = {}
    for m in member.findall(f".//{list_tag}/member"):
        name = m.findtext("PolicyName") or ""
        try:
            docs[name] = _decode_doc(m.findtext("PolicyDocument") or "")
        except (ValueError, RecursionError):
            continue
    return docs


def _attached(member: ET.Element) -> list[str]:
    return [a for a in
            (m.findtext("PolicyArn") or ""
             for m in member.findall(".//AttachedManagedPolicies/member"))
            if a]


def build_model(pages: list[str], usage: dict | None = None) -> dict:
    """GetAccountAuthorizationDetails pages -> analysis model.

    Principals/groups/policies sorted; account_id derived from the
    first (sorted) principal ARN; caps disclosed in model["skips"].
    """
    principals: list[dict] = []
    groups: dict[str, dict] = {}
    policies: dict[str, dict] = {}
    skips: list[dict] = []
    seen: set[str] = set()
    capped = False

    def _add(principal: dict) -> None:
        nonlocal capped
        key = principal["arn"]
        if not key or key in seen:
            return
        if len(principals) >= MAX_PRINCIPALS:
            if not capped:
                skips.append({"stage": "iam", "target": "model",
                              "reason": f"principal_cap_{MAX_PRINCIPALS}",
                              "detail": {"total": len(seen) + 1}})
                capped = True
            return
        seen.add(key)
        principals.append(principal)

    for page in pages:
        root = _xml(page)
        for member in root.findall(".//UserDetailList/member"):
            _add({"kind": "user",
                  "name": member.findtext("UserName") or "",
                  "arn": member.findtext("Arn") or "",
                  "inline": _member_docs(member, "UserPolicyList"),
                  "managed": _attached(member),
                  "groups": [g for g in
                             ((m.text or "").strip()
                              for m in member.findall(".//GroupList/member"))
                             if g],
                  "trust": None})
        for member in root.findall(".//RoleDetailList/member"):
            trust = None
            raw_trust = member.findtext("AssumeRolePolicyDocument")
            if raw_trust:
                try:
                    trust = _decode_doc(raw_trust)
                except (ValueError, RecursionError):
                    skips.append({"stage": "iam",
                                  "target": member.findtext("Arn") or "",
                                  "reason": "trust_parse_error"})
            _add({"kind": "role",
                  "name": member.findtext("RoleName") or "",
                  "arn": member.findtext("Arn") or "",
                  "inline": _member_docs(member, "RolePolicyList"),
                  "managed": _attached(member),
                  "groups": [],
                  "trust": trust})
        for member in root.findall(".//GroupDetailList/member"):
            name = member.findtext("GroupName") or ""
            if name and name not in groups:
                groups[name] = {
                    "inline": _member_docs(member, "GroupPolicyList"),
                    "managed": _attached(member)}
        for member in root.findall(".//Policies/member"):
            arn = member.findtext("Arn") or ""
            if not arn or arn in policies:
                continue
            versions = member.findall(".//PolicyVersionList/member")
            chosen = None
            for v in versions:
                if (v.findtext("IsDefaultVersion") or "").lower() == "true":
                    chosen = v
                    break
            if chosen is None and versions:
                chosen = versions[0]
            if chosen is None:
                continue
            try:
                policies[arn] = _decode_doc(chosen.findtext("Document") or "")
            except (ValueError, RecursionError):
                skips.append({"stage": "iam", "target": arn,
                              "reason": "policy_parse_error"})

    principals.sort(key=lambda p: (p["kind"], p["name"]))
    account_id = None
    for p in sorted(principals, key=lambda p: p["arn"]):
        account_id = account_of(p["arn"])
        if account_id:
            break
    usage_out = None
    if isinstance(usage, dict):
        usage_out = {str(k): sorted(str(s) for s in v)
                     for k, v in usage.items()}
    return {"account_id": account_id, "principals": principals,
            "groups": groups, "policies": policies,
            "usage": usage_out, "skips": skips}


def _managed_doc(model: dict, arn: str) -> dict | None:
    if arn in model.get("policies", {}):
        return model["policies"][arn]
    if arn in AWS_MANAGED:
        return AWS_MANAGED[arn]
    return None


def _inline_items(inline) -> list:
    if isinstance(inline, dict):
        return list(inline.items())
    if isinstance(inline, list):
        return [(str(i), d) for i, d in enumerate(inline)]
    return []


def effective_for(model: dict) -> dict:
    """Per-principal effective grants keyed by ARN.

    {allow: set, deny: set, allow_stmts: [...], deny_stmts: [...],
     wildcards: [{action, tier}], unknown_managed: [arns], notes: [...]}
    """
    out: dict[str, dict] = {}
    groups = model.get("groups", {})
    for p in model.get("principals", []):
        sources: list[tuple[str, dict]] = []
        for name, doc in _inline_items(p.get("inline")):
            sources.append((f"inline:{name}", doc))
        for gname in p.get("groups", []) or []:
            g = groups.get(gname) or {}
            for name, doc in _inline_items(g.get("inline")):
                sources.append((f"group:{gname}:inline:{name}", doc))
            for arn in g.get("managed", []) or []:
                doc = _managed_doc(model, arn)
                if doc is not None:
                    sources.append((f"group:{gname}:managed:{arn}", doc))
        unknown: list[str] = []
        for arn in p.get("managed", []) or []:
            doc = _managed_doc(model, arn)
            if doc is None:
                unknown.append(arn)
            else:
                sources.append((f"managed:{arn}", doc))

        allow_actions: set[str] = set()
        deny_actions: set[str] = set()
        allow_stmts: list[dict] = []
        deny_stmts: list[dict] = []
        notes: list[str] = []
        for source, doc in sources:
            try:
                stmts = parse_policy(doc)
            except (ValueError, RecursionError) as exc:
                notes.append(f"policy_parse_error:{source}:{exc}"[:WINDOW_200])
                continue
            for s in stmts:
                rec = dict(s, source=source)
                if s["effect"] == "deny":
                    deny_stmts.append(rec)
                    deny_actions.update(s["actions"])
                else:
                    allow_stmts.append(rec)
                    allow_actions.update(s["actions"])
                    if s["not_actions"]:
                        notes.append(f"not_action_allow:{source}")
        # deny subtraction: a deny pattern removes allow strings it
        # matches (fnmatch).  Wildcard denies are disclosed anyway --
        # pattern-vs-pattern overlap cannot be decided cheaply, and the
        # note keeps that limitation visible instead of silent.
        for d in sorted(deny_actions):
            if "*" in d or "?" in d:
                notes.append(f"wildcard_deny:{d}")
        kept = {a for a in allow_actions
                if not any(fnmatch.fnmatchcase(a, d)
                           for d in deny_actions)}
        wildcards = [{"action": a, "tier": classify_action(a)}
                     for a in sorted(kept)
                     if classify_action(a) != "none"]
        out[p["arn"]] = {
            "allow": kept, "deny": set(deny_actions),
            "allow_stmts": allow_stmts, "deny_stmts": deny_stmts,
            "wildcards": wildcards,
            "unknown_managed": sorted(set(unknown)),
            "notes": sorted(set(notes))}
    return out
