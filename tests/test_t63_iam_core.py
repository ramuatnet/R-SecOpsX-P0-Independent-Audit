"""T-6.3: IAM policy analysis -- grants, wildcards, cross-account
trust, privilege-escalation graph, unused permissions.

Everything network-shaped is fakes (send recorder/bombs); the clock is
injected.  Headlines:
  * default run does ZERO network I/O, byte-identical;
  * escalation paths are a stdlib adjacency graph + BFS (petgraph NOT
    adopted -- offline no-required-deps invariant, taint_interproc
    precedent);
  * missing data is always an insufficient_data gap, never a pass;
  * every judgement carries explanation + evidence + remediation;
  * graph/parse caps are disclosed, never silent.
"""
from __future__ import annotations

import json
import urllib.parse
from datetime import datetime, timezone

import pytest

from analysis.iam import checks, escalation, policy
from analysis.iam.connect import (MAX_PAGES, SCHEMA, collect_iam, main,
                                  resolve_credentials)

AS_OF = datetime(2026, 10, 31, 12, 0, 0, tzinfo=timezone.utc)
ACCT = "123456789012"
ACCT2 = "999988887777"


class NetworkBomb:
    def __call__(self, *a, **k):
        raise AssertionError(f"network attempted: {a!r} {k!r}")


def _user(name, acct=ACCT):
    return f"arn:aws:iam::{acct}:user/{name}"


def _role(name, acct=ACCT):
    return f"arn:aws:iam::{acct}:role/{name}"


def _doc(*stmts):
    return {"Version": "2012-10-17", "Statement": list(stmts)}


_KW_CANON = {"principal": "Principal", "condition": "Condition",
             "not_actions": "NotAction", "not_resources": "NotResource",
             "sid": "Sid"}


def _stmt(action, resource="*", effect="Allow", **kw):
    """Build a statement with real AWS JSON keys (kw convenience names
    are canonicalised so stored trust docs match production shape)."""
    s = {"Effect": effect, "Action": action, "Resource": resource}
    for k, v in kw.items():
        s[_KW_CANON.get(k, k)] = v
    return s


def _enc(doc):
    return urllib.parse.quote(json.dumps(doc, separators=(",", ":")))


def _page(users=(), roles=(), groups=(), policies=(), truncated=False):
    """One GetAccountAuthorizationDetails XML page (url-encoded policy
    documents, exactly as the query protocol returns them)."""
    u_xml = ""
    for u in users:
        inline = "".join(
            f"<member><PolicyName>{n}</PolicyName>"
            f"<PolicyDocument>{_enc(d)}</PolicyDocument></member>"
            for n, d in u.get("inline", {}).items())
        grp = "".join(f"<member>{g}</member>" for g in u.get("groups", []))
        man = "".join(
            f"<member><PolicyName>{a.rsplit('/', 1)[-1]}</PolicyName>"
            f"<PolicyArn>{a}</PolicyArn></member>"
            for a in u.get("managed", []))
        u_xml += (
            f"<member><UserName>{u['name']}</UserName>"
            f"<UserId>aid-{u['name']}</UserId>"
            f"<Arn>{_user(u['name'], u.get('acct', ACCT))}</Arn>"
            f"<UserPolicyList>{inline}</UserPolicyList>"
            f"<GroupList>{grp}</GroupList>"
            f"<AttachedManagedPolicies>{man}</AttachedManagedPolicies>"
            f"</member>")
    g_xml = ""
    for g in groups:
        inline = "".join(
            f"<member><PolicyName>{n}</PolicyName>"
            f"<PolicyDocument>{_enc(d)}</PolicyDocument></member>"
            for n, d in g.get("inline", {}).items())
        man = "".join(
            f"<member><PolicyName>{a.rsplit('/', 1)[-1]}</PolicyName>"
            f"<PolicyArn>{a}</PolicyArn></member>"
            for a in g.get("managed", []))
        g_xml += (
            f"<member><GroupName>{g['name']}</GroupName>"
            f"<GroupId>gid-{g['name']}</GroupId>"
            f"<Arn>arn:aws:iam::{ACCT}:group/{g['name']}</Arn>"
            f"<GroupPolicyList>{inline}</GroupPolicyList>"
            f"<AttachedManagedPolicies>{man}</AttachedManagedPolicies>"
            f"</member>")
    r_xml = ""
    for r in roles:
        inline = "".join(
            f"<member><PolicyName>{n}</PolicyName>"
            f"<PolicyDocument>{_enc(d)}</PolicyDocument></member>"
            for n, d in r.get("inline", {}).items())
        man = "".join(
            f"<member><PolicyName>{a.rsplit('/', 1)[-1]}</PolicyName>"
            f"<PolicyArn>{a}</PolicyArn></member>"
            for a in r.get("managed", []))
        trust = _enc(r.get("trust") or _doc(_stmt(
            "sts:AssumeRole",
            principal={"AWS": f"arn:aws:iam::{ACCT}:root"})))
        r_xml += (
            f"<member><RoleName>{r['name']}</RoleName>"
            f"<RoleId>rid-{r['name']}</RoleId>"
            f"<Arn>{_role(r['name'], r.get('acct', ACCT))}</Arn>"
            f"<AssumeRolePolicyDocument>{trust}</AssumeRolePolicyDocument>"
            f"<RolePolicyList>{inline}</RolePolicyList>"
            f"<AttachedManagedPolicies>{man}</AttachedManagedPolicies>"
            f"</member>")
    p_xml = ""
    for p in policies:
        p_xml += (
            f"<member><PolicyName>{p['name']}</PolicyName>"
            f"<PolicyId>pid-{p['name']}</PolicyId>"
            f"<Arn>{p['arn']}</Arn>"
            f"<PolicyVersionList><member><IsDefaultVersion>true</"
            f"IsDefaultVersion><Document>{_enc(p['doc'])}</Document>"
            f"</member></PolicyVersionList></member>")
    trunc = "<IsTruncated>true</IsTruncated>" if truncated else ""
    return (
        "<GetAccountAuthorizationDetailsResponse>"
        "<GetAccountAuthorizationDetailsResult>"
        f"<UserDetailList>{u_xml}</UserDetailList>"
        f"<GroupDetailList>{g_xml}</GroupDetailList>"
        f"<RoleDetailList>{r_xml}</RoleDetailList>"
        f"<Policies>{p_xml}</Policies>{trunc}"
        "</GetAccountAuthorizationDetailsResult>"
        "<ResponseMetadata><RequestId>r</RequestId></ResponseMetadata>"
        "</GetAccountAuthorizationDetailsResponse>")


def _capture(users=(), roles=(), groups=(), policies=(), usage=None):
    doc = {"ops": {"iam:GetAccountAuthorizationDetails": [
        _page(users=users, roles=roles, groups=groups, policies=policies)]}}
    if usage is not None:
        doc["usage"] = usage
    return doc


def _write(tmp_path, doc, name="cap.json"):
    p = tmp_path / name
    p.write_text(json.dumps(doc), encoding="utf-8")
    return str(p)


# ---------------------------------------------------------------------------
# policy: parse / classify / match
# ---------------------------------------------------------------------------

def test_parse_policy_normalizes_statements():
    doc = _doc(_stmt(["s3:Get*", "ec2:Describe*"], resource="arn:aws:s3:::*",
                     sid="S1"),
               _stmt("s3:Put*", effect="Deny"))
    stmts = policy.parse_policy(doc)
    assert stmts[0]["actions"] == ["s3:get*", "ec2:describe*"]
    assert stmts[0]["resources"] == ["arn:aws:s3:::*"]
    assert stmts[0]["sid"] == "S1"
    assert stmts[0]["effect"] == "allow"
    assert stmts[1]["effect"] == "deny"
    assert stmts[0]["condition"] is False


def test_parse_policy_flags_condition_and_not_action():
    stmts = policy.parse_policy(_doc(_stmt(
        "*", resource="*", condition={"StringEquals": {"a": "b"}})),
        _doc(_stmt("s3:GetObject", not_actions=["s3:GetObjectAcl"])))
    assert stmts[0]["condition"] is True
    assert stmts[1]["not_actions"] == ["s3:getobjectacl"]


def test_parse_policy_accepts_json_string_and_bounds_statements(
        monkeypatch):
    monkeypatch.setattr(policy, "MAX_STATEMENTS_PER_POLICY", 2)
    text = json.dumps(_doc(*(_stmt(f"svc{i}:Act") for i in range(5))))
    stmts = policy.parse_policy(text)
    assert len(stmts) == 2
    # truncation is disclosed on the model, never silent
    assert any(s["reason"] == "statement_cap_2" for s in policy.LAST_CAPS), (
        "statement cap must be recorded, not silently dropped")


def test_classify_action_wildcard_tiers():
    assert policy.classify_action("*") == "full"
    assert policy.classify_action("S3:*") == "service"
    assert policy.classify_action("s3:Get*") == "prefix"
    assert policy.classify_action("s3:GetObject") == "none"


def test_arn_matches_and_account_of():
    assert policy.arn_matches("*", _user("alice"))
    assert policy.arn_matches("arn:aws:iam::123456789012:user/*",
                              _user("alice"))
    assert not policy.arn_matches("arn:aws:iam::999988887777:user/*",
                                  _user("alice"))
    assert policy.arn_matches("arn:aws:s3:::b?cket", "arn:aws:s3:::bucket")
    assert policy.account_of(_role("deploy")) == ACCT
    assert policy.account_of("not-an-arn") is None


def test_build_model_parses_users_roles_groups_policies():
    admin = _doc(_stmt("*"))
    page = _page(
        users=[{"name": "alice", "inline": {"inline1": _doc(
            _stmt("s3:GetObject"))},
                "groups": ["admins"],
                "managed": ["arn:aws:iam::aws:policy/AdministratorAccess"]}],
        groups=[{"name": "admins",
                 "inline": {"gp": _doc(_stmt("s3:List*"))}}],
        roles=[{"name": "deploy",
                "inline": {"r": _doc(_stmt("lambda:InvokeFunction"))},
                "trust": _doc(_stmt("sts:AssumeRole",
                                    principal={"AWS": _user("alice")}))}],
        policies=[{"name": "cust", "arn": f"arn:aws:iam::{ACCT}:policy/cust",
                   "doc": admin}])
    model = policy.build_model([page])
    assert model["account_id"] == ACCT
    names = {(p["kind"], p["name"]) for p in model["principals"]}
    assert names == {("user", "alice"), ("role", "deploy")}
    alice = next(p for p in model["principals"] if p["name"] == "alice")
    assert alice["groups"] == ["admins"]
    assert alice["managed"] == ["arn:aws:iam::aws:policy/AdministratorAccess"]
    deploy = next(p for p in model["principals"] if p["name"] == "deploy")
    assert deploy["trust"]["Statement"][0]["Principal"]["AWS"] == \
        _user("alice")
    assert f"arn:aws:iam::{ACCT}:policy/cust" in model["policies"]


def test_effective_expands_group_and_managed_and_records_unknown():
    page = _page(
        users=[{"name": "alice", "groups": ["admins"],
                "managed": ["arn:aws:iam::aws:policy/AdministratorAccess",
                            f"arn:aws:iam::{ACCT}:policy/mystery"]}],
        groups=[{"name": "admins",
                 "inline": {"gp": _doc(_stmt("s3:List*"))}}])
    model = policy.build_model([page])
    eff = policy.effective_for(model)
    a = eff[_user("alice")]
    assert "*" in a["allow"]          # AdministratorAccess built-in
    assert "s3:list*" in a["allow"]   # via group
    assert a["unknown_managed"] == [f"arn:aws:iam::{ACCT}:policy/mystery"]


def test_effective_deny_subtracts_and_wildcard_deny_is_disclosed():
    page = _page(users=[{"name": "bob", "inline": {
        "p": _doc(_stmt(["s3:GetObject", "ec2:Describe*"]),
                  _stmt("s3:*", effect="Deny"))}}])
    eff = policy.effective_for(policy.build_model([page]))
    b = eff[_user("bob")]
    assert "s3:getobject" not in b["allow"]      # literal removed by deny
    assert "ec2:describe*" in b["allow"]         # untouched
    assert any("wildcard_deny" in n for n in b["notes"]), (
        "a pattern-vs-pattern deny cannot be decided; it must be noted")


def test_effective_collects_wildcard_evidence():
    page = _page(users=[{"name": "carol", "inline": {"p": _doc(
        _stmt(["*", "s3:Get*", "logs:*"]))}}])
    eff = policy.effective_for(policy.build_model([page]))
    tiers = {w["action"]: w["tier"] for w in eff[_user("carol")]["wildcards"]}
    assert tiers == {"*": "full", "s3:get*": "prefix", "logs:*": "service"}


# ---------------------------------------------------------------------------
# escalation graph
# ---------------------------------------------------------------------------

_ADMIN_TRUST = _doc(_stmt("sts:AssumeRole",
                          principal={"AWS": f"arn:aws:iam::{ACCT}:root"}))


def _model(users=(), roles=(), groups=(), policies=()):
    return policy.build_model([_page(users=users, roles=roles,
                                     groups=groups, policies=policies)])


def test_graph_assume_role_requires_trust_acceptance():
    m = _model(
        users=[{"name": "eve"}],
        roles=[{"name": "r1", "inline": {"x": _doc(_stmt("sts:AssumeRole",
                                                         resource=_role("r1")))},
                "trust": _doc(_stmt("sts:AssumeRole",
                                    principal={"AWS": _user("eve")}))},
               {"name": "r2",
                "trust": _doc(_stmt("sts:AssumeRole",
                                    principal={"AWS": _user("nobody")}))}])
    # give eve sts:AssumeRole on both roles via inline policy
    m = _model(
        users=[{"name": "eve", "inline": {"p": _doc(_stmt(
            "sts:AssumeRole", resource=[_role("r1"), _role("r2")]))}}],
        roles=[{"name": "r1",
                "trust": _doc(_stmt("sts:AssumeRole",
                                    principal={"AWS": _user("eve")}))},
               {"name": "r2",
                "trust": _doc(_stmt("sts:AssumeRole",
                                    principal={"AWS": _user("nobody")}))}])
    g = escalation.build_graph(m, policy.effective_for(m))
    edges = {(e["from"], e["to"], e["label"]) for e in g["edges"]}
    assert (_user("eve"), _role("r1"), "assume-role") in edges
    assert (_user("eve"), _role("r2"), "assume-role") not in edges


def test_graph_passrole_needs_compute_action():
    m = _model(
        users=[{"name": "u1", "inline": {"p": _doc(
            _stmt(["iam:PassRole", "lambda:CreateFunction"],
                  resource="*"))}},
               {"name": "u2", "inline": {"p": _doc(
            _stmt("iam:PassRole"))}}],
        roles=[{"name": "app"}])
    g = escalation.build_graph(m, policy.effective_for(m))
    edges = {(e["from"], e["to"], e["label"]) for e in g["edges"]}
    assert (_user("u1"), _role("app"), "passrole-run") in edges
    assert (_user("u2"), _role("app"), "passrole-run") not in edges


def test_graph_impersonation_edges():
    m = _model(users=[
        {"name": "ck", "inline": {"p": _doc(
            _stmt("iam:CreateAccessKey", resource=_user("victim")))}},
        {"name": "lp", "inline": {"p": _doc(
            _stmt("iam:UpdateLoginProfile", resource=_user("victim")))}},
        {"name": "victim"}])
    g = escalation.build_graph(m, policy.effective_for(m))
    edges = {(e["from"], e["to"], e["label"]) for e in g["edges"]}
    assert (_user("ck"), _user("victim"),
            "impersonate-access-key") in edges
    assert (_user("lp"), _user("victim"),
            "impersonate-login-profile") in edges


def test_graph_admin_edges_wildcard_selfattach_policyversion():
    cust = f"arn:aws:iam::{ACCT}:policy/cust"
    m = _model(
        users=[{"name": "wa", "inline": {"p": _doc(_stmt("*"))}},
               {"name": "sa", "inline": {"p": _doc(_stmt(
                   "iam:AttachUserPolicy", resource=_user("sa")))}},
               {"name": "pv", "inline": {"p": _doc(_stmt(
                   ["iam:CreatePolicyVersion",
                    "iam:SetDefaultPolicyVersion"], resource=cust))}},
               {"name": "scoped", "inline": {"p": _doc(_stmt(
                   "iam:AttachUserPolicy",
                   resource=_user("someoneelse")))}}],
        policies=[{"name": "cust", "arn": cust,
                   "doc": _doc(_stmt("*"))}],
        roles=[])
    # pv needs the target policy attached to itself for the takeover edge
    m["principals"] = [dict(p, managed=[cust] if p["name"] == "pv" else
                            p.get("managed", []))
                       for p in m["principals"]]
    g = escalation.build_graph(m, policy.effective_for(m))
    edges = {(e["from"], e["to"], e["label"]) for e in g["edges"]}
    assert (_user("wa"), "admin", "wildcard-admin") in edges
    assert (_user("sa"), "admin", "self-attach-policy") in edges
    assert (_user("pv"), "admin", "policy-version-takeover") in edges
    assert (_user("scoped"), "admin", "self-attach-policy") not in edges


def test_find_paths_two_hop_and_deterministic():
    m = _model(
        users=[{"name": "eve", "inline": {"p": _doc(_stmt(
            "sts:AssumeRole", resource=_role("r1")))}}],
        roles=[{"name": "r1",
                "trust": _doc(_stmt("sts:AssumeRole",
                                    principal={"AWS": _user("eve")}))},
               {"name": "r2", "inline": {"p": _doc(_stmt(
                   "iam:AttachUserPolicy", resource=_role("r2")))}}])
    # r1 trusts eve; give r1 a path: assume r1 then r1 assumes r2? Use
    # direct: eve -> r1 (assume), r1 self-attach admin.
    m = _model(
        users=[{"name": "eve", "inline": {"p": _doc(_stmt(
            "sts:AssumeRole", resource=_role("r1")))}}],
        roles=[{"name": "r1",
                "inline": {"p": _doc(_stmt("iam:AttachRolePolicy",
                                           resource="*"))},
                "trust": _doc(_stmt("sts:AssumeRole",
                                    principal={"AWS": _user("eve")}))}])
    eff = policy.effective_for(m)
    g = escalation.build_graph(m, eff)
    out = escalation.find_paths(g)
    paths = {p["principal"]: p for p in out["paths"]}
    assert _user("eve") in paths
    assert paths[_user("eve")]["path"] == [_user("eve"), _role("r1"),
                                           "admin"]
    assert paths[_user("eve")]["edges"] == ["assume-role",
                                            "self-attach-role"]
    # determinism: shuffled principals give identical output
    m2 = dict(m, principals=list(reversed(m["principals"])))
    out2 = escalation.find_paths(escalation.build_graph(
        m2, policy.effective_for(m2)))
    assert out2["paths"] == out["paths"]


def test_find_paths_respects_depth_cap():
    roles = []
    for i in range(1, 7):
        nxt = _role(f"r{i + 1}") if i < 6 else None
        doc = _doc(_stmt("sts:AssumeRole", resource=nxt or "*")) \
            if nxt else _doc(_stmt("iam:AttachRolePolicy", resource="*"))
        roles.append({"name": f"r{i}", "inline": {"p": doc}})
    chain_users_inline = _doc(_stmt("sts:AssumeRole",
                                    resource=_role("r1")))
    m = _model(users=[{"name": "u", "inline": {"p": chain_users_inline}}],
               roles=roles)
    # rebuild trust so each role trusts the previous hop
    def trust_for(prev):
        return _doc(_stmt("sts:AssumeRole",
                          principal={"AWS": prev}))
    m["principals"] = [
        dict(p, trust=trust_for(_user("u") if p["name"] == "r1"
                                else _role(f"r{int(p['name'][1:]) - 1}"))
             if p["kind"] == "role" else p)
        for p in m["principals"]]
    eff = policy.effective_for(m)
    g = escalation.build_graph(m, eff)
    out = escalation.find_paths(g)
    # 6-edge chain exceeds MAX_DEPTH=6? u->r1(1) r1->r2(2) ... r5 self(6)
    paths = {p["principal"]: p for p in out["paths"]}
    if _user("u") in paths:
        assert len(paths[_user("u")]["edges"]) <= escalation.MAX_DEPTH
    else:
        assert any(s["reason"].startswith("depth_cap")
                   for s in out["skips"])


def test_graph_caps_disclosed(monkeypatch):
    monkeypatch.setattr(escalation, "MAX_PRINCIPALS", 2)
    m = _model(users=[{"name": f"u{i}"} for i in range(4)])
    g = escalation.build_graph(m, policy.effective_for(m))
    assert any("principal_cap" in s["reason"] for s in g["skips"])
    assert len([n for n in g["nodes"] if n.startswith("arn:")]) <= 2


def test_graph_marks_conditioned_trust_edges():
    m = _model(
        users=[{"name": "eve", "inline": {"p": _doc(_stmt(
            "sts:AssumeRole", resource=_role("r1")))}}],
        roles=[{"name": "r1", "trust": _doc(_stmt(
            "sts:AssumeRole", principal={"AWS": f"arn:aws:iam::{ACCT}:root"},
            condition={"StringEquals": {"sts:ExternalId": "x"}}))}])
    g = escalation.build_graph(m, policy.effective_for(m))
    edge = next(e for e in g["edges"]
                if e["label"] == "assume-role")
    assert edge["conditioned"] is True


# ---------------------------------------------------------------------------
# checks: findings + gaps
# ---------------------------------------------------------------------------

def test_over_permissive_fires_and_carries_remediation():
    m = _model(users=[{"name": "admin", "inline": {"p": _doc(
        _stmt("*", resource="*"))}}])
    findings, gaps = checks.run_checks(m, AS_OF)
    f = next(x for x in findings if x["check_id"] == "iam.over_permissive")
    assert f["subject"] == _user("admin")
    assert f["explanation"] and f["remediation"]
    assert f["evidence"]["policy"] == "inline:p"
    assert f["kind"] == "finding"


def test_over_permissive_notaction_and_conditioned_note():
    m = _model(users=[{"name": "na", "inline": {"p": _doc(_stmt(
        "s3:GetObject", resource="*", not_actions=["iam:*"],
        condition={"Bool": {"aws:SecureTransport": "false"}}))}}])
    findings, _ = checks.run_checks(m, AS_OF)
    f = next(x for x in findings if x["check_id"] == "iam.over_permissive")
    assert f["evidence"]["not_action"] is True
    assert f["evidence"]["conditioned"] is True


def test_scoped_wildcards_not_over_permissive_but_wildcard_finding():
    m = _model(users=[{"name": "dev", "inline": {"p": _doc(
        _stmt(["s3:*", "s3:Get*"],
              resource="arn:aws:s3:::logs/*"))}}])
    findings, _ = checks.run_checks(m, AS_OF)
    assert not any(x["check_id"] == "iam.over_permissive" for x in findings)
    f = next(x for x in findings
             if x["check_id"] == "iam.wildcard_actions")
    tiers = {w["action"]: w["tier"] for w in f["evidence"]["wildcards"]}
    assert tiers == {"s3:*": "service", "s3:get*": "prefix"}


def test_wildcard_actions_list_is_bounded_and_sorted(monkeypatch):
    monkeypatch.setattr(checks, "MAX_WILDCARDS_LISTED", 2)
    m = _model(users=[{"name": "w", "inline": {"p": _doc(
        _stmt(["svcC:*", "svcA:*", "svcB:*"]))}}])
    findings, _ = checks.run_checks(m, AS_OF)
    f = next(x for x in findings
             if x["check_id"] == "iam.wildcard_actions")
    assert [w["action"] for w in f["evidence"]["wildcards"]] == \
        ["svca:*", "svcb:*"]
    assert f["evidence"]["truncated"] is True


def test_cross_account_trust_and_anonymous():
    m = _model(roles=[
        {"name": "xa", "trust": _doc(_stmt(
            "sts:AssumeRole",
            principal={"AWS": [f"arn:aws:iam::{ACCT2}:root",
                                _user("alice")]}))},
        {"name": "anon", "trust": _doc(_stmt(
            "sts:AssumeRole", principal="*"))},
        {"name": "svc", "trust": _doc(_stmt(
            "sts:AssumeRole",
            principal={"Service": "ec2.amazonaws.com"}))}])
    findings, gaps = checks.run_checks(m, AS_OF)
    xa = [x for x in findings
          if x["check_id"] == "iam.cross_account_trust"]
    subjects = {x["subject"] for x in xa}
    assert _role("xa") in subjects
    assert _role("anon") in subjects          # anonymous trust
    assert _role("svc") not in subjects       # service principal ok
    xa_f = next(x for x in xa if x["subject"] == _role("xa"))
    assert xa_f["evidence"]["foreign_accounts"] == [ACCT2]


def test_cross_account_trust_same_account_silent_and_gap_without_account():
    m = _model(roles=[{"name": "ok", "trust": _doc(_stmt(
        "sts:AssumeRole", principal={"AWS": f"arn:aws:iam::{ACCT}:root"}))}])
    findings, _ = checks.run_checks(m, AS_OF)
    assert not any(x["check_id"] == "iam.cross_account_trust"
                   for x in findings)
    # no account id anywhere -> cannot judge, gap not finding
    m2 = {"account_id": None,
          "principals": [{"kind": "role", "name": "r",
                          "arn": "arn:aws:iam::X:role/r",
                          "inline": [], "managed": [], "groups": [],
                          "trust": _doc(_stmt(
                              "sts:AssumeRole",
                              principal={"AWS": "arn:aws:iam::Y:root"}))}],
          "groups": {}, "policies": {}, "usage": None, "skips": []}
    findings2, gaps2 = checks.run_checks(m2, AS_OF)
    assert not any(x["check_id"] == "iam.cross_account_trust"
                   for x in findings2)
    assert any(g["check_id"] == "iam.cross_account_trust"
               and g["reason"] == "insufficient_data" for g in gaps2)


def test_cross_account_trust_condition_still_flagged_with_note():
    m = _model(roles=[{"name": "c", "trust": _doc(_stmt(
        "sts:AssumeRole", principal={"AWS": f"arn:aws:iam::{ACCT2}:root"},
        condition={"StringEquals": {"aws:PrincipalOrgID": "o-1"}}))}])
    findings, _ = checks.run_checks(m, AS_OF)
    f = next(x for x in findings
             if x["check_id"] == "iam.cross_account_trust")
    assert f["evidence"]["conditioned"] is True


def test_unused_permissions_gap_then_finding():
    page_users = [{"name": "z", "inline": {"p": _doc(
        _stmt(["s3:GetObject", "lambda:InvokeFunction"]))}}]
    m = policy.build_model([_page(users=page_users)])
    findings, gaps = checks.run_checks(m, AS_OF)
    assert any(g["check_id"] == "iam.unused_permissions"
               and g["reason"] == "insufficient_data" for g in gaps)
    m2 = policy.build_model([_page(users=page_users)],
                            usage={_user("z"): ["s3"]})
    findings2, gaps2 = checks.run_checks(m2, AS_OF)
    assert not any(g["check_id"] == "iam.unused_permissions"
                   for g in gaps2)
    f = next(x for x in findings2
             if x["check_id"] == "iam.unused_permissions")
    assert f["evidence"]["unused_services"] == ["lambda"]


def test_unused_permissions_list_bounded(monkeypatch):
    monkeypatch.setattr(checks, "MAX_UNUSED_LISTED", 2)
    svcs = [f"svc{i}" for i in range(5)]
    m = policy.build_model([_page(users=[{"name": "z", "inline": {"p": _doc(
        _stmt([f"{s}:Act" for s in svcs]))}}])], usage={})
    findings, _ = checks.run_checks(m, AS_OF)
    f = next(x for x in findings
             if x["check_id"] == "iam.unused_permissions")
    assert len(f["evidence"]["unused_services"]) == 2
    assert f["evidence"]["truncated"] is True


def test_escalation_path_finding_carries_chain():
    m = _model(
        users=[{"name": "eve", "inline": {"p": _doc(_stmt(
            "sts:AssumeRole", resource=_role("r1")))}}],
        roles=[{"name": "r1",
                "inline": {"p": _doc(_stmt("iam:AttachRolePolicy",
                                           resource="*"))},
                "trust": _doc(_stmt("sts:AssumeRole",
                                    principal={"AWS": _user("eve")}))}])
    findings, _ = checks.run_checks(m, AS_OF)
    f = next(x for x in findings
             if x["check_id"] == "iam.escalation_path"
             and x["subject"] == _user("eve"))
    assert f["subject"] == _user("eve")
    assert f["evidence"]["path"] == [_user("eve"), _role("r1"), "admin"]
    assert f["evidence"]["primitive"] == "self-attach-role"


def test_every_finding_is_explainable_and_sorted():
    cust = f"arn:aws:iam::{ACCT}:policy/cust"
    m = _model(
        users=[{"name": "admin", "inline": {"p": _doc(_stmt("*"))},
                "managed": [cust]},
               {"name": "eve", "inline": {"p": _doc(_stmt(
                   "sts:AssumeRole", resource=_role("r1")))}}],
        roles=[{"name": "r1",
                "inline": {"p": _doc(_stmt("iam:AttachRolePolicy",
                                           resource="*"))},
                "trust": _doc(_stmt("sts:AssumeRole",
                                    principal={"AWS": _user("eve")}))}],
        policies=[{"name": "cust", "arn": cust, "doc": _doc(_stmt("*"))}])
    findings, gaps = checks.run_checks(m, AS_OF)
    assert findings, "fixture must produce findings"
    for f in findings:
        assert f["kind"] == "finding"
        assert f["explanation"] and f["remediation"]
        assert f["evidence"] is not None
    keys = [(f["check_id"], f["subject"]) for f in findings]
    assert keys == sorted(keys)
    for g in gaps:
        assert g["kind"] == "gap" and g["reason"]


# ---------------------------------------------------------------------------
# connect: ingest / live / CLI / bounds
# ---------------------------------------------------------------------------

def test_default_run_is_zero_io_and_byte_identical():
    a = collect_iam((), as_of=AS_OF, send=NetworkBomb())
    b = collect_iam((), as_of=AS_OF, send=NetworkBomb())
    assert a["schema"] == SCHEMA
    assert a["principals"] == []
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)
    assert any(s["reason"] == "provider_not_requested" for s in a["skips"])


def test_ingest_happy_path(tmp_path):
    path = _write(tmp_path, _capture(
        users=[{"name": "admin", "inline": {"p": _doc(_stmt("*"))}}]))
    doc = collect_iam(("aws",), files={"aws": path}, as_of=AS_OF,
                      send=NetworkBomb())
    assert doc["principals"]
    assert any(f["check_id"] == "iam.over_permissive"
               for f in doc["findings"])
    assert any(s["kind"] == "aws:ingest" and s["status"] == "ok"
               for s in doc["sources"])


def test_ingest_missing_and_bad_json_become_skips(tmp_path):
    missing = str(tmp_path / "nope.json")
    doc = collect_iam(("aws",), files={"aws": missing}, as_of=AS_OF,
                      send=NetworkBomb())
    assert any("FileNotFoundError" in s["reason"] for s in doc["skips"])
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    doc2 = collect_iam(("aws",), files={"aws": str(bad)}, as_of=AS_OF,
                       send=NetworkBomb())
    assert any("JSONDecodeError" in s["reason"] or "ValueError" in s["reason"]
               for s in doc2["skips"])
    assert doc2["principals"] == []


def test_usage_sidecar_feeds_unused_permissions(tmp_path):
    path = _write(tmp_path, _capture(
        users=[{"name": "z", "inline": {"p": _doc(
            _stmt(["s3:GetObject", "lambda:Invoke"]))}}],
        usage={_user("z"): ["s3"]}))
    doc = collect_iam(("aws",), files={"aws": path}, as_of=AS_OF,
                      send=NetworkBomb())
    f = next(x for x in doc["findings"]
             if x["check_id"] == "iam.unused_permissions")
    assert f["evidence"]["unused_services"] == ["lambda"]


def test_live_fetch_signs_and_paginates():
    calls = []
    pages = [
        _page(users=[{"name": "p0"}], truncated=True),
        _page(users=[{"name": "p1"}]),
    ]

    def send(method, url, headers, body):
        calls.append((method, url, dict(headers), body))
        nxt = len([c for c in calls]) - 1
        return 200, {}, pages[min(nxt, len(pages) - 1)].encode()

    doc = collect_iam(("aws",), creds={"aws": {
        "access_key": "AKID", "secret_key": "SECRET",
        "region": "us-east-1"}}, as_of=AS_OF, send=send)
    assert [p["name"] for p in doc["principals"]] == ["p0", "p1"]
    method, url, headers, body = calls[0]
    assert method == "POST"
    assert url == "https://iam.amazonaws.com/"
    assert headers["authorization"].startswith("AWS4-HMAC-SHA256 ")
    assert b"Action=GetAccountAuthorizationDetails" in body
    assert len(calls) == 2                      # Marker page 2
    assert b"Marker=" in calls[1][3]


def test_live_403_becomes_skip_never_raises():
    def send(method, url, headers, body):
        return 403, {}, b"<Error><Message>no</Message></Error>"
    doc = collect_iam(("aws",), creds={"aws": {
        "access_key": "AKID", "secret_key": "SECRET",
        "region": "us-east-1"}}, as_of=AS_OF, send=send)
    assert any("ApiError" in s["reason"] and "http_403" in s["reason"]
               for s in doc["skips"])
    assert doc["principals"] == []


def test_live_page_cap_disclosed():
    def send(method, url, headers, body):
        page = _page(users=[{"name": "x"}], truncated=True)
        return 200, {}, page.encode()
    doc = collect_iam(("aws",), creds={"aws": {
        "access_key": "AKID", "secret_key": "SECRET",
        "region": "us-east-1"}}, as_of=AS_OF, send=send)
    assert any(f"page_cap_{MAX_PAGES}" in s["reason"] for s in doc["skips"])


def test_resolve_credentials_is_the_cloud_handler():
    import analysis.cloud.connect as cloud_connect
    assert resolve_credentials is cloud_connect.resolve_credentials
    got = resolve_credentials("aws", env={
        "AWS_ACCESS_KEY_ID": "K", "AWS_SECRET_ACCESS_KEY": "S"})
    assert got["access_key"] == "K" and got["region"] == "us-east-1"


def test_cli_two_runs_byte_identical_and_bad_as_of(tmp_path, capsys):
    cap = _write(tmp_path, _capture(
        users=[{"name": "admin", "inline": {"p": _doc(_stmt("*"))}}]))
    out1, out2 = tmp_path / "a.json", tmp_path / "b.json"
    rc = main(["--aws-file", cap, "--as-of", "2026-10-31T12:00:00Z",
               "--out", str(out1)])
    rc2 = main(["--aws-file", cap, "--as-of", "2026-10-31T12:00:00Z",
                "--out", str(out2)])
    assert rc == rc2 == 0
    assert out1.read_bytes() == out2.read_bytes()
    assert main(["--as-of", "not-a-time"]) == 2


def test_cli_default_prints_offline_artifact(capsys):
    assert main([]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["schema"] == SCHEMA and doc["principals"] == []


def test_principal_cap_in_model(monkeypatch):
    monkeypatch.setattr(policy, "MAX_PRINCIPALS", 2)
    page = _page(users=[{"name": f"u{i}"} for i in range(4)])
    model = policy.build_model([page])
    assert len(model["principals"]) == 2
    assert any("principal_cap" in s["reason"] for s in model["skips"])


def test_petgraph_not_adopted_is_documented():
    """task.md names petgraph; the offline no-required-deps invariant
    outranks the library (taint_interproc precedent).  The disclosure
    must survive in the escalation module docstring."""
    assert "petgraph" in (escalation.__doc__ or "").lower()
    assert "not adopted" in (escalation.__doc__ or "").lower()
