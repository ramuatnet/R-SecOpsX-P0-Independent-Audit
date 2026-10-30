"""T-6.4: unified asset graph -- external asset -> internal resource ->
code finding attack paths.

All inputs are offline artifacts (rsecopsx.asm_inventory/v1,
rsecopsx.cloud_posture/v1, rsecopsx.iam_analysis/v1, code findings).
Headline assertions:
  * default (no-input) graph is zero-I/O and byte-identical;
  * every edge carries explanation + evidence (ground rule 11);
  * attack paths are exactly the task.md chain external -> resource ->
    code finding, deterministically sorted and capped with disclosure;
  * the Phase-6 gate: ASM inventory reproducible run-to-run, and graph
    links verified against a known sandbox account (fixture account
    capture -- no live credentials on this box, disclosed).
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from analysis.asm.collect import build_inventory
from analysis.cloud.connect import collect_posture
from analysis.graph import model as gmodel
from analysis.graph import paths as gpaths
from analysis.iam.connect import collect_iam
from analysis.graph.connect import build_graph, collect_graph, main

AS_OF = datetime(2026, 10, 31, 12, 0, 0, tzinfo=timezone.utc)


# --------------------------------------------------------------------------
# fixtures
# --------------------------------------------------------------------------

def _host(name, addresses=(), ports=(), admin=(), takeover=None):
    return {"host": name, "addresses": list(addresses), "cname": None,
            "records": [],
            "ports": ({"host": name,
                       "open": [{"port": p, "service": ""}
                                for p in sorted(ports)],
                       "stats": {}} if ports else None),
            "tls": None, "favicon": None, "techs": [], "admin": list(admin),
            "takeover": takeover}


def _storage_result(provider="aws_s3", name="acme-backup", public=True,
                    posture="public"):
    return {"provider": provider, "name": name,
            "url": f"https://{name}.s3.amazonaws.com",
            "exists": True, "public": public, "posture": posture,
            "evidence": "http_200+listing_xml" if public else "http_403"}


def _asm(hosts=(), storage=()):
    return {"schema": "rsecopsx.asm_inventory/v1", "domain": "acme.example",
            "as_of": "2026-10-31T12:00:00Z",
            "seed_url": "http://acme.example/", "sources": [],
            "hosts": list(hosts),
            "storage": {"candidates": [], "results": list(storage),
                        "stats": {}},
            "skips": [], "stats": {}}


def _res(provider="aws", rtype="compute", rid="i-1", name="web",
         region="us-east-1", config=None, service="ec2"):
    return {"provider": provider, "type": rtype, "service": service,
            "id": rid, "name": name, "region": region,
            "config": dict(config or {}), "tags": []}


def _cloud(resources=(), findings=()):
    return {"schema": "rsecopsx.cloud_posture/v1",
            "as_of": "2026-10-31T12:00:00Z", "providers": ["aws"],
            "sources": [], "inventory": {"resources": list(resources)},
            "findings": list(findings), "posture": {}, "skips": [],
            "stats": {}}


def _principal(arn="arn:aws:iam::123456789012:user/alice", kind="user",
               name="alice"):
    return {"kind": kind, "name": name, "arn": arn, "inline": {},
            "managed": [], "groups": [], "trust": None}


def _iam(principals=(), findings=()):
    return {"schema": "rsecopsx.iam_analysis/v1",
            "as_of": "2026-10-31T12:00:00Z",
            "account_id": "123456789012", "sources": [],
            "principals": list(principals), "findings": list(findings),
            "skips": [], "stats": {}}


def _iam_finding(check_id="iam.over_permissive",
                 subject="arn:aws:iam::123456789012:user/alice"):
    return {"kind": "finding", "check_id": check_id, "subject": subject,
            "explanation": "x", "evidence": {}, "remediation": "y"}


def _cis_finding(check_id="cis.aws.s3.public", rid="acme-backup"):
    return {"kind": "finding", "check_id": check_id, "provider": "aws",
            "resource_id": rid, "explanation": "x", "evidence": {}}


def _code(rule_id="R1", file="app.py", line=10, snippet="",
          description="", evidence=None, title="t"):
    return {"rule_id": rule_id, "title": title, "file": file, "line": line,
            "severity": "high", "vuln_type": "x", "cwe": "79",
            "description": description, "snippet": snippet,
            "evidence": evidence or {}}


def _kinds(nodes):
    return {n["id"]: n["kind"] for n in nodes}


def _edge_set(graph):
    return {(e["from"], e["to"], e["kind"]) for e in graph["edges"]}


# --------------------------------------------------------------------------
# default offline graph
# --------------------------------------------------------------------------

def test_default_graph_is_empty_zero_io_byte_identical():
    a = build_graph(as_of=AS_OF)
    b = build_graph(as_of=AS_OF)
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)
    assert a["schema"] == gmodel.SCHEMA
    assert a["as_of"] == "2026-10-31T12:00:00Z"
    assert a["nodes"] == [] and a["edges"] == [] and a["attack_paths"] == []
    assert a["skips"] == []
    assert a["stats"]["nodes"] == 0 and a["stats"]["attack_paths"] == 0


def test_collect_graph_default_skips_not_provided_inputs(tmp_path):
    graph = collect_graph(files={}, as_of=AS_OF)
    reasons = {(s["stage"], s["reason"]) for s in graph["skips"]}
    for stage in ("asm", "cloud", "iam", "findings"):
        assert (stage, "not_provided") in reasons
    assert graph["nodes"] == []


# --------------------------------------------------------------------------
# node extraction
# --------------------------------------------------------------------------

def test_host_and_storage_become_external_nodes():
    graph = build_graph(
        asm=_asm(hosts=[_host("acme.example", ["203.0.113.5"], ports=(80,),
                              takeover="none"),
                        _host("www.acme.example")],
                 storage=[_storage_result()]),
        as_of=AS_OF)
    kinds = _kinds(graph["nodes"])
    assert kinds["ext:host:acme.example"] == "external"
    assert kinds["ext:host:www.acme.example"] == "external"
    assert kinds["ext:storage:aws_s3:acme-backup"] == "external"
    node = next(n for n in graph["nodes"]
                if n["id"] == "ext:storage:aws_s3:acme-backup")
    assert node["subkind"] == "storage"
    assert node["attrs"]["public"] is True
    assert node["attrs"]["posture"] == "public"
    host = next(n for n in graph["nodes"] if n["id"] == "ext:host:acme.example")
    assert host["attrs"]["addresses"] == ["203.0.113.5"]
    assert host["attrs"]["open_ports"] == [80]


def test_cloud_resources_become_resource_nodes_sorted():
    graph = build_graph(
        cloud=_cloud(resources=[
            _res(rid="i-2", name="b", config={"public_ip": "198.51.100.2"}),
            _res(rid="i-1", name="a", config={"public_ip": "198.51.100.1"}),
            _res(rtype="storage", service="s3", rid="bucket-a",
                 name="bucket-a", config={"public_access_block": {}}),
        ]), as_of=AS_OF)
    res_ids = [n["id"] for n in graph["nodes"] if n["kind"] == "resource"]
    assert res_ids == ["res:aws:compute:i-1", "res:aws:compute:i-2",
                       "res:aws:storage:bucket-a"]
    node = next(n for n in graph["nodes"]
                if n["id"] == "res:aws:compute:i-1")
    assert node["attrs"]["public_ip"] == "198.51.100.1"
    assert node["attrs"]["provider"] == "aws"


def test_iam_principals_become_resource_nodes():
    graph = build_graph(
        iam=_iam(principals=[_principal(),
                             _principal(kind="role", name="app",
                                        arn="arn:aws:iam::123456789012:"
                                            "role/app")]),
        as_of=AS_OF)
    res_ids = sorted(n["id"] for n in graph["nodes"]
                     if n["kind"] == "resource")
    assert res_ids == ["res:iam:arn:aws:iam::123456789012:role/app",
                       "res:iam:arn:aws:iam::123456789012:user/alice"]
    node = next(n for n in graph["nodes"]
                if n["id"] == "res:iam:arn:aws:iam::123456789012:user/alice")
    assert node["attrs"]["arn"] == "arn:aws:iam::123456789012:user/alice"


def test_code_findings_become_finding_nodes():
    row = _code(rule_id="R9", snippet='bucket = "acme-backup"')
    graph = build_graph(findings=[row], as_of=AS_OF)
    node = next(n for n in graph["nodes"] if n["kind"] == "finding")
    assert node["id"] == "find:code:R9:app.py:10"
    assert node["subkind"] == "code"
    assert node["attrs"]["rule_id"] == "R9"
    assert node["attrs"]["file"] == "app.py"
    assert node["attrs"]["line"] == 10


def test_iam_and_cis_findings_become_finding_nodes():
    graph = build_graph(
        cloud=_cloud(resources=[_res(rtype="storage", service="s3",
                                     rid="acme-backup", name="acme-backup")],
                     findings=[_cis_finding()]),
        iam=_iam(findings=[_iam_finding()]),
        as_of=AS_OF)
    kinds = _kinds(graph["nodes"])
    assert kinds["find:cis:cis.aws.s3.public:acme-backup"] == "finding"
    assert kinds["find:iam:iam.over_permissive:"
                 "arn:aws:iam::123456789012:user/alice"] == "finding"


def test_finding_node_id_collisions_get_suffix():
    row = _code(rule_id="R1")
    graph = build_graph(findings=[row, dict(row), dict(row)], as_of=AS_OF)
    ids = sorted(n["id"] for n in graph["nodes"] if n["kind"] == "finding")
    assert ids == ["find:code:R1:app.py:10", "find:code:R1:app.py:10#2",
                   "find:code:R1:app.py:10#3"]


def test_invalid_finding_rows_annotated_never_silent():
    graph = build_graph(findings=[_code(rule_id="ok"), "junk", 7],
                        as_of=AS_OF)
    code_nodes = [n for n in graph["nodes"] if n["subkind"] == "code"]
    assert len(code_nodes) == 1
    skip = next(s for s in graph["skips"]
                if s["reason"] == "finding_rows_not_objects")
    assert skip["detail"]["count"] == 2


def test_finding_cap_disclosed(monkeypatch):
    monkeypatch.setattr(gmodel, "MAX_FINDINGS", 1)
    graph = build_graph(
        findings=[_code(rule_id="A"), _code(rule_id="B"), _code(rule_id="C")],
        as_of=AS_OF)
    code_nodes = [n for n in graph["nodes"] if n["subkind"] == "code"]
    assert len(code_nodes) == 1
    assert any(s["reason"] == "cap_findings_1" for s in graph["skips"])


def test_node_cap_disclosed(monkeypatch):
    monkeypatch.setattr(gmodel, "MAX_NODES", 2)
    graph = build_graph(
        cloud=_cloud(resources=[_res(rid="i-1"), _res(rid="i-2"),
                                _res(rid="i-3")]),
        as_of=AS_OF)
    assert len(graph["nodes"]) == 2
    assert any(s["reason"] == "cap_nodes_2" for s in graph["skips"])


# --------------------------------------------------------------------------
# edges: external -> resource
# --------------------------------------------------------------------------

def test_host_ip_edge_matches_public_ip_intersection():
    graph = build_graph(
        asm=_asm(hosts=[_host("a.example", ["203.0.113.7", "10.0.0.1"]),
                        _host("b.example", ["192.0.2.9"])]),
        cloud=_cloud(resources=[
            _res(rid="i-1", config={"public_ip": "203.0.113.7"}),
            _res(rid="i-2", config={"public_ip": "192.0.2.1"})]),
        as_of=AS_OF)
    edges = _edge_set(graph)
    assert ("ext:host:a.example", "res:aws:compute:i-1", "host_ip") in edges
    assert not any(e[0] == "ext:host:b.example" for e in edges)
    assert not any(e[2] == "host_ip" and e[1].endswith("i-2")
                   for e in edges)


def test_bucket_name_edge_is_provider_scoped():
    graph = build_graph(
        asm=_asm(storage=[_storage_result(provider="aws_s3",
                                          name="shared-bucket"),
                          _storage_result(provider="gcs",
                                          name="gcp-bucket")]),
        cloud=_cloud(resources=[
            _res(rtype="storage", service="s3", rid="shared-bucket",
                 name="shared-bucket"),
            _res(provider="gcp", rtype="storage", service="gcs",
                 rid="shared-bucket", name="shared-bucket"),
            _res(provider="gcp", rtype="storage", service="gcs",
                 rid="gcp-bucket", name="gcp-bucket")]),
        as_of=AS_OF)
    edges = _edge_set(graph)
    assert ("ext:storage:aws_s3:shared-bucket",
            "res:aws:storage:shared-bucket", "bucket_name") in edges
    # same NAME on a different provider is a different bucket -- no link
    assert ("ext:storage:aws_s3:shared-bucket",
            "res:gcp:storage:shared-bucket", "bucket_name") not in edges
    assert ("ext:storage:gcs:gcp-bucket",
            "res:gcp:storage:gcp-bucket", "bucket_name") in edges


def test_edges_carry_explanation_and_evidence():
    graph = build_graph(
        asm=_asm(hosts=[_host("a.example", ["203.0.113.7"])]),
        cloud=_cloud(resources=[
            _res(rid="i-1", config={"public_ip": "203.0.113.7"})]),
        as_of=AS_OF)
    edge = graph["edges"][0]
    assert edge["kind"] == "host_ip"
    assert "a.example" in edge["explanation"]
    assert "203.0.113.7" in edge["explanation"]
    assert edge["evidence"]["matched_ip"] == "203.0.113.7"


def test_identity_edge_links_cloud_user_to_iam_principal():
    arn = "arn:aws:iam::123456789012:user/alice"
    graph = build_graph(
        cloud=_cloud(resources=[
            _res(rtype="identity", service="iam", rid="AIDA123",
                 name="alice", config={"arn": arn})]),
        iam=_iam(principals=[_principal()]),
        as_of=AS_OF)
    assert ("res:aws:identity:AIDA123", "res:iam:" + arn,
            "identity") in _edge_set(graph)
    # different arn -> no identity edge
    graph2 = build_graph(
        cloud=_cloud(resources=[
            _res(rtype="identity", service="iam", rid="AIDA123",
                 name="alice", config={"arn": arn})]),
        iam=_iam(principals=[_principal(arn="arn:aws:iam::123456789012:"
                                            "user/bob", name="bob")]),
        as_of=AS_OF)
    assert not any(e[2] == "identity" for e in _edge_set(graph2))


# --------------------------------------------------------------------------
# edges: resource -> finding (mention / subject)
# --------------------------------------------------------------------------

def test_finding_mention_uses_word_boundaries():
    graph = build_graph(
        cloud=_cloud(resources=[
            _res(rid="web", name="web"),
            _res(rid="i-1", name="svc")]),
        findings=[
            _code(rule_id="IN-SUBSTRING",
                  snippet="webserver = True  # i-12345"),
            _code(rule_id="IN-EXACT", snippet="target = web  # host i-1"),
        ], as_of=AS_OF)
    edges = _edge_set(graph)
    assert ("res:aws:compute:web", "find:code:IN-EXACT:app.py:10",
            "finding_mention") in edges
    assert ("res:aws:compute:web", "find:code:IN-SUBSTRING:app.py:10",
            "finding_mention") not in edges
    # "i-1" is a substring of "i-12345" -> no; exact token -> yes
    assert ("res:aws:compute:i-1", "find:code:IN-SUBSTRING:app.py:10",
            "finding_mention") not in edges
    assert ("res:aws:compute:i-1", "find:code:IN-EXACT:app.py:10",
            "finding_mention") in edges


def test_finding_mention_is_case_insensitive():
    graph = build_graph(
        cloud=_cloud(resources=[_res(rid="Acme-Backup")]),
        findings=[_code(rule_id="R", description="use acme-backup here")],
        as_of=AS_OF)
    assert ("res:aws:compute:Acme-Backup",
            "find:code:R:app.py:10", "finding_mention") in _edge_set(graph)


def test_finding_mention_covers_ip_and_arn_identifiers():
    arn = "arn:aws:iam::123456789012:user/bob"
    graph = build_graph(
        cloud=_cloud(resources=[
            _res(rid="i-9", config={"public_ip": "198.51.100.7"}),
            _res(rtype="identity", service="iam", rid="AIDABOB",
                 name="bob", config={"arn": arn})]),
        findings=[
            _code(rule_id="IP", evidence={"url": "http://198.51.100.7/x"}),
            _code(rule_id="ARN", description=f"principal {arn} is used"),
        ], as_of=AS_OF)
    edges = _edge_set(graph)
    assert ("res:aws:compute:i-9", "find:code:IP:app.py:10",
            "finding_mention") in edges
    assert ("res:aws:identity:AIDABOB", "find:code:ARN:app.py:10",
            "finding_mention") in edges


def test_identifier_cap_disclosed(monkeypatch):
    monkeypatch.setattr(gmodel, "MAX_IDENTIFIERS_PER_RESOURCE", 2)
    graph = build_graph(
        cloud=_cloud(resources=[
            _res(rid="i-100", name="name-two",
                 config={"public_ip": "", "arn": "zzz-arn-keep"})]),
        findings=[_code(rule_id="R", description="mentions zzz-arn-keep")],
        as_of=AS_OF)
    # candidates in order rid, name, public_ip, arn -- cap keeps first two
    assert not any(e[2] == "finding_mention" for e in _edge_set(graph))
    assert any(s["reason"] == "cap_identifiers_2"
               for s in graph["skips"])


def test_absent_and_short_identifiers_never_match():
    from analysis.cloud.model import ABSENT
    graph = build_graph(
        cloud=_cloud(resources=[
            _res(rid="i-5", config={"public_ip": ABSENT}),
            _res(rid="i-6", name="")]),
        findings=[_code(rule_id="R", description="about __absent__ and ")],
        as_of=AS_OF)
    assert not any(e[2] == "finding_mention" for e in _edge_set(graph))


def test_iam_subject_edge_and_mismatch():
    good = "arn:aws:iam::123456789012:user/alice"
    graph = build_graph(
        iam=_iam(principals=[_principal()],
                 findings=[_iam_finding(),
                           _iam_finding(check_id="iam.wildcard_actions",
                                        subject="arn:aws:iam::123456789012:"
                                                "user/nobody")]),
        as_of=AS_OF)
    edges = _edge_set(graph)
    assert ("res:iam:" + good,
            "find:iam:iam.over_permissive:" + good,
            "iam_subject") in edges
    assert not any(e[0] == "res:iam:" + good
                   and e[1].endswith("user/nobody") for e in edges)


def test_cis_subject_edge():
    graph = build_graph(
        cloud=_cloud(resources=[_res(rtype="storage", service="s3",
                                     rid="acme-backup", name="acme-backup")],
                     findings=[_cis_finding(),
                               _cis_finding(check_id="cis.other",
                                            rid="someone-else")]),
        as_of=AS_OF)
    edges = _edge_set(graph)
    assert ("res:aws:storage:acme-backup",
            "find:cis:cis.aws.s3.public:acme-backup",
            "cis_subject") in edges
    assert not any(e[1].endswith("someone-else") and e[2] == "cis_subject"
                   for e in edges)


def test_edges_sorted_and_order_invariant():
    base = dict(
        asm=_asm(hosts=[_host("a.example", ["203.0.113.7"])]),
        cloud=_cloud(resources=[
            _res(rid="i-1", config={"public_ip": "203.0.113.7"}),
            _res(rtype="storage", service="s3", rid="acme-backup",
                 name="acme-backup")]),
        as_of=AS_OF)
    a = build_graph(**base)
    shuffled = dict(base)
    shuffled["cloud"] = _cloud(resources=list(reversed(
        base["cloud"]["inventory"]["resources"])))
    b = build_graph(**shuffled)
    assert json.dumps(a["edges"], sort_keys=True) == \
        json.dumps(b["edges"], sort_keys=True)
    keys = [(e["from"], e["to"], e["kind"]) for e in a["edges"]]
    assert keys == sorted(keys)


def test_edge_cap_disclosed(monkeypatch):
    monkeypatch.setattr(gmodel, "MAX_EDGES", 1)
    graph = build_graph(
        asm=_asm(hosts=[_host("a.example", ["203.0.113.7"]),
                        _host("b.example", ["203.0.113.8"])]),
        cloud=_cloud(resources=[
            _res(rid="i-1", config={"public_ip": "203.0.113.7"}),
            _res(rid="i-2", config={"public_ip": "203.0.113.8"})]),
        as_of=AS_OF)
    assert len(graph["edges"]) == 1
    assert any(s["reason"] == "cap_edges_1" for s in graph["skips"])


# --------------------------------------------------------------------------
# attack paths
# --------------------------------------------------------------------------

def _path_fixture():
    return dict(
        asm=_asm(hosts=[_host("a.example", ["203.0.113.7"])],
                 storage=[_storage_result(name="acme-backup")]),
        cloud=_cloud(resources=[
            _res(rid="i-1", name="web",
                 config={"public_ip": "203.0.113.7"}),
            _res(rtype="storage", service="s3", rid="acme-backup",
                 name="acme-backup")]),
        findings=[
            _code(rule_id="SSRF", snippet="http://203.0.113.7/admin"),
            _code(rule_id="PUBBUCKET", snippet='bucket = "acme-backup"'),
            _code(rule_id="UNRELATED", snippet="password = 1"),
        ], as_of=AS_OF)


def test_attack_path_external_resource_code_finding():
    graph = build_graph(**_path_fixture())
    got = [(p["path"], p["edges"]) for p in graph["attack_paths"]]
    assert got == [
        (["ext:host:a.example", "res:aws:compute:i-1",
          "find:code:SSRF:app.py:10"], ["host_ip", "finding_mention"]),
        (["ext:storage:aws_s3:acme-backup",
          "res:aws:storage:acme-backup",
          "find:code:PUBBUCKET:app.py:10"],
         ["bucket_name", "finding_mention"]),
    ]


def test_attack_path_explanation_names_every_node():
    graph = build_graph(**_path_fixture())
    first = graph["attack_paths"][0]
    assert "a.example" in first["explanation"]
    assert "i-1" in first["explanation"]
    assert "203.0.113.7" in first["explanation"]
    assert "SSRF" in first["explanation"]


def test_no_path_terminating_at_iam_or_cis_finding():
    arn = "arn:aws:iam::123456789012:user/alice"
    graph = build_graph(
        asm=_asm(hosts=[_host("a.example", ["203.0.113.7"])]),
        cloud=_cloud(resources=[
            _res(rid="i-1", config={"public_ip": "203.0.113.7"})]),
        iam=_iam(principals=[_principal(arn=arn)],
                 findings=[_iam_finding(subject=arn)]),
        as_of=AS_OF)
    # iam_subject edge exists, but task.md paths end at code findings
    assert any(e[2] == "iam_subject" for e in _edge_set(graph))
    assert graph["attack_paths"] == []


def test_path_requires_both_halves():
    graph = build_graph(
        asm=_asm(hosts=[_host("a.example", ["203.0.113.7"])]),
        cloud=_cloud(resources=[
            _res(rid="i-1", config={"public_ip": "203.0.113.7"})]),
        findings=[_code(rule_id="NO-MATCH", snippet="nothing here")],
        as_of=AS_OF)
    assert any(e[2] == "host_ip" for e in _edge_set(graph))
    assert graph["attack_paths"] == []


def test_paths_capped_and_disclosed(monkeypatch):
    monkeypatch.setattr(gpaths, "MAX_PATHS", 1)
    graph = build_graph(**_path_fixture())
    assert len(graph["attack_paths"]) == 1
    assert any(s["reason"] == "cap_paths_1" for s in graph["skips"])


def test_paths_sorted_and_input_order_invariant():
    fixture = _path_fixture()
    a = build_graph(**fixture)
    shuffled = dict(fixture)
    shuffled["findings"] = list(reversed(fixture["findings"]))
    shuffled["cloud"] = _cloud(resources=list(reversed(
        fixture["cloud"]["inventory"]["resources"])))
    b = build_graph(**shuffled)
    assert json.dumps(a["attack_paths"], sort_keys=True) == \
        json.dumps(b["attack_paths"], sort_keys=True)
    ids = [p["path"] for p in a["attack_paths"]]
    assert ids == sorted(ids)


def test_stats_counts_by_kind():
    graph = build_graph(**_path_fixture())
    assert graph["stats"]["nodes"] == len(graph["nodes"])
    assert graph["stats"]["edges"] == len(graph["edges"])
    assert graph["stats"]["attack_paths"] == len(graph["attack_paths"])
    by_kind = {n["kind"] for n in graph["nodes"]}
    assert by_kind == {"external", "resource", "finding"}


# --------------------------------------------------------------------------
# ingest (connect)
# --------------------------------------------------------------------------

def test_collect_graph_missing_file_is_skip_not_crash(tmp_path):
    good = tmp_path / "rsx_t64_cloud.json"
    good.write_text(json.dumps(_cloud(resources=[_res(rid="i-1")])),
                    encoding="utf-8")
    graph = collect_graph(
        files={"cloud": str(good),
               "asm": str(tmp_path / "rsx_t64_absent.json")},
        as_of=AS_OF)
    assert any(s["stage"] == "asm" and "FileNotFoundError" in s["reason"]
               for s in graph["skips"])
    assert any(n["id"] == "res:aws:compute:i-1" for n in graph["nodes"])


def test_collect_graph_wrong_schema_skip(tmp_path):
    asm_path = tmp_path / "rsx_t64_asm.json"
    bad = _asm()
    bad["schema"] = "rsecopsx.asm_inventory/v0"
    asm_path.write_text(json.dumps(bad), encoding="utf-8")
    graph = collect_graph(files={"asm": str(asm_path)}, as_of=AS_OF)
    skip = next(s for s in graph["skips"] if s["reason"] == "wrong_schema")
    assert skip["stage"] == "asm"
    assert graph["nodes"] == []


def test_collect_graph_findings_payload_or_list(tmp_path):
    payload = tmp_path / "rsx_t64_payload.json"
    payload.write_text(json.dumps({"findings": [_code(rule_id="P")]}),
                       encoding="utf-8")
    bare = tmp_path / "rsx_t64_bare.json"
    bare.write_text(json.dumps([_code(rule_id="P")]), encoding="utf-8")
    a = collect_graph(files={"findings": str(payload)}, as_of=AS_OF)
    b = collect_graph(files={"findings": str(bare)}, as_of=AS_OF)
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)
    assert any(n["id"] == "find:code:P:app.py:10" for n in a["nodes"])


def test_collect_graph_bad_findings_shape_skip(tmp_path):
    bad = tmp_path / "rsx_t64_bad.json"
    bad.write_text(json.dumps({"findings": {"not": "a list"}}),
                   encoding="utf-8")
    graph = collect_graph(files={"findings": str(bad)}, as_of=AS_OF)
    assert any(s["reason"] == "bad_findings_shape" for s in graph["skips"])


def test_cli_default_stdout_artifact(capsys):
    rc = main([])
    out = capsys.readouterr().out
    assert rc == 0
    doc = json.loads(out)
    assert doc["schema"] == gmodel.SCHEMA
    assert doc["nodes"] == []
    assert any(s["reason"] == "not_provided" for s in doc["skips"])


def test_cli_bad_as_of_rc2(capsys):
    rc = main(["--as-of", "not-a-timestamp"])
    assert rc == 2


def test_cli_out_file_byte_identical_two_runs(tmp_path):
    out_a = tmp_path / "rsx_t64_graph_a.json"
    out_b = tmp_path / "rsx_t64_graph_b.json"
    assert main(["--as-of", "2026-10-31T12:00:00Z",
                 "--out", str(out_a)]) == 0
    assert main(["--as-of", "2026-10-31T12:00:00Z",
                 "--out", str(out_b)]) == 0
    assert out_a.read_bytes() == out_b.read_bytes()


def test_graph_package_sources_are_offline_pinned():
    import analysis.graph as pkg
    import pathlib
    pkg_dir = pathlib.Path(pkg.__file__).parent
    forbidden = ("urllib", "socket", "boto3", "requests",
                 "os.environ", "http.client")
    for src in sorted(pkg_dir.glob("*.py")):
        text = src.read_text(encoding="utf-8")
        for token in forbidden:
            assert token not in text, f"{src.name} contains {token!r}"


def test_analysis_graph_submodules_not_shadowed():
    import analysis.graph as pkg
    assert pkg.model.__name__ == "analysis.graph.model"
    assert pkg.links.__name__ == "analysis.graph.links"
    assert pkg.paths.__name__ == "analysis.graph.paths"
    assert callable(pkg.build_graph)


# --------------------------------------------------------------------------
# Phase-6 gate: sandbox-account link verification + ASM reproducibility
# --------------------------------------------------------------------------

EC2_XML = """<?xml version="1.0" encoding="UTF-8"?>
<DescribeInstancesResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
  <reservationSet><item><instancesSet><item>
    <instanceId>i-0sandbox000000001</instanceId>
    <instanceType>t3.micro</instanceType>
    <state><name>running</name></state>
    <publicIpAddress>203.0.113.10</publicIpAddress>
    <metadataOptions><httpTokens>required</httpTokens></metadataOptions>
    <tagSet><item><key>rsx-sandbox-web</key><value>web</value></item></tagSet>
  </item></instancesSet></item></reservationSet>
</DescribeInstancesResponse>"""

S3_LIST_XML = """<?xml version="1.0" encoding="UTF-8"?>
<ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Owner><ID>owner</ID><DisplayName>rsx-sandbox</DisplayName></Owner>
  <Buckets><Bucket><Name>rsx-sandbox</Name>
    <CreationDate>2026-01-01T00:00:00.000Z</CreationDate>
  </Bucket></Buckets>
</ListAllMyBucketsResult>"""

IAM_LIST_XML = """<?xml version="1.0" encoding="UTF-8"?>
<ListUsersResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
  <ListUsersResult><Users><member>
    <UserName>alice</UserName>
    <UserId>AIDARSXSANDBOXALICE</UserId>
    <Arn>arn:aws:iam::123456789012:user/alice</Arn>
    <CreateDate>2026-01-01T00:00:00Z</CreateDate>
  </member></Users></ListUsersResult>
</ListUsersResponse>"""

IAM_AUTHZ_PAGE = """<?xml version="1.0" encoding="UTF-8"?>
<GetAccountAuthorizationDetailsResponse
    xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
  <GetAccountAuthorizationDetailsResult>
    <UserDetailList><member>
      <UserName>alice</UserName>
      <UserId>AIDARSXSANDBOXALICE</UserId>
      <Arn>arn:aws:iam::123456789012:user/alice</Arn>
      <CreateDate>2026-01-01T00:00:00Z</CreateDate>
      <UserPolicyList><member>
        <PolicyName>admin-inline</PolicyName>
        <PolicyDocument>%7B%22Version%22%3A%222012-10-17%22%2C%22Statem"""
IAM_AUTHZ_PAGE += """ent%22%3A%5B%7B%22Effect%22%3A%22Allow%22%2C%22Action%22%3A%22*%22%2C%22R"""
IAM_AUTHZ_PAGE += """esource%22%3A%22*%22%7D%5D%7D</PolicyDocument>
      </member></UserPolicyList>
    </member></UserDetailList>
    <RoleDetailList/>
    <GroupDetailList/>
    <Policies/>
  </GetAccountAuthorizationDetailsResult>
</GetAccountAuthorizationDetailsResponse>"""

LISTING_XML = ("<ListBucketResult><Name>rsx-sandbox</Name>"
               "<Contents><Key>a.txt</Key></Contents>"
               "</ListBucketResult>")


def _mk_dns_response(query, a_records, cname=None, rcode=0):
    import struct
    from analysis.asm.dnsx import QTYPE_A, QTYPE_CNAME
    tid = int.from_bytes(query[0:2], "big")
    answers = []
    for ip in a_records:
        answers.append(b"\xc0\x0c" + struct.pack(">HHIH", QTYPE_A, 1, 60, 4)
                       + bytes(int(x) for x in ip.split(".")))
    if cname:
        wire = b"".join(bytes([len(p)]) + p.encode()
                        for p in cname.split(".")) + b"\x00"
        answers.append(b"\xc0\x0c"
                        + struct.pack(">HHIH", QTYPE_CNAME, 1, 60,
                                      len(wire)) + wire)
    header = struct.pack(">HHHHHH", tid, 0x8180 | rcode, 1, len(answers),
                         0, 0)
    return header + query[12:] + b"".join(answers)


def _make_send(mapping):
    from analysis.asm.dnsx import decode_name

    def _send(query: bytes) -> bytes:
        name, _ = decode_name(query, 12)
        rec = mapping.get(name)
        if not rec:
            return _mk_dns_response(query, [], rcode=3)
        return _mk_dns_response(query, rec.get("a", []),
                                cname=rec.get("cname"))
    return _send


def _sandbox_asm():
    import io
    import urllib.error

    def _http(url: str):
        if url == "https://rsx-sandbox.s3.amazonaws.com":
            return 200, {}, LISTING_XML.encode(), url
        raise urllib.error.HTTPError(url, 404, "Not Found", {},
                                     io.BytesIO(b""))

    send = _make_send({
        "rsx-sandbox.example.com": {"a": ["203.0.113.9"]},
        "www.rsx-sandbox.example.com": {"a": ["203.0.113.10"]},
    })
    return build_inventory(
        "rsx-sandbox.example.com", as_of=AS_OF,
        stage_brute=True, stage_resolve=True, stage_ports=True,
        stage_storage=True, words=("www",),
        send=send, http=_http,
        connect=lambda host, port, timeout: port == 80,
        sleep=lambda s: None)


def test_asm_inventory_reproducible_run_to_run():
    a = _sandbox_asm()
    b = _sandbox_asm()
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)
    assert a["stats"]["hosts"] == 2
    storage = next(r for r in a["storage"]["results"]
                   if r["name"] == "rsx-sandbox")
    assert storage["provider"] == "aws_s3" and storage["public"] is True


def test_sandbox_account_graph_links_verified(tmp_path):
    """Phase-6 gate: graph links verified against a known sandbox
    account (offline capture fixture; no live credentials on box)."""
    asm = _sandbox_asm()
    asm_path = tmp_path / "rsx_t64_asm.json"
    asm_path.write_text(json.dumps(asm), encoding="utf-8")

    cloud_capture = {"ops": {
        "ec2:DescribeInstances": [EC2_XML],
        "s3:ListBuckets": [S3_LIST_XML],
        "s3:GetPublicAccessBlock:rsx-sandbox": ["__absent__"],
        "iam:ListUsers": [IAM_LIST_XML],
    }}
    cloud_cap = tmp_path / "rsx_t64_cloud_cap.json"
    cloud_cap.write_text(json.dumps(cloud_capture), encoding="utf-8")
    cloud = collect_posture(("aws",),
                            files={"aws": str(cloud_cap)}, as_of=AS_OF)
    cloud_path = tmp_path / "rsx_t64_cloud.json"
    cloud_path.write_text(json.dumps(cloud), encoding="utf-8")

    iam_cap = tmp_path / "rsx_t64_iam_cap.json"
    iam_cap.write_text(json.dumps({"ops": {
        "iam:GetAccountAuthorizationDetails": [IAM_AUTHZ_PAGE]}}),
        encoding="utf-8")
    iam = collect_iam(("aws",), files={"aws": str(iam_cap)},
                      as_of=AS_OF)
    assert any(p["arn"] == "arn:aws:iam::123456789012:user/alice"
               for p in iam["principals"])
    iam_path = tmp_path / "rsx_t64_iam.json"
    iam_path.write_text(json.dumps(iam), encoding="utf-8")

    findings = [
        {"rule_id": "TF-S3-PUBLIC", "title": "public bucket",
         "file": "infra/s3.tf", "line": 12, "severity": "high",
         "vuln_type": "misconfiguration", "cwe": "284",
         "description": "bucket rsx-sandbox is world-listable",
         "snippet": 'resource "aws_s3_bucket" "pub" {\n'
                    '  bucket = "rsx-sandbox"\n}',
         "evidence": {}},
        {"rule_id": "CFG-SSRF-ENDPOINT", "title": "hardcoded upstream",
         "file": "nginx/site.conf", "line": 3, "severity": "medium",
         "vuln_type": "ssrf", "cwe": "918",
         "description": "upstream pinned to an internet address",
         "snippet": "proxy_pass http://203.0.113.10/admin;",
         "evidence": {"url": "http://203.0.113.10/admin"}},
    ]
    findings_path = tmp_path / "rsx_t64_findings.json"
    findings_path.write_text(json.dumps({"findings": findings}),
                             encoding="utf-8")

    files = {"asm": str(asm_path), "cloud": str(cloud_path),
             "iam": str(iam_path), "findings": str(findings_path)}
    graph = collect_graph(files=files, as_of=AS_OF)

    alice = "arn:aws:iam::123456789012:user/alice"
    expected_edges = {
        ("ext:host:www.rsx-sandbox.example.com",
         "res:aws:compute:i-0sandbox000000001", "host_ip"),
        ("ext:storage:aws_s3:rsx-sandbox",
         "res:aws:storage:rsx-sandbox", "bucket_name"),
        ("res:aws:storage:rsx-sandbox",
         "find:code:TF-S3-PUBLIC:infra/s3.tf:12", "finding_mention"),
        ("res:aws:compute:i-0sandbox000000001",
         "find:code:CFG-SSRF-ENDPOINT:nginx/site.conf:3",
         "finding_mention"),
        ("res:aws:identity:AIDARSXSANDBOXALICE", "res:iam:" + alice,
         "identity"),
    }
    assert expected_edges <= _edge_set(graph)
    assert any(e[0] == "res:iam:" + alice and e[2] == "iam_subject"
               for e in _edge_set(graph))

    got_paths = [tuple(p["path"]) for p in graph["attack_paths"]]
    assert got_paths == [
        ("ext:host:www.rsx-sandbox.example.com",
         "res:aws:compute:i-0sandbox000000001",
         "find:code:CFG-SSRF-ENDPOINT:nginx/site.conf:3"),
        ("ext:storage:aws_s3:rsx-sandbox",
         "res:aws:storage:rsx-sandbox",
         "find:code:TF-S3-PUBLIC:infra/s3.tf:12"),
    ]
    # run-to-run reproducibility of the whole join
    again = collect_graph(files=files, as_of=AS_OF)
    assert json.dumps(graph, sort_keys=True) == \
        json.dumps(again, sort_keys=True)
