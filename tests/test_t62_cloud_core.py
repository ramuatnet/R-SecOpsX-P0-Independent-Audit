"""T-6.2: cloud posture -- SigV4, transport bounds, normalizers,
CIS checks, posture rollup, connector orchestration + CLI.

Everything network-shaped is fakes (send recorder/bombs); the clock is
injected.  Headlines:
  * SigV4 pinned to the AWS documentation vector;
  * default run does ZERO network I/O, byte-identical;
  * missing data is always an insufficient_data gap, never a pass;
  * per-provider failures become skips, never raises.
"""
from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone

import pytest

from analysis.cloud import cis, model, posture
from analysis.cloud.client import (ApiError, ResponseTooLarge, bearer_call,
                                   http_call, parse_json)
from analysis.cloud.connect import (MAX_DETAIL_CALLS, MAX_PAGES, SCHEMA,
                                    collect_posture, main,
                                    resolve_credentials)
from analysis.cloud.sigv4 import (canonical_query, sha256_hex, sign_request,
                                  signing_key)

AS_OF = datetime(2026, 10, 31, 12, 0, 0, tzinfo=timezone.utc)

# AWS documentation SigV4 example
_VECTOR_SIG = "5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
_VECTOR_CANON = "f536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59"


class NetworkBomb:
    def __call__(self, *a, **k):
        raise AssertionError(f"network attempted: {a!r} {k!r}")


def _sign_vector(now=None):
    now = now or datetime(2015, 8, 30, 12, 36, 0, tzinfo=timezone.utc)
    url = "https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08"
    return sign_request(
        "GET", url,
        {"Content-Type": "application/x-www-form-urlencoded; charset=utf-8"},
        b"", access_key="AKIDEXAMPLE",
        secret_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        region="us-east-1", service="iam", now=now), url


# ---------------------------------------------------------------------------
# sigv4
# ---------------------------------------------------------------------------

def test_sigv4_matches_aws_documentation_vector():
    headers, url = _sign_vector()
    got = headers["authorization"].split("Signature=")[1]
    assert got == _VECTOR_SIG
    # intermediate canonical hash pinned too
    from analysis.cloud.sigv4 import canonical_request
    low = {k: v for k, v in headers.items() if k != "authorization"}
    canon, _signed = canonical_request(
        "GET", url, low, sha256_hex(b""))
    assert sha256_hex(canon.encode()) == _VECTOR_CANON


def test_sigv4_is_deterministic_and_secret_sensitive():
    a, _ = _sign_vector()
    b, _ = _sign_vector()
    assert a == b
    url = "https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08"
    c = sign_request("GET", url, {}, b"", access_key="AKIDEXAMPLE",
                     secret_key="different-secret",
                     region="us-east-1", service="iam",
                     now=datetime(2015, 8, 30, 12, 36, 0,
                                  tzinfo=timezone.utc))
    assert c["authorization"] != a["authorization"]


def test_sigv4_host_header_from_url_with_port_and_case_fold():
    out = sign_request("GET", "https://example.test:8443/x", {"X-TeSt": "1"},
                       b"", access_key="k", secret_key="s",
                       region="us-east-1", service="ec2", now=AS_OF)
    assert out["host"] == "example.test:8443"
    assert out["x-test"] == "1" and "X-TeSt" not in out
    assert "x-amz-date" in out and out["authorization"].startswith(
        "AWS4-HMAC-SHA256 ")


def test_canonical_query_normalizes_encoding_and_order():
    assert canonical_query("b=2&a=1") == "a=1&b=2"
    assert canonical_query("a%20b=c") == canonical_query("a b=c")


def test_signing_key_chain_is_service_scoped():
    k1 = signing_key("secret", "20261031", "us-east-1", "ec2")
    k2 = signing_key("secret", "20261031", "us-west-2", "ec2")
    assert k1 != k2 and len(k1) == 32


# ---------------------------------------------------------------------------
# client bounds
# ---------------------------------------------------------------------------

def test_http_call_raises_api_error_with_bounded_excerpt():
    def send(method, url, headers, body):
        return 403, {}, (b"denied " * 100)
    with pytest.raises(ApiError) as exc:
        http_call(send, "GET", "https://x", {}, b"")
    assert exc.value.status == 403
    assert len(exc.value.excerpt) <= 200


def test_http_call_enforces_response_size_cap():
    def send(method, url, headers, body):
        return 200, {}, b"x" * (4 * 1024 * 1024 + 1)
    with pytest.raises(ResponseTooLarge):
        http_call(send, "GET", "https://x", {}, b"")


def test_bearer_call_sets_header_and_parse_json_discloses():
    seen = {}

    def send(method, url, headers, body):
        seen.update(headers)
        return 200, {}, b'{"ok": true}'
    st, text = bearer_call(send, "GET", "https://x", {"X-A": "1"},
                           b"", "tok-123")
    assert seen["authorization"] == "Bearer tok-123"
    assert parse_json(text, op="op") == {"ok": True}
    with pytest.raises(ApiError):
        parse_json("{not json", op="bad-op")


# ---------------------------------------------------------------------------
# normalizers (fixtures mirror documented API shapes)
# ---------------------------------------------------------------------------

def test_aws_instances_normalize_with_xmlns_root():
    page = ('<DescribeInstancesResponse '
            'xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">'
            "<reservationSet><item><instancesSet><item>"
            "<instanceId>i-1</instanceId><instanceType>t3.micro</instanceType>"
            "<state><name>running</name></state>"
            "<publicIpAddress>1.2.3.4</publicIpAddress>"
            "<metadataOptions><httpTokens>optional</httpTokens>"
            "</metadataOptions></item></instancesSet></item>"
            "</reservationSet></DescribeInstancesResponse>")
    res = model.aws_instances([page])
    assert res == [{"provider": "aws", "type": "compute", "service": "ec2",
                    "id": "i-1", "name": "i-1", "region": "",
                    "config": {"instance_type": "t3.micro",
                               "state": "running", "public_ip": "1.2.3.4",
                               "imds_http_tokens": "optional"},
                    "tags": {}}]


def test_aws_security_groups_extract_world_ingress():
    page = ("<DescribeSecurityGroupsResponse><securityGroupSet><item>"
            "<groupId>sg-1</groupId><groupName>web</groupName>"
            "<ipPermissions><item><ipProtocol>tcp</ipProtocol>"
            "<fromPort>22</fromPort><toPort>22</toPort>"
            "<ipRanges><item><cidrIp>0.0.0.0/0</cidrIp></item></ipRanges>"
            "</item></ipPermissions></item></securityGroupSet>"
            "</DescribeSecurityGroupsResponse>")
    res = model.aws_security_groups([page])
    assert res[0]["config"]["ingress"] == [
        {"protocol": "tcp", "from_port": "22", "to_port": "22",
         "cidrs": ["0.0.0.0/0"]}]


def test_aws_volumes_users_summary_normalize():
    vols = model.aws_volumes(
        ["<DescribeVolumesResponse><volumeSet><item><volumeId>vol-1</volumeId>"
         "<encrypted>true</encrypted><kmsKeyId>key-1</kmsKeyId>"
         "<state>in-use</state><size>10</size></item></volumeSet>"
         "</DescribeVolumesResponse>"])
    assert vols[0]["config"]["encrypted"] is True
    users = model.aws_users(
        ["<ListUsersResponse><ListUsersResult><Users><member>"
         "<UserName>alice</UserName><UserId>AIDA1</UserId>"
         "<PasswordLastUsed>2026-01-01T00:00:00Z</PasswordLastUsed>"
         "</member></Users></ListUsersResult></ListUsersResponse>"], AS_OF)
    assert users[0]["config"]["password_last_used_days"] == 303
    summary = model.aws_account_summary(
        ["<GetAccountSummaryResponse><GetAccountSummaryResult><SummaryMap>"
         "<entry><key>AccountMFAEnabled</key><value>0</value></entry>"
         "</SummaryMap></GetAccountSummaryResult></GetAccountSummaryResponse>"])
    assert summary[0]["config"]["summary"] == {"AccountMFAEnabled": "0"}


def test_aws_bucket_paab_four_states():
    buckets = ("<ListAllMyBucketsResult><Buckets><Bucket><Name>b1</Name>"
               "</Bucket><Bucket><Name>b2</Name></Bucket>"
               "<Bucket><Name>b3</Name></Bucket><Bucket><Name>b4</Name>"
               "</Bucket></Buckets></ListAllMyBucketsResult>")
    full = ("<PublicAccessBlockConfiguration><BlockPublicAcls>true"
            "</BlockPublicAcls><IgnorePublicAcls>true</IgnorePublicAcls>"
            "<BlockPublicPolicy>true</BlockPublicPolicy>"
            "<RestrictPublicBuckets>true</RestrictPublicBuckets>"
            "</PublicAccessBlockConfiguration>")
    res = model.aws_buckets([buckets], {
        "b1": full,                                  # observed, complete
        "b2": model.ABSENT,                          # observed, all-false
        # b3: not observed (fetch failed) -> None + False
        "b4": full.replace("true", "false", 1),      # observed, partial
    })
    by_id = {r["id"]: r["config"] for r in res}
    assert by_id["b1"]["public_access_block"]["block_public_acls"] is True
    assert by_id["b2"]["public_access_block"] == {
        "block_public_acls": False, "ignore_public_acls": False,
        "block_public_policy": False, "restrict_public_buckets": False}
    assert by_id["b3"]["public_access_block"] is None
    assert by_id["b3"]["public_access_block_observed"] is False
    assert by_id["b4"]["public_access_block"]["block_public_acls"] is False


def test_aws_keys_and_trails_detail_states():
    keys = model.aws_keys(
        [json.dumps({"Keys": [{"KeyId": "k-1", "KeyState": "Enabled"},
                              {"KeyId": "k-2", "KeyState": "Disabled"}]})],
        {"k-1": json.dumps({"KeyRotationEnabled": False})})
    k1 = [r for r in keys if r["id"] == "k-1"][0]
    k2 = [r for r in keys if r["id"] == "k-2"][0]
    assert k1["config"]["rotation_enabled"] is False
    assert k1["config"]["rotation_observed"] is True
    assert k2["config"]["rotation_observed"] is False   # no detail fetched
    trails = model.aws_trails(
        [json.dumps({"trailList": [{"Name": "t", "IsMultiRegionTrail": True,
                                    "LogFileValidationEnabled": True}]})],
        {"t": json.dumps({"IsLogging": True})})
    assert trails[0]["config"]["is_logging"] is True
    assert trails[0]["config"]["status_observed"] is True


def test_gcp_normalizers_and_azure_normalizers():
    inst = model.gcp_instances([json.dumps({"items": {
        "zones/us-central1-a": {"instances": [{
            "id": 7, "name": "g1", "status": "RUNNING",
            "zone": "zones/us-central1-a",
            "networkInterfaces": [{"accessConfigs": [{"natIP": "9.9.9.9"}]}],
        }]}}})])
    assert inst[0]["config"]["public_ip"] == "9.9.9.9"
    fw = model.gcp_firewalls([json.dumps({"items": [{
        "name": "allow-ssh", "direction": "INGRESS",
        "sourceRanges": ["0.0.0.0/0"],
        "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}]}]})])
    assert fw[0]["config"]["ports"] == ["22"]
    buckets = model.gcp_buckets(
        [json.dumps({"items": [{"name": "b", "location": "US",
                                "storageClass": "STANDARD"}]})],
        {"b": json.dumps({"bindings": [
            {"role": "roles/storage.objectViewer",
             "members": ["allUsers"]}]})})
    assert buckets[0]["config"]["public_members"] == ["allUsers"]
    keys = model.gcp_keys([json.dumps({"keys": [{
        "name": "projects/p/locations/l/keyRings/r/keys/k1",
        "rotationPeriod": "31557600s", "primary": {"state": "ENABLED"}}]})])
    assert keys[0]["config"]["rotation_period"] == "31557600s"
    stor = model.az_storage_accounts([json.dumps({"value": [{
        "id": "/subscriptions/s/x", "name": "sa", "location": "eastus",
        "properties": {"allowBlobPublicAccess": True,
                       "enableHttpsTrafficOnly": False,
                       "minimumTlsVersion": "TLS1_2"}}]})])
    assert stor[0]["config"] == {"blob_public_access": True,
                                 "https_only": False, "min_tls": "TLS1_2"}
    nsgs = model.az_nsgs([json.dumps({"value": [{
        "id": "/subscriptions/s/n", "name": "nsg", "location": "eastus",
        "properties": {"securityRules": [{
            "name": "ssh", "properties": {
                "direction": "Inbound", "access": "Allow",
                "protocol": "Tcp", "sourceAddressPrefix": "0.0.0.0/0",
                "destinationPortRange": "22"}}]}}]})])
    assert nsgs[0]["config"]["security_rules"][0]["source"] == "0.0.0.0/0"
    vms = model.az_vms([json.dumps({"value": [{
        "id": "/subscriptions/s/vm/1", "name": "vm", "location": "eastus",
        "properties": {"hardwareProfile": {"vmSize": "Standard_B1s"}}}]})])
    assert vms[0]["config"]["vm_size"] == "Standard_B1s"


def test_normalize_sorts_and_dispatches_providers():
    raws = {"ec2:DescribeVolumes": [
        "<DescribeVolumesResponse><volumeSet>"
        "<item><volumeId>vol-2</volumeId><encrypted>true</encrypted></item>"
        "<item><volumeId>vol-1</volumeId><encrypted>false</encrypted></item>"
        "</volumeSet></DescribeVolumesResponse>"]}
    res = model.normalize("aws", raws, AS_OF)
    assert [r["id"] for r in res] == ["vol-1", "vol-2"]   # sorted
    assert model.normalize("gcp", {}, AS_OF) == []


# ---------------------------------------------------------------------------
# posture rollup
# ---------------------------------------------------------------------------

def test_posture_rollup_public_unencrypted_unlogged():
    res = [
        {"provider": "aws", "type": "storage", "service": "s3",
         "id": "open", "config": {"public_access_block_observed": True,
                                  "public_access_block": {
                                      "block_public_acls": True,
                                      "ignore_public_acls": True,
                                      "block_public_policy": False,
                                      "restrict_public_buckets": True}}},
        {"provider": "gcp", "type": "storage", "service": "storage",
         "id": "gb", "config": {"iam_observed": True,
                                "public_members": ["allUsers"]}},
        {"provider": "azure", "type": "storage", "service": "storage",
         "id": "sa", "config": {"blob_public_access": True}},
        {"provider": "aws", "type": "storage", "service": "ec2",
         "id": "vol-1", "config": {"encrypted": False}},
        {"provider": "aws", "type": "logging", "service": "cloudtrail",
         "id": "t", "config": {"status_observed": True,
                               "is_logging": False}},
    ]
    out = posture.rollup(res)
    # contract: sorted (provider, resource_id, reason) -- aws < azure < gcp
    assert [r["resource_id"] for r in out["public_buckets"]] == \
        ["open", "sa", "gb"]
    assert out["unencrypted_stores"] == [
        {"provider": "aws", "resource_id": "vol-1",
         "reason": "ebs_encrypted=false"}]
    assert out["unlogged"][0]["reason"] == "is_logging=false"


def test_posture_unlogged_account_when_no_trails_but_aws_present():
    res = [{"provider": "aws", "type": "identity", "service": "iam",
            "id": "u1", "config": {}}]
    out = posture.rollup(res)
    assert out["unlogged"] == [
        {"provider": "aws", "resource_id": "account",
         "reason": "cloudtrail_not_configured"}]


# ---------------------------------------------------------------------------
# CIS checks
# ---------------------------------------------------------------------------

def _run(provider, res):
    return cis.run_checks(provider, res, AS_OF)


def _compliant_trail():
    """So cloudtrail_exists doesn't fire on fixtures that only probe
    other checks (it legitimately fires when zero trails are observed)."""
    return {"provider": "aws", "type": "logging", "service": "cloudtrail",
            "id": "t-ok",
            "config": {"multi_region": True, "log_file_validation": True,
                       "is_logging": True, "status_observed": True}}


def test_root_mfa_and_access_key_pos_neg():
    acct = {"provider": "aws", "type": "identity", "service": "iam",
            "id": "account-summary",
            "config": {"summary": {"AccountMFAEnabled": "0",
                                   "AccountAccessKeysPresent": "1"}}}
    findings, gaps = _run("aws", [acct, _compliant_trail()])
    ids = {f["check_id"] for f in findings}
    assert ids == {"cis.aws.root_mfa", "cis.aws.root_access_key"}
    # missing summary -> gaps, never a silent pass
    findings, gaps = _run("aws", [])
    assert {g["check_id"] for g in gaps} >= {"cis.aws.root_mfa",
                                             "cis.aws.root_access_key"}
    # compliant
    acct["config"]["summary"] = {"AccountMFAEnabled": "1",
                                 "AccountAccessKeysPresent": "0"}
    findings, _ = _run("aws", [acct, _compliant_trail()])
    assert findings == []


def test_sg_world_ssh_only_rdp_clean_and_protocol_all():
    sg = {"provider": "aws", "type": "network", "service": "ec2",
          "id": "sg-1",
          "config": {"ingress": [
              {"protocol": "tcp", "from_port": "22", "to_port": "22",
               "cidrs": ["0.0.0.0/0"]},
              {"protocol": "tcp", "from_port": "443", "to_port": "443",
               "cidrs": ["10.0.0.0/8"]}]}}
    res = [sg, _compliant_trail()]
    findings, _ = _run("aws", res)
    assert [f["check_id"] for f in findings] == ["cis.aws.sg_ssh_world"]
    sg["config"]["ingress"][0] = {"protocol": "-1", "from_port": "",
                                  "to_port": "", "cidrs": ["::/0"]}
    findings, _ = _run("aws", res)
    assert {f["check_id"] for f in findings} == {"cis.aws.sg_ssh_world",
                                                 "cis.aws.sg_rdp_world"}
    # no security groups at all -> disclosed gap, not a pass
    _, gaps = _run("aws", [])
    assert any(g["check_id"] == "cis.aws.sg_ssh_world" and
               g["reason"] == "no_resources" for g in gaps)


def test_ebs_unencrypted_finds_volumes_not_buckets():
    res = [
        {"provider": "aws", "type": "storage", "service": "ec2",
         "id": "vol-1", "config": {"encrypted": False, "state": "in-use"}},
        {"provider": "aws", "type": "storage", "service": "ec2",
         "id": "vol-2", "config": {"encrypted": True, "state": "in-use"}},
        {"provider": "aws", "type": "storage", "service": "s3",
         "id": "bucket", "config": {"public_access_block_observed": False,
                                    "public_access_block": None}},
    ]
    findings, gaps = _run("aws", res)
    assert [f["resource_id"] for f in findings
            if f["check_id"] == "cis.aws.ebs_unencrypted"] == ["vol-1"]
    # bucket's unobserved PAAB -> gap, bucket itself no false ebs hit
    assert any(g["check_id"] == "cis.aws.s3_public_access_block"
               for g in gaps)


def test_s3_paab_partial_finding_and_unobserved_gap():
    def bucket(name, observed, flags):
        return {"provider": "aws", "type": "storage", "service": "s3",
                "id": name,
                "config": {"public_access_block_observed": observed,
                           "public_access_block": flags}}
    all_true = {k: True for k in ("block_public_acls", "ignore_public_acls",
                                  "block_public_policy",
                                  "restrict_public_buckets")}
    findings, gaps = _run("aws", [
        bucket("b1", True, dict(all_true, block_public_policy=False)),
        bucket("b2", True, all_true),
        bucket("b3", False, None),
    ])
    hit = [f for f in findings if f["check_id"] ==
           "cis.aws.s3_public_access_block"]
    assert [f["resource_id"] for f in hit] == ["b1"]
    assert hit[0]["evidence"]["disabled"] == ["block_public_policy"]
    assert any("1 buckets unobserved" in g["target"] for g in gaps)


def test_cloudtrail_family_pos_neg_and_status_gap():
    def trail(name, multi, valid, logging, observed):
        return {"provider": "aws", "type": "logging",
                "service": "cloudtrail", "id": name,
                "config": {"multi_region": multi,
                           "log_file_validation": valid,
                           "is_logging": logging,
                           "status_observed": observed}}
    # zero trails (DescribeTrails returned empty) -> exists finding
    findings, _ = _run("aws", [])
    assert any(f["check_id"] == "cis.aws.cloudtrail_exists" and
               f["resource_id"] == "account" for f in findings)
    findings, gaps = _run("aws", [
        trail("t1", False, False, False, True),
        trail("t2", True, True, None, False),
    ])
    ids = [f["check_id"] for f in findings]
    assert ids == ["cis.aws.cloudtrail_multiregion",
                   "cis.aws.cloudtrail_status",
                   "cis.aws.cloudtrail_validation"]
    assert any(g["check_id"] == "cis.aws.cloudtrail_status" and
               "t2" in g["target"] for g in gaps)
    # fully compliant trail -> only exists-positive silence
    findings, _ = _run("aws", [trail("t", True, True, True, True)])
    assert findings == []


def test_kms_rotation_and_iam_stale():
    res = [
        {"provider": "aws", "type": "kms", "service": "kms", "id": "k1",
         "config": {"state": "Enabled", "rotation_enabled": False,
                    "rotation_observed": True}},
        {"provider": "aws", "type": "kms", "service": "kms", "id": "k2",
         "config": {"state": "Enabled", "rotation_enabled": None,
                    "rotation_observed": False}},
        {"provider": "aws", "type": "kms", "service": "kms", "id": "k3",
         "config": {"state": "Disabled", "rotation_enabled": False,
                    "rotation_observed": False}},
        {"provider": "aws", "type": "identity", "service": "iam",
         "id": "AIDA-old",
         "config": {"password_last_used_days": 200}},
        {"provider": "aws", "type": "identity", "service": "iam",
         "id": "AIDA-fresh",
         "config": {"password_last_used_days": 3}},
        {"provider": "aws", "type": "identity", "service": "iam",
         "id": "AIDA-keyonly",
         "config": {"password_last_used_days": None}},
    ]
    findings, gaps = _run("aws", res)
    ids = [(f["check_id"], f["resource_id"]) for f in findings]
    assert ("cis.aws.kms_rotation", "k1") in ids
    assert ("cis.aws.kms_rotation", "k2") not in ids   # -> gap instead
    assert ("cis.aws.kms_rotation", "k3") not in ids   # disabled: N/A
    assert ("cis.aws.iam_stale_password", "AIDA-old") in ids
    assert not any(f["resource_id"] == "AIDA-fresh" for f in findings)
    assert not any(f["resource_id"] == "AIDA-keyonly" for f in findings)
    assert any("kms:GetKeyRotationStatus" in g["target"] for g in gaps)


def test_gcp_firewall_buckets_rotation():
    res = [
        {"provider": "gcp", "type": "network", "service": "compute",
         "id": "allow-ssh",
         "config": {"direction": "INGRESS",
                    "source_ranges": ["0.0.0.0/0"], "ports": ["8000-9000"]}},
        {"provider": "gcp", "type": "network", "service": "compute",
         "id": "egress",
         "config": {"direction": "EGRESS",
                    "source_ranges": ["0.0.0.0/0"], "ports": ["22"]}},
        {"provider": "gcp", "type": "storage", "service": "storage",
         "id": "b1", "config": {"iam_observed": True,
                                "public_members": ["allUsers"]}},
        {"provider": "gcp", "type": "storage", "service": "storage",
         "id": "b2", "config": {"iam_observed": False,
                                "public_members": []}},
        {"provider": "gcp", "type": "kms", "service": "cloudkms",
         "id": "k1", "config": {"state": "ENABLED",
                                "rotation_period": "",
                                "next_rotation": ""}},
        {"provider": "gcp", "type": "kms", "service": "cloudkms",
         "id": "k2", "config": {"state": "ENABLED",
                                "rotation_period": "777600000s"}},
    ]
    findings, gaps = _run("gcp", res)
    by_id = [(f["check_id"], f["resource_id"]) for f in findings]
    # 8000-9000 covers 8443? no -- must NOT cover 22/3389
    assert not any("firewall" in cid for cid, _ in by_id)
    assert any(cid == "cis.gcp.bucket_all_users" and rid == "b1"
               for cid, rid in by_id)
    assert any(g["target"] == "gcs:getIamPolicy:b2" for g in gaps)
    assert ("cis.gcp.kms_rotation", "k1") in by_id      # empty period
    assert ("cis.gcp.kms_rotation", "k2") in by_id      # 9000d > 397d
    # open range covering 22
    res[0]["config"]["ports"] = ["0-65535"]
    findings, _ = _run("gcp", res)
    assert any(f["check_id"] == "cis.gcp.firewall_ssh_world"
               for f in findings)


def test_azure_storage_and_nsg_checks():
    res = [
        {"provider": "azure", "type": "storage", "service": "storage",
         "id": "sa-bad", "config": {"blob_public_access": True,
                                    "https_only": False,
                                    "min_tls": "TLS1_2"}},
        {"provider": "azure", "type": "storage", "service": "storage",
         "id": "sa-ok", "config": {"blob_public_access": False,
                                   "https_only": True,
                                   "min_tls": "TLS1_2"}},
        {"provider": "azure", "type": "network", "service": "network",
         "id": "nsg-1", "config": {"security_rules": [
             {"name": "ssh-open", "direction": "Inbound", "access": "Allow",
              "protocol": "Tcp", "source": "Internet", "port": "22"},
             {"name": "rdp-deny", "direction": "Inbound", "access": "Deny",
              "protocol": "Tcp", "source": "*", "port": "3389"},
             {"name": "range", "direction": "Inbound", "access": "Allow",
              "protocol": "Tcp", "source": "0.0.0.0/0",
              "port": "1000-2000"}]}},
    ]
    findings, _ = _run("azure", res)
    ids = [(f["check_id"], f["resource_id"]) for f in findings]
    assert ("cis.azure.storage_blob_public", "sa-bad") in ids
    assert ("cis.azure.storage_https_off", "sa-bad") in ids
    assert not any(rid == "sa-ok" for _, rid in ids)
    assert ("cis.azure.nsg_ssh_world", "nsg-1") in ids     # Internet src
    assert not any(cid == "cis.azure.nsg_rdp_world"
                   for cid, _ in ids)                      # deny rule
    assert not any("range" in f["evidence"].get("rule", "")
                   for f in findings)                      # 1000-2000


def test_run_checks_stamps_meta_and_sorts():
    findings, gaps = _run("aws", [])
    for f in findings:
        assert f["benchmark"].startswith("CIS Amazon")
        assert f["severity"] in ("high", "medium", "low", "critical")
        assert f["remediation"] and f["explanation"] and f["evidence"]
        assert f["kind"] == "finding"
    assert findings == sorted(findings, key=lambda f: (f["check_id"],
                                                       f["resource_id"],
                                                       f["explanation"]))
    for g in gaps:
        assert g["kind"] == "gap" and g["reason"]


def test_port_covers_edges():
    assert cis.port_covers("22", 22)
    assert not cis.port_covers("22", 3389)
    assert cis.port_covers("1000-2000", 1500)
    assert cis.port_covers("*", 22)
    assert cis.port_covers("", 22)          # empty = all (gcp semantics)
    assert not cis.port_covers("abc", 22)


# ---------------------------------------------------------------------------
# orchestration + CLI
# ---------------------------------------------------------------------------

def _write_capture(tmp_path, ops=None, drop=()):
    raws = {"ops": dict(AWS_CAPTURE)}
    for key in drop:
        raws["ops"].pop(key, None)
    if ops:
        raws["ops"].update(ops)
    path = tmp_path / "aws_cap.json"
    path.write_text(json.dumps(raws), encoding="utf-8")
    return str(path)


def _run_cli(args):
    return main(args)


AWS_CAPTURE = {
    "ec2:DescribeInstances": [
        "<DescribeInstancesResponse><reservationSet/></"
        "DescribeInstancesResponse>"],
    "ec2:DescribeSecurityGroups": [
        "<DescribeSecurityGroupsResponse><securityGroupSet><item>"
        "<groupId>sg-1</groupId><groupName>web</groupName>"
        "<ipPermissions><item><ipProtocol>tcp</ipProtocol>"
        "<fromPort>22</fromPort><toPort>22</toPort>"
        "<ipRanges><item><cidrIp>0.0.0.0/0</cidrIp></item></ipRanges>"
        "</item></ipPermissions></item></securityGroupSet>"
        "</DescribeSecurityGroupsResponse>"],
    "ec2:DescribeSubnets": ["<DescribeSubnetsResponse><subnetSet/>"
                            "</DescribeSubnetsResponse>"],
    "ec2:DescribeVolumes": [
        "<DescribeVolumesResponse><volumeSet><item><volumeId>vol-1"
        "</volumeId><encrypted>false</encrypted><state>in-use</state>"
        "<size>8</size></item></volumeSet></DescribeVolumesResponse>"],
    "iam:ListUsers": [
        "<ListUsersResponse><ListUsersResult><Users><member>"
        "<UserName>alice</UserName><UserId>AIDA1</UserId>"
        "<Arn>arn:aws:iam::1:user/alice</Arn>"
        "<CreateDate>2020-01-01T00:00:00Z</CreateDate>"
        "<PasswordLastUsed>2026-01-01T00:00:00Z</PasswordLastUsed>"
        "</member></Users><IsTruncated>false</IsTruncated>"
        "</ListUsersResult></ListUsersResponse>"],
    "iam:GetAccountSummary": [
        "<GetAccountSummaryResponse><GetAccountSummaryResult>"
        "<SummaryMap><entry><key>AccountMFAEnabled</key><value>0"
        "</value></entry><entry><key>AccountAccessKeysPresent</key>"
        "<value>1</value></entry></SummaryMap>"
        "</GetAccountSummaryResult></GetAccountSummaryResponse>"],
    "s3:ListBuckets": ["<ListAllMyBucketsResult><Buckets><Bucket>"
                       "<Name>open-bucket</Name></Bucket></Buckets>"
                       "</ListAllMyBucketsResult>"],
    "s3:GetPublicAccessBlock:open-bucket": [
        "<PublicAccessBlockConfiguration><BlockPublicAcls>false"
        "</BlockPublicAcls><IgnorePublicAcls>true</IgnorePublicAcls>"
        "<BlockPublicPolicy>false</BlockPublicPolicy>"
        "<RestrictPublicBuckets>false</RestrictPublicBuckets>"
        "</PublicAccessBlockConfiguration>"],
    "kms:ListKeys": [json.dumps({"Keys": [{"KeyId": "k-1",
                                           "KeyState": "Enabled"}],
                                 "Truncated": False})],
    "kms:GetKeyRotationStatus:k-1": [json.dumps(
        {"KeyRotationEnabled": False})],
    "cloudtrail:DescribeTrails": [json.dumps({"trailList": [{
        "Name": "main", "IsMultiRegionTrail": False,
        "LogFileValidationEnabled": False,
        "S3BucketName": "logs"}]})],
    "cloudtrail:GetTrailStatus:main": [json.dumps({"IsLogging": False})],
}


def test_default_run_is_offline_byte_identical(tmp_path):
    bomb = NetworkBomb()
    a = collect_posture((), as_of=AS_OF, send=bomb)
    b = collect_posture((), as_of=AS_OF, send=bomb)
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)
    assert a["schema"] == SCHEMA
    assert a["stats"]["resources"] == 0
    assert {(s["stage"], s["reason"]) for s in a["skips"]} == {
        ("aws", "provider_not_requested"),
        ("gcp", "provider_not_requested"),
        ("azure", "provider_not_requested"),
    }


def test_requested_provider_without_credentials_skips(tmp_path):
    old = {k: os.environ.get(k) for k in
           ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
            "RSX_GCP_ACCESS_TOKEN", "RSX_AZURE_ACCESS_TOKEN",
            "AZURE_ACCESS_TOKEN")}
    for k in old:
        os.environ.pop(k, None)
    try:
        doc = collect_posture(("aws", "gcp", "azure"), as_of=AS_OF,
                              send=NetworkBomb())
    finally:
        for k, v in old.items():
            if v is not None:
                os.environ[k] = v
    reasons = {(s["stage"], s["reason"]) for s in doc["skips"]}
    assert reasons == {("aws", "no_provider_configured"),
                       ("gcp", "no_provider_configured"),
                       ("azure", "no_provider_configured")}


def test_file_ingest_produces_findings_without_network(tmp_path):
    path = _write_capture(tmp_path)
    bomb = NetworkBomb()
    doc = collect_posture(("aws",), files={"aws": path}, as_of=AS_OF,
                          send=bomb)
    assert doc["stats"]["resources"] == 7
    assert doc["stats"]["findings"] == 10
    src = [s for s in doc["sources"] if s["kind"] == "aws:ingest"][0]
    assert src["detail"] == {"input": "file", "ops": len(AWS_CAPTURE)}
    # byte-identical with same input
    doc2 = collect_posture(("aws",), files={"aws": path}, as_of=AS_OF,
                           send=bomb)
    assert json.dumps(doc, sort_keys=True) == json.dumps(doc2, sort_keys=True)


def test_file_ingest_missing_required_op_becomes_cis_gap(tmp_path):
    path = _write_capture(tmp_path, drop=("iam:GetAccountSummary",))
    doc = collect_posture(("aws",), files={"aws": path}, as_of=AS_OF)
    gaps = [s for s in doc["skips"] if s["stage"] == "cis"]
    assert any(g["check_id"] == "cis.aws.root_mfa" and
               g["target"] == "iam:GetAccountSummary" and
               g["reason"] == "insufficient_data" for g in gaps)
    # and no root_mfa finding was fabricated
    assert not any(f["check_id"] == "cis.aws.root_mfa"
                   for f in doc["findings"])


def test_missing_capture_file_is_a_skip_not_a_crash(tmp_path):
    doc = collect_posture(("aws",),
                          files={"aws": str(tmp_path / "nope.json")},
                          as_of=AS_OF)
    assert any(s["stage"] == "aws" and
               s["reason"].startswith("FileNotFoundError")
               for s in doc["skips"])
    assert doc["stats"]["resources"] == 0


def test_cli_default_offline_rc0_and_reproducible(tmp_path):
    out1, out2 = tmp_path / "o1.json", tmp_path / "o2.json"
    assert _run_cli(["--as-of", "2026-10-31T12:00:00Z",
                     "--out", str(out1)]) == 0
    assert _run_cli(["--as-of", "2026-10-31T12:00:00Z",
                     "--out", str(out2)]) == 0
    assert out1.read_bytes() == out2.read_bytes()
    doc = json.loads(out1.read_text(encoding="utf-8"))
    assert doc["schema"] == SCHEMA
    assert doc["stats"]["findings"] == 0


def test_cli_with_capture_file_and_bad_as_of(tmp_path, capsys):
    path = _write_capture(tmp_path)
    out = tmp_path / "inv.json"
    assert _run_cli(["--aws-file", path, "--as-of",
                     "2026-10-31T12:00:00Z", "--out", str(out)]) == 0
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["findings"] and doc["stats"]["resources"] == 7
    assert _run_cli(["--as-of", "not-a-date"]) == 2
    assert "error:" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# live fetch paths (fake send -- no sockets)
# ---------------------------------------------------------------------------

def _recording_aws_send(routes):
    """routes: substring -> response text, first match in dict order
    (specific keys first; "amazonaws.com/" fallback LAST catches the
    bare s3 ListBuckets GET, whose URL carries no marker).  A ``None``
    value means "answer 404".  Records (url, headers, body)."""
    calls = []

    def send(method, url, headers, body):
        calls.append((url, dict(headers), body))
        text = b""
        for key, val in routes.items():
            if key in url or key in str(body) or \
                    key in str(headers.get("x-amz-target", "")):
                if val is None:
                    return 404, {}, b"<Error><Code>NoSuchKey</Code></Error>"
                text = val.encode() if isinstance(val, str) else val
                break
        if not text:
            return 404, {}, b"<Error><Code>NoSuchThing</Code></Error>"
        return 200, {}, text
    send.calls = calls
    return send


_S3_FALLBACK = "amazonaws.com/"   # bare ListBuckets endpoint marker


def test_live_aws_fetch_signs_and_normalizes():
    creds = {"access_key": "AKIDEXAMPLE", "secret_key": "secret",
             "region": "us-east-1"}
    routes = {
        "Action=DescribeInstances": AWS_CAPTURE["ec2:DescribeInstances"][0],
        "Action=DescribeSecurityGroups":
            AWS_CAPTURE["ec2:DescribeSecurityGroups"][0],
        "Action=DescribeSubnets": AWS_CAPTURE["ec2:DescribeSubnets"][0],
        "Action=DescribeVolumes": AWS_CAPTURE["ec2:DescribeVolumes"][0],
        "Action=ListUsers": AWS_CAPTURE["iam:ListUsers"][0],
        "Action=GetAccountSummary":
            AWS_CAPTURE["iam:GetAccountSummary"][0],
        "publicaccessblock":
            AWS_CAPTURE["s3:GetPublicAccessBlock:open-bucket"][0],
        "ListKeys": AWS_CAPTURE["kms:ListKeys"][0],
        "GetKeyRotationStatus":
            AWS_CAPTURE["kms:GetKeyRotationStatus:k-1"][0],
        "DescribeTrails": AWS_CAPTURE["cloudtrail:DescribeTrails"][0],
        "GetTrailStatus": AWS_CAPTURE["cloudtrail:GetTrailStatus:main"][0],
        _S3_FALLBACK: AWS_CAPTURE["s3:ListBuckets"][0],
    }
    send = _recording_aws_send(routes)
    doc = collect_posture(("aws",), creds={"aws": creds}, as_of=AS_OF,
                          send=send)
    assert doc["stats"]["findings"] == 10
    # every request was SigV4-signed
    assert send.calls
    for _url, headers, _body in send.calls:
        assert headers.get("authorization", "").startswith(
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/")
    sources = [s for s in doc["sources"] if s["kind"].startswith(
        ("ec2:", "iam:", "s3:", "kms:", "cloudtrail:"))]
    assert all(s["status"] == "ok" for s in sources)


def test_live_aws_missing_detail_404_marks_bucket_absent():
    creds = {"access_key": "k", "secret_key": "s",
             "region": "us-east-1"}
    routes = {
        "Action=DescribeInstances": AWS_CAPTURE["ec2:DescribeInstances"][0],
        "Action=DescribeSecurityGroups": AWS_CAPTURE[
            "ec2:DescribeSecurityGroups"][0],
        "Action=DescribeSubnets": AWS_CAPTURE["ec2:DescribeSubnets"][0],
        "Action=DescribeVolumes": AWS_CAPTURE["ec2:DescribeVolumes"][0],
        "Action=ListUsers": AWS_CAPTURE["iam:ListUsers"][0],
        "Action=GetAccountSummary": AWS_CAPTURE[
            "iam:GetAccountSummary"][0],
        # PAAB explicitly 404s -> ABSENT sentinel (no config on bucket)
        "publicaccessblock": None,
        "ListKeys": AWS_CAPTURE["kms:ListKeys"][0],
        "GetKeyRotationStatus": AWS_CAPTURE[
            "kms:GetKeyRotationStatus:k-1"][0],
        "DescribeTrails": AWS_CAPTURE["cloudtrail:DescribeTrails"][0],
        "GetTrailStatus": AWS_CAPTURE["cloudtrail:GetTrailStatus:main"][0],
        _S3_FALLBACK: AWS_CAPTURE["s3:ListBuckets"][0],
    }
    send = _recording_aws_send(routes)
    doc = collect_posture(("aws",), creds={"aws": creds}, as_of=AS_OF,
                          send=send)
    # 404 on PAAB is observation of "no config" (all-false), not a skip
    assert not any("publicaccessblock" in s["target"]
                   for s in doc["skips"])
    hit = [f for f in doc["findings"]
           if f["check_id"] == "cis.aws.s3_public_access_block"]
    assert hit and hit[0]["resource_id"] == "open-bucket"
    # ABSENT = no config at all -> AWS enforces all-false defaults
    assert hit[0]["evidence"]["disabled"] == ["block_public_acls",
                                              "block_public_policy",
                                              "ignore_public_acls",
                                              "restrict_public_buckets"]


def test_live_aws_pagination_and_page_cap():
    creds = {"access_key": "k", "secret_key": "s",
             "region": "us-east-1"}
    # endless NextToken -> cap at MAX_PAGES with disclosed skip
    endless = ("<DescribeVolumesResponse><volumeSet><item>"
               "<volumeId>vol-1</volumeId><encrypted>true</encrypted>"
               "</item></volumeSet><nextToken>tok</nextToken>"
               "</DescribeVolumesResponse>")
    routes = {
        "Action=DescribeInstances": AWS_CAPTURE["ec2:DescribeInstances"][0],
        "Action=DescribeSecurityGroups": AWS_CAPTURE[
            "ec2:DescribeSecurityGroups"][0],
        "Action=DescribeSubnets": AWS_CAPTURE["ec2:DescribeSubnets"][0],
        "Action=DescribeVolumes": endless,
        "Action=ListUsers": AWS_CAPTURE["iam:ListUsers"][0],
        "Action=GetAccountSummary": AWS_CAPTURE[
            "iam:GetAccountSummary"][0],
        "ListBuckets": AWS_CAPTURE["s3:ListBuckets"][0],
        "publicaccessblock": AWS_CAPTURE[
            "s3:GetPublicAccessBlock:open-bucket"][0],
        "ListKeys": AWS_CAPTURE["kms:ListKeys"][0],
        "GetKeyRotationStatus": AWS_CAPTURE[
            "kms:GetKeyRotationStatus:k-1"][0],
        "DescribeTrails": AWS_CAPTURE["cloudtrail:DescribeTrails"][0],
        "GetTrailStatus": AWS_CAPTURE["cloudtrail:GetTrailStatus:main"][0],
    }
    send = _recording_aws_send(routes)
    doc = collect_posture(("aws",), creds={"aws": creds}, as_of=AS_OF,
                          send=send)
    vol_src = [s for s in doc["sources"]
               if s["kind"] == "ec2:DescribeVolumes"][0]
    assert vol_src["detail"] == {"pages": MAX_PAGES, "truncated": True}
    assert any(s["target"] == "ec2:DescribeVolumes" and
               s["reason"] == f"page_cap_{MAX_PAGES}" for s in doc["skips"])
    assert doc["stats"]["resources"] >= 7   # deduped ids survive paging


def test_live_aws_detail_cap_disclosed():
    creds = {"access_key": "k", "secret_key": "s",
             "region": "us-east-1"}
    names = "".join(f"<Bucket><Name>b{i:02d}</Name></Bucket>"
                    for i in range(MAX_DETAIL_CALLS + 5))
    buckets_page = (f"<ListAllMyBucketsResult><Buckets>{names}</Buckets>"
                    "</ListAllMyBucketsResult>")
    paab = ("<PublicAccessBlockConfiguration><BlockPublicAcls>true"
            "</BlockPublicAcls><IgnorePublicAcls>true</IgnorePublicAcls>"
            "<BlockPublicPolicy>true</BlockPublicPolicy>"
            "<RestrictPublicBuckets>true</RestrictPublicBuckets>"
            "</PublicAccessBlockConfiguration>")
    routes = {
        "Action=DescribeInstances": AWS_CAPTURE["ec2:DescribeInstances"][0],
        "Action=DescribeSecurityGroups": AWS_CAPTURE[
            "ec2:DescribeSecurityGroups"][0],
        "Action=DescribeSubnets": AWS_CAPTURE["ec2:DescribeSubnets"][0],
        "Action=DescribeVolumes": AWS_CAPTURE["ec2:DescribeVolumes"][0],
        "Action=ListUsers": AWS_CAPTURE["iam:ListUsers"][0],
        "Action=GetAccountSummary": AWS_CAPTURE[
            "iam:GetAccountSummary"][0],
        "publicaccessblock": paab,
        "ListKeys": AWS_CAPTURE["kms:ListKeys"][0],
        "GetKeyRotationStatus": AWS_CAPTURE[
            "kms:GetKeyRotationStatus:k-1"][0],
        "DescribeTrails": AWS_CAPTURE["cloudtrail:DescribeTrails"][0],
        "GetTrailStatus": AWS_CAPTURE["cloudtrail:GetTrailStatus:main"][0],
        _S3_FALLBACK: buckets_page,
    }
    send = _recording_aws_send(routes)
    doc = collect_posture(("aws",), creds={"aws": creds}, as_of=AS_OF,
                          send=send)
    capped = [s for s in doc["skips"] if s["reason"] == "detail_cap"]
    # one machine-readable truncation row for the op (25 polled, 5 not)
    assert len(capped) == 1
    assert capped[0]["target"] == "s3:GetPublicAccessBlock"
    assert capped[0]["stage"] == "aws"
    # unobserved (capped) buckets -> insufficient_data gap, not a pass
    assert any(s["stage"] == "cis" and
               "buckets unobserved" in s["target"]
               for s in doc["skips"])


def test_live_gcp_fetch_uses_bearer_and_next_page():
    creds = {"token": "tok-1", "project": "p1"}
    state = {"pages": 0}

    def send(method, url, headers, body):
        assert headers.get("authorization") == "Bearer tok-1"
        if "aggregated/instances" in url:
            return 200, {}, json.dumps({"items": {}}).encode()
        if "global/firewalls" in url:
            state["pages"] += 1
            if state["pages"] == 1:
                return 200, {}, json.dumps({
                    "items": [{"name": "fw", "direction": "INGRESS",
                               "sourceRanges": ["0.0.0.0/0"],
                               "allowed": [{"IPProtocol": "tcp",
                                            "ports": ["22"]}]}],
                    "nextPageToken": "t1"}).encode()
            return 200, {}, json.dumps({"items": []}).encode()
        if "storage/v1/b?" in url:
            return 200, {}, json.dumps({"items": [
                {"name": "gb", "location": "US"}]}).encode()
        if "/iam" in url and "storage/v1/b/gb" in url:
            return 200, {}, json.dumps({"bindings": []}).encode()
        if "cloudkms" in url:
            return 200, {}, json.dumps({"keys": []}).encode()
        return 404, {}, b"{}"

    doc = collect_posture(("gcp",), creds={"gcp": creds}, as_of=AS_OF,
                          send=send)
    fw_src = [s for s in doc["sources"] if s["kind"] == "gce:firewalls"][0]
    assert fw_src["detail"]["pages"] == 2      # nextPageToken followed
    assert any(f["check_id"] == "cis.gcp.firewall_ssh_world"
               for f in doc["findings"])


def test_live_azure_fetch_follows_next_link():
    creds = {"token": "tok-az", "subscription": "sub-1"}
    state = {"n": 0}

    def send(method, url, headers, body):
        assert headers.get("authorization") == "Bearer tok-az"
        if "virtualMachines" in url and "nextLink" not in url:
            state["n"] += 1
            return 200, {}, json.dumps({
                "value": [{"id": "/s/vm/1", "name": "vm",
                           "location": "eastus", "properties": {}}],
                "nextLink": "https://management.azure.com/page2?api=x"
            }).encode()
        if "page2" in url:
            return 200, {}, json.dumps({"value": []}).encode()
        if "storageAccounts" in url:
            return 200, {}, json.dumps({"value": [{
                "id": "/s/sa/1", "name": "sa", "location": "eastus",
                "properties": {"allowBlobPublicAccess": True,
                               "enableHttpsTrafficOnly": True}}]}).encode()
        if "networkSecurityGroups" in url:
            return 200, {}, json.dumps({"value": []}).encode()
        return 404, {}, b"{}"

    doc = collect_posture(("azure",), creds={"azure": creds},
                          as_of=AS_OF, send=send)
    vm_src = [s for s in doc["sources"]
              if s["kind"] == "arm:virtualMachines"][0]
    assert vm_src["detail"]["pages"] == 2      # nextLink followed
    assert any(f["check_id"] == "cis.azure.storage_blob_public"
               for f in doc["findings"])


def test_resolve_credentials_stage_scoped():
    env = {"AWS_ACCESS_KEY_ID": "k", "AWS_SECRET_ACCESS_KEY": "s",
           "AWS_REGION": "eu-west-1",
           "RSX_GCP_ACCESS_TOKEN": "t", "RSX_GCP_PROJECT_ID": "p",
           "RSX_AZURE_ACCESS_TOKEN": "ta", "AZURE_SUBSCRIPTION_ID": "sub"}
    aws = resolve_credentials("aws", env=env)
    assert aws == {"access_key": "k", "secret_key": "s",
                   "region": "eu-west-1"}
    assert resolve_credentials("gcp", env=env) == {
        "token": "t", "project": "p"}
    assert resolve_credentials("azure", env=env) == {
        "token": "ta", "subscription": "sub"}
    assert resolve_credentials("aws", env={}) is None
    # explicit dict wins over env
    assert resolve_credentials("aws", explicit={"access_key": "explicit"},
                               env=env) == {"access_key": "explicit"}


def test_provider_failure_during_fetch_is_a_skip_not_a_crash():
    def boom(method, url, headers, body):
        raise OSError("network unreachable")

    doc = collect_posture(("aws",),
                          creds={"aws": {"access_key": "k",
                                         "secret_key": "s",
                                         "region": "us-east-1"}},
                          as_of=AS_OF, send=boom)
    assert any(s["stage"] == "aws" and
               "network unreachable" in s["reason"] for s in doc["skips"])
    # every required table op failed -> cis insufficient_data gaps exist
    assert any(s["stage"] == "cis" and
               s["reason"] == "insufficient_data" for s in doc["skips"])
    assert doc["stats"]["resources"] == 0
