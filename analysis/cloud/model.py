"""T-6.2: normalized cloud inventory model + provider normalizers.

Raw op payloads (strings: XML for AWS query/REST APIs, JSON for
AWS-JSON/GCP/Azure) -> uniform resource records:

  {provider, type, service, id, name, region, config, tags}

Types mirror task.md: compute / storage / network / identity / kms /
logging.  Everything here is PURE: pages in, records out, sorted, no
clock (``as_of`` is passed in where age maths is needed).  CIS checks
and posture rollups consume ONLY these records -- a field the
normalizer did not observe is absent, and checks must treat absence as
``insufficient data`` (disclosed skip), never as compliant.
"""
from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

RESOURCE_TYPES = ("compute", "storage", "network", "identity",
                  "kms", "logging")
_MAX_STR = 512
_MAX_RULES = 64


def _s(value) -> str:
    return str(value)[:_MAX_STR] if value is not None else ""


def resource(provider: str, rtype: str, service: str, rid: str,
             name: str = "", region: str = "", config: dict | None = None,
             tags: dict | None = None) -> dict:
    return {"provider": provider, "type": rtype, "service": service,
            "id": _s(rid), "name": _s(name or rid), "region": _s(region),
            "config": config or {}, "tags": tags or {}}


def _xml(text: str) -> ET.Element:
    root = ET.fromstring(text)
    for el in root.iter():            # AWS docs namespaces on EC2/S3 roots
        if isinstance(el.tag, str):
            el.tag = el.tag.rsplit("}", 1)[-1]
    return root


def _t(elem: ET.Element | None, path: str, default: str = "") -> str:
    if elem is None:
        return default
    found = elem.find(path)
    if found is None or found.text is None:
        return default
    return found.text.strip()


def _all(elem: ET.Element | None, path: str) -> list[ET.Element]:
    if elem is None:
        return []
    return [e for e in elem.findall(path) if e is not None]


def _jpage(pages: list[str], op: str) -> list[object]:
    out = []
    for p in pages:
        try:
            out.append(json.loads(p))
        except ValueError:
            raise ApiLike(op) from None
    return out


class ApiLike(ValueError):
    """json parse failure surfaced to the fetch layer as a skip."""


# ---------------------------------------------------------------------------
# AWS normalizers
# ---------------------------------------------------------------------------

def aws_instances(pages: list[str]) -> list[dict]:
    out = []
    for page in pages:
        root = _xml(page)
        for item in _all(root, ".//instancesSet/item"):
            out.append(resource(
                "aws", "compute", "ec2",
                _t(item, "instanceId"), _t(item, "tagSet/item/key"),
                config={
                    "instance_type": _s(_t(item, "instanceType")),
                    "state": _s(_t(item, "state/name")),
                    "public_ip": _s(_t(item, "publicIpAddress")),
                    "imds_http_tokens": _s(
                        _t(item, "metadataOptions/httpTokens")),
                }))
    return out


def aws_security_groups(pages: list[str]) -> list[dict]:
    out = []
    for page in pages:
        root = _xml(page)
        for item in _all(root, ".//securityGroupSet/item"):
            rules = []
            for perm in _all(item, "ipPermissions/item")[:_MAX_RULES]:
                cidrs = [ _s(_t(r, "cidrIp"))
                          for r in _all(perm, "ipRanges/item") ]
                cidrs += [ _s(_t(r, "ipv6CidrBlock"))
                           for r in _all(perm, "ipv6Ranges/item") ]
                rules.append({
                    "protocol": _s(_t(perm, "ipProtocol")),
                    "from_port": _t(perm, "fromPort"),
                    "to_port": _t(perm, "toPort"),
                    "cidrs": [c for c in cidrs if c][:32],
                })
            out.append(resource(
                "aws", "network", "ec2",
                _t(item, "groupId"), _t(item, "groupName"),
                config={"vpc_id": _s(_t(item, "vpcId")), "ingress": rules}))
    return out


def aws_subnets(pages: list[str]) -> list[dict]:
    out = []
    for page in pages:
        root = _xml(page)
        for item in _all(root, ".//subnetSet/item"):
            out.append(resource(
                "aws", "network", "ec2",
                _t(item, "subnetId"), _t(item, "subnetId"),
                config={
                    "vpc_id": _s(_t(item, "vpcId")),
                    "cidr_block": _s(_t(item, "cidrBlock")),
                    "map_public_ip": _t(item, "mapPublicIpOnLaunch") == "true",
                    "state": _s(_t(item, "state")),
                }))
    return out


def aws_volumes(pages: list[str]) -> list[dict]:
    out = []
    for page in pages:
        root = _xml(page)
        for item in _all(root, ".//volumeSet/item"):
            out.append(resource(
                "aws", "storage", "ec2",
                _t(item, "volumeId"), _t(item, "volumeId"),
                config={
                    "encrypted": _t(item, "encrypted") == "true",
                    "kms_key_id": _s(_t(item, "kmsKeyId")),
                    "state": _s(_t(item, "state")),
                    "size_gib": _t(item, "size"),
                }))
    return out


def aws_users(pages: list[str], as_of: datetime) -> list[dict]:
    out = []
    for page in pages:
        root = _xml(page)
        for member in _all(root, ".//Users/member"):
            used = _t(member, "PasswordLastUsed")
            days = None
            if used:
                try:
                    last = datetime.fromisoformat(
                        used.replace("Z", "+00:00"))
                    days = max(0, (as_of - last.astimezone(timezone.utc))
                               .days)
                except ValueError:
                    days = None
            out.append(resource(
                "aws", "identity", "iam",
                _t(member, "UserId"), _t(member, "UserName"),
                config={
                    "arn": _s(_t(member, "Arn")),
                    "password_last_used_days": days,
                    "create_date": _s(_t(member, "CreateDate")),
                }))
    return out


def aws_account_summary(pages: list[str]) -> list[dict]:
    """One synthetic identity resource holding the account-level facts
    root-MFA / root-access-key checks need."""
    summary: dict[str, str] = {}
    for page in pages:
        root = _xml(page)
        for entry in _all(root, ".//SummaryMap/entry"):
            summary[_t(entry, "key")] = _t(entry, "value")
    if not summary:
        return []
    return [resource("aws", "identity", "iam", "account-summary",
                     "account-summary",
                     config={"summary": {k: summary[k]
                                         for k in sorted(summary)}})]


def aws_buckets(pages: list[str], detail: dict[str, str]) -> list[dict]:
    """``detail`` maps bucket -> GetPublicAccessBlock XML, or the
    sentinel ABSENT when the bucket has no configuration (AWS then
    enforces the all-false defaults).  Missing key = not observed."""
    out = []
    for page in pages:
        root = _xml(page)
        for item in _all(root, ".//Buckets/Bucket"):
            name = _t(item, "Name")
            paab = None
            observed = name in detail
            if observed:
                raw = detail[name]
                if raw == ABSENT:
                    paab = {"block_public_acls": False,
                            "ignore_public_acls": False,
                            "block_public_policy": False,
                            "restrict_public_buckets": False}
                else:
                    x = _xml(raw)
                    # explicit snake_case -- must match the ABSENT
                    # defaults below (naive .lower() gives blockpublicacls)
                    paab = {"block_public_acls":
                            _t(x, "BlockPublicAcls") == "true",
                            "ignore_public_acls":
                            _t(x, "IgnorePublicAcls") == "true",
                            "block_public_policy":
                            _t(x, "BlockPublicPolicy") == "true",
                            "restrict_public_buckets":
                            _t(x, "RestrictPublicBuckets") == "true"}
            out.append(resource(
                "aws", "storage", "s3", name, name,
                config={
                    "created": _s(_t(item, "CreationDate")),
                    "public_access_block": paab,
                    "public_access_block_observed": observed,
                }))
    return out


ABSENT = "__absent__"          # detail op answered 404 -- config unset


def aws_keys(pages: list[str], detail: dict[str, str]) -> list[dict]:
    """KMS keys; detail maps key-id -> GetKeyRotationStatus JSON."""
    out = []
    for page in pages:
        doc = json.loads(page)
        for item in doc.get("Keys", []):
            kid = _s(item.get("KeyId"))
            rotation = None
            observed = kid in detail
            if observed and detail[kid] != ABSENT:
                try:
                    rotation = bool(
                        json.loads(detail[kid]).get("KeyRotationEnabled"))
                except ValueError:
                    observed = False
            out.append(resource(
                "aws", "kms", "kms", kid, kid,
                config={
                    "state": _s(item.get("KeyState")),
                    "rotation_enabled": rotation,
                    "rotation_observed": observed,
                }))
    return out


def aws_trails(pages: list[str], detail: dict[str, str]) -> list[dict]:
    """CloudTrail trails; detail maps trail -> GetTrailStatus JSON."""
    out = []
    for page in pages:
        doc = json.loads(page)
        for item in doc.get("trailList", []):
            name = _s(item.get("Name"))
            logging = None
            observed = name in detail
            if observed and detail[name] != ABSENT:
                try:
                    logging = bool(json.loads(detail[name]).get("IsLogging"))
                except ValueError:
                    observed = False
            out.append(resource(
                "aws", "logging", "cloudtrail", name, name,
                config={
                    "multi_region": bool(item.get("IsMultiRegionTrail")),
                    "log_file_validation": bool(
                        item.get("LogFileValidationEnabled")),
                    "s3_bucket": _s(item.get("S3BucketName")),
                    "is_logging": logging,
                    "status_observed": observed,
                }))
    return out


# ---------------------------------------------------------------------------
# GCP normalizers
# ---------------------------------------------------------------------------

def gcp_instances(pages: list[str]) -> list[dict]:
    out = []
    for page in pages:
        doc = json.loads(page)
        items = doc.get("items") or {}
        for zone_key in sorted(items):
            for inst in (items[zone_key] or {}).get("instances") or []:
                public = ""
                for nic in inst.get("networkInterfaces") or []:
                    for cfg in nic.get("accessConfigs") or []:
                        public = cfg.get("natIP") or public
                out.append(resource(
                    "gcp", "compute", "compute", _s(inst.get("id")),
                    _s(inst.get("name")), _s(inst.get("zone")),
                    config={
                        "status": _s(inst.get("status")),
                        "public_ip": _s(public),
                        "machine_type": _s(inst.get("machineType")),
                    }))
    return out


def gcp_firewalls(pages: list[str]) -> list[dict]:
    out = []
    for page in pages:
        doc = json.loads(page)
        for item in doc.get("items") or []:
            ports: list[str] = []
            for allowed in (item.get("allowed") or [])[:_MAX_RULES]:
                ports += [str(p) for p in (allowed.get("ports") or [])]
            out.append(resource(
                "gcp", "network", "compute", _s(item.get("name")),
                _s(item.get("name")), config={
                    "direction": _s(item.get("direction")),
                    "source_ranges": [str(r) for r in
                                      (item.get("sourceRanges") or [])][:32],
                    "ports": ports[:32],
                }))
    return out


def gcp_buckets(pages: list[str], detail: dict[str, str]) -> list[dict]:
    """``detail`` maps bucket -> GetIamPolicy JSON (allUsers bindings)."""
    out = []
    for page in pages:
        doc = json.loads(page)
        for item in doc.get("items") or []:
            name = _s(item.get("name"))
            bindings = []
            observed = name in detail
            if observed and detail[name] != ABSENT:
                try:
                    bindings = json.loads(detail[name]).get("bindings") or []
                except ValueError:
                    observed = False
            public_members = sorted({
                m for b in bindings for m in (b.get("members") or [])
                if m in ("allUsers", "allAuthenticatedUsers")})
            out.append(resource(
                "gcp", "storage", "storage", name, name,
                _s(item.get("location")),
                config={
                    "public_access_prevention": _s(
                        (item.get("iamConfiguration") or {})
                        .get("publicAccessPrevention")),
                    "iam_observed": observed,
                    "public_members": public_members,
                    "storage_class": _s(item.get("storageClass")),
                }))
    return out


def gcp_keys(pages: list[str]) -> list[dict]:
    out = []
    for page in pages:
        doc = json.loads(page)
        for item in doc.get("keys") or []:
            out.append(resource(
                "gcp", "kms", "cloudkms", _s(item.get("name")),
                _s(item.get("name")).rsplit("/", 1)[-1],
                config={
                    "state": _s((item.get("primary") or {}).get("state")),
                    "rotation_period": _s(item.get("rotationPeriod")),
                    "next_rotation": _s(item.get("nextRotationTime")),
                }))
    return out


# ---------------------------------------------------------------------------
# Azure normalizers
# ---------------------------------------------------------------------------

def az_vms(pages: list[str]) -> list[dict]:
    out = []
    for page in pages:
        doc = json.loads(page)
        for item in doc.get("value") or []:
            out.append(resource(
                "azure", "compute", "compute", _s(item.get("id")),
                _s(item.get("name")), _s(item.get("location")),
                config={
                    "vm_size": _s((item.get("properties") or {})
                                  .get("hardwareProfile", {})
                                  .get("vmSize")),
                }))
    return out


def az_storage_accounts(pages: list[str]) -> list[dict]:
    out = []
    for page in pages:
        doc = json.loads(page)
        for item in doc.get("value") or []:
            props = item.get("properties") or {}
            out.append(resource(
                "azure", "storage", "storage", _s(item.get("id")),
                _s(item.get("name")), _s(item.get("location")),
                config={
                    "blob_public_access": bool(
                        props.get("allowBlobPublicAccess")),
                    "https_only": bool(props.get("enableHttpsTrafficOnly")),
                    "min_tls": _s(props.get("minimumTlsVersion")),
                }))
    return out


def az_nsgs(pages: list[str]) -> list[dict]:
    out = []
    for page in pages:
        doc = json.loads(page)
        for item in doc.get("value") or []:
            rules = []
            for r in ((item.get("properties") or {})
                      .get("securityRules") or [])[:_MAX_RULES]:
                p = r.get("properties") or {}
                rules.append({
                    "name": _s(r.get("name")),
                    "direction": _s(p.get("direction")),
                    "access": _s(p.get("access")),
                    "protocol": _s(p.get("protocol")),
                    "source": _s(p.get("sourceAddressPrefix")
                                 or p.get("sourceAddressPrefixes")),
                    "port": _s(p.get("destinationPortRange")),
                })
            out.append(resource(
                "azure", "network", "network", _s(item.get("id")),
                _s(item.get("name")), _s(item.get("location")),
                config={"security_rules": rules}))
    return out


# ---------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------

def normalize(provider: str, raws: dict[str, list[str]],
              as_of: datetime) -> list[dict]:
    """raws: op -> list of page payloads (strings).  Detail ops are
    keyed ``"<op>:<id>"``.  Returns records sorted (type, id)."""
    res: list[dict] = []

    def pages(op: str) -> list[str]:
        return raws.get(op) or []

    def detail_map(op: str) -> dict[str, str]:
        prefix = op + ":"
        return {k[len(prefix):]: v[0]
                for k, v in raws.items() if k.startswith(prefix) and v}

    if provider == "aws":
        res += aws_instances(pages("ec2:DescribeInstances"))
        res += aws_security_groups(pages("ec2:DescribeSecurityGroups"))
        res += aws_subnets(pages("ec2:DescribeSubnets"))
        res += aws_volumes(pages("ec2:DescribeVolumes"))
        res += aws_users(pages("iam:ListUsers"), as_of)
        res += aws_account_summary(pages("iam:GetAccountSummary"))
        res += aws_buckets(pages("s3:ListBuckets"),
                           detail_map("s3:GetPublicAccessBlock"))
        res += aws_keys(pages("kms:ListKeys"),
                        detail_map("kms:GetKeyRotationStatus"))
        res += aws_trails(pages("cloudtrail:DescribeTrails"),
                          detail_map("cloudtrail:GetTrailStatus"))
    elif provider == "gcp":
        res += gcp_instances(pages("gce:aggregatedInstances"))
        res += gcp_firewalls(pages("gce:firewalls"))
        res += gcp_buckets(pages("gcs:buckets"),
                           detail_map("gcs:getIamPolicy"))
        res += gcp_keys(pages("kms:listKeys"))
    elif provider == "azure":
        res += az_vms(pages("arm:virtualMachines"))
        res += az_storage_accounts(pages("arm:storageAccounts"))
        res += az_nsgs(pages("arm:networkSecurityGroups"))
    res.sort(key=lambda r: (r["type"], r["id"]))
    return res
