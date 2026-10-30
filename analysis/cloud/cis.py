"""T-6.2: CIS benchmark checks over the normalized inventory.

Registry of bounded controls (task.md: "CIS benchmark checks"), one
function each, pure: (provider resources, as_of) -> findings + gaps.

Two entry kinds from every check, so nothing is silently dropped:

  * ``finding`` -- the control is violated; carries ``explanation``
    (why) + ``evidence`` (the observed values) + ``remediation``
    (ground rule 11: every judgement explainable);
  * ``gap``     -- the data needed to judge was NOT observed
    (``insufficient_data``).  A gap is never a pass.

Checks may also be skipped wholesale when their required ops were
never fetched/ingested -- connect.py emits those gaps from the
``requires`` field in this registry.
"""
from __future__ import annotations

from datetime import datetime

B_AWS = "CIS Amazon Web Services Foundations Benchmark v3.0.0"
B_GCP = "CIS Google Cloud Platform Foundation Benchmark v1.4.0"
B_AZURE = "CIS Microsoft Azure Foundations Benchmark v2.1.0"

_WORLD = ("0.0.0.0/0", "::/0", "*", "internet", "any")


def _finding(check_id: str, provider: str, rid: str, explanation: str,
             evidence: dict) -> dict:
    return {"kind": "finding", "check_id": check_id, "provider": provider,
            "resource_id": rid, "explanation": explanation,
            "evidence": evidence}


def _gap(check_id: str, target: str,
         reason: str = "insufficient_data") -> dict:
    return {"kind": "gap", "check_id": check_id, "target": target,
            "reason": reason}


def _world(sources) -> bool:
    return any(str(s).strip().lower() in _WORLD for s in sources or ())


def port_covers(spec: str, target: int) -> bool:
    """'22' -> equals; '80-90' -> range; '*'/'empty' -> everything."""
    s = str(spec or "").strip()
    if s in ("*", ""):
        return True
    if "-" in s:
        lo, _, hi = s.partition("-")
        try:
            return int(lo) <= target <= int(hi)
        except ValueError:
            return False
    if s.isdigit():
        return int(s) == target
    return False


# ---------------------------------------------------------------------------
# AWS
# ---------------------------------------------------------------------------

def _root_mfa(res, as_of):
    out = []
    acct = [r for r in res if r["id"] == "account-summary"]
    if not acct:
        return out, [_gap("cis.aws.root_mfa", "iam:GetAccountSummary")]
    summary = acct[0]["config"].get("summary") or {}
    if "AccountMFAEnabled" not in summary:
        return out, [_gap("cis.aws.root_mfa", "iam:GetAccountSummary")]
    if summary["AccountMFAEnabled"] != "1":
        out.append(_finding(
            "cis.aws.root_mfa", "aws", "root",
            "The account root user does not have MFA enabled "
            "(AccountMFAEnabled != 1).",
            {"AccountMFAEnabled": summary["AccountMFAEnabled"]}))
    return out, []


def _root_access_key(res, as_of):
    out = []
    acct = [r for r in res if r["id"] == "account-summary"]
    if not acct:
        return out, [_gap("cis.aws.root_access_key", "iam:GetAccountSummary")]
    summary = acct[0]["config"].get("summary") or {}
    present = summary.get("AccountAccessKeysPresent")
    if present is None:
        return out, [_gap("cis.aws.root_access_key", "iam:GetAccountSummary")]
    if present != "0":
        out.append(_finding(
            "cis.aws.root_access_key", "aws", "root",
            "The account root user has active access keys "
            "(AccountAccessKeysPresent != 0); root keys should not exist.",
            {"AccountAccessKeysPresent": present}))
    return out, []


def _sg_world(res, as_of, port: int, check_id: str):
    out, gaps = [], []
    sgs = [r for r in res if "ingress" in (r.get("config") or {})]
    if not sgs:
        return out, [_gap(check_id, "ec2:DescribeSecurityGroups",
                          "no_resources")]
    for r in sgs:
        for rule in r["config"].get("ingress") or []:
            if not _world(rule.get("cidrs")):
                continue
            lo = rule.get("from_port") or ""
            hi = rule.get("to_port") or ""
            # protocol -1 (all) or port range covering the target
            covers = (rule.get("protocol") == "-1")
            try:
                covers = covers or (
                    (not lo and not hi) or
                    (int(lo) <= port <= int(hi if hi else lo)))
            except ValueError:
                covers = covers or False
            if covers:
                out.append(_finding(
                    check_id, "aws", r["id"],
                    f"Security group {r['id']} allows ingress to port "
                    f"{port} from the whole internet.",
                    {"cidrs": rule.get("cidrs"), "from_port": lo,
                     "to_port": hi, "protocol": rule.get("protocol")}))
    return out, gaps


def _sg_ssh(res, as_of):
    return _sg_world(res, as_of, 22, "cis.aws.sg_ssh_world")


def _sg_rdp(res, as_of):
    return _sg_world(res, as_of, 3389, "cis.aws.sg_rdp_world")


def _ebs_unencrypted(res, as_of):
    out = []
    for r in res:
        cfg = r.get("config") or {}
        if r["type"] == "storage" and "encrypted" in cfg:
            if not cfg.get("encrypted"):
                out.append(_finding(
                    "cis.aws.ebs_unencrypted", "aws", r["id"],
                    "EBS volume is not encrypted at rest.",
                    {"encrypted": cfg.get("encrypted"),
                     "state": cfg.get("state")}))
    return out, []


def _s3_paab(res, as_of):
    out, gaps = [], []
    buckets = [r for r in res
               if r["type"] == "storage" and r.get("service") == "s3"]
    if not buckets:
        return out, [_gap("cis.aws.s3_public_access_block",
                          "s3:GetPublicAccessBlock", "no_resources")]
    unobserved = 0
    for r in buckets:
        cfg = r["config"]
        if not cfg.get("public_access_block_observed"):
            unobserved += 1
            continue
        paab = cfg.get("public_access_block") or {}
        off = sorted(k for k, v in paab.items() if not v)
        if off:
            out.append(_finding(
                "cis.aws.s3_public_access_block", "aws", r["id"],
                "Bucket public access block is incomplete "
                f"(disabled: {', '.join(off)}); all four settings must "
                "be true.", {"flags": paab, "disabled": off}))
    if unobserved:
        gaps.append(_gap("cis.aws.s3_public_access_block",
                         f"s3:GetPublicAccessBlock "
                         f"({unobserved} buckets unobserved)"))
    return out, gaps


def _aws_trails(res) -> list[dict]:
    return [r for r in res if r["type"] == "logging"]


def _trail_exists(res, as_of):
    if not _aws_trails(res):          # op ran, no pages -> no trails
        return [_finding("cis.aws.cloudtrail_exists", "aws", "account",
                         "No CloudTrail trail is configured; at least one "
                         "trail is required.", {"trails": 0})], []
    return [], []


def _trail_status(res, as_of):
    out, gaps = [], []
    for r in _aws_trails(res):
        cfg = r["config"]
        if not cfg.get("status_observed"):
            gaps.append(_gap("cis.aws.cloudtrail_status",
                             f"cloudtrail:GetTrailStatus:{r['id']}"))
            continue
        if cfg.get("is_logging") is False:
            out.append(_finding(
                "cis.aws.cloudtrail_status", "aws", r["id"],
                "Trail exists but logging is stopped (IsLogging=false).",
                {"is_logging": False}))
    return out, gaps


def _trail_validation(res, as_of):
    out = []
    for r in _aws_trails(res):
        if not r["config"].get("log_file_validation"):
            out.append(_finding(
                "cis.aws.cloudtrail_validation", "aws", r["id"],
                "Trail does not validate log file integrity "
                "(LogFileValidationEnabled=false).",
                {"log_file_validation": False}))
    return out, []


def _trail_multiregion(res, as_of):
    out = []
    for r in _aws_trails(res):
        if not r["config"].get("multi_region"):
            out.append(_finding(
                "cis.aws.cloudtrail_multiregion", "aws", r["id"],
                "Trail is single-region (IsMultiRegionTrail=false).",
                {"multi_region": False}))
    return out, []


def _kms_rotation(res, as_of):
    out, gaps = [], []
    keys = [r for r in res if r["type"] == "kms"]
    if not keys:
        return out, [_gap("cis.aws.kms_rotation", "kms:ListKeys",
                          "no_resources")]
    unobserved = 0
    for r in keys:
        cfg = r["config"]
        if cfg.get("state") not in ("Enabled",):
            continue                  # rotation N/A for disabled/pending
        if not cfg.get("rotation_observed"):
            unobserved += 1
            continue
        if cfg.get("rotation_enabled") is False:
            out.append(_finding(
                "cis.aws.kms_rotation", "aws", r["id"],
                "KMS customer-managed key is enabled without automatic "
                "rotation.", {"rotation_enabled": False}))
    if unobserved:
        gaps.append(_gap("cis.aws.kms_rotation",
                         f"kms:GetKeyRotationStatus "
                         f"({unobserved} keys unobserved)"))
    return out, gaps


def _iam_stale(res, as_of):
    out = []
    for r in res:
        if r["type"] != "identity" or r["id"] == "account-summary":
            continue
        days = r["config"].get("password_last_used_days")
        if days is not None and days > 90:
            out.append(_finding(
                "cis.aws.iam_stale_password", "aws", r["id"],
                f"IAM user password last used {days} days before as_of "
                "(> 90 days = unused credentials).",
                {"password_last_used_days": days}))
    return out, []


# ---------------------------------------------------------------------------
# GCP
# ---------------------------------------------------------------------------

def _gcp_firewall_world(res, as_of, port: int, check_id: str):
    out = []
    for r in res:
        if r["type"] != "network":
            continue
        cfg = r["config"]
        if str(cfg.get("direction", "INGRESS")).upper() != "INGRESS":
            continue
        if not _world(cfg.get("source_ranges")):
            continue
        ports = cfg.get("ports") or []
        covers = (not ports) or any(port_covers(p, port) for p in ports)
        if covers:
            out.append(_finding(
                check_id, "gcp", r["id"],
                f"Firewall rule {r['id']} allows ingress to port {port} "
                "from 0.0.0.0/0.",
                {"source_ranges": cfg.get("source_ranges"),
                 "ports": ports}))
    return out, []


def _gcp_ssh(res, as_of):
    return _gcp_firewall_world(res, as_of, 22, "cis.gcp.firewall_ssh_world")


def _gcp_rdp(res, as_of):
    return _gcp_firewall_world(res, as_of, 3389,
                               "cis.gcp.firewall_rdp_world")


def _gcp_bucket_all_users(res, as_of):
    out, gaps = [], []
    buckets = [r for r in res if r["type"] == "storage"]
    if not buckets:
        return out, [_gap("cis.gcp.bucket_all_users", "gcs:getIamPolicy",
                          "no_resources")]
    for r in buckets:
        cfg = r["config"]
        if not cfg.get("iam_observed"):
            gaps.append(_gap("cis.gcp.bucket_all_users",
                             f"gcs:getIamPolicy:{r['id']}"))
            continue
        if cfg.get("public_members"):
            out.append(_finding(
                "cis.gcp.bucket_all_users", "gcp", r["id"],
                "Bucket IAM policy grants access to allUsers/"
                "allAuthenticatedUsers.",
                {"public_members": cfg["public_members"]}))
    return out, gaps


def _gcp_kms_rotation(res, as_of):
    out, gaps = [], []
    keys = [r for r in res if r["type"] == "kms"]
    if not keys:
        return out, [_gap("cis.gcp.kms_rotation", "kms:listKeys",
                          "no_resources")]
    for r in keys:
        # GCP reports ENABLED/DISABLED (uppercase); accept case-blind
        state = str(r["config"].get("state") or "").strip().upper()
        if state not in ("", "ENABLED"):
            continue
        period = str(r["config"].get("rotation_period") or "").rstrip("s")
        if not period:
            out.append(_finding(
                "cis.gcp.kms_rotation", "gcp", r["id"],
                "KMS key has no rotation period set (rotation disabled).",
                {"rotation_period": ""}))
            continue
        try:
            seconds = int(period)
        except ValueError:
            gaps.append(_gap("cis.gcp.kms_rotation",
                             f"kms:listKeys:{r['id']} "
                             f"(unparseable rotationPeriod)"))
            continue
        if seconds > 397 * 86400:
            out.append(_finding(
                "cis.gcp.kms_rotation", "gcp", r["id"],
                f"KMS key rotation period {seconds}s exceeds the 397-day "
                "CIS maximum.",
                {"rotation_period": r["config"].get("rotation_period")}))
    return out, gaps          # unparseable-period gaps must survive


# ---------------------------------------------------------------------------
# Azure
# ---------------------------------------------------------------------------

def _az_blob_public(res, as_of):
    out = []
    for r in res:
        if r["type"] == "storage" and r["config"].get("blob_public_access"):
            out.append(_finding(
                "cis.azure.storage_blob_public", "azure", r["id"],
                "Storage account allows anonymous public blob access "
                "(allowBlobPublicAccess=true).",
                {"allowBlobPublicAccess": True}))
    return out, []


def _az_https_off(res, as_of):
    out = []
    for r in res:
        if r["type"] != "storage":
            continue
        if not r["config"].get("https_only"):
            out.append(_finding(
                "cis.azure.storage_https_off", "azure", r["id"],
                "Storage account accepts non-HTTPS traffic "
                "(enableHttpsTrafficOnly=false).",
                {"enableHttpsTrafficOnly": False,
                 "min_tls": r["config"].get("min_tls")}))
    return out, []


def _az_nsg_world(res, as_of, port: int, check_id: str):
    out = []
    for r in res:
        if r["type"] != "network":
            continue
        for rule in r["config"].get("security_rules") or []:
            if str(rule.get("direction", "")).lower() != "inbound":
                continue
            if str(rule.get("access", "")).lower() != "allow":
                continue
            if not _world([rule.get("source")]):
                continue
            if port_covers(rule.get("port"), port):
                out.append(_finding(
                    check_id, "azure", r["id"],
                    f"NSG rule {rule.get('name')} allows inbound {port} "
                    "from the internet.",
                    {"source": rule.get("source"), "port": rule.get("port"),
                     "rule": rule.get("name")}))
    return out, []


def _az_ssh(res, as_of):
    return _az_nsg_world(res, as_of, 22, "cis.azure.nsg_ssh_world")


def _az_rdp(res, as_of):
    return _az_nsg_world(res, as_of, 3389, "cis.azure.nsg_rdp_world")


# ---------------------------------------------------------------------------
# registry
# ---------------------------------------------------------------------------

CHECKS: tuple[dict, ...] = (
    {"check_id": "cis.aws.root_mfa", "provider": "aws",
     "benchmark": B_AWS, "severity": "high", "control": "5.2",
     "title": "Ensure MFA is enabled for the root user",
     "remediation": "Enable hardware/MFA for the root user.",
     "requires": ("iam:GetAccountSummary",), "fn": _root_mfa},
    {"check_id": "cis.aws.root_access_key", "provider": "aws",
     "benchmark": B_AWS, "severity": "high", "control": "5.1",
     "title": "Ensure no root user access keys exist",
     "remediation": "Delete root access keys; use IAM roles instead.",
     "requires": ("iam:GetAccountSummary",), "fn": _root_access_key},
    {"check_id": "cis.aws.sg_ssh_world", "provider": "aws",
     "benchmark": B_AWS, "severity": "high", "control": "5.2/4.1",
     "title": "Security groups must not allow 0.0.0.0/0 to port 22",
     "remediation": "Restrict SSH ingress to known CIDR ranges.",
     "requires": ("ec2:DescribeSecurityGroups",), "fn": _sg_ssh},
    {"check_id": "cis.aws.sg_rdp_world", "provider": "aws",
     "benchmark": B_AWS, "severity": "high", "control": "5.3/4.2",
     "title": "Security groups must not allow 0.0.0.0/0 to port 3389",
     "remediation": "Restrict RDP ingress to known CIDR ranges.",
     "requires": ("ec2:DescribeSecurityGroups",), "fn": _sg_rdp},
    {"check_id": "cis.aws.ebs_unencrypted", "provider": "aws",
     "benchmark": B_AWS, "severity": "medium", "control": "2.2.1",
     "title": "EBS volumes must be encrypted at rest",
     "remediation": "Enable encryption at rest on all EBS volumes.",
     "requires": ("ec2:DescribeVolumes",), "fn": _ebs_unencrypted},
    {"check_id": "cis.aws.s3_public_access_block", "provider": "aws",
     "benchmark": B_AWS, "severity": "high", "control": "2.1.5",
     "title": "S3 bucket public access block must be fully enabled",
     "remediation": "Set all four BlockPublic* / RestrictPublicBuckets "
                    "flags to true.",
     "requires": ("s3:ListBuckets", "s3:GetPublicAccessBlock"),
     "fn": _s3_paab},
    {"check_id": "cis.aws.cloudtrail_exists", "provider": "aws",
     "benchmark": B_AWS, "severity": "high", "control": "3.1",
     "title": "At least one CloudTrail trail must exist",
     "remediation": "Create a multi-region trail with validation enabled.",
     "requires": ("cloudtrail:DescribeTrails",), "fn": _trail_exists},
    {"check_id": "cis.aws.cloudtrail_status", "provider": "aws",
     "benchmark": B_AWS, "severity": "high", "control": "3.2",
     "title": "CloudTrail trails must be actively logging",
     "remediation": "Restart logging on stopped trails.",
     "requires": ("cloudtrail:DescribeTrails",
                  "cloudtrail:GetTrailStatus"),
     "fn": _trail_status},
    {"check_id": "cis.aws.cloudtrail_validation", "provider": "aws",
     "benchmark": B_AWS, "severity": "medium", "control": "3.5",
     "title": "CloudTrail log file validation must be enabled",
     "remediation": "Enable log file validation on every trail.",
     "requires": ("cloudtrail:DescribeTrails",),
     "fn": _trail_validation},
    {"check_id": "cis.aws.cloudtrail_multiregion", "provider": "aws",
     "benchmark": B_AWS, "severity": "medium", "control": "3.4",
     "title": "CloudTrail trails must be multi-region",
     "remediation": "Convert single-region trails to multi-region.",
     "requires": ("cloudtrail:DescribeTrails",),
     "fn": _trail_multiregion},
    {"check_id": "cis.aws.kms_rotation", "provider": "aws",
     "benchmark": B_AWS, "severity": "medium", "control": "3.7",
     "title": "KMS CMKs must have automatic rotation enabled",
     "remediation": "Enable automatic annual rotation on CMKs.",
     "requires": ("kms:ListKeys", "kms:GetKeyRotationStatus"),
     "fn": _kms_rotation},
    {"check_id": "cis.aws.iam_stale_password", "provider": "aws",
     "benchmark": B_AWS, "severity": "medium", "control": "5.4",
     "title": "Unused IAM user passwords (>90 days) must be removed",
     "remediation": "Delete or reset stale user passwords.",
     "requires": ("iam:ListUsers",), "fn": _iam_stale},
    {"check_id": "cis.gcp.firewall_ssh_world", "provider": "gcp",
     "benchmark": B_GCP, "severity": "high", "control": "4.1",
     "title": "Firewall rules must not allow 0.0.0.0/0 to port 22",
     "remediation": "Restrict SSH ingress to known ranges.",
     "requires": ("gce:firewalls",), "fn": _gcp_ssh},
    {"check_id": "cis.gcp.firewall_rdp_world", "provider": "gcp",
     "benchmark": B_GCP, "severity": "high", "control": "4.2",
     "title": "Firewall rules must not allow 0.0.0.0/0 to port 3389",
     "remediation": "Restrict RDP ingress to known ranges.",
     "requires": ("gce:firewalls",), "fn": _gcp_rdp},
    {"check_id": "cis.gcp.bucket_all_users", "provider": "gcp",
     "benchmark": B_GCP, "severity": "high", "control": "5.1",
     "title": "Storage buckets must not be readable by allUsers",
     "remediation": "Remove allUsers/allAuthenticatedUsers bindings.",
     "requires": ("gcs:buckets", "gcs:getIamPolicy"),
     "fn": _gcp_bucket_all_users},
    {"check_id": "cis.gcp.kms_rotation", "provider": "gcp",
     "benchmark": B_GCP, "severity": "medium", "control": "1.4",
     "title": "KMS keys must rotate at least every 397 days",
     "remediation": "Set rotationPeriod to <= 397d on every key.",
     "requires": ("kms:listKeys",), "fn": _gcp_kms_rotation},
    {"check_id": "cis.azure.storage_blob_public", "provider": "azure",
     "benchmark": B_AZURE, "severity": "high", "control": "3.1",
     "title": "Storage accounts must not allow public blob access",
     "remediation": "Set allowBlobPublicAccess=false.",
     "requires": ("arm:storageAccounts",), "fn": _az_blob_public},
    {"check_id": "cis.azure.storage_https_off", "provider": "azure",
     "benchmark": B_AZURE, "severity": "medium", "control": "3.2",
     "title": "Storage accounts must require HTTPS",
     "remediation": "Set enableHttpsTrafficOnly=true.",
     "requires": ("arm:storageAccounts",), "fn": _az_https_off},
    {"check_id": "cis.azure.nsg_ssh_world", "provider": "azure",
     "benchmark": B_AZURE, "severity": "high", "control": "4.1",
     "title": "NSGs must not allow inbound 22 from the internet",
     "remediation": "Restrict inbound SSH to known prefixes.",
     "requires": ("arm:networkSecurityGroups",), "fn": _az_ssh},
    {"check_id": "cis.azure.nsg_rdp_world", "provider": "azure",
     "benchmark": B_AZURE, "severity": "high", "control": "4.2",
     "title": "NSGs must not allow inbound 3389 from the internet",
     "remediation": "Restrict inbound RDP to known prefixes.",
     "requires": ("arm:networkSecurityGroups",), "fn": _az_rdp},
)

CHECKS_BY_ID = {c["check_id"]: c for c in CHECKS}


def run_checks(provider: str, resources: list[dict],
               as_of: datetime) -> tuple[list[dict], list[dict]]:
    """Run every check for ``provider``.  Returns (findings, gaps) --
    findings carry full meta from the registry, sorted deterministically.
    Checks whose required ops were never obtained are reported as gaps
    by the caller (connect) using CHECKS_BY_ID[...]['requires']."""
    findings: list[dict] = []
    gaps: list[dict] = []
    for check in CHECKS:
        if check["provider"] != provider:
            continue
        got, gaps_for_check = check["fn"](resources, as_of)
        for body in got:
            findings.append({
                "kind": "finding",     # gaps carry kind too -- parity
                "check_id": check["check_id"],
                "benchmark": check["benchmark"],
                "control": check["control"],
                "severity": check["severity"],
                "title": check["title"],
                "remediation": check["remediation"],
                **{k: v for k, v in body.items() if k != "kind"},
            })
        for gap in gaps_for_check:
            gaps.append({**gap, "check_id": check["check_id"]})
    findings.sort(key=lambda f: (f["check_id"], f["resource_id"],
                                 f["explanation"]))
    gaps.sort(key=lambda g: (g["check_id"], g.get("target", "")))
    return findings, gaps
