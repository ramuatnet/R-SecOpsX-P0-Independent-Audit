"""T-6.2: posture rollup -- public-bucket / encryption / logging facts.

The inventory-level view task.md asks for beside the CIS control
findings: which stores are exposed, which are unencrypted, which
logging is off.  Pure derivation from normalized records; a field the
normalizer never observed is NOT assessed here (it becomes a CIS
``insufficient_data`` gap instead of a silent pass).  Sorted output --
same records in, same rollup out.
"""
from __future__ import annotations


def _row(provider: str, rid: str, reason: str) -> dict:
    return {"provider": provider, "resource_id": rid, "reason": reason}


def rollup(resources: list[dict]) -> dict:
    public_buckets: list[dict] = []
    unencrypted: list[dict] = []
    unlogged: list[dict] = []
    trail_seen = False

    for r in resources:
        cfg = r.get("config") or {}
        if r["type"] == "storage" and r["provider"] == "aws":
            paab = cfg.get("public_access_block")
            if cfg.get("public_access_block_observed") and paab is not None:
                off = sorted(k for k, v in paab.items() if not v)
                if off:
                    public_buckets.append(_row(
                        "aws", r["id"],
                        "public_access_block_disabled:" + ",".join(off)))
        elif r["type"] == "storage" and r["provider"] == "gcp":
            if cfg.get("iam_observed") and cfg.get("public_members"):
                public_buckets.append(_row(
                    "gcp", r["id"],
                    "iam_binding:" + ",".join(cfg["public_members"])))
        elif r["type"] == "storage" and r["provider"] == "azure":
            if cfg.get("blob_public_access"):
                public_buckets.append(_row(
                    "azure", r["id"], "allowBlobPublicAccess=true"))

        if r["type"] == "storage" and r["provider"] == "aws" \
                and "encrypted" in cfg and not cfg.get("encrypted"):
            unencrypted.append(_row("aws", r["id"], "ebs_encrypted=false"))

        if r["type"] == "logging" and r["provider"] == "aws":
            trail_seen = True
            if cfg.get("status_observed") and cfg.get("is_logging") is False:
                unlogged.append(_row("aws", r["id"], "is_logging=false"))

    # account-level: AWS in inventory but zero trails at all
    if any(r["provider"] == "aws" for r in resources) and not trail_seen:
        if any(r["provider"] == "aws" and r["type"] == "identity"
               for r in resources):
            unlogged.append(_row("aws", "account", "cloudtrail_not_configured"))

    def key(row):
        return (row["provider"], row["resource_id"], row["reason"])

    return {"public_buckets": sorted(public_buckets, key=key),
            "unencrypted_stores": sorted(unencrypted, key=key),
            "unlogged": sorted(unlogged, key=key)}
