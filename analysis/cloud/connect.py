"""T-6.2: read-only cloud connectors + posture artifact orchestration.

Risk-register contract (task.md): **credentials only in the ``cloud``
stage** -- this module is the ONLY place credential-shaped data exists;
``resolve_credentials`` reads env exclusively when a provider was
explicitly requested.  Scan mode never imports or runs this path.

Three ways in, same normalizer on the other side:

  * live     -- op table -> signed/bearer HTTP via injected ``send``
                (SigV4/bearer; pagination + detail polls bounded,
                truncation disclosed);
  * ingest   -- offline JSON capture (``--aws-file`` ...): raw pages
                exactly as the live path stores them -- same code path,
                no network;
  * nothing  -- default run: every provider becomes a machine-readable
                skip and the artifact is byte-identical run-to-run.

Artifact: ``rsecopsx.cloud_posture/v1`` = {schema, as_of, providers[],
sources[], inventory{resources[]}, findings[], posture{}, skips[],
stats{}}.  Never raises on provider failure -- failures are skips.
"""
from __future__ import annotations

import argparse
import json
import os
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Callable

from analysis.cloud import cis, model, posture
from analysis.cloud.client import (ApiError, ResponseTooLarge, aws_call,
                                   bearer_call, http_call, parse_json)

SCHEMA = "rsecopsx.cloud_posture/v1"
PROVIDERS = ("aws", "gcp", "azure")
DEFAULT_REGION = "us-east-1"
MAX_PAGES = 20
MAX_DETAIL_CALLS = 25
MAX_BODY = 4 * 1024 * 1024

# detail ops are polled per-resource; coverage gaps are reported by the
# CIS fn itself (observed flags), never by the requires-pass below
DETAIL_OPS = frozenset({"s3:GetPublicAccessBlock", "kms:GetKeyRotationStatus",
                        "cloudtrail:GetTrailStatus", "gcs:getIamPolicy"})

# ---------------------------------------------------------------------------
# op tables (read-only Describe/List/Get ONLY)
# ---------------------------------------------------------------------------

# (op, service, protocol, action/version or target, list-param, token extractor)
AWS_OPS: tuple[tuple, ...] = (
    ("ec2:DescribeInstances", "ec2", "query", "2016-11-15",
     "NextToken", ("xml", "nextToken")),
    ("ec2:DescribeSecurityGroups", "ec2", "query", "2016-11-15",
     "NextToken", ("xml", "nextToken")),
    ("ec2:DescribeSubnets", "ec2", "query", "2016-11-15",
     "NextToken", ("xml", "nextToken")),
    ("ec2:DescribeVolumes", "ec2", "query", "2016-11-15",
     "NextToken", ("xml", "nextToken")),
    ("iam:ListUsers", "iam", "query", "2010-05-08",
     "Marker", ("iam", "Marker")),
    ("iam:GetAccountSummary", "iam", "query", "2010-05-08",
     None, None),
    ("s3:ListBuckets", "s3", "rest-list", None, None, None),
    ("kms:ListKeys", "kms", "json", "TrentService.ListKeys",
     "NextMarker", ("json_trunc", "NextMarker")),
    ("cloudtrail:DescribeTrails", "cloudtrail", "json",
     "CloudTrail_20131101.DescribeTrails", None, None),
)

GCP_OPS: tuple[tuple, ...] = (
    ("gce:aggregatedInstances",
     "compute/v1/projects/{project}/aggregated/instances", None, None),
    ("gce:firewalls", "compute/v1/projects/{project}/global/firewalls",
     "pageToken", ("json", "nextPageToken")),
    ("gcs:buckets", "storage/v1/b?project={project}", "pageToken",
     ("json", "nextPageToken")),
    ("kms:listKeys",
     "cloudkms/v1/projects/{project}/locations/-/keyRings/-/keys",
     "pageToken", ("json", "nextPageToken")),
)
GCP_BASE = "https://www.googleapis.com/"

AZURE_OPS: tuple[tuple, ...] = (
    ("arm:virtualMachines",
     "subscriptions/{sub}/providers/Microsoft.Compute/"
     "virtualMachines?api-version=2024-03-01",),
    ("arm:storageAccounts",
     "subscriptions/{sub}/providers/Microsoft.Storage/"
     "storageAccounts?api-version=2023-05-01",),
    ("arm:networkSecurityGroups",
     "subscriptions/{sub}/providers/Microsoft.Network/"
     "networkSecurityGroups?api-version=2024-01-01",),
)
AZURE_BASE = "https://management.azure.com/"


def _token_from(text: str, spec, op: str):
    """spec: (xml|json|iam|json_trunc, field). -> next list-param value
    or None.  Raises ApiError on unreadable pagination fields."""
    style, field = spec
    if style == "json" or style == "json_trunc":
        doc = parse_json(text, op=op)
        if style == "json_trunc" and not doc.get("Truncated"):
            return None
        value = doc.get(field)
        return str(value) if value else None
    if style == "iam":
        import xml.etree.ElementTree as ET
        root = ET.fromstring(text)
        for el in root.iter():
            if isinstance(el.tag, str):
                el.tag = el.tag.rsplit("}", 1)[-1]
        if (root.findtext(".//IsTruncated") or "").lower() != "true":
            return None
        marker = root.findtext(".//Marker")
        return marker or None
    import xml.etree.ElementTree as ET
    root = ET.fromstring(text)
    for el in root.iter():
        if isinstance(el.tag, str):
            el.tag = el.tag.rsplit("}", 1)[-1]
    value = root.findtext(f".//{field}")
    return value or None


# ---------------------------------------------------------------------------
# credentials (stage-scoped env reads)
# ---------------------------------------------------------------------------

def resolve_credentials(provider: str, explicit: dict | None = None,
                        env: dict | None = None) -> dict | None:
    """Stage-scoped credential resolution.  Returns None when not
    configured -> caller records ``no_provider_configured`` (the
    passive_dns precedent).  Env is read ONLY here, and only for
    providers the caller explicitly requested."""
    env = os.environ if env is None else env
    if explicit:
        got = {k: v for k, v in explicit.items() if v}
        if got:
            return got
    if provider == "aws":
        key, secret = env.get("AWS_ACCESS_KEY_ID"), env.get("AWS_SECRET_ACCESS_KEY")
        if key and secret:
            return {"access_key": key, "secret_key": secret,
                    "region": env.get("AWS_REGION") or
                    env.get("AWS_DEFAULT_REGION") or DEFAULT_REGION}
    elif provider == "gcp":
        token = env.get("RSX_GCP_ACCESS_TOKEN")
        project = env.get("RSX_GCP_PROJECT_ID") or env.get("GOOGLE_CLOUD_PROJECT")
        if token and project:
            return {"token": token, "project": project}
    elif provider == "azure":
        token = (env.get("RSX_AZURE_ACCESS_TOKEN") or
                 env.get("AZURE_ACCESS_TOKEN"))
        sub = env.get("AZURE_SUBSCRIPTION_ID")
        if token and sub:
            return {"token": token, "subscription": sub}
    return None


# ---------------------------------------------------------------------------
# live fetch (bounded)
# ---------------------------------------------------------------------------

def _urllib_send(timeout: float, sleep):
    def _send(method: str, url: str, headers: dict, body: bytes):
        sleep(0)
        req = urllib.request.Request(url, data=body or None,
                                     method=method.upper())
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.status, dict(resp.headers), resp.read(MAX_BODY)
        except urllib.error.HTTPError as exc:
            return exc.code, dict(exc.headers or {}), exc.read(MAX_BODY)
    return _send


def _paginate(fetch_page, param: str | None, spec, op: str):
    """fetch_page(next_value) -> (text, url_for_debug).  Returns
    (pages, truncated)."""
    pages: list[str] = []
    nxt = None
    for _ in range(MAX_PAGES):
        text, _url = fetch_page(nxt)
        pages.append(text)
        if param is None or spec is None:
            return pages, False
        nxt = _token_from(text, spec, op)
        if not nxt:
            return pages, False
    return pages, True                   # budget exhausted -> disclosed


def _fetch_aws(send, creds, now, sleep=0.0):
    """raws + source/skip rows for the AWS op table + detail polls."""
    raws: dict[str, list[str]] = {}
    sources: list[dict] = []
    skips: list[dict] = []
    region = creds.get("region", DEFAULT_REGION)

    for op, service, protocol, version, param, spec in AWS_OPS:
        try:
            if protocol in ("query",):
                url = f"https://{service}.{region}.amazonaws.com/"

                def fetch(nxt, url=url, op=op, service=service,
                          version=version, param=param, creds=creds,
                          now=now):
                    action = op.split(":", 1)[1]
                    params = {"Action": action, "Version": version}
                    if nxt:
                        params[param] = nxt
                    body = ("&".join(f"{k}={v}" for k, v in params.items())
                            .encode())
                    headers = {"content-type":
                               "application/x-www-form-urlencoded; "
                               "charset=utf-8"}
                    _st, text = aws_call(
                        send, "POST", url, headers, body,
                        access_key=creds["access_key"],
                        secret_key=creds["secret_key"],
                        region=region, service=service, now=now)
                    return text, url
            elif protocol == "json":
                url = f"https://{service}.{region}.amazonaws.com/"
                target = version

                def fetch(nxt, url=url, target=target, creds=creds,
                          now=now, param=param):
                    payload: dict = {}
                    if nxt and param:
                        payload[param] = nxt
                    body = json.dumps(payload).encode()
                    headers = {"content-type": "application/x-amz-json-1.1",
                               "x-amz-target": target}
                    _st, text = aws_call(
                        send, "POST", url, headers, body,
                        access_key=creds["access_key"],
                        secret_key=creds["secret_key"],
                        region=region, service=service, now=now)
                    return text, url
            else:                        # s3 ListBuckets (REST, no pages)
                url = f"https://s3.{region}.amazonaws.com/"

                def fetch(_nxt, url=url, creds=creds, now=now):
                    _st, text = aws_call(
                        send, "GET", url, {}, b"",
                        access_key=creds["access_key"],
                        secret_key=creds["secret_key"],
                        region=region, service="s3", now=now)
                    return text, url

            pages, truncated = _paginate(fetch, param, spec, op)
            raws[op] = pages
            sources.append({"kind": op, "status": "ok",
                            "detail": {"pages": len(pages),
                                       "truncated": truncated}})
            if truncated:
                skips.append({"stage": "aws", "target": op,
                              "reason": f"page_cap_{MAX_PAGES}"})
        except (ApiError, ResponseTooLarge, OSError, ValueError) as exc:
            skips.append({"stage": "aws", "target": op,
                          "reason": f"{type(exc).__name__}: {exc}"[:200]})

    # ---- bounded detail polls (attempt-count at the call site: one
    # detail_cap row per op, then stop -- no silent pre-slice drops) ----
    def _detail(op: str, ident: str, call):
        key = f"{op}:{ident}"
        try:
            raws[key] = [call()]
        except ApiError as exc:
            if exc.status == 404:
                raws[key] = [model.ABSENT]
            else:
                skips.append({"stage": "aws", "target": key,
                              "reason": f"ApiError: http_{exc.status}"})
        except (ResponseTooLarge, OSError, ValueError) as exc:
            skips.append({"stage": "aws", "target": key,
                          "reason": f"{type(exc).__name__}"[:120]})

    def _cap_reached(i: int, op: str) -> bool:
        if i < MAX_DETAIL_CALLS:
            return False
        skips.append({"stage": "aws", "target": op,
                      "reason": "detail_cap"})
        return True

    if "s3:ListBuckets" in raws:
        try:
            import xml.etree.ElementTree as ET
            names = []
            for page in raws["s3:ListBuckets"]:
                root = ET.fromstring(page)
                for el in root.iter():
                    if isinstance(el.tag, str):
                        el.tag = el.tag.rsplit("}", 1)[-1]
                names += [b.findtext("Name") or ""
                          for b in root.findall(".//Buckets/Bucket")]
            for i, name in enumerate(n for n in names if n):
                if _cap_reached(i, "s3:GetPublicAccessBlock"):
                    break
                url = (f"https://{name}.s3.{region}.amazonaws.com/"
                       f"?publicaccessblock")
                def poll(url=url, name=name):
                    _st, text = aws_call(
                        send, "GET", url, {}, b"",
                        access_key=creds["access_key"],
                        secret_key=creds["secret_key"],
                        region=region, service="s3", now=now)
                    return text
                _detail("s3:GetPublicAccessBlock", name, poll)
        except (ApiError, ValueError) as exc:
            skips.append({"stage": "aws",
                          "target": "s3:GetPublicAccessBlock",
                          "reason": f"{type(exc).__name__}"[:120]})

    if "kms:ListKeys" in raws:
        try:
            key_ids = []
            for page in raws["kms:ListKeys"]:
                key_ids += [k.get("KeyId", "")
                            for k in json.loads(page).get("Keys", [])]
            for i, kid in enumerate(k for k in key_ids if k):
                if _cap_reached(i, "kms:GetKeyRotationStatus"):
                    break
                def poll(kid=kid):
                    body = json.dumps({"KeyId": kid}).encode()
                    headers = {"content-type": "application/x-amz-json-1.1",
                               "x-amz-target":
                               "TrentService.GetKeyRotationStatus"}
                    _st, text = aws_call(
                        send, "POST",
                        f"https://kms.{region}.amazonaws.com/",
                        headers, body,
                        access_key=creds["access_key"],
                        secret_key=creds["secret_key"],
                        region=region, service="kms", now=now)
                    return text
                _detail("kms:GetKeyRotationStatus", kid, poll)
        except (ApiError, ValueError) as exc:
            skips.append({"stage": "aws",
                          "target": "kms:GetKeyRotationStatus",
                          "reason": f"{type(exc).__name__}"[:120]})

    if "cloudtrail:DescribeTrails" in raws:
        try:
            names = []
            for page in raws["cloudtrail:DescribeTrails"]:
                names += [t.get("Name", "")
                          for t in json.loads(page).get("trailList", [])]
            for i, tname in enumerate(n for n in names if n):
                if _cap_reached(i, "cloudtrail:GetTrailStatus"):
                    break
                def poll(tname=tname):
                    body = json.dumps({"Name": tname}).encode()
                    headers = {
                        "content-type": "application/x-amz-json-1.1",
                        "x-amz-target":
                        "CloudTrail_20131101.GetTrailStatus"}
                    _st, text = aws_call(
                        send, "POST",
                        f"https://cloudtrail.{region}.amazonaws.com/",
                        headers, body,
                        access_key=creds["access_key"],
                        secret_key=creds["secret_key"],
                        region=region, service="cloudtrail", now=now)
                    return text
                _detail("cloudtrail:GetTrailStatus", tname, poll)
        except (ApiError, ValueError) as exc:
            skips.append({"stage": "aws",
                          "target": "cloudtrail:GetTrailStatus",
                          "reason": f"{type(exc).__name__}"[:120]})

    return raws, sources, skips


def _fetch_gcp(send, creds, now, sleep=0.0):
    raws: dict[str, list[str]] = {}
    sources: list[dict] = []
    skips: list[dict] = []
    project = creds["project"]

    for op, path_tmpl, param, spec in GCP_OPS:
        try:
            url0 = GCP_BASE + path_tmpl.format(project=project)

            def fetch(nxt, url0=url0, param=param, op=op):
                url = url0
                if nxt and param:
                    sep = "&" if "?" in url else "?"
                    url = f"{url}{sep}{param}={nxt}"
                _st, text = bearer_call(send, "GET", url, {}, b"",
                                        creds["token"])
                return text, url
            pages, truncated = _paginate(fetch, param, spec, op)
            raws[op] = pages
            sources.append({"kind": op, "status": "ok",
                            "detail": {"pages": len(pages),
                                       "truncated": truncated}})
            if truncated:
                skips.append({"stage": "gcp", "target": op,
                              "reason": f"page_cap_{MAX_PAGES}"})
        except (ApiError, ResponseTooLarge, OSError, ValueError) as exc:
            skips.append({"stage": "gcp", "target": op,
                          "reason": f"{type(exc).__name__}: {exc}"[:200]})

    if "gcs:buckets" in raws:
        try:
            names = []
            for page in raws["gcs:buckets"]:
                names += [b.get("name", "")
                          for b in json.loads(page).get("items") or []]
            for i, name in enumerate(n for n in names if n):
                if i >= MAX_DETAIL_CALLS:
                    skips.append({"stage": "gcp",
                                  "target": "gcs:getIamPolicy",
                                  "reason": "detail_cap"})
                    break
                def poll(name=name):
                    url = (f"{GCP_BASE}storage/v1/b/{name}/iam")
                    _st, text = bearer_call(send, "GET", url, {}, b"",
                                            creds["token"])
                    return text
                key = f"gcs:getIamPolicy:{name}"
                try:
                    raws[key] = [poll()]
                except ApiError as exc:
                    skips.append({"stage": "gcp", "target": key,
                                  "reason": f"ApiError: http_{exc.status}"})
        except (ApiError, ValueError) as exc:
            skips.append({"stage": "gcp", "target": "gcs:getIamPolicy",
                          "reason": f"{type(exc).__name__}"[:120]})

    return raws, sources, skips


def _fetch_azure(send, creds, now, sleep=0.0):
    raws: dict[str, list[str]] = {}
    sources: list[dict] = []
    skips: list[dict] = []
    sub = creds["subscription"]

    for (op, path_tmpl) in AZURE_OPS:
        try:
            url = AZURE_BASE + path_tmpl.format(sub=sub)
            pages: list[str] = []
            nxt = None
            truncated = False
            for _ in range(MAX_PAGES):
                _st, text = bearer_call(send, "GET", nxt or url, {}, b"",
                                        creds["token"])
                pages.append(text)
                doc = json.loads(text)
                nxt = doc.get("nextLink")
                if not nxt:
                    break
            else:
                truncated = True
            raws[op] = pages
            sources.append({"kind": op, "status": "ok",
                            "detail": {"pages": len(pages),
                                       "truncated": truncated}})
            if truncated:
                skips.append({"stage": "azure", "target": op,
                              "reason": f"page_cap_{MAX_PAGES}"})
        except (ApiError, ResponseTooLarge, OSError, ValueError) as exc:
            skips.append({"stage": "azure", "target": op,
                          "reason": f"{type(exc).__name__}: {exc}"[:200]})

    return raws, sources, skips


_FETCHERS = {"aws": _fetch_aws, "gcp": _fetch_gcp, "azure": _fetch_azure}


# ---------------------------------------------------------------------------
# orchestration
# ---------------------------------------------------------------------------

def collect_posture(requested: tuple[str, ...] = (),
                    *, files: dict[str, str] | None = None,
                    creds: dict[str, dict] | None = None,
                    as_of: datetime | None = None,
                    send=None, timeout_s: float = 10.0,
                    sleep=None) -> dict:
    """Build the rsecopsx.cloud_posture/v1 artifact.

    Default (no providers): zero I/O, byte-identical.  Per provider:
    ingest-file > explicit creds > env creds (stage-scoped) > skip.
    """
    files = files or {}
    creds = creds or {}
    as_of_dt = as_of or datetime.now(timezone.utc)
    if as_of_dt.tzinfo is None:
        as_of_dt = as_of_dt.replace(tzinfo=timezone.utc)
    _sleep = sleep or time.sleep
    _send = send or _urllib_send(timeout_s, _sleep)

    sources: list[dict] = []
    skips: list[dict] = []
    all_resources: list[dict] = []
    raws_by_provider: dict[str, dict] = {}

    for provider in PROVIDERS:
        if provider not in requested:
            skips.append({"stage": provider,
                          "target": provider,
                          "reason": "provider_not_requested"})
            continue
        if provider in files:
            try:
                with open(files[provider], "rb") as fh:
                    doc = json.loads(fh.read().decode("utf-8"))
                raws = {k: [str(p) for p in v]
                        for k, v in doc.get("ops", doc).items()}
                raws_by_provider[provider] = raws
                sources.append({"kind": f"{provider}:ingest",
                                "status": "ok",
                                "detail": {"input": "file",
                                           "ops": len(raws)}})
            except (OSError, ValueError) as exc:
                skips.append({"stage": provider,
                              "target": files[provider],
                              "reason": f"{type(exc).__name__}: {exc}"[:200]})
            continue
        got = creds.get(provider) or resolve_credentials(provider)
        if not got:
            skips.append({"stage": provider, "target": provider,
                          "reason": "no_provider_configured"})
            continue
        try:
            raws, src, sk = _FETCHERS[provider](_send, got, as_of_dt,
                                                sleep=_sleep)
            raws_by_provider[provider] = raws
            sources.extend(src)
            skips.extend(sk)
        except Exception as exc:       # noqa: BLE001 - disclose, never raise
            skips.append({"stage": provider, "target": provider,
                          "reason": f"{type(exc).__name__}: {exc}"[:200]})

    # normalize + checks per obtained provider
    findings: list[dict] = []
    cis_gaps: list[dict] = []
    for provider in PROVIDERS:
        raws = raws_by_provider.get(provider)
        if raws is None:
            continue
        resources = model.normalize(provider, raws, as_of_dt)
        all_resources.extend(resources)
        got_findings, got_gaps = cis.run_checks(provider, resources,
                                                as_of_dt)
        findings.extend(got_findings)
        cis_gaps.extend(got_gaps)
        # required table ops never obtained -> insufficient_data gap
        for check in cis.CHECKS:
            if check["provider"] != provider:
                continue
            for req in check["requires"]:
                if req in DETAIL_OPS:
                    continue            # fn reports per-resource coverage
                if req not in raws:
                    cis_gaps.append({"kind": "gap", "reason":
                                     "insufficient_data",
                                     "check_id": check["check_id"],
                                     "target": req})

    all_resources.sort(key=lambda r: (r["provider"], r["type"], r["id"]))
    findings.sort(key=lambda f: (f["check_id"], f["resource_id"],
                                 f["explanation"]))
    for gap in cis_gaps:
        skips.append({"stage": "cis",
                      "target": gap.get("target", ""),
                      "reason": gap.get("reason", "insufficient_data"),
                      "check_id": gap.get("check_id", "")})
    skips.sort(key=lambda s: (s["stage"], s["target"], s["reason"],
                              s.get("check_id", "")))
    sources.sort(key=lambda s: (s["kind"], s["status"]))

    return {
        "schema": SCHEMA,
        "as_of": as_of_dt.astimezone(timezone.utc).isoformat()
                 .replace("+00:00", "Z"),
        "providers": list(requested),
        "sources": sources,
        "inventory": {"resources": all_resources},
        "findings": findings,
        "posture": posture.rollup(all_resources),
        "skips": skips,
        "stats": {
            "resources": len(all_resources),
            "findings": len(findings),
            "sources_ok": sum(1 for s in sources
                              if s["status"] == "ok"),
            "skips": len(skips),
        },
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="python -m analysis.cloud.collect",
        description="Build rsecopsx.cloud_posture/v1. No provider flags "
                    "= offline deterministic run. Credentials are read "
                    "only for explicitly requested providers.")
    ap.add_argument("--aws", action="store_true",
                    help="request AWS stage (env AWS_ACCESS_KEY_ID etc.)")
    ap.add_argument("--gcp", action="store_true",
                    help="request GCP stage (env RSX_GCP_ACCESS_TOKEN, "
                         "RSX_GCP_PROJECT_ID)")
    ap.add_argument("--azure", action="store_true",
                    help="request Azure stage (env RSX_AZURE_ACCESS_TOKEN, "
                         "AZURE_SUBSCRIPTION_ID)")
    ap.add_argument("--aws-file", default=None,
                    help="offline AWS op capture (JSON), no network")
    ap.add_argument("--gcp-file", default=None,
                    help="offline GCP op capture (JSON)")
    ap.add_argument("--azure-file", default=None,
                    help="offline Azure op capture (JSON)")
    ap.add_argument("--as-of", default=None,
                    help="ISO-8601 clock injection for reproducibility")
    ap.add_argument("--out", default=None, help="write artifact JSON here")
    args = ap.parse_args(argv)

    requested: list[str] = []
    files: dict[str, str] = {}
    for p, flag, f in (("aws", args.aws, args.aws_file),
                       ("gcp", args.gcp, args.gcp_file),
                       ("azure", args.azure, args.azure_file)):
        if flag or f:
            requested.append(p)
        if f:
            files[p] = f

    as_of = None
    if args.as_of:
        try:
            as_of = datetime.fromisoformat(
                args.as_of.replace("Z", "+00:00"))
            if as_of.tzinfo is None:
                as_of = as_of.replace(tzinfo=timezone.utc)
        except ValueError:
            print(f"error: bad --as-of: {args.as_of}")
            return 2

    try:
        doc = collect_posture(tuple(requested), files=files, as_of=as_of)
    except ValueError as exc:
        print(f"error: {exc}")
        return 2
    text = json.dumps(doc, sort_keys=True, indent=2) + "\n"
    if args.out:
        with open(args.out, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
    else:
        print(text, end="")
    return 0
