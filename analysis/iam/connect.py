"""T-6.3: IAM analysis orchestration (ingest / live / CLI).

Three ways in, same model on the other side:

  * live     -- iam:GetAccountAuthorizationDetails (query protocol,
                Marker pagination bounded by MAX_PAGES, truncation
                disclosed) via injected ``send`` + SigV4;
  * ingest   -- offline JSON capture (``--aws-file``): raw pages
                exactly as the live path stores them, plus an optional
                ``usage`` sidecar (principal arn -> service prefixes)
                for the unused-permissions check -- same code path,
                no network;
  * nothing  -- default run: a machine-readable skip, zero I/O,
                byte-identical artifact.

Credentials are resolved ONLY by ``analysis.cloud.connect.
resolve_credentials`` (the single stage-scoped env reader); this
module never reads credential env vars itself (task.md risk
register).  Artifact: ``rsecopsx.iam_analysis/v1``.
"""
from __future__ import annotations

import argparse
import json
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

from analysis.cloud.client import ApiError, ResponseTooLarge, aws_call
# single stage-scoped credential handler (cloud stage); never inlined
from analysis.cloud.connect import resolve_credentials  # noqa: F401
from analysis.iam import checks, policy

SCHEMA = "rsecopsx.iam_analysis/v1"
PROVIDERS = ("aws",)
DEFAULT_REGION = "us-east-1"
MAX_PAGES = 20
MAX_BODY = 4 * 1024 * 1024

IAM_OP = "iam:GetAccountAuthorizationDetails"
IAM_URL = "https://iam.amazonaws.com/"
IAM_VERSION = "2010-05-08"


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


def _iam_marker(text: str) -> str | None:
    """Next Marker value, or None when the response is final.  A
    truncated response without a Marker yields '' (still paginated --
    disclosed by the live test harness; real AWS always sends one)."""
    root = ET.fromstring(text)
    for el in root.iter():
        if isinstance(el.tag, str):
            el.tag = el.tag.rsplit("}", 1)[-1]
    truncated = (root.findtext(".//IsTruncated") or "").lower() == "true"
    if not truncated:
        return None
    return root.findtext(".//Marker") or ""


def _fetch_aws(send, creds, now, sleep=0.0):
    """raw pages + source/skip rows for GetAccountAuthorizationDetails."""
    pages: list[str] = []
    truncated = False
    nxt = None
    for _ in range(MAX_PAGES):
        params = {"Action": "GetAccountAuthorizationDetails",
                  "Version": IAM_VERSION}
        if nxt is not None:
            params["Marker"] = nxt
        body = ("&".join(f"{k}={v}" for k, v in params.items())
                .encode())
        headers = {"content-type":
                   "application/x-www-form-urlencoded; charset=utf-8"}
        _st, text = aws_call(
            send, "POST", IAM_URL, headers, body,
            access_key=creds["access_key"],
            secret_key=creds["secret_key"],
            region=creds.get("region", DEFAULT_REGION),
            service="iam", now=now)
        pages.append(text)
        nxt = _iam_marker(text)
        if nxt is None:
            break
    else:
        truncated = True                     # budget exhausted -> disclosed
    sources = [{"kind": IAM_OP, "status": "ok",
                "detail": {"pages": len(pages), "truncated": truncated}}]
    skips: list[dict] = []
    if truncated:
        skips.append({"stage": "aws", "target": IAM_OP,
                      "reason": f"page_cap_{MAX_PAGES}"})
    return pages, sources, skips


def collect_iam(requested: tuple[str, ...] = (),
                *, files: dict[str, str] | None = None,
                creds: dict[str, dict] | None = None,
                as_of: datetime | None = None,
                send=None, timeout_s: float = 10.0,
                sleep=None) -> dict:
    """Build the rsecopsx.iam_analysis/v1 artifact.

    Default (nothing requested): zero I/O, byte-identical.  Per
    provider: ingest-file > explicit creds > env creds (stage-scoped)
    > skip.
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
    pages: list[str] = []
    usage = None
    obtained = False

    for provider in PROVIDERS:
        if provider not in requested:
            skips.append({"stage": provider, "target": provider,
                          "reason": "provider_not_requested"})
            continue
        if provider in files:
            try:
                with open(files[provider], "r", encoding="utf-8") as fh:
                    doc = json.loads(fh.read())
                ops = doc.get("ops", doc)
                pages = [str(p) for p in
                         ops.get(IAM_OP, []) if str(p).strip()]
                if not pages:
                    skips.append({"stage": provider,
                                  "target": files[provider],
                                  "reason": "capture_missing_op"})
                else:
                    obtained = True
                    sidecar = doc.get("usage")
                    if isinstance(sidecar, dict):
                        usage = sidecar
                    sources.append({"kind": f"{provider}:ingest",
                                    "status": "ok",
                                    "detail": {"input": "file",
                                               "pages": len(pages)}})
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
            pages, src, sk = _fetch_aws(_send, got, as_of_dt, sleep=_sleep)
            obtained = True
            sources.extend(src)
            skips.extend(sk)
        except (ApiError, ResponseTooLarge, OSError, ValueError) as exc:
            skips.append({"stage": provider, "target": IAM_OP,
                          "reason": f"{type(exc).__name__}: {exc}"[:200]})

    model = {"account_id": None, "principals": [], "groups": {},
             "policies": {}, "usage": None, "skips": []}
    findings: list[dict] = []
    gaps: list[dict] = []
    if obtained:
        model = policy.build_model(pages, usage=usage)
        findings, gaps = checks.run_checks(model, as_of_dt)

    for s in model["skips"]:
        skips.append(dict(s))
    for g in gaps:
        skips.append({"stage": "iam", "target": g.get("target", ""),
                      "reason": g.get("reason", "insufficient_data"),
                      "check_id": g.get("check_id", "")})
    skips.sort(key=lambda s: (s["stage"], s["target"], s["reason"],
                              s.get("check_id", "")))
    sources.sort(key=lambda s: (s["kind"], s["status"]))

    return {
        "schema": SCHEMA,
        "as_of": as_of_dt.astimezone(timezone.utc).isoformat()
                 .replace("+00:00", "Z"),
        "account_id": model["account_id"],
        "sources": sources,
        "principals": model["principals"],
        "findings": findings,
        "skips": skips,
        "stats": {
            "principals": len(model["principals"]),
            "groups": len(model.get("groups", {})),
            "customer_policies": len(model.get("policies", {})),
            "findings": len(findings),
            "sources_ok": sum(1 for s in sources
                              if s["status"] == "ok"),
            "skips": len(skips),
        },
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="python -m analysis.iam.connect",
        description="Build rsecopsx.iam_analysis/v1. No provider flags "
                    "= offline deterministic run. Credentials are read "
                    "only for explicitly requested providers.")
    ap.add_argument("--aws", action="store_true",
                    help="request live AWS IAM fetch (env "
                         "AWS_ACCESS_KEY_ID etc., resolved stage-scoped "
                         "in analysis.cloud.connect)")
    ap.add_argument("--aws-file", default=None,
                    help="offline GetAccountAuthorizationDetails capture "
                         "(JSON with ops + optional usage sidecar)")
    ap.add_argument("--as-of", default=None,
                    help="ISO-8601 clock injection for reproducibility")
    ap.add_argument("--out", default=None, help="write artifact JSON here")
    args = ap.parse_args(argv)

    requested: list[str] = []
    files: dict[str, str] = {}
    if args.aws or args.aws_file:
        requested.append("aws")
    if args.aws_file:
        files["aws"] = args.aws_file

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

    doc = collect_iam(tuple(requested), files=files, as_of=as_of)
    text = json.dumps(doc, sort_keys=True, indent=2) + "\n"
    if args.out:
        with open(args.out, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
    else:
        print(text, end="")
    return 0
