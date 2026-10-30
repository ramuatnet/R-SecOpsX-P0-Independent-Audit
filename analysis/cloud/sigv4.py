"""T-6.2: AWS Signature Version 4 -- pure stdlib, injected clock.

No SDK dependency (offline invariant: boto3 is NOT a runtime dep).  The
canonical form follows the AWS SigV4 spec exactly:

  canonical request = method\\n uri\\n query\\n headers\\n signed\\n payload_hash
  string to sign    = ALGORITHM\\n ts\\n scope\\n hex(sha256(canonical))
  signature         = hex(HMAC-SHA256 chain(secret -> date -> region ->
                      service -> "aws4_request", string_to_sign))

Pinned test vector (AWS documentation example): AKIDEXAMPLE /
us-east-1 / iam / 20150830T123600Z signs GET
https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08 with
payload hash of the empty body -> signature
5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7.
"""
from __future__ import annotations

import hashlib
import hmac
from datetime import datetime, timezone
from urllib.parse import quote, urlsplit

ALGORITHM = "AWS4-HMAC-SHA256"
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
SAFE = "-_.~"


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hmac(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def _uri_encode(value: str) -> str:
    # RFC 3986 unreserved only; uppercase hex (quote does this by default)
    return quote(str(value), safe="")


def canonical_query(query: str) -> str:
    """Canonical query string: sorted key=value pairs, RFC3986 encoded.

    Input is the RAW query (already percent-encoded or not -- decode then
    re-encode so 'a b' and 'a%20b' canonicalize identically).
    """
    from urllib.parse import parse_qsl, urlencode

    pairs = parse_qsl(query, keep_blank_values=True)
    return urlencode(sorted(( _uri_encode(k), _uri_encode(v))
                            for k, v in pairs), safe="")


def canonical_request(method: str, url: str, headers: dict[str, str],
                      payload_hash: str) -> tuple[str, list[str]]:
    """(canonical_request_text, signed_header_names).  ``headers`` must
    already be lower-cased; Host and x-amz-date MUST be present."""
    parts = urlsplit(url)
    path = _uri_encode(parts.path or "/")
    # path segments are individually safe="/" -- encode whole then restore
    # separators so '/a b' -> '/a%20b' (single encoding, IAM/S3 default)
    path = quote(parts.path or "/", safe="/")
    signed = sorted(headers)
    canon_headers = "".join(
        f"{k}:{' '.join(str(headers[k]).split())}\n" for k in signed)
    text = (f"{method.upper()}\n{path}\n"
            f"{canonical_query(parts.query or '')}\n"
            f"{canon_headers}\n"
            f"{';'.join(signed)}\n{payload_hash}")
    return text, signed


def string_to_sign(amz_date: str, scope: str, canon_hash: str) -> str:
    return f"{ALGORITHM}\n{amz_date}\n{scope}\n{canon_hash}"


def signing_key(secret: str, date_stamp: str, region: str,
                service: str) -> bytes:
    k = _hmac(f"AWS4{secret}".encode("utf-8"), date_stamp)
    k = _hmac(k, region)
    k = _hmac(k, service)
    return _hmac(k, "aws4_request")


def sign_request(method: str, url: str, headers: dict[str, str],
                 body: bytes, *, access_key: str, secret_key: str,
                 region: str, service: str,
                 now: datetime) -> dict[str, str]:
    """Return headers with x-amz-date + Authorization added (original
    dict untouched).  ``now`` is injected (determinism)."""
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    now = now.astimezone(timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now.strftime("%Y%m%d")

    low = {str(k).lower(): str(v) for k, v in headers.items()}
    parts = urlsplit(url)
    if "host" not in low:
        host = parts.hostname or ""
        if parts.port and parts.port not in (80, 443):
            host = f"{host}:{parts.port}"
        low["host"] = host
    low["x-amz-date"] = amz_date

    payload_hash = sha256_hex(body or b"")
    canon, signed = canonical_request(method, url, low, payload_hash)
    scope = f"{date_stamp}/{region}/{service}/aws4_request"
    sts = string_to_sign(amz_date, scope, sha256_hex(canon.encode("utf-8")))
    sig = hmac.new(signing_key(secret_key, date_stamp, region, service),
                   sts.encode("utf-8"), hashlib.sha256).hexdigest()

    low["authorization"] = (
        f"{ALGORITHM} Credential={access_key}/{scope}, "
        f"SignedHeaders={';'.join(signed)}, Signature={sig}")
    return low
