"""T-6.2: read-only cloud API transport (bounds + auth wrappers).

Everything network-shaped is injected: ``send(method, url, headers,
body) -> (status, headers_lower, body_BYTES)``.  No SDK, no sockets in
this module -- the same HttpFetch contract as analysis.asm/collect.

Read-only by construction: the ONLY ops ever issued are the GET/POST
``Describe/List/Get`` operations in the provider op tables (connect.py).
Authorization headers are built here (SigV4 for AWS, bearer for
GCP/Azure); credentials never leave this layer and are never read
outside the ``cloud`` stage (task.md risk register).
"""
from __future__ import annotations

import json
from datetime import datetime
from typing import Callable

from analysis.cloud import sigv4

# Resource bounds for untrusted API responses (ground rule 12)
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_EXCERPT = 200

SendFn = Callable[[str, str, dict, bytes], tuple[int, dict, bytes]]


class ApiError(Exception):
    """Non-2xx from a provider API.  ``status`` + bounded excerpt."""

    def __init__(self, status: int, excerpt: str = "") -> None:
        super().__init__(f"http_{status}")
        self.status = int(status)
        self.excerpt = str(excerpt)[:MAX_EXCERPT]


class ResponseTooLarge(Exception):
    def __init__(self, size: int) -> None:
        super().__init__(f"response_too_large_{size}")
        self.size = int(size)


def http_call(send: SendFn, method: str, url: str, headers: dict,
              body: bytes = b"") -> tuple[int, str]:
    """One bounded request -> (status, text).  4xx/5xx -> ApiError with
    a bounded excerpt (providers put the useful error in the body)."""
    status, resp_headers, resp_body = send(method, url, headers, body)
    status = int(status)
    if len(resp_body) > MAX_RESPONSE_BYTES:
        raise ResponseTooLarge(len(resp_body))
    text = resp_body.decode("utf-8", errors="replace")
    if status >= 400:
        raise ApiError(status, text[:MAX_EXCERPT])
    return status, text


def aws_call(send: SendFn, method: str, url: str, headers: dict,
             body: bytes, *, access_key: str, secret_key: str,
             region: str, service: str, now: datetime) -> tuple[int, str]:
    signed = sigv4.sign_request(method, url, headers, body,
                                access_key=access_key, secret_key=secret_key,
                                region=region, service=service, now=now)
    return http_call(send, method, url, signed, body)


def bearer_call(send: SendFn, method: str, url: str, headers: dict,
                body: bytes, token: str) -> tuple[int, str]:
    low = {str(k).lower(): str(v) for k, v in headers.items()}
    low["authorization"] = f"Bearer {token}"
    return http_call(send, method, url, low, body)


def parse_json(text: str, *, op: str) -> object:
    """JSON decode with a bound (text already size-capped by http_call;
    this guards pathological nesting cheaply via the decoder itself)."""
    try:
        return json.loads(text)
    except (ValueError, RecursionError) as exc:
        raise ApiError(0, f"{op}: json_parse_error: {exc}"[:MAX_EXCERPT]) from None
