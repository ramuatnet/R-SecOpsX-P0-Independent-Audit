"""T-6.1: Certificate Transparency subdomain enumeration.

``crt.sh`` is the conventional free CT search endpoint; the value here is
the PARSE, which is pure and offline-testable -- the fetch is one
injectable callable (like every other network edge in this package), so
the gate "inventory reproducible run-to-run" can be proven from saved
responses with no network at all.

Passive DNS has no default provider: it needs a paid API key, so it is a
declared connector slot (``collect`` records a ``passive_dns`` skip) --
inventing an offline passive-DNS source would be a lie.  A provider can
be wired later by handing ``parse``-style results to ``merge_names``.
Bounds: response byte cap, per-name cap, wildcard names dropped (CT logs
of ``*.example.com`` must not become thousands of phantom hosts).
"""
from __future__ import annotations

import json
from typing import Callable, Iterable

MAX_CT_RESPONSE_BYTES = 8 * 1024 * 1024   # crt.sh pages can be large
MAX_CT_NAMES = 10_000


class CtParseError(ValueError):
    """Malformed CT payload (bad JSON, wrong shape)."""


def parse_crtsh(payload: bytes | str, domain: str,
                limit: int = MAX_CT_NAMES) -> dict:
    """Extract unique subdomain names of ``domain`` from a crt.sh JSON
    response (a list of rows with ``name_value`` holding newline-separated
    names, one row per certificate entry).

    Pure: bytes in -> names out, sorted, wildcard entries dropped and
    counted (disclosed, never silently expanded), same-domain filter so a
    search overshoot cannot smuggle foreign hosts into the inventory.
    """
    if isinstance(payload, bytes):
        if len(payload) > MAX_CT_RESPONSE_BYTES:
            raise CtParseError("CT response exceeds size bound")
        text = payload.decode("utf-8", "replace")
    else:
        text = str(payload)
        if len(text.encode("utf-8", "replace")) > MAX_CT_RESPONSE_BYTES:
            raise CtParseError("CT response exceeds size bound")
    try:
        rows = json.loads(text)
    except json.JSONDecodeError as exc:
        raise CtParseError("CT response is not valid JSON") from exc
    if not isinstance(rows, list):
        raise CtParseError("CT response is not a list of rows")
    suffix = "." + domain.lower().lstrip(".")
    names: set[str] = set()
    wildcards = 0
    foreign = 0
    truncated = False
    for row in rows:
        if not isinstance(row, dict):
            continue
        raw = row.get("name_value")
        if not isinstance(raw, str):
            continue
        for piece in raw.splitlines():
            n = piece.strip().lower().rstrip(".")
            if not n:
                continue
            if n.startswith("*."):
                wildcards += 1
                continue
            if n != domain.lower() and not n.endswith(suffix):
                foreign += 1
                continue
            if len(names) >= limit:
                truncated = True
                continue
            names.add(n)
    return {
        "domain": domain,
        "names": sorted(names),
        "stats": {"rows": len(rows), "found": len(names),
                  "wildcards_dropped": wildcards, "foreign_dropped": foreign,
                  "name_cap": limit, "name_cap_hit": truncated},
    }


FetchFn = Callable[[str], bytes]          # url -> body (throws on failure)


def fetch_crtsh(domain: str, fetch: FetchFn,
                base_url: str = "https://crt.sh/?q=%25.{domain}&output=json",
                limit: int = MAX_CT_NAMES) -> dict:
    """Fetch + parse in one step.  All network failure modes (DNS down,
    TLS interception, 5xx) surface as a raised exception to the caller --
    an unreachable CT log is a skip at the inventory layer, never an
    empty 'no subdomains exist' result."""
    url = base_url.format(domain=domain)
    return parse_crtsh(fetch(url), domain, limit=limit)


def merge_names(*groups: Iterable[str]) -> list[str]:
    """Union of name groups, sorted and deduped -- the merge point where
    brute-force, CT and (future) passive-DNS sources meet.  Sorts so the
    inventory is byte-identical run-to-run regardless of source order."""
    out: set[str] = set()
    for g in groups:
        for n in g:
            s = str(n).strip().lower().rstrip(".")
            if s:
                out.add(s)
    return sorted(out)
