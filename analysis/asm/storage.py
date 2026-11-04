"""T-6.1: cloud-storage discovery (bucket candidates + response class).

Discovery is split so the interesting half is pure:

  * ``bucket_candidates`` -- derive storage hostnames from EXPLICIT name
    tokens (the target's own labels / an org token the caller passed).
    The scanner does not invent company names -- guessing that acme.com
    belongs to "acme-corp" would flood the inventory with noise.  Same
    tokens -> same candidate list, sorted (reproducible).
  * ``classify_storage_response`` -- map (provider, status, body) to a
    posture verdict.  A 403 AccessDenied is NOT "nothing there" (the
    bucket exists but is private -- inventory HIT + posture OK); a
    NoSuchBucket/404 is absence.  Getting this wrong in either
    direction is how scanners end up claiming public buckets they never
    saw.

Probing (HTTPS HEAD/GET to each candidate) runs in the collector with
injected fetch and rate limiting; unreachable providers classify as
skips, never as "bucket absent".
"""
from __future__ import annotations
try:
    from analysis.spans import WINDOW_16384
except ImportError:  # FND-03: standalone, repo root not on path
    import sys as _fnd03_sys
    from pathlib import Path as _fnd03_path
    _fnd03_sys.path.insert(0, str(_fnd03_path(__file__).resolve().parents[2]))
    from analysis.spans import WINDOW_16384

import re
from typing import Iterable

MAX_CANDIDATES = 64
_TOKEN_RE = re.compile(r"[^a-z0-9-]+")

PROVIDERS: tuple[tuple[str, str], ...] = (
    # (provider_id, hostname template with {name})
    ("aws_s3", "{name}.s3.amazonaws.com"),
    ("gcs", "storage.googleapis.com/{name}"),
    ("azure_blob", "{name}.blob.core.windows.net"),
)

_TOKEN_MAX_LEN = 63


def _tokenize(name: str) -> str:
    t = _TOKEN_RE.sub("-", str(name).strip().lower()).strip("-")
    return t[:_TOKEN_MAX_LEN]


def bucket_candidates(tokens: Iterable[str], extra: Iterable[str] = ()) -> list[dict]:
    """Expand name tokens x providers into storage endpoints.

    Empty after sanitizing -> empty list (a token like ``*.`` must not
    become a wildcard probe).  Sorted by (provider, name) so two runs
    emit identical lists; capped at MAX_CANDIDATES (the pre-cap count is
    disclosed by ``candidates_with_stats``).
    """
    names: list[str] = []
    seen: set[str] = set()
    for raw in tuple(tokens) + tuple(extra):
        t = _tokenize(raw)
        # >=2 chars: sanitizing "*.x" yields "x", which is bucket-name
        # noise, not a real candidate
        if len(t) >= 2 and t not in seen:
            seen.add(t)
            names.append(t)
    out: list[dict] = []
    for provider, template in PROVIDERS:
        for n in names:
            if len(out) >= MAX_CANDIDATES:
                break
            url = "https://" + template.format(name=n)
            out.append({"provider": provider, "name": n, "url": url})
    out.sort(key=lambda c: (c["provider"], c["name"]))
    return out


def candidates_with_stats(tokens: Iterable[str],
                          extra: Iterable[str] = ()) -> dict:
    """Candidates + disclosure stats (pre-cap count vs emitted)."""
    names_pre = len({t for x in tuple(tokens) + tuple(extra)
                     if len(t := _tokenize(x)) >= 2})
    cands = bucket_candidates(tokens, extra)
    emitted = len(cands)
    pre = names_pre * len(PROVIDERS)
    return {
        "candidates": cands,
        "stats": {"tokens": names_pre, "candidates": pre,
                  "emitted": emitted,
                  "cap_hit": pre > emitted},
    }


_NOT_FOUND = ("nosuchbucket", "blobnotfound", "404 not found", "not found")
_EXISTS_DENIED = ("accessdenied", "access denied", "forbidden",
                  "credentials not provided", "authenticationrequired")
_PUBLIC_MARK = ("<listbucketresult", "<enumerationresults",
                "<blobs>", "<contents>")


def classify_storage_response(provider: str, status: int,
                              body: str) -> dict | None:
    """Posture verdict for one bucket probe.

    Returns None only when the response says the OBJECT/BUCKET does not
    exist (true negative).  Everything else -- public listing, private-
    denied, odd proxy pages -- yields a verdict row, because the bucket
    EXISTING is the inventory fact and the posture is the finding.
    ``provider`` is part of the record (callers log it); classification
    itself reads only status + body so the same evidence maps to the
    same verdict on every run.
    """
    try:
        code = int(status)
    except (TypeError, ValueError):
        return None
    text = (body or "")[:WINDOW_16384].lower()

    def _has(options) -> bool:
        return any(o in text for o in options)

    if _has(("nosuchbucket", "blobnotfound")):
        if _has(_EXISTS_DENIED):
            # providers sometimes answer denied-with-not-found for private
            # buckets; existence beats the status line
            return {"exists": True, "public": False, "posture": "private",
                    "provider": provider, "evidence": "denied_on_404"}
        return None                          # true absence
    if code == 404 and not _has(_PUBLIC_MARK + _EXISTS_DENIED):
        return None                          # plain 404, no existence evidence
    if code in (401, 403) or _has(_EXISTS_DENIED):
        return {"exists": True, "public": False, "posture": "private",
                "provider": provider, "evidence": f"http_{code}"}
    if 200 <= code < 300:
        listing = _has(_PUBLIC_MARK)
        return {"exists": True, "public": True, "posture": "public",
                "provider": provider,
                "evidence": f"http_{code}+listing_xml" if listing
                else f"http_{code}"}
    if code in (400, 409, 411, 422):
        # provider answered about an existing resource (e.g. wrong verb)
        return {"exists": True, "public": False, "posture": "unknown",
                "provider": provider, "evidence": f"http_{code}"}
    return None
