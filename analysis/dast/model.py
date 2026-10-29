"""T-5.1: the normalized DAST route/method/param model.

Every producer (OpenAPI, Postman, HAR, HTML, JS, sitemap, robots, the
live crawler, and the SAST API-BOM) emits *entries* in the same shape;
``merge_entries`` unions them by route key and ``finalize`` stamps the
envelope fields.  Path-parameter syntax differs per framework
(``/u/<id>``, ``/u/:id``, ``/u/{id}``, Postman ``{{var}}``) -- all of it
canonicalizes to ``{name}`` so a SAST route and a crawled route for the
same endpoint merge into ONE entry instead of colliding as two.
"""
from __future__ import annotations

import re
from typing import Iterable, Optional
from urllib.parse import urlsplit

MODEL_SCHEMA = "rsecopsx.dast_target_model/v1"

HTTP_METHODS = frozenset(
    {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
)

PARAM_LOCATIONS = frozenset({"path", "query", "header", "body", "cookie", "unknown"})

# One token per param syntax: <name> (Flask/Spring), {name} (FastAPI/Express
# OpenAPI), :name (Express/Rails).
_PARAM_TOKEN = re.compile(r"<([^<>]+)>|\{([^{}]+)\}|:([A-Za-z_]\w*)")


def normalize_path(path: str) -> str:
    """Canonical route path: no query/fragment, ``{name}`` params, leading ``/``.

    Absolute URLs (HAR/Postman/sitemap often carry them) reduce to their
    path.  ``{{var}}`` (Postman client variables) becomes ``{var}``; a
    *leading* ``{{hostVar}}`` is conventionally the base-URL variable and
    is dropped so ``{{baseUrl}}/users/:id`` -> ``/users/{id}``.
    """
    p = str(path or "").strip()
    if p.lower().startswith(("http://", "https://")):
        p = urlsplit(p).path or "/"
    p = p.split("?", 1)[0].split("#", 1)[0]
    p = re.sub(r"^\{\{[^}]+\}\}", "", p)          # leading base-url variable
    p = re.sub(r"\{\{([^{}]+)\}\}", r"{\1}", p)   # {{var}} -> {var}

    def _sub(m: re.Match) -> str:
        name = next(g for g in m.groups() if g)
        return "{" + name + "}"

    p = _PARAM_TOKEN.sub(_sub, p)
    if not p.startswith("/"):
        p = "/" + p
    if len(p) > 1:
        p = p.rstrip("/")
    return p


def route_key(method: str, path: str) -> str:
    return f"{str(method).upper()} {normalize_path(path)}"


def param_name(token: str) -> str:
    """Strip any framework's param decoration down to the bare name."""
    t = str(token or "").strip()
    m = _PARAM_TOKEN.search(t)
    if m:
        return next(g for g in m.groups() if g)
    return t.strip("{}<>:")


def _clean_params(params: Optional[list], path: str) -> list[dict]:
    """Normalize, dedupe, sort; synthesize undeclared path-template params.

    A route like ``/files/{fileId}`` whose producer declared no ``fileId``
    parameter still has one -- T-5.3 payload building needs the name.
    """
    out: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for p in params or []:
        if not isinstance(p, dict):
            continue
        name = str(p.get("name") or "").strip()
        if not name:
            continue
        loc = str(p.get("in") or "unknown").lower()
        if loc == "formdata":          # Swagger-2 formData is a body upload
            loc = "body"
        if loc not in PARAM_LOCATIONS:
            loc = "unknown"
        key = (loc, name)
        if key in seen:
            continue
        seen.add(key)
        out.append({"name": name, "in": loc})
    for name in re.findall(r"\{([^{}]+)\}", path):
        key = ("path", name)
        if key not in seen:
            seen.add(key)
            out.append({"name": name, "in": "path"})
    out.sort(key=lambda p: (p["in"], p["name"]))
    return out


def make_entry(*, method: str, path: str, kind: str, ref: str,
               params: Optional[list] = None, file: Optional[str] = None,
               line: int = 0, auth_required: Optional[bool] = None,
               evidence: str = "") -> dict:
    """One producer's claim about one (method, path) endpoint."""
    m = str(method).upper()
    p = normalize_path(path)
    return {
        "route_key": f"{m} {p}",
        "method": m,
        "path": p,
        "params": _clean_params(params, p),
        "provenance": [{
            "kind": str(kind),
            "ref": str(ref or ""),
            "file": file,
            "line": int(line or 0),
            "auth_required": auth_required,
            "evidence": str(evidence or ""),
        }],
    }


def merge_entries(entries: Iterable[dict]) -> list[dict]:
    """Union entries by route key: params merge, provenance appends."""
    merged: dict[str, dict] = {}
    for e in entries:
        key = e["route_key"]
        if key not in merged:
            merged[key] = {
                "route_key": key,
                "method": e["method"],
                "path": e["path"],
                "params": list(e["params"]),
                "provenance": list(e["provenance"]),
            }
            continue
        cur = merged[key]
        have = {(p["in"], p["name"]) for p in cur["params"]}
        for p in e["params"]:
            if (p["in"], p["name"]) not in have:
                have.add((p["in"], p["name"]))
                cur["params"].append(p)
        cur["params"].sort(key=lambda p: (p["in"], p["name"]))
        cur["provenance"].extend(e["provenance"])
    return [finalize(v) for v in merged.values()]


def finalize(entry: dict) -> dict:
    """Stamp the merged envelope fields (sources union, auth resolution)."""
    auths = [p.get("auth_required") for p in entry["provenance"]]
    if any(a is True for a in auths):
        auth: Optional[bool] = True
    elif any(a is None for a in auths):
        auth = None                      # unknown beats "not observed"
    elif any(a is False for a in auths):
        auth = False
    else:
        auth = None
    return {
        "route_key": entry["route_key"],
        "method": entry["method"],
        "path": entry["path"],
        "params": entry["params"],
        "sources": sorted({p["kind"] for p in entry["provenance"]}),
        "auth_required": auth,
        "provenance": entry["provenance"],
    }


def merge_with_sast(entries: list[dict], apibom_items: Optional[list],
                    ) -> tuple[list[dict], int, int]:
    """Merge DAST entries with the SAST route model (scanner.apibom).

    Returns ``(routes, sast_route_count, intersection)`` where
    intersection counts route keys present in BOTH worlds -- the
    high-confidence crawl targets for T-5.3.
    """
    dast_keys = {e["route_key"] for e in entries}
    sast_entries: list[dict] = []
    for item in apibom_items or []:
        route = str(item.get("route") or "")
        if not route:
            continue
        methods = [str(m).upper() for m in (item.get("methods") or [])]
        good = [m for m in methods if m in HTTP_METHODS]
        if not good:
            continue                      # UNKNOWN methods carry no endpoint
        params = [{"name": param_name(tok), "in": "path"}
                  for tok in (item.get("route_params") or []) if tok]
        auth = True if item.get("auth_hint") == "AUTH_HINT_PRESENT" else None
        for m in good:
            sast_entries.append(make_entry(
                method=m, path=route, kind="sast_apibom",
                ref=str(item.get("file") or ""),
                params=params,
                file=str(item.get("file") or "") or None,
                line=int(item.get("line") or 0),
                auth_required=auth,
                evidence=str(item.get("evidence") or ""),
            ))
    sast_keys = {e["route_key"] for e in sast_entries}
    routes = merge_entries(list(entries) + sast_entries)
    routes.sort(key=lambda r: r["route_key"])
    return routes, len(sast_keys), len(dast_keys & sast_keys)
