"""T-5.1: the opt-in, scope-bounded HTML/JS crawler.

Discovery only -- GET/HEAD class requests, never a state-changing verb
(T-5.3 owns attack payloads; this module finds endpoints).  Safety
posture, all testable without sockets via the injected ``fetch``:

* opt-in: no crawl unless a base URL is handed over;
* same-origin scope by default -- out-of-scope URLs are counted, never
  fetched (no silent drop);
* robots.txt Disallow respected;
* rate limit between requests, backoff hooks left to T-5.3;
* hard page/depth budget with ``truncated`` disclosure;
* deterministic BFS (sorted frontier) -- same site, same model bytes.
"""
from __future__ import annotations
try:
    from analysis.spans import WINDOW_1, WINDOW_TOP_5
except ImportError:  # FND-03: standalone, repo root not on path
    import sys as _fnd03_sys
    from pathlib import Path as _fnd03_path
    _fnd03_sys.path.insert(0, str(_fnd03_path(__file__).resolve().parents[2]))
    from analysis.spans import WINDOW_1, WINDOW_TOP_5

import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Callable, Optional
from urllib.parse import urljoin, urlsplit

from analysis.dast.model import make_entry
from analysis.dast.sources import (
    MAX_SOURCE_BYTES,
    parse_html,
    parse_js,
    parse_robots,
    parse_sitemap,
)

DEFAULT_MAX_PAGES = 50
DEFAULT_MAX_DEPTH = 3
DEFAULT_RATE_LIMIT_S = 0.5
DEFAULT_USER_AGENT = "R-SecOpsX-DAST/0.1 (+recon; safe-mode GET only)"


@dataclass(frozen=True)
class CrawlConfig:
    base_url: str
    max_pages: int = DEFAULT_MAX_PAGES
    max_depth: int = DEFAULT_MAX_DEPTH
    rate_limit_s: float = DEFAULT_RATE_LIMIT_S
    same_origin_only: bool = True
    respect_robots: bool = True
    timeout_s: float = 10.0
    user_agent: str = DEFAULT_USER_AGENT
    # T-5.2: headers from an AuthSession (e.g. Authorization/Cookie) attached
    # to every request.  When None the fetch keeps its original 3-arg call
    # shape, so unauthenticated fetches (and their tests) are unchanged.
    auth_headers: Optional[dict] = None
    # T-5.5: path prefixes that are NEVER fetched (an authenticated crawl
    # that follows logout.php destroys its own session -- disclosed and
    # counted in the report's ``excluded`` list).
    exclude_paths: tuple = ()


@dataclass(frozen=True)
class FetchResponse:
    url: str
    status: int
    headers: dict
    body: str


def default_fetch(url: str, timeout_s: float, user_agent: str,
                  headers: Optional[dict] = None) -> FetchResponse:
    """GET one URL with stdlib urllib (the repo's offline-optional pattern).

    Raises on transport failure; the crawler records the error and moves
    on.  Body is capped so a hostile endpoint cannot exhaust memory.
    ``headers`` (T-5.5) carries e.g. an authenticated crawl's Cookie; the
    original 3-arg call shape stays valid for unauthenticated crawls.
    """
    hdrs = {"User-Agent": user_agent, "Accept": "*/*"}
    hdrs.update({str(k): str(v) for k, v in (headers or {}).items()})
    req = urllib.request.Request(
        url,
        headers=hdrs,
        method="GET",
    )
    with urllib.request.urlopen(req, timeout=timeout_s) as resp:
        body = resp.read(MAX_SOURCE_BYTES).decode("utf-8", "replace")
        headers = {str(k).lower(): str(v) for k, v in resp.headers.items()}
        return FetchResponse(url=resp.geturl(), status=resp.status,
                             headers=headers, body=body)


def _origin(url: str) -> tuple[str, str, int]:
    parts = urlsplit(url)
    port = parts.port or (443 if parts.scheme == "https" else 80)
    return (parts.scheme.lower(), (parts.hostname or "").lower(), port)


def _same_origin(url: str, origin: tuple[str, str, int]) -> bool:
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"}:
        return False
    scheme, host, port = origin
    # Scheme-flexible on the SAME host+port (http<->https upgrades are
    # still the user's own target), but any other host is out.
    return (parts.hostname or "").lower() == host and (
        parts.port or (443 if parts.scheme == "https" else 80)) == port


def _robots_blocked(path: str, disallow: list[str]) -> bool:
    for prefix in disallow:
        if prefix and path.startswith(prefix):
            return True
    return False


def _excluded(path: str, exclude_paths: tuple) -> bool:
    for prefix in exclude_paths:
        if prefix and path.startswith(prefix):
            return True
    return False


def _canonical(url: str) -> str:
    parts = urlsplit(url)
    return parts._replace(fragment="").geturl()


def crawl(config: CrawlConfig,
          fetch: Optional[Callable[..., FetchResponse]] = None,
          sleep: Callable[[float], None] = time.sleep) -> dict:
    """BFS-crawl from ``base_url``.  Returns the crawl report:

    ``routes``   route-model entries (kind ``crawl``);
    ``pages``    HTML pages successfully fetched, BFS order;
    ``out_of_scope`` / ``blocked_by_robots`` / ``excluded`` / ``errors``
    / ``truncated``.
    """
    fetch = fetch or default_fetch
    origin = _origin(config.base_url)
    routes: list[dict] = []
    pages: list[str] = []
    out_of_scope: list[str] = []
    blocked: list[str] = []
    excluded: list[str] = []
    errors: list[dict] = []
    disallow: list[str] = []
    robots_sitemaps: list[str] = []
    fetched = 0            # page/asset budget (max_pages)
    requests_made = 0      # every HTTP request, for the rate limit
    truncated = False

    def _throttle():
        nonlocal requests_made
        if config.rate_limit_s > 0 and requests_made > 0:
            sleep(config.rate_limit_s)
        requests_made += 1

    def _do_fetch(url: str) -> FetchResponse:
        if config.auth_headers:
            return fetch(url, config.timeout_s, config.user_agent,
                         headers=dict(config.auth_headers))
        return fetch(url, config.timeout_s, config.user_agent)

    def _try_sitemap(url: str):
        # Recon like robots: rate-limited, but a bounded side channel --
        # at most 5 sitemap fetches, never consuming the page budget.
        _throttle()
        try:
            resp = _do_fetch(url)
        except Exception as exc:               # noqa: BLE001 - disclose, continue
            errors.append({"url": url, "reason": type(exc).__name__})
            return
        if resp.status >= 400:
            errors.append({"url": url, "reason": f"http_{resp.status}"})
            return
        routes.extend(parse_sitemap(resp.body, url))

    # --- robots.txt (recon step, not part of the page budget) -------------
    if config.respect_robots:
        robots_url = urljoin(config.base_url, "/robots.txt")
        _throttle()
        try:
            resp = _do_fetch(robots_url)
            if resp.status < 400:
                _entries, robots_sitemaps, disallow = parse_robots(
                    resp.body, robots_url)
        except Exception as exc:               # noqa: BLE001
            errors.append({"url": robots_url, "reason": type(exc).__name__})
        for sm in robots_sitemaps[:WINDOW_TOP_5]:
            _try_sitemap(sm)

    # --- page frontier ----------------------------------------------------
    frontier: list[tuple[str, int]] = [(config.base_url, 0)]
    seen = {_canonical(config.base_url)}
    while frontier:
        if fetched >= config.max_pages:
            truncated = True
            break
        frontier.sort(key=lambda x: x[0])      # deterministic BFS order
        url, depth = frontier.pop(0)
        url = _canonical(url)
        parts = urlsplit(url)
        if parts.scheme not in {"http", "https"}:
            continue
        if config.same_origin_only and not _same_origin(url, origin):
            out_of_scope.append(url)
            continue
        if _excluded(parts.path, config.exclude_paths):
            excluded.append(url)
            continue
        if _robots_blocked(parts.path, disallow):
            blocked.append(url)
            continue
        _throttle()
        fetched += 1
        try:
            resp = _do_fetch(url)
        except Exception as exc:               # noqa: BLE001
            errors.append({"url": url, "reason": type(exc).__name__})
            continue
        if resp.status >= 400:
            errors.append({"url": url, "reason": f"http_{resp.status}"})
            continue

        ctype = str(resp.headers.get("content-type", "")).lower()
        is_js = ("javascript" in ctype
                 or url.lower().endswith((".js", ".mjs")))
        is_html = "html" in ctype or (
            not is_js and resp.body.lstrip()[:WINDOW_1] == "<")

        if is_js:
            for e in parse_js(resp.body, url, kind="crawl"):
                routes.append(e)
            continue

        if not is_html:
            continue

        pages.append(url)
        path = parts.path or "/"
        routes.append(make_entry(method="GET", path=path, kind="crawl",
                                 ref=url))
        entries, links = parse_html(resp.body, url, kind="crawl")
        routes.extend(entries)

        for href in links:
            absu = _canonical(urljoin(url, href))
            if absu in seen:
                continue
            if absu.lower().endswith((".js", ".mjs")):
                # Script asset: fetch immediately (GET), extract routes.
                seen.add(absu)
                if fetched >= config.max_pages:
                    truncated = True
                    break
                if config.same_origin_only and not _same_origin(absu, origin):
                    out_of_scope.append(absu)
                    continue
                if _excluded(urlsplit(absu).path, config.exclude_paths):
                    excluded.append(absu)
                    continue
                if _robots_blocked(urlsplit(absu).path, disallow):
                    blocked.append(absu)
                    continue
                _throttle()
                fetched += 1
                try:
                    js_resp = _do_fetch(absu)
                    if js_resp.status < 400:
                        for e in parse_js(js_resp.body, absu, kind="crawl"):
                            routes.append(e)
                except Exception as exc:       # noqa: BLE001
                    errors.append({"url": absu, "reason": type(exc).__name__})
                continue
            if depth + 1 > config.max_depth:
                continue
            seen.add(absu)
            frontier.append((absu, depth + 1))

    return {
        "routes": routes,
        "pages": pages,
        "out_of_scope": sorted(set(out_of_scope)),
        "blocked_by_robots": sorted(set(blocked)),
        "excluded": sorted(set(excluded)),
        "errors": errors,
        "truncated": truncated,
        "robots": {"disallow": disallow, "sitemaps": robots_sitemaps},
    }
