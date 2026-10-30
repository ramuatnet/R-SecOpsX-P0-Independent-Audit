"""T-5.1: build the merged DAST+SAST target model for one target.

File sources (OpenAPI/Swagger, Postman, HAR, HTML, JS, sitemap, robots)
are auto-detected and parsed offline.  A live crawl is strictly opt-in
(``--crawl URL`` / ``crawl_url=``).  The SAST route model comes from
``scanner.apibom.generate_apibom`` -- the same walk main.py uses -- so
the merge is with the real in-product route inventory, not a re-implementation.

Every input yields a source-status row (``parsed`` / ``error:...`` /
``skipped:...``); nothing is dropped silently.  The envelope is new,
additive product surface: no finding rows, no parity impact.
"""
from __future__ import annotations

import argparse
import json
from dataclasses import replace
from pathlib import Path
from typing import Callable, Optional
from urllib.parse import urlsplit

from analysis.dast.crawler import CrawlConfig, FetchResponse, crawl
from analysis.dast.model import MODEL_SCHEMA, merge_with_sast
from analysis.dast.sources import (
    SourceLimits,
    detect_source_files,
    load_document,
    parse_har,
    parse_html,
    parse_js,
    parse_openapi,
    parse_postman,
    parse_robots,
    parse_sitemap,
    read_text_capped,
)
from scanner.apibom import generate_apibom


def _rel(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.name


def _parse_file_source(kind: str, path: Path, limits: SourceLimits
                       ) -> tuple[list[dict], str]:
    """Parse one detected file.  Returns ``(entries, status)``."""
    if kind in {"openapi", "postman", "har"}:
        doc, reason = load_document(path, limits)
        if doc is None:
            return [], f"error:{reason}"
        parser = {"openapi": parse_openapi, "postman": parse_postman,
                  "har": parse_har}[kind]
        return parser(doc, path.name, limits=limits), "parsed"

    text = read_text_capped(path, limits)
    if text is None:
        return [], "error:toobig"
    if kind == "sitemap":
        return parse_sitemap(text, path.name, limits=limits), "parsed"
    if kind == "robots":
        entries, _sitemaps, _disallow = parse_robots(
            text, path.name, limits=limits)
        return entries, "parsed"
    if kind == "html":
        entries, _links = parse_html(text, path.name, kind="html",
                                     limits=limits)
        return entries, "parsed"
    if kind == "js":
        return parse_js(text, path.name, kind="js", limits=limits), "parsed"
    return [], f"error:unknown_kind:{kind}"


def build_target_model(target, *,
                       crawl_url: Optional[str] = None,
                       fetch: Optional[Callable[..., FetchResponse]] = None,
                       sleep: Optional[Callable[[float], None]] = None,
                       limits: Optional[SourceLimits] = None,
                       crawl_auth_headers: Optional[dict] = None,
                       crawl_respect_robots: bool = True,
                       crawl_exclude: tuple = ()) -> dict:
    """Auto-detect sources under ``target``, optionally crawl, merge SAST.

    ``crawl_auth_headers`` (T-5.5) attaches e.g. a session Cookie to every
    crawl fetch; when None the crawl keeps its original unauthenticated
    shape (T-5.1 contract, pinned by test).  ``crawl_respect_robots=False``
    is the authorized-testing opt-out (some deliberately-vulnerable apps
    ship ``Disallow: /``); the default stays robots-aware.
    ``crawl_exclude`` (T-5.5) is a tuple of path prefixes the crawler
    never fetches -- an authenticated crawl that follows ``/logout.php``
    destroys its own session; excluded URLs land in the crawl report's
    ``excluded`` list (disclosed, never silent).
    """
    limits = limits or SourceLimits()
    root = Path(target)
    if root.is_file():
        root = root.parent
    source_status: list[dict] = []
    entries: list[dict] = []

    detected = detect_source_files(Path(target), limits)
    for kind in sorted(detected):
        for path in detected[kind]:
            parsed, status = _parse_file_source(kind, path, limits)
            entries.extend(parsed)
            source_status.append({
                "kind": kind,
                "ref": _rel(path, root),
                "status": status,
                "routes_emitted": len(parsed),
            })

    crawl_stats = None
    if crawl_url:
        kwargs = {}
        if fetch is not None:
            kwargs["fetch"] = fetch
        if sleep is not None:
            kwargs["sleep"] = sleep
        cfg = CrawlConfig(base_url=crawl_url,
                          respect_robots=bool(crawl_respect_robots))
        if crawl_auth_headers:
            cfg = replace(cfg, auth_headers=dict(crawl_auth_headers))
        if crawl_exclude:
            cfg = replace(cfg, exclude_paths=tuple(crawl_exclude))
        result = crawl(cfg, **kwargs)
        entries.extend(result["routes"])
        source_status.append({
            "kind": "crawl",
            "ref": crawl_url,
            "status": "parsed",
            "routes_emitted": len(result["routes"]),
        })
        crawl_stats = {
            "pages": result["pages"],
            "out_of_scope": result["out_of_scope"],
            "blocked_by_robots": result["blocked_by_robots"],
            "excluded": result["excluded"],
            "errors": result["errors"],
            "truncated": result["truncated"],
        }

    apibom_items = generate_apibom(str(target))
    routes, sast_count, intersection = merge_with_sast(entries, apibom_items)

    return {
        "schema": MODEL_SCHEMA,
        "routes": routes,
        "sources": source_status,
        "stats": {
            "routes": len(routes),
            "sources_parsed": sum(
                1 for s in source_status if s["status"].startswith("parsed")),
            "sources_skipped": sum(
                1 for s in source_status if not s["status"].startswith("parsed")),
            "sast_routes": sast_count,
            "intersection": intersection,
            "crawl": crawl_stats,
        },
    }


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m analysis.dast.target_model",
        description="Build the merged DAST+SAST route/method/param model.")
    parser.add_argument("target", help="directory (or file) to model")
    parser.add_argument("--crawl", metavar="URL", default=None,
                        help="opt-in live crawl base URL (off by default)")
    parser.add_argument("--out", default=None,
                        help="write the model JSON here (default: stdout)")
    args = parser.parse_args(argv)

    model = build_target_model(args.target, crawl_url=args.crawl)
    text = json.dumps(model, indent=2)
    if args.out:
        Path(args.out).write_text(text + "\n", encoding="utf-8")
        stats = model["stats"]
        print(f"[dast-target-model] routes={stats['routes']} "
              f"parsed={stats['sources_parsed']} "
              f"skipped={stats['sources_skipped']} "
              f"sast={stats['sast_routes']} "
              f"intersection={stats['intersection']} -> {args.out}")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
