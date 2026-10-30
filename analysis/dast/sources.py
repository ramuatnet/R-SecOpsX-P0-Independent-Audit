"""T-5.1: file-based target-model sources.

OpenAPI/Swagger, Postman, HAR, HTML, JS, sitemap and robots parsers --
all pure functions over text/dict, all offline, all bounded (untrusted
input: size caps and per-source route caps, with the cap disclosed via
the caller's source status, never a silent truncation).  YAML OpenAPI
needs PyYAML (optional extra, the repo-wide pattern); without it the
source is SKIPPED with reason ``yaml_needs_pyyaml``.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path
from typing import Optional
from urllib.parse import parse_qs, urljoin, urlsplit

from analysis.dast.model import HTTP_METHODS, make_entry

# Resource bounds for untrusted input.
MAX_SOURCE_BYTES = 5 * 1024 * 1024
MAX_ROUTES_PER_SOURCE = 5000
MAX_HTML_FILES = 100
MAX_JS_FILES = 100

_SKIP_DIRS = frozenset({
    ".git", ".hg", ".svn", "node_modules", "dist", "build", "vendor",
    "venv", ".venv", "__pycache__", ".tox", ".mypy_cache", ".pytest_cache",
    "target",
})


@dataclass(frozen=True)
class SourceLimits:
    max_bytes: int = MAX_SOURCE_BYTES
    max_routes_per_source: int = MAX_ROUTES_PER_SOURCE
    max_html_files: int = MAX_HTML_FILES
    max_js_files: int = MAX_JS_FILES


# ---------------------------------------------------------------------------
# Loading (size-capped, JSON or optional-PyYAML)
# ---------------------------------------------------------------------------

def load_document(path: Path,
                  limits: Optional[SourceLimits] = None,
                  ) -> tuple[Optional[dict], Optional[str]]:
    """Read one source document.  Returns ``(doc, skip_reason)``.

    ``doc`` is None exactly when ``skip_reason`` explains why -- callers
    record the reason as the source status; nothing is dropped silently.
    """
    limits = limits or SourceLimits()
    try:
        size = path.stat().st_size
    except OSError:
        return None, "unreadable"
    if size > limits.max_bytes:
        return None, "toobig"
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None, "unreadable"

    if path.suffix.lower() in {".yaml", ".yml"}:
        try:
            import yaml  # type: ignore
        except ImportError:
            return None, "yaml_needs_pyyaml"
        try:
            doc = yaml.safe_load(text)
        except Exception:
            return None, "parse_error"
    else:
        try:
            doc = json.loads(text)
        except Exception:
            return None, "parse_error"
    if not isinstance(doc, dict):
        return None, "parse_error"
    return doc, None


def read_text_capped(path: Path,
                     limits: Optional[SourceLimits] = None) -> Optional[str]:
    limits = limits or SourceLimits()
    try:
        if path.stat().st_size > limits.max_bytes:
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


# ---------------------------------------------------------------------------
# OpenAPI / Swagger 2 + 3
# ---------------------------------------------------------------------------

def _auth_from_security(sec) -> Optional[bool]:
    if sec is None:
        return None
    if sec == [] or sec == {}:
        return False                      # explicit empty: auth optional
    return True


def _op_auth(op: dict, path_item: dict, global_sec) -> Optional[bool]:
    if isinstance(op, dict) and "security" in op:
        return _auth_from_security(op.get("security"))
    if isinstance(path_item, dict) and "security" in path_item:
        return _auth_from_security(path_item.get("security"))
    return _auth_from_security(global_sec)


def _declared_params(path_level, op_level) -> list[dict]:
    """Merge parameter lists; op-level wins on (name, in)."""
    out: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for source in (op_level, path_level):     # op first: higher precedence
        for p in source or []:
            if not isinstance(p, dict):
                continue
            name = str(p.get("name") or "").strip()
            loc = str(p.get("in") or "unknown").lower()
            if not name:
                continue
            key = (name, loc)
            if key in seen:
                continue
            seen.add(key)
            out.append({"name": name, "in": loc})
    return out


def parse_openapi(doc: dict, ref: str,
                  limits: Optional[SourceLimits] = None) -> list[dict]:
    limits = limits or SourceLimits()
    if not isinstance(doc, dict):
        return []
    paths = doc.get("paths")
    if not isinstance(paths, dict):
        return []
    global_sec = doc.get("security")
    entries: list[dict] = []
    for path, item in sorted(paths.items()):
        if not isinstance(item, dict):
            continue
        for method, op in sorted(item.items()):
            if str(method).upper() not in HTTP_METHODS or not isinstance(op, dict):
                continue
            params = _declared_params(item.get("parameters"), op.get("parameters"))
            # OAS3 requestBody: top-level schema properties are body params.
            rb = op.get("requestBody")
            if isinstance(rb, dict):
                content = rb.get("content")
                if isinstance(content, dict):
                    for media in content.values():
                        if not isinstance(media, dict):
                            continue
                        schema = media.get("schema")
                        if isinstance(schema, dict):
                            props = schema.get("properties")
                            if isinstance(props, dict):
                                for pname in sorted(props):
                                    params.append({"name": pname, "in": "body"})
                        break               # first content-type only
            entries.append(make_entry(
                method=method, path=path, kind="openapi", ref=ref,
                params=params,
                auth_required=_op_auth(op, item, global_sec),
            ))
            if len(entries) >= limits.max_routes_per_source:
                return entries
    return entries


# ---------------------------------------------------------------------------
# Postman Collection v2.x
# ---------------------------------------------------------------------------

def _postman_path(url) -> str:
    if isinstance(url, str):
        return url.strip()
    if isinstance(url, dict):
        raw = url.get("raw")
        if isinstance(raw, str) and raw.strip():
            return raw.strip()
        segs = url.get("path")
        if isinstance(segs, list) and segs:
            return "/" + "/".join(str(s) for s in segs)
    return ""


def _postman_query(url) -> list[dict]:
    if isinstance(url, dict):
        q = url.get("query")
        if isinstance(q, list):
            return [{"name": str(x.get("key")), "in": "query"}
                    for x in q if isinstance(x, dict) and x.get("key")]
    return []


def parse_postman(doc: dict, ref: str,
                  limits: Optional[SourceLimits] = None) -> list[dict]:
    limits = limits or SourceLimits()
    entries: list[dict] = []

    def walk(items):
        for it in items or []:
            if not isinstance(it, dict):
                continue
            if "item" in it:
                walk(it.get("item"))
                continue
            req = it.get("request")
            if not isinstance(req, dict):
                continue
            url = req.get("url")
            path = _postman_path(url)
            if not path:
                continue
            entries.append(make_entry(
                method=str(req.get("method") or "GET"), path=path,
                kind="postman", ref=ref, params=_postman_query(url),
            ))
            if len(entries) >= limits.max_routes_per_source:
                return

    if isinstance(doc, dict):
        walk(doc.get("item"))
    return entries


# ---------------------------------------------------------------------------
# HAR 1.2
# ---------------------------------------------------------------------------

def parse_har(doc: dict, ref: str,
              limits: Optional[SourceLimits] = None) -> list[dict]:
    limits = limits or SourceLimits()
    entries: list[dict] = []
    log = doc.get("log") if isinstance(doc, dict) else None
    for ent in (log or {}).get("entries") or []:
        req = ent.get("request") if isinstance(ent, dict) else None
        if not isinstance(req, dict):
            continue
        url = str(req.get("url") or "")
        parts = urlsplit(url)
        path = parts.path or "/"
        params = [{"name": str(q.get("key")), "in": "query"}
                  for q in (req.get("queryString") or [])
                  if isinstance(q, dict) and q.get("key")]
        entries.append(make_entry(
            method=str(req.get("method") or "GET"), path=path,
            kind="har", ref=ref, params=params,
        ))
        if len(entries) >= limits.max_routes_per_source:
            break
    return entries


# ---------------------------------------------------------------------------
# HTML links + forms
# ---------------------------------------------------------------------------

_BAD_SCHEMES = ("mailto:", "javascript:", "data:", "tel:", "about:")
_ASSET_EXT = (".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
              ".woff", ".woff2", ".ttf", ".map")


class _PageParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.forms: list[dict] = []
        self._form: Optional[dict] = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a":
            href = a.get("href")
            if href:
                self.links.append(href.strip())
        elif tag == "script":
            src = a.get("src")              # JS assets carry routes (T-5.1)
            if src:
                self.links.append(src.strip())
        elif tag == "link":
            href = a.get("href") or ""
            rel = (a.get("rel") or "").lower()
            if href and "stylesheet" not in rel:
                self.links.append(href.strip())
        elif tag == "form":
            self._form = {
                "action": (a.get("action") or "").strip(),
                "method": (a.get("method") or "GET").strip().upper(),
                "inputs": [],
            }
            self.forms.append(self._form)
        elif tag == "input" and self._form is not None:
            name = a.get("name")
            if name:
                self._form["inputs"].append(name.strip())

    def handle_endtag(self, tag):
        if tag == "form":
            self._form = None


def _link_ok(href: str) -> bool:
    h = href.strip()
    if not h or h.startswith("#"):
        return False
    if h.lower().startswith(_BAD_SCHEMES):
        return False
    # Binary assets are not routes; JS assets stay (they carry routes).
    return not urlsplit(h).path.lower().endswith(_ASSET_EXT)


def _href_is_local(href: str, ref: str) -> bool:
    """True when ``href`` could belong to the same site as ``ref``.

    Absolute URLs with a foreign host are not this target's routes: they
    stay in the crawler frontier (so scope accounting counts them) but
    never become route entries.  A file-backed ``ref`` (no netloc) has
    no site, so only relative hrefs count.
    """
    parts = urlsplit(href.strip())
    if parts.scheme in {"http", "https"} and parts.netloc:
        ref_parts = urlsplit(ref)
        if not ref_parts.netloc:
            return False
        return parts.netloc.lower() == ref_parts.netloc.lower()
    return True


def parse_html(html: str, ref: str, kind: str = "html",
               limits: Optional[SourceLimits] = None
               ) -> tuple[list[dict], list[str]]:
    """Extract link routes + form routes; return ``(entries, raw_links)``.

    ``raw_links`` feeds the crawler frontier (caller resolves them with
    urljoin); fragments, non-fetchable schemes and binary assets are
    filtered here.  Foreign absolute URLs remain in ``raw_links`` (the
    crawler counts them out-of-scope) but yield no route entry.
    """
    limits = limits or SourceLimits()
    parser = _PageParser()
    try:
        parser.feed(html)
        parser.close()
    except Exception:
        pass                                # tolerate malformed pages
    entries: list[dict] = []
    links = [h for h in parser.links if _link_ok(h)]
    for href in links:
        if len(entries) >= limits.max_routes_per_source:
            break
        if not _href_is_local(href, ref):
            continue
        entries.append(make_entry(
            method="GET", path=urlsplit(href).path or "/", kind=kind, ref=ref,
        ))
    for form in parser.forms:
        if len(entries) >= limits.max_routes_per_source:
            break
        method = form["method"] if form["method"] in HTTP_METHODS else "GET"
        action = form["action"]
        loc = "query" if method == "GET" else "body"
        params = [{"name": n, "in": loc} for n in form["inputs"] if n]
        if urlsplit(action).path == "" and urlsplit(ref).scheme in {"http", "https"}:
            # action="#" / "" / "?x" submits to the page itself (HTML
            # spec); resolve against the page URL so the params land on
            # the RIGHT route (DVWA's vuln pages all use action="#",
            # previously collapsing to "/" and losing the pairing).
            action_path = urlsplit(urljoin(ref, "#")).path or "/"
        else:
            action_path = urlsplit(action).path or "/"
        if _href_is_local(action or "/", ref):
            entries.append(make_entry(
                method=method, path=action_path,
                kind=kind, ref=ref, params=params,
            ))
        if method == "GET" and _link_ok(action) and _href_is_local(action, ref):
            links.append(action)
    return entries, links


# ---------------------------------------------------------------------------
# JS route extraction (static strings only)
# ---------------------------------------------------------------------------

# (?!\s*\+) after the closing quote rejects string concatenation
# (``"/api/u/" + id``) -- only fully static route strings count.
_JS_FETCH = re.compile(
    r"\bfetch\s*\(\s*[`'\"]([^`'\"]+)[`'\"](?!\s*\+)")
_JS_AXIOS = re.compile(
    r"\baxios\s*\.\s*(get|post|put|patch|delete)\s*\(\s*"
    r"[`'\"]([^`'\"]+)[`'\"](?!\s*\+)")
_JS_JQ = re.compile(
    r"\$\.ajax\s*\(\s*\{[^}]{0,400}?url\s*:\s*[`'\"]([^`'\"]+)[`'\"](?!\s*\+)")


def _js_path(raw: str) -> Optional[str]:
    s = raw.strip()
    if not s or "${" in s or "+" in s:
        return None                        # not a static route string
    if s.startswith("http://") or s.startswith("https://"):
        s = urlsplit(s).path or "/"
    if not s.startswith("/"):
        return None                        # relative/ambiguous: skip, disclose
    return s


def parse_js(js: str, ref: str, kind: str = "js",
             limits: Optional[SourceLimits] = None) -> list[dict]:
    limits = limits or SourceLimits()
    entries: list[dict] = []

    def add(method: str, raw: str):
        if len(entries) >= limits.max_routes_per_source:
            return
        path = _js_path(raw)
        if not path:
            return
        parts = urlsplit(path)
        params = [{"name": k, "in": "query"}
                  for k in parse_qs(parts.query)]
        entries.append(make_entry(
            method=method, path=parts.path, kind=kind, ref=ref,
            params=params))

    for m in _JS_FETCH.finditer(js):
        add("GET", m.group(1))
    for m in _JS_AXIOS.finditer(js):
        add(m.group(1), m.group(2))
    for m in _JS_JQ.finditer(js):
        add("GET", m.group(1))
    return entries


# ---------------------------------------------------------------------------
# sitemap.xml + robots.txt
# ---------------------------------------------------------------------------

def parse_sitemap(xml_text: str, ref: str,
                  limits: Optional[SourceLimits] = None) -> list[dict]:
    limits = limits or SourceLimits()
    import xml.etree.ElementTree as ET
    try:
        root = ET.fromstring(xml_text)
    except Exception:
        return []
    entries: list[dict] = []
    for el in root.iter():
        if el.tag.rsplit("}", 1)[-1] == "loc" and el.text:
            entries.append(make_entry(
                method="GET", path=el.text.strip(), kind="sitemap", ref=ref))
            if len(entries) >= limits.max_routes_per_source:
                break
    return entries


def parse_robots(text: str, ref: str,
                 limits: Optional[SourceLimits] = None
                 ) -> tuple[list[dict], list[str], list[str]]:
    """Wildcard-agent rules -> ``(entries, sitemap_urls, disallow_prefixes)``.

    Only ``User-agent: *`` groups apply by default (T-5.3 may refine
    per-agent targeting later).  Allow/Disallow paths become crawl
    candidates -- a disallowed path still EXISTS; the crawler just
    must not fetch it.
    """
    limits = limits or SourceLimits()
    entries: list[dict] = []
    sitemaps: list[str] = []
    disallow: list[str] = []
    current_agents: list[str] = []
    applies = False

    for raw in str(text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        field, _, value = line.partition(":")
        field = field.strip().lower()
        value = value.strip()
        if field == "user-agent":
            current_agents.append(value)
            applies = "*" in current_agents
        elif field in {"allow", "disallow"} and applies and value:
            if value != "/" and len(entries) < limits.max_routes_per_source:
                entries.append(make_entry(
                    method="GET", path=value, kind="robots", ref=ref))
            if field == "disallow":
                disallow.append(value)
        elif field == "sitemap" and value:
            sitemaps.append(value)
    return entries, sitemaps, disallow


# ---------------------------------------------------------------------------
# Detection: which sources exist under a target
# ---------------------------------------------------------------------------

def _classify(name: str) -> Optional[str]:
    n = name.lower()
    if n.endswith(".postman_collection.json") or n.endswith(".postman.json"):
        return "postman"
    if n.endswith(".har"):
        return "har"
    if n == "robots.txt":
        return "robots"
    if n.endswith(".xml") and "sitemap" in n:
        return "sitemap"
    if n.endswith((".json", ".yaml", ".yml")) and (
            "openapi" in n or "swagger" in n):
        return "openapi"
    if n.endswith((".html", ".htm")):
        return "html"
    if n.endswith((".js", ".mjs")) and not n.endswith(".min.js"):
        return "js"
    return None


def detect_source_files(root: Path,
                        limits: Optional[SourceLimits] = None
                        ) -> dict[str, list[Path]]:
    """Classify source files under ``root`` (dir or single file).

    Deterministic order (sorted walk); node_modules and friends pruned;
    HTML/JS capped so a huge tree cannot explode the walk.
    """
    limits = limits or SourceLimits()
    found: dict[str, list[Path]] = {
        "openapi": [], "postman": [], "har": [],
        "sitemap": [], "robots": [], "html": [], "js": [],
    }
    root = Path(root)
    files: list[Path] = []
    if root.is_file():
        files = [root]
    elif root.is_dir():
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = sorted(
                d for d in dirnames if d.lower() not in _SKIP_DIRS)
            for fn in sorted(filenames):
                files.append(Path(dirpath) / fn)
    html_seen = js_seen = 0
    for p in files:
        kind = _classify(p.name)
        if kind is None:
            continue
        if kind == "html":
            html_seen += 1
            if html_seen > limits.max_html_files:
                continue
        elif kind == "js":
            js_seen += 1
            if js_seen > limits.max_js_files:
                continue
        found[kind].append(p)
    return found
