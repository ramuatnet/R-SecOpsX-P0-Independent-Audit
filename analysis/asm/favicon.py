"""T-6.1: favicon / asset correlation.

Two halves:

  * ``extract_icon_href`` -- HTMLParser-based (attribute ORDER
    independent -- ``href`` may come before or after ``rel``, which is
    exactly where regex approaches break), returns the first
    ``rel=icon|shortcut icon|apple-touch-icon`` link.
  * ``favicon_record`` -- turns fetched icon bytes into a correlation
    record: sha256 (identity), Shodan-recipe murmur hash (cross-tool
    lookup), size and mime.  Same bytes => same record on every run.

The fetch is injected; scope matters -- only SAME-ORIGIN icon URLs are
ever fetched, a page pointing at a third-party CDN icon is recorded as
``foreign_icon`` (asset signal, not silently pulled).
"""
from __future__ import annotations

import hashlib
from html.parser import HTMLParser
from typing import Callable
from urllib.parse import urljoin, urlsplit

from analysis.asm.hashing import favicon_hash

MAX_ICON_BYTES = 2 * 1024 * 1024        # ICO/PNG icons; cap the fetch
_ICON_RELS = {"icon", "shortcut", "apple-touch-icon", "apple-touch-icon-precomposed"}

_MIME_BY_EXT = {
    ".ico": "image/x-icon",
    ".png": "image/png",
    ".svg": "image/svg+xml",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".webp": "image/webp",
}


class _IconParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.hrefs: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "link":
            return
        low = {k.lower(): (v or "") for k, v in attrs}
        rels = {r.lower() for r in low.get("rel", "").split()}
        href = low.get("href", "").strip()
        if href and rels & _ICON_RELS:
            self.hrefs.append(href)


def extract_icon_href(html: str) -> str | None:
    """First icon link href in document order (parser, not regex)."""
    parser = _IconParser()
    try:
        parser.feed(html or "")
        parser.close()
    except Exception:                    # noqa: BLE001 - malformed HTML
        return parser.hrefs[0] if parser.hrefs else None
    return parser.hrefs[0] if parser.hrefs else None


def icon_mime(url: str) -> str:
    path = urlsplit(url).path.lower()
    for ext, mime in _MIME_BY_EXT.items():
        if path.endswith(ext):
            return mime
    return "image/x-icon"                # default: the favicon.ico convention


def same_origin(url: str, base: str) -> bool:
    a, b = urlsplit(url), urlsplit(base)
    if not a.scheme and not a.netloc:
        return True                       # still relative after urljoin
    default_port = {"http": 80, "https": 443}
    pa = a.port or default_port.get(a.scheme)
    pb = b.port or default_port.get(b.scheme)
    return (a.scheme, a.hostname, pa) == (b.scheme, b.hostname, pb)


FetchFn = Callable[[str], bytes]


def favicon_record(page_url: str, html: str, fetch: FetchFn) -> dict:
    """Resolve the page's icon, fetch (same-origin only) and hash it.

    Always returns a record -- absence is a value (``status``), never an
    exception: a site without an icon is normal inventory output.
    """
    href = extract_icon_href(html)
    icon_url = urljoin(page_url, href) if href else urljoin(page_url, "/favicon.ico")
    base = {
        "icon_url": icon_url,
        "sha256": None,
        "murmur32": None,
        "mime": icon_mime(icon_url),
        "size": 0,
        # source = WHERE the icon URL came from; status = fetch outcome.
        # Kept as two fields so a hashed fallback icon is still honest
        # about not having been declared by the page.
        "source": "linked" if href else "fallback",
        "status": "pending",
    }
    if not same_origin(icon_url, page_url):
        base["status"] = "foreign_icon"
        return base
    try:
        data = fetch(icon_url)
    except Exception as exc:             # noqa: BLE001 - disclose, never raise
        base["status"] = f"fetch_failed_{type(exc).__name__}"
        return base
    if not data:
        base["status"] = "empty"
        return base
    if len(data) > MAX_ICON_BYTES:
        base["status"] = "toobig"
        return base
    base["sha256"] = hashlib.sha256(data).hexdigest()
    base["murmur32"] = favicon_hash(data, base["mime"])
    base["size"] = len(data)
    base["status"] = "hashed"
    return base
