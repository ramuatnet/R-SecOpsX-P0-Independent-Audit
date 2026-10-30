"""T-6.1: technology fingerprinting from a single HTTP response.

Signature matching is PURE (headers + body in, tech list out) so it is
offline-testable; the fetch lives in the collector.  Signatures are
high-signal, low-volume on purpose: server/X-Powered-By headers, framework
cookies, generator metas and a few body path markers.  This is NOT a
Wappalyzer replacement -- breadth claims we cannot back would turn the
inventory into guesswork.  Every match records which SIGNATURE fired
(evidence = signature id + matched token), never the raw body.

Body reads are capped (``MAX_BODY_BYTES``) -- fingerprinting must not
pull an unbounded response into memory.
"""
from __future__ import annotations

import re
from typing import Iterable

MAX_BODY_BYTES = 256 * 1024
MAX_EVIDENCE = 80

# (signature_id, kind, target, pattern, tech_name)
#   kind: header | cookie | meta | body
SIGNATURES: tuple[tuple[str, str, str, str, str], ...] = (
    # server software
    ("srv_apache", "header", "server", r"\bapache\b", "Apache httpd"),
    ("srv_nginx", "header", "server", r"\bnginx\b", "nginx"),
    ("srv_iis", "header", "server", r"\biis\b|microsoft-iis", "Microsoft IIS"),
    ("srv_gunicorn", "header", "server", r"gunicorn", "gunicorn"),
    ("srv_werkzeug", "header", "server", r"werkzeug", "Werkzeug"),
    ("srv_caddy", "header", "server", r"\bcaddy\b", "Caddy"),
    ("srv_lighttpd", "header", "server", r"lighttpd", "lighttpd"),
    ("srv_tomcat", "header", "server", r"tomcat", "Apache Tomcat"),
    ("srv_jetty", "header", "server", r"jetty", "Jetty"),
    ("srv_openresty", "header", "server", r"openresty", "OpenResty"),
    # language / framework headers
    ("xph_php", "header", "x-powered-by", r"php", "PHP"),
    ("xph_aspnet", "header", "x-powered-by", r"asp\.net", "ASP.NET"),
    ("xph_express", "header", "x-powered-by", r"express", "Express"),
    ("xgen_wordpress", "header", "x-generator", r"wordpress", "WordPress"),
    ("xdrupal_cache", "header", "x-drupal-cache", r".", "Drupal"),
    # framework cookies
    ("ck_jsession", "cookie", "jsessionid", r".", "Java Servlet"),
    ("ck_php", "cookie", "phpsessid", r".", "PHP"),
    ("ck_aspnet", "cookie", "asp.net_sessionid", r".", "ASP.NET"),
    ("ck_django", "cookie", "csrftoken", r".", "Django"),
    ("ck_rails", "cookie", "_session", r".", "Ruby on Rails"),
    ("ck_express", "cookie", "connect.sid", r".", "Express/Node"),
    # generator meta
    ("meta_wordpress", "meta", "generator", r"wordpress", "WordPress"),
    ("meta_drupal", "meta", "generator", r"drupal", "Drupal"),
    ("meta_joomla", "meta", "generator", r"joomla", "Joomla"),
    ("meta_django", "meta", "generator", r"django", "Django"),
    # generic: report the generator string itself as the tech claim
    ("meta_generator", "meta", "generator", r".+", None),
    # body path/markers
    ("bdy_wp", "body", "text", r"/wp-content/|/wp-includes/", "WordPress"),
    ("bdy_drupal", "body", "text", r"/sites/default/|/sites/all/", "Drupal"),
    ("bdy_joomla", "body", "text", r"/media/jui/|com_content", "Joomla"),
    ("bdy_next", "body", "text", r"__NEXT_DATA__", "Next.js"),
    ("bdy_nuxt", "body", "text", r"__nuxt__|window\.__NUXT__", "Nuxt"),
    ("bdy_angular", "body", "text", r"ng-version=", "Angular"),
    ("bdy_react", "body", "text", r"data-reactroot|__REACT_DEVTOOLS", "React"),
    ("bdy_rails", "body", "text", r"csrf-param|csrf-token", "Ruby on Rails"),
    ("bdy_spring", "body", "text", r"Whitelabel Error Page|org\.springframework",
     "Spring"),
    ("bdy_tomcat", "body", "text", r"Apache Tomcat/\d|tomcat\.css", "Tomcat"),
    ("bdy_gin", "body", "text", r"gin\.debug", "Gin"),
    ("bdy_flask", "body", "text", r"Werkzeug|Flask", "Werkzeug/Flask"),
)

_META_RE = re.compile(
    r"<meta[^>]+name=[\"']?generator[\"']?[^>]+content=[\"']([^\"']+)",
    re.I)
_META_RE_SWAP = re.compile(
    r"<meta[^>]+content=[\"']([^\"']+)[\"'][^>]+name=[\"']?generator",
    re.I)


def _cookie_map(headers: dict) -> dict[str, str]:
    raw = headers.get("set-cookie") or headers.get("Set-Cookie") or ""
    if isinstance(raw, (list, tuple)):
        raw = "; ".join(str(x) for x in raw)
    out: dict[str, str] = {}
    for chunk in str(raw).split(","):
        name = chunk.split("=", 1)[0].strip().lower()
        if name:
            out.setdefault(name, chunk.strip())
    return out


def _generator_meta(body: str) -> str | None:
    m = _META_RE.search(body) or _META_RE_SWAP.search(body)
    return m.group(1).strip() if m else None


def fingerprint(headers: dict, body: str,
                extra_signatures: Iterable[tuple] | None = None) -> list[dict]:
    """Match response signals against the signature table.

    Returns matches sorted by signature id (deterministic).  ``None``
    tech names mean "observable but generic" -- reported under a derived
    name instead of claiming a product we only saw a header of.
    """
    body = (body or "")[:MAX_BODY_BYTES]
    hdrs = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    cookies = _cookie_map(hdrs)
    meta_gen = _generator_meta(body)
    matches: dict[str, dict] = {}

    def _hit(sig_id: str, tech: str, kind: str, token: str) -> None:
        if sig_id in matches:
            return
        tech_name = tech
        if tech_name is None:
            tech_name = {
                "meta_generator": (meta_gen or "generator")[:MAX_EVIDENCE],
            }.get(sig_id, sig_id)
        matches[sig_id] = {
            "sig_id": sig_id,
            "tech": tech_name,
            "kind": kind,
            "token": token[:MAX_EVIDENCE],
        }

    sigs = list(SIGNATURES) + list(extra_signatures or ())
    for sig_id, kind, target, pattern, tech in sigs:
        try:
            rx = re.compile(pattern, re.I)
        except re.error:
            continue                   # bad table row must not kill the run
        if kind == "header":
            value = hdrs.get(target.lower())
            if value and rx.search(value):
                _hit(sig_id, tech, kind, value)
        elif kind == "cookie":
            value = cookies.get(target.lower())
            if value and rx.search(value):
                _hit(sig_id, tech, kind, target)
        elif kind == "meta":
            if target == "generator" and meta_gen and rx.search(meta_gen):
                _hit(sig_id, tech, kind, meta_gen)
        elif kind == "body":
            m = rx.search(body)
            if m:
                _hit(sig_id, tech, kind, m.group(0))
    return [matches[k] for k in sorted(matches)]
