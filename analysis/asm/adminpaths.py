"""T-6.1: exposed admin / management panel discovery.

The path list is bounded and curated (admin UIs and management consoles,
not a general content-discovery wordlist -- that would be a different,
much noisier tool).  Classification is PURE (status + headers + body ->
verdict) so every response combination is unit-testable offline; the
probing runs in the collector with injected fetch + rate limiting.

Verdicts:
  ``restricted``  401/403 on a known admin path -- the PANEL EXISTS and
                  is access-controlled (an inventory hit, not a vuln);
  ``detected``    2xx whose title/body matches the panel's own marker --
                  an unauthenticated admin surface;
  None            404/soft-404/irrelevant -- not reported (a generic
                  200 SPA catch-all must not become "17 admin panels").
"""
from __future__ import annotations
try:
    from analysis.spans import WINDOW_60, WINDOW_80, WINDOW_8192
except ImportError:  # FND-03: standalone, repo root not on path
    import sys as _fnd03_sys
    from pathlib import Path as _fnd03_path
    _fnd03_sys.path.insert(0, str(_fnd03_path(__file__).resolve().parents[2]))
    from analysis.spans import WINDOW_60, WINDOW_80, WINDOW_8192

import re

# Bounded on purpose: untrusted wordlists belong in an explicit override.
MAX_ADMIN_PATHS = 256

ADMIN_PATHS: tuple[str, ...] = (
    "/admin", "/admin/", "/admin/login", "/administrator",
    "/administrator/", "/wp-admin", "/wp-login.php", "/user/login",
    "/login", "/signin", "/backend", "/controlpanel", "/manager/html",
    "/host-manager/html", "/manager/status", "/console", "/jmx-console",
    "/web-console", "/phpmyadmin", "/pma", "/myadmin", "/mysql",
    "/adminer", "/adminer.php", "/phppgadmin", "/pgadmin",
    "/actuator", "/actuator/health", "/actuator/env", "/actuator/mappings",
    "/jolokia", "/server-status", "/server-info", "/nginx_status",
    "/solr/", "/solr/admin", "/jenkins/login", "/jenkins/", "/hudson",
    "/grafana", "/grafana/login", "/kibana", "/kibana/app",
    "/zabbix", "/nagios", "/nagios4", "/cacti", "/webmin",
    "/dashboard", "/dashboard/login", "/console/login",
    "/swagger-ui.html", "/swagger/index.html", "/api-docs",
    "/graphql", "/graphiql", "/playground",
    "/_profiler", "/_profiler/empty/search/results?limit=10",
    "/debug/default/view", "/debug", "/elmah", "/trace.axd",
    "/.git/HEAD", "/.env", "/backup", "/phpinfo.php", "/info.php",
    "/server.php", "/status", "/status.jsp", "/status.php",
    "/cpanel", "/webmail", "/plesk", "/virtualmin",
    "/wp-content/plugins/", "/bitrix/admin/",
)

# marker regex -> panel name, matched against <title> + first 8KiB body
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_PANEL_MARKERS: tuple[tuple[str, str], ...] = (
    (r"apache tomcat.*manager", "Tomcat Manager"),
    (r"tomcat (web application )?manager", "Tomcat Manager"),
    (r"phpmyadmin", "phpMyAdmin"),
    (r"adminer", "Adminer"),
    (r"grafana", "Grafana"),
    (r"kibana", "Kibana"),
    (r"jenkins", "Jenkins"),
    (r"zabbix", "Zabbix"),
    (r"nagios", "Nagios"),
    (r"spring boot.*actuator|\"_links\"", "Spring Actuator"),
    (r"prometheus", "Prometheus"),
    (r"pgadmin", "pgAdmin"),
    (r"webmin", "Webmin"),
    (r"solr administration", "Solr Admin"),
    (r"django administration", "Django Admin"),
    (r"wordpress.*log in|log in.*wordpress", "WordPress Login"),
    (r"wp-admin", "WordPress Admin"),
    (r"jolokia", "Jolokia"),
    (r"swagger", "Swagger UI"),
    (r"graphiql|graphql playground", "GraphQL Console"),
    (r"__web_debug__|symfony (web debug toolbar|profiler)", "Symfony Profiler"),
    (r"phpinfo\(\)", "phpinfo"),
    (r"whitelabel error page", None),   # Spring default 404: NOT a panel
)
_MARKER_RE = tuple(
    (re.compile(pat, re.I), name) for pat, name in _PANEL_MARKERS
    if name is not None
)
_NEGATIVE_RE = tuple(
    re.compile(pat, re.I) for pat, name in _PANEL_MARKERS if name is None
)

LOGIN_TITLE_RE = re.compile(r"\b(log ?in|sign ?in|authenticat|password)\b", re.I)
GENERIC_SPA_TITLES = re.compile(
    r"^(not found|404|home|welcome|index)(\s|$)", re.I)


def classify_admin_response(path: str, status: int,
                            headers: dict, body: str) -> dict | None:
    """Classify one admin-path probe.  Pure; deterministic verdict."""
    try:
        code = int(status)
    except (TypeError, ValueError):
        return None
    if code in (401, 403):
        return {"path": path, "status": code, "kind": "restricted",
                "evidence": f"http_{code}"}
    if code < 200 or code >= 400:
        return None
    text = (body or "")[:WINDOW_8192]
    title_m = _TITLE_RE.search(text)
    title = title_m.group(1).strip() if title_m else ""
    combined = f"{title}\n{text}"
    if any(rx.search(combined) for rx in _NEGATIVE_RE):
        return None
    for rx, name in _MARKER_RE:
        if rx.search(combined):
            return {"path": path, "status": code, "kind": "detected",
                    "panel": name, "evidence": rx.pattern[:WINDOW_80]}
    if title and LOGIN_TITLE_RE.search(title) and not GENERIC_SPA_TITLES.match(title):
        return {"path": path, "status": code, "kind": "detected",
                "panel": "Login Form", "evidence": f"title={title[:WINDOW_60]}"}
    # 200 on /admin with no panel signal = soft-404/SPA catch-all
    return None


def admin_paths(extra: tuple[str, ...] = ()) -> list[str]:
    """Curated list + caller overrides, normalized, deduped, capped --
    overflow beyond MAX_ADMIN_PATHS is dropped ONLY here, and the
    collector records the pre-cap length in stats so it is disclosed."""
    seen: dict[str, None] = {}
    for p in tuple(ADMIN_PATHS) + tuple(extra):
        s = str(p).strip()
        if not s.startswith("/"):
            s = "/" + s
        if s not in seen:
            seen[s] = None
    return list(seen)


def cap_for(paths: list[str]) -> tuple[list[str], int]:
    """Apply the cap; returns (kept, dropped_count) for disclosure."""
    if len(paths) <= MAX_ADMIN_PATHS:
        return paths, 0
    return paths[:MAX_ADMIN_PATHS], len(paths) - MAX_ADMIN_PATHS
