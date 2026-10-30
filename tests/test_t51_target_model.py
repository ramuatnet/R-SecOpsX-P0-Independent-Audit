"""T-5.1 crawler & target model.

Pins the normalized route/method/param model, every file-based source
parser (OpenAPI/Swagger, Postman, HAR, HTML, JS, sitemap, robots), the
opt-in scope-bounded crawler, and the merge with the SAST route model
(scanner.apibom).  Nothing here may touch the network unless a crawl URL
is explicitly handed to the crawler.
"""
import json
import sys
from pathlib import Path

import pytest

from analysis.dast import target_model as tm
from analysis.dast.crawler import CrawlConfig, FetchResponse, crawl
from analysis.dast.model import (
    MODEL_SCHEMA,
    make_entry,
    merge_entries,
    merge_with_sast,
    normalize_path,
    route_key,
)
from analysis.dast.sources import (
    detect_source_files,
    load_document,
    parse_har,
    parse_html,
    parse_js,
    parse_openapi,
    parse_postman,
    parse_robots,
    parse_sitemap,
)


# ---------------------------------------------------------------------------
# normalize_path / route_key
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("raw,expected", [
    ("/users/<user_id>/posts/:post_id", "/users/{user_id}/posts/{post_id}"),
    ("/users/{id}", "/users/{id}"),                    # idempotent
    ("users/", "/users"),                              # leading slash + rstrip
    ("/", "/"),
    ("", "/"),
    ("/x?q=1#frag", "/x"),                             # query/fragment stripped
    ("{{baseUrl}}/v1/items/:itemId", "/v1/items/{itemId}"),  # Postman base var
    ("/a/{{version}}/b", "/a/{version}/b"),
])
def test_normalize_path_unifies_param_syntaxes(raw, expected):
    assert normalize_path(raw) == expected


def test_route_key_is_method_and_normalized_path():
    assert route_key("get", "/users/<id>") == "GET /users/{id}"


# ---------------------------------------------------------------------------
# OpenAPI / Swagger
# ---------------------------------------------------------------------------

OPENAPI3_DOC = {
    "openapi": "3.0.0",
    "security": [{"bearerAuth": []}],
    "paths": {
        "/pets/{petId}": {
            "get": {
                "parameters": [
                    {"name": "petId", "in": "path", "required": True,
                     "schema": {"type": "string"}},
                    {"name": "limit", "in": "query", "schema": {"type": "integer"}},
                    {"name": "X-Trace", "in": "header", "schema": {"type": "string"}},
                ],
                "responses": {"200": {"description": "ok"}},
            },
            "post": {
                "requestBody": {
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {"name": {}, "tag": {}},
                            }
                        }
                    }
                },
            },
            "delete": {"security": []},   # op-level override: no auth
        },
    },
}


def test_parse_openapi3_routes_params_and_methods():
    entries = parse_openapi(OPENAPI3_DOC, "petstore.json")
    keys = sorted(e["route_key"] for e in entries)
    assert keys == ["DELETE /pets/{petId}", "GET /pets/{petId}", "POST /pets/{petId}"]

    get = next(e for e in entries if e["method"] == "GET")
    locs = {(p["in"], p["name"]) for p in get["params"]}
    assert ("path", "petId") in locs
    assert ("query", "limit") in locs
    assert ("header", "X-Trace") in locs
    # undeclared template param would be synthesized; petId is declared.
    assert sum(1 for p in get["params"] if p["name"] == "petId") == 1


def test_parse_openapi3_auth_inheritance_and_override():
    entries = parse_openapi(OPENAPI3_DOC, "petstore.json")
    auth = {e["method"]: e["provenance"][0]["auth_required"] for e in entries}
    assert auth["GET"] is True          # inherits global security
    assert auth["POST"] is True
    assert auth["DELETE"] is False      # op-level security: [] means optional


def test_parse_openapi3_body_params_from_request_body():
    entries = parse_openapi(OPENAPI3_DOC, "petstore.json")
    post = next(e for e in entries if e["method"] == "POST")
    body = {p["name"] for p in post["params"] if p["in"] == "body"}
    assert body == {"name", "tag"}


SWAGGER2_DOC = {
    "swagger": "2.0",
    "security": [{"apiKey": []}],
    "paths": {
        "/users/{id}": {
            "parameters": [
                {"name": "id", "in": "path", "required": True, "type": "integer"},
            ],
            "get": {"parameters": [{"name": "q", "in": "query", "type": "string"}]},
            "put": {"parameters": [{"name": "body", "in": "body", "schema": {"type": "object"}}]},
        },
    },
}


def test_parse_swagger2_params_and_auth():
    entries = parse_openapi(SWAGGER2_DOC, "swagger.json")
    keys = sorted(e["route_key"] for e in entries)
    assert keys == ["GET /users/{id}", "PUT /users/{id}"]
    get = next(e for e in entries if e["method"] == "GET")
    locs = {(p["in"], p["name"]) for p in get["params"]}
    assert ("path", "id") in locs
    assert ("query", "q") in locs
    assert get["provenance"][0]["auth_required"] is True


def test_openapi_path_template_synthesizes_undeclared_params():
    doc = {"paths": {"/files/{fileId}": {"get": {}}}}
    entries = parse_openapi(doc, "x.json")
    get = entries[0]
    assert {"name": "fileId", "in": "path"} in get["params"]


# ---------------------------------------------------------------------------
# Postman
# ---------------------------------------------------------------------------

POSTMAN_DOC = {
    "info": {"name": "demo", "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
    "item": [
        {
            "name": "auth",
            "item": [
                {
                    "name": "login",
                    "request": {
                        "method": "POST",
                        "url": "{{baseUrl}}/users/:userId/login",
                    },
                },
            ],
        },
        {
            "name": "items",
            "request": {
                "method": "GET",
                "url": {
                    "raw": "https://example.test/api/items?limit=10",
                    "host": ["example.test"],
                    "path": ["api", "items"],
                    "query": [{"key": "limit", "value": "10"}],
                },
            },
        },
    ],
}


def test_parse_postman_recurses_folders_and_normalizes_urls():
    entries = parse_postman(POSTMAN_DOC, "demo.postman_collection.json")
    keys = sorted(e["route_key"] for e in entries)
    assert keys == ["GET /api/items", "POST /users/{userId}/login"]
    items = next(e for e in entries if e["method"] == "GET")
    assert {"name": "limit", "in": "query"} in items["params"]


# ---------------------------------------------------------------------------
# HAR
# ---------------------------------------------------------------------------

HAR_DOC = {
    "log": {
        "entries": [
            {"request": {"method": "GET",
                         "url": "https://example.test/search?q=shoes&page=2",
                         "queryString": [{"key": "q", "value": "shoes"},
                                         {"key": "page", "value": "2"}]}},
            {"request": {"method": "POST", "url": "https://example.test/orders"}},
        ]
    },
}


def test_parse_har_methods_paths_and_query_params():
    entries = parse_har(HAR_DOC, "session.har")
    keys = sorted(e["route_key"] for e in entries)
    assert keys == ["GET /search", "POST /orders"]
    get = next(e for e in entries if e["method"] == "GET")
    assert {(p["in"], p["name"]) for p in get["params"]} == {("query", "q"), ("query", "page")}


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------

HTML_PAGE = """
<html><body>
  <a href="/products">Products</a>
  <a href="https://other.test/out">external</a>
  <a href="mailto:x@y.test">mail</a>
  <a href="#top">frag</a>
  <form action="/login" method="post">
    <input name="user"><input name="pass" type="password">
  </form>
  <form action="/search" method="GET"><input name="q"></form>
</body></html>
"""


def test_parse_html_links_forms_and_params():
    entries, links = parse_html(HTML_PAGE, "index.html")
    keys = sorted(e["route_key"] for e in entries)
    assert keys == ["GET /products", "GET /search", "POST /login"]
    login = next(e for e in entries if e["method"] == "POST")
    assert {p["name"] for p in login["params"] if p["in"] == "body"} == {"user", "pass"}
    search = next(e for e in entries if e["path"] == "/search")
    assert {"name": "q", "in": "query"} in search["params"]
    # Frontier links: anchors + GET-form actions; mailto/fragment filtered.
    assert "/products" in links
    assert "https://other.test/out" in links
    assert "/search" in links                 # GET form is followable
    assert not any(l.startswith("mailto:") or l.startswith("#") for l in links)


def test_parse_html_form_action_hash_lands_on_page_route():
    """action="#" submits to the page itself (HTML spec); the params must
    land on that page's route, not on '/'.  DVWA's vuln pages all use
    action="#", and the T-5.5 correlation gate depends on the pairing."""
    page = ('<html><body><form action="#" method="GET">'
            '<input name="id"><input name="Submit" type="submit">'
            "</form></body></html>")
    entries, links = parse_html(page, "http://t.local/vulnerabilities/sqli/",
                                kind="crawl")
    keys = sorted(e["route_key"] for e in entries)
    assert keys == ["GET /vulnerabilities/sqli"]     # normalize_path strips /
    assert {p["name"] for p in entries[0]["params"]} == {"id", "Submit"}
    assert not any(l.startswith("#") for l in links)


# ---------------------------------------------------------------------------
# JS route extraction
# ---------------------------------------------------------------------------

JS_SOURCE = """
const api = "/api/base";
fetch('/api/users');
fetch(`/api/dynamic/${id}`);          // NOT a static route -- must not match
axios.get("/api/me");
axios.post('/api/submit', body);
axios.put("/api/u/" + id);            // NOT static -- must not match
$.ajax({ url: "/api/search?q=1", method: "GET" });
"""

def test_parse_js_static_routes_only():
    entries = parse_js(JS_SOURCE, "app.js")
    keys = sorted(e["route_key"] for e in entries)
    assert keys == ["GET /api/me", "GET /api/search", "GET /api/users", "POST /api/submit"]
    search = next(e for e in entries if e["path"] == "/api/search")
    assert {"name": "q", "in": "query"} in search["params"]


# ---------------------------------------------------------------------------
# sitemap / robots
# ---------------------------------------------------------------------------

SITEMAP_XML = """<?xml version="1.0"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://example.test/</loc></url>
  <url><loc>https://example.test/about</loc></url>
  <url><loc>https://example.test/contact</loc></url>
</urlset>
"""


def test_parse_sitemap_locs_become_get_routes():
    entries = parse_sitemap(SITEMAP_XML, "sitemap.xml")
    assert sorted(e["path"] for e in entries) == ["/", "/about", "/contact"]
    assert all(e["method"] == "GET" for e in entries)


ROBOTS_TXT = """User-agent: *
Disallow: /admin
Disallow: /tmp/
Allow: /admin/public
Sitemap: https://example.test/sitemap.xml
"""


def test_parse_robots_routes_sitemaps_and_disallow():
    entries, sitemaps, disallow = parse_robots(ROBOTS_TXT, "robots.txt")
    paths = {e["path"] for e in entries}
    assert "/admin" in paths
    assert "/admin/public" in paths
    assert disallow == ["/admin", "/tmp/"]
    assert sitemaps == ["https://example.test/sitemap.xml"]


# ---------------------------------------------------------------------------
# Crawler (fetch injected -- no sockets in tests)
# ---------------------------------------------------------------------------

def _pages_fixture():
    return {
        "http://t.local/": (
            '<html><a href="/a">a</a>'
            '<a href="/b">b</a>'
            '<a href="http://evil.local/x">evil</a>'
            '<a href="/admin">blocked</a></html>'
        ),
        "http://t.local/a": '<html><a href="/c">c</a></html>',
        "http://t.local/b": "<html>b</html>",
        "http://t.local/c": "<html>c</html>",
        "http://t.local/admin": "<html>secret</html>",
        "http://t.local/robots.txt": "User-agent: *\nDisallow: /admin\n",
        "http://evil.local/x": "<html>evil</html>",
    }


def _fake_fetch(pages, calls):
    def fetch(url, timeout_s, user_agent):
        calls.append(url)
        if url not in pages:
            raise OSError(f"unexpected url {url}")
        return FetchResponse(url=url, status=200,
                             headers={"content-type": "text/html"},
                             body=pages[url])
    return fetch


def test_crawler_scope_robots_and_bfs():
    pages = _pages_fixture()
    calls = []
    result = crawl(CrawlConfig(base_url="http://t.local/", rate_limit_s=0),
                   fetch=_fake_fetch(pages, calls))

    assert "http://evil.local/x" not in calls                    # scope
    assert "http://t.local/admin" not in calls                   # robots Disallow
    assert "http://evil.local/x" in result["out_of_scope"]
    assert "http://t.local/admin" in result["blocked_by_robots"]
    # BFS order: robots.txt first (recon), then base, then depth-1 sorted.
    assert result["pages"][0] == "http://t.local/"
    assert result["pages"][1:] == ["http://t.local/a", "http://t.local/b",
                                   "http://t.local/c"]
    paths = {e["path"] for e in result["routes"]}
    assert {"/", "/a", "/b", "/c"} <= paths


def test_crawler_max_pages_truncation_disclosed():
    chain = {"http://t.local/robots.txt": "User-agent: *\n",
             "http://t.local/": '<a href="/p1"><a href="/p2"><a href="/p3">'}
    for i in (1, 2, 3):
        chain[f"http://t.local/p{i}"] = f"<html>{i}</html>"
    calls = []
    result = crawl(CrawlConfig(base_url="http://t.local/", max_pages=2,
                               max_depth=5, rate_limit_s=0, respect_robots=False),
                   fetch=_fake_fetch(chain, calls))
    assert result["truncated"] is True
    assert len(result["pages"]) == 2


def test_crawler_js_asset_extraction():
    pages = {
        "http://t.local/": '<html><script src="/app.js"></script>'
                           '<a href="/app.js">x</a></html>',
        "http://t.local/app.js": 'axios.get("/api/fromjs");',
        "http://t.local/robots.txt": "User-agent: *\n",
    }
    result = crawl(CrawlConfig(base_url="http://t.local/", rate_limit_s=0),
                   fetch=_fake_fetch(pages, []))
    assert any(e["path"] == "/api/fromjs" and e["method"] == "GET"
               for e in result["routes"])


def test_crawler_rate_limit_sleeps_between_fetches():
    pages = {"http://t.local/": "<html>only</html>",
             "http://t.local/robots.txt": "User-agent: *\n"}
    sleeps = []
    crawl(CrawlConfig(base_url="http://t.local/", rate_limit_s=0.25),
          fetch=_fake_fetch(pages, []), sleep=sleeps.append)
    # robots.txt then the page: one inter-request delay, none before the
    # first fetch and none after the last.
    assert sleeps == [0.25]


def test_default_fetch_is_get_with_user_agent(monkeypatch):
    import urllib.request

    captured = {}

    class _Resp:
        status = 200
        headers = {"Content-Type": "text/html"}

        def read(self, n=-1):
            return b"<html></html>"

        def geturl(self):
            return "http://t.local/"

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def fake_urlopen(req, timeout=None):
        captured["req"] = req
        captured["timeout"] = timeout
        return _Resp()

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    from analysis.dast.crawler import default_fetch
    resp = default_fetch("http://t.local/", 5.0, "R-SecOpsX-DAST/0.1")
    req = captured["req"]
    assert req.get_method() == "GET"
    assert req.headers.get("User-agent") == "R-SecOpsX-DAST/0.1"
    assert captured["timeout"] == 5.0
    assert resp.status == 200


# ---------------------------------------------------------------------------
# Model merge
# ---------------------------------------------------------------------------

def test_merge_normalizes_across_sast_and_dast():
    dast = [make_entry(method="GET", path="/users/{id}", kind="openapi",
                       ref="openapi.json")]
    sast = [{
        "framework": "Flask", "language": "python",
        "file": "app.py", "line": 12,
        "route": "/users/<id>", "methods": ["GET"],
        "route_params": ["<id>"],
        "auth_hint": "AUTH_HINT_PRESENT",
        "evidence": "@app.route('/users/<id>')",
    }]
    routes, sast_count, intersection = merge_with_sast(dast, sast)
    assert intersection == 1 and sast_count == 1
    assert len(routes) == 1                       # merged, not duplicated
    r = routes[0]
    assert r["route_key"] == "GET /users/{id}"    # <id> == {id} after normalize
    assert r["sources"] == ["openapi", "sast_apibom"]
    assert r["auth_required"] is True
    sast_prov = next(p for p in r["provenance"] if p["kind"] == "sast_apibom")
    assert sast_prov["file"] == "app.py" and sast_prov["line"] == 12


def test_merge_expands_multi_method_sast_items():
    sast = [{
        "framework": "Flask", "file": "app.py", "line": 3,
        "route": "/upload", "methods": ["GET", "POST"],
        "route_params": [], "auth_hint": "AUTH_HINT_NOT_OBSERVED",
        "evidence": "",
    }]
    routes, sast_count, intersection = merge_with_sast([], sast)
    assert sorted(r["route_key"] for r in routes) == ["GET /upload", "POST /upload"]
    assert sast_count == 2 and intersection == 0
    # NOT_OBSERVED is absence of evidence -> unknown, not "known unauthenticated".
    assert all(r["auth_required"] is None for r in routes)


def test_merge_skips_unknown_sast_methods():
    sast = [{"framework": "X", "file": "f.py", "line": 1, "route": "/x",
             "methods": ["UNKNOWN"], "route_params": [],
             "auth_hint": "AUTH_HINT_NOT_OBSERVED", "evidence": ""}]
    routes, sast_count, _ = merge_with_sast([], sast)
    assert routes == [] and sast_count == 0


def test_auth_union_any_true_wins_else_unknown():
    dast = [make_entry(method="GET", path="/a", kind="openapi", ref="o",
                       auth_required=None)]
    sast = [{"framework": "F", "file": "f.py", "line": 1, "route": "/a",
             "methods": ["GET"], "route_params": [],
             "auth_hint": "AUTH_HINT_PRESENT", "evidence": ""}]
    routes, _, _ = merge_with_sast(dast, sast)
    assert routes[0]["auth_required"] is True


def test_merge_entries_unions_params_and_provenance():
    a = make_entry(method="GET", path="/x", kind="openapi", ref="o",
                   params=[{"name": "q", "in": "query"}])
    b = make_entry(method="GET", path="/x", kind="postman", ref="p",
                   params=[{"name": "q", "in": "query"},
                           {"name": "page", "in": "query"}])
    merged = merge_entries([a, b])
    assert len(merged) == 1
    assert {(p["in"], p["name"]) for p in merged[0]["params"]} == \
        {("query", "q"), ("query", "page")}
    assert len(merged[0]["provenance"]) == 2


# ---------------------------------------------------------------------------
# Source detection / load_document / resource bounds
# ---------------------------------------------------------------------------

def test_detect_source_files_by_name_and_extension(tmp_path):
    (tmp_path / "openapi.yaml").write_text("openapi: 3.0.0\npaths: {}\n", "utf-8")
    (tmp_path / "shop.postman_collection.json").write_text("{}", "utf-8")
    (tmp_path / "trace.har").write_text("{}", "utf-8")
    (tmp_path / "sitemap.xml").write_text("<urlset/>", "utf-8")
    (tmp_path / "robots.txt").write_text("User-agent: *\n", "utf-8")
    (tmp_path / "index.html").write_text("<html></html>", "utf-8")
    (tmp_path / "app.js").write_text("fetch('/x')", "utf-8")
    nm = tmp_path / "node_modules" / "pkg"
    nm.mkdir(parents=True)
    (nm / "lib.js").write_text("fetch('/y')", "utf-8")

    found = detect_source_files(tmp_path)
    assert [p.name for p in found["openapi"]] == ["openapi.yaml"]
    assert [p.name for p in found["postman"]] == ["shop.postman_collection.json"]
    assert [p.name for p in found["har"]] == ["trace.har"]
    assert [p.name for p in found["sitemap"]] == ["sitemap.xml"]
    assert [p.name for p in found["robots"]] == ["robots.txt"]
    assert [p.name for p in found["html"]] == ["index.html"]
    assert [p.name for p in found["js"]] == ["app.js"]      # node_modules pruned


def test_load_document_size_cap_disclosed(tmp_path):
    big = tmp_path / "big.json"
    big.write_bytes(b"x" * 200)
    from analysis.dast.sources import SourceLimits
    doc, reason = load_document(big, limits=SourceLimits(max_bytes=100))
    assert doc is None and reason == "toobig"


def test_load_document_yaml_needs_pyyaml_disclosed(tmp_path, monkeypatch):
    f = tmp_path / "openapi.yaml"
    f.write_text("openapi: 3.0.0\npaths: {}\n", "utf-8")
    monkeypatch.setitem(sys.modules, "yaml", None)   # forces ImportError
    doc, reason = load_document(f)
    assert doc is None and reason == "yaml_needs_pyyaml"


def test_load_document_parse_error_disclosed(tmp_path):
    f = tmp_path / "openapi.json"
    f.write_text("{not json", "utf-8")
    doc, reason = load_document(f)
    assert doc is None and reason == "parse_error"


# ---------------------------------------------------------------------------
# build_target_model end-to-end (offline)
# ---------------------------------------------------------------------------

@pytest.fixture
def fixture_target(tmp_path):
    (tmp_path / "openapi.json").write_text(json.dumps(OPENAPI3_DOC), "utf-8")
    (tmp_path / "app.py").write_text(
        "from flask import Flask\n"
        "app = Flask(__name__)\n"
        "@app.route('/users/<uid>', methods=['GET', 'POST'])\n"
        "def u(uid): pass\n", "utf-8")
    (tmp_path / "index.html").write_text(
        '<html><form action="/login" method="post">'
        '<input name="user"></form></html>', "utf-8")
    (tmp_path / "app.js").write_text("axios.get('/api/me');", "utf-8")
    (tmp_path / "robots.txt").write_text("User-agent: *\nDisallow: /admin\n")
    (tmp_path / "sitemap.xml").write_text(SITEMAP_XML)
    return tmp_path


def test_build_target_model_end_to_end(fixture_target):
    model = tm.build_target_model(fixture_target)
    assert model["schema"] == MODEL_SCHEMA
    keys = [r["route_key"] for r in model["routes"]]
    assert keys == sorted(keys)                          # deterministic order
    assert "POST /login" in keys
    assert "GET /api/me" in keys
    assert "GET /pets/{petId}" in keys                   # openapi
    assert "GET /users/{uid}" in keys                    # sast apibom
    assert "POST /users/{uid}" in keys                   # method expansion
    assert "GET /about" in keys                          # sitemap
    # SAST<->DAST intersection: openapi GET /pets/{petId} is dast-only here,
    # but the SAST route must appear with its source tagged.
    user = next(r for r in model["routes"] if r["route_key"] == "GET /users/{uid}")
    assert "sast_apibom" in user["sources"]
    statuses = {s["kind"]: s["status"] for s in model["sources"]}
    assert all(v.startswith("parsed") for v in statuses.values())
    assert model["stats"]["routes"] == len(keys)
    assert model["stats"]["sast_routes"] >= 2


def test_build_target_model_is_byte_deterministic(fixture_target):
    a = json.dumps(tm.build_target_model(fixture_target), sort_keys=True)
    b = json.dumps(tm.build_target_model(fixture_target), sort_keys=True)
    assert a == b


def test_build_target_model_never_touches_network(fixture_target, monkeypatch):
    import urllib.request

    def boom(*a, **k):
        raise AssertionError("network access in offline build")

    monkeypatch.setattr(urllib.request, "urlopen", boom)
    model = tm.build_target_model(fixture_target)         # no crawl_url
    assert model["routes"]


def test_build_target_model_bad_source_status_not_silent(tmp_path):
    (tmp_path / "openapi.json").write_text("{broken", "utf-8")
    model = tm.build_target_model(tmp_path)
    status = next(s for s in model["sources"] if s["kind"] == "openapi")
    assert status["status"] == "error:parse_error"
    assert model["stats"]["sources_skipped"] == 1


def test_cli_main_writes_model(fixture_target, tmp_path):
    out = tmp_path / "model.json"
    rc = tm.main([str(fixture_target), "--out", str(out)])
    assert rc == 0
    doc = json.loads(out.read_text("utf-8"))
    assert doc["schema"] == MODEL_SCHEMA


def test_model_exports_on_package_init():
    from analysis.dast import build_target_model, MODEL_SCHEMA as MS
    assert build_target_model is tm.build_target_model
    assert MS == MODEL_SCHEMA
