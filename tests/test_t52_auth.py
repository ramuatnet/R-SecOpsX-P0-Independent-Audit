"""T-5.2 DAST auth: profiles, sessions, replay, multi-role differential.

Five strategies (none/bearer/cookie/form/oauth2_cc) plus the scripted
hook, all fetch-injected (no sockets), plus session replay on expiry and
the route-inventory differential that feeds T-5.3 IDOR work.  Security
pins: auth material never appears in serialized session reports; the
scripted hook runs isolated (python -I), bounded and time-capped.
"""
import base64
import json
import sys
import time

import pytest

from analysis.dast import auth as A
from analysis.dast.auth import (
    AuthProfile,
    AuthSession,
    build_session,
    build_sessions,
    differential,
    load_profiles,
    session_headers,
    SessionReplay,
)
from analysis.dast.crawler import CrawlConfig, FetchResponse, crawl


def _profile(name, strategy, **config):
    p, err = AuthProfile.from_dict(
        {"name": name, "strategy": strategy, "config": config})
    assert err is None, err
    return p


# ---------------------------------------------------------------------------
# Profiles: loading + validation
# ---------------------------------------------------------------------------

def test_load_profiles_valid_and_invalid_rows(tmp_path):
    path = tmp_path / "profiles.json"
    path.write_text(json.dumps({
        "schema": A.AUTH_PROFILE_SCHEMA,
        "profiles": [
            {"name": "user", "strategy": "bearer", "config": {"token": "t1"}},
            {"name": "bad", "strategy": "telepathy", "config": {}},
            {"name": "nocfg", "strategy": "form", "config": {}},
        ],
    }), "utf-8")
    profiles, errors = load_profiles(path)
    assert [p.name for p in profiles] == ["user"]
    assert len(errors) == 2
    assert all("name" in e or "strategy" in e or "config" in e for e in errors)


def test_load_profiles_size_cap(tmp_path):
    path = tmp_path / "big.json"
    path.write_bytes(b"x" * 400)
    from analysis.dast.auth import ProfileLimits
    profiles, errors = load_profiles(path, limits=ProfileLimits(max_bytes=100))
    assert profiles == [] and errors == ["toobig"]


# ---------------------------------------------------------------------------
# Redaction: secrets never reach serialized output
# ---------------------------------------------------------------------------

SENTINEL = "SUPER_SECRET_VALUE_9f3c"


def test_session_reports_never_contain_secret_values():
    profiles = [
        _profile("b", "bearer", token=SENTINEL),
        _profile("c", "cookie", cookies={"sid": SENTINEL}),
        _profile("f", "form", url="http://t.local/login",
                 username="u", password=SENTINEL),
        _profile("o", "oauth2_cc", token_url="http://t.local/token",
                 client_id="cid", client_secret=SENTINEL),
    ]

    def fake_fetch(url, timeout_s, user_agent, method="GET", data=None,
                   headers=None):
        return A.AuthResponse(
            url=url, status=200,
            header_items=[("Set-Cookie", f"sess={SENTINEL}; Path=/")],
            body='{"access_token": "%s", "expires_in": 3600}' % SENTINEL)

    sessions = build_sessions(profiles, fetch=fake_fetch, now=lambda: 1000.0)
    blob = json.dumps([s.report() for s in sessions.values()])
    assert SENTINEL not in blob
    # ...but the session itself still carries the material for requests.
    assert SENTINEL in sessions["b"].headers.get("Authorization", "")


# ---------------------------------------------------------------------------
# none / bearer / cookie strategies
# ---------------------------------------------------------------------------

def test_none_strategy_is_empty_ok():
    s = build_session(_profile("anon", "none"))
    assert s.status == "ok" and s.headers == {}
    assert s.report()["header_names"] == []


def test_bearer_strategy_sets_authorization():
    s = build_session(_profile("api", "bearer", token="tok123"))
    assert s.headers == {"Authorization": "Bearer tok123"}
    assert s.report()["header_names"] == ["Authorization"]
    assert "tok123" not in json.dumps(s.report())


def test_cookie_strategy_assembles_cookie_header_deterministically():
    p = _profile("j", "cookie", cookies={"b": "2", "a": "1"})
    s = build_session(p)
    assert s.headers["Cookie"] == "a=1; b=2"          # sorted, stable
    s2 = build_session(p)
    assert s.headers == s2.headers


# ---------------------------------------------------------------------------
# Form login
# ---------------------------------------------------------------------------

FORM_LOGIN_HTML = (
    '<html><form method="post" action="/login">'
    '<input type="hidden" name="csrf_token" value="cs-abc">'
    '<input name="username"><input name="password">'
    "</form></html>"
)


def _form_fetch(script, calls):
    """script: url -> (status, header_items, body)."""
    def fetch(url, timeout_s, user_agent, method="GET", data=None,
              headers=None):
        calls.append({"url": url, "method": method, "data": data,
                      "headers": headers or {}})
        status, hdrs, body = script[url]
        return A.AuthResponse(url=url, status=status,
                              header_items=hdrs, body=body)
    return fetch


def test_form_login_harvests_csrf_cookies_and_follows_redirect():
    calls = []
    script = {
        "http://t.local/login": (
            200, [("Set-Cookie", "pre=1; Path=/")], FORM_LOGIN_HTML),
        "http://t.local/login/submit": (
            302, [("Set-Cookie", "session=s3cr3t; Path=/"),
                  ("Location", "http://t.local/dashboard")], ""),
        "http://t.local/dashboard": (
            200, [("Set-Cookie", "session=s3cr3t; Path=/; HttpOnly")],
            "<html>Welcome u</html>"),
    }
    p = _profile("member", "form",
                 url="http://t.local/login",
                 username="u", password="pw",
                 submit_url="http://t.local/login/submit",
                 verify_regex="Welcome")
    s = build_session(p, fetch=_form_fetch(script, calls))

    assert s.status == "ok" and s.verified is True
    post = next(c for c in calls if c["method"] == "POST")
    assert "csrf_token" in post["data"] and post["data"]["csrf_token"] == "cs-abc"
    assert post["data"]["username"] == "u" and post["data"]["password"] == "pw"
    assert post["headers"].get("Cookie", "").startswith("pre=1")
    # session cookie captured from the 302 and carried to the redirect GET.
    get = next(c for c in calls if c["url"].endswith("/dashboard"))
    assert "session=s3cr3t" in get["headers"].get("Cookie", "")
    assert "pw" not in json.dumps(s.report())


def test_form_login_failure_is_disclosed_not_raised():
    script = {
        "http://t.local/login": (200, [], FORM_LOGIN_HTML),
        "http://t.local/login/submit": (401, [], "nope"),
    }
    p = _profile("m", "form", url="http://t.local/login",
                 username="u", password="bad",
                 submit_url="http://t.local/login/submit")
    s = build_session(p, fetch=_form_fetch(script, []))
    assert s.status == "error:http_401" and s.headers == {}


def test_form_login_verify_mismatch_sets_verified_false():
    script = {
        "http://t.local/login": (200, [], FORM_LOGIN_HTML),
        "http://t.local/login/submit": (302, [], ""),
        "http://t.local/dashboard": (200, [], "Login failed"),
    }
    p = _profile("m", "form", url="http://t.local/login",
                 username="u", password="pw",
                 submit_url="http://t.local/login/submit",
                 verify_regex="Welcome")
    s = build_session(p, fetch=_form_fetch(script, []))
    assert s.status == "ok" and s.verified is False


# ---------------------------------------------------------------------------
# OAuth2 client-credentials
# ---------------------------------------------------------------------------

def _token_fetch(status, body, calls, header_items=()):
    def fetch(url, timeout_s, user_agent, method="GET", data=None,
              headers=None):
        calls.append({"url": url, "method": method, "data": data,
                      "headers": headers or {}})
        return A.AuthResponse(url=url, status=status,
                              header_items=list(header_items), body=body)
    return fetch


def test_oauth2_client_credentials_basic_style():
    calls = []
    p = _profile("svc", "oauth2_cc",
                 token_url="http://t.local/token",
                 client_id="cid", client_secret="csec",
                 scope="read write", auth_style="client_secret_basic")
    s = build_session(p, fetch=_token_fetch(
        200, '{"access_token": "tok99", "expires_in": 3600}', calls),
        now=lambda: 1000.0)
    assert s.status == "ok"
    assert s.headers == {"Authorization": "Bearer tok99"}
    assert s.expires_at == 4600.0
    post = calls[0]
    assert post["method"] == "POST"
    expected = base64.b64encode(b"cid:csec").decode("ascii")
    assert post["headers"]["Authorization"] == f"Basic {expected}"
    assert post["data"]["grant_type"] == "client_credentials"
    assert post["data"]["scope"] == "read write"
    assert "csec" not in json.dumps(s.report())


def test_oauth2_client_credentials_post_style_and_failure():
    calls = []
    p = _profile("svc", "oauth2_cc", token_url="http://t.local/token",
                 client_id="cid", client_secret="csec",
                 auth_style="client_secret_post")
    s = build_session(p, fetch=_token_fetch(
        401, '{"error": "invalid_client"}', calls))
    assert s.status == "error:unauthorized"
    assert calls[0]["data"]["client_secret"] == "csec"
    assert s.headers == {}


# ---------------------------------------------------------------------------
# Scripted login hook
# ---------------------------------------------------------------------------

def test_script_hook_uses_injected_runner():
    def runner(path, timeout_s):
        assert path.endswith("hook.py")
        return {"headers": {"X-Custom": "1"},
                "cookies": {"script_sid": "zz"}, "status": "ok"}
    p = _profile("otp", "script", path="hook.py")
    s = build_session(p, script_runner=runner)
    assert s.status == "ok"
    assert s.headers["X-Custom"] == "1"
    assert "script_sid=zz" in s.headers.get("Cookie", "")


def test_script_hook_runner_failure_disclosed():
    def runner(path, timeout_s):
        raise RuntimeError("boom")
    p = _profile("otp", "script", path="hook.py")
    s = build_session(p, script_runner=runner)
    assert s.status.startswith("error:script")


def test_script_hook_real_subprocess_isolated(tmp_path):
    hook = tmp_path / "hook.py"
    hook.write_text(
        "import json, sys\n"
        "print(json.dumps({'cookies': {'sid': 'from-script'},"
        " 'status': 'ok'}))\n", "utf-8")
    p = _profile("otp", "script", path=str(hook), timeout_s=10)
    s = build_session(p)                     # default runner: python -I
    assert s.status == "ok"
    assert "sid=from-script" in s.headers.get("Cookie", "")


def test_script_hook_timeout_disclosed(tmp_path):
    hook = tmp_path / "slow.py"
    hook.write_text("import time\ntime.sleep(5)\n", "utf-8")
    p = _profile("slow", "script", path=str(hook), timeout_s=1)
    s = build_session(p)
    assert s.status == "error:script_timeout"


# ---------------------------------------------------------------------------
# Session replay
# ---------------------------------------------------------------------------

def test_replay_caches_until_expiry_then_refreshes():
    clock = {"t": 1000.0}
    calls = []

    def fetch(url, timeout_s, user_agent, method="GET", data=None,
              headers=None):
        calls.append(url)
        n = len(calls)
        return A.AuthResponse(url=url, status=200, header_items=[],
                              body='{"access_token": "tok%d", "expires_in": 3600}' % n)

    p = _profile("svc", "oauth2_cc", token_url="http://t.local/token",
                 client_id="a", client_secret="b")
    replay = SessionReplay([p], fetch=fetch, now=lambda: clock["t"])
    s1 = replay.session("svc")
    s2 = replay.session("svc")
    assert len(calls) == 1 and s1 is s2            # cached while fresh
    clock["t"] = 1000.0 + 3600 - 30                # inside the 60s skew
    s3 = replay.session("svc")
    assert len(calls) == 2 and s3 is not s1
    assert s3.headers["Authorization"] == "Bearer tok2"
    # unknown name -> disclosed, not raised
    assert replay.session("nope").status.startswith("error:")


# ---------------------------------------------------------------------------
# Multi-role differential
# ---------------------------------------------------------------------------

def test_differential_visibility_and_role_uniques():
    diff = differential({
        "anon": ["/public", "/login"],
        "user": ["/public", "/me"],
        "admin": ["/public", "/me", "/admin"],
    })
    assert diff["roles"] == ["admin", "anon", "user"]
    assert diff["visible_to"]["/admin"] == ["admin"]
    assert diff["visible_to"]["/public"] == ["admin", "anon", "user"]
    assert diff["role_unique"]["admin"] == ["/admin"]
    assert diff["role_unique"]["anon"] == ["/login"]
    assert "/admin" in diff["hidden_from"]["anon"]
    # user sees neither /admin (admin-only) nor /login (anon-only)
    assert diff["hidden_from"]["user"] == ["/admin", "/login"]


def test_differential_is_deterministic_and_handles_empty_roles():
    roles = {"a": ["/x", "/y", "/x"], "b": []}
    d1 = differential(roles)
    d2 = differential(roles)
    assert json.dumps(d1, sort_keys=True) == json.dumps(d2, sort_keys=True)
    assert d1["routes"] == 2 and d1["role_unique"]["b"] == []
    assert d1["hidden_from"]["b"] == ["/x", "/y"]


# ---------------------------------------------------------------------------
# Crawl integration (CrawlConfig.auth_headers) + end-to-end differential
# ---------------------------------------------------------------------------

def test_crawl_without_auth_keeps_three_arg_fetch_contract():
    """T-5.1 contract: no auth_headers -> fetch called WITHOUT headers kwarg."""
    pages = {"http://t.local/": "<html>hi</html>",
             "http://t.local/robots.txt": "User-agent: *\n"}
    seen = []

    def fetch(url, timeout_s, user_agent):        # exactly 3 params
        seen.append(url)
        return FetchResponse(url=url, status=200,
                             headers={"content-type": "text/html"},
                             body=pages[url])

    crawl(CrawlConfig(base_url="http://t.local/", rate_limit_s=0),
          fetch=fetch)
    assert seen


def test_crawl_with_auth_passes_headers_to_fetch():
    pages = {"http://t.local/": "<html>hi</html>",
             "http://t.local/robots.txt": "User-agent: *\n"}
    got = []

    def fetch(url, timeout_s, user_agent, headers=None):
        got.append(headers)
        return FetchResponse(url=url, status=200,
                             headers={"content-type": "text/html"},
                             body=pages[url])

    crawl(CrawlConfig(base_url="http://t.local/", rate_limit_s=0,
                      auth_headers={"Authorization": "Bearer t"}),
          fetch=fetch)
    assert got and all(h == {"Authorization": "Bearer t"} for h in got)


def _role_crawl(auth_session, pages):
    """Crawl a fixture site as one role; return the SUCCESSFULLY FETCHED paths.

    Only fetched pages count as visible: a link to /admin in the landing
    page is not access evidence -- the 404 body is.
    """
    def fetch(url, timeout_s, user_agent, headers=None):
        cookie = (headers or {}).get("Cookie", "")
        allowed = pages.get(url, {})
        if "any" in allowed:
            return FetchResponse(url=url, status=200,
                                 headers={"content-type": "text/html"},
                                 body=allowed["any"])
        for key, body in allowed.items():
            if key and key in cookie:
                return FetchResponse(url=url, status=200,
                                     headers={"content-type": "text/html"},
                                     body=body)
        return FetchResponse(url=url, status=404, headers={}, body="")

    cfg = CrawlConfig(base_url="http://t.local/", rate_limit_s=0,
                      max_depth=2,
                      auth_headers=session_headers(auth_session))
    result = crawl(cfg, fetch=fetch)
    from urllib.parse import urlsplit
    return {urlsplit(p).path for p in result["pages"]}


def test_multi_role_end_to_end_differential():
    profiles = [
        _profile("user", "cookie", cookies={"role": "user"}),
        _profile("admin", "cookie", cookies={"role": "admin"}),
    ]
    sessions = build_sessions(profiles)
    site = {
        "http://t.local/robots.txt": {"any": "User-agent: *\n"},
        "http://t.local/": {"any": '<a href="/public"><a href="/me">'
                                   '<a href="/admin">'},
        "http://t.local/public": {"any": "<html>pub</html>"},
        "http://t.local/me": {"role=user": "<html>me</html>"},
        "http://t.local/admin": {"role=admin": "<html>panel</html>"},
    }
    routes = {name: _role_crawl(s, site) for name, s in sessions.items()}
    diff = differential(routes)
    assert diff["visible_to"]["/public"] == ["admin", "user"]
    assert diff["visible_to"]["/admin"] == ["admin"]
    assert diff["role_unique"]["admin"] == ["/admin"]
    assert diff["hidden_from"]["user"] == ["/admin"]


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def test_cli_writes_redacted_report(tmp_path, capsys):
    profiles = tmp_path / "p.json"
    profiles.write_text(json.dumps({
        "schema": A.AUTH_PROFILE_SCHEMA,
        "profiles": [
            {"name": "api", "strategy": "bearer", "config": {"token": "tok"}},
        ],
    }), "utf-8")
    out = tmp_path / "sessions.json"
    rc = A.main([str(profiles), "--out", str(out)])
    assert rc == 0
    doc = json.loads(out.read_text("utf-8"))
    assert doc["schema"] == A.SESSION_REPORT_SCHEMA
    assert doc["sessions"]["api"]["status"] == "ok"
    assert "tok" not in out.read_text("utf-8")


def test_cli_nonzero_when_any_session_errors(tmp_path):
    profiles = tmp_path / "p.json"
    profiles.write_text(json.dumps({
        "schema": A.AUTH_PROFILE_SCHEMA,
        "profiles": [
            {"name": "f", "strategy": "form", "config": {
                # no url -> invalid profile -> error row
            }},
        ],
    }), "utf-8")
    rc = A.main([str(profiles)])
    assert rc == 1


def test_package_exports():
    from analysis.dast import auth as auth_mod
    assert auth_mod.AUTH_PROFILE_SCHEMA.startswith("rsecopsx.")
    assert callable(auth_mod.differential)
