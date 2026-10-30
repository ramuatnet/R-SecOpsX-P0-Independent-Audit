"""T-5.3 active checks: framework + one positive AND one negative control
per implemented family, safe-mode guards, budgets, determinism.

Everything runs on an injected fetch -- no sockets.  Safe-mode invariants
pinned here: DELETE/PUT/PATCH probes are never sent; every probe URL stays
on the configured origin; 429 triggers backoff and route abort; probe
count is bounded per route.
"""
import json

import pytest

from analysis.dast import checks as C
from analysis.dast.auth import AuthProfile, build_sessions
from analysis.dast.model import make_entry, merge_entries


def _route(path="/search", method="GET", params=None):
    e = make_entry(method=method, path=path, kind="openapi", ref="f",
                   params=params or [{"name": "q", "in": "query"}])
    return merge_entries([e])[0]


def _resp(status=200, body="<html>ok</html>", headers=None):
    return C.ProbeResponse(url="", status=status, body=body,
                           headers=headers or {})


class FakeFetch:
    """Routes (url substring, method) -> response factory; records calls."""

    def __init__(self, responder):
        self.responder = responder
        self.calls = []

    def __call__(self, url, timeout_s, user_agent, headers=None, data=None,
                 method="GET"):
        self.calls.append({"url": url, "method": method, "data": data,
                           "headers": headers or {}})
        r = self.responder(url, method, data, headers or {})
        if isinstance(r, list):            # sequential answers
            r = r[min(len(self.calls) - 1, len(r) - 1)] if False else r.pop(0) \
                if len(r) else _resp(404)
        return r


def _ctx(routes, fetch, **kw):
    kw.setdefault("rate_limit_s", 0)
    return C.CheckContext(base_url="http://t.local/", routes=routes,
                          fetch=fetch, **kw)


# ---------------------------------------------------------------------------
# Framework: registry, budgets, determinism, safe mode
# ---------------------------------------------------------------------------

def test_registry_covers_task_families_and_states_gaps():
    ids = {c["id"] for c in C.CHECKS}
    for want in ("dast.sqli", "dast.xss_reflected", "dast.ssrf", "dast.lfi",
                 "dast.cmdi", "dast.xxe", "dast.ssti", "dast.open_redirect",
                 "dast.cors", "dast.security_headers", "dast.tls_grade",
                 "dast.jwt_weaknesses", "dast.deser", "dast.idor",
                 "dast.mass_assignment", "dast.rate_limit"):
        assert want in ids
    # xss stored/DOM are honestly declared not_modelled, not silently absent
    xss = next(c for c in C.CHECKS if c["id"] == "dast.xss_reflected")
    assert "stored" in xss["not_modelled"] and "dom" in xss["not_modelled"]


def test_run_checks_is_deterministic_and_bounded():
    def responder(url, method, data, headers):
        return _resp(200, "<html>" + "x" * 5000 + "</html>",
                     {"x-frame-options": "DENY", "content-security-policy": "default-src 'none'",
                      "strict-transport-security": "max-age=1",
                      "x-content-type-options": "nosniff"})
    routes = [_route("/a"), _route("/b")]
    out1 = C.run_checks(_ctx(routes, FakeFetch(responder)))
    out2 = C.run_checks(_ctx(routes, FakeFetch(responder)))
    assert json.dumps(out1, sort_keys=True) == json.dumps(out2, sort_keys=True)
    assert out1["schema"] == C.FINDINGS_SCHEMA
    assert out1["stats"]["probed_requests"] <= \
        len(routes) * (C.MAX_PROBES_PER_ROUTE + 5)


def test_safe_mode_never_sends_destructive_verbs():
    sent = []

    def responder(url, method, data, headers):
        sent.append(method)
        return _resp(200, "<html>ok</html>", {})

    routes = [_route("/item", method="DELETE",
                     params=[{"name": "id", "in": "query"}])]
    C.run_checks(_ctx(routes, FakeFetch(responder)))
    assert "DELETE" not in sent and "PUT" not in sent and "PATCH" not in sent


def test_probe_urls_stay_on_origin():
    urls = []

    def responder(url, method, data, headers):
        urls.append(url)
        return _resp(200, "<html>ok</html>", {})

    C.run_checks(_ctx([_route("/s")], FakeFetch(responder)))
    assert urls and all(u.startswith("http://t.local/") for u in urls)


def test_429_backoff_aborts_route_probes():
    calls = []

    def responder(url, method, data, headers):
        calls.append(url)
        return _resp(429, "slow down", {"retry-after": "30"})

    sleeps = []
    ctx = _ctx([_route("/s")], FakeFetch(responder), backoff_sleep=sleeps.append)
    out = C.run_checks(ctx)
    # backoff happened once, and probing stopped for the route
    assert sleeps and len(calls) <= 3
    assert any("429" in s["reason"] for s in out["stats"].get("aborts", []))


# ---------------------------------------------------------------------------
# security headers (passive)
# ---------------------------------------------------------------------------

def test_security_headers_positive_and_negative():
    pos = C.run_checks(_ctx([_route("/p")], FakeFetch(
        lambda u, m, d, h: _resp(200, "<html></html>", {}))))
    ids = [f["check"] for f in pos["findings"]]
    assert "dast.security_headers" in ids
    missing = sorted({f["evidence"]["missing"][0]
                      for f in pos["findings"]
                      if f["check"] == "dast.security_headers"})
    assert "content-security-policy" in missing

    neg = C.run_checks(_ctx([_route("/p")], FakeFetch(
        lambda u, m, d, h: _resp(200, "<html></html>", {
            "content-security-policy": "default-src 'none'",
            "x-frame-options": "DENY",
            "x-content-type-options": "nosniff",
            "strict-transport-security": "max-age=31536000"}))))
    assert not [f for f in neg["findings"] if f["check"] == "dast.security_headers"]


# ---------------------------------------------------------------------------
# CORS
# ---------------------------------------------------------------------------

def test_cors_positive_and_negative():
    pos = C.run_checks(_ctx([_route("/api")], FakeFetch(
        lambda u, m, d, h: _resp(200, "{}", {
            "access-control-allow-origin": "https://evil.test",
            "access-control-allow-credentials": "true"}))))
    cors = [f for f in pos["findings"] if f["check"] == "dast.cors"]
    assert cors and cors[0]["evidence"]["origin"] == "https://evil.test"

    neg = C.run_checks(_ctx([_route("/api")], FakeFetch(
        lambda u, m, d, h: _resp(200, "{}", {
            "access-control-allow-origin": "https://t.local"}))))
    assert not [f for f in neg["findings"] if f["check"] == "dast.cors"]


# ---------------------------------------------------------------------------
# SQLi
# ---------------------------------------------------------------------------

def test_sqli_positive_and_negative():
    pos = C.run_checks(_ctx([_route("/s")], FakeFetch(
        lambda u, m, d, h: _resp(200, "<html>You have an error in your SQL "
                                 "syntax near ''' at line 1</html>"))))
    hits = [f for f in pos["findings"] if f["check"] == "dast.sqli"]
    assert hits and hits[0]["confidence"] in {"likely", "confirmed"}
    assert hits[0]["evidence"]["param"] == "q"

    neg = C.run_checks(_ctx([_route("/s")], FakeFetch(
        lambda u, m, d, h: _resp(200, "<html>3 results for shoes</html>"))))
    assert not [f for f in neg["findings"] if f["check"] == "dast.sqli"]


# ---------------------------------------------------------------------------
# XSS reflected
# ---------------------------------------------------------------------------

CANARY = "rsxXssCanary7f3c"

def test_xss_reflected_positive_and_negative():
    def pos_responder(url, method, data, headers):
        if CANARY in url or (data and CANARY in str(data)):
            # the payload IS the tag -- reflect it verbatim, as an
            # unfiltered sink would
            return _resp(200, f"<html>You searched for <{CANARY}></html>")
        return _resp(200, "<html>ok</html>")
    pos = C.run_checks(_ctx([_route("/s")], FakeFetch(pos_responder)))
    hits = [f for f in pos["findings"] if f["check"] == "dast.xss_reflected"]
    assert hits and hits[0]["evidence"]["param"] == "q"

    def neg_responder(url, method, data, headers):
        return _resp(200, "<html>searched</html>")
    neg = C.run_checks(_ctx([_route("/s")], FakeFetch(neg_responder)))
    assert not [f for f in neg["findings"] if f["check"] == "dast.xss_reflected"]


def test_xss_encoded_reflections_are_not_findings():
    """Negative controls (DVWA gate): a redirect stub echoes the canary
    URL-encoded in an href, and careful apps echo it entity-encoded or
    tag-stripped -- none of those is an injectable reflection."""
    def responder(body):
        return lambda u, m, d, h: _resp(200, body)
    cases = [
        f"<a href=\"/s?q=%3C{CANARY}%3E\">next</a>",     # URL-encoded
        f"<html>&lt;{CANARY}&gt;</html>",                # HTML entity
        f"<html>You searched for {CANARY}</html>",        # tag stripped
    ]
    for body in cases:
        out = C.run_checks(_ctx([_route("/s")], FakeFetch(responder(body))))
        hits = [f for f in out["findings"]
                if f["check"] == "dast.xss_reflected"]
        assert not hits, body


# ---------------------------------------------------------------------------
# LFI
# ---------------------------------------------------------------------------

def test_lfi_positive_and_negative():
    def pos(url, m, d, h):
        if "..%2f" in url or "../" in url:
            return _resp(200, "root:x:0:0:root:/root:/bin/bash\n")
        return _resp(200, "welcome")
    hits = [f for f in C.run_checks(_ctx([_route("/view")], FakeFetch(pos)))["findings"]
            if f["check"] == "dast.lfi"]
    assert hits

    neg = C.run_checks(_ctx([_route("/view")], FakeFetch(
        lambda u, m, d, h: _resp(200, "welcome"))))
    assert not [f for f in neg["findings"] if f["check"] == "dast.lfi"]


# ---------------------------------------------------------------------------
# Command injection
# ---------------------------------------------------------------------------

def test_cmdi_positive_and_negative():
    def pos(url, m, d, h):
        if "RSXCMDcanary" in url and ";" in url or "%3B" in url:
            return _resp(200, "uid=33(www-data) RSXCMDcanary")
        return _resp(200, "ok")
    hits = [f for f in C.run_checks(_ctx([_route("/ping")], FakeFetch(pos)))["findings"]
            if f["check"] == "dast.cmdi"]
    assert hits

    neg = C.run_checks(_ctx([_route("/ping")], FakeFetch(
        lambda u, m, d, h: _resp(200, "pong"))))
    assert not [f for f in neg["findings"] if f["check"] == "dast.cmdi"]


def test_cmdi_executed_canary_without_shell_signature_is_tentative():
    """DVWA exec style: the app echoes the command line AND the echo
    output runs -- canary survives payload-strip without uid= evidence."""
    payload = ";echo RSXCMDcanary"

    def pos(url, m, d, h):
        return _resp(200, f"<pre>Executing: ping -c 4 {payload}\n"
                          f"64 bytes ...\nRSXCMDcanary\n</pre>")
    hits = [f for f in C.run_checks(_ctx([_route("/ping")], FakeFetch(pos)))["findings"]
            if f["check"] == "dast.cmdi"]
    assert hits and hits[0]["confidence"] == "tentative"


def test_cmdi_reflected_payload_only_is_not_a_finding():
    """Redirect-stub style: the canary appears ONLY inside the reflected
    (raw or URL-encoded) payload string -- stripping the payload copies
    removes it, so no execution evidence remains."""
    def neg(url, m, d, h):
        return _resp(200, "<a href=\"/ping?ip=%3Becho%20RSXCMDcanary\">go</a>")
    out = C.run_checks(_ctx([_route("/ping")], FakeFetch(neg)))
    assert not [f for f in out["findings"] if f["check"] == "dast.cmdi"]

    def neg_raw(url, m, d, h):
        return _resp(200, "<html>you asked for ;echo RSXCMDcanary</html>")
    out2 = C.run_checks(_ctx([_route("/ping")], FakeFetch(neg_raw)))
    assert not [f for f in out2["findings"] if f["check"] == "dast.cmdi"]


# ---------------------------------------------------------------------------
# SSTI
# ---------------------------------------------------------------------------

def test_ssti_positive_and_negative():
    def pos(url, m, d, h):
        if "987*654" in url or "987*654" in str(d):
            return _resp(200, "<html>645498</html>")
        return _resp(200, "hi")
    hits = [f for f in C.run_checks(_ctx([_route("/greet")], FakeFetch(pos)))["findings"]
            if f["check"] == "dast.ssti"]
    assert hits and hits[0]["evidence"]["param"]
    assert hits[0]["evidence"]["marker"] == "645498"

    neg = C.run_checks(_ctx([_route("/greet")], FakeFetch(
        lambda u, m, d, h: _resp(200, "hi"))))
    assert not [f for f in neg["findings"] if f["check"] == "dast.ssti"]


def test_ssti_page_content_is_not_a_render():
    """Gate FP controls (DVWA login token, wrongsecrets CSRF-error nav):
    hex-token fragments, nav labels, version strings, and a page that
    merely echoes the payload are not template evaluation.  The rare
    product must stand alone as an actual render."""
    cases = [
        # hex token embedding the product (DVWA-style CSRF token)
        "<html><input value='c9ff645498d5c961'></html>",
        # challenge-number nav label (wrongsecrets403 page)
        "<a href='/challenge/challenge-49'>Challenge 49</a>",
        # version fragment: dot/word neighbours, not a render
        "<span>build v1.645498.3</span>",
        # both probe payloads echoed raw = nothing evaluated; a stray
        # standalone product on the page still cannot fire (per-payload
        # veto has to cover every payload in SSTI_PAYLOADS)
        "<html>{{987*654}} / ${987*654} printed; try 645498</html>",
        # product present but glued into an identifier
        "<td>x645498y</td>",
    ]
    for body in cases:
        out = C.run_checks(_ctx([_route("/greet")], FakeFetch(
            lambda u, m, d, h, b=body: _resp(200, b))))
        hits = [f for f in out["findings"] if f["check"] == "dast.ssti"]
        assert not hits, body


def test_probe_requests_carry_authenticated_scan_session():
    """T-5.5: the first ok profile's headers ride on EVERY runner request
    (baseline + probes); caller-set headers still win (role Cookie)."""
    from analysis.dast.auth import AuthSession

    sessions = {
        "scan": AuthSession(name="scan", strategy="cookie",
                            headers={"Cookie": "PHPSESSID=abc; security=low"},
                            expires_at=None, status="ok", verified=None),
        "broken": AuthSession(name="broken", strategy="cookie",
                              headers={}, expires_at=None,
                              status="error:http_401", verified=None),
    }
    ff = FakeFetch(lambda u, m, d, h: _resp(200, "<html>ok</html>", {}))
    out = C.run_checks(_ctx([_route("/s")], ff, sessions=sessions))
    assert ff.calls, "no requests made"
    for call in ff.calls:
        assert call["headers"].get("Cookie") == "PHPSESSID=abc; security=low", \
            call["url"]
    # ...and the unauthenticated default is unchanged
    ff2 = FakeFetch(lambda u, m, d, h: _resp(200, "<html>ok</html>", {}))
    C.run_checks(_ctx([_route("/s")], ff2))
    assert all("Cookie" not in c["headers"] for c in ff2.calls)
    # session attach never muddies the findings contract
    assert out["schema"] == C.FINDINGS_SCHEMA


def test_excluded_paths_get_no_request_and_disclosed_skips():
    """DVWA gate root cause: GET /logout.php lives in the model (link
    extraction, not just crawl), and probing it kills the authenticated
    session mid-scan. Excluded routes get NO fetch -- not even the
    baseline -- and every check is a machine-readable skip."""
    ff = FakeFetch(lambda u, m, d, h: _resp(200, "<html>ok</html>", {}))
    routes = [_route("/logout.php", params=[]), _route("/s")]
    out = C.run_checks(_ctx(routes, ff, exclude_paths=("/logout.php",)))
    assert not any("/logout.php" in c["url"] for c in ff.calls)
    assert any("/s" in c["url"] for c in ff.calls)   # others unaffected
    lk = [s for s in out["stats"]["skips"]
          if s["route_key"] == "GET /logout.php"]
    expected = len(C.CHECKS) - 1          # every route check, tls is *
    assert len(lk) == expected and lk, lk
    assert all(s["reason"] == "excluded_path" for s in lk)


def test_excluded_paths_match_after_traversal_normalization():
    ctx = C.CheckContext(base_url="http://t.local/", routes=[],
                         fetch=lambda *a, **k: None,
                         exclude_paths=("/logout.php",))
    assert C._excluded_route({"path": "/../../logout.php"}, ctx)
    assert C._excluded_route({"path": "/../../../logout.php"}, ctx)
    assert C._excluded_route({"path": "logout.php"}, ctx)
    assert not C._excluded_route({"path": "/vulnerabilities/sqli"}, ctx)


# ---------------------------------------------------------------------------
# Open redirect
# ---------------------------------------------------------------------------

def test_open_redirect_positive_and_negative():
    def pos(url, m, d, h):
        if "evil.test" in url:
            return _resp(302, "", {"location": "https://evil.test/steal"})
        return _resp(200, "home")
    hits = [f for f in C.run_checks(_ctx([_route("/login")], FakeFetch(pos)))["findings"]
            if f["check"] == "dast.open_redirect"]
    assert hits

    neg = C.run_checks(_ctx([_route("/login")], FakeFetch(
        lambda u, m, d, h: _resp(200, "home"))))
    assert not [f for f in neg["findings"] if f["check"] == "dast.open_redirect"]


def test_redirect_target_follows_same_origin_only():
    """Transport decision behind default_probe_fetch: same-host 3xx hops
    are followed (Apache's trailing-slash 301 canonicalization must not
    stub the probe), cross-origin 3xx stay observable as the
    open-redirect signal."""
    base = "http://t.local/"
    # same host, relative Location -> followed
    nxt = C._redirect_target(
        301, {"location": "/vulnerabilities/sqli/?id=1"},
        "http://t.local/vulnerabilities/sqli?id=1", base)
    assert nxt == "http://t.local/vulnerabilities/sqli/?id=1"
    # cross-origin -> NOT followed
    assert C._redirect_target(
        302, {"location": "https://evil.test/steal"},
        "http://t.local/go", base) is None
    # different port is a different origin -> NOT followed
    assert C._redirect_target(
        301, {"location": "http://t.local:9999/x"},
        "http://t.local/x", base) is None
    # non-3xx, missing Location, and self-redirect (loop guard)
    assert C._redirect_target(200, {"location": "/x"},
                              "http://t.local/a", base) is None
    assert C._redirect_target(301, {}, "http://t.local/a", base) is None
    assert C._redirect_target(301, {"location": "/a"},
                              "http://t.local/a", base) is None


# ---------------------------------------------------------------------------
# SSRF (non-blind canary)
# ---------------------------------------------------------------------------

def test_ssrf_positive_and_negative():
    def pos(url, m, d, h):
        if "169.254.169.254" in url:
            return _resp(200, '{"Code":"Success","AccessKeyId":"ASIA"}')
        return _resp(200, "ok")
    hits = [f for f in C.run_checks(_ctx([_route("/fetch")], FakeFetch(pos)))["findings"]
            if f["check"] == "dast.ssrf"]
    assert hits and hits[0]["confidence"] in {"likely", "confirmed"}

    neg = C.run_checks(_ctx([_route("/fetch")], FakeFetch(
        lambda u, m, d, h: _resp(200, "ok"))))
    assert not [f for f in neg["findings"] if f["check"] == "dast.ssrf"]


# ---------------------------------------------------------------------------
# XXE
# ---------------------------------------------------------------------------

def test_xxe_positive_and_negative():
    def pos(url, m, d, h):
        body = str(d or "")
        if "ENTITY" in body or (m == "POST"):
            return _resp(200, "root:x:0:0:root:/root:/bin/bash")
        return _resp(200, "ok")
    hits = [f for f in C.run_checks(_ctx([_route("/xml", method="POST",
                                                params=[])], FakeFetch(pos)))["findings"]
            if f["check"] == "dast.xxe"]
    assert hits

    neg = C.run_checks(_ctx([_route("/xml", method="POST", params=[])],
                            FakeFetch(lambda u, m, d, h: _resp(200, "ok"))))
    assert not [f for f in neg["findings"] if f["check"] == "dast.xxe"]


# ---------------------------------------------------------------------------
# Deserialization
# ---------------------------------------------------------------------------

def test_deser_positive_and_negative():
    def pos(url, m, d, h):
        if "O%3A" in url or "O:" in str(d or "") or "rO0AB" in url:
            return _resp(500, "java.io.InvalidClassException: evil")
        return _resp(200, "ok")
    hits = [f for f in C.run_checks(_ctx([_route("/obj")], FakeFetch(pos)))["findings"]
            if f["check"] == "dast.deser"]
    assert hits

    neg = C.run_checks(_ctx([_route("/obj")], FakeFetch(
        lambda u, m, d, h: _resp(200, "ok"))))
    assert not [f for f in neg["findings"] if f["check"] == "dast.deser"]


# ---------------------------------------------------------------------------
# JWT weaknesses (passive parse of observed tokens)
# ---------------------------------------------------------------------------

def test_jwt_alg_none_positive_and_hardened_negative():
    # header {"alg":"none"} base64url + empty signature
    import base64
    def b64(o):
        return base64.urlsafe_b64encode(json.dumps(o).encode()).decode().rstrip("=")
    weak = f"{b64({'alg': 'none', 'typ': 'JWT'})}.{b64({'sub': 'u1'})}."
    pos = C.run_checks(_ctx([_route("/me")], FakeFetch(
        lambda u, m, d, h: _resp(200, json.dumps({"token": weak})))))
    hits = [f for f in pos["findings"] if f["check"] == "dast.jwt_weaknesses"]
    assert hits and hits[0]["evidence"]["weakness"] == "alg_none"

    hard = f"{b64({'alg': 'RS256', 'typ': 'JWT'})}.{b64({'sub': 'u1', 'exp': 99})}.sig"
    neg = C.run_checks(_ctx([_route("/me")], FakeFetch(
        lambda u, m, d, h: _resp(200, json.dumps({"token": hard})))))
    assert not [f for f in neg["findings"] if f["check"] == "dast.jwt_weaknesses"]


# ---------------------------------------------------------------------------
# IDOR (multi-role)
# ---------------------------------------------------------------------------

def test_idor_cross_role_positive_and_negative():
    profiles = [
        AuthProfile.from_dict({"name": "user", "strategy": "cookie",
                               "config": {"cookies": {"role": "user"}}})[0],
        AuthProfile.from_dict({"name": "admin", "strategy": "cookie",
                               "config": {"cookies": {"role": "admin"}}})[0],
    ]
    sessions = build_sessions(profiles)

    def pos(url, m, d, h):
        # /docs/1 readable by BOTH roles with identical body -> IDOR-ish
        if "/docs/1" in url:
            return _resp(200, "<html>secret plan v1 exact</html>")
        return _resp(200, "ok")
    ctx = _ctx([_route("/docs/1")], FakeFetch(pos), sessions=sessions,
               role_routes={"user": ["GET /docs/1"], "admin": ["GET /docs/1"]})
    hits = [f for f in C.run_checks(ctx)["findings"] if f["check"] == "dast.idor"]
    assert hits and hits[0]["confidence"] == "likely"

    def neg(url, m, d, h):
        if "role=user" in str(h.get("Cookie", "")) or (
                "Cookie" in h and "user" in h.get("Cookie", "")):
            return _resp(200, "<html>secret plan v1 exact</html>")
        return _resp(403, "forbidden")
    ctx2 = _ctx([_route("/docs/1")], FakeFetch(neg), sessions=sessions,
                role_routes={"user": ["GET /docs/1"], "admin": ["GET /docs/1"]})
    assert not [f for f in C.run_checks(ctx2)["findings"]
                if f["check"] == "dast.idor"]


# ---------------------------------------------------------------------------
# Mass assignment (heuristic)
# ---------------------------------------------------------------------------

def test_mass_assignment_positive_and_negative():
    def pos(url, m, d, h):
        if m == "POST" and d and "is_admin" in str(d):
            return _resp(200, json.dumps({"ok": True, "is_admin": True}))
        return _resp(200, "ok")
    hits = [f for f in C.run_checks(_ctx(
        [_route("/profile", method="POST",
                params=[{"name": "name", "in": "body"}])], FakeFetch(pos))
    )["findings"] if f["check"] == "dast.mass_assignment"]
    assert hits and hits[0]["confidence"] == "heuristic"

    neg = C.run_checks(_ctx(
        [_route("/profile", method="POST", params=[{"name": "name", "in": "body"}])],
        FakeFetch(lambda u, m, d, h: _resp(400, "unknown field is_admin"))))
    assert not [f for f in neg["findings"] if f["check"] == "dast.mass_assignment"]


# ---------------------------------------------------------------------------
# Rate limit (passive observation; burst behind aggressive)
# ---------------------------------------------------------------------------

def test_rate_limit_passive_observes_429_and_burst_is_optin():
    def responder(url, m, d, h):
        return _resp(429, "rate limited", {"retry-after": "60"})
    out = C.run_checks(_ctx([_route("/login", method="POST")], FakeFetch(responder)))
    hits = [f for f in out["findings"] if f["check"] == "dast.rate_limit"]
    assert hits and hits[0]["evidence"]["observed"] == "429"

    # aggressive burst fires the configured number of requests (default off)
    calls = []
    burst_fetch = FakeFetch(lambda u, m, d, h: (_resp(200, "ok"), calls.append(1) and _resp(200, "ok"))[0])
    out2 = C.run_checks(_ctx([_route("/login", method="POST")],
                             FakeFetch(lambda u, m, d, h: _resp(200, "ok")),
                             aggressive=False))
    assert not [f for f in out2["findings"] if f["check"] == "dast.rate_limit"]


# ---------------------------------------------------------------------------
# TLS (live-only; disclosed when not live)
# ---------------------------------------------------------------------------

def test_tls_grade_disclosed_when_not_live():
    out = C.run_checks(_ctx([_route("/x")], FakeFetch(
        lambda u, m, d, h: _resp(200, "ok"))))
    assert not [f for f in out["findings"] if f["check"] == "dast.tls_grade"]
    tls = next(c for c in C.CHECKS if c["id"] == "dast.tls_grade")
    assert tls["live_only"] is True


# ---------------------------------------------------------------------------
# Evidence bounds + redaction + envelope
# ---------------------------------------------------------------------------

def test_evidence_is_bounded():
    big = "<html>" + ("A" * 20000) + "SQL syntax error near '''" + "</html>"
    out = C.run_checks(_ctx([_route("/s")], FakeFetch(
        lambda u, m, d, h: _resp(200, big))))
    for f in out["findings"]:
        assert len(f["evidence"].get("response_excerpt", "")) <= C.MAX_EVIDENCE_CHARS
        assert len(f["evidence"].get("request_url", "")) <= 2048


def test_envelope_stats_and_skips_are_machine_readable():
    out = C.run_checks(_ctx([_route("/s")], FakeFetch(
        lambda u, m, d, h: _resp(200, "ok"))))
    assert out["schema"] == C.FINDINGS_SCHEMA
    assert "by_check" in out["stats"]
    assert isinstance(out["stats"].get("skips"), list)
    assert all("reason" in s for s in out["stats"]["skips"])

def test_sqlite_error_signature_matches_modern_driver_text():
    """T-5.5 gate exposed a signature gap: better-sqlite3 (juice-shop)
    reports errors as ``SQLITE_ERROR: ...`` with NO dot, which the
    original sqlite3-dot alternative never matched.  The alternative
    is additive; no oracle exercises DAST."""
    assert C.SQLI_RE.search("Error: SQLITE_ERROR: incomplete input")
    assert C.SQLI_RE.search("sqlite3.OperationalError: no such table")
    assert not C.SQLI_RE.search("plain 200 response")
