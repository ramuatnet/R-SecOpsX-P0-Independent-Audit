"""T-5.4 OOB listener: Interactsh-style correlation for blind SSRF/XXE/RCE.

Everything protocol-shaped is pure and byte-level testable without
sockets: token minting, DNS query parsing/response building, the HTTP
callback handler, the interaction store, and the client's confirm loop
(injected clock/sleep).  The only socket-bearing pieces are the two
live servers, which the suite never starts (disclosed, like the T-5.3
live TLS path).

Integration pins: with a client configured, blind probes mint tokens;
a callback arriving for a token creates (or promotes to ``confirmed``)
exactly the owning route's finding; no callback -> nothing changes.
"""
import json

from analysis.dast import checks as C
from analysis.dast import oob as O


def _resp(status=200, body="<html>ok</html>", headers=None):
    return C.ProbeResponse(url="", status=status, body=body,
                           headers=headers or {})


def _route(path="/fetch", method="GET", params=None):
    from analysis.dast.model import make_entry, merge_entries
    e = make_entry(method=method, path=path, kind="openapi", ref="f",
                   params=params or [{"name": "q", "in": "query"}])
    return merge_entries([e])[0]


class FakeFetch:
    def __init__(self, responder):
        self.responder = responder
        self.calls = []

    def __call__(self, url, timeout_s, user_agent, headers=None, data=None,
                 method="GET"):
        self.calls.append({"url": url, "method": method, "data": data})
        return self.responder(url, method, data, headers or {})


FIXED_RNG = lambda n: b"\xab" * n          # noqa: E731 - deterministic token
FIXED_TOKEN = "ab" * 16                    # hexlify(b"\xab" * 16)


def _client(**kw):
    kw.setdefault("public_host", "oob.example.test")
    kw.setdefault("rng", FIXED_RNG)
    kw.setdefault("now", lambda: 1000.0)
    kw.setdefault("sleep", lambda s: None)
    return O.OOBClient(**kw)


def _ctx(routes, fetch, **kw):
    kw.setdefault("rate_limit_s", 0)
    return C.CheckContext(base_url="http://t.local/", routes=routes,
                          fetch=fetch, **kw)


def _record_http(client, path="/ssrf", body="", host=None, method="GET"):
    """Simulate the vulnerable server calling back, via the pure handler."""
    token = FIXED_TOKEN
    client.store.issue(token)          # mint allowlist gate
    host = host or f"{token}.oob.example.test"
    status, _ = O.handle_callback(
        client.store, method=method, path=path, host=host,
        headers={"User-Agent": "curl/8.0", "X-Secret": "leak",
                 "Content-Type": "text/plain"},
        body=body, client_ip="203.0.113.7", now=client.now)
    assert status == 200


# ---------------------------------------------------------------------------
# Mint / payload construction
# ---------------------------------------------------------------------------

def test_mint_is_deterministic_with_injected_rng():
    a, tok_a = _client().mint("ssrf")
    b, tok_b = _client().mint("ssrf")
    assert tok_a == tok_b == FIXED_TOKEN
    assert a == b
    assert a == f"http://{FIXED_TOKEN}.oob.example.test/ssrf"


def test_payload_kinds_embed_token_host_and_distinct_paths():
    c = _client()
    urls = {k: c.mint(k)[0] for k in ("ssrf", "xxe", "rce")}
    assert all(FIXED_TOKEN in u for u in urls.values())
    assert all("oob.example.test" in u for u in urls.values())
    assert len({u.rsplit("/", 1)[-1] for u in urls.values()}) == 3


# ---------------------------------------------------------------------------
# DNS wire format (pure bytes)
# ---------------------------------------------------------------------------

def _dns_query(name: str) -> bytes:
    q = b""
    for label in name.split("."):
        q += bytes([len(label)]) + label.encode()
    q += b"\x00"
    return (b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
            + q + b"\x00\x01\x00\x01")


def test_parse_dns_qname():
    q = _dns_query(f"{FIXED_TOKEN}.oob.example.test")
    assert O.parse_dns_qname(q) == f"{FIXED_TOKEN}.oob.example.test"


def test_build_dns_response_echoes_id_flags_and_answers():
    q = _dns_query(f"{FIXED_TOKEN}.oob.example.test")
    resp = O.build_dns_response(q)
    assert resp[0:2] == b"\x12\x34"          # transaction id echoed
    assert resp[2] & 0x80                    # QR bit set
    assert resp[6:8] == b"\x00\x01"          # one answer
    assert b"\x7f\x00\x00\x01" in resp       # 127.0.0.1
    # answer name uses the compression pointer to the question
    assert b"\xc0\x0c" in resp


# ---------------------------------------------------------------------------
# HTTP callback handler (pure)
# ---------------------------------------------------------------------------

def test_handle_callback_records_interaction_from_host_header():
    store = O.InteractionStore(now=lambda: 1000.0)
    store.issue(FIXED_TOKEN)
    status, _ = O.handle_callback(
        store, method="GET", path="/xxe",
        host=f"{FIXED_TOKEN}.oob.example.test:8080",
        headers={"User-Agent": "curl/8.0"}, body="cb", client_ip="1.2.3.4",
        now=lambda: 1000.0)
    assert status == 200
    inter = store.drain(FIXED_TOKEN)
    assert len(inter) == 1
    i = inter[0]
    assert i["proto"] == "http" and i["token"] == FIXED_TOKEN
    assert i["path"] == "/xxe" and i["client_ip"] == "1.2.3.4"
    assert i["ts"] == 1000.0


def test_handle_callback_rejects_unknown_token():
    store = O.InteractionStore()
    status, _ = O.handle_callback(
        store, host="deadbeef" * 4 + ".oob.example.test",
        headers={}, body="", now=lambda: 1.0)
    assert status == 404
    assert store.drain(FIXED_TOKEN) == []


def test_interaction_stores_bounded_body_and_header_subset():
    store = O.InteractionStore()
    store.issue(FIXED_TOKEN)
    O.handle_callback(
        store, host=f"{FIXED_TOKEN}.oob.example.test", path="/",
        headers={"User-Agent": "u", "X-Secret": "leak-me",
                 "Cookie": "session=abc", "Content-Type": "text/plain"},
        body="B" * 10000, now=lambda: 1.0)
    i = store.drain(FIXED_TOKEN)[0]
    assert len(i["body"]) <= O.MAX_INTERACTION_BODY
    assert "X-Secret" not in i["headers"] and "Cookie" not in i["headers"]
    assert set(i["headers"]) <= set(O.INTERACTION_HEADER_ALLOW)


def test_store_caps_interactions_per_token():
    store = O.InteractionStore(max_per_token=3, now=lambda: 1.0)
    for n in range(6):
        store.record({"token": FIXED_TOKEN, "proto": "http", "ts": float(n),
                      "host": "h", "path": "/", "method": "GET",
                      "client_ip": "", "body": "", "headers": {}})
    kept = store.peek(FIXED_TOKEN)
    assert len(kept) == 3 and kept[-1]["ts"] == 5.0
    assert store.dropped == 3


def test_drain_is_consumptive():
    store = O.InteractionStore()
    store.record({"token": FIXED_TOKEN, "proto": "dns", "ts": 1.0,
                  "host": "h", "path": "", "method": "", "client_ip": "",
                  "body": "", "headers": {}})
    assert len(store.drain(FIXED_TOKEN)) == 1
    assert store.drain(FIXED_TOKEN) == []


# ---------------------------------------------------------------------------
# Client confirm loop (injected clock/sleep)
# ---------------------------------------------------------------------------

def test_confirm_returns_interaction_immediately_when_present():
    c = _client()
    _record_http(c)
    i = c.confirm(FIXED_TOKEN, timeout=0)
    assert i and i["proto"] == "http"


def test_confirm_times_out_without_interaction_and_never_sleeps_forever():
    c = _client()
    clock = {"t": 1000.0}
    sleeps = []
    c.now = lambda: clock["t"]
    c.sleep = lambda s: (sleeps.append(s), clock.update(t=clock["t"] + s))
    assert c.confirm(FIXED_TOKEN, timeout=0.2) is None
    assert sleeps and sum(sleeps) <= 0.2 + 0.05


def test_dns_callback_also_confirms():
    c = _client()
    c.mint("ssrf")                          # issues FIXED_TOKEN in the store
    q = _dns_query(f"{FIXED_TOKEN}.oob.example.test")
    name = O.parse_dns_qname(q)
    O.handle_dns_query(c.store, qname=name, client_ip="10.0.0.1",
                       now=c.now)
    i = c.confirm(FIXED_TOKEN, timeout=0)
    assert i and i["proto"] == "dns"


# ---------------------------------------------------------------------------
# run_checks integration: blind -> confirmed; negative controls
# ---------------------------------------------------------------------------

def test_ssrf_blind_confirmed_via_oob_callback():
    store = O.InteractionStore(now=lambda: 1000.0)
    client = _client(store=store)

    def responder(url, method, data, headers):
        # the vulnerable target fetches whatever URL we injected; this app
        # is vulnerable to SSRF only, so it calls back on the ssrf kind:
        if ".oob." in url and "/ssrf" in url:
            import re
            m = re.search(r"([0-9a-f]{32})\.oob\.", url)
            if m:
                O.handle_callback(store, host=f"{m.group(1)}.oob.example.test",
                                  path="/ssrf", headers={}, body="",
                                  client_ip="203.0.113.7", now=lambda: 1000.0)
        return _resp(200, "plain response, no signature")

    out = C.run_checks(_ctx([_route("/fetch")], FakeFetch(responder), oob=client))
    ssrf = [f for f in out["findings"] if f["check"] == "dast.ssrf"]
    assert len(ssrf) == 1
    assert ssrf[0]["confidence"] == "confirmed"
    ev = ssrf[0]["evidence"]["oob_interaction"]
    assert ev["proto"] == "http" and ev["host"].startswith(FIXED_TOKEN)
    assert out["stats"]["oob_confirmed"] == 1


def test_ssrf_without_callback_creates_nothing():
    client = _client()
    out = C.run_checks(_ctx(
        [_route("/fetch")], FakeFetch(lambda u, m, d, h: _resp(200, "ok")),
        oob=client))
    assert not [f for f in out["findings"] if f["check"] == "dast.ssrf"]
    assert out["stats"]["oob_confirmed"] == 0


def test_signature_finding_promoted_to_confirmed_by_callback():
    store = O.InteractionStore(now=lambda: 1000.0)
    client = _client(store=store)

    def responder(url, method, data, headers):
        if ".oob." in url:
            O.handle_callback(store, host=f"{FIXED_TOKEN}.oob.example.test",
                              path="/ssrf", headers={}, body="",
                              client_ip="", now=lambda: 1000.0)
            return _resp(200, "ok")
        return _resp(200, '{"AccessKeyId": "ASIA"}')   # signature hit

    out = C.run_checks(_ctx([_route("/fetch")], FakeFetch(responder), oob=client))
    ssrf = [f for f in out["findings"] if f["check"] == "dast.ssrf"]
    assert len(ssrf) == 1
    assert ssrf[0]["confidence"] == "confirmed"       # was "likely"
    assert "signature" in ssrf[0]["evidence"]
    assert "oob_interaction" in ssrf[0]["evidence"]


def test_cmdi_blind_confirmed_via_oob_callback():
    store = O.InteractionStore(now=lambda: 1000.0)
    client = _client(store=store)

    def responder(url, method, data, headers):
        if ".oob." in url:
            O.handle_callback(store, host=f"{FIXED_TOKEN}.oob.example.test",
                              path="/rce", headers={}, body="",
                              client_ip="", now=lambda: 1000.0)
        return _resp(200, "pong")

    out = C.run_checks(_ctx([_route("/ping")], FakeFetch(responder), oob=client))
    cmdi = [f for f in out["findings"] if f["check"] == "dast.cmdi"]
    assert len(cmdi) == 1 and cmdi[0]["confidence"] == "confirmed"


def test_xxe_blind_confirmed_via_oob_callback():
    store = O.InteractionStore(now=lambda: 1000.0)
    client = _client(store=store)

    def responder(url, method, data, headers):
        if ".oob." in str(data or ""):
            O.handle_callback(store, host=f"{FIXED_TOKEN}.oob.example.test",
                              path="/xxe", headers={}, body="",
                              client_ip="", now=lambda: 1000.0)
        return _resp(200, "no file signature here")

    out = C.run_checks(_ctx(
        [_route("/xml", method="POST", params=[])], FakeFetch(responder),
        oob=client))
    xxe = [f for f in out["findings"] if f["check"] == "dast.xxe"]
    assert len(xxe) == 1 and xxe[0]["confidence"] == "confirmed"


def test_without_oob_context_behavior_is_unchanged():
    out = C.run_checks(_ctx(
        [_route("/fetch")],
        FakeFetch(lambda u, m, d, h: _resp(200, '{"AccessKeyId": "ASIA"}'))))
    ssrf = [f for f in out["findings"] if f["check"] == "dast.ssrf"]
    assert ssrf and ssrf[0]["confidence"] == "likely"   # no promotion path
    assert "oob_interaction" not in ssrf[0]["evidence"]


def test_oob_run_is_deterministic_with_fixed_rng():
    def responder(url, method, data, headers):
        return _resp(200, "ok")
    a = C.run_checks(_ctx([_route("/fetch")], FakeFetch(responder),
                          oob=_client()))
    b = C.run_checks(_ctx([_route("/fetch")], FakeFetch(responder),
                          oob=_client()))
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


def test_cli_mint_prints_token_and_urls(capsys):
    rc = O.main(["mint", "--public-host", "oob.example.test"])
    assert rc == 0
    doc = json.loads(capsys.readouterr().out)
    assert len(doc["token"]) == 32 and doc["urls"]["ssrf"].startswith("http://")


def test_oob_mode_keeps_post_route_within_budget_headroom():
    """T-5.3 fit every check on a single-target POST route in 15 probes
    (cap 16).  OOB prepends +3 probes (cmdi/ssrf/xxe), so the effective
    cap must grow by a bounded headroom when OOB is enabled -- otherwise
    idor/mass silently fall off routes that fit without OOB."""
    from analysis.dast.auth import AuthProfile, build_sessions
    from analysis.dast.model import make_entry, merge_entries

    profiles = [
        AuthProfile.from_dict({"name": "user", "strategy": "cookie",
                               "config": {"cookies": {"role": "user"}}})[0],
        AuthProfile.from_dict({"name": "admin", "strategy": "cookie",
                               "config": {"cookies": {"role": "admin"}}})[0],
    ]
    sessions = build_sessions(profiles)
    e = make_entry(method="POST", path="/w", kind="openapi", ref="f",
                   params=[{"name": "a", "in": "body"}])
    route = merge_entries([e])[0]

    def responder(u, m, d, h):
        # echo only the mass-injected field (so mass emits a finding);
        # everything else (incl. identical idor bodies) gets "ok"
        if d and "is_admin" in str(d):
            return _resp(200, '{"is_admin": true}')
        return _resp(200, "ok")

    out = C.run_checks(C.CheckContext(
        base_url="http://t.local/", routes=[route],
        fetch=FakeFetch(responder),
        rate_limit_s=0, oob=_client(), sessions=sessions,
        role_routes={"user": ["POST /w"], "admin": ["POST /w"]}))
    budget = [s for s in out["stats"]["skips"]
              if s["reason"] == "budget_exhausted"]
    assert budget == [], budget
    # every check must have had its chance (mass + idor are the tail)
    assert out["stats"]["by_check"].get("dast.mass_assignment", 0) == 1
    assert out["stats"]["by_check"].get("dast.idor", 0) == 1
