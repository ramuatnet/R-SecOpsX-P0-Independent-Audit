"""T-9.1 serve authentication + RBAC + audit log (task.md section 12).

Red-first contracts pinned BEFORE analysis/serve/auth.py exists:

* roles -- viewer < editor < admin; required_role: /v1/health is OPEN
  (liveness leaks nothing), GET = viewer, POST /v1/jobs = editor,
  POST /v1/schedules|/v1/webhooks = admin, everything else (DELETE)
  = admin;
* static bearer tokens (offline, operator-issued, compared with
  hmac.compare_digest) + OIDC-style JWT HS256 validation (stdlib hmac,
  no third-party JWT library) -- the offline-substitutable subset of
  OIDC; SAML/XML-DSig + discovery/JWKS round-trips are NOT adopted
  (greppable disclosure in auth.py);
* loud config errors: AuthInvalid.reason strings for every authoring
  mistake (a config that cannot be interpreted never runs);
* bind guard: non-loopback host WITHOUT auth refuses to start
  (ValueError auth_required_for_non_loopback) -- exposing the API
  beyond localhost unauthenticated would be the hole api.py:156 warns
  about;
* audit log: injectable audit_fn receives one fixed-shape entry per
  request (allowed AND denied), CLI --audit-log appends canonical
  JSONL with flush-per-line; works with or without auth;
* flag-off: no --auth-file/--audit-log/--serve-host => t82 behaviour
  byte-identical (t82's own tests stay green unchanged);
* rc: bad auth file or non-loopback-without-auth => rc 2 usage.
"""
import base64
import hashlib
import hmac
import json
import pathlib
import subprocess
import sys
import time
import urllib.error
import urllib.request

import pytest

import analysis.serve.auth as serve_auth
from analysis.serve.auth import (
    ROLE_RANK,
    AuthConfig,
    AuthInvalid,
    audit_entry,
    load_auth_file,
    required_role,
    verify,
)

REPO = pathlib.Path(__file__).resolve().parent.parent

_BANNED_TOP = {"urllib", "socket", "requests", "boto3", "http", "os",
               "subprocess"}

_NOW = 1_800_000_000.0   # fixed clock for pure verify() tests


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _jwt(claims, secret="hs256-secret", alg="HS256", sig_secret=None):
    head = _b64(json.dumps({"alg": alg, "typ": "JWT"}).encode())
    payload = _b64(json.dumps(claims).encode())
    sign_key = (sig_secret if sig_secret is not None else secret).encode()
    sig = _b64(hmac.new(sign_key, f"{head}.{payload}".encode(),
                        hashlib.sha256).digest())
    return f"{head}.{payload}.{sig}"


def _auth_doc(**over):
    doc = {
        "tokens": [
            {"name": "viewer1", "token": "tok-viewer", "role": "viewer"},
            {"name": "editor1", "token": "tok-editor", "role": "editor"},
            {"name": "admin1", "token": "tok-admin", "role": "admin"},
        ],
        "jwt": {"secret": "hs256-secret",
                "issuer": "https://idp.test"},
    }
    doc.update(over)
    return doc


def _write_auth(tmp_path, doc, name="rsx_t91_auth.json"):
    path = tmp_path / name
    if isinstance(doc, str):
        path.write_text(doc, encoding="utf-8")
    else:
        path.write_text(json.dumps(doc), encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# A. auth model: roles, config loading, verification
# ---------------------------------------------------------------------------


def test_role_vocabulary_and_ranks():
    assert ROLE_RANK == {"viewer": 1, "editor": 2, "admin": 3}


def test_required_role_matrix():
    assert required_role("GET", "/v1/health") is None      # liveness open
    assert required_role("GET", "/v1/jobs") == "viewer"
    assert required_role("GET", "/v1/jobs/x") == "viewer"
    assert required_role("GET", "/v1/events") == "viewer"
    assert required_role("GET", "/v1/schedules") == "viewer"
    assert required_role("POST", "/v1/jobs") == "editor"
    assert required_role("POST", "/v1/schedules") == "admin"
    assert required_role("POST", "/v1/webhooks") == "admin"
    assert required_role("DELETE", "/v1/jobs/x") == "admin"


def test_load_auth_file_happy(tmp_path):
    cfg = load_auth_file(_write_auth(tmp_path, _auth_doc()))
    assert isinstance(cfg, AuthConfig)
    assert [t["name"] for t in cfg.tokens] == ["viewer1", "editor1",
                                               "admin1"]
    assert cfg.jwt_secret == "hs256-secret"
    assert cfg.jwt_issuer == "https://idp.test"
    assert cfg.jwt_audience is None


def test_load_auth_file_errors_are_reasons(tmp_path):
    cases = [
        ("missing", None, "auth_file_unreadable"),
        ("not-object", "[]", "auth_not_object"),
        ("tokens-type", {"tokens": {}}, "auth_tokens_invalid"),
        ("item-type", {"tokens": ["x"]}, "token_not_object:0"),
        ("no-name", {"tokens": [{"token": "t", "role": "viewer"}]},
         "token_missing:0:name"),
        ("no-token", {"tokens": [{"name": "a", "role": "viewer"}]},
         "token_missing:0:token"),
        ("no-role", {"tokens": [{"name": "a", "token": "t"}]},
         "token_missing:0:role"),
        ("bad-role", {"tokens": [{"name": "a", "token": "t",
                                  "role": "root"}]},
         "token_bad_role:0:root"),
        ("jwt-type", {"jwt": "x"}, "jwt_invalid"),
        ("jwt-no-secret", {"jwt": {}}, "jwt_secret_missing"),
        ("jwt-issuer-type", {"jwt": {"secret": "s", "issuer": 5}},
         "jwt_bad_field:issuer"),
        ("bad-json", "{oops", "auth_unreadable_json"),
    ]
    for label, doc, reason in cases:
        if doc is None:
            path = tmp_path / "rsx_t91_absent.json"
        else:
            path = _write_auth(tmp_path, doc, f"rsx_t91_{label}.json")
        with pytest.raises(AuthInvalid) as ei:
            load_auth_file(path)
        assert ei.value.reason == reason, (label, ei.value.reason)


def test_static_token_verification(tmp_path):
    cfg = load_auth_file(_write_auth(tmp_path, _auth_doc()))
    principal, reason = verify(cfg, "Bearer tok-viewer", now=_NOW)
    assert reason is None
    assert principal == {"actor": "viewer1", "role": "viewer"}
    # failures carry machine reasons, never exceptions
    assert verify(cfg, None, now=_NOW) == (None, "missing_credentials")
    assert verify(cfg, "", now=_NOW) == (None, "missing_credentials")
    assert verify(cfg, "Bearer ", now=_NOW) == (None, "missing_credentials")
    assert verify(cfg, "Basic dXNlcg==", now=_NOW) == \
        (None, "bad_credentials_scheme")
    assert verify(cfg, "Bearer nope", now=_NOW) == \
        (None, "invalid_credentials")


def test_static_match_wins_over_jwt(tmp_path):
    # the same string never has to be a JWT if it is a configured token
    cfg = load_auth_file(_write_auth(tmp_path, _auth_doc(
        tokens=[{"name": "ci", "token": "tok-editor", "role": "editor"}])))
    principal, reason = verify(cfg, "Bearer tok-editor", now=_NOW)
    assert reason is None
    assert principal == {"actor": "ci", "role": "editor"}


def test_empty_config_denies_everything(tmp_path):
    cfg = load_auth_file(_write_auth(tmp_path, {}))
    assert verify(cfg, "Bearer anything", now=_NOW) == \
        (None, "invalid_credentials")


def test_jwt_hs256_valid_carries_role_claim(tmp_path):
    cfg = load_auth_file(_write_auth(tmp_path, _auth_doc()))
    token = _jwt({"sub": "alice", "role": "admin",
                  "iss": "https://idp.test", "exp": _NOW + 600},
                 secret="hs256-secret")
    principal, reason = verify(cfg, f"Bearer {token}", now=_NOW)
    assert reason is None
    assert principal == {"actor": "alice", "role": "admin"}


def test_jwt_without_role_claim_defaults_to_viewer(tmp_path):
    # IdPs don't mint our role claim -- least privilege until mapped
    cfg = load_auth_file(_write_auth(tmp_path, _auth_doc()))
    token = _jwt({"sub": "bob", "iss": "https://idp.test",
                  "exp": _NOW + 600}, secret="hs256-secret")
    principal, reason = verify(cfg, f"Bearer {token}", now=_NOW)
    assert reason is None
    assert principal == {"actor": "bob", "role": "viewer"}


def test_jwt_expired_is_a_dedicated_reason(tmp_path):
    cfg = load_auth_file(_write_auth(tmp_path, _auth_doc()))
    token = _jwt({"sub": "alice", "exp": _NOW - 1},
                 secret="hs256-secret")
    assert verify(cfg, f"Bearer {token}", now=_NOW) == \
        (None, "jwt_expired")


def test_jwt_not_yet_valid(tmp_path):
    cfg = load_auth_file(_write_auth(tmp_path, _auth_doc()))
    token = _jwt({"sub": "alice", "exp": _NOW + 600,
                  "nbf": _NOW + 300}, secret="hs256-secret")
    assert verify(cfg, f"Bearer {token}", now=_NOW) == \
        (None, "jwt_not_yet_valid")


def test_jwt_alg_none_rejected(tmp_path):
    cfg = load_auth_file(_write_auth(tmp_path, _auth_doc()))
    head = _b64(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    payload = _b64(json.dumps({"sub": "mallory", "exp": _NOW + 600}).encode())
    token = f"{head}.{payload}."
    assert verify(cfg, f"Bearer {token}", now=_NOW) == \
        (None, "invalid_credentials")


def test_jwt_tampered_payload_rejected(tmp_path):
    cfg = load_auth_file(_write_auth(tmp_path, _auth_doc()))
    good = _jwt({"sub": "alice", "exp": _NOW + 600},
                secret="hs256-secret")
    head, _, _ = good.partition(".")
    forged = _b64(json.dumps(
        {"sub": "alice", "role": "admin", "exp": _NOW + 60000}).encode())
    assert verify(cfg, f"Bearer {head}.{forged}.fakesig", now=_NOW) == \
        (None, "invalid_credentials")


def test_jwt_wrong_secret_rejected(tmp_path):
    cfg = load_auth_file(_write_auth(tmp_path, _auth_doc()))
    token = _jwt({"sub": "alice", "exp": _NOW + 600},
                 secret="other-secret")
    assert verify(cfg, f"Bearer {token}", now=_NOW) == \
        (None, "invalid_credentials")


def test_jwt_missing_exp_rejected(tmp_path):
    cfg = load_auth_file(_write_auth(tmp_path, _auth_doc()))
    token = _jwt({"sub": "alice"}, secret="hs256-secret")
    assert verify(cfg, f"Bearer {token}", now=_NOW) == \
        (None, "invalid_credentials")


def test_jwt_issuer_and_audience_checks(tmp_path):
    cfg = load_auth_file(_write_auth(tmp_path, _auth_doc()))
    wrong_iss = _jwt({"sub": "a", "iss": "https://evil",
                      "exp": _NOW + 600}, secret="hs256-secret")
    assert verify(cfg, f"Bearer {wrong_iss}", now=_NOW) == \
        (None, "invalid_credentials")

    aud_cfg = load_auth_file(_write_auth(
        tmp_path, _auth_doc(jwt={"secret": "hs256-secret",
                                 "audience": "serve-api"}),
        name="rsx_t91_auth_aud.json"))
    good_aud = _jwt({"sub": "a", "aud": ["serve-api", "other"],
                     "exp": _NOW + 600}, secret="hs256-secret")
    principal, reason = verify(aud_cfg, f"Bearer {good_aud}", now=_NOW)
    assert reason is None and principal["actor"] == "a"
    bad_aud = _jwt({"sub": "a", "aud": ["elsewhere"],
                    "exp": _NOW + 600}, secret="hs256-secret")
    assert verify(aud_cfg, f"Bearer {bad_aud}", now=_NOW) == \
        (None, "invalid_credentials")


def test_jwt_rejected_when_not_configured(tmp_path):
    cfg = load_auth_file(_write_auth(
        tmp_path, {"tokens": [{"name": "v", "token": "t",
                               "role": "viewer"}]}))
    token = _jwt({"sub": "a", "exp": _NOW + 600}, secret="hs256-secret")
    assert verify(cfg, f"Bearer {token}", now=_NOW) == \
        (None, "invalid_credentials")


def test_garbage_bearer_tokens_rejected(tmp_path):
    cfg = load_auth_file(_write_auth(tmp_path, _auth_doc()))
    for junk in ("abc", "a.b.c", "....", "a.b.c.d.e"):
        assert verify(cfg, f"Bearer {junk}", now=_NOW) == \
            (None, "invalid_credentials"), junk


# ---------------------------------------------------------------------------
# B. serve() wiring: bind guard + audit entry shape
# ---------------------------------------------------------------------------


def test_serve_refuses_non_loopback_without_auth():
    from analysis.serve.api import serve
    with pytest.raises(ValueError,
                       match="auth_required_for_non_loopback"):
        serve(None, host="0.0.0.0")


def test_audit_entry_has_a_fixed_shape():
    entry = audit_entry(method="POST", path="/v1/jobs", status=403,
                        decision="denied", actor="viewer1", role="viewer",
                        reason="insufficient_role", ts=123.5)
    assert set(entry) == {"actor", "decision", "method", "path", "reason",
                          "role", "status", "ts"}
    assert entry["decision"] in ("allowed", "denied")
    # canonical single line, byte-stable
    assert json.dumps(entry, sort_keys=True, ensure_ascii=True) == (
        '{"actor": "viewer1", "decision": "denied", "method": "POST", '
        '"path": "/v1/jobs", "reason": "insufficient_role", '
        '"role": "viewer", "status": 403, "ts": 123.5}')


# ---------------------------------------------------------------------------
# C. live smoke: CLI serve with --auth-file + --audit-log
# ---------------------------------------------------------------------------


def _wait_ready(proc, ready, timeout=30):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if ready.exists() and ready.read_text(encoding="utf-8").strip():
            return ready.read_text(encoding="utf-8").strip()
        if proc.poll() is not None:
            raise AssertionError(
                f"serve exited early: {proc.stderr.read()[:400]}")
        time.sleep(0.1)
    raise AssertionError("serve never announced its address")


def _http(base, path, method="GET", token=None, body=None):
    headers = {}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(base + path, method=method, data=data,
                                 headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as he:
        raw = he.read()
        return he.code, (json.loads(raw) if raw else {})


def _popen_serve(tmp_path, extra, tag):
    db = tmp_path / f"rsx_t91_{tag}.db"
    ready = tmp_path / f"rsx_t91_{tag}_ready.txt"
    proc = subprocess.Popen(
        [sys.executable, "-m", "analysis.serve.connect",
         "--db", str(db), "--serve", "--serve-port", "0",
         "--serve-ready-file", str(ready), *extra],
        cwd=REPO, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True)
    return proc, ready


def test_cli_serve_authz_live_smoke(tmp_path):
    auth = _write_auth(tmp_path, _auth_doc())
    proc, ready = _popen_serve(tmp_path,
                               ["--auth-file", str(auth)], "authz")
    try:
        base = f"http://{_wait_ready(proc, ready)}"
        # health stays open (liveness) even with auth enforced
        status, doc = _http(base, "/v1/health")
        assert status == 200 and doc["status"] == "ok"
        # no credentials -> 401 with machine reason
        status, doc = _http(base, "/v1/jobs")
        assert (status, doc["error"], doc["reason"]) == \
            (401, "unauthorized", "missing_credentials")
        # wrong token -> 401 invalid_credentials
        status, doc = _http(base, "/v1/jobs", token="nope")
        assert (status, doc["error"], doc["reason"]) == \
            (401, "unauthorized", "invalid_credentials")
        # viewer: read ok, write refused with the required role named
        status, doc = _http(base, "/v1/jobs", token="tok-viewer")
        assert status == 200 and "jobs" in doc
        status, doc = _http(base, "/v1/jobs", method="POST",
                            token="tok-viewer",
                            body={"target": "app/"})
        assert (status, doc["error"], doc["required"]) == \
            (403, "forbidden", "editor")
        # editor: can enqueue jobs, cannot touch config surface
        status, doc = _http(base, "/v1/jobs", method="POST",
                            token="tok-editor", body={"target": "app/"})
        assert status == 201 and "job" in doc
        status, doc = _http(base, "/v1/webhooks", method="POST",
                            token="tok-editor",
                            body={"url": "http://127.0.0.1:9/hook"})
        assert (status, doc["error"], doc["required"]) == \
            (403, "forbidden", "admin")
        # admin: config surface opens
        status, doc = _http(base, "/v1/webhooks", method="POST",
                            token="tok-admin",
                            body={"url": "http://127.0.0.1:9/hook"})
        assert status == 201 and "webhook" in doc
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()


def test_cli_serve_jwt_live_and_audit_log(tmp_path):
    auth = _write_auth(tmp_path, _auth_doc())
    audit = tmp_path / "rsx_t91_audit.jsonl"
    proc, ready = _popen_serve(
        tmp_path,
        ["--auth-file", str(auth), "--audit-log", str(audit)], "jwt")
    try:
        base = f"http://{_wait_ready(proc, ready)}"
        # health is open -- and the audit log still records it (actor
        # null: anonymous liveness is a legitimate first-class event)
        status, _ = _http(base, "/v1/health")
        assert status == 200
        now = int(time.time())
        # OIDC-style bearer from the configured issuer, no role claim
        token = _jwt({"sub": "svc-1", "iss": "https://idp.test",
                      "exp": now + 600}, secret="hs256-secret")
        status, _ = _http(base, "/v1/jobs", token=token)
        assert status == 200
        # default viewer role cannot write
        status, doc = _http(base, "/v1/jobs", method="POST", token=token,
                            body={"target": "app/"})
        assert (status, doc["error"]) == (403, "forbidden")
        # expired JWT -> 401 jwt_expired
        expired = _jwt({"sub": "svc-1", "iss": "https://idp.test",
                        "exp": now - 10}, secret="hs256-secret")
        status, doc = _http(base, "/v1/jobs", token=expired)
        assert (status, doc["error"], doc["reason"]) == \
            (401, "unauthorized", "jwt_expired")
        # one unauthenticated probe for a denied audit row
        _http(base, "/v1/jobs")
        time.sleep(0.3)          # flush-per-line already; let threads land
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()

    lines = [json.loads(l) for l in
             audit.read_text(encoding="utf-8").splitlines() if l.strip()]
    assert lines, "audit log empty"
    for entry in lines:
        assert set(entry) == {"actor", "decision", "method", "path",
                              "reason", "role", "status", "ts"}
    decisions = {(e["decision"], e["reason"]) for e in lines}
    assert ("denied", "missing_credentials") in decisions
    assert ("allowed", None) in decisions
    jwt_allowed = [e for e in lines
                   if e["decision"] == "allowed" and e["actor"] == "svc-1"]
    assert jwt_allowed and jwt_allowed[0]["path"] == "/v1/jobs"
    health = [e for e in lines if e["path"] == "/v1/health"]
    assert health and health[0]["actor"] is None


def test_cli_non_loopback_without_auth_is_usage_error(tmp_path):
    r = subprocess.run(
        [sys.executable, "-m", "analysis.serve.connect",
         "--db", ":memory:", "--serve", "--serve-host", "0.0.0.0"],
        capture_output=True, text=True, cwd=REPO, timeout=60)
    assert r.returncode == 2
    assert "auth_required_for_non_loopback" in r.stderr


# ---------------------------------------------------------------------------
# D. CLI flags
# ---------------------------------------------------------------------------


def test_cli_help_lists_t91_flags():
    r = subprocess.run(
        [sys.executable, "-m", "analysis.serve.connect", "--help"],
        capture_output=True, text=True, cwd=REPO, timeout=60)
    assert r.returncode == 0
    for flag in ("--auth-file", "--audit-log", "--serve-host"):
        assert flag in r.stdout


def test_cli_bad_auth_file_is_usage_error(tmp_path):
    bad = tmp_path / "rsx_t91_bad.json"
    bad.write_text("[]", encoding="utf-8")
    r = subprocess.run(
        [sys.executable, "-m", "analysis.serve.connect",
         "--auth-file", str(bad)],
        capture_output=True, text=True, cwd=REPO, timeout=60)
    assert r.returncode == 2
    assert "auth error: auth_not_object" in r.stderr


def test_cli_auth_file_without_serve_is_validated_then_ignored(tmp_path):
    auth = _write_auth(tmp_path, _auth_doc())
    out = tmp_path / "rsx_t91_doc.json"
    r = subprocess.run(
        [sys.executable, "-m", "analysis.serve.connect",
         "--auth-file", str(auth), "--as-of", "2026-10-31T00:00:00",
         "--out", str(out)],
        capture_output=True, text=True, cwd=REPO, timeout=60)
    assert r.returncode == 0, r.stderr
    doc = json.loads(out.read_text(encoding="utf-8"))
    # validated (rc 0) but no auth bookkeeping leaks into the zero-I/O doc
    assert sorted(s["reason"] for s in doc["skips"]) == [
        "not_provided:db", "not_provided:enqueue", "not_provided:webhooks"]
    assert "auth" not in doc


# ---------------------------------------------------------------------------
# E. pins: disclosure, package surface, offline import pin
# ---------------------------------------------------------------------------


def test_oidc_saml_disclosure_is_one_greppable_line():
    # petgraph/axum precedent: task.md names OIDC/SAML SSO -- the
    # full-flow versions are not adopted; the offline subset is.
    text = serve_auth.__doc__ or ""
    lowered = text.lower()
    assert "oidc" in lowered
    assert "saml" in lowered
    assert "not adopted" in lowered


def test_package_surface_without_submodule_shadow():
    import analysis.serve as pkg
    assert pkg.auth is serve_auth
    assert pkg.AuthConfig is AuthConfig
    assert pkg.ROLE_RANK is ROLE_RANK
    assert callable(pkg.verify) and callable(pkg.load_auth_file)
    __import__("analysis.serve.auth")


def test_auth_source_top_level_imports_stay_offline():
    # twin of t82's AST pin, scoped so this file alone catches regressions
    import ast
    src = REPO / "analysis" / "serve" / "auth.py"
    tree = ast.parse(src.read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Import):
            names = {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom):
            names = {(node.module or "").split(".")[0]}
        else:
            continue
        assert not (names & _BANNED_TOP), \
            f"auth.py top-level import {names & _BANNED_TOP}"
