"""T-9.2 serve multi-tenancy -- tenant-scoped data plane (task.md section 12).

This batch EDITS the existing serve modules (auth/model/storage/queue/
events/api), so the red-first baseline is contract failures against the
UNCHANGED product (unexpected-keyword TypeErrors + isolation asserts),
not a collection error.

Contracts pinned:

* credentials: a token entry or JWT claim may declare "tenant"; the
  principal gains a "tenant" key ONLY when the credential declares one
  -- tenant-less credentials keep the exact T-9.1 principal shape and
  are UNSCOPED operators (see isolation tests); a BAD tenant in a JWT
  claim is invalid_credentials, never a silent fall-back to unscoped
  (silent unscoped = escalation);
* ids are tenant-isolated but the LEGACY (no-tenant) digests are
  byte-identical to T-8.2 -- flag-off discipline;
* a client-posted "tenant" key in a job body is IGNORED (validate_job
  rebuilds from known keys; tenant only ever comes from the credential
  via the route layer);
* storage rows carry a tenant column (legacy rows + unscoped writes
  stamp ""); reads filter when a tenant scope is given, and None keeps
  the old unscoped behaviour;
* deliveries: an event reaches only hooks with the SAME tenant
  (exact match, "" == "" so legacy fan-out is unchanged);
* route() gains an optional tenant= kwarg; tenant=None sees everything
  (legacy / operator); API job lookups across tenants are 404, not 403
  (no existence oracle);
* caps (webhooks/schedules/enqueue) stay GLOBAL across tenants --
  disclosed, pinned so nobody assumes per-tenant quotas;
* the ticker (drain/cron) intentionally runs ALL tenants: the server
  is one process serving every tenant's jobs.
"""
import hashlib
import json
import pathlib
import sqlite3
import subprocess
import sys
import time
import urllib.error
import urllib.request

import pytest

from analysis.serve import auth as serve_auth
from analysis.serve.api import route, serve
from analysis.serve.events import deliver_events, follow_events
from analysis.serve.model import MAX_WEBHOOKS, job_id_for, validate_job
from analysis.serve.queue import add_schedule, cron_tick, enqueue_jobs
from analysis.serve.storage import SqliteBackend

REPO = pathlib.Path(__file__).resolve().parent.parent

_NOW = 1_800_000_000.0


# ---------------------------------------------------------------------------
# A. credentials -> tenant claim
# ---------------------------------------------------------------------------


def _write_auth(tmp_path, tokens, name="rsx_t92_auth.json"):
    doc = {"tokens": tokens}
    path = tmp_path / name
    path.write_text(json.dumps(doc), encoding="utf-8")
    return serve_auth.load_auth_file(path)


def test_token_with_tenant_lands_on_principal(tmp_path):
    cfg = _write_auth(tmp_path, [
        {"name": "alice", "token": "tok-a", "role": "editor",
         "tenant": "acme"}])
    principal, reason = serve_auth.verify(cfg, "Bearer tok-a", now=_NOW)
    assert reason is None
    assert principal == {"actor": "alice", "role": "editor",
                         "tenant": "acme"}


def test_token_without_tenant_keeps_exact_t91_shape(tmp_path):
    cfg = _write_auth(tmp_path, [
        {"name": "bob", "token": "tok-b", "role": "viewer"}])
    principal, _ = serve_auth.verify(cfg, "Bearer tok-b", now=_NOW)
    # T-9.1 pins exact dict equality -- no tenant key appears unless
    # the credential declares one
    assert principal == {"actor": "bob", "role": "viewer"}
    assert "tenant" not in principal


def test_jwt_tenant_claim_lands_on_principal(tmp_path):
    import base64 as _b64
    import hmac as _hmac
    import hashlib as _hl

    doc = {"tokens": [],
           "jwt": {"secret": "s3cret", "issuer": "idp"}}
    p = tmp_path / "rsx_t92_jwt.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    jcfg = serve_auth.load_auth_file(p)

    def jwt(claims):
        h = _b64.urlsafe_b64encode(
            json.dumps({"alg": "HS256"}).encode()).rstrip(b"=").decode()
        pl = _b64.urlsafe_b64encode(
            json.dumps(claims).encode()).rstrip(b"=").decode()
        sig = _b64.urlsafe_b64encode(_hmac.new(
            b"s3cret", f"{h}.{pl}".encode(), _hl.sha256).digest()
        ).rstrip(b"=").decode()
        return f"{h}.{pl}.{sig}"

    token = jwt({"sub": "svc", "iss": "idp", "tenant": "globex",
                 "exp": _NOW + 600})
    principal, reason = serve_auth.verify(jcfg, f"Bearer {token}",
                                          now=_NOW)
    assert reason is None
    assert principal["tenant"] == "globex"
    assert principal["role"] == "viewer"

    # a BAD tenant claim is loud -- never silently unscoped
    bad = jwt({"sub": "svc", "iss": "idp", "tenant": "",
               "exp": _NOW + 600})
    assert serve_auth.verify(jcfg, f"Bearer {bad}", now=_NOW) == \
        (None, "invalid_credentials")
    bad2 = jwt({"sub": "svc", "iss": "idp", "tenant": 7,
                "exp": _NOW + 600})
    assert serve_auth.verify(jcfg, f"Bearer {bad2}", now=_NOW) == \
        (None, "invalid_credentials")


def test_tenant_validation_is_loud_at_load(tmp_path):
    for bad, reason in ((5, "tenant_invalid:0"), ("", "tenant_invalid:0"),
                        ([], "tenant_invalid:0")):
        path = tmp_path / f"rsx_t92_bad_{type(bad).__name__}.json"
        path.write_text(json.dumps({"tokens": [
            {"name": "x", "token": "t", "role": "viewer", "tenant": bad}
        ]}), encoding="utf-8")
        with pytest.raises(serve_auth.AuthInvalid) as ei:
            serve_auth.load_auth_file(path)
        assert ei.value.reason == reason


# ---------------------------------------------------------------------------
# B. ids and validation -- tenant isolation, legacy digests frozen
# ---------------------------------------------------------------------------


def _legacy_job_id(target, out=None, occurrence=None):
    """The T-8.2 canon, recomputed here so drift reddens this test."""
    canon = json.dumps(
        {"target": target, "out": out, "occurrence": occurrence},
        sort_keys=True, ensure_ascii=True, separators=(",", ":"))
    return "job_" + hashlib.sha256(canon.encode("utf-8")).hexdigest()[:12]


def test_job_id_legacy_digest_is_frozen():
    assert job_id_for({"target": "app/"}) == \
        _legacy_job_id("app/")
    assert job_id_for({"target": "app/"}, occurrence=42) == \
        _legacy_job_id("app/", occurrence=42)


def test_job_id_isolates_tenants():
    legacy = job_id_for({"target": "app/"})
    a = job_id_for({"target": "app/", "tenant": "acme"})
    b = job_id_for({"target": "app/", "tenant": "globex"})
    assert a != legacy and b != legacy and a != b


def test_validate_job_legacy_shape_has_no_tenant_key():
    job, err = validate_job({"target": "app/", "out": "o"})
    assert err is None
    assert "tenant" not in job
    assert job["id"] == _legacy_job_id("app/", out="o")


def test_validate_job_with_tenant_stamps_and_scopes_id():
    job, err = validate_job({"target": "app/"}, tenant="acme")
    assert err is None
    assert job["tenant"] == "acme"
    assert job["id"] == job_id_for({"target": "app/", "tenant": "acme"})


def test_posted_tenant_key_cannot_escalate():
    # client-supplied tenant in the BODY is dropped by validate_job
    job, err = validate_job({"target": "app/", "tenant": "victim"})
    assert err is None
    assert "tenant" not in job
    assert job["id"] == _legacy_job_id("app/")

    scoped, err = validate_job({"target": "app/", "tenant": "victim"},
                               tenant="attacker")
    assert err is None
    assert scoped["tenant"] == "attacker"   # credential wins, body ignored


def test_schedule_ids_isolate_tenants_and_legacy_is_frozen():
    backend = SqliteBackend(":memory:")
    row = {"cron": "0 * * * *", "target": "app/"}
    legacy = "sch_" + hashlib.sha256(
        "0 * * * *|app/|None".encode()).hexdigest()[:12]
    good, _ = add_schedule(backend, [row], now=_NOW)
    assert good[0]["id"] == legacy            # no-tenant canon frozen
    a, _ = add_schedule(backend, [row], now=_NOW, tenant="acme")
    b, _ = add_schedule(backend, [row], now=_NOW, tenant="globex")
    assert a[0]["id"] != b[0]["id"] != legacy and a[0]["id"] != legacy
    assert a[0]["tenant"] == "acme" and b[0]["tenant"] == "globex"
    backend.close()


# ---------------------------------------------------------------------------
# C. storage -- migration, scoped reads, stamping, global caps
# ---------------------------------------------------------------------------

_LEGACY_DDL = """
CREATE TABLE IF NOT EXISTS jobs (
    id TEXT PRIMARY KEY, target TEXT, out TEXT,
    status TEXT, attempts INTEGER, last_error TEXT,
    created_at REAL, updated_at REAL);
CREATE TABLE IF NOT EXISTS schedules (
    id TEXT PRIMARY KEY, cron TEXT, target TEXT, out TEXT,
    created_at REAL, last_tick REAL);
CREATE TABLE IF NOT EXISTS events (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT, payload TEXT, at REAL);
CREATE TABLE IF NOT EXISTS webhooks (
    id TEXT PRIMARY KEY, url TEXT, active INTEGER);
CREATE TABLE IF NOT EXISTS deliveries (
    event_seq INTEGER, webhook_id TEXT,
    attempts INTEGER, status TEXT, at REAL,
    PRIMARY KEY (event_seq, webhook_id));
"""


def test_migration_adds_tenant_to_legacy_database(tmp_path):
    path = tmp_path / "rsx_t92_legacy.db"
    conn = sqlite3.connect(path)
    conn.executescript(_LEGACY_DDL)
    conn.execute(
        "INSERT INTO jobs (id, target, out, status, attempts,"
        " last_error, created_at, updated_at)"
        " VALUES ('job_old','app/',NULL,'done',1,NULL,1.0,1.0)")
    conn.commit()
    conn.close()

    backend = SqliteBackend(str(path))
    row = backend.job("job_old")
    assert row is not None and row["tenant"] == ""   # migrated, not lost
    assert backend.job("job_old", tenant="acme") is None  # legacy = ""
    cols = {r[1] for r in backend._conn.execute(
        "PRAGMA table_info(events)")}  # noqa: SLF001 (migration probe)
    assert "tenant" in cols
    backend.close()


def test_jobs_scoped_reads_and_writes():
    backend = SqliteBackend(":memory:")
    ja, _ = validate_job({"target": "app/"}, tenant="acme")
    jb, _ = validate_job({"target": "app/"}, tenant="globex")
    enqueue_jobs(backend, [{"target": "app/"}], now=_NOW, tenant="acme")
    enqueue_jobs(backend, [{"target": "app/"}], now=_NOW, tenant="globex")
    assert len(backend.list_jobs(tenant="acme")) == 1
    assert len(backend.list_jobs(tenant="globex")) == 1
    assert len(backend.list_jobs()) == 2                 # None = all
    assert backend.job(ja["id"], tenant="acme") is not None
    assert backend.job(ja["id"], tenant="globex") is None  # cross-tenant
    assert backend.job(ja["id"]) is not None              # unscoped
    backend.close()


def test_events_carry_and_filter_on_tenant():
    backend = SqliteBackend(":memory:")
    backend.append_event("job.enqueued", {"n": 1}, at=_NOW, tenant="acme")
    backend.append_event("job.enqueued", {"n": 2}, at=_NOW, tenant="globex")
    only_a = backend.events_since(0, tenant="acme")
    assert [e["payload"]["n"] for e in only_a] == [1]
    assert only_a[0]["tenant"] == "acme"
    assert len(backend.events_since(0)) == 2           # None = all
    assert len(backend.events_since(0, tenant="")) == 0
    backend.close()


def test_webhook_ids_isolate_tenants_and_legacy_id_frozen():
    backend = SqliteBackend(":memory:")
    url = "http://ok.example/hook"
    legacy = "wh_" + hashlib.sha256(url.encode("utf-8")).hexdigest()[:12]
    assert backend.register_webhook(url) == legacy     # frozen digest
    a = backend.register_webhook(url, tenant="acme")
    b = backend.register_webhook(url, tenant="globex")
    assert a != b and a != legacy and b != legacy
    assert [w["id"] for w in backend.webhooks(tenant="acme")] == [a]
    assert len(backend.webhooks()) == 3
    backend.close()


def test_webhook_cap_stays_global_across_tenants():
    backend = SqliteBackend(":memory:")
    for i in range(MAX_WEBHOOKS):
        backend.register_webhook(f"http://h.example/{i}", tenant="acme")
    from analysis.serve.storage import WebhookInvalid
    with pytest.raises(WebhookInvalid) as ei:
        backend.register_webhook("http://h.example/late", tenant="globex")
    assert ei.value.reason == f"cap_webhooks_{MAX_WEBHOOKS}"
    backend.close()


def test_cross_tenant_same_target_enqueues_both():
    backend = SqliteBackend(":memory:")
    a, sa = enqueue_jobs(backend, [{"target": "app/"}], now=_NOW,
                         tenant="acme")
    b, sb = enqueue_jobs(backend, [{"target": "app/"}], now=_NOW,
                         tenant="globex")
    assert len(a) == 1 and len(b) == 1 and not sa and not sb
    # same tenant, same target -> still job_exists (content-addressed)
    dup, sd = enqueue_jobs(backend, [{"target": "app/"}], now=_NOW,
                           tenant="acme")
    assert not dup and sd[0]["reason"].startswith("job_exists:")
    backend.close()


def test_cron_occurrences_inherit_schedule_tenant():
    backend = SqliteBackend(":memory:")
    good, _ = add_schedule(backend,
                           [{"cron": "* * * * *", "target": "app/"}],
                           now=_NOW, tenant="acme")
    backend.set_last_tick(good[0]["id"], _NOW - 60)   # cursor past (skip first-tick)
    res = cron_tick(backend, now=_NOW)
    assert res["enqueued"] >= 1
    jobs = backend.list_jobs(tenant="acme")
    assert jobs and all(j["tenant"] == "acme" for j in jobs)
    assert all(backend.job(j["id"], tenant="globex") is None
               for j in jobs)
    backend.close()


# ---------------------------------------------------------------------------
# D. route -- API isolation (optional tenant= kwarg, legacy default)
# ---------------------------------------------------------------------------


def _two_tenant_backend():
    backend = SqliteBackend(":memory:")
    enqueue_jobs(backend, [{"target": "app/"}], now=_NOW, tenant="acme")
    enqueue_jobs(backend, [{"target": "app/"}], now=_NOW, tenant="globex")
    return backend


def test_route_scoped_reads_and_404_across_tenants():
    backend = _two_tenant_backend()
    ja = backend.list_jobs(tenant="acme")[0]
    jb = backend.list_jobs(tenant="globex")[0]

    status, _, body = route(backend, "GET", "/v1/jobs", {}, b"",
                            tenant="acme")
    doc = json.loads(body)
    assert status == 200 and [j["id"] for j in doc["jobs"]] == [ja["id"]]

    # cross-tenant lookup is 404, not 403 -- no existence oracle
    status, _, body = route(backend, "GET", f"/v1/jobs/{jb['id']}", {},
                            b"", tenant="acme")
    assert status == 404 and json.loads(body)["error"] == "job_not_found"

    # tenant=None (unscoped/legacy) sees everything
    status, _, body = route(backend, "GET", "/v1/jobs", {}, b"")
    assert status == 200 and len(json.loads(body)["jobs"]) == 2
    backend.close()


def test_route_write_stamps_credential_tenant():
    backend = SqliteBackend(":memory:")
    status, _, body = route(backend, "POST", "/v1/jobs", {},
                            json.dumps({"target": "app/"}).encode(),
                            tenant="acme")
    assert status == 201
    job_id = json.loads(body)["job"]["id"]
    assert backend.job(job_id)["tenant"] == "acme"
    # body-supplied tenant is ignored (credential decides): the same
    # target under the SAME credential yields the SAME id -> duplicate
    # rejection proves globex was dropped (honouring it would mint a
    # fresh id and a 201 -- the escalation this guards against)
    status, _, body = route(backend, "POST", "/v1/jobs", {},
                            json.dumps({"target": "app/",
                                        "tenant": "globex"}).encode(),
                            tenant="acme")
    assert status == 400
    reason = json.loads(body)["error"]
    assert reason.startswith("job_exists:")
    assert reason[len("job_exists:"):] == job_id
    backend.close()


def test_route_schedules_and_webhooks_stamped_and_scoped():
    backend = SqliteBackend(":memory:")
    status, _, body = route(backend, "POST", "/v1/schedules", {},
                            json.dumps({"cron": "0 * * * *",
                                        "target": "app/"}).encode(),
                            tenant="acme")
    assert status == 201
    assert backend.schedules()[0]["tenant"] == "acme"

    status, _, body = route(backend, "POST", "/v1/webhooks", {},
                            json.dumps({"url": "http://a.example/h"}).encode(),
                            tenant="acme")
    assert status == 201
    assert len(backend.webhooks(tenant="acme")) == 1
    assert len(backend.webhooks(tenant="globex")) == 0

    status, _, body = route(backend, "GET", "/v1/schedules", {}, b"",
                            tenant="globex")
    assert status == 200 and json.loads(body)["schedules"] == []
    backend.close()


def test_route_events_sse_is_scoped():
    backend = SqliteBackend(":memory:")
    ja, _ = enqueue_jobs(backend, [{"target": "app/"}], now=_NOW,
                         tenant="acme")
    jb, _ = enqueue_jobs(backend, [{"target": "app/"}], now=_NOW,
                         tenant="globex")
    status, headers, body = route(backend, "GET", "/v1/events",
                                  {"since": "0"}, b"", tenant="acme")
    assert status == 200
    assert ja[0]["id"].encode() in body
    assert jb[0]["id"].encode() not in body     # other tenant never leaks
    backend.close()


# ---------------------------------------------------------------------------
# E. webhook delivery matches tenants exactly
# ---------------------------------------------------------------------------


def test_deliver_events_matches_tenant_exactly():
    backend = SqliteBackend(":memory:")
    hook_a = backend.register_webhook("http://a.example/h", tenant="acme")
    hook_b = backend.register_webhook("http://b.example/h", tenant="globex")
    seq_a = backend.append_event("job.enqueued", {"who": "a"}, at=_NOW,
                                 tenant="acme")
    seq_b = backend.append_event("job.enqueued", {"who": "b"}, at=_NOW,
                                 tenant="globex")
    stats = deliver_events(backend, sender=None, now=_NOW,
                           sleep_fn=lambda _s: None, dry=True)
    assert backend.delivery_recorded(seq_a, hook_a) is not None
    assert backend.delivery_recorded(seq_b, hook_a) is None   # no leak
    assert backend.delivery_recorded(seq_b, hook_b) is not None
    assert backend.delivery_recorded(seq_a, hook_b) is None
    # legacy "" == "" fan-out unchanged: unscoped hook sees unscoped event
    hook_l = backend.register_webhook("http://l.example/h")
    seq_l = backend.append_event("job.enqueued", {"who": "l"}, at=_NOW)
    deliver_events(backend, sender=None, now=_NOW + 1,
                   sleep_fn=lambda _s: None, dry=True)
    assert backend.delivery_recorded(seq_l, hook_l) is not None
    # dry pass: recorded, never attempted (sender=None; dry counts "dry")
    assert stats["attempted"] == 0 and stats["dry"] >= 2
    backend.close()


def test_follow_events_is_scoped():
    backend = SqliteBackend(":memory:")
    backend.append_event("job.enqueued", {"n": 1}, at=_NOW, tenant="acme")
    clock = {"t": 0.0}

    rows_a = list(follow_events(backend, since=0, deadline=_NOW - 1,
                                now_fn=lambda: _NOW, sleep_fn=lambda _s: None,
                                tenant="acme"))
    assert [r["payload"]["n"] for r in rows_a] == [1]
    rows_g = list(follow_events(backend, since=0, deadline=_NOW - 1,
                                now_fn=lambda: _NOW, sleep_fn=lambda _s: None,
                                tenant="globex"))
    assert rows_g == []
    del clock
    backend.close()


# ---------------------------------------------------------------------------
# F. live smoke -- two tenants + unscoped operator over the wire
# ---------------------------------------------------------------------------


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


def test_cli_serve_tenant_isolation_live_smoke(tmp_path):
    auth_path = tmp_path / "rsx_t92_auth.json"
    auth_path.write_text(json.dumps({"tokens": [
        {"name": "a1", "token": "tok-a", "role": "editor",
         "tenant": "acme"},
        {"name": "g1", "token": "tok-g", "role": "editor",
         "tenant": "globex"},
        {"name": "root", "token": "tok-root", "role": "admin"},
    ]}), encoding="utf-8")
    db = tmp_path / "rsx_t92.db"
    ready = tmp_path / "rsx_t92_ready.txt"
    proc = subprocess.Popen(
        [sys.executable, "-m", "analysis.serve.connect",
         "--db", str(db), "--serve", "--serve-port", "0",
         "--serve-ready-file", str(ready),
         "--auth-file", str(auth_path)],
        cwd=REPO, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True)
    try:
        deadline = time.time() + 30
        while time.time() < deadline and not (
                ready.exists() and ready.read_text(encoding="utf-8").strip()):
            assert proc.poll() is None, proc.stderr.read()[:400]
            time.sleep(0.1)
        base = f"http://{ready.read_text(encoding='utf-8').strip()}"

        status, doc = _http(base, "/v1/jobs", method="POST",
                            token="tok-a", body={"target": "app/"})
        assert status == 201
        a_id = doc["job"]["id"]

        # tenant A sees its job
        status, doc = _http(base, "/v1/jobs", token="tok-a")
        assert [j["id"] for j in doc["jobs"]] == [a_id]
        # tenant B sees nothing, and the cross-tenant id is 404
        status, doc = _http(base, "/v1/jobs", token="tok-g")
        assert doc["jobs"] == []
        status, doc = _http(base, f"/v1/jobs/{a_id}", token="tok-g")
        assert status == 404
        # tenant B writes its own row with its own id
        status, doc = _http(base, "/v1/jobs", method="POST",
                            token="tok-g", body={"target": "app/"})
        assert status == 201 and doc["job"]["id"] != a_id
        # the unscoped operator credential sees both (documented)
        status, doc = _http(base, "/v1/jobs", token="tok-root")
        assert len(doc["jobs"]) == 2
        # event stream is scoped: B never sees A's enqueue event
        req = urllib.request.Request(
            base + "/v1/events?since=0", headers={
                "Authorization": "Bearer tok-g"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            events_body = resp.read()
        assert a_id.encode() not in events_body
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()


# ---------------------------------------------------------------------------
# G. pins
# ---------------------------------------------------------------------------


def test_zero_io_default_unchanged():
    r = subprocess.run(
        [sys.executable, "-m", "analysis.serve.connect",
         "--as-of", "2026-10-31T00:00:00"],
        capture_output=True, text=True, cwd=REPO, timeout=60)
    assert r.returncode == 0
    doc = json.loads(r.stdout)
    assert sorted(s["reason"] for s in doc["skips"]) == [
        "not_provided:db", "not_provided:enqueue", "not_provided:webhooks"]
    assert "tenant" not in json.dumps(doc)


def test_auth_module_declares_tenant_surface():
    # the tenant claim is documented where operators read the config
    text = (serve_auth.__doc__ or "").lower()
    assert "tenant" in text


def test_serve_source_top_level_imports_stay_offline():
    import ast
    banned = {"urllib", "socket", "requests", "boto3", "http", "os",
              "subprocess"}
    for name in ("auth", "model", "storage", "queue", "events", "api",
                 "connect"):
        src = REPO / "analysis" / "serve" / f"{name}.py"
        tree = ast.parse(src.read_text(encoding="utf-8"))
        for node in tree.body:
            if isinstance(node, ast.Import):
                names = {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom):
                names = {(node.module or "").split(".")[0]}
            else:
                continue
            assert not (names & banned), f"{name}.py {names & banned}"
