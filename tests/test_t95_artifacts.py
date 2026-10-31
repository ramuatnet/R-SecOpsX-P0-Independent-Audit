"""T-9.5 artifact store -- durable, tenancy-scoped scan artifacts.

task.md section 12 PHASE 9 lists "artifact store" between Postgres and
the UI: the platform-side durable layer for scan artifacts (reports,
manifests, SBOM slices) that the API -- and later the SPA -- read and
write with the SAME credential tenancy as jobs.

Contracts pinned here BEFORE product code exists:

* store -- content-addressed digests ("sha256:" + sha256 of the final
  bytes), logical NAMES never paths (charset [A-Za-z0-9._-], so no
  traversal), caps as model constants with behaviour at the boundary,
  replace-on-put (idempotent re-stow), verify-on-read opt-in;
* id canon -- ``art_`` + sha256(name)[:12] unscoped, tenant+name when
  scoped (webhook_id_for precedent); frozen by test from this batch;
* tenancy -- cross-tenant get/delete miss (404-shaped, never an
  existence oracle); unscoped operator sees all; metas carry tenant
  key always (T-9.2 additive-key convention);
* api -- GET/POST /v1/artifacts + GET/DELETE /v1/artifacts/{name},
  riding the EXISTING auth/RBAC/audit gates (required_role classifies
  these automatically: GET viewer, POST admin, DELETE admin);
* both backends -- the artifacts table + four methods are parity-pinned
  against the sqlite-translating shim from T-9.4 (no live Postgres).

Red baseline at HEAD is a collection error (new module) -- disclosed.
"""
import base64
import hashlib
import json
import pathlib
import sys

import pytest

from analysis.serve import model as serve_model
from analysis.serve.api import route
from analysis.serve.auth import required_role
from analysis.serve.artifacts import (
    ArtifactInvalid, artifact_id_for, delete, get, list_artifacts, put,
)
from analysis.serve.storage import PostgresBackend, SqliteBackend

_TESTS = str(pathlib.Path(__file__).resolve().parent)
if _TESTS not in sys.path:
    sys.path.insert(0, _TESTS)
from test_t94_postgres_backend import _install_fake_psycopg  # noqa: E402


def _sha(content: bytes) -> str:
    return "sha256:" + hashlib.sha256(content).hexdigest()


# ---------------------------------------------------------------------------
# A. store core
# ---------------------------------------------------------------------------


def test_put_get_roundtrip_meta_shape():
    b = SqliteBackend(":memory:")
    meta = put(b, "report.json", '{"a": 1}', kind="report", now=100.0)
    assert meta == {
        "id": "art_" + hashlib.sha256(b"report.json").hexdigest()[:12],
        "name": "report.json", "kind": "report",
        "digest": _sha(b'{"a": 1}'), "size": 8,
        "created_at": 100.0, "tenant": "", "job_id": None,
    }
    row = get(b, "report.json")
    assert row is not None and row["content"] == b'{"a": 1}'
    assert row["digest"] == meta["digest"]
    b.close()


def test_content_normalization_str_bytes_object_same_digest():
    b = SqliteBackend(":memory:")
    obj = {"findings": 3, "a": [1, 2]}
    m1 = put(b, "a.json", obj, kind="report", now=1.0)
    canonical = json.dumps(obj, sort_keys=True, ensure_ascii=True,
                           separators=(",", ":")).encode("utf-8")
    assert m1["digest"] == _sha(canonical)
    m2 = put(b, "b.json", canonical, kind="report", now=2.0)
    assert m1["digest"] == m2["digest"]        # content-addressed
    m3 = put(b, "c.json", "text", kind="report", now=3.0)
    assert m3["digest"] == _sha(b"text")       # str -> utf-8
    b.close()


def test_put_replaces_same_name_and_bumps_timestamp():
    b = SqliteBackend(":memory:")
    put(b, "r.json", "one", kind="report", now=10.0)
    m2 = put(b, "r.json", "two!", kind="manifest", now=20.0)
    rows = list_artifacts(b)
    assert len(rows) == 1
    assert rows[0]["size"] == 4 and rows[0]["kind"] == "manifest"
    assert rows[0]["created_at"] == 20.0
    assert rows[0]["digest"] == m2["digest"]
    b.close()


@pytest.mark.parametrize("bad", ["", "a b", "x/y", "..", ".", "x" * 129,
                                 "tab\tname", None, 7])
def test_invalid_names_are_machine_reasons(bad):
    b = SqliteBackend(":memory:")
    with pytest.raises(ArtifactInvalid) as ei:
        put(b, bad, b"x", kind="report", now=1.0)
    assert ei.value.reason == "artifact_name_invalid"
    b.close()


@pytest.mark.parametrize("bad", ["", "a b", "x/y", "k" * 65, None])
def test_invalid_kind_is_machine_reason(bad):
    b = SqliteBackend(":memory:")
    with pytest.raises(ArtifactInvalid) as ei:
        put(b, "ok.json", b"x", kind=bad, now=1.0)
    assert ei.value.reason == "artifact_kind_invalid"
    b.close()


def test_invalid_job_id_is_machine_reason():
    b = SqliteBackend(":memory:")
    with pytest.raises(ArtifactInvalid) as ei:
        put(b, "ok.json", b"x", kind="report", job_id="has space",
            now=1.0)
    assert ei.value.reason == "artifact_job_id_invalid"
    b.close()


def test_byte_cap_is_enforced_with_machine_reason(monkeypatch):
    monkeypatch.setattr(serve_model, "MAX_ARTIFACT_BYTES", 8)
    b = SqliteBackend(":memory:")
    put(b, "ok.json", b"12345678", kind="report", now=1.0)   # at cap
    with pytest.raises(ArtifactInvalid) as ei:
        put(b, "big.json", b"123456789", kind="report", now=2.0)
    assert ei.value.reason == "cap_artifact_bytes_8"
    b.close()


def test_artifact_cap_counts_across_tenants_but_replace_is_free(monkeypatch):
    monkeypatch.setattr(serve_model, "MAX_ARTIFACTS", 2)
    b = SqliteBackend(":memory:")
    put(b, "a.json", b"1", kind="report", now=1.0)
    put(b, "b.json", b"2", kind="report", tenant="acme", now=2.0)
    with pytest.raises(ArtifactInvalid) as ei:
        put(b, "c.json", b"3", kind="report", now=3.0)
    assert ei.value.reason == "cap_artifacts_2"
    # replacing an existing artifact at the cap is still allowed
    assert put(b, "a.json", b"new", kind="report", now=4.0)["size"] == 3
    b.close()


def test_verify_detects_tampering_and_is_opt_in():
    b = SqliteBackend(":memory:")
    put(b, "r.json", "honest", kind="report", now=1.0)
    aid = artifact_id_for("r.json")
    with b._lock, b._conn:                      # simulate tamper
        b._conn.execute("UPDATE artifacts SET content=? WHERE id=?",
                        (b"EVIL", aid))
    row = get(b, "r.json")                      # default: no verify
    assert row["content"] == b"EVIL"
    with pytest.raises(ArtifactInvalid) as ei:
        get(b, "r.json", verify=True)
    assert ei.value.reason == "artifact_content_corrupt"
    b.close()


def test_delete_is_idempotent_miss():
    b = SqliteBackend(":memory:")
    put(b, "r.json", b"x", kind="report", now=1.0)
    assert delete(b, "r.json") is True
    assert delete(b, "r.json") is False
    assert get(b, "r.json") is None
    b.close()


# ---------------------------------------------------------------------------
# B. tenancy + id canon
# ---------------------------------------------------------------------------


def test_id_canon_is_frozen_and_tenant_sensitive():
    name = "report.json"
    unscoped = "art_" + hashlib.sha256(name.encode()).hexdigest()[:12]
    scoped = "art_" + hashlib.sha256(
        f"acme\n{name}".encode()).hexdigest()[:12]
    assert artifact_id_for(name) == unscoped
    assert artifact_id_for(name, tenant="acme") == scoped
    assert artifact_id_for(name, tenant=None) == artifact_id_for(name)
    assert artifact_id_for(name, tenant="acme") != unscoped


def test_cross_tenant_reads_miss_and_unscoped_sees_all():
    b = SqliteBackend(":memory:")
    put(b, "r.json", b"a", kind="report", tenant="acme", now=1.0)
    put(b, "r.json", b"b", kind="report", tenant="globex", now=2.0)
    put(b, "u.json", b"c", kind="report", now=3.0)
    acme = get(b, "r.json", tenant="acme")
    assert acme is not None and acme["content"] == b"a"
    # scoped caller cannot read another tenant's artifact by name,
    # nor another tenant's artifact by its id (404-shaped, no oracle)
    assert get(b, "r.json", tenant="globex")["content"] == b"b"
    assert get(b, artifact_id_for("r.json", tenant="acme"),
               tenant="globex") is None
    # unscoped operator sees everything (T-9.2 convention), by name
    # for its own scope and by id for scoped rows
    assert get(b, "u.json")["content"] == b"c"
    assert get(b, artifact_id_for("r.json", tenant="acme"))["content"] \
        == b"a"
    assert [m["name"] for m in list_artifacts(b)] == ["r.json", "r.json",
                                                      "u.json"]
    assert [m["tenant"] for m in list_artifacts(b, tenant="acme")] == \
        ["acme"]
    b.close()


def test_cross_tenant_delete_misses_and_leaves_the_row():
    b = SqliteBackend(":memory:")
    put(b, "r.json", b"a", kind="report", tenant="acme", now=1.0)
    assert delete(b, "r.json", tenant="globex") is False
    assert delete(b, artifact_id_for("r.json", tenant="acme"),
                  tenant="globex") is False
    assert get(b, "r.json", tenant="acme") is not None
    assert delete(b, "r.json", tenant="acme") is True
    b.close()


def test_kind_filter_on_list():
    b = SqliteBackend(":memory:")
    put(b, "a.json", b"1", kind="report", now=1.0)
    put(b, "b.json", b"2", kind="manifest", now=2.0)
    assert [m["name"] for m in list_artifacts(b, kind="manifest")] == \
        ["b.json"]
    assert len(list_artifacts(b, kind="report")) == 1
    b.close()


# ---------------------------------------------------------------------------
# C. backend parity (sqlite vs the T-9.4 translating shim)
# ---------------------------------------------------------------------------


def _store_scenario(b):
    put(b, "r.json", {"n": 1}, kind="report", now=10.0)
    put(b, "m.json", b"\x00\xffbin", kind="manifest", tenant="acme",
        now=11.0)
    metas = list_artifacts(b)
    scoped = list_artifacts(b, tenant="acme")
    one = get(b, "r.json")
    two = get(b, "m.json", tenant="acme")
    gone = delete(b, "m.json", tenant="globex")
    kept = delete(b, "m.json", tenant="acme")
    after = get(b, "m.json", tenant="acme")
    return {"metas": metas, "scoped": scoped, "one": one, "two": two,
            "gone": gone, "kept": kept, "after": after}


def test_backend_parity_sqlite_vs_postgres_shim(monkeypatch):
    sq = SqliteBackend(":memory:")
    _install_fake_psycopg(monkeypatch)
    pg = PostgresBackend("postgres://u:p@h/d")
    try:
        assert _store_scenario(sq) == _store_scenario(pg)
    finally:
        sq.close()
        pg.close()


def test_postgres_bytea_content_returns_bytes(monkeypatch):
    _install_fake_psycopg(monkeypatch)
    b = PostgresBackend("postgres://u:p@h/d")
    try:
        put(b, "bin.dat", b"\x00\xff", kind="report", now=1.0)
        row = get(b, "bin.dat")
        assert row["content"] == b"\x00\xff"
        assert isinstance(row["size"], int)
    finally:
        b.close()


# ---------------------------------------------------------------------------
# D. API routes
# ---------------------------------------------------------------------------


def _post(body_obj):
    return json.dumps(body_obj).encode("utf-8")


def test_api_post_list_get_delete_roundtrip():
    b = SqliteBackend(":memory:")
    st, _, payload = route(b, "POST", "/v1/artifacts", {},
                           _post({"name": "r.json", "kind": "report",
                                  "content": "hello"}))
    assert st == 201
    meta = json.loads(payload)["artifact"]
    assert meta["name"] == "r.json" and "content" not in meta

    st, _, payload = route(b, "GET", "/v1/artifacts", {}, b"")
    assert st == 200 and [m["name"] for m in
                          json.loads(payload)["artifacts"]] == ["r.json"]

    st, _, payload = route(b, "GET", "/v1/artifacts/r.json", {}, b"")
    assert st == 200
    doc = json.loads(payload)["artifact"]
    assert doc["encoding"] == "utf-8" and doc["content"] == "hello"
    assert doc["digest"] == _sha(b"hello")

    st, _, payload = route(b, "DELETE", "/v1/artifacts/r.json", {}, b"")
    assert st == 200 and json.loads(payload) == {"deleted": True}

    st, _, _ = route(b, "GET", "/v1/artifacts/r.json", {}, b"")
    assert st == 404
    st, _, payload = route(b, "DELETE", "/v1/artifacts/r.json", {}, b"")
    assert st == 404 and json.loads(payload)["error"] == \
        "artifact_not_found"
    b.close()


def test_api_base64_content_roundtrip_for_binary():
    b = SqliteBackend(":memory:")
    blob = bytes([0, 159, 146, 150])
    st, _, _ = route(b, "POST", "/v1/artifacts", {}, _post(
        {"name": "b.bin", "kind": "report",
         "content": base64.b64encode(blob).decode("ascii"),
         "encoding": "base64"}))
    assert st == 201
    st, _, payload = route(b, "GET", "/v1/artifacts/b.bin", {}, b"")
    doc = json.loads(payload)["artifact"]
    assert doc["encoding"] == "base64"
    assert base64.b64decode(doc["content"]) == blob
    b.close()


def test_api_json_object_content_is_canonical_json():
    b = SqliteBackend(":memory:")
    st, _, _ = route(b, "POST", "/v1/artifacts", {}, _post(
        {"name": "o.json", "kind": "report", "content": {"b": 2,
                                                         "a": 1}}))
    assert st == 201
    st, _, payload = route(b, "GET", "/v1/artifacts/o.json", {}, b"")
    doc = json.loads(payload)["artifact"]
    assert doc["content"] == '{"a":1,"b":2}'
    b.close()


def test_api_error_shapes():
    b = SqliteBackend(":memory:")
    st, _, payload = route(b, "POST", "/v1/artifacts", {}, b"{nope")
    assert st == 400 and json.loads(payload)["error"] == "bad_json"
    st, _, payload = route(b, "POST", "/v1/artifacts", {},
                           _post({"kind": "report"}))
    assert st == 400 and json.loads(payload)["error"] == \
        "artifact_name_invalid"
    st, _, payload = route(b, "POST", "/v1/artifacts", {}, _post(
        {"name": "x", "kind": "report", "content": "y",
         "encoding": "utf-16"}))
    assert st == 400 and json.loads(payload)["error"] == \
        "artifact_encoding_invalid"
    st, _, payload = route(b, "POST", "/v1/artifacts", {}, _post(
        {"name": "x", "kind": "report", "content": "!!notb64!!",
         "encoding": "base64"}))
    assert st == 400 and json.loads(payload)["error"] == \
        "artifact_content_invalid"
    b.close()


def test_api_method_matrix_and_unknown_routes_unchanged():
    b = SqliteBackend(":memory:")
    st, _, _ = route(b, "PUT", "/v1/artifacts", {}, b"")
    assert st == 405
    st, _, _ = route(b, "POST", "/v1/artifacts/r.json", {}, b"")
    assert st == 405
    st, _, _ = route(b, "GET", "/v1/nope", {}, b"")
    assert st == 404
    b.close()


def test_api_tenant_scoping_through_route():
    b = SqliteBackend(":memory:")
    put(b, "r.json", b"acme", kind="report", tenant="acme", now=1.0)
    put(b, "r.json", b"other", kind="report", tenant="globex", now=2.0)
    put(b, "u.json", b"op", kind="report", now=3.0)
    # scoped caller: sees only its rows, cross-tenant by name -> 404
    st, _, payload = route(b, "GET", "/v1/artifacts", {}, b"",
                           tenant="acme")
    names = [(m["name"], m["tenant"]) for m in
             json.loads(payload)["artifacts"]]
    assert names == [("r.json", "acme")]
    st, _, payload = route(b, "GET", "/v1/artifacts/r.json", {}, b"",
                           tenant="acme")
    assert st == 200 and json.loads(payload)["artifact"]["content"] == \
        "acme"
    st, _, _ = route(b, "DELETE", "/v1/artifacts/u.json", {}, b"",
                     tenant="acme")
    assert st == 404                      # unscoped row, scoped caller
    # unscoped operator: list sees every tenant (T-9.2 convention)
    st, _, payload = route(b, "GET", "/v1/artifacts", {}, b"")
    assert len(json.loads(payload)["artifacts"]) == 3
    st, _, _ = route(b, "GET",
                     "/v1/artifacts/" + artifact_id_for(
                         "r.json", tenant="acme"), {}, b"")
    assert st == 200                     # operator reads scoped row by id
    b.close()


def test_api_list_kind_filter_query():
    b = SqliteBackend(":memory:")
    put(b, "a.json", b"1", kind="report", now=1.0)
    put(b, "b.json", b"2", kind="manifest", now=2.0)
    st, _, payload = route(b, "GET", "/v1/artifacts", {"kind": "manifest"},
                           b"")
    assert st == 200 and [m["name"] for m in
                          json.loads(payload)["artifacts"]] == ["b.json"]
    b.close()


# ---------------------------------------------------------------------------
# E. RBAC classification (existing required_role patterns)
# ---------------------------------------------------------------------------


def test_required_role_classifies_artifact_routes():
    assert required_role("GET", "/v1/artifacts") == "viewer"
    assert required_role("POST", "/v1/artifacts") == "admin"
    assert required_role("DELETE", "/v1/artifacts/r.json") == "admin"
    assert required_role("GET", "/v1/artifacts/r.json") == "viewer"


# ---------------------------------------------------------------------------
# F. pins
# ---------------------------------------------------------------------------


def test_caps_declared_as_model_constants():
    assert isinstance(serve_model.MAX_ARTIFACTS, int)
    assert isinstance(serve_model.MAX_ARTIFACT_BYTES, int)
    assert serve_model.MAX_ARTIFACTS > 0
    assert serve_model.MAX_ARTIFACT_BYTES >= 1_048_576   # >= body cap


def test_artifacts_module_has_no_banned_top_level_imports():
    import ast
    src = (pathlib.Path(__file__).resolve().parents[1]
           / "analysis" / "serve" / "artifacts.py")
    tree = ast.parse(src.read_text(encoding="utf-8"))
    banned = {"urllib", "socket", "requests", "boto3", "http", "os",
              "subprocess"}
    top = []
    for node in tree.body:
        if isinstance(node, ast.Import):
            top.extend(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            top.append(node.module)
    assert not (set(top) & banned), top
