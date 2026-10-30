"""T-6.1: ASM collector -- stage wiring, skip discipline, reproducibility.

All transports are fakes (DNS send, HTTP, port connect, cert probe); the
clock is injected.  The headline assertions:
  * default (no-stage) run does ZERO network I/O and is byte-identical;
  * every stage failure becomes a machine-readable skip, never a raise;
  * a staged run with the same fake transports + same as_of is
    byte-identical (the run-to-run reproducibility gate).
"""
from __future__ import annotations

import io
import json
import struct
import urllib.error
from datetime import datetime, timezone

import pytest

from analysis.asm import collect
from analysis.asm.collect import build_inventory, main
from analysis.asm.dnsx import QTYPE_A, QTYPE_CNAME, decode_name

AS_OF = datetime(2026, 10, 31, 12, 0, 0, tzinfo=timezone.utc)


class NetworkBomb:
    """Any transport call in an offline run is a bug -- explodes."""

    def __call__(self, *a, **k):
        raise AssertionError(f"network attempted: {a!r} {k!r}")


def _mk_dns_response(query: bytes, a_records: list[str],
                     cname: str | None = None, rcode: int = 0) -> bytes:
    tid = struct.unpack_from(">H", query, 0)[0]
    answers = []
    for ip in a_records:
        answers.append(b"\xc0\x0c" + struct.pack(">HHIH", QTYPE_A, 1, 60, 4)
                       + bytes(int(x) for x in ip.split(".")))
    if cname:
        wire = b"".join(bytes([len(p)]) + p.encode() for p in cname.split(".")) + b"\x00"
        answers.append(b"\xc0\x0c" + struct.pack(">HHIH", QTYPE_CNAME, 1, 60,
                                                 len(wire)) + wire)
    flags = 0x8180 | rcode
    header = struct.pack(">HHHHHH", tid, flags, 1, len(answers), 0, 0)
    return header + query[12:] + b"".join(answers)


def make_send(mapping: dict[str, dict]) -> callable:
    """mapping: fqdn -> {'a': [ips], 'cname': str} | None (NXDOMAIN)."""
    def _send(query: bytes) -> bytes:
        name, _ = decode_name(query, 12)
        rec = mapping.get(name)
        if not rec:
            return _mk_dns_response(query, [], rcode=3)
        return _mk_dns_response(query, rec.get("a", []),
                                cname=rec.get("cname"))
    return _send


def make_http(routes: dict[str, tuple]) -> callable:
    """routes: exact url -> (status, headers, body_bytes|str, final_url).

    EXACT match on purpose: a prefix route for "/" would swallow every
    admin/favicon probe and hand back the root body (caught red-first --
    /manager/html never classified).
    """
    def _http(url: str):
        val = routes.get(url)
        if val is None:
            raise urllib.error.HTTPError(url, 404, "Not Found", {},
                                         io.BytesIO(b""))
        status, headers, body, final = val
        if isinstance(body, str):
            body = body.encode()
        return status, {k.lower(): v for k, v in headers.items()}, body, final
    return _http


# --------------------------------------------------------------------------
# default offline run
# --------------------------------------------------------------------------

def test_default_run_is_offline_byte_identical_and_fully_skipped():
    bomb = NetworkBomb()
    a = build_inventory("example.com", as_of=AS_OF, send=bomb, http=bomb,
                        connect=bomb, cert_probe=bomb)
    b = build_inventory("example.com", as_of=AS_OF, send=bomb, http=bomb,
                        connect=bomb, cert_probe=bomb)
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)
    assert a["schema"] == collect.ASM_SCHEMA
    assert a["stats"]["hosts"] == 1
    assert a["storage"]["results"] == []
    # every stage disclosed; passive DNS is the connector slot
    reasons = {(s["stage"], s["reason"]) for s in a["skips"]}
    assert ("passive_dns", "no_provider_configured") in reasons
    for stage in ("dns_brute", "ct_logs", "resolve", "ports", "tls",
                  "http_root", "admin_probe", "storage"):
        assert (stage, "stage_not_requested") in reasons


def test_domain_validation_rejects_paths_and_spaces():
    with pytest.raises(ValueError):
        build_inventory("example.com/path", as_of=AS_OF)
    with pytest.raises(ValueError):
        build_inventory("two words", as_of=AS_OF)


# --------------------------------------------------------------------------
# DNS stages
# --------------------------------------------------------------------------

def test_resolve_stage_populates_addresses_and_records_skip():
    send = make_send({"example.com": {"a": ["93.184.216.27"]},
                      "www.example.com": {"a": ["1.2.3.4", "5.6.7.8"]}})
    doc = build_inventory("example.com", as_of=AS_OF,
                          stage_resolve=True, send=send)
    apex = doc["hosts"][0]
    assert apex["addresses"] == ["93.184.216.27"]
    # resolved second host? not present without brute/ct -- apex only
    assert doc["sources"] == [{"kind": "resolve", "status": "ok",
                               "detail": {"resolved": 1, "hosts": 1}}]
    assert not any(s["reason"] == "no_records" for s in doc["skips"])


def test_resolve_stage_records_no_records_skip_and_unreachable_error():
    # unresolvable apex -> no_records skip, source still ok
    doc = build_inventory("nx.example.com", as_of=AS_OF,
                          stage_resolve=True, send=make_send({}))
    assert any(s == {"stage": "resolve", "target": "nx.example.com",
                     "reason": "no_records"} for s in doc["skips"])
    # transport that blows up entirely -> stage error skip, no raise
    def bad_send(query):
        raise OSError("resolver down")
    doc = build_inventory("example.com", as_of=AS_OF,
                          stage_resolve=True, send=bad_send)
    src = [s for s in doc["sources"] if s["kind"] == "resolve"][0]
    assert src["status"] == "ok"           # per-name errors, stage survived
    assert any(s["stage"] == "resolve" and s["reason"] == "no_records"
               for s in doc["skips"])


def test_brute_stage_adds_hosts_from_wordlist():
    send = make_send({"example.com": {"a": ["9.9.9.9"]},
                      "api.example.com": {"a": ["10.0.0.5"]}})
    doc = build_inventory("example.com", as_of=AS_OF,
                          stage_brute=True, send=send, words=("api", "ghost"))
    hosts = [h["host"] for h in doc["hosts"]]
    assert hosts == ["api.example.com", "example.com"]
    src = [s for s in doc["sources"] if s["kind"] == "dns_brute"][0]
    assert src["status"] == "ok" and src["detail"]["found"] == 1


# --------------------------------------------------------------------------
# CT stage
# --------------------------------------------------------------------------

def _ct(rows):
    return json.dumps(rows).encode()


def test_ct_stage_from_payload_adds_hosts_and_is_deterministic():
    payload = _ct([{"name_value": "a.example.com\nb.example.com"},
                   {"name_value": "*.example.com"}])
    a = build_inventory("example.com", as_of=AS_OF, stage_ct=True,
                        ct_payload=payload)
    b = build_inventory("example.com", as_of=AS_OF, stage_ct=True,
                        ct_payload=payload)
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)
    assert [h["host"] for h in a["hosts"]] == \
        ["a.example.com", "b.example.com", "example.com"]
    src = [s for s in a["sources"] if s["kind"] == "ct_logs"][0]
    assert src["detail"]["input"] == "file"
    assert src["detail"]["wildcards_dropped"] == 1


def test_ct_stage_fetch_failure_becomes_skip_and_error_source():
    def boom(url):
        raise OSError("crt.sh unreachable")
    doc = build_inventory("example.com", as_of=AS_OF, stage_ct=True, http=boom)
    src = [s for s in doc["sources"] if s["kind"] == "ct_logs"][0]
    assert src["status"] == "error" and src["detail"] == "OSError"
    assert any(s["stage"] == "ct_logs" and
               "crt.sh unreachable" in s["reason"] for s in doc["skips"])


def test_ct_stage_host_cap_is_a_skip_not_a_crash():
    rows = [{"name_value": "\n".join(f"h{i}.example.com"
                                     for i in range(collect.MAX_HOSTS + 5))}]
    doc = build_inventory("example.com", as_of=AS_OF, stage_ct=True,
                          ct_payload=_ct(rows))
    assert doc["stats"]["hosts"] <= collect.MAX_HOSTS
    src = [s for s in doc["sources"] if s["kind"] == "ct_logs"][0]
    assert src["status"] == "error"
    assert any("host cap" in s["reason"] for s in doc["skips"])


# --------------------------------------------------------------------------
# ports + tls stages
# --------------------------------------------------------------------------

def test_ports_stage_scans_only_resolved_hosts():
    send = make_send({"example.com": {"a": ["1.1.1.1"]}})
    seen = []

    def connect(host, port, timeout):
        seen.append((host, port))
        return port == 443

    doc = build_inventory("example.com", as_of=AS_OF,
                          stage_resolve=True, stage_ports=True,
                          send=send, connect=connect)
    apex = doc["hosts"][0]
    assert [p["port"] for p in apex["ports"]["open"]] == [443]
    assert all(h == "example.com" for h, _ in seen)
    src = [s for s in doc["sources"] if s["kind"] == "ports"][0]
    assert src["detail"]["hosts"] == 1


def test_ports_stage_unresolved_host_is_disclosed():
    doc = build_inventory("example.com", as_of=AS_OF, stage_ports=True,
                          send=make_send({}), connect=lambda *_: True)
    # resolve is implied only via CLI; here addresses are empty -> skip
    assert any(s["stage"] == "ports" and s["reason"] == "unresolved"
               for s in doc["skips"])


def test_tls_stage_probe_populates_and_failures_skip():
    def probe(host, port, timeout, as_of):
        assert as_of == AS_OF
        return {"grade": "A", "host": host, "not_after": "2027-01-01"}

    doc = build_inventory("example.com", as_of=AS_OF, stage_tls=True,
                          send=make_send({"example.com": {"a": ["1.1.1.1"]}}),
                          cert_probe=probe)
    assert doc["hosts"][0]["tls"]["grade"] == "A"
    src = [s for s in doc["sources"] if s["kind"] == "tls"][0]
    assert src["detail"]["hosts"] == 1

    def dead(host, port, timeout, as_of):
        raise ConnectionRefusedError("closed")

    doc = build_inventory("example.com", as_of=AS_OF, stage_tls=True,
                          send=make_send({"example.com": {"a": ["1.1.1.1"]}}),
                          cert_probe=dead)
    assert doc["hosts"][0]["tls"] is None
    assert any(s["stage"] == "tls" and "ConnectionRefusedError" in s["reason"]
               for s in doc["skips"])


def test_tls_stage_unresolved_non_apex_skipped():
    payload = _ct([{"name_value": "ghost.example.com"}])
    doc = build_inventory("example.com", as_of=AS_OF, stage_ct=True,
                          stage_tls=True, ct_payload=payload,
                          send=make_send({}),
                          cert_probe=lambda **k: {"grade": "A"})
    assert any(s["stage"] == "tls" and s["target"] == "ghost.example.com"
               and s["reason"] == "unresolved" for s in doc["skips"])


# --------------------------------------------------------------------------
# http stage (tech + favicon + takeover + admin)
# --------------------------------------------------------------------------

_TOMCAT_HTML = b"<html><title>Apache Tomcat Manager</title></html>"
_ROOT_HTML = (
    b"<html><head><meta name='generator' content='WordPress 6.4'>"
    b"<link rel='icon' href='/favicon.ico'></head>"
    b"<body>hello</body></html>"
)


def _http_routes():
    return {
        "http://example.com/": (200, {"Server": "nginx"}, _ROOT_HTML,
                                "http://example.com/"),
        "http://example.com/favicon.ico": (200, {}, b"\x00\x00\x01\x00ico",
                                           "http://example.com/favicon.ico"),
        "http://example.com/manager/html": (200, {}, _TOMCAT_HTML,
                                            "http://example.com/manager/html"),
    }


def test_http_stage_tech_favicon_admin_wired():
    doc = build_inventory("example.com", as_of=AS_OF, stage_http=True,
                          http=make_http(_http_routes()))
    apex = doc["hosts"][0]
    assert any(t["sig_id"] == "meta_wordpress" for t in apex["techs"])
    assert apex["favicon"]["status"] == "hashed"
    assert apex["favicon"]["source"] == "linked"
    assert apex["admin"] == [{"path": "/manager/html", "status": 200,
                              "kind": "detected", "panel": "Tomcat Manager",
                              # evidence = matched pattern (stable), not
                              # body wording -- adminpaths contract
                              "evidence": "apache tomcat.*manager"}]
    kinds = [s["kind"] for s in doc["sources"]]
    assert "http_root" in kinds and "admin_paths" in kinds
    admin_src = [s for s in doc["sources"] if s["kind"] == "admin_paths"][0]
    assert admin_src["detail"]["hits"] == 1


def test_http_stage_root_failure_skips_admin_without_per_path_noise():
    def boom(url):
        raise OSError("web down")

    doc = build_inventory("example.com", as_of=AS_OF, stage_http=True,
                          http=boom)
    assert any(s["stage"] == "http_root" and "web down" in s["reason"]
               for s in doc["skips"])
    assert any(s["stage"] == "admin_probe" and
               s["reason"] == "root_fetch_failed" for s in doc["skips"])
    # no 60-odd per-path fetch_failed rows when the root is already down
    assert not any(s["stage"] == "admin_probe" and s["reason"] == "fetch_failed"
                   for s in doc["skips"])


def test_http_stage_takeover_correlates_cname_with_body():
    send = make_send({"example.com": {
        "a": ["1.1.1.1"],
        "cname": "parked.github.io"}})
    routes = dict(_http_routes())
    routes["http://example.com/"] = (
        200, {}, b"There isn't a GitHub Pages site here.",
        "http://example.com/")
    doc = build_inventory("example.com", as_of=AS_OF,
                          stage_resolve=True, stage_http=True,
                          send=send, http=make_http(routes))
    apex = doc["hosts"][0]
    assert apex["takeover"]["provider"] == "GitHub Pages"
    assert apex["takeover"]["confidence"] == "confirmed"


# --------------------------------------------------------------------------
# storage stage
# --------------------------------------------------------------------------

def test_storage_stage_classifies_public_and_private():
    def http(url):
        if "s3.amazonaws.com" in url:
            return (200, {}, b"<ListBucketResult><Contents/></ListBucketResult>",
                    url)
        if "blob.core.windows.net" in url:
            raise urllib.error.HTTPError(
                url, 403, "Forbidden", {}, io.BytesIO(
                    b"<Error><Code>AuthenticationRequired</Code></Error>"))
        raise urllib.error.HTTPError(
            url, 404, "Not Found", {}, io.BytesIO(
                b"<Error><Code>NoSuchBucket</Code></Error>"))

    doc = build_inventory("acme.example.com", as_of=AS_OF,
                          stage_storage=True, http=http)
    results = doc["storage"]["results"]
    by_prov = {r["provider"]: r for r in results}
    assert by_prov["aws_s3"]["posture"] == "public"
    assert by_prov["azure_blob"]["posture"] == "private"
    assert "gcs" not in by_prov                 # NoSuchBucket -> absent
    # tokens = acme + example (com = public suffix) x 3 providers = 6
    # probed; gcs x2 absent -> 4 hits
    assert {r["name"] for r in results if r["provider"] == "aws_s3"} == \
        {"acme", "example"}
    src = [s for s in doc["sources"] if s["kind"] == "storage"][0]
    assert src["detail"] == {"probed": 6, "hits": 4}


def test_storage_stage_transport_errors_become_skips():
    def http(url):
        raise OSError("no route to host")

    doc = build_inventory("acme.example.com", as_of=AS_OF,
                          stage_storage=True, http=http)
    assert doc["storage"]["results"] == []
    assert any(s["stage"] == "storage" for s in doc["skips"])


# --------------------------------------------------------------------------
# full staged reproducibility + CLI
# --------------------------------------------------------------------------

def _staged_doc(http=None, send=None):
    return build_inventory(
        "example.com", as_of=AS_OF,
        stage_resolve=True, stage_brute=True, stage_ct=True,
        stage_ports=True, stage_tls=True, stage_http=True,
        stage_storage=True,
        words=("api", "www"),
        ct_payload=_ct([{"name_value": "api.example.com\nwww.example.com"}]),
        send=send or make_send({
            "example.com": {"a": ["1.1.1.1"]},
            "api.example.com": {"a": ["10.0.0.1"]},
            "www.example.com": {"a": ["10.0.0.2"]},
        }),
        http=http or make_http(_http_routes()),
        connect=lambda h, p, t: p == 80,
        cert_probe=lambda **k: {"grade": "A", "not_after": "2027-01-01"},
    )


def test_full_staged_run_is_byte_identical_run_to_run():
    a = _staged_doc()
    b = _staged_doc()
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)
    assert a["stats"]["hosts"] == 3            # apex + api + www (CT+brute)
    assert a["stats"]["sources_ok"] >= 6


def test_cli_offline_run_writes_reproducible_artifact(tmp_path):
    out1 = tmp_path / "inv1.json"
    out2 = tmp_path / "inv2.json"
    rc1 = main(["example.com", "--as-of", "2026-10-31T12:00:00Z",
                "--out", str(out1)])
    rc2 = main(["example.com", "--as-of", "2026-10-31T12:00:00Z",
                "--out", str(out2)])
    assert rc1 == rc2 == 0
    assert out1.read_bytes() == out2.read_bytes()
    doc = json.loads(out1.read_text(encoding="utf-8"))
    assert doc["schema"] == collect.ASM_SCHEMA
    assert doc["as_of"] == "2026-10-31T12:00:00Z"


def test_cli_rejects_bad_domain_with_rc2(capsys):
    assert main(["example.com/path"]) == 2
    assert "error:" in capsys.readouterr().out
