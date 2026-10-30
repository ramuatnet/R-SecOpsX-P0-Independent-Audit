"""T-6.1: ASM core units -- hashing, DNS codec, CT, ports, TLS, tech,
favicon, takeover, admin paths, storage.

Everything here is offline: transports are fakes, clocks are injected,
certificates are generated in-process.  The one live-shaped surface
(murmur/favicon) is pinned against canonical vectors so cross-tool
correlation cannot silently drift.
"""
from __future__ import annotations

import json
import struct

import pytest

from analysis.asm import adminpaths, ctlog, fingerprint, ports, storage, takeover, tlsinfo
from analysis.asm.dnsx import (DnsFormatError, QTYPE_A, QTYPE_CNAME,
                               brute_subdomains, build_query, decode_name,
                               encode_name, parse_response, resolve_name)
from analysis.asm.favicon import (extract_icon_href, favicon_record,
                                  same_origin)
from analysis.asm.hashing import favicon_hash, murmur3_32


# --------------------------------------------------------------------------
# hashing
# --------------------------------------------------------------------------

def test_murmur3_canonical_vectors():
    """mmh3.hash('foo') == -156908512 is THE widely published vector; the
    rest were cross-checked against an independent transcription."""
    assert murmur3_32(b"foo") == -156908512
    assert murmur3_32(b"") == 0
    assert murmur3_32(b"hello") == 0x248BFA47
    assert murmur3_32(b"hello world") == 0x5E928F0F


def test_murmur3_signed_return_and_seed():
    # signed int32 convention (Shodan compares signed hashes)
    assert -0x80000000 <= murmur3_32(b"x") <= 0x7FFFFFFF
    # seed changes the result
    assert murmur3_32(b"foo", seed=1) != murmur3_32(b"foo")


def test_favicon_hash_follows_data_uri_recipe():
    import base64
    icon = b"\x00\x00\x01\x00fake-icon-bytes"
    expected = murmur3_32(
        ("data:image/x-icon;base64," +
         base64.b64encode(icon).decode()).encode("ascii"))
    assert favicon_hash(icon) == expected
    assert favicon_hash(icon) != favicon_hash(icon + b"x")


# --------------------------------------------------------------------------
# DNS codec
# --------------------------------------------------------------------------

def test_encode_decode_roundtrip():
    wire = encode_name("www.example.com")
    assert wire == b"\x03www\x07example\x03com\x00"
    name, end = decode_name(wire, 0)
    assert name == "www.example.com"
    assert end == len(wire)


def test_encode_rejects_oversized_label():
    with pytest.raises(DnsFormatError):
        encode_name("a" * 64 + ".example.com")


def test_decode_pointer_compression_and_cursor():
    # full name occupies 13 bytes; a compressed copy starts at 13
    buf = b"\x07example\x03com\x00" + b"\xc0\x00"   # pointer to offset 0
    assert len(b"\x07example\x03com\x00") == 13
    name, end = decode_name(buf, 13)
    assert name == "example.com"
    assert end == 15                                # consumed the 2 pointer bytes


def test_decode_self_pointer_rejected():
    buf = b"\xc0\x00"
    with pytest.raises(DnsFormatError):
        decode_name(buf, 0)


def test_decode_truncated_label_rejected():
    with pytest.raises(DnsFormatError):
        decode_name(b"\x05ab", 0)                   # declares 5, has 2


def test_build_query_header_and_question():
    q = build_query("example.com", QTYPE_A, txn_id=0x1234)
    tid, flags, qd, an, ns, ar = struct.unpack_from(">HHHHHH", q, 0)
    assert (tid, flags, qd, an, ns, ar) == (0x1234, 0x0100, 1, 0, 0, 0)
    assert q.endswith(struct.pack(">HH", QTYPE_A, 1))
    with pytest.raises(DnsFormatError):
        build_query("example.com", 999)             # unsupported type


def _mk_response(query: bytes, answers: list[tuple[str, int, bytes]],
                 rcode: int = 0, flags_extra: int = 0) -> bytes:
    """Craft a response echoing the query question, with answers whose
    names are compressed onto the question (0xC00C -- question at 12)."""
    tid = struct.unpack_from(">H", query, 0)[0]
    flags = 0x8180 | rcode | flags_extra
    header = struct.pack(">HHHHHH", tid, flags, 1, len(answers), 0, 0)
    question = query[12:]
    body = b""
    for name, rtype, rdata in answers:
        body += b"\xc0\x0c" + struct.pack(">HHIH", rtype, 1, 60, len(rdata))
        body += rdata
    return header + question + body


def test_parse_response_a_record():
    q = build_query("example.com", QTYPE_A, txn_id=7)
    resp = _mk_response(q, [("example.com", QTYPE_A, b"\x5d\xb8\xd8\x1b")])
    out = parse_response(resp, expect_id=7)
    assert out["rcode"] == 0
    assert out["answers"] == [
        {"name": "example.com", "type": 1, "type_name": "A",
         "ttl": 60, "data": "93.184.216.27"}]


def test_parse_response_nxdomain_and_truncated_flag():
    q = build_query("nope.example.com", QTYPE_A, txn_id=8)
    out = parse_response(_mk_response(q, [], rcode=3), expect_id=8)
    assert out["rcode"] == 3 and out["answers"] == []
    out2 = parse_response(_mk_response(q, [], flags_extra=0x0200), expect_id=8)
    assert out2["truncated"] is True


def test_parse_response_txn_mismatch_and_short_packet():
    q = build_query("example.com", QTYPE_A, txn_id=7)
    resp = _mk_response(q, [("example.com", QTYPE_A, b"\x01\x02\x03\x04")])
    with pytest.raises(DnsFormatError):
        parse_response(resp, expect_id=9)
    with pytest.raises(DnsFormatError):
        parse_response(b"\x00" * 8)


def test_resolve_name_uses_injected_send():
    seen = {}

    def fake_send(query: bytes) -> bytes:
        seen["q"] = query
        return _mk_response(query, [("api.example.com", QTYPE_A,
                                     b"\x0a\x00\x00\x01")])

    answers = resolve_name("api.example.com", QTYPE_A, fake_send, txn_id=1)
    assert answers[0]["data"] == "10.0.0.1"
    assert "q" in seen


def test_brute_subdomains_normalizes_and_is_deterministic():
    def fake_send(query: bytes) -> bytes:
        # only www + api resolve; decode the question via the codec
        name, _ = decode_name(query, 12)
        if name.startswith(("www.", "api.")):
            return _mk_response(query, [(name, QTYPE_A, b"\x0a\x00\x00\x01")])
        return _mk_response(query, [], rcode=3)

    words = ["WWW", "www", " api ", "# comment", "*.wild", "", "api", "nope"]
    r1 = brute_subdomains("example.com", words, fake_send)
    r2 = brute_subdomains("example.com", words, fake_send)
    assert json.dumps(r1, sort_keys=True) == json.dumps(r2, sort_keys=True)
    assert [h["host"] for h in r1["hosts"]] == ["api.example.com",
                                                "www.example.com"]
    assert r1["stats"]["found"] == 2
    assert r1["stats"]["wordlist_truncated"] is False
    # comment/blank/wildcard dropped, case+space normalized, dup collapsed:
    # www, api, nope
    assert r1["stats"]["words"] == 3


def test_brute_subdomains_word_cap_disclosed():
    def fake_send(query: bytes) -> bytes:
        return _mk_response(query, [], rcode=3)

    r = brute_subdomains("example.com", [f"w{i}" for i in range(20)],
                         fake_send, limit=5)
    assert r["stats"]["words"] == 5
    assert r["stats"]["wordlist_truncated"] is True


# --------------------------------------------------------------------------
# CT logs
# --------------------------------------------------------------------------

def _ct_payload(rows):
    return json.dumps(rows).encode()


def test_parse_crtsh_filters_and_sorts():
    payload = _ct_payload([
        {"name_value": "a.example.com\nb.example.com"},
        {"name_value": "*.example.com"},                 # wildcard dropped
        {"name_value": "other.org"},                     # foreign dropped
        {"name_value": "A.EXAMPLE.COM."},                # normalize + dedup
        {"name_value": "b.example.com"},
        "not-a-dict",
        {"name_value": 42},
    ])
    out = ctlog.parse_crtsh(payload, "example.com")
    assert out["names"] == ["a.example.com", "b.example.com"]
    assert out["stats"]["wildcards_dropped"] == 1
    assert out["stats"]["foreign_dropped"] == 1
    assert out["stats"]["found"] == 2


def test_parse_crtsh_bad_payloads():
    with pytest.raises(ctlog.CtParseError):
        ctlog.parse_crtsh(b"not json", "example.com")
    with pytest.raises(ctlog.CtParseError):
        ctlog.parse_crtsh(b'{"not": "a list"}', "example.com")
    with pytest.raises(ctlog.CtParseError):
        ctlog.parse_crtsh(b"x" * (ctlog.MAX_CT_RESPONSE_BYTES + 1),
                          "example.com")


def test_parse_crtsh_name_cap_disclosed():
    rows = [{"name_value": f"h{i}.example.com"} for i in range(30)]
    out = ctlog.parse_crtsh(_ct_payload(rows), "example.com", limit=10)
    assert len(out["names"]) == 10
    assert out["stats"]["name_cap_hit"] is True


def test_fetch_crtsh_builds_url_and_injects_fetch():
    urls = []

    def fake_fetch(url: str) -> bytes:
        urls.append(url)
        return _ct_payload([{"name_value": "x.example.com"}])

    out = ctlog.fetch_crtsh("example.com", fake_fetch)
    assert out["names"] == ["x.example.com"]
    assert "%25.example.com" in urls[0] and "crt.sh" in urls[0]


def test_merge_names_union_sorted_deduped():
    assert ctlog.merge_names(["b.X.com", "a.x.com"],
                             ["A.x.com", "c.x.com."]) == \
        ["a.x.com", "b.x.com", "c.x.com"]


# --------------------------------------------------------------------------
# ports
# --------------------------------------------------------------------------

def test_scan_ports_sorted_open_and_service_labels():
    def connect(host, port, timeout):
        return port in (8080, 22)

    out = ports.scan_ports("h", ports=[8080, 9999, 22, 8080, 70000, -1],
                           connect=connect)
    assert [p["port"] for p in out["open"]] == [22, 8080]
    assert out["open"][0]["service"] == "ssh"
    assert out["open"][1]["service"] == "http-proxy"
    assert out["stats"]["requested"] == 3          # dup + 2 invalids dropped
    assert out["stats"]["refused"] == 1            # only 9999 refused


def test_scan_ports_cap_disclosed_and_workers_bounded():
    out = ports.scan_ports("h", ports=range(1, 100), connect=lambda *_: False,
                           cap=10, workers=9999)
    assert out["stats"]["requested"] == 10
    assert out["stats"]["port_cap_hit"] is True
    assert out["stats"]["workers"] <= ports.MAX_WORKERS


def test_scan_ports_empty_input_is_empty_not_error():
    out = ports.scan_ports("h", ports=[0, 99999, "junk"], connect=lambda *_: True)
    assert out["open"] == [] and out["stats"]["requested"] == 0


# --------------------------------------------------------------------------
# TLS certificate inventory
# --------------------------------------------------------------------------

def _make_cert(self_signed: bool = True, expired: bool = False):
    """Generate a real DER in-process (cryptography is present in dev;
    the no-crypto path is exercised by import-skipping elsewhere)."""
    from datetime import datetime, timedelta, timezone
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,
                                             "t61-test")])
    now = datetime(2026, 6, 1, tzinfo=timezone.utc)
    not_before = now - timedelta(days=30)
    not_after = now + (timedelta(days=-1) if expired else timedelta(days=90))
    builder = (x509.CertificateBuilder()
               .subject_name(subject)
               .issuer_name(subject if self_signed else
                            x509.Name([x509.NameAttribute(
                                NameOID.COMMON_NAME, "t61-ca")]))
               .public_key(key.public_key())
               .serial_number(x509.random_serial_number())
               .not_valid_before(not_before)
               .not_valid_after(not_after)
               .add_extension(x509.SubjectAlternativeName(
                   [x509.DNSName("t61.test")]), critical=False))
    if not self_signed:
        # signed by a different key than the subject key: issuer != subject
        ca_key = ec.generate_private_key(ec.SECP256R1())
        cert = builder.sign(ca_key, hashes.SHA256())
    else:
        cert = builder.sign(key, hashes.SHA256())
    der = cert.public_bytes(serialization.Encoding.DER)
    return der


def test_analyze_cert_self_signed_grades_t():
    from datetime import datetime, timezone
    der = _make_cert(self_signed=True)
    rec = tlsinfo.analyze_cert(der, as_of=datetime(2026, 6, 15,
                                                   tzinfo=timezone.utc))
    assert rec["grade"] == "T" and rec["self_signed"] is True
    assert rec["expired"] is False
    assert rec["subject"] and rec["issuer"]
    assert rec["sans"] == ["t61.test"]
    assert rec["days_left"] == 76                   # Jun 15 -> Sep 1 +90-14
    assert len(rec["sha256"]) == 64


def test_analyze_cert_expired_untrusted_grades_e():
    from datetime import datetime, timezone
    der = _make_cert(self_signed=False, expired=True)
    rec = tlsinfo.analyze_cert(der, as_of=datetime(2026, 6, 15,
                                                   tzinfo=timezone.utc),
                               verified=False,
                               verify_error="SSLCertVerificationError: expired")
    assert rec["grade"] == "E" and rec["expired"] is True
    assert rec["self_signed"] is False
    assert rec["days_left"] < 0


def test_analyze_cert_trusted_valid_grades_a_and_untrusted_grades_u():
    from datetime import datetime, timezone
    der = _make_cert(self_signed=False, expired=False)
    clock = datetime(2026, 6, 15, tzinfo=timezone.utc)
    ok = tlsinfo.analyze_cert(der, as_of=clock, verified=True)
    bad = tlsinfo.analyze_cert(der, as_of=clock, verified=False,
                               verify_error="hostname mismatch")
    assert ok["grade"] == "A" and bad["grade"] == "U"
    # same input + same clock => byte-identical records
    assert tlsinfo.analyze_cert(der, as_of=clock, verified=True) == ok


def test_analyze_cert_rejects_bad_der():
    with pytest.raises(ValueError):
        tlsinfo.analyze_cert(b"")
    with pytest.raises(ValueError):
        tlsinfo.analyze_cert(b"x" * (tlsinfo.MAX_DER_BYTES + 1))


def test_probe_certificate_retries_unverified_after_verify_error():
    import ssl
    from datetime import datetime, timezone
    der = _make_cert(self_signed=True)
    calls = []

    def probe(host, port, timeout, require_verified):
        calls.append(require_verified)
        if require_verified:
            raise ssl.SSLCertVerificationError("self-signed certificate")
        return der

    rec = tlsinfo.probe_certificate("h", 443, 1.0,
                                    as_of=datetime(2026, 6, 15,
                                                   tzinfo=timezone.utc),
                                    probe=probe)
    assert calls == [True, False]
    assert rec["verified"] is False
    assert "self-signed" in rec["verify_error"]
    assert rec["grade"] == "T"


def test_probe_certificate_dead_endpoint_raises_for_stage_skip():
    def probe(host, port, timeout, require_verified):
        raise ConnectionRefusedError("nope")

    with pytest.raises(ConnectionRefusedError):
        tlsinfo.probe_certificate("h", 443, 0.1, probe=probe)


# --------------------------------------------------------------------------
# tech fingerprint
# --------------------------------------------------------------------------

def test_fingerprint_headers_cookies_meta_body():
    out = fingerprint.fingerprint(
        {"Server": "nginx/1.24", "X-Powered-By": "PHP/8.2",
         "Set-Cookie": "PHPSESSID=abc123; path=/"},
        "<html><meta name='generator' content='WordPress 6.4'>"
        "<link href='/wp-content/x.css'></html>")
    sig_ids = [m["sig_id"] for m in out]
    assert sig_ids == sorted(sig_ids)               # deterministic order
    assert {"srv_nginx", "xph_php", "ck_php",
            "meta_wordpress", "bdy_wp"} <= set(sig_ids)


def test_fingerprint_generator_meta_attribute_order():
    for html in ("<meta name=\"generator\" content=\"Django 5.0\">",
                 "<meta content=\"Django 5.0\" name=\"generator\">"):
        out = fingerprint.fingerprint({}, html)
        assert any(m["sig_id"] == "meta_django" for m in out)


def test_fingerprint_no_evidence_no_claims_and_evidence_capped():
    assert fingerprint.fingerprint({"server": "weird"}, "<html></html>") == []
    out = fingerprint.fingerprint(
        {"server": "nginx " + "x" * 500}, "")
    assert out and len(out[0]["token"]) <= fingerprint.MAX_EVIDENCE


def test_fingerprint_bad_signature_row_is_survivable():
    extra = [("bad_rx", "body", "text", "([unclosed", "X")]
    # invalid regex must be skipped, not raise
    assert fingerprint.fingerprint({}, "text", extra_signatures=extra) == []


# --------------------------------------------------------------------------
# favicon
# --------------------------------------------------------------------------

def test_extract_icon_href_attribute_order_and_variants():
    assert extract_icon_href(
        '<link rel="icon" href="/a.ico">') == "/a.ico"
    assert extract_icon_href(
        '<link href="/b.png" rel="shortcut icon">') == "/b.png"
    assert extract_icon_href(
        '<link rel="apple-touch-icon" href="/c.png">') == "/c.png"
    assert extract_icon_href('<link rel="stylesheet" href="/s.css">') is None
    assert extract_icon_href("<html></html>") is None


def test_same_origin_normalizes_default_ports():
    assert same_origin("http://h/x.ico", "http://h:80/page")
    assert same_origin("https://h/x.ico", "https://h/page")
    assert not same_origin("https://h/x.ico", "http://h/page")
    assert not same_origin("http://evil/x.ico", "http://h/page")
    assert not same_origin("http://h:8080/x", "http://h/x")   # explicit port


def test_favicon_record_hashes_same_origin_icon():
    icon = b"\x00\x00\x01\x00icon-payload"
    fetched = []

    def fetch(url):
        fetched.append(url)
        return icon

    rec = favicon_record("http://h/app/", '<link rel="icon" href="/favicon.ico">',
                         fetch)
    assert rec["status"] == "hashed"
    assert rec["murmur32"] == favicon_hash(icon)
    assert rec["size"] == len(icon) and len(rec["sha256"]) == 64
    assert fetched == ["http://h/favicon.ico"]


def test_favicon_record_foreign_icon_never_fetched():
    def fetch(url):
        raise AssertionError("must not fetch foreign icons")

    rec = favicon_record("http://h/", '<link rel="icon" href="https://cdn.x/i.ico">',
                         fetch)
    assert rec["status"] == "foreign_icon"
    assert rec["murmur32"] is None


def test_favicon_record_statuses():
    rec = favicon_record("http://h/", "<html></html>", lambda u: b"")
    assert rec["status"] == "empty"

    def boom(url):
        raise OSError("down")

    rec = favicon_record("http://h/", "<html></html>", boom)
    assert rec["status"] == "fetch_failed_OSError"

    rec = favicon_record("http://h/", "<html></html>",
                         lambda u: b"y" * (2 * 1024 * 1024 + 1))
    assert rec["status"] == "toobig"
    # no link tag -> conventional /favicon.ico; source says fallback,
    # status says the fetch outcome
    rec = favicon_record("http://h/", "<html></html>", lambda u: b"icon")
    assert rec["source"] == "fallback"
    assert rec["status"] == "hashed" and rec["murmur32"] is not None


# --------------------------------------------------------------------------
# takeover
# --------------------------------------------------------------------------

def test_match_cname_label_boundary_and_longest_suffix():
    m = takeover.match_cname("user.github.io")
    assert m["provider"] == "GitHub Pages" and m["confidence"] == "tentative"
    assert takeover.match_cname("evilgithub.io") is None    # boundary!
    assert takeover.match_cname("a.b.cloudfront.net")["provider"] == \
        "AWS CloudFront"
    assert takeover.match_cname("x.s3-website-us-east-1.amazonaws.com")[
        "provider"] == "AWS S3 website"
    assert takeover.match_cname(None) is None
    assert takeover.match_cname("normal.example.com") is None


def test_match_body_markers():
    out = takeover.match_body(
        "There isn't a GitHub Pages site here.")
    assert out[0]["provider"] == "GitHub Pages"
    assert out[0]["confidence"] == "confirmed"
    assert takeover.match_body("ordinary page") == []


def test_correlate_takeover_needs_both_for_confirmed():
    both = takeover.correlate_takeover(
        "user.github.io", "There isn't a GitHub Pages site here.")
    assert both["confidence"] == "confirmed" and both["provider"] == \
        "GitHub Pages"
    # cname alone: normal setup, NOT a finding
    assert takeover.correlate_takeover("user.github.io", "hello") is None
    # body alone: tentative, never confirmed without the cname
    alone = takeover.correlate_takeover("app.example.com",
                                        "There isn't a GitHub Pages site here.")
    assert alone["confidence"] == "tentative"
    assert "no_matching_cname" in alone["evidence"]
    # disagreement keeps both signals, downgrades to tentative
    disagree = takeover.correlate_takeover("site.azurewebsites.net",
                                           "There isn't a GitHub Pages site here.")
    assert disagree["confidence"] == "tentative"
    assert any("azure" in e for e in disagree["evidence"])


# --------------------------------------------------------------------------
# admin paths
# --------------------------------------------------------------------------

def test_classify_admin_restricted_detected_and_noise():
    # restricted panels are inventory hits even without a body
    assert adminpaths.classify_admin_response(
        "/admin", 401, {}, "")["kind"] == "restricted"
    assert adminpaths.classify_admin_response(
        "/x", 403, {}, "")["kind"] == "restricted"
    # detected via panel marker
    hit = adminpaths.classify_admin_response(
        "/manager/html", 200, {},
        "<title>Apache Tomcat Manager</title>")
    assert hit["kind"] == "detected" and hit["panel"] == "Tomcat Manager"
    # detected via login title -- the WordPress-specific marker wins over
    # the generic login-form fallback (more precise panel name)
    hit = adminpaths.classify_admin_response(
        "/wp-login.php", 200, {}, "<title>Log In &#8212; WordPress</title>")
    assert hit["panel"] == "WordPress Login"
    # generic login title falls back to Login Form
    hit = adminpaths.classify_admin_response(
        "/admin", 200, {}, "<title>Please sign in</title>")
    assert hit["panel"] == "Login Form"
    # Spring whitelabel default page is NOT a panel
    assert adminpaths.classify_admin_response(
        "/actuator", 200, {},
        "<html><body>Whitelabel Error Page</body></html>") is None
    # generic SPA catch-all must not count
    assert adminpaths.classify_admin_response(
        "/admin", 200, {}, "<title>Home</title><div>app</div>") is None
    # 404/500 are not hits
    assert adminpaths.classify_admin_response("/admin", 404, {}, "") is None
    assert adminpaths.classify_admin_response("/admin", 500, {}, "") is None


def test_admin_paths_normalized_deduped_and_capped():
    paths = adminpaths.admin_paths(extra=["admin", "/admin", "/custom/"])
    assert "/admin" in paths and "admin" not in paths
    assert "/custom/" in paths
    assert len(paths) == len(set(paths))
    big = [f"/p{i}" for i in range(300)]
    kept, dropped = adminpaths.cap_for(big)
    assert len(kept) == adminpaths.MAX_ADMIN_PATHS
    assert dropped == 300 - adminpaths.MAX_ADMIN_PATHS
    kept2, dropped2 = adminpaths.cap_for(paths)
    assert dropped2 == 0 and kept2 == paths


# --------------------------------------------------------------------------
# storage
# --------------------------------------------------------------------------

def test_bucket_candidates_tokens_sorted_deduped_capped():
    out = storage.bucket_candidates(["ACME", "acme corp", "acme-corp", "*.x"])
    names = [(c["provider"], c["name"]) for c in out]
    assert names == sorted(names)
    # sanitize: upper->lower, spaces->dash, deduped; "*.x" -> "x" dropped
    assert [n for p, n in names if p == "aws_s3"] == ["acme", "acme-corp"]
    assert all(" " not in c["name"] and "*" not in c["name"] for c in out)
    assert all(c["url"].startswith("https://") for c in out)
    # cap + disclosure
    st = storage.candidates_with_stats([f"t{i}" for i in range(40)])
    assert st["stats"]["candidates"] == 40 * len(storage.PROVIDERS)
    assert st["stats"]["emitted"] == storage.MAX_CANDIDATES
    assert st["stats"]["cap_hit"] is True


def test_classify_storage_responses():
    # true negative
    assert storage.classify_storage_response(
        "aws_s3", 404, "<Error><Code>NoSuchBucket</Code></Error>") is None
    # private bucket exists
    v = storage.classify_storage_response(
        "aws_s3", 403, "<Error><Code>AccessDenied</Code></Error>")
    assert v == {"exists": True, "public": False, "posture": "private",
                 "provider": "aws_s3", "evidence": "http_403"}
    # public listing
    v = storage.classify_storage_response(
        "aws_s3", 200, "<ListBucketResult><Contents/></ListBucketResult>")
    assert v["public"] is True and v["posture"] == "public"
    # denied-on-404: existence beats status
    v = storage.classify_storage_response(
        "azure_blob", 404, "AuthenticationRequired for this resource")
    assert v["exists"] is True and v["posture"] == "private"
    # plain 404 with no provider evidence: absence
    assert storage.classify_storage_response("aws_s3", 404, "not here") is None
    # odd verb on existing bucket
    v = storage.classify_storage_response("aws_s3", 400, "bad request")
    assert v["exists"] is True and v["posture"] == "unknown"
    # garbage status input
    assert storage.classify_storage_response("aws_s3", "junk", "") is None
