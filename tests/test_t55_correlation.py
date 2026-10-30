"""T-5.5 SAST<->DAST correlation: same route + same sink -> one merged row.

The correlator is pure: findings lists in, additive ``rsecopsx.correlated_findings/v1``
document out.  SAST rows are never mutated (parity pin), sink-matched
pairs that cannot be route-linked are ANNOTATED as candidates with a
machine-readable reason (ground rule 2: no silent drops), and every
active check family has a positive and a negative control below.
"""
import json

from analysis.dast.checks import CHECKS
from analysis.dast.correlate import (
    CORRELATE_SCHEMA,
    SINK_CLASS_BY_CHECK,
    correlate,
)

_CHECK_BY_ID = {m["id"]: m for m in CHECKS}


def sast(vuln_type="sql_injection", cwe="CWE-89", file="app/views.py",
         line=10, rule_id="TAINT_SQL_INJECTION", finding_id="f-1",
         title="SQL Injection"):
    return {"finding_id": finding_id, "rule_id": rule_id, "title": title,
            "vuln_type": vuln_type, "cwe": cwe, "file": file, "line": line,
            "confidence": "HIGH"}


def dast(check="dast.sqli", route_key="GET /users", confidence="likely",
         severity=None, cwe=None, evidence=None, method="GET"):
    meta = _CHECK_BY_ID[check]
    return {"check": check, "severity": severity or meta["severity"],
            "confidence": confidence, "route_key": route_key,
            "method": method, "cwe": cwe if cwe is not None else meta.get("cwe", ""),
            "owasp": meta.get("owasp", ""), "evidence": evidence or {}}


# ---------------------------------------------------------------------------
# Registry integrity: every active check participates in the sink map
# ---------------------------------------------------------------------------

def test_sink_map_covers_every_dast_check():
    assert set(SINK_CLASS_BY_CHECK) == {m["id"] for m in CHECKS}
    for check, sink in SINK_CLASS_BY_CHECK.items():
        assert sink["cwes"], check
        assert isinstance(sink["vuln_types"], frozenset), check


def test_every_check_positive_control_sink_matches():
    """Positive control per active check: a same-CWE SAST row is sink-
    matched against that check (route linking then decides merge vs
    annotated candidate)."""
    for check in sorted(_CHECK_BY_ID):
        cwe = sorted(SINK_CLASS_BY_CHECK[check]["cwes"])[0]
        out = correlate([sast(cwe=cwe)], [dast(check=check)])
        assert out["stats"]["sink_matched"] == 1, check
        assert out["stats"]["merged"] + len(out["candidates"]) == 1, check


def test_every_check_negative_control_unrelated_sink_never_matches():
    """Negative control per active check: a hardcoded-secret style row
    (CWE-798) is never sink-matched, never merged, never a candidate."""
    for check in sorted(_CHECK_BY_ID):
        out = correlate(
            [sast(vuln_type="configuration_secret", cwe="CWE-798")],
            [dast(check=check)])
        assert out["stats"]["sink_matched"] == 0, check
        assert out["findings"] == [] and out["candidates"] == [], check


def test_linkable_checks_merge_on_same_route_and_sink():
    """The 15 route-bearing checks merge when the finding file lives on
    the route (tls_grade is excluded: its route_key is the ``*`` host
    sentinel and can never route-link -- disclosed, annotated instead)."""
    for check in sorted(_CHECK_BY_ID):
        if check == "dast.tls_grade":
            continue
        cwe = sorted(SINK_CLASS_BY_CHECK[check]["cwes"])[0]
        # path-segment fixture: route /vulns/x links to app/x/views.py
        out = correlate(
            [sast(cwe=cwe, file="app/x/views.py")],
            [dast(check=check, route_key="GET /vulns/x")])
        assert len(out["findings"]) == 1, check
        assert out["findings"][0]["check"] == check, check


def test_tls_star_route_never_links_and_is_annotated():
    cwe = sorted(SINK_CLASS_BY_CHECK["dast.tls_grade"]["cwes"])[0]
    out = correlate([sast(cwe=cwe, file="app/t/views.py")],
                    [dast(check="dast.tls_grade", route_key="*")])
    assert out["findings"] == []
    assert len(out["candidates"]) == 1
    assert out["candidates"][0]["reason"] == "route_not_linked"


# ---------------------------------------------------------------------------
# Merge semantics: confidence boost, single row, shape
# ---------------------------------------------------------------------------

def test_confidence_boost_table_tentative_likely_confirmed():
    for before, after in (("tentative", "likely"), ("likely", "confirmed"),
                          ("confirmed", "confirmed")):
        out = correlate([sast(file="app/x/views.py")],
                        [dast(confidence=before, route_key="GET /x")])
        assert out["findings"][0]["confidence"] == after, before


def test_unknown_confidence_passes_through_unboosted():
    out = correlate([sast(file="app/x/views.py")],
                    [dast(confidence="observed", route_key="GET /x")])
    assert out["findings"][0]["confidence"] == "observed"


def test_merged_row_shape_carries_both_sides_and_explanation():
    out = correlate([sast(file="app/x/views.py", line=42)],
                    [dast(route_key="GET /x", evidence={"signature": "s"})])
    row = out["findings"][0]
    for key in ("correlation_id", "route_key", "check", "cwe", "severity",
                "confidence", "sast", "dast", "linkage", "explanation"):
        assert key in row, key
    assert row["sast"]["file"] == "app/x/views.py" and row["sast"]["line"] == 42
    assert row["dast"]["confidence"] == "likely"
    assert row["dast"]["evidence_keys"] == ["signature"]
    assert row["linkage"]["route"] in ("route_file", "path_segments")
    assert row["linkage"]["sink"] in ("cwe", "vuln_type")
    assert "GET /x" in row["explanation"] and "CWE-89" in row["explanation"]
    assert row["correlation_id"] == "corr-0001"


def test_severity_takes_dast_side():
    out = correlate([sast(file="app/x/views.py")],
                    [dast(route_key="GET /x", severity="critical")])
    assert out["findings"][0]["severity"] == "critical"


def test_one_sast_two_dast_checks_only_matching_sink_merges():
    out = correlate(
        [sast(cwe="CWE-89", file="app/x/views.py")],
        [dast(check="dast.sqli", route_key="GET /x"),
         dast(check="dast.cmdi", route_key="GET /x")])
    assert [f["check"] for f in out["findings"]] == ["dast.sqli"]


def test_two_sast_rows_same_route_sink_both_merge():
    out = correlate(
        [sast(finding_id="f-1", line=10, file="app/x/views.py"),
         sast(finding_id="f-2", line=20, file="app/x/views.py")],
        [dast(route_key="GET /x")])
    assert len(out["findings"]) == 2
    assert [f["sast"]["finding_id"] for f in out["findings"]] == ["f-1", "f-2"]


# ---------------------------------------------------------------------------
# Route linkage strategies
# ---------------------------------------------------------------------------

def test_route_file_linkage_via_apibom_with_param_shape_match():
    # apibom route is templated (/users/{user_id}); the DAST side saw the
    # concrete /users/42 -- shape match, param names are irrelevant.
    apibom = [{"file": "app/views.py", "route": "/users/{user_id}",
               "methods": ["GET"], "line": 8}]
    out = correlate(
        [sast(file="app/views.py")],
        [dast(route_key="GET /users/42")],
        apibom_items=apibom)
    row = out["findings"][0]
    assert row["linkage"]["route"] == "route_file"
    assert row["route_key"] == "GET /users/42"


def test_route_file_requires_method_compatibility():
    apibom = [{"file": "app/views.py", "route": "/users",
               "methods": ["POST"], "line": 8}]
    out = correlate(
        [sast(file="app/views.py")],
        [dast(route_key="GET /users", method="GET")],
        apibom_items=apibom)
    # method mismatch -> route_file rejected; path_segments: 'users' is
    # not a file segment of app/views.py -> annotated, not merged.
    assert out["findings"] == []
    assert len(out["candidates"]) == 1


def test_route_file_unknown_method_is_wildcard():
    apibom = [{"file": "app/views.py", "route": "/users",
               "methods": ["UNKNOWN"], "line": 8}]
    out = correlate(
        [sast(file="app/views.py")],
        [dast(route_key="GET /users")],
        apibom_items=apibom)
    assert out["findings"][0]["linkage"]["route"] == "route_file"


def test_path_segments_linkage_dvwa_style_directory_routes():
    out = correlate(
        [sast(file="vulnerabilities/sqli/source/high.php", cwe="CWE-89")],
        [dast(check="dast.sqli", route_key="GET /vulnerabilities/sqli")])
    assert out["findings"][0]["linkage"]["route"] == "path_segments"


def test_path_segments_last_segment_rule_juice_shop_style():
    # routes/search.ts links to /rest/products/search ('rest' is a
    # generic route segment and is dropped before matching):
    ok = correlate(
        [sast(file="routes/search.ts", cwe="CWE-89")],
        [dast(route_key="GET /rest/products/search")])
    assert ok["findings"] and ok["findings"][0]["linkage"]["route"] == "path_segments"
    # ...but an unrelated handler file on the same tree does NOT link:
    no = correlate(
        [sast(file="routes/captcha.ts", cwe="CWE-89")],
        [dast(route_key="GET /rest/products/search")])
    assert no["findings"] == [] and len(no["candidates"]) == 1


def test_generic_segments_do_not_satisfy_linkage():
    # /api/v1/ has nothing left after generic drops -> no link
    out = correlate([sast(file="src/app/api_client.py", cwe="CWE-89")],
                    [dast(route_key="GET /api/v1")])
    assert out["findings"] == []


def test_sink_only_pair_is_annotated_candidate_not_dropped():
    out = correlate(
        [sast(file="unrelated/module.py")],
        [dast(route_key="GET /x")])
    assert out["findings"] == []
    cand = out["candidates"][0]
    assert cand["reason"] == "route_not_linked"
    assert cand["sast"]["file"] == "unrelated/module.py"
    assert cand["dast"]["route_key"] == "GET /x"
    assert cand["sink"]["matched_on"] == "cwe"


def test_vuln_type_is_a_secondary_sink_signal():
    # a row whose cwe is absent/empty still matches via vuln_type
    out = correlate(
        [sast(vuln_type="sql_injection", cwe="", file="app/x/views.py")],
        [dast(route_key="GET /x")])
    assert out["findings"][0]["linkage"]["sink"] == "vuln_type"


# ---------------------------------------------------------------------------
# Document contract: stats, determinism, immutability, empty inputs
# ---------------------------------------------------------------------------

def test_stats_add_up():
    out = correlate(
        [sast(file="app/x/views.py"), sast(file="elsewhere/mod.py",
                                           finding_id="f-2")],
        [dast(route_key="GET /x"), dast(check="dast.cmdi",
                                        route_key="GET /y")])
    st = out["stats"]
    assert st["merged"] == st["route_linked"] == len(out["findings"])
    assert st["sink_only"] == len(out["candidates"])
    assert st["pairs_considered"] == st["sink_matched"] == 2
    assert sum(st["by_check"].values()) == st["merged"]


def test_determinism_across_runs():
    a = correlate([sast(file="app/x/views.py"), sast(file="app/y.py",
                                                     cwe="CWE-78")],
                  [dast(route_key="GET /x"),
                   dast(check="dast.cmdi", route_key="GET /y")])
    b = correlate([sast(file="app/x/views.py"), sast(file="app/y.py",
                                                     cwe="CWE-78")],
                  [dast(route_key="GET /x"),
                   dast(check="dast.cmdi", route_key="GET /y")])
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


def test_inputs_never_mutated():
    s = [sast(file="app/x/views.py")]
    d = [dast(route_key="GET /x", evidence={"signature": "s"})]
    apibom = [{"file": "app/views.py", "route": "/x", "methods": ["GET"],
               "line": 8}]
    before = json.dumps((s, d, apibom), sort_keys=True)
    correlate(s, d, apibom_items=apibom)
    assert json.dumps((s, d, apibom), sort_keys=True) == before


def test_empty_inputs_yield_valid_empty_document():
    out = correlate([], [], apibom_items=[])
    assert out["schema"] == CORRELATE_SCHEMA
    assert out["findings"] == [] and out["candidates"] == []
    assert out["stats"]["merged"] == 0


def test_unknown_check_is_counted_unmapped_not_crashed():
    out = correlate([sast()],
                    [{"check": "dast.future_check", "route_key": "GET /x",
                      "confidence": "likely", "severity": "low",
                      "cwe": "CWE-0", "method": "GET", "evidence": {}}])
    assert out["stats"]["unmapped_checks"] == ["dast.future_check"]
    assert out["findings"] == []


def test_cli_smoke_roundtrip(tmp_path):
    import analysis.dast.correlate as C

    sast_doc = {"findings": [sast(file="app/x/views.py")]}
    dast_doc = {"schema": "rsecopsx.dast_findings/v1",
                "findings": [dast(route_key="GET /x")]}
    sp = tmp_path / "sast.json"
    dp = tmp_path / "dast.json"
    op = tmp_path / "out.json"
    sp.write_text(json.dumps(sast_doc), encoding="utf-8")
    dp.write_text(json.dumps(dast_doc), encoding="utf-8")
    rc = C.main(["--sast", str(sp), "--dast", str(dp), "--out", str(op)])
    assert rc == 0
    doc = json.loads(op.read_text(encoding="utf-8"))
    assert doc["schema"] == CORRELATE_SCHEMA
    assert len(doc["findings"]) == 1


def test_cli_rejects_unreadable_input(tmp_path):
    import analysis.dast.correlate as C
    rc = C.main(["--sast", str(tmp_path / "missing.json"),
                 "--dast", str(tmp_path / "missing2.json")])
    assert rc == 2

def test_build_target_model_attaches_crawl_auth_headers(tmp_path):
    """T-5.5: authenticated crawl passthrough -- the Cookie header must
    reach the fetch, and the unauthenticated default stays intact."""
    from analysis.dast.crawler import FetchResponse
    from analysis.dast.target_model import build_target_model

    (tmp_path / "index.html").write_text(
        "<a href=\"/about\">about</a>", encoding="utf-8")
    seen = []

    def fake_fetch(url, timeout_s, user_agent, headers=None):
        seen.append(dict(headers or {}))
        return FetchResponse(url=url, status=200, headers={},
                             body="<html><a href=\"/about\">x</a></html>")

    model = build_target_model(tmp_path, crawl_url="http://t.local/",
                               fetch=fake_fetch,
                               crawl_auth_headers={"Cookie": "sess=abc"})
    assert model["stats"]["crawl"] is not None
    assert seen and seen[0].get("Cookie") == "sess=abc"

    seen.clear()
    model2 = build_target_model(tmp_path, crawl_url="http://t.local/",
                                fetch=fake_fetch)
    assert seen and "Cookie" not in (seen[0] or {})

def test_crawl_respect_robots_opt_out_for_authorized_targets(tmp_path):
    """DVWA ships robots.txt 'Disallow: /'; the default crawl stops
    (T-5.1 robots-aware contract) and crawl_respect_robots=False is the
    authorized-testing opt-out."""
    from analysis.dast.crawler import FetchResponse
    from analysis.dast.target_model import build_target_model

    (tmp_path / "index.html").write_text("x", encoding="utf-8")

    def fake_fetch(url, timeout_s, user_agent, headers=None):
        if url.rstrip("/").endswith("robots.txt"):
            return FetchResponse(url=url, status=200, headers={},
                                 body="User-Agent: *\nDisallow: /\n")
        return FetchResponse(url=url, status=200, headers={},
                             body='<html><a href="/about">x</a></html>')

    polite = build_target_model(tmp_path, crawl_url="http://t.local/",
                                fetch=fake_fetch)
    assert len(polite["stats"]["crawl"]["pages"]) <= 1
    assert polite["stats"]["crawl"]["blocked_by_robots"]

    opted = build_target_model(tmp_path, crawl_url="http://t.local/",
                               fetch=fake_fetch, crawl_respect_robots=False)
    assert len(opted["stats"]["crawl"]["pages"]) >= 2
    assert opted["stats"]["crawl"]["blocked_by_robots"] == []


def test_crawl_exclude_paths_never_fetches_logout(tmp_path):
    """An authenticated crawl that follows logout.php destroys its own
    session; crawl_exclude=('/logout.php',) keeps it out of the frontier
    and discloses it in the crawl report's ``excluded`` list."""
    from analysis.dast.crawler import FetchResponse
    from analysis.dast.target_model import build_target_model

    (tmp_path / "index.html").write_text("x", encoding="utf-8")
    requested = []

    def fake_fetch(url, timeout_s, user_agent, headers=None):
        requested.append(url)
        return FetchResponse(url=url, status=200, headers={},
                             body=('<html><a href="/logout.php">x</a>'
                                   '<a href="/about">y</a></html>'))

    model = build_target_model(tmp_path, crawl_url="http://t.local/",
                               fetch=fake_fetch, crawl_respect_robots=False,
                               crawl_exclude=("/logout.php",))
    assert not any(u.endswith("/logout.php") for u in requested)
    assert model["stats"]["crawl"]["excluded"] == ["http://t.local/logout.php"]
    assert "http://t.local/about" in requested
