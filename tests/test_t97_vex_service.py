"""T-9.7 SBOM/VEX service -- offline ingest + query (task.md section 12).

Gates pinned here (task.md section 12 PHASE 9 "SBOM/VEX service"):

* ingest our own ``build_vex`` statements round-trip (status vocabulary,
  product->component name mapping);
* ingest CycloneDX ``vulnerabilities[]`` (state mapping, multi-affects)
  and OpenVEX single statements;
* SBOM components reuse ``scanner.sbom_reader``; join counts matched /
  unmatched statements; declared VEX stays unmerged at the scanner level
  (mixing happens only here, at the query surface);
* conflicts are REPORT-ONLY (same vulnerability+component with two
  statuses is counted, never silently precedence-picked);
* queries by vulnerability / component / status embed their matches;
* deterministic + order-independent output; default run is zero-I/O
  with exactly two ``not_provided`` skips;
* CLI rc0 written / rc1 loud (ALL input errors collected, NO partial
  artifact) / rc2 usage;
* no banned network imports (offline invariant).
"""
from __future__ import annotations

import ast
import json
import pathlib

import pytest

from analysis.vex import (
    SCHEMA, VEX_STATUSES, VexInvalid, build, conflicts_for,
    component_key, normalize_status, normalize_vex_doc, run_queries,
)
from analysis.vex.connect import main as connect_main
from reporting.vex_export import build_vex

REPO = pathlib.Path(__file__).resolve().parents[1]


def _ours_stmt(vuln="CVE-2026-0001", name="flask", version="2.0.1",
               purl="pkg:pypi/flask@2.0.1", status="affected",
               bom_ref="pkg:pypi/flask@2.0.1"):
    return {
        "vulnerability": {"id": vuln, "source": "NVD"},
        "product": {"component": name, "version": version,
                    "ecosystem": "PyPI", "bom_ref": bom_ref, "purl": purl},
        "status": status,
        "justification": "reachable_code",
        "impact_statement": "impact",
        "action_statement": "action",
        "timestamp": "2026-10-31T00:00:00+00:00",
    }


def _ours_doc(*stmts):
    return {"document": {"type": "R-SecOpsX VEX", "version": "1.1"},
            "statements": list(stmts)}


def _cdx_vuln(vid="CVE-2026-0002", state="exploitable",
              refs=("pkg:pypi/requests@2.31.0",), justification="m"):
    return {
        "id": vid,
        "analysis": {"state": state, "justification": justification,
                     "detail": "detail"},
        "affects": [{"ref": r} for r in refs],
    }


def _cdx_doc(*vulns):
    return {"bomFormat": "CycloneDX", "specVersion": "1.6",
            "vulnerabilities": list(vulns)}


def _sbom_doc():
    return {"components": [
        {"name": "flask", "version": "2.0.1", "ecosystem": "PyPI",
         "license": "BSD", "purl": "pkg:pypi/flask@2.0.1", "cpe": None,
         "direct": True, "sbom_ref": "pkg:pypi/flask@2.0.1",
         "ingested_from": "sbom.json"},
        {"name": "requests", "version": "2.31.0", "ecosystem": "PyPI",
         "license": "Apache-2.0", "purl": "pkg:pypi/requests@2.31.0",
         "cpe": None, "direct": False, "sbom_ref": "pkg:pypi/requests@2.31.0",
         "ingested_from": "sbom.json"},
    ]}


# ---------------------------------------------------------------------------
# A. model contracts
# ---------------------------------------------------------------------------


def test_default_run_is_zero_io_with_two_not_provided_skips():
    doc = build([], [], [])
    assert doc["schema"] == SCHEMA
    assert doc["statements"] == [] and doc["components"] == []
    assert doc["conflicts"] == [] and doc["queries"] == []
    assert doc["skips"] == [
        {"reason": "not_provided", "source": "vex"},
        {"reason": "not_provided", "source": "sbom"},
    ]
    assert doc["stats"]["statements"] == 0
    assert doc["stats"]["skipped_statements"] == 0
    assert "as_of" not in doc          # absent unless --as-of supplied


def test_status_normalization_aliases_and_honest_nulls():
    assert normalize_status("affected") == "affected"
    assert normalize_status("not-affected") == "not_affected"
    assert normalize_status("NOT AFFECTED") == "not_affected"
    assert normalize_status("exploitable") == "affected"
    assert normalize_status("in_triage") == "under_investigation"
    assert normalize_status("resolved") == "fixed"
    assert normalize_status("resolved_with_pedigree") == "fixed"
    assert normalize_status("mystery_state") is None
    assert normalize_status(None) is None
    assert normalize_status("") is None
    assert set(VEX_STATUSES) == {"affected", "not_affected",
                                 "under_investigation", "fixed"}


def test_ours_statement_ingest_maps_component_name_and_status():
    rows, skips = normalize_vex_doc(_ours_doc(_ours_stmt()), "ours.json")
    assert skips == []
    assert len(rows) == 1
    row = rows[0]
    assert row["vulnerability"] == "CVE-2026-0001"
    assert row["source_format"] == "rsecopsx_vex"
    assert row["status"] == "affected"
    # product.component is OUR name for the package -- mapped to name
    assert row["component"]["name"] == "flask"
    assert row["component"]["version"] == "2.0.1"
    assert row["component"]["purl"] == "pkg:pypi/flask@2.0.1"
    assert row["justification"] == "reachable_code"


def test_ours_row_junk_is_annotated_never_silently_dropped():
    doc = _ours_doc(
        42,                                    # not an object
        {"status": "affected"},                # no vulnerability id
        _ours_stmt(vuln="CVE-2026-9", status="mystery_state"),
        _ours_stmt(vuln="CVE-2026-1"),
    )
    rows, skips = normalize_vex_doc(doc, "ours.json")
    assert len(rows) == 1 and rows[0]["vulnerability"] == "CVE-2026-1"
    assert [s["reason"] for s in skips] == [
        "statement_not_object:0",
        "vulnerability_missing:1",
        "statement_status_unrecognized:mystery_state",
    ]
    doc_out = build([("ours.json", doc)], [], [])
    assert doc_out["stats"]["skipped_statements"] == 3


def test_ours_missing_status_is_honest_null_not_guessed():
    stmt = _ours_stmt()
    del stmt["status"]
    rows, skips = normalize_vex_doc(_ours_doc(stmt), "ours.json")
    assert skips == []
    assert rows[0]["status"] is None


def test_cdx_state_mapping_multi_affects_and_unknown_state():
    doc = _cdx_doc(
        _cdx_vuln(vid="CVE-A", state="exploitable", refs=("ref-1", "ref-2")),
        _cdx_vuln(vid="CVE-B", state="resolved"),
        _cdx_vuln(vid="CVE-C", state="in_triage"),
        _cdx_vuln(vid="CVE-D", state="mystery"),
    )
    rows, skips = normalize_vex_doc(doc, "cdx.json")
    by_vuln = {}
    for row in rows:
        by_vuln.setdefault(row["vulnerability"], []).append(row)
    assert len(by_vuln["CVE-A"]) == 2          # one row per affects ref
    assert {r["status"] for r in by_vuln["CVE-A"]} == {"affected"}
    assert by_vuln["CVE-B"][0]["status"] == "fixed"
    assert by_vuln["CVE-C"][0]["status"] == "under_investigation"
    assert "CVE-D" not in by_vuln
    assert skips == [{"reason": "statement_status_unrecognized:mystery",
                      "source": "cdx.json"}]


def test_cdx_doc_without_vulnerabilities_is_valid_empty():
    rows, skips = normalize_vex_doc(
        {"bomFormat": "CycloneDX", "specVersion": "1.5",
         "components": []}, "sbom.json")
    assert rows == [] and skips == []


def test_openvex_single_statement_and_multi_products():
    doc = {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "vulnerability": {"@id": "https://nvd.nist.gov/vuln/detail/CVE-1"},
        "products": [{"@id": "pkg:npm/left@1.0.0"},
                     {"@id": "pkg:npm/right@2.0.0"}],
        "status": "not_affected",
        "justification": "code_not_present",
        "status_notes": "not in the binary",
        "timestamp": "2026-10-01T00:00:00Z",
    }
    rows, skips = normalize_vex_doc(doc, "openvex.json")
    assert skips == [] and len(rows) == 2
    assert rows[0]["source_format"] == "openvex"
    assert {r["status"] for r in rows} == {"not_affected"}
    assert rows[0]["component"]["bom_ref"] == "pkg:npm/left@1.0.0"
    assert rows[0]["detail"] == "not in the binary"
    assert rows[0]["vulnerability"] == \
        "https://nvd.nist.gov/vuln/detail/CVE-1"
    # document-level: an OpenVEX doc with no recognizable status is fatal
    # (the whole document IS the statement)
    with pytest.raises(VexInvalid) as exc:
        normalize_vex_doc({"status": "wildcard", "vulnerability": "CVE-X"},
                          "openvex.json")
    assert exc.value.reason.startswith("statement_status_unrecognized:")


def test_unrecognised_vex_format_is_fatal_with_reason():
    with pytest.raises(VexInvalid) as exc:
        normalize_vex_doc({"foo": 1}, "x.json")
    assert exc.value.reason == "unrecognised_vex_format:x.json"
    with pytest.raises(VexInvalid) as exc:
        normalize_vex_doc({"statements": "nope"}, "y.json")
    assert exc.value.reason == "vex_statement_list_expected:y.json"


def test_conflicts_are_report_only_sorted_and_counted():
    doc = _ours_doc(
        _ours_stmt(vuln="CVE-C1", status="affected"),
        _ours_stmt(vuln="CVE-C1", status="not_affected"),
        _ours_stmt(vuln="CVE-C1", status="not_affected"),   # same status OK
        _ours_stmt(vuln="CVE-C2", status="fixed"),
    )
    doc_out = build([("a.json", doc)], [], [])
    assert doc_out["stats"]["statements"] == 4          # none rewritten
    assert doc_out["conflicts"] == [{
        "vulnerability": "CVE-C1",
        "component": "pkg:pypi/flask@2.0.1",
        "statuses": ["affected", "not_affected"],
    }]
    assert doc_out["stats"]["conflicts"] == 1
    # order independence: same statements ingested in reverse order
    other = build([("a.json", _ours_doc(*reversed(doc["statements"])))],
                  [], [])
    assert other["conflicts"] == doc_out["conflicts"]
    assert [s["vulnerability"] for s in other["statements"]] == \
        [s["vulnerability"] for s in doc_out["statements"]]
    assert json.dumps(other, sort_keys=True) == \
        json.dumps(doc_out, sort_keys=True)


def test_build_is_order_independent_byte_identical():
    d1 = _cdx_doc(_cdx_vuln(vid="CVE-X", state="exploitable"),
                  _cdx_vuln(vid="CVE-Y", state="resolved"))
    d2 = _ours_doc(_ours_stmt(vuln="CVE-Z", status="fixed"))
    a = json.dumps(build([("1.json", d1), ("2.json", d2)], [], []),
                   sort_keys=True)
    b = json.dumps(build([("2.json", d2), ("1.json", d1)], [], []),
                   sort_keys=True)
    assert a == b
    # statements sorted by (vulnerability, component key, source doc)
    doc_out = build([("2.json", d2), ("1.json", d1)], [], [])
    assert [s["vulnerability"] for s in doc_out["statements"]] == \
        ["CVE-X", "CVE-Y", "CVE-Z"]


def test_queries_by_vulnerability_component_and_status():
    vex = ("ours.json", _ours_doc(
        _ours_stmt(vuln="CVE-Q1", status="affected"),
        _ours_stmt(vuln="CVE-Q2", status="fixed",
                   name="requests", version="2.31.0",
                   purl="pkg:pypi/requests@2.31.0"),
    ))
    doc_out = build([vex], [("sbom.json", _sbom_doc())], [
        ("vulnerability", "cve-q1"),          # case-insensitive
        ("component", "pkg:pypi/requests@2.31.0"),
        ("status", "affected"),
    ])
    q_vuln, q_comp, q_status = doc_out["queries"]
    assert q_vuln["kind"] == "vulnerability" and q_vuln["count"] == 1
    assert q_vuln["statements"][0]["vulnerability"] == "CVE-Q1"
    assert q_comp["count"] == 1
    assert q_comp["statements"][0]["vulnerability"] == "CVE-Q2"
    assert q_comp["components"][0]["name"] == "requests"
    assert q_status["kind"] == "status" and q_status["count"] == 1
    assert q_status["statements"][0]["vulnerability"] == "CVE-Q1"


def test_sbom_join_counts_match_by_purl_and_bom_ref_and_name():
    vex = ("ours.json", _ours_doc(
        _ours_stmt(vuln="CVE-M1"),                                # purl hit
        _ours_stmt(vuln="CVE-M2", purl=None, bom_ref="other-ref",
                   name="requests", version="2.31.0"),            # name hit
        _ours_stmt(vuln="CVE-M3", purl=None, bom_ref="ref-x",
                   name="ghost", version="9.9.9"),                # miss
    ))
    doc_out = build([vex], [("sbom.json", _sbom_doc())], [])
    stats = doc_out["stats"]
    assert stats["components"] == 2
    assert stats["statements_matched_to_sbom"] == 2
    assert stats["statements_unmatched_to_sbom"] == 1
    assert stats["by_status"] == {"affected": 3}
    # component rows are the fixed sbom_reader projection
    comp = doc_out["components"][0]
    assert set(comp) == {"name", "version", "ecosystem", "license",
                         "purl", "cpe", "direct", "sbom_ref",
                         "ingested_from"}


def test_component_key_prefers_purl_then_name_version():
    assert component_key({"purl": "pkg:pypi/x@1"}) == "pkg:pypi/x@1"
    assert component_key({"name": "x", "version": "1"}) == "x@1"
    assert component_key({"name": "x"}) == "x"
    assert component_key({"version": "1"}) == ""
    assert component_key("junk") == ""


def test_conflicts_for_is_pure_and_sorted():
    stmts = [
        {"vulnerability": "CVE-B", "component": {"purl": "p2"},
         "status": "fixed"},
        {"vulnerability": "CVE-A", "component": {"purl": "p1"},
         "status": "affected"},
        {"vulnerability": "CVE-A", "component": {"purl": "p1"},
         "status": "under_investigation"},
    ]
    out = conflicts_for(stmts)
    assert [c["vulnerability"] for c in out] == ["CVE-A"]
    assert out[0]["statuses"] == ["affected", "under_investigation"]
    assert run_queries(stmts, [], [("status", "fixed")])[0]["count"] == 1


def test_model_has_no_banned_network_imports():
    for rel in ("analysis/vex/model.py", "analysis/vex/connect.py"):
        src = (REPO / rel).read_text(encoding="utf-8")
        tree = ast.parse(src)
        banned = {"urllib", "socket", "requests", "boto3", "http",
                  "subprocess"}
        top = []
        for node in tree.body:
            if isinstance(node, ast.Import):
                top.extend(a.name for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                top.append(node.module)
        assert not (set(top) & banned), (rel, top)
        for token in ("urllib", "boto3", "requests", "os.environ",
                      "http.client", "socket."):
            assert token not in src, (rel, token)


# ---------------------------------------------------------------------------
# B. CLI
# ---------------------------------------------------------------------------


def test_cli_default_run_writes_deterministic_artifact(tmp_path, capsys):
    out = tmp_path / "store.json"
    assert connect_main(["--out", str(out)]) == 0
    first = out.read_bytes()
    assert first.endswith(b"\n")
    doc = json.loads(first)
    assert doc["schema"] == SCHEMA
    assert doc["skips"] == [
        {"reason": "not_provided", "source": "vex"},
        {"reason": "not_provided", "source": "sbom"},
    ]
    assert "vex service: wrote" in capsys.readouterr().out
    assert connect_main(["--out", str(out)]) == 0
    assert out.read_bytes() == first


def test_cli_as_of_is_optional_echo(tmp_path):
    out = tmp_path / "store.json"
    assert connect_main(["--as-of", "2026-10-31T00:00:00Z",
                         "--out", str(out)]) == 0
    assert json.loads(out.read_text(encoding="utf-8"))["as_of"] == \
        "2026-10-31T00:00:00Z"
    with pytest.raises(SystemExit) as eu:
        connect_main(["--as-of", "not-a-date", "--out", str(out)])
    assert eu.value.code == 2


def test_cli_rc1_collects_every_input_error_with_no_partial(tmp_path,
                                                            capsys):
    bad_json = tmp_path / "bad.json"
    bad_json.write_text("{nope", encoding="utf-8")
    arr = tmp_path / "arr.json"
    arr.write_text("[1]", encoding="utf-8")
    shape = tmp_path / "shape.json"
    shape.write_text(json.dumps({"foo": 1}), encoding="utf-8")
    out = tmp_path / "store.json"
    rc = connect_main([
        "--vex", str(tmp_path / "missing.json"),
        "--vex", str(bad_json),
        "--vex", str(arr),
        "--vex", str(shape),
        "--out", str(out),
    ])
    assert rc == 1 and not out.exists()
    text = capsys.readouterr().out
    assert "vex service error: vex_file_does_not_exist:" in text
    assert "vex service error: vex_not_json:" in text
    assert "vex service error: vex_not_an_object:" in text
    assert "vex service error: unrecognised_vex_format:" in text
    # reasons printed in sorted order (deterministic diagnostics)
    reasons = [l for l in text.splitlines() if l.startswith("vex service")]
    assert reasons == sorted(reasons)


def test_cli_shape_errors_across_multiple_vex_inputs_all_collected(
        tmp_path, capsys):
    a = tmp_path / "a.json"
    a.write_text(json.dumps({"statements": "nope"}), encoding="utf-8")
    b = tmp_path / "b.json"
    b.write_text(json.dumps({"foo": 2}), encoding="utf-8")
    out = tmp_path / "store.json"
    rc = connect_main(["--vex", str(a), "--vex", str(b),
                       "--out", str(out)])
    assert rc == 1 and not out.exists()
    text = capsys.readouterr().out
    assert "vex_statement_list_expected:" in text
    assert "unrecognised_vex_format:" in text


def test_cli_usage_errors_are_rc2(tmp_path):
    with pytest.raises(SystemExit) as eu:
        connect_main([])                     # --out required
    assert eu.value.code == 2
    with pytest.raises(SystemExit) as eu:
        connect_main(["--status", "wildcard",
                      "--out", str(tmp_path / "x.json")])
    assert eu.value.code == 2                # choices=VEX_STATUSES


def test_cli_end_to_end_with_sbom_and_all_query_kinds(tmp_path, capsys):
    vex = tmp_path / "ours.json"
    vex.write_text(json.dumps(_ours_doc(
        _ours_stmt(vuln="CVE-E2E"),
        _ours_stmt(vuln="CVE-E2E2", status="fixed", name="requests",
                   version="2.31.0", purl="pkg:pypi/requests@2.31.0"),
    )), encoding="utf-8")
    sbom = tmp_path / "sbom.json"
    sbom.write_text(json.dumps({
        "bomFormat": "CycloneDX", "specVersion": "1.5",
        "components": [
            {"type": "library", "name": "flask", "version": "2.0.1",
             "purl": "pkg:pypi/flask@2.0.1"},
            {"type": "library", "name": "requests", "version": "2.31.0",
             "purl": "pkg:pypi/requests@2.31.0"},
        ],
    }), encoding="utf-8")
    out = tmp_path / "store.json"
    rc = connect_main([
        "--vex", str(vex), "--sbom", str(sbom),
        "--vulnerability", "CVE-E2E",
        "--component", "pkg:pypi/requests@2.31.0",
        "--status", "fixed",
        "--out", str(out),
    ])
    assert rc == 0
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["stats"]["statements"] == 2
    assert doc["stats"]["components"] == 2
    assert doc["stats"]["statements_matched_to_sbom"] == 2
    assert doc["skips"] == []
    assert [q["count"] for q in doc["queries"]] == [1, 1, 1]


def test_cli_sbom_read_error_is_loud_and_reason_carried(tmp_path, capsys):
    xml = tmp_path / "sbom.xml"
    xml.write_text("<?xml version='1.0'?><bom/>", encoding="utf-8")
    out = tmp_path / "store.json"
    rc = connect_main(["--sbom", str(xml), "--out", str(out)])
    assert rc == 1 and not out.exists()
    text = capsys.readouterr().out
    assert "vex service error: sbom_read_error:" in text
    assert "XML" in text


def test_cli_input_size_cap_is_enforced(tmp_path, monkeypatch, capsys):
    import analysis.vex.connect as connect
    small = tmp_path / "small.json"
    small.write_text(json.dumps(_ours_doc(_ours_stmt())),
                     encoding="utf-8")
    monkeypatch.setattr(connect, "MAX_INPUT_BYTES", 10)
    out = tmp_path / "store.json"
    rc = connect_main(["--vex", str(small), "--out", str(out)])
    assert rc == 1 and not out.exists()
    assert "input_too_large:" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# C. integration with existing surfaces
# ---------------------------------------------------------------------------


def test_roundtrip_our_vex_export_build_vex(tmp_path):
    payload = {
        "sbom": [
            {"name": "flask", "version": "2.0.1", "ecosystem": "PyPI",
             "cve": "CVE-2026-0001", "purl": "pkg:pypi/flask@2.0.1",
             "vex_status": "affected"},
            {"name": "django", "version": "4.2.0", "ecosystem": "PyPI",
             "cve": "CVE-2026-0002", "purl": "pkg:pypi/django@4.2.0",
             "fixed_in": "4.2.1", "status": "fixed"},
            {"name": "novuln", "version": "1.0", "ecosystem": "PyPI"},
        ],
        "metadata": {},
    }
    vex = build_vex(payload)
    path = tmp_path / "security_report.vex.json"
    path.write_text(json.dumps(vex), encoding="utf-8")

    from analysis.vex.connect import _load_vex
    doc_out = build([(str(path), _load_vex(str(path)))], [], [])
    assert doc_out["stats"]["statements"] == 2      # novuln has no id
    rows = {r["vulnerability"]: r for r in doc_out["statements"]}
    assert rows["CVE-2026-0001"]["status"] == "affected"
    assert rows["CVE-2026-0001"]["component"]["name"] == "flask"
    assert rows["CVE-2026-0002"]["status"] == "fixed"
    assert rows["CVE-2026-0002"]["component"]["name"] == "django"
    # statuses agree with the exporter's own vocabulary normalization
    exported = {s["vulnerability"]["id"]: s["status"]
                for s in vex["statements"]}
    assert exported == {k: rows[k]["status"] for k in exported}


def test_reader_preserves_declared_cdx_vex_and_service_owns_the_mixing():
    from scanner.sbom_reader import read_sbom
    import tempfile
    with tempfile.TemporaryDirectory(prefix="rsx_t97_") as tmp:
        path = pathlib.Path(tmp) / "cdx.json"
        path.write_text(json.dumps({
            "bomFormat": "CycloneDX", "specVersion": "1.6",
            "components": [{"type": "library", "name": "requests",
                            "version": "2.31.0",
                            "bom-ref": "pkg:pypi/requests@2.31.0",
                            "purl": "pkg:pypi/requests@2.31.0"}],
            "vulnerabilities": [_cdx_vuln(refs=("pkg:pypi/requests@2.31.0",))],
        }), encoding="utf-8")
        doc = read_sbom(str(path))
        # the scanner preserves declared VEX verbatim but does NOT merge
        # it into its package records (policy from T-9.x sbom_reader)
        assert doc["vulnerabilities"] == [_cdx_vuln(
            refs=("pkg:pypi/requests@2.31.0",))]
        for comp in doc["components"]:
            assert "vex_status" not in comp and "status" not in comp
        # the SERVICE is the surface that turns those statements into
        # queryable rows, next to (not inside) the scanner's records
        rows, skips = normalize_vex_doc(
            {"bomFormat": "CycloneDX",
             "vulnerabilities": doc["vulnerabilities"]}, str(path))
        assert skips == [] and rows[0]["status"] == "affected"
        doc_out = build([(str(path), {
            "bomFormat": "CycloneDX",
            "vulnerabilities": doc["vulnerabilities"]})],
            [(str(path), doc)], [("vulnerability", "CVE-2026-0002")])
        assert doc_out["queries"][0]["count"] == 1
        assert doc_out["stats"]["statements_matched_to_sbom"] == 1
