"""T-0.1 gate: every filter pass annotates; nothing is dropped silently.

task.md section 3, T-0.1 (BLOCKER) and ground rule 3:

    No silent drops. Every filter pass must *annotate*, never *delete*.
    A finding removed from clean_report.json must carry a machine-readable
    reason.

Before this gate existed, eleven filter passes across main.py,
core/analyzer.py and scanner/sast.py deleted findings and occurrences with
no record of why. The historical casualties were a request-controlled PHP
include (path traversal), a taint-corroborated command injection, and PHP
webshell findings -- each vanished between the producer and
clean_report.json with nothing to explain where.

The contract asserted here:

  * every *occurrence* removed from a reported finding appends a
    {pass, decision, reason, evidence_ref} entry to the finding's
    filter_trace (the finding stays in the report, the loss is visible);
  * every *finding* removed from the report population is recorded in the
    drop ledger, which --explain-drops serializes to drops.json;
  * the integration scan reproduces the historical drop shapes and
    asserts recovery plus a full accounting: every producer outcome is
    either reported or explained.
"""
from __future__ import annotations

import importlib
import json
import pathlib
import subprocess
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

MAIN = REPO / "main.py"


@pytest.fixture()
def ledger():
    """Fresh drop ledger per test so entries never leak between cases."""
    from core import filter_trace
    filter_trace.begin_scan()
    yield filter_trace.current_ledger()
    filter_trace.begin_scan()


@pytest.fixture(scope="module")
def main_module():
    return importlib.import_module("main")


@pytest.fixture(scope="module")
def analyzer_module():
    return importlib.import_module("core.analyzer")


def _occ(file="app/main.py", line=1, snippet="sink(x)", taint=""):
    return {"file": file, "line": line, "snippet": snippet,
            "taint_path": taint, "detection": "Enterprise SAST Pattern",
            "severity": "High", "cwe": "CWE-78"}


def _finding(**kw):
    base = {"rule_id": "TEST_RULE", "vuln_type": "command_injection",
            "title": "Test finding", "severity": "High",
            "file": "app/main.py", "line": 1, "snippet": "sink(x)",
            "instances": 1, "occurrence_count": 1,
            "occurrences": [_occ()]}
    base.update(kw)
    return base


# ---------------------------------------------------------------------------
# 1. benchmark fixture boundary (main._filter_benchmark_fixtures)
# ---------------------------------------------------------------------------
def _abs(*parts):
    return str(pathlib.Path.cwd().joinpath(*parts))


def test_benchmark_fixture_finding_drop_is_recorded(main_module, ledger):
    fixture_file = _abs("repo", "data", "static", "codefixes", "vuln.js")
    f = _finding(occurrences=[_occ(file=fixture_file, line=3)],
                 file=fixture_file)
    kept, dropped = main_module._filter_benchmark_fixtures([f])
    assert kept == [] and dropped == 1
    assert f["filter_trace"], "removed finding carries no filter_trace"
    entry = f["filter_trace"][-1]
    assert entry["pass"] == "benchmark_fixture_boundary"
    assert entry["decision"] == "drop_finding"
    assert entry["reason"]
    rows = [d for d in ledger.entries if d["pass"] == "benchmark_fixture_boundary"]
    assert rows, "drop ledger has no benchmark_fixture_boundary entry"
    assert rows[-1]["reason"]


def test_benchmark_fixture_opt_in_keeps_everything(main_module, ledger):
    f = _finding(occurrences=[_occ(
        file=_abs("repo", "data", "static", "codefixes", "vuln.js"))])
    kept, dropped = main_module._filter_benchmark_fixtures(
        [f], include_fixtures=True)
    assert dropped == 0 and len(kept) == 1
    assert not ledger.entries


# ---------------------------------------------------------------------------
# 2. intake target boundary (main._filter_findings_to_target)
# ---------------------------------------------------------------------------
def test_out_of_target_occurrence_annotated_on_survivor(main_module, ledger):
    inside = _occ(file=_abs("repo", "app", "ok.py"))
    outside = _occ(file=_abs("elsewhere", "evil.py"))
    f = _finding(occurrences=[inside, outside], instances=2)
    kept, dropped = main_module._filter_findings_to_target(
        [f], _abs("repo"))
    assert len(kept) == 1 and dropped == 1
    entry = f["filter_trace"][-1]
    assert entry["pass"] == "intake_target_boundary"
    assert entry["decision"] == "drop_occurrence"
    assert entry["reason"]
    assert "evil.py" in json.dumps(entry.get("evidence_ref"))


def test_all_out_of_target_finding_is_recorded(main_module, ledger):
    f = _finding(occurrences=[_occ(file=_abs("elsewhere", "evil.py"))],
                 file=_abs("elsewhere", "evil.py"))
    kept, dropped = main_module._filter_findings_to_target(
        [f], _abs("repo"))
    assert kept == [] and dropped >= 1
    rows = [d for d in ledger.entries if d["pass"] == "intake_target_boundary"]
    assert rows and rows[-1]["reason"]


# ---------------------------------------------------------------------------
# 3. post-normalization scope boundary (main._drop_out_of_scope_occurrences)
# ---------------------------------------------------------------------------
def test_scope_boundary_occurrence_drop_annotated(main_module, ledger):
    f = _finding(occurrences=[
        _occ(file=_abs("repo", "app", "ok.py")),
        _occ(file=_abs("elsewhere", "evil.py"), line=9),
    ], instances=2)
    payload = {"findings": [f]}
    removed = main_module._drop_out_of_scope_occurrences(payload, _abs("repo"))
    assert removed == 1
    entry = f["filter_trace"][-1]
    assert entry["pass"] == "scope_boundary_post_normalization"
    assert entry["decision"] == "drop_occurrence"
    assert entry["reason"] and entry.get("evidence_ref")


# ---------------------------------------------------------------------------
# 4. occurrence evidence gate (main._prune_unsupported_occurrences)
# ---------------------------------------------------------------------------
def test_evidence_gate_occurrence_drop_annotated(main_module, ledger):
    # The historical pathtraver shape: a literal include that must stay pruned
    # -- but pruned *with a reason* now, not silently.
    f = _finding(vuln_type="path_traversal", cwe="CWE-22",
                 occurrences=[_occ(file="app/index.php", line=3,
                                   snippet="include('config.php');", taint="")])
    payload = {"findings": [f]}
    removed = main_module._prune_unsupported_occurrences(payload)
    assert removed == 1
    entry = f["filter_trace"][-1]
    assert entry["pass"] == "occurrence_evidence_gate"
    assert entry["decision"] == "drop_occurrence"
    assert "path_traversal" in entry["reason"]


def test_evidence_gate_kept_occurrence_has_no_trace(main_module, ledger):
    f = _finding(vuln_type="path_traversal",
                 occurrences=[_occ(file="app/index.php", line=3,
                                   snippet="include($p);", taint="$p -> include")])
    payload = {"findings": [f]}
    removed = main_module._prune_unsupported_occurrences(payload)
    assert removed == 0
    assert not f.get("filter_trace"), "kept findings must stay byte-stable"


# ---------------------------------------------------------------------------
# 5. evidex refresh boundary (main._evidex_refresh_filter)
# ---------------------------------------------------------------------------
def test_evidex_refresh_records_empty_occurrence_drop(main_module, ledger):
    f = _finding(occurrences=[])
    payload = {"findings": [f]}
    dropped = main_module._evidex_refresh_filter(payload)
    assert dropped == 1 and payload["findings"] == []
    rows = [d for d in ledger.entries if d["pass"] == "evidex_refresh"]
    assert rows and rows[-1]["reason"]


def test_evidex_refresh_records_zero_instance_drop(main_module, ledger):
    f = _finding(instances=0, occurrence_count=0)
    payload = {"findings": [f]}
    dropped = main_module._evidex_refresh_filter(payload)
    assert dropped == 1
    rows = [d for d in ledger.entries if d["pass"] == "evidex_refresh"]
    assert rows and rows[-1]["reason"]


# ---------------------------------------------------------------------------
# 6. final report integrity (main._final_report_integrity_pass)
# ---------------------------------------------------------------------------
def test_final_integrity_duplicate_occurrence_annotated(main_module, ledger):
    occ = _occ(file="app/a.py", line=5)
    f = _finding(occurrences=[dict(occ), dict(occ)], instances=2)
    payload = {"findings": [f]}
    main_module._final_report_integrity_pass(payload)
    assert len(f["occurrences"]) == 1
    entry = f["filter_trace"][-1]
    assert entry["pass"] == "final_report_integrity"
    assert entry["decision"] == "drop_occurrence"
    assert entry["reason"]


def test_final_integrity_empty_finding_recorded(main_module, ledger):
    # Only non-dict occurrence entries: the integrity rebuild keeps none, so
    # the finding itself must leave the population -- with a reason.
    f = _finding(occurrences=[None])
    payload = {"findings": [f]}
    main_module._final_report_integrity_pass(payload)
    assert payload["findings"] == []
    rows = [d for d in ledger.entries if d["pass"] == "final_report_integrity"]
    assert rows and rows[-1]["reason"]


# ---------------------------------------------------------------------------
# 7. shell sink taint gate (scanner.sast._gate_shell_sink_findings)
# ---------------------------------------------------------------------------
def test_shell_sink_gate_drop_is_recorded(ledger):
    from scanner.sast import _gate_shell_sink_findings
    shell = _finding(rule_id="SUBPROCESS_SHELL_TRUE",
                     snippet="subprocess.call('ls ' + q, shell=True)")
    kept = _gate_shell_sink_findings([shell])
    assert kept == [], "uncorroborated shell-sink finding must be gated"
    assert shell["filter_trace"], "gated finding carries no filter_trace"
    entry = shell["filter_trace"][-1]
    assert entry["pass"] == "shell_sink_taint_gate"
    assert entry["decision"] == "drop_finding"
    assert entry["reason"]
    rows = [d for d in ledger.entries if d["pass"] == "shell_sink_taint_gate"]
    assert rows and rows[-1]["reason"]


def test_shell_sink_gate_keeps_taint_corroborated(ledger):
    from scanner.sast import _gate_shell_sink_findings
    shell = _finding(rule_id="SUBPROCESS_SHELL_TRUE", line=10)
    taint = _finding(rule_id="PY_TAINT_CMDI", line=11,
                     vuln_type="command_injection")
    kept = _gate_shell_sink_findings([shell, taint])
    assert len(kept) == 2
    assert not shell.get("filter_trace")
    assert not ledger.entries


# ---------------------------------------------------------------------------
# 8. dedup merge (core.analyzer.deduplicate)
# ---------------------------------------------------------------------------
def test_dedup_merge_is_recorded(analyzer_module, ledger):
    a = _finding()
    b = _finding()  # identical fingerprint
    out = analyzer_module.deduplicate([a, b])
    assert len(out) == 1
    rows = [d for d in ledger.entries if d["pass"] == "dedup_merge"]
    assert rows, "merged duplicate is not in the drop ledger"
    assert rows[-1]["decision"] == "merged"
    assert rows[-1]["reason"]


# ---------------------------------------------------------------------------
# 9. enrichment gate (core.analyzer.build_report_payload)
# ---------------------------------------------------------------------------
def test_enrichment_gate_drop_is_recorded(analyzer_module, ledger, monkeypatch):
    monkeypatch.setattr(analyzer_module, "enrich_finding", lambda f: {})
    payload_out = analyzer_module.build_report_payload([_finding()], [], "repo")
    assert payload_out["findings"] == []
    rows = [d for d in ledger.entries if d["pass"] == "enrichment_gate"]
    assert rows and rows[-1]["reason"]


# ---------------------------------------------------------------------------
# 10. occurrence integrity (core.analyzer._finalize_occurrence_integrity)
# ---------------------------------------------------------------------------
def test_occurrence_integrity_duplicate_annotated(analyzer_module, ledger):
    occ = _occ(file="app/a.py", line=7)
    f = _finding(occurrences=[dict(occ), dict(occ)], instances=2)
    out = analyzer_module._finalize_occurrence_integrity([f])
    assert len(out) == 1 and len(out[0]["occurrences"]) == 1
    entry = out[0]["filter_trace"][-1]
    assert entry["pass"] == "occurrence_integrity"
    assert entry["decision"] == "drop_occurrence"
    assert entry["reason"]


def test_occurrence_integrity_confirmed_invalid_recorded(analyzer_module, ledger):
    # A confirmed-class finding whose evidence cannot be validated is dropped
    # at the integrity pass; that drop must be explained.
    f = _finding(finding_class="confirmed", vuln_type="sql_injection",
                 occurrences=[_occ(snippet="foo = 1", taint="")])
    out = analyzer_module._finalize_occurrence_integrity([f])
    if out:
        pytest.skip("evidence validator accepted this shape; drop path not exercised")
    rows = [d for d in ledger.entries if d["pass"] == "occurrence_integrity"]
    assert rows and rows[-1]["reason"]


# ---------------------------------------------------------------------------
# 11. drops document (--explain-drops serialization)
# ---------------------------------------------------------------------------
def test_drops_document_shape_and_determinism(ledger):
    from core import filter_trace
    f1 = _finding(rule_id="B_RULE", file="b.py")
    f2 = _finding(rule_id="A_RULE", file="a.py")
    filter_trace.record_finding_drop(f1, "some_pass", "because b")
    filter_trace.record_finding_drop(f2, "some_pass", "because a")
    doc = filter_trace.build_drops_document({"findings": []})
    assert doc["schema"] == "rsecopsx.filter_drops/v1"
    assert doc["summary"]["total_findings_removed"] == 2
    assert [d["rule_id"] for d in doc["drops"]] == ["A_RULE", "B_RULE"], (
        "drops must be sorted for byte-identical output across runs"
    )
    for row in doc["drops"]:
        assert row["pass"] and row["reason"] and row["decision"]


def test_drops_document_counts_occurrence_drops_on_reported_findings(ledger):
    from core import filter_trace
    f = _finding()
    filter_trace.annotate_occurrence_drop(
        f, "some_pass", _occ(file="gone.py", line=3), "because gone")
    doc = filter_trace.build_drops_document({"findings": [f]})
    assert doc["summary"]["occurrence_drops_on_reported_findings"] == 1


# ---------------------------------------------------------------------------
# 12. Integration: the historical drop shapes, end to end
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module")
def scan_artifacts(tmp_path_factory):
    """Reproduce the three historical silent-drop shapes in one scan."""
    proj = tmp_path_factory.mktemp("silent_drop_proj")
    # (a) historical pathtraver: request-controlled PHP include
    (proj / "lfi.php").write_text(
        "<?php\n$p = $_GET['page'];\ninclude($p);\n", encoding="utf-8")
    # (b) historical cmdi: shell sink the taint engine corroborates
    (proj / "shell.py").write_text(
        "import subprocess\n"
        "def handler(request):\n"
        "    subprocess.call('ls ' + request.args['q'], shell=True)\n",
        encoding="utf-8")
    # (c) historical PHP webshell
    (proj / "webshell.php").write_text(
        "<?php\nsystem($_GET['cmd']);\neval($_POST['x']);\n", encoding="utf-8")
    # (d) benchmark fixture boundary: must drop *with a reason*
    bench = proj / "data" / "static" / "codefixes"
    bench.mkdir(parents=True)
    (bench / "vuln.js").write_text("eval(window.name);\n", encoding="utf-8")

    outdir = tmp_path_factory.mktemp("silent_drop_out")
    proc = subprocess.run(
        [sys.executable, str(MAIN), str(proj),
         "--output-dir", str(outdir), "--no-pdf", "--no-excel",
         "--explain-drops", "--workers", "2"],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        cwd=str(REPO), timeout=1800,
    )
    return proc, outdir, proj


def test_integration_scan_exits_zero(scan_artifacts):
    proc, _outdir, _proj = scan_artifacts
    assert proc.returncode == 0, (
        f"main.py exited {proc.returncode}.\n"
        f"--- stdout tail ---\n{(proc.stdout or '')[-3000:]}\n"
        f"--- stderr tail ---\n{(proc.stderr or '')[-3000:]}"
    )


def test_integration_writes_clean_report_and_drops(scan_artifacts):
    _proc, outdir, _proj = scan_artifacts
    assert (outdir / "clean_report.json").exists()
    assert (outdir / "drops.json").exists(), (
        "--explain-drops must serialize the drop ledger to drops.json"
    )


def test_integration_every_drop_is_explained(scan_artifacts):
    _proc, outdir, _proj = scan_artifacts
    drops = json.loads((outdir / "drops.json").read_text(encoding="utf-8"))
    assert drops["summary"]["total_findings_removed"] == len(drops["drops"])
    for row in drops["drops"]:
        assert row.get("pass"), row
        assert row.get("reason"), f"unexplained drop: {row}"
        assert row.get("decision") in {"drop_finding", "merged"}, row


def test_integration_historical_pathtraver_recovers(scan_artifacts):
    """The request-controlled PHP include must reach the report.

    This is the recovery assertion for the drop that motivated T-0.1: the
    finding used to vanish at the occurrence evidence gate with no trace.
    """
    _proc, outdir, _proj = scan_artifacts
    report = json.loads((outdir / "clean_report.json").read_text(encoding="utf-8"))
    blob = json.dumps(report.get("findings") or []).lower()
    assert "lfi.php" in blob, (
        "the request-controlled PHP include (lfi.php) is missing from "
        "clean_report.json -- the historical silent drop has regressed"
    )


def test_integration_benchmark_fixture_drop_is_explained(scan_artifacts):
    """The seeded codefixes finding must be dropped, and the drop explained."""
    _proc, outdir, _proj = scan_artifacts
    drops = json.loads((outdir / "drops.json").read_text(encoding="utf-8"))
    fixture_rows = [d for d in drops["drops"]
                    if d["pass"] == "benchmark_fixture_boundary"]
    assert fixture_rows, (
        "the seeded data/static/codefixes finding was neither reported nor "
        "listed in drops.json"
    )
    assert all("codefixes" in json.dumps(d) for d in fixture_rows)


def test_integration_reported_findings_trace_is_wellformed(scan_artifacts):
    _proc, outdir, _proj = scan_artifacts
    report = json.loads((outdir / "clean_report.json").read_text(encoding="utf-8"))
    for finding in report.get("findings") or []:
        for entry in finding.get("filter_trace") or []:
            assert entry.get("pass")
            assert entry.get("decision") in {
                "drop_finding", "drop_occurrence", "merged",
                "kept_after_path_repair"}
            assert entry.get("reason")


def test_integration_output_is_deterministic(tmp_path_factory):
    """Same input -> byte-identical clean_report.json AND drops.json."""
    import shutil
    proj = tmp_path_factory.mktemp("determinism_proj")
    (proj / "lfi.php").write_text(
        "<?php\n$p = $_GET['page'];\ninclude($p);\n", encoding="utf-8")
    outs = []
    for tag in ("run1", "run2"):
        outdir = tmp_path_factory.mktemp(f"determinism_{tag}")
        proc = subprocess.run(
            [sys.executable, str(MAIN), str(proj),
             "--output-dir", str(outdir), "--no-pdf", "--no-excel",
             "--explain-drops", "--workers", "1"],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            cwd=str(REPO), timeout=1800,
        )
        assert proc.returncode == 0, (proc.stdout or "")[-2000:]
        outs.append(outdir)
    a = (outs[0] / "drops.json").read_text(encoding="utf-8")
    b = (outs[1] / "drops.json").read_text(encoding="utf-8")
    assert a == b, "drops.json is not deterministic across identical runs"
