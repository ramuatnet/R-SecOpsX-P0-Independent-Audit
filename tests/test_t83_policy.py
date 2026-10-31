"""T-8.3 policy-as-code gates -- red-first acceptance tests (task.md §11).

Contracts pinned here BEFORE any analysis/policy/ file exists:

* policy file -- canonical YAML subset (works under BOTH PyYAML and the
  airgap fallback parser: top-level scalars, top-level flow lists, one
  block list `exclusions:`), schema-stamped rsecopsx.policy/v1,
  loud PolicyInvalid reasons for every authoring error (a suppression
  without a reason can never load);
* fail_on -- NORMALIZED TO ITS LOWEST RUNG with or-above semantics
  (the list form replaces the hardcoded --fail-on rung without ever
  being weaker than it: ['high'] blocks Critical too);
* scope -- include/exclude globs (true ** semantics), non-matching
  rows are annotated out_of_scope, never silently dropped; SCA rows
  (no file) bypass file globs;
* exclusions -- honored only with rule+reason; matched rows keep the
  human reason in the artifact;
* SLA per severity -- breach blocks independently of fail_on; unknown
  age is ANNOTATED (sla_age_unknown), never a silent pass;
* required evidence -- a blocking row missing a required key stays
  blocking and carries a machine note (fail-closed);
* evaluate() -- pure/deterministic, junk rows counted never raised,
  rows sorted (rule_id, file, line);
* CLI -- zero-I/O default (exactly 2 not_provided skips), rc 0 pass /
  1 gate failed / 2 usage, byte-identical under a fixed --as-of;
* main.py -- --policy attaches metadata.policy_gate and OR-s into the
  exit code; flag-off runs carry NO policy_gate key (A/B byte-check);
* pins -- Rego disclosure one greppable line (axum/petgraph precedent),
  offline source pin, package surface without submodule shadow.
"""
import json
import pathlib
import subprocess
import sys
import time
from datetime import datetime, timezone

import pytest

import analysis.policy as pkg
from analysis.policy import (
    POLICY_SCHEMA,
    RESULT_SCHEMA,
    SEVERITIES,
    PolicyInvalid,
    evaluate,
    load_policy_file,
    parse_policy,
    rows_from_payload,
)
from analysis.policy import model as policy_model

REPO = pathlib.Path(__file__).resolve().parent.parent

CANON = """# T-8.3 canonical policy fixture
schema: 'rsecopsx.policy/v1'
name: 'default-gate'
fail_on: ['critical', 'high']
scope_include: ['**/*.py']
scope_exclude: ['legacy/**']
sla_critical: 7
sla_high: 30
required_evidence: ['file', 'line', 'snippet']
exclusions:
  - rule: 'hardcoded_secret'
    file: 'legacy/*.py'
    reason: 'accepted risk 2026-Q3'
  - rule: 'weak_tls'
    line: 42
    reason: 'false positive -- vendored test key'
"""

_AS_OF = int(datetime(2026, 10, 31, tzinfo=timezone.utc).timestamp())


def _row(rule_id="R1", severity="critical", file="src/app.py", line=3,
         **extra):
    row = {"rule_id": rule_id, "severity": severity, "file": file,
           "line": line}
    row.update(extra)
    return row


# ---------------------------------------------------------------------------
# A. policy file: normalization + validation
# ---------------------------------------------------------------------------


def test_policy_vocab_and_schemas():
    assert POLICY_SCHEMA == "rsecopsx.policy/v1"
    assert RESULT_SCHEMA == "rsecopsx.policy_result/v1"
    assert SEVERITIES == ("critical", "high", "medium", "low", "info")


def test_canonical_policy_normalizes_to_lowest_rung():
    p = parse_policy(CANON)
    assert p["schema"] == POLICY_SCHEMA
    assert p["name"] == "default-gate"
    # list form -> rung is the LOWEST listed severity (or-above semantics)
    assert p["fail_on"] == ("critical", "high")
    assert p["rung"] == "high"
    assert p["scope_include"] == ("**/*.py",)
    assert p["scope_exclude"] == ("legacy/**",)
    assert p["sla"] == {"critical": 7, "high": 30}
    assert p["required_evidence"] == ("file", "line", "snippet")
    assert len(p["exclusions"]) == 2
    assert p["exclusions"][0]["reason"] == "accepted risk 2026-Q3"
    assert p["exclusions"][1]["line"] == 42


def test_both_yaml_paths_produce_equal_structures(monkeypatch):
    import sys as _sys
    canon = parse_policy(CANON)
    monkeypatch.setitem(_sys.modules, "yaml", None)   # force airgap parser
    subset = parse_policy(CANON)
    assert subset == canon


def test_single_string_fail_on_is_normalized():
    p = parse_policy("schema: 'rsecopsx.policy/v1'\nfail_on: 'medium'\n")
    assert p["fail_on"] == ("medium",)
    assert p["rung"] == "medium"


def test_policy_validation_errors_are_reasons():
    cases = [
        ("just-a-string", "policy_not_object"),
        ("schema: 'wrong/v9'\n", "policy_schema"),
        ("schema: 'rsecopsx.policy/v1'\nfail_on: ['blocker']\n",
         "fail_on_unknown_severity:blocker"),
        ("schema: 'rsecopsx.policy/v1'\n"
         "exclusions:\n  - rule: 'x'\n", "exclusion_missing_reason:0"),
        ("schema: 'rsecopsx.policy/v1'\nsla_critical: 0\n",
         "sla_bad_days:critical"),
        ("schema: 'rsecopsx.policy/v1'\nsla_blocker: 7\n",
         "sla_unknown_severity:blocker"),
        ("schema: 'rsecopsx.policy/v1'\n"
         "exclusions:\n  - rule: 'x'\n    reason: 'r'\n    note: 'huh'\n",
         "exclusion_unknown_key:0:note"),
        ("schema: 'rsecopsx.policy/v1'\nscope_include: 7\n",
         "scope_invalid"),
    ]
    for text, reason in cases:
        with pytest.raises(PolicyInvalid) as ei:
            parse_policy(text)
        assert ei.value.reason == reason, (text, ei.value.reason)


# ---------------------------------------------------------------------------
# B. evaluate -- the gate itself
# ---------------------------------------------------------------------------


def test_fail_on_rung_blocks_at_or_above():
    # no SLA here: the exact-counts assert below must not be disturbed
    # by sla_age_unknown annotations (covered separately)
    policy = parse_policy("schema: 'rsecopsx.policy/v1'\n"
                          "fail_on: ['critical', 'high']\n")
    rows = [_row(severity=s) for s in
            ("critical", "high", "medium", "low")]
    result = evaluate(policy, rows, as_of=_AS_OF)
    assert result["schema"] == RESULT_SCHEMA
    assert result["passed"] is False
    by_sev = {r["severity"]: r for r in result["rows"]}
    assert by_sev["critical"]["status"] == "blocking"
    assert by_sev["high"]["status"] == "blocking"
    assert by_sev["medium"]["status"] == "pass"
    assert by_sev["low"]["status"] == "pass"
    assert by_sev["critical"]["reasons"] == ["fail_on_rung"]
    assert result["counts"] == {"pass": 2, "blocking": 2, "excluded": 0,
                                "out_of_scope": 0, "sla_age_unknown": 0,
                                "severity_unrecognised": 0,
                                "rows_not_objects": 0}
    assert len(result["blocking"]) == 2


def test_fail_on_list_normalizes_to_lowest_rung():
    p = parse_policy("schema: 'rsecopsx.policy/v1'\n"
                     "fail_on: ['critical', 'medium']\n")
    assert p["rung"] == "medium"
    result = evaluate(p, [_row(severity="high")], as_of=_AS_OF)
    assert result["passed"] is False      # or-above: medium rung blocks high
    assert result["blocking"][0]["reasons"] == ["fail_on_rung"]


def test_empty_fail_on_never_blocks_on_severity():
    p = parse_policy("schema: 'rsecopsx.policy/v1'\n")
    result = evaluate(p, [_row(severity="critical")], as_of=_AS_OF)
    assert result["passed"] is True
    assert result["rows"][0]["status"] == "pass"


def test_scope_include_and_exclude_annotate_out_of_scope():
    p = parse_policy("schema: 'rsecopsx.policy/v1'\n"
                     "fail_on: ['info']\n"
                     "scope_include: ['src/**']\n"
                     "scope_exclude: ['src/generated/**']\n")
    rows = [_row(severity="critical", file="src/app.py"),
            _row(severity="critical", file="lib/tool.py"),
            _row(severity="critical", file="src/generated/gen.py")]
    result = evaluate(p, rows, as_of=_AS_OF)
    by_file = {r["file"]: r for r in result["rows"]}
    assert by_file["src/app.py"]["status"] == "blocking"
    assert by_file["lib/tool.py"]["status"] == "out_of_scope"
    assert by_file["lib/tool.py"]["note"] == "scope_not_included"
    assert by_file["src/generated/gen.py"]["status"] == "out_of_scope"
    assert by_file["src/generated/gen.py"]["note"] == "scope_excluded"
    # out-of-scope rows never block, and the counts stay honest
    assert result["counts"]["out_of_scope"] == 2
    assert result["counts"]["blocking"] == 1
    assert result["passed"] is False


def test_glob_semantics_double_star_matches_zero_or_many_dirs():
    p = parse_policy("schema: 'rsecopsx.policy/v1'\n"
                     "fail_on: ['info']\n"
                     "scope_include: ['**/*.py']\n")
    result = evaluate(p, [_row(file="app.py"), _row(file="src/x/app.py"),
                          _row(file="src/x/notes.txt")], as_of=_AS_OF)
    by_file = {r["file"]: r for r in result["rows"]}
    assert by_file["app.py"]["status"] == "blocking"
    assert by_file["src/x/app.py"]["status"] == "blocking"
    assert by_file["src/x/notes.txt"]["status"] == "out_of_scope"


def test_sca_rows_bypass_file_scope_but_stay_evaluable():
    # R1 lives outside the include glob; the SCA row has file=None and
    # must bypass the file scope entirely while remaining evaluable
    payload = {"findings": [_row(severity="critical", file="lib/tool.py")],
               "sbom": [{"name": "flask", "severity": "Critical",
                         "cve": ["CVE-2024-0001"]}]}
    rows = rows_from_payload(payload)
    assert rows[1]["file"] is None and rows[1]["rule_id"] == "sca:flask"
    p = parse_policy("schema: 'rsecopsx.policy/v1'\n"
                     "fail_on: ['info']\n"
                     "scope_include: ['src/**']\n")
    result = evaluate(p, rows, as_of=_AS_OF)
    by_rule = {r["rule_id"]: r for r in result["rows"]}
    # the code finding is out of scope; the package row (no file) is not
    assert by_rule["sca:flask"]["status"] == "blocking"
    assert by_rule["R1"]["status"] == "out_of_scope"


def test_exclusion_honors_rule_file_line_and_keeps_the_reason():
    p = parse_policy(CANON)              # hardcoded_secret @ legacy/*.py
    rows = [_row(rule_id="hardcoded_secret", file="legacy/old.py"),
            _row(rule_id="hardcoded_secret", file="src/app.py"),
            _row(rule_id="weak_tls", file="src/app.py", line=42)]
    result = evaluate(p, rows, as_of=_AS_OF)
    by_key = {(r["rule_id"], r["file"], r["line"]): r for r in result["rows"]}
    excl = by_key[("hardcoded_secret", "legacy/old.py", 3)]
    assert excl["status"] == "excluded"
    assert excl["note"] == "accepted risk 2026-Q3"
    # exclusion did NOT match another file, and line 42 matched exactly
    assert by_key[("hardcoded_secret", "src/app.py", 3)]["status"] == "blocking"
    assert by_key[("weak_tls", "src/app.py", 42)]["status"] == "excluded"
    assert result["counts"]["excluded"] == 2
    assert result["counts"]["blocking"] == 1
    assert result["passed"] is False


def test_exclusion_line_mismatch_does_not_suppress():
    p = parse_policy(CANON)
    result = evaluate(p, [_row(rule_id="weak_tls", file="src/app.py",
                               line=7)], as_of=_AS_OF)
    assert result["rows"][0]["status"] == "blocking"


def test_sla_breach_blocks_independently_of_fail_on():
    p = parse_policy("schema: 'rsecopsx.policy/v1'\nsla_critical: 7\n")
    old = "2026-06-01T00:00:00Z"         # ~152 days before _AS_OF
    result = evaluate(p, [_row(severity="critical", first_seen=old)],
                      as_of=_AS_OF)
    assert result["passed"] is False
    assert result["blocking"][0]["reasons"] == ["sla_breach"]
    # a young finding at the same severity passes
    fresh = evaluate(p, [_row(severity="critical",
                              first_seen="2026-10-30T00:00:00Z")],
                     as_of=_AS_OF)
    assert fresh["passed"] is True


def test_sla_age_unknown_is_annotated_never_a_silent_pass():
    p = parse_policy("schema: 'rsecopsx.policy/v1'\nsla_critical: 7\n")
    result = evaluate(p, [_row(severity="critical")], as_of=_AS_OF)
    assert result["passed"] is True                # fail_on empty -> no block
    assert result["counts"]["sla_age_unknown"] == 1
    assert "sla_age_unknown" in result["rows"][0]["notes"]


def test_missing_required_evidence_stays_blocking_with_a_note():
    p = parse_policy(CANON)          # required_evidence: file,line,snippet
    missing = evaluate(p, [_row(severity="critical")], as_of=_AS_OF)
    assert missing["passed"] is False                 # fail-closed
    assert "missing_evidence:snippet" in missing["rows"][0]["notes"]
    have = evaluate(p, [_row(severity="critical", snippet="eval(x)")],
                    as_of=_AS_OF)
    assert have["passed"] is False
    assert not any(n.startswith("missing_evidence")
                   for n in have["rows"][0]["notes"])


def test_unrecognised_severity_is_reported_never_silent():
    p = parse_policy(CANON)
    result = evaluate(p, [_row(severity="Blocker"), _row(severity="")],
                      as_of=_AS_OF)
    assert result["passed"] is True
    assert result["counts"]["severity_unrecognised"] == 2
    notes = result["rows"][0]["notes"] + result["rows"][1]["notes"]
    assert any(n.startswith("severity_unrecognised") for n in notes)


def test_junk_rows_are_counted_not_raised():
    p = parse_policy(CANON)
    result = evaluate(p, [1, None, "x"], as_of=_AS_OF)
    assert result["passed"] is True
    assert result["counts"]["rows_not_objects"] == 3
    assert result["rows"] == []


def test_rows_sorted_and_repeat_runs_byte_identical():
    p = parse_policy(CANON)
    rows = [_row(rule_id="B_R", file="z.py"),
            _row(rule_id="A_R", file="a.py"),
            _row(rule_id="A_R", file="a.py", line=9)]
    r1 = evaluate(p, list(reversed(rows)), as_of=_AS_OF)
    r2 = evaluate(p, rows, as_of=_AS_OF)
    keys = [(r["rule_id"], r["file"], r["line"]) for r in r1["rows"]]
    assert keys == sorted(keys)
    assert json.dumps(r1, sort_keys=True) == json.dumps(r2, sort_keys=True)


def test_result_document_shape_is_fixed():
    result = evaluate(parse_policy(CANON), [_row()], as_of=_AS_OF)
    assert set(result) == {"schema", "policy", "as_of", "passed", "rows",
                           "blocking", "counts", "skips"}
    assert set(result["policy"]) == {"schema", "name", "fail_on", "rung",
                                     "sla", "required_evidence",
                                     "exclusions"}
    assert result["policy"]["exclusions"] == 2
    assert set(result["counts"]) == {"pass", "blocking", "excluded",
                                     "out_of_scope", "sla_age_unknown",
                                     "severity_unrecognised",
                                     "rows_not_objects"}
    assert result["skips"] == []


def test_rows_from_payload_counts_only_vulnerable_packages():
    payload = {"findings": [_row()],
               "sbom": [
                   {"name": "flask", "severity": "Critical",
                    "cve": ["CVE-2024-0001"]},
                   {"name": "clean-pkg", "severity": "High"},
                   {"name": "adv-only", "advisory_id": "GHSA-1",
                    "highest_vulnerability_severity": "Medium"},
                   "not-a-dict"]}
    rows = rows_from_payload(payload)
    rule_ids = [r["rule_id"] for r in rows]
    assert rule_ids == ["R1", "sca:flask", "sca:adv-only"]
    assert rows[1]["severity"] == "Critical"
    assert rows[2]["severity"] == "Medium"


def test_load_policy_file_reads_from_disk(tmp_path):
    path = tmp_path / "rsx_t83_policy.yaml"
    path.write_text(CANON, encoding="utf-8")
    assert load_policy_file(path) == parse_policy(CANON)
    with pytest.raises(PolicyInvalid) as ei:
        load_policy_file(tmp_path / "rsx_t83_absent.yaml")
    # a missing file must fail loudly with a reason the CLI can print
    assert ei.value.reason.startswith("policy_file_missing")


# ---------------------------------------------------------------------------
# C. CLI: python -m analysis.policy.connect
# ---------------------------------------------------------------------------


def _run_cli(args, cwd=None):
    return subprocess.run(
        [sys.executable, "-m", "analysis.policy.connect", *args],
        capture_output=True, text=True, cwd=cwd or REPO, timeout=120)


def _write_report(tmp_path, severity="low"):
    report = tmp_path / "rsx_t83_report.json"
    report.write_text(json.dumps({"findings": [
        {"rule_id": "EVAL_CALL", "severity": severity,
         "file": "a.py", "line": 2}]}), encoding="utf-8")
    return report


def test_cli_default_run_is_zero_io_with_two_skips(tmp_path):
    out = tmp_path / "rsx_t83_doc.json"
    r = _run_cli(["--as-of", "2026-10-31T00:00:00", "--out", str(out)])
    assert r.returncode == 0, r.stderr
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["schema"] == "rsecopsx.policy_doc/v1"
    assert doc["result"] is None
    assert sorted(s["reason"] for s in doc["skips"]) == [
        "not_provided:policy", "not_provided:report"]
    out2 = tmp_path / "rsx_t83_doc2.json"
    r2 = _run_cli(["--as-of", "2026-10-31T00:00:00", "--out", str(out2)])
    assert r2.returncode == 0
    assert out.read_bytes() == out2.read_bytes()


def test_cli_pass_and_fail_exit_codes(tmp_path):
    policy = tmp_path / "rsx_t83_p.yaml"
    policy.write_text(CANON, encoding="utf-8")        # rung high, row low
    report = _write_report(tmp_path, severity="low")
    out = tmp_path / "rsx_t83_pass.json"
    r = _run_cli(["--policy", str(policy), "--report", str(report),
                  "--as-of", "2026-10-31T00:00:00", "--out", str(out)])
    assert r.returncode == 0, r.stderr
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["result"]["passed"] is True
    assert doc["stats"]["passed"] is True

    fail_policy = tmp_path / "rsx_t83_fail.yaml"
    fail_policy.write_text(
        CANON.replace("fail_on: ['critical', 'high']",
                      "fail_on: ['info']"), encoding="utf-8")
    out2 = tmp_path / "rsx_t83_fail.json"
    r2 = _run_cli(["--policy", str(fail_policy), "--report", str(report),
                   "--as-of", "2026-10-31T00:00:00", "--out", str(out2)])
    assert r2.returncode == 1, r2.stderr
    doc2 = json.loads(out2.read_text(encoding="utf-8"))
    assert doc2["result"]["passed"] is False
    assert doc2["stats"]["blocking"] == 1
    # same inputs, same bytes: determinism is the gate's whole promise
    out3 = tmp_path / "rsx_t83_fail2.json"
    _run_cli(["--policy", str(fail_policy), "--report", str(report),
              "--as-of", "2026-10-31T00:00:00", "--out", str(out3)])
    assert out2.read_bytes() == out3.read_bytes()


def test_cli_bad_policy_exits_2_with_a_reason(tmp_path):
    bad = tmp_path / "rsx_t83_bad.yaml"
    bad.write_text("schema: 'wrong/v9'\n", encoding="utf-8")
    report = _write_report(tmp_path)
    r = _run_cli(["--policy", str(bad), "--report", str(report)])
    assert r.returncode == 2
    assert "policy_schema" in r.stderr


def test_cli_missing_report_exits_2(tmp_path):
    policy = tmp_path / "rsx_t83_p.yaml"
    policy.write_text(CANON, encoding="utf-8")
    r = _run_cli(["--policy", str(policy),
                  "--report", str(tmp_path / "rsx_t83_absent.json")])
    assert r.returncode == 2


def test_cli_bad_as_of_exits_2(tmp_path):
    r = _run_cli(["--as-of", "not-a-date"])
    assert r.returncode == 2


# ---------------------------------------------------------------------------
# D. main.py wiring -- --policy replaces the hardcoded rung's job
# ---------------------------------------------------------------------------


def _main_fixture(tmp_path):
    target = tmp_path / "rsx_t83_target"
    target.mkdir()
    (target / "a.py").write_text("def f(x):\n    return eval(x)\n",
                                 encoding="utf-8")
    return target


def _run_main(args, cwd=None):
    return subprocess.run(
        [sys.executable, str(REPO / "main.py"), *args],
        capture_output=True, text=True, cwd=cwd or REPO, timeout=300)


def test_main_policy_flag_is_offered():
    r = subprocess.run([sys.executable, str(REPO / "main.py"), "--help"],
                       capture_output=True, text=True, cwd=REPO,
                       timeout=120)
    assert r.returncode == 0
    assert "--policy" in r.stdout


def test_main_without_policy_carries_no_policy_gate(tmp_path):
    target = _main_fixture(tmp_path)
    out = tmp_path / "rsx_t83_out"
    r = _run_main([str(target), "--output-dir", str(out), "--quiet",
                   "--no-pdf", "--no-excel"])
    assert r.returncode == 0, r.stderr
    rep = json.loads((out / "clean_report.json").read_text(encoding="utf-8"))
    assert "policy_gate" not in rep.get("metadata", {})
    assert rep["metadata"]["security_gate"]["threshold"] is None


def test_main_policy_pass_writes_gate_and_exits_0(tmp_path):
    target = _main_fixture(tmp_path)
    policy = tmp_path / "rsx_t83_pass.yaml"
    policy.write_text(CANON, encoding="utf-8")     # rung high; row is Low
    out = tmp_path / "rsx_t83_out"
    r = _run_main([str(target), "--output-dir", str(out), "--quiet",
                   "--no-pdf", "--no-excel", "--policy", str(policy)])
    assert r.returncode == 0, r.stderr
    rep = json.loads((out / "clean_report.json").read_text(encoding="utf-8"))
    gate = rep["metadata"]["policy_gate"]
    assert gate["schema"] == RESULT_SCHEMA
    assert gate["passed"] is True
    assert rep["metadata"]["security_gate"]["threshold"] is None


def test_main_policy_fail_exits_1_and_still_writes_report(tmp_path):
    target = _main_fixture(tmp_path)
    policy = tmp_path / "rsx_t83_fail.yaml"
    policy.write_text(
        CANON.replace("fail_on: ['critical', 'high']",
                      "fail_on: ['info']"), encoding="utf-8")
    out = tmp_path / "rsx_t83_out"
    r = _run_main([str(target), "--output-dir", str(out), "--quiet",
                   "--no-pdf", "--no-excel", "--policy", str(policy)])
    assert r.returncode == 1, r.stderr
    rep = json.loads((out / "clean_report.json").read_text(encoding="utf-8"))
    gate = rep["metadata"]["policy_gate"]
    assert gate["passed"] is False
    assert gate["counts"]["blocking"] >= 1
    assert any(b["rule_id"] == "EVAL_CALL" for b in gate["blocking"])


def test_main_bad_policy_is_a_usage_error(tmp_path):
    target = _main_fixture(tmp_path)
    bad = tmp_path / "rsx_t83_bad.yaml"
    bad.write_text("schema: 'wrong/v9'\n", encoding="utf-8")
    out = tmp_path / "rsx_t83_out"
    r = _run_main([str(target), "--output-dir", str(out), "--quiet",
                   "--no-pdf", "--no-excel", "--policy", str(bad)])
    assert r.returncode == 2
    assert "policy_schema" in r.stderr


# ---------------------------------------------------------------------------
# E. pins: Rego disclosure, offline source pin, package surface
# ---------------------------------------------------------------------------


def test_rego_disclosure_is_one_greppable_line():
    # axum/petgraph precedent: task.md names Rego -> not adopted here,
    # disclosed where the evaluation lives.
    text = policy_model.__doc__ or ""
    lowered = text.lower()
    assert "rego" in lowered
    assert "not adopted" in lowered


def test_offline_source_pin_no_network_tokens_in_sources():
    banned = ("urllib", "socket", "boto3", "requests", "os.environ",
              "http.client")
    for src in sorted((REPO / "analysis" / "policy").glob("*.py")):
        text = src.read_text(encoding="utf-8")
        for token in banned:
            assert token not in text, f"{src.name} contains {token!r}"


def test_package_surface_without_submodule_shadow():
    assert pkg.POLICY_SCHEMA == POLICY_SCHEMA
    assert pkg.model is policy_model
    assert callable(pkg.evaluate) and callable(pkg.parse_policy)
    for name in ("model", "policy_yaml", "connect"):
        __import__(f"analysis.policy.{name}")


# ---------------------------------------------------------------------------
# F. perf: policy evaluation cost (gate-time, not in the event path)
# ---------------------------------------------------------------------------


def test_evaluate_p95_stays_well_under_the_incremental_budget():
    policy = parse_policy(CANON.replace(
        "fail_on: ['critical', 'high']",
        "fail_on: ['critical', 'high', 'medium']"))
    # add exclusions to give the matcher real work
    policy = parse_policy(CANON + (
        "".join(f"  - rule: 'EXCL_{i}'\n    reason: 'r{i}'\n"
                for i in range(200)).replace(
            "exclusions:\n", "exclusions:\n", 1)))
    rows = [_row(rule_id=f"R{i}", severity=SEVERITIES[i % 5],
                 file=f"src/mod{i}.py", line=i) for i in range(10_000)]
    times = []
    for _ in range(7):
        t0 = time.perf_counter()
        result = evaluate(policy, rows, as_of=_AS_OF)
        times.append(time.perf_counter() - t0)
        assert result["counts"]["blocking"] + result["counts"]["pass"] \
            + result["counts"]["excluded"] \
            + result["counts"]["out_of_scope"] == 10_000
    times.sort()
    p95 = times[int(0.95 * (len(times) - 1))]
    assert p95 < 0.5, f"evaluate p95 {p95:.3f}s on 10k rows"
