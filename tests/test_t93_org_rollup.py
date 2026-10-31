"""T-9.3 org/multi-repo rollup (D-1): manifest envelope + collator (red-first).

Contract (opencodetask.md D-1):
* define + publish org_rollup.json schema v1 -- per-repo scan envelopes
  (digest, timestamp, flags, summary counters, top techniques from A-6,
  API posture from A-1, SBOM drift from B-2);
* producer: ``--org-rollup manifests/*.json`` collator (pure CLI,
  offline) + schema validator;
* gate: schema tests + shuffle -> byte-identical output.

This batch EDITS nothing existing: it adds the analysis/rollup package,
so the red baseline at HEAD is a collection error
(ModuleNotFoundError: No module named 'analysis.rollup') -- disclosed
in the commit like every prior new-package batch.
"""
import json
import subprocess
import sys
import tempfile
import itertools
import pathlib

import pytest

from analysis.rollup import model as rollup_model


# ---------------------------------------------------------------------------
# A. manifest envelope validation (the schema validator)
# ---------------------------------------------------------------------------


def _good_manifest(**over):
    man = {
        "schema": rollup_model.MANIFEST_SCHEMA,
        "repo": "dvpwa",
        "digest": "sha256:abc123",
        "timestamp": "2026-10-31T00:00:00Z",
        "flags": ["policy"],
        "summary": {"findings": 17, "critical": 1},
        "top_techniques": [{"technique": "T1190", "count": 2}],
    }
    man.update(over)
    return man


def test_manifest_schema_strings_frozen():
    # published v1 contract -- renaming these breaks every stored manifest
    assert rollup_model.MANIFEST_SCHEMA == "rsecopsx.scan_manifest/v1"
    assert rollup_model.ORG_ROLLUP_SCHEMA == "rsecopsx.org_rollup/v1"


def test_valid_manifest_passes_with_none_reason():
    assert rollup_model.validate_manifest(_good_manifest()) is None


def test_manifest_reject_reasons_are_machine_strings():
    cases = [
        ((None, "not-an-object"), "manifest_not_object"),
        (["schema", "rsecopsx.other/v1"], "manifest_schema"),
        (["repo", ""], "repo_empty"),
        (["repo", 7], "repo_not_a_string"),
        (["digest", ""], "digest_empty"),
        (["timestamp", ""], "timestamp_empty"),
        (["flags", "policy"], "flags_not_a_list"),
        (["flags", [1]], "flags_item_not_string:0"),
        (["summary", []], "summary_not_object"),
        (["summary", {"findings": "17"}], "summary_bad_counter:findings"),
        (["summary", {"findings": True}], "summary_bad_counter:findings"),
        (["summary", {"findings": -1}], "summary_bad_counter:findings"),
        (["top_techniques", "T1190"], "top_techniques_not_a_list"),
        (["top_techniques", ["T1190"]], "technique_not_object:0"),
        (["top_techniques", [{"technique": ""}]],
         "technique_missing:0"),
        (["top_techniques", [{"technique": "T1190", "count": -1}]],
         "technique_count_bad:0"),
        (["api_posture", "open"], "api_posture_not_object"),
        (["api_posture", {"routes": "12"}], "api_posture_bad_counter:routes"),
        (["sbom_drift", 3], "sbom_drift_not_object"),
        (["sbom_drift", {"added": 1.5}], "sbom_drift_bad_counter:added"),
    ]
    for (key, value), reason in cases:
        if key is None:                      # whole-manifest junk input
            man = value
        else:
            man = _good_manifest()
            if key == "schema":
                man["schema"] = value
            elif key in ("repo", "digest", "timestamp", "flags", "summary",
                         "top_techniques", "api_posture", "sbom_drift"):
                man[key] = value
        got = rollup_model.validate_manifest(man)
        assert got == reason, f"{key}={value!r}: {got!r} != {reason!r}"


def test_optional_sections_may_be_absent_and_may_be_empty_objects():
    # _good_manifest omits both sections entirely = absent by default
    assert "api_posture" not in _good_manifest()
    assert "sbom_drift" not in _good_manifest()
    assert rollup_model.validate_manifest(_good_manifest()) is None
    assert rollup_model.validate_manifest(
        _good_manifest(api_posture={}, sbom_drift={})) is None


def test_missing_required_field_reasons():
    for key, reason in (("repo", "repo_missing"), ("digest", "digest_missing"),
                        ("timestamp", "timestamp_missing"),
                        ("flags", "flags_missing"),
                        ("summary", "summary_missing"),
                        ("top_techniques", "top_techniques_missing")):
        man = _good_manifest()
        del man[key]
        assert rollup_model.validate_manifest(man) == reason


# ---------------------------------------------------------------------------
# B. manifest_from_report -- envelope extracted from a real scan payload
# ---------------------------------------------------------------------------


def _report():
    return {
        "metadata": {
            "target": "/targets/dvpwa-master",
            "scan_date": "2026-10-31T10:11:20Z",
            "total_findings": 3,
            "sast_findings": 2,
            "sca_findings": 1,
            "severity_distribution": {
                "Critical": 1, "High": 1, "Medium": 1, "Low": 0, "Info": 0},
        },
        "findings": [
            {"rule_id": "A", "file": "a.py", "line": 1, "mitre": ["T1190"]},
            {"rule_id": "B", "file": "b.py", "line": 2,
             "mitre": [{"id": "T1059"}, "T1190"]},
            {"rule_id": "C", "file": "c.py", "line": 3},
        ],
        "apibom": [],
        "sbom": [],
    }


def test_manifest_from_report_maps_envelope_fields():
    man = rollup_model.manifest_from_report(_report(), repo="dvpwa",
                                            flags=["policy"])
    assert man["schema"] == rollup_model.MANIFEST_SCHEMA
    assert man["repo"] == "dvpwa"
    assert man["digest"].startswith("sha256:")
    assert man["timestamp"] == "2026-10-31T10:11:20Z"
    assert man["flags"] == ["policy"]
    assert man["summary"] == {
        "findings": 3, "sast": 2, "sca": 1,
        "critical": 1, "high": 1, "medium": 1, "low": 0, "info": 0}
    # top techniques from A-6 lineage: counts over findings' mitre field
    # (str or {id}), sorted (-count, technique)
    assert man["top_techniques"] == [
        {"technique": "T1190", "count": 2},
        {"technique": "T1059", "count": 1},
    ]
    # A-1 posture matrix and B-2 drift are not built yet -- the envelope
    # must carry them as ABSENT, never as an empty/"all clear" object
    assert "api_posture" not in man
    assert "sbom_drift" not in man
    assert rollup_model.validate_manifest(man) is None


def test_manifest_from_report_digest_is_content_addressed():
    a = rollup_model.manifest_from_report(_report(), repo="x")
    b = rollup_model.manifest_from_report(_report(), repo="x")
    assert a["digest"] == b["digest"]
    other = _report()
    other["findings"] = other["findings"][:1]
    c = rollup_model.manifest_from_report(other, repo="x")
    assert c["digest"] != a["digest"]


def test_manifest_from_report_defaults_repo_from_target():
    man = rollup_model.manifest_from_report(_report())
    assert man["repo"] == "dvpwa-master"
    assert man["flags"] == []


# ---------------------------------------------------------------------------
# C. collator: shuffle -> byte-identical (the D-1 gate)
# ---------------------------------------------------------------------------


def _manifests(n=4):
    return [
        _good_manifest(repo=f"repo{i:02d}", digest=f"sha256:{i:02d}",
                       summary={"findings": i + 1},
                       top_techniques=[{"technique": "T1059",
                                        "count": i + 1}])
        for i in range(n)
    ]


def test_build_rollup_is_byte_identical_under_every_input_order():
    mans = _manifests(4)
    payloads = set()
    for perm in itertools.permutations(mans):
        doc = rollup_model.build_rollup(list(perm), as_of="2026-10-31T00:00:00Z")
        payloads.add(json.dumps(doc, sort_keys=True, ensure_ascii=True,
                                separators=(",", ":")))
    assert len(payloads) == 1, f"shuffle broke determinism: {len(payloads)}"


def test_build_rollup_shape_and_totals():
    doc = rollup_model.build_rollup(_manifests(3),
                                    as_of="2026-10-31T00:00:00Z")
    assert doc["schema"] == rollup_model.ORG_ROLLUP_SCHEMA
    assert doc["as_of"] == "2026-10-31T00:00:00Z"
    assert [r["repo"] for r in doc["repos"]] == ["repo00", "repo01",
                                                 "repo02"]
    assert doc["totals"]["repos"] == 3
    # counters summed across repos (sorted keys)
    assert doc["totals"]["counters"]["findings"] == 1 + 2 + 3
    # techniques aggregated then sorted (-count, technique)
    assert doc["totals"]["techniques"] == [
        {"technique": "T1059", "count": 6}]
    assert doc["totals"]["repos_with_api_posture"] == 0
    assert doc["totals"]["repos_with_sbom_drift"] == 0
    # A-1/B-2 not reported by any repo -> totals sections ABSENT
    # (absent = not reported, never a fabricated "0 means clean")
    assert "api_posture" not in doc["totals"]
    assert "sbom_drift" not in doc["totals"]
    assert doc["skips"] == []
    assert rollup_model.validate_rollup(doc) is None


def test_build_rollup_normalizes_flags_and_techniques():
    man = _good_manifest(
        flags=["zeta", "alpha", "zeta"],
        top_techniques=[{"technique": "T1059", "count": 1},
                        {"technique": "T1190", "count": 9}])
    doc = rollup_model.build_rollup([man], as_of="t")
    out = doc["repos"][0]
    assert out["flags"] == ["alpha", "zeta"]        # sorted unique
    assert out["top_techniques"][0]["technique"] == "T1190"
    # inputs are never mutated
    assert man["flags"] == ["zeta", "alpha", "zeta"]


def test_build_rollup_counts_identical_duplicates_and_conflicts_loud():
    a = _good_manifest()
    doc = rollup_model.build_rollup([a, json.loads(json.dumps(a))],
                                    as_of="t")
    assert len(doc["repos"]) == 1
    assert doc["stats"]["duplicates_identical"] == 1
    with pytest.raises(rollup_model.RollupInvalid) as exc:
        rollup_model.build_rollup([a, _good_manifest(digest="sha256:other")],
                                  as_of="t")
    assert exc.value.reason == "duplicate_repo_conflict:dvpwa"


def test_build_rollup_refuses_invalid_manifest_loud():
    with pytest.raises(rollup_model.RollupInvalid) as exc:
        rollup_model.build_rollup([_good_manifest(repo="")], as_of="t")
    assert exc.value.reason == "repo_empty"


def test_validate_rollup_roundtrip_and_reasons():
    doc = rollup_model.build_rollup(_manifests(2), as_of="t")
    assert rollup_model.validate_rollup(doc) is None
    bad = dict(doc)
    bad["schema"] = "wrong"
    assert rollup_model.validate_rollup(bad) == "rollup_schema"
    bad2 = dict(doc)
    bad2["totals"] = "nope"
    assert rollup_model.validate_rollup(bad2) == "rollup_totals_not_object"
    bad3 = dict(doc)
    bad3["repos"] = doc["repos"] + ["junk"]
    assert rollup_model.validate_rollup(bad3) == "rollup_repo_not_object"


# ---------------------------------------------------------------------------
# D. CLI: --org-rollup manifests/*.json collator (pure, offline)
# ---------------------------------------------------------------------------


def _write_manifests(tmp, n=3):
    paths = []
    for i in range(n):
        p = pathlib.Path(tmp) / f"manifest{i}.json"
        p.write_text(json.dumps(_good_manifest(repo=f"repo{i:02d}",
                                               digest=f"sha256:{i}")),
                     encoding="utf-8")
        paths.append(str(p))
    return paths


def _run_cli(args):
    return subprocess.run(
        [sys.executable, "-m", "analysis.rollup.connect"] + args,
        capture_output=True, text=True, timeout=120,
        cwd=str(pathlib.Path(__file__).resolve().parents[1]))


def test_cli_collates_and_is_byte_stable_across_runs():
    with tempfile.TemporaryDirectory(prefix="rsx_t93_") as tmp:
        paths = _write_manifests(tmp)
        out1 = str(pathlib.Path(tmp) / "org_rollup.json")
        r1 = _run_cli(["--org-rollup"] + paths + [
            "--out", out1, "--as-of", "2026-10-31T00:00:00Z"])
        assert r1.returncode == 0, r1.stderr
        # shuffled ARG order -> identical bytes (D-1 gate)
        out2 = str(pathlib.Path(tmp) / "org_rollup2.json")
        r2 = _run_cli(["--org-rollup"] + list(reversed(paths)) + [
            "--out", out2, "--as-of", "2026-10-31T00:00:00Z"])
        assert r2.returncode == 0, r2.stderr
        b1 = pathlib.Path(out1).read_bytes()
        b2 = pathlib.Path(out2).read_bytes()
        assert b1 == b2
        doc = json.loads(b1)
        assert doc["schema"] == rollup_model.ORG_ROLLUP_SCHEMA
        assert [r["repo"] for r in doc["repos"]] == ["repo00", "repo01",
                                                     "repo02"]


def test_cli_glob_pattern_argument_expands_offline():
    with tempfile.TemporaryDirectory(prefix="rsx_t93_") as tmp:
        _write_manifests(tmp, n=2)
        out = str(pathlib.Path(tmp) / "org_rollup.json")
        r = _run_cli(["--org-rollup",
                      str(pathlib.Path(tmp) / "manifest*.json"),
                      "--out", out, "--as-of", "2026-10-31T00:00:00Z"])
        assert r.returncode == 0, r.stderr
        doc = json.loads(pathlib.Path(out).read_text(encoding="utf-8"))
        assert doc["totals"]["repos"] == 2


def test_cli_zero_i_O_default_is_not_provided_skip():
    with tempfile.TemporaryDirectory(prefix="rsx_t93_") as tmp:
        out = str(pathlib.Path(tmp) / "org_rollup.json")
        r = _run_cli(["--out", out, "--as-of", "2026-10-31T00:00:00Z"])
        assert r.returncode == 0, r.stderr
        doc = json.loads(pathlib.Path(out).read_text(encoding="utf-8"))
        assert doc["repos"] == []
        assert doc["skips"] == [{"reason": "not_provided",
                                 "source": "org_rollup"}]


def test_cli_invalid_manifest_fails_loud_and_writes_no_artifact():
    with tempfile.TemporaryDirectory(prefix="rsx_t93_") as tmp:
        bad = pathlib.Path(tmp) / "manifest0.json"
        bad.write_text(json.dumps({"schema": rollup_model.MANIFEST_SCHEMA,
                                   "repo": ""}), encoding="utf-8")
        out = str(pathlib.Path(tmp) / "org_rollup.json")
        r = _run_cli(["--org-rollup", str(bad), "--out", out,
                      "--as-of", "2026-10-31T00:00:00Z"])
        assert r.returncode == 1
        assert "repo_empty" in r.stderr
        assert not pathlib.Path(out).exists()


def test_cli_usage_errors():
    r = _run_cli([])
    assert r.returncode == 2                      # --out required
    r = _run_cli(["--out", "x.json", "--as-of", "not-a-time"])
    assert r.returncode == 2 and "as-of" in r.stderr


# ---------------------------------------------------------------------------
# E. pins: offline + package surface
# ---------------------------------------------------------------------------


def test_offline_source_pin_no_network_tokens():
    pkg = pathlib.Path(__file__).resolve().parents[1] / "analysis" / "rollup"
    banned = ("urllib", "socket", "boto3", "requests", "os.environ",
              "http.client")
    for py in pkg.glob("*.py"):
        src = py.read_text(encoding="utf-8")
        for token in banned:
            assert token not in src, f"{py.name} contains banned {token}"


def test_package_surface():
    import analysis.rollup as pkg
    for name in ("MANIFEST_SCHEMA", "ORG_ROLLUP_SCHEMA",
                 "RollupInvalid", "build_rollup", "manifest_from_report",
                 "validate_manifest", "validate_rollup"):
        assert hasattr(pkg, name), f"analysis.rollup missing {name}"
