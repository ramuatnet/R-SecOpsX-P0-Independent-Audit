"""V3 differential (secrets / IaC / licence) unit tests.

The differential's product is its report, so these tests pin the machinery
that produces it: path normalisation, licence-family canonicalisation,
1:1 location matching, per-peer JSON adapters (against captured output
shapes), the BLOCKED semantics for absent tools, and the exit-code
contract. They also pin the secret non-republication guarantee: no adapter
result may ever carry secret material, only file/line/rule triples.

The composer.lock licence extraction test records a gap this differential
work found and fixed: declared package licences were discarded, so every
Packagist package showed "unknown" while peers resolved them.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from analysis.validation import v3_differential as v3  # noqa: E402


# ---------------------------------------------------------------------------
# path normalisation
# ---------------------------------------------------------------------------

def test_rel_file_absolute_inside_root():
    root = Path("/tmp/root")
    assert v3._rel_file(str(root / "sub" / "main.tf"), root) == "sub/main.tf"


def test_rel_file_absolute_outside_root_keeps_tail():
    assert v3._rel_file("C:/other/place/main.tf", Path("/tmp/root")).endswith("main.tf")


def test_rel_file_relative_forms():
    root = Path("/tmp/root")
    assert v3._rel_file("main.tf", root) == "main.tf"
    assert v3._rel_file("./main.tf", root) == "main.tf"
    assert v3._rel_file("sub\\main.tf", root) == "sub/main.tf"
    # checkov emits leading-backslash pseudo-absolute paths
    assert v3._rel_file("\\main.tf", root) == "main.tf"


def test_rel_file_root_token():
    root = Path("/tmp/root")
    assert v3._rel_file(".", root) == v3._ROOT_TOKEN
    assert v3._rel_file("", root) == v3._ROOT_TOKEN
    assert v3._rel_file(None, root) == v3._ROOT_TOKEN


def test_strip_root_prefix():
    root = Path("/tmp/rsx_v3_x/target")
    assert v3._strip_root_prefix("target/main.tf", root) == "main.tf"
    assert v3._strip_root_prefix("other/main.tf", root) == "other/main.tf"


# ---------------------------------------------------------------------------
# licence family canonicalisation
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("raw,expected", [
    ("MIT", "mit"),
    ("The MIT License (MIT)", "mit"),
    ("mit license", "mit"),
    ("Apache-2.0", "apache-2.0"),
    ("Apache License 2.0", "apache-2.0"),
    ("GPL-3.0-only", "gpl-3.0"),
    ("GPL-3.0-or-later", "gpl-3.0"),
    ("GNU General Public License v3.0 (gpl-3.0)", "gpl-3.0"),
    ("BSD-3-Clause", "bsd-3-clause"),
    ("Mozilla Public License 2.0 (MPL-2.0)", "mpl-2.0"),
    ("LGPL-2.1-only", "lgpl"),
    ("unknown", "unknown"),
    ("UNKNOWN", "unknown"),
    ("", "unknown"),
    (None, "unknown"),
])
def test_license_family_canonicalisation(raw, expected):
    assert v3._license_family(raw) == expected


def test_families_match_equal_contained_and_unknown():
    assert v3._families_match("mit", "mit")
    assert v3._families_match("gpl-3.0", "gpl-3.0-or-later-thing")
    assert not v3._families_match("mit", "gpl-3.0")
    assert not v3._families_match("unknown", "mit")


# ---------------------------------------------------------------------------
# location diff: greedy 1:1 nearest-line per file
# ---------------------------------------------------------------------------

def _o(file, line, label="OURS"):
    return {"file": file, "line": line, "label": label}


def _t(file, line, label="PEER"):
    return {"file": file, "line": line, "label": label}


def test_diff_location_exact_and_within_tolerance():
    ours = [_o("a.tf", 10), _o("a.tf", 40)]
    theirs = [_t("a.tf", 11), _t("a.tf", 44)]
    in_both, only_o, only_t = v3._diff_location(ours, theirs, tolerance=5)
    assert len(in_both) == 2 and not only_o and not only_t
    assert in_both[0]["ours_rule"] == "OURS" and in_both[0]["peer_rule"] == "PEER"


def test_diff_location_beyond_tolerance_is_a_disagreement():
    in_both, only_o, only_t = v3._diff_location([_o("a.tf", 10)], [_t("a.tf", 30)], tolerance=5)
    assert not in_both and len(only_o) == 1 and len(only_t) == 1


def test_diff_location_is_greedy_one_to_one():
    # three ours findings on one line, one peer finding: exactly one pair.
    ours = [_o("a.tf", 5, "R1"), _o("a.tf", 5, "R2"), _o("a.tf", 5, "R3")]
    theirs = [_t("a.tf", 5, "P1")]
    in_both, only_o, only_t = v3._diff_location(ours, theirs, tolerance=2)
    assert len(in_both) == 1
    assert len(only_o) == 2 and len(only_t) == 0


def test_diff_location_nearest_wins():
    ours = [_o("a.tf", 10)]
    theirs = [_t("a.tf", 12), _t("a.tf", 9)]
    in_both, _, _ = v3._diff_location(ours, theirs, tolerance=5)
    assert in_both[0]["peer_line"] == 9  # nearest unmatched peer line


def test_diff_location_separates_files():
    ours = [_o("a.tf", 10), _o("b.tf", 10)]
    theirs = [_t("b.tf", 10)]
    in_both, only_o, _ = v3._diff_location(ours, theirs, tolerance=3)
    assert len(in_both) == 1 and in_both[0]["file"] == "b.tf"
    assert [e["file"] for e in only_o] == ["a.tf"]


# ---------------------------------------------------------------------------
# licence diffs
# ---------------------------------------------------------------------------

def test_diff_license_packages_match_conflict_and_splits():
    ours = [
        {"name": "monolog/monolog", "display_name": "monolog/monolog", "license": "MIT"},
        {"name": "flask", "display_name": "flask", "license": "BSD-3-Clause"},
        {"name": "only-ours", "display_name": "only-ours", "license": "MIT"},
        {"name": "disputed", "display_name": "disputed", "license": "MIT"},
    ]
    theirs = [
        {"name": "monolog/monolog", "display_name": "monolog/monolog", "license": "The MIT License"},
        {"name": "disputed", "display_name": "disputed", "license": "GPL-3.0-only"},
        {"name": "only-peer", "display_name": "only-peer", "license": "Apache-2.0"},
    ]
    in_both, only_o, only_t, conflicts = v3._diff_license_packages(ours, theirs)
    assert [e["package"] for e in in_both] == ["monolog/monolog"]
    assert [e["package"] for e in only_o] == ["flask", "only-ours"]
    assert [e["package"] for e in only_t] == ["only-peer"]
    assert len(conflicts) == 1 and conflicts[0]["package"] == "disputed"
    assert conflicts[0]["ours_family"] == "mit" and conflicts[0]["peer_family"] == "gpl-3.0"


def test_diff_license_packages_name_normalisation():
    ours = [{"name": "py-yaml", "display_name": "py-yaml", "license": "MIT"}]
    theirs = [{"name": "py_yaml", "display_name": "py_yaml", "license": "MIT"}]
    in_both, _, _, _ = v3._diff_license_packages(ours, theirs)
    # runner-side names are pre-casefolded; the helper trusts them.
    assert in_both == []


def test_diff_license_files_family_overlap():
    ours = [{"file": "LICENSE", "license": "MIT"}]
    theirs = [{"file": "LICENSE", "license": "The MIT License"}]
    in_both, _, _, conflicts = v3._diff_license_files(ours, theirs)
    assert len(in_both) == 1 and not conflicts


# ---------------------------------------------------------------------------
# peer adapters against captured output shapes
# ---------------------------------------------------------------------------

def test_parse_checkov_json_shapes(tmp_path):
    payload = [
        {
            "check_type": "terraform",
            "results": {
                "failed_checks": [
                    {
                        "check_id": "CKV_AWS_18",
                        "file_abs_path": str(tmp_path / "main.tf"),
                        "file_path": "\\main.tf",
                        "file_line_range": [8, 11],
                    }
                ]
            },
        }
    ]
    entries = v3._parse_checkov_json(json.dumps(payload), tmp_path)
    assert entries == [{"file": "main.tf", "line": 8, "label": "CKV_AWS_18"}]


def test_parse_checkov_json_single_object(tmp_path):
    payload = {"check_type": "dockerfile",
               "results": {"failed_checks": [
                   {"check_id": "CKV_DOCKER_2", "file_path": "\\Dockerfile",
                    "file_line_range": [2, 2]}]}}
    entries = v3._parse_checkov_json(json.dumps(payload), tmp_path)
    assert entries == [{"file": "Dockerfile", "line": 2, "label": "CKV_DOCKER_2"}]


def test_parse_kics_json(tmp_path):
    payload = {"queries": [
        {"query_id": "58a3c151-6h..", "query_name": "S3 bucket public ACL",
         "files": [{"file_name": str(tmp_path / "main.tf"), "line": 10}]},
    ]}
    entries = v3._parse_kics_json(json.dumps(payload), tmp_path)
    assert entries == [{"file": "main.tf", "line": 10, "label": "58a3c151-6h.."}]


def test_parse_kics_json_relative_paths_resolve_against_base(tmp_path):
    """kics relativises paths to ITS cwd when the tree sits under it.

    Without base_dir resolution every kics finding landed in
    only_in_peer as "scanroot/main.tf" and in_both was silently zero.
    """
    copy_root = tmp_path / "scanroot"
    copy_root.mkdir()
    payload = {"queries": [
        {"query_id": "q1", "files": [{"file_name": "scanroot/main.tf", "line": 8}]},
    ]}
    entries = v3._parse_kics_json(json.dumps(payload), copy_root, base_dir=tmp_path)
    assert entries == [{"file": "main.tf", "line": 8, "label": "q1"}]


def test_parse_trivy_config_filters_pass_and_uses_cause_metadata(tmp_path):
    payload = {"Results": [
        {"Target": "main.tf", "Misconfigurations": [
            {"ID": "AWS-0092", "Status": "FAIL",
             "CauseMetadata": {"StartLine": 8}},
            {"ID": "AWS-0026", "Status": "PASS",
             "CauseMetadata": {"StartLine": 24}},
        ]},
        {"Target": ".", "Misconfigurations": [
            {"ID": "DS-0026", "Status": "FAIL", "CauseMetadata": {}},
        ]},
    ]}
    entries = v3._parse_trivy_config(json.dumps(payload), tmp_path)
    assert {"file": "main.tf", "line": 8, "label": "AWS-0092"} in entries
    assert {"file": v3._ROOT_TOKEN, "line": 0, "label": "DS-0026"} in entries
    assert len(entries) == 2  # the PASS entry is dropped


def test_parse_trivy_license_package_class_only():
    payload = {"Results": [
        {"Target": "composer.lock", "Class": "license", "Licenses": [
            {"PkgName": "monolog/monolog", "Name": "MIT", "FilePath": "composer.lock"},
        ]},
        {"Target": "requirements.txt", "Class": "lang-pkgs",
         "Packages": [{"Name": "flask"}]},
        {"Target": "LICENSE", "Class": "license-file", "Licenses": [
            {"Name": "MIT", "FilePath": "LICENSE"},
        ]},
    ]}
    entries = v3._parse_trivy_license(json.dumps(payload), Path("/tmp/x"))
    assert entries == [
        {"name": "monolog/monolog", "display_name": "monolog/monolog",
         "license": "MIT", "file": "composer.lock"},
    ]


def test_gitleaks_adapter_never_carries_secret_material(tmp_path, monkeypatch):
    """Policy: adapter results are file/line/rule triples only."""
    report = tmp_path / "gitleaks.json"
    secret_value = "RAWSECRET_SHOULD_NEVER_APPEAR_123456"
    report.write_text(json.dumps([
        {"RuleID": "github-pat", "File": str(tmp_path / ".env"), "StartLine": 2,
         "Secret": secret_value, "Match": "token = " + secret_value},
    ]), encoding="utf-8")

    seen_argv = {}

    def fake_run_tool(argv, cwd, timeout):
        seen_argv["argv"] = argv
        class Proc:
            stderr = stdout = ""
        return Proc()

    monkeypatch.setattr(v3, "_run_tool", fake_run_tool)
    entries = v3._run_gitleaks(["gitleaks"], tmp_path, tmp_path, 10)

    assert report.exists()  # the adapter reads the file gitleaks wrote
    assert "--redact" in seen_argv["argv"]
    assert entries == [{"file": ".env", "line": 2, "label": "github-pat"}]
    serialized = json.dumps(entries)
    assert secret_value not in serialized


def test_gitleaks_adapter_missing_report_is_tool_error(tmp_path, monkeypatch):
    def fake_run_tool(argv, cwd, timeout):
        class Proc:
            stderr = "boom"
            stdout = ""
        return Proc()

    monkeypatch.setattr(v3, "_run_tool", fake_run_tool)
    with pytest.raises(v3.ToolError):
        v3._run_gitleaks(["gitleaks"], tmp_path, tmp_path, 10)


# ---------------------------------------------------------------------------
# peer resolution and BLOCKED semantics
# ---------------------------------------------------------------------------

def test_find_peer_argv_unknown_tool_is_none(tmp_path, monkeypatch):
    monkeypatch.setattr(v3.shutil, "which", lambda name: None)
    monkeypatch.setattr(v3, "_tool_dir", lambda: tmp_path)
    # isolate BOTH tool locations: a real rsx_checkov_venv in the system
    # tempdir must not leak into this assertion.
    monkeypatch.setattr(v3.tempfile, "gettempdir", lambda: str(tmp_path))
    monkeypatch.setenv("RSX_CHECKOV_VENV", str(tmp_path / "novenv"))
    assert v3._find_peer_argv("gitleaks") is None
    assert v3._find_peer_argv("checkov") is None


def test_find_peer_argv_finds_tool_dir_binary(tmp_path, monkeypatch):
    monkeypatch.setattr(v3.shutil, "which", lambda name: None)
    monkeypatch.setattr(v3, "_tool_dir", lambda: tmp_path)
    exe = tmp_path / "gitleaks" / "gitleaks.exe"
    exe.parent.mkdir(parents=True)
    exe.write_text("", encoding="utf-8")
    assert v3._find_peer_argv("gitleaks") == [str(exe)]


def test_find_peer_argv_checkov_venv(tmp_path, monkeypatch):
    monkeypatch.setattr(v3.shutil, "which", lambda name: None)
    venv = tmp_path / "venv"
    py = venv / "Scripts" / "python.exe"
    py.parent.mkdir(parents=True)
    py.write_text("", encoding="utf-8")
    monkeypatch.setenv("RSX_CHECKOV_VENV", str(venv))
    assert v3._find_peer_argv("checkov") == [str(py), "-m", "checkov.main"]


def test_run_domain_blocked_on_missing_target(tmp_path):
    result = v3.run_domain("secrets", tmp_path / "nope")
    assert result["status"] == "blocked"
    assert any("does not exist" in r for r in result["reasons"])


def test_run_domain_blocked_on_absent_peer(tmp_path, monkeypatch):
    monkeypatch.setattr(v3, "_find_peer_argv", lambda peer: None)
    target = tmp_path / "t"
    target.mkdir()
    result = v3.run_domain("iac", target)
    assert result["status"] == "blocked"
    assert any("not available" in r for r in result["reasons"])


def test_run_domain_blocked_on_ours_failure(tmp_path, monkeypatch):
    monkeypatch.setattr(v3, "_find_peer_argv", lambda peer: ["fake"])
    monkeypatch.setitem(v3.OURS_RUNNERS, "secrets", _boom_runner)
    target = tmp_path / "t"
    target.mkdir()
    result = v3.run_domain("secrets", target)
    assert result["status"] == "blocked"
    assert any("scanner failed" in r for r in result["reasons"])


def _boom_runner(copy_root):
    raise RuntimeError("kaboom")


def _fake_ours(copy_root):
    return [
        {"file": "main.tf", "line": 8, "label": "TF_PUBLIC_S3_ACL"},
        {"file": "main.tf", "line": 13, "label": "TF_OPEN_SECURITY_GROUP_INGRESS"},
    ]


def _fake_peer(argv, copy_root, work, timeout):
    return [
        {"file": "main.tf", "line": 8, "label": "CKV_AWS_18"},
        {"file": "main.tf", "line": 99, "label": "CKV_AWS_23"},
    ]


def test_run_domain_end_to_end_counts(tmp_path, monkeypatch):
    monkeypatch.setattr(v3, "_find_peer_argv", lambda peer: ["fake-checkov"])
    monkeypatch.setitem(v3.OURS_RUNNERS, "iac", _fake_ours)
    monkeypatch.setitem(v3.PEER_ADAPTERS, ("iac", "checkov"), _fake_peer)
    target = tmp_path / "t"
    target.mkdir()
    (target / "main.tf").write_text("# fixture", encoding="utf-8")

    result = v3.run_domain("iac", target)
    assert result["status"] == "ran"
    assert result["agreement"] == "disagreements"
    assert result["counts"] == {
        "rsecopsx": 2, "peer": 2, "in_both": 1,
        "only_in_rsecopsx": 1, "only_in_peer": 1,
    }
    assert result["in_both"][0]["ours_rule"] == "TF_PUBLIC_S3_ACL"
    assert result["in_both"][0]["peer_rule"] == "CKV_AWS_18"


def test_run_domain_license_conflicts_are_disagreements(tmp_path, monkeypatch):
    # scancode must NOT resolve: peer order puts it first and it would win.
    monkeypatch.setattr(v3, "_find_peer_argv",
                        lambda peer: ["fake-trivy"] if peer == "trivy" else None)
    monkeypatch.setitem(v3.OURS_RUNNERS, "license",
                        lambda root: [{"name": "x", "display_name": "x", "license": "MIT"}])
    monkeypatch.setitem(v3.PEER_ADAPTERS, ("license", "trivy"),
                        lambda argv, root, work, t: [
                            {"name": "x", "display_name": "x", "license": "GPL-3.0-only",
                             "file": "composer.lock"}])
    target = tmp_path / "t"
    target.mkdir()
    result = v3.run_domain("license", target)
    assert result["counts"]["conflicts"] == 1
    assert result["agreement"] == "disagreements"


def test_run_domain_agree_returns_agree(tmp_path, monkeypatch):
    monkeypatch.setattr(v3, "_find_peer_argv", lambda peer: ["fake"])
    monkeypatch.setitem(v3.OURS_RUNNERS, "iac", _fake_ours)
    monkeypatch.setitem(v3.PEER_ADAPTERS, ("iac", "checkov"),
                        lambda argv, root, work, t: list(_fake_ours(root)))
    target = tmp_path / "t"
    target.mkdir()
    result = v3.run_domain("iac", target)
    assert result["agreement"] == "agree"
    assert result["counts"]["only_in_rsecopsx"] == 0


# ---------------------------------------------------------------------------
# CLI exit-code contract
# ---------------------------------------------------------------------------

def _result(status, agreement="agree"):
    r = {"status": status, "domain": "secrets", "reasons": ["x"],
         "counts": {"rsecopsx": 0, "peer": 0, "in_both": 0,
                    "only_in_rsecopsx": 0, "only_in_peer": 0}}
    if status == "ran":
        r["agreement"] = agreement
        r.update({"peer_tool": "gitleaks", "peer_binary": "gitleaks",
                  "in_both": [], "only_in_rsecopsx": [], "only_in_peer": [],
                  "conflicts": []})
    return r


def test_main_exit_codes(tmp_path, monkeypatch):
    monkeypatch.setattr(
        v3, "run_domain",
        lambda domain, target, peer=None, tolerance=None, timeout=600: _result("ran", "agree"))
    assert v3.main(["--domain", "secrets", "--target", str(tmp_path)]) == 0

    monkeypatch.setattr(
        v3, "run_domain",
        lambda domain, target, peer=None, tolerance=None, timeout=600: _result("ran", "disagreements"))
    assert v3.main(["--domain", "secrets", "--target", str(tmp_path)]) == 1

    monkeypatch.setattr(
        v3, "run_domain",
        lambda domain, target, peer=None, tolerance=None, timeout=600: _result("blocked"))
    assert v3.main(["--domain", "secrets", "--target", str(tmp_path)]) == 2


def test_main_disagreement_beats_blocked(tmp_path, monkeypatch):
    """A real disagreement outranks a blocked domain in the exit code."""
    calls = {"n": 0}

    def fake_run(domain, target, peer=None, tolerance=None, timeout=600):
        calls["n"] += 1
        if calls["n"] == 1:
            return _result("ran", "disagreements")
        return _result("blocked")

    monkeypatch.setattr(v3, "run_domain", fake_run)
    assert v3.main(["--domain", "all", "--target", str(tmp_path)]) == 1


def test_main_writes_json_report(tmp_path, monkeypatch):
    monkeypatch.setattr(
        v3, "run_domain",
        lambda domain, target, peer=None, tolerance=None, timeout=600: _result("ran", "agree"))
    out = tmp_path / "report.json"
    code = v3.main(["--domain", "secrets", "--target", str(tmp_path),
                    "--json", str(out)])
    assert code == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data[0]["status"] == "ran"


# ---------------------------------------------------------------------------
# composer.lock declared licences (gap found by this differential)
# ---------------------------------------------------------------------------

def test_composer_lock_extracts_declared_licenses(tmp_path):
    from scanner.manifests.composer_lock import parse_composer_lock

    lock = {
        "packages": [
            {"name": "monolog/monolog", "version": "v3.5.0", "license": ["MIT"]},
            {"name": "example/gpl-toolkit", "version": "1.2.3", "license": ["GPL-3.0-only"]},
            {"name": "string-license/pkg", "version": "1.0.0", "license": "Apache-2.0"},
            {"name": "no-license/pkg", "version": "1.0.0"},
        ],
        "packages-dev": [],
    }
    p = tmp_path / "composer.lock"
    p.write_text(json.dumps(lock), encoding="utf-8")
    pkgs = {x["name"]: x for x in parse_composer_lock(str(p))}
    assert pkgs["monolog/monolog"]["license"] == "MIT"
    assert pkgs["example/gpl-toolkit"]["license"] == "GPL-3.0-only"
    assert pkgs["string-license/pkg"]["license"] == "Apache-2.0"
    assert pkgs["no-license/pkg"]["license"] == "unknown"


def test_composer_lock_fixture_files_have_licenses():
    """The shipped V3 fixture must exercise the declared-licence path."""
    from scanner.manifests.composer_lock import parse_composer_lock

    fixture = REPO / "tests" / "v3_targets" / "license_target" / "composer.lock"
    pkgs = parse_composer_lock(str(fixture))
    licenses = {x["name"]: x["license"] for x in pkgs}
    assert licenses.get("monolog/monolog") == "MIT"
    assert licenses.get("example/gpl-toolkit") == "GPL-3.0-only"


def test_ours_license_runner_sees_manifests_in_neutral_temp_copy(tmp_path):
    """Regression for the silent zero: the runner's temp copy once sat in a
    directory named "target", which sbom.EXCLUDED_DIRS (cargo build dir)
    excluded from every manifest walk -- the licence domain then compared
    zero of our packages against the peer and looked like a peer-only
    report. The copy name is part of the contract, so pin it here.
    """
    import shutil

    copy_root = tmp_path / "scanroot"
    shutil.copytree(REPO / "tests" / "v3_targets" / "license_target", copy_root)
    pkgs = v3._ours_license(copy_root)
    names = {p["name"] for p in pkgs}
    assert "monolog/monolog" in names
    assert "flask" in names
    by_name = {p["name"]: p for p in pkgs}
    assert by_name["monolog/monolog"]["license"] == "MIT"
    assert by_name["example/gpl-toolkit"]["license"] == "GPL-3.0-only"
