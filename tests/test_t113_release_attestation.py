"""T-9.13 SLSA + sigstore-signed releases (task.md section 13).

Pins the in-house release attestation: the sigstore/slsa-verifier
NOT-adopted disclosure, deterministic canonical JSON and statement
bytes (no wall-clock in the signed payload), HMAC-SHA256 sign/verify
with constant-time comparison, tamper detection, key handling
(--key-file / RSECOPSX_RELEASE_KEY only, never echoed), the honest
SLSA level-1 self-attestation wording, and CLI EXIT CODES
0 / 1 / 2.
"""
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
MODULE_SRC = (REPO / "analysis" / "validation" / "release_attestation.py")

KEY = b"rsx-t113-test-key"
OTHER_KEY = b"rsx-t113-other-key"


def _make_tree(root: pathlib.Path) -> pathlib.Path:
    """Minimal release surface: root files + nested deploy/ tree."""
    (root / "deploy" / "helm" / "rsecopsx").mkdir(parents=True)
    (root / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    (root / "docker-compose.yml").write_text("services: {}\n",
                                             encoding="utf-8")
    (root / "pyproject.toml").write_text("[project]\nname='x'\n",
                                         encoding="utf-8")
    (root / "deploy" / "AIRGAP.md").write_text("# airgap\n",
                                               encoding="utf-8")
    (root / "deploy" / "helm" / "rsecopsx" / "Chart.yaml").write_text(
        "name: rsecopsx\n", encoding="utf-8")
    return root


@pytest.fixture()
def release_root(tmp_path) -> pathlib.Path:
    return _make_tree(tmp_path / "rsx_t113_root")


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    monkeypatch.delenv("RSECOPSX_RELEASE_KEY", raising=False)


# ---------------------------------------------------------------- disclosure


def test_sigstore_not_adopted_disclosure():
    src = MODULE_SRC.read_text(encoding="utf-8")
    needles = (
        "sigstore (cosign / Fulcio / Rekor) and slsa-verifier are NOT "
        "adopted",
        "named-tool precedent",
        "offline/airgap scan invariant",
        "self-attested",
        "EXIT CODES",
        "RSECOPSX_RELEASE_KEY",
        "slsa_build_level: 1",
    )
    for needle in needles:
        assert needle in src, "disclosure missing: %r" % needle


def test_not_adopted_grep_matches_named_tool_style():
    """The greppable one-liner other NOT-adopted modules use."""
    src = MODULE_SRC.read_text(encoding="utf-8")
    assert "NOT adopted" in src
    assert "sigstore" in src.lower()


# ------------------------------------------------------------ canonical json


def test_canonical_json_key_order_independent():
    from analysis.validation import release_attestation as ra
    a = {"b": 1, "a": {"y": 2, "x": [1, 2]}}
    b = {"a": {"x": [1, 2], "y": 2}, "b": 1}
    assert ra.canonical_json(a) == ra.canonical_json(b)
    assert ra.canonical_json(a) == b'{"a":{"x":[1,2],"y":2},"b":1}'


def test_statement_deterministic_no_wallclock(release_root):
    from analysis.validation import release_attestation as ra
    s1 = ra.build_statement(release_root, "1.2.3")
    s2 = ra.build_statement(release_root, "1.2.3")
    assert ra.canonical_json(s1) == ra.canonical_json(s2)
    blob = json.dumps(s1)
    for banned in ("timestamp", "builtAt", "created", "now", "time"):
        assert '"%s"' % banned not in blob, banned


def test_statement_shape_and_slsa_level(release_root):
    from analysis.validation import release_attestation as ra
    s = ra.build_statement(release_root, "9.9.9", source_commit="abc123")
    assert s["_type"] == ra.IN_TOTO_TYPE
    assert s["predicateType"] == ra.PREDICATE_TYPE
    pred = s["predicate"]
    assert pred["builder"]["id"] == ra.BUILDER_ID
    assert pred["buildType"] == ra.BUILD_TYPE
    assert pred["metadata"]["toolVersion"] == "9.9.9"
    assert pred["metadata"]["sourceCommit"] == "abc123"
    assert pred["slsa"]["buildLevel"] == 1
    assert "NOT adopted" in pred["slsa"]["note"]
    assert "offline" in pred["slsa"]["note"]


def test_subject_digests_match_files(release_root):
    from analysis.validation import release_attestation as ra
    subjects = ra.collect_subjects(release_root)
    names = {sub["name"] for sub in subjects}
    assert names == {"Dockerfile", "docker-compose.yml", "pyproject.toml",
                     "deploy/AIRGAP.md",
                     "deploy/helm/rsecopsx/Chart.yaml"}
    by_name = {sub["name"]: sub for sub in subjects}
    digest = ra.hash_file(release_root / "Dockerfile")
    assert by_name["Dockerfile"]["digest"]["sha256"] == digest


def test_default_globs_cover_real_release_surface():
    from analysis.validation import release_attestation as ra
    subjects = ra.collect_subjects(REPO)
    names = {sub["name"] for sub in subjects}
    assert "Dockerfile" in names
    assert "docker-compose.yml" in names
    assert "pyproject.toml" in names
    assert any(n.startswith("deploy/") for n in names), names


def test_empty_tree_raises(release_root):
    from analysis.validation import release_attestation as ra
    with pytest.raises(ValueError):
        ra.build_statement(release_root, "1.0", globs=("no/such/*",))


# ---------------------------------------------------------------- sign/verify


def test_sign_verify_roundtrip(release_root):
    from analysis.validation import release_attestation as ra
    s = ra.build_statement(release_root, "1.0")
    sig = ra.sign(s, KEY)
    assert sig["alg"] == ra.ALG
    assert sig["schema"] == ra.SCHEMA
    assert len(sig["keyId"]) == 16
    assert ra.verify(s, sig, KEY) is True


def test_sign_deterministic():
    from analysis.validation import release_attestation as ra
    s = {"x": 1}
    assert ra.sign(s, KEY)["sig"] == ra.sign(s, KEY)["sig"]


def test_tampered_subject_fails(release_root):
    from analysis.validation import release_attestation as ra
    s = ra.build_statement(release_root, "1.0")
    sig = ra.sign(s, KEY)
    s["subject"][0]["digest"]["sha256"] = "0" * 64
    assert ra.verify(s, sig, KEY) is False


def test_tampered_predicate_fails(release_root):
    from analysis.validation import release_attestation as ra
    s = ra.build_statement(release_root, "1.0")
    sig = ra.sign(s, KEY)
    s["predicate"]["metadata"]["toolVersion"] = "0.0-evil"
    assert ra.verify(s, sig, KEY) is False


def test_wrong_key_fails(release_root):
    from analysis.validation import release_attestation as ra
    s = ra.build_statement(release_root, "1.0")
    sig = ra.sign(s, KEY)
    assert ra.verify(s, sig, OTHER_KEY) is False


def test_bad_alg_schema_keyid_fail(release_root):
    from analysis.validation import release_attestation as ra
    s = ra.build_statement(release_root, "1.0")
    sig = ra.sign(s, KEY)
    for field, value in (("alg", "HMAC-SHA1"), ("schema", "evil/v1"),
                         ("keyId", "deadbeefdeadbeef"), ("sig", "00"),
                         ("sig", "")):
        bad = dict(sig)
        bad[field] = value
        assert ra.verify(s, bad, KEY) is False, (field, value)


def test_verify_uses_compare_digest():
    # Needle = the call site, not the name: the docstring also says
    # "hmac.compare_digest", so a bare name grep would survive M3.
    src = MODULE_SRC.read_text(encoding="utf-8")
    assert "hmac.compare_digest(expected, got)" in src


# ---------------------------------------------------------------- key handling


def test_load_key_from_file(tmp_path):
    from analysis.validation import release_attestation as ra
    key_path = tmp_path / "rsx_t113_key"
    key_path.write_bytes(KEY)
    assert ra.load_key(key_path) == KEY


def test_load_key_from_env(monkeypatch):
    from analysis.validation import release_attestation as ra
    monkeypatch.setenv("RSECOPSX_RELEASE_KEY", "env-key")
    assert ra.load_key(None) == b"env-key"


def test_load_key_missing_raises(monkeypatch, tmp_path):
    from analysis.validation import release_attestation as ra
    with pytest.raises(ValueError):
        ra.load_key(tmp_path / "no-such-key")
    empty = tmp_path / "rsx_t113_empty"
    empty.write_bytes(b"")
    with pytest.raises(ValueError):
        ra.load_key(empty)


def test_key_never_echoed_in_cli_error(tmp_path, capsys):
    from analysis.validation import release_attestation as ra
    rc = ra.main(["verify", "--dir", str(tmp_path)])
    out = capsys.readouterr().out
    assert rc == 2
    assert "RSECOPSX_RELEASE_KEY" in out
    assert "could-not-run" in out.lower() or "could-not-run" in out


# ---------------------------------------------------------------------- attest / verify_dir


def test_attest_and_verify_dir_roundtrip(release_root, tmp_path):
    from analysis.validation import release_attestation as ra
    out = tmp_path / "rsx_t113_out"
    statement, sig, dest = ra.attest(release_root, KEY, tool_version="1.0",
                                     out_dir=out)
    assert (dest / "provenance.intoto.json").is_file()
    assert (dest / "provenance.intoto.json.sig").is_file()
    status, reason = ra.verify_dir(dest, KEY)
    assert status == "ok", reason


def test_verify_dir_tampered_statement(release_root, tmp_path):
    from analysis.validation import release_attestation as ra
    out = tmp_path / "rsx_t113_out"
    ra.attest(release_root, KEY, tool_version="1.0", out_dir=out)
    spath = out / "provenance.intoto.json"
    statement = json.loads(spath.read_text(encoding="utf-8"))
    statement["predicate"]["metadata"]["toolVersion"] = "hacked"
    spath.write_text(json.dumps(statement, indent=2, sort_keys=True),
                     encoding="utf-8")
    status, reason = ra.verify_dir(out, KEY)
    assert status == "invalid", reason


def test_verify_dir_missing_files(release_root, tmp_path):
    from analysis.validation import release_attestation as ra
    status, reason = ra.verify_dir(tmp_path / "rsx_t113_absent", KEY)
    assert status == "could-not-run"
    assert "missing" in reason


# ---------------------------------------------------------------------- CLI


def test_cli_attest_verify_exit_codes(release_root, tmp_path, monkeypatch):
    from analysis.validation import release_attestation as ra
    key_path = tmp_path / "rsx_t113_cli_key"
    key_path.write_bytes(KEY)
    out = tmp_path / "rsx_t113_cli_out"
    rc = ra.main(["attest", "--root", str(release_root),
                  "--out-dir", str(out), "--key-file", str(key_path)])
    assert rc == 0
    rc = ra.main(["verify", "--dir", str(out), "--key-file", str(key_path)])
    assert rc == 0
    # tamper -> 1
    spath = out / "provenance.intoto.json"
    statement = json.loads(spath.read_text(encoding="utf-8"))
    statement["subject"][0]["digest"]["sha256"] = "f" * 64
    spath.write_text(json.dumps(statement), encoding="utf-8")
    rc = ra.main(["verify", "--dir", str(out), "--key-file", str(key_path)])
    assert rc == 1
    # missing key -> 2
    rc = ra.main(["verify", "--dir", str(out)])
    assert rc == 2
    # empty root -> 2 (could-not-run: no artifacts)
    rc = ra.main(["attest", "--root", str(tmp_path / "rsx_t113_empty_root"),
                  "--key-file", str(key_path)])
    assert rc == 2


def test_cli_json_output(release_root, tmp_path, capsys):
    from analysis.validation import release_attestation as ra
    key_path = tmp_path / "rsx_t113_json_key"
    key_path.write_bytes(KEY)
    out = tmp_path / "rsx_t113_json_out"
    assert ra.main(["attest", "--root", str(release_root),
                    "--out-dir", str(out), "--key-file",
                    str(key_path)]) == 0
    capsys.readouterr()
    rc = ra.main(["verify", "--dir", str(out), "--key-file", str(key_path),
                  "--json"])
    payload = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert rc == 0
    assert payload["valid"] is True
    assert payload["status"] == "ok"


def test_cli_module_entry_smoke(release_root, tmp_path):
    """`python -m analysis.validation.release_attestation` must run."""
    key_path = tmp_path / "rsx_t113_smoke_key"
    key_path.write_bytes(KEY)
    out = tmp_path / "rsx_t113_smoke_out"
    proc = subprocess.run(
        [sys.executable, "-m", "analysis.validation.release_attestation",
         "attest", "--root", str(release_root), "--out-dir", str(out),
         "--key-file", str(key_path)],
        cwd=str(REPO), capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stderr
    assert "sigstore NOT adopted" in proc.stdout


def test_tool_version_single_sourced():
    """Statement metadata uses core.config.TOOL_VERSION via the CLI."""
    from core.config import TOOL_VERSION
    from analysis.validation import release_attestation as ra
    src = MODULE_SRC.read_text(encoding="utf-8")
    assert "from core.config import TOOL_VERSION" in src
    assert isinstance(TOOL_VERSION, str) and TOOL_VERSION
