"""T-9.19 container image scanning (task.md section 13, last §13 item).

Pins the image-scanning surface:
* scanner/image_scan.py evaluates a REAL container image -- config
  posture from `docker image inspect` or from a `docker save` tarball
  (manifest.json + config blob + layers, docker compat format), plus
  layer content rules (secret file paths, private-key material bounded
  to a 4 MiB read per member);
* NEVER pulls: a missing local image is a could-not-run (rc 2), never
  a registry fetch -- offline invariant;
* main.py gains --image-ref / --image-tar (both default off, so a
  default run does zero image work) and merges the findings into the
  normal verdict pipeline;
* NOT ADOPTED: trivy/grype class scanners (no CVE feed offline).

Tests: disclosure needles, stdlib-only import whitelist, the rules
registry (ids + severities + sensitive-port parity with iac_docker),
good/bad config controls, layer path + bounded content rules, the
tar end-to-end path, inspect normalization, CLI rc 0/2, main.py
wiring pins, and a live daemon probe (skips without docker).
"""
from __future__ import annotations

import ast
import json
import pathlib
import subprocess
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
ENGINE = REPO / "scanner" / "image_scan.py"
MAIN_SRC = REPO / "main.py"

#: The nine rule ids, in registry order.  Severities are pinned too:
#: a severity quietly downgraded is an accuracy change, not a refactor.
EXPECTED_RULES = {
    "IMAGE_RUNS_AS_ROOT": "High",
    "IMAGE_LATEST_TAG": "Medium",
    "IMAGE_UNTAGGED": "Medium",
    "IMAGE_DIGEST_UNPINNED": "Low",
    "IMAGE_ENV_SECRET": "Critical",
    "IMAGE_EXPOSE_SENSITIVE_PORT": "Medium",
    "IMAGE_MISSING_HEALTHCHECK": "Low",
    "IMAGE_LAYER_SECRET_PATH": "High",
    "IMAGE_LAYER_PRIVATE_KEY": "Critical",
}

#: Parity with scanner/iac_docker.py DOCKER_EXPOSE_SENSITIVE_PORT.
SENSITIVE_PORTS = frozenset(
    {"22", "2375", "2376", "3306", "5432", "6379", "27017", "9200"})

# Assembled at runtime so the test source itself carries no complete
# private-key literal (repo self-scan stays clean).
_PEM = "-----BEGIN " + "RSA PRIVATE KEY-----\n" + (
    "bW9jay1rZXktbWF0ZXJpYWwtcnN4X3QxMTlfZml4dHVyZQ==\n") + (
    "-----END " + "RSA PRIVATE KEY-----\n")


def _engine_src() -> str:
    return ENGINE.read_text(encoding="utf-8")


def _load_engine():
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "rsx_image_scan", ENGINE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------- disclosure


def test_disclosure_needles():
    src = _engine_src()
    needles = (
        "container image scanning (task.md section 13",
        "NOT ADOPTED",
        "trivy",
        "grype",
        "never pull",
        "docker save",
        "4 MiB",
        "could-not-run",
    )
    for needle in needles:
        assert needle in src, "engine disclosure missing: %r" % needle


def test_engine_never_pulls():
    # Functional offline invariant: the source may inspect/save/load
    # local state but must never contain a pull command -- in either
    # bare ("docker pull") or argv-array ('"pull"') spelling.
    src = _engine_src()
    assert "docker pull" not in src
    assert '"pull"' not in src, "argv-form pull found in engine source"


def test_engine_imports_are_stdlib_only():
    tree = ast.parse(_engine_src())
    allowed = {"__future__", "argparse", "json", "pathlib", "re",
               "subprocess", "sys", "tarfile", "typing"}
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                found.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                found.add(node.module.split(".")[0])
    assert found <= allowed, found - allowed


# ------------------------------------------------------------------- rules


def test_rules_registry_pinned():
    mod = _load_engine()
    got = {r["rule_id"]: r["severity"] for r in mod.RULES}
    assert got == EXPECTED_RULES, got
    port_rule = next(r for r in mod.RULES
                     if r["rule_id"] == "IMAGE_EXPOSE_SENSITIVE_PORT")
    assert frozenset(port_rule["ports"]) == SENSITIVE_PORTS, (
        port_rule["ports"])


# ------------------------------------------------------------------ config


def _meta(**over):
    meta = {
        "user": "10001:10001",
        "env": ["PATH=/usr/bin", "PYTHONUNBUFFERED=1"],
        "exposed": {"8080/tcp": {}},
        "healthcheck": {"test": ["CMD", "true"]},
        "tags": ["demo:0.1.0"],
        "digests": ["demo@sha256:" + "a" * 64],
    }
    meta.update(over)
    return meta


def test_good_config_yields_no_findings():
    mod = _load_engine()
    findings = mod.findings_from_config(_meta(), source="docker://demo:0.1.0")
    assert findings == [], [f["rule_id"] for f in findings]


def test_bad_config_findings_and_severities():
    mod = _load_engine()
    meta = _meta(
        user="",                                   # root
        env=["PATH=/bin", "API_KEY=rsx_t119_dummy_value"],
        exposed={"22/tcp": {}, "8080/tcp": {}},    # ssh
        healthcheck=None,                          # missing
        tags=["demo:latest"],                      # mutable
        digests=[],                                # unpinned
    )
    findings = mod.findings_from_config(meta, source="docker://demo:latest")
    got = {f["rule_id"]: f["severity"] for f in findings}
    assert got == {
        "IMAGE_RUNS_AS_ROOT": "High",
        "IMAGE_LATEST_TAG": "Medium",
        "IMAGE_DIGEST_UNPINNED": "Low",
        "IMAGE_ENV_SECRET": "Critical",
        "IMAGE_EXPOSE_SENSITIVE_PORT": "Medium",
        "IMAGE_MISSING_HEALTHCHECK": "Low",
    }, got
    # every finding carries the iac-docker key contract
    for f in findings:
        for key in ("title", "rule_id", "category", "severity", "priority",
                    "file", "line", "evidence", "description", "remediation",
                    "cwe", "framework", "control", "detection"):
            assert key in f, (f["rule_id"], key)


def test_untagged_image_rule():
    mod = _load_engine()
    findings = mod.findings_from_config(_meta(tags=[], digests=[]),
                                        source="docker://demo")
    ids = {f["rule_id"] for f in findings}
    assert "IMAGE_UNTAGGED" in ids, ids
    assert "IMAGE_LATEST_TAG" not in ids, ids


def test_explicit_root_username_variants():
    # The empty-User branch and the named-root branch are different
    # code paths (M24 proved the named one was unpinned): "root",
    # "root:root" and "0" must all fire IMAGE_RUNS_AS_ROOT.
    mod = _load_engine()
    for user in ("root", "root:root", "0", "0:0"):
        findings = mod.findings_from_config(_meta(user=user),
                                            source="docker://demo")
        ids = {f["rule_id"] for f in findings}
        assert "IMAGE_RUNS_AS_ROOT" in ids, (user, ids)
    clean = mod.findings_from_config(_meta(user="10001:10001"),
                                     source="docker://demo")
    assert "IMAGE_RUNS_AS_ROOT" not in {f["rule_id"] for f in clean}


def test_scan_image_ref_inspect_path(monkeypatch):
    # Hermetic pin of the daemon path: the argv must be
    # `docker image inspect` (never pull), and the inspect JSON must
    # normalize into the config-meta contract.
    import subprocess as _sp

    mod = _load_engine()
    recorded: list[list] = []

    class _Proc:
        returncode = 0
        stderr = ""
        stdout = json.dumps([{
            "Config": {
                "User": "root",
                "Env": ["API_KEY=rsx_t119_dummy_value"],
                "ExposedPorts": {"3306/tcp": {}},
                "Healthcheck": None,
            },
            "RepoTags": ["demo:latest"],
            "RepoDigests": [],
        }])

    def _fake_run(cmd, **kwargs):
        recorded.append(list(cmd))
        return _Proc()

    monkeypatch.setattr(_sp, "run", _fake_run)
    findings = mod.scan_image_ref("demo:latest")
    assert recorded == [["docker", "image", "inspect", "demo:latest"]], (
        recorded)
    ids = {f["rule_id"] for f in findings}
    assert ids == {
        "IMAGE_RUNS_AS_ROOT", "IMAGE_LATEST_TAG",
        "IMAGE_DIGEST_UNPINNED", "IMAGE_ENV_SECRET",
        "IMAGE_EXPOSE_SENSITIVE_PORT", "IMAGE_MISSING_HEALTHCHECK",
    }, ids
    assert all(f["file"] == "docker://demo:latest" for f in findings)

    # missing image -> could-not-run, with the never-pulls promise
    class _Missing(_Proc):
        returncode = 1
        stdout = "[]"
        stderr = "Error: No such image: ghost:rsx_t119"

    monkeypatch.setattr(_sp, "run", lambda cmd, **kw: _Missing())
    with pytest.raises(mod.ImageScanError) as excinfo:
        mod.scan_image_ref("ghost:rsx_t119")
    msg = str(excinfo.value)
    assert "could-not-run" in msg, msg
    assert "never pulls" in msg, msg


# ------------------------------------------------------------------ layers


def test_layer_secret_paths_and_public_cert_control():
    mod = _load_engine()
    members = {
        "app/id_rsa": b"not-really-a-key",
        "app/.env": b"PASSWORD=rsx_t119_dummy",
        "etc/ssl/certs/ca.pem": b"-----BEGIN CERTIFICATE-----\nMIIB\n",
        "usr/bin/app": b"#!/bin/sh\necho ok\n",
    }
    findings = mod.findings_from_layer(members, source="docker://demo")
    paths = {f["evidence"] for f in findings
             if f["rule_id"] == "IMAGE_LAYER_SECRET_PATH"}
    assert paths == {"app/id_rsa", "app/.env"}, paths
    ids = {f["rule_id"] for f in findings}
    assert ids == {"IMAGE_LAYER_SECRET_PATH"}, ids  # ca.pem NOT a secret


def test_layer_private_key_content_and_mib_bound():
    mod = _load_engine()
    members = {
        "app/server.key": _PEM.encode("utf-8"),
        # needle parked past the 4 MiB read bound: must NOT be seen
        "big/payload.bin": b"x" * (5 * 1024 * 1024)
                           + _PEM.encode("utf-8"),
    }
    findings = mod.findings_from_layer(members, source="docker://demo")
    keyed = [f for f in findings
             if f["rule_id"] == "IMAGE_LAYER_PRIVATE_KEY"]
    assert len(keyed) == 1, [f["evidence"] for f in keyed]
    assert keyed[0]["evidence"] == "app/server.key", keyed[0]["evidence"]
    assert not any(f["evidence"] == "big/payload.bin" for f in findings), (
        "content scan must stop at the 4 MiB bound")


# --------------------------------------------------------------- tar path


def _write_image_tar(tmp_path, *, bad=False) -> pathlib.Path:
    """Build a docker-save style tar (manifest.json + config + layers)."""
    import gzip
    import io
    import tarfile

    if bad:
        config = {
            "config": {
                "User": "",
                "Env": ["API_KEY=rsx_t119_dummy_value"],
                "ExposedPorts": {"22/tcp": {}},
                "Healthcheck": None,
            },
        }
        layer_payload = b"app/.env=" + b"rsx_t119_dummy"
    else:
        config = {
            "config": {
                "User": "10001:10001",
                "Env": ["PATH=/bin"],
                "ExposedPorts": {"8080/tcp": {}},
                "Healthcheck": {"test": ["CMD", "true"]},
            },
        }
        layer_payload = b"usr/bin/app=ok"

    layer_buf = io.BytesIO()
    with tarfile.open(fileobj=layer_buf, mode="w") as lt:
        for name, data in [
            ("app/.env" if bad else "usr/bin/app", layer_payload),
            ("app/id_rsa" if bad else "usr/lib/ok.txt",
             b"rsx_t119_dummy" if bad else b"fine"),
        ]:
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            lt.addfile(ti, io.BytesIO(data))

    manifest = json.dumps([{
        "Config": "config.json",
        "RepoTags": ["demo:latest" if bad else "demo:0.1.0"],
        "Layers": ["layer.tar"],
    }]).encode("utf-8")
    cfg_bytes = json.dumps(config).encode("utf-8")
    layer_bytes = gzip.compress(layer_buf.getvalue())

    out = tmp_path / "image.tar"
    with tarfile.open(out, mode="w") as ot:
        for name, data in [("manifest.json", manifest),
                           ("config.json", cfg_bytes),
                           ("layer.tar", layer_bytes)]:
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            ot.addfile(ti, io.BytesIO(data))
    return out


def test_scan_image_tar_end_to_end(tmp_path):
    mod = _load_engine()
    bad = _write_image_tar(tmp_path, bad=True)
    findings = mod.scan_image_tar(str(bad))
    ids = {f["rule_id"] for f in findings}
    assert "IMAGE_RUNS_AS_ROOT" in ids, ids
    assert "IMAGE_ENV_SECRET" in ids, ids
    assert "IMAGE_LAYER_SECRET_PATH" in ids, ids
    # source label flows into the finding file field
    assert all(f["file"] for f in findings), findings[:1]


def test_scan_image_tar_good_image_is_clean(tmp_path):
    mod = _load_engine()
    good = _write_image_tar(tmp_path, bad=False)
    findings = mod.scan_image_tar(str(good))
    assert findings == [], [f["rule_id"] for f in findings]


# -------------------------------------------------------------------- CLI


def test_cli_tar_scan_exit_0(tmp_path):
    tar_path = _write_image_tar(tmp_path, bad=True)
    proc = subprocess.run(
        [sys.executable, str(ENGINE), "--image-tar", str(tar_path),
         "--json"],
        cwd=str(REPO), capture_output=True, text=True, encoding="utf-8",
        errors="replace", timeout=60)
    assert proc.returncode == 0, (proc.stdout[-1500:], proc.stderr[-1500:])
    payload = json.loads(proc.stdout)
    assert payload["findings"], payload
    assert payload["source"] == str(tar_path), payload.get("source")


def test_cli_missing_tar_is_could_not_run(tmp_path):
    proc = subprocess.run(
        [sys.executable, str(ENGINE),
         "--image-tar", str(tmp_path / "absent.tar"), "--json"],
        cwd=str(REPO), capture_output=True, text=True, encoding="utf-8",
        errors="replace", timeout=60)
    assert proc.returncode == 2, (proc.stdout[-1500:], proc.stderr[-1500:])
    assert "could-not-run" in (proc.stdout + proc.stderr), (
        proc.stdout + proc.stderr)


# ------------------------------------------------------------- main.py pin


def test_main_py_wiring():
    src = MAIN_SRC.read_text(encoding="utf-8")
    for needle in (
        '"--image-ref"',
        '"--image-tar"',
        "from scanner.image_scan import scan_images",
        "raw.extend(image_findings)",
        "T-9.19 container image scanning",
    ):
        assert needle in src, "main.py wiring missing: %r" % needle
    # default-off: the help text must promise no pull
    assert "never pulls" in src or "never pull" in src, (
        "offline promise missing from --image-ref help")


# -------------------------------------------------------- verdict pipeline


def test_image_findings_survive_the_verdict_pipeline():
    """The live wiring measured every image finding REJECTED_FALSE_POSITIVE
    before this batch's two engine-layer fixes: line 0 is legal only for
    SCA/SBOM claims (ufib G1), and the SECRET/KEY rule-id tokens routed
    posture claims into the hardcoded_secret value-evidence contract they
    never made.  An image posture finding must instead resolve to the SAME
    category its Dockerfile twin DOCKER_SECRET_IN_ENV uses
    (iac_misconfiguration), pass G1-G3, and land release-eligible as LIKELY
    -- declared config is the evidence, runtime context is unverifiable
    from a docker:// source, hence LIKELY, never CONFIRMED, never REJECTED.
    """
    from analysis.ufib_brain import evaluate_finding
    from analysis.ufib_contracts import resolve_category

    mod = _load_engine()
    config = _meta(user="",
                   env=["PATH=/bin", "API_KEY=rsx_t119_dummy_value"],
                   exposed={"22/tcp": {}, "8080/tcp": {}},
                   healthcheck=None, tags=["demo:latest"], digests=[])
    members = {
        "app/server.key": _PEM.encode("utf-8"),
        "app/.env": b"PASSWORD=rsx_t119_dummy",
    }
    findings = mod.findings_from_config(config, source="docker://demo:latest")
    findings += mod.findings_from_layer(members, source="docker://demo:latest")
    assert len(findings) == 8, [f["rule_id"] for f in findings]
    for f in findings:
        assert f["rule_id"] in EXPECTED_RULES, f["rule_id"]
        assert resolve_category(f) == "iac_misconfiguration", (
            f["rule_id"], resolve_category(f))
        assert f["line"] >= 1, (f["rule_id"], f["line"])
        disposition = evaluate_finding(f, target=".")
        g1 = next(g for g in f["ufib"]["gates"] if g["gate"] == "G1")
        assert g1["result"] == "PASS", (f["rule_id"], g1)
        # declared config is the evidence: STRONG, same as DOCKER_* twins
        assert f["ufib"]["claim_strength"] == "STRONG", (
            f["rule_id"], f["ufib"]["claim_strength"])
        assert disposition == "LIKELY", (
            f["rule_id"], disposition,
            f["ufib"].get("disposition_rationale"))
        assert f["release_eligible"] is True, f["rule_id"]


# ------------------------------------------------------------ live daemon


def test_live_docker_scan_of_own_image():
    """Probe the local daemon: our own image must scan through the
    inspect path with every finding in the pinned registry.  Skips
    when docker or the image is absent (fresh clone / no daemon)."""
    docker = _which_docker()
    if not docker:
        pytest.skip("docker not on PATH")
    probe = subprocess.run(
        [docker, "image", "inspect", "rsecopsx/api:0.1.0"],
        capture_output=True, timeout=60)
    if probe.returncode != 0:
        pytest.skip("rsecopsx/api:0.1.0 not present locally")
    mod = _load_engine()
    findings = mod.findings_from_config(
        _config_from_inspect(json.loads(probe.stdout.decode("utf-8"))[0]),
        source="docker://rsecopsx/api:0.1.0")
    ids = {f["rule_id"] for f in findings}
    unknown = ids - set(EXPECTED_RULES)
    assert not unknown, unknown
    # our own image is pinned non-root with no env secrets (t99 contract)
    assert "IMAGE_RUNS_AS_ROOT" not in ids, ids
    assert "IMAGE_ENV_SECRET" not in ids, ids


def _which_docker():
    import shutil
    return shutil.which("docker")


def _config_from_inspect(inspect_obj: dict) -> dict:
    cfg = inspect_obj.get("Config") or {}
    return {
        "user": cfg.get("User"),
        "env": cfg.get("Env") or [],
        "exposed": cfg.get("ExposedPorts") or {},
        "healthcheck": cfg.get("Healthcheck"),
        "tags": inspect_obj.get("RepoTags") or [],
        "digests": inspect_obj.get("RepoDigests") or [],
    }
