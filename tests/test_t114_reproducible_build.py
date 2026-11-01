"""T-9.14 reproducible builds (task.md section 13).

Pins the in-house offline double-build gate: two independent child
processes must produce byte-identical wheels, the artifact must pass
self-consistency (RECORD digests, sorted entries, uniform
SOURCE_DATE_EPOCH timestamps, portable paths), METADATA must equal
pyproject.toml with the version single-sourced from core.config, and
the disclosure/exit-code contract must stay greppable.

The suite builds once (module-scoped fixture, two real children) and
reuses the kept wheel for the structural assertions -- total cost is
seconds, not minutes.
"""
from __future__ import annotations

import ast
import json
import pathlib
import subprocess
import sys
import zipfile

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
MODULE_SRC = REPO / "analysis" / "validation" / "reproducible_build.py"


def _src() -> str:
    return MODULE_SRC.read_text(encoding="utf-8")


# ---------------------------------------------------------------- disclosure


def test_disclosure_needles():
    src = _src()
    needles = (
        "reproducible builds (task.md section 13)",
        "byte-identical",
        "setuptools / the wheel package / ``python -m build`` "
        "(the PEP 517\npath pyproject.toml declares) are NOT adopted",
        "offline/airgap invariant",
        "named-tool precedent",
        "PEP 427 wheel writer",
        "Docker image reproducibility is NOT claimed",
        "EXIT CODES",
        "SOURCE_DATE_EPOCH",
        "single-sourced from\ncore.config.TOOL_VERSION",
    )
    for needle in needles:
        assert needle in src, "disclosure missing: %r" % needle


def test_imports_are_stdlib_only():
    tree = ast.parse(_src())
    allowed = {
        "__future__", "argparse", "base64", "fnmatch", "hashlib", "io",
        "json", "os", "pathlib", "shutil", "subprocess", "sys",
        "tempfile", "time", "tomllib", "zipfile",
        # in-repo, not third-party: the TOOL_VERSION single-source
        "core",
    }
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                found.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                found.add(node.module.split(".")[0])
    assert found <= allowed, found - allowed


# ------------------------------------------------------------------ constants


def test_env_and_epoch_pins():
    from analysis.validation import reproducible_build as rb
    assert rb.REPRO_ENV == {
        "PYTHONHASHSEED": "0",
        "TZ": "UTC",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    assert rb.ZIP_MIN_EPOCH == 315532800
    assert rb.DEFAULT_EPOCH == str(rb.ZIP_MIN_EPOCH)


def test_epoch_env_handling():
    from analysis.validation import reproducible_build as rb
    assert rb._epoch_from_env({"SOURCE_DATE_EPOCH": "0"}) == rb.ZIP_MIN_EPOCH
    assert rb._epoch_from_env({}) == rb.ZIP_MIN_EPOCH
    with pytest.raises(ValueError):
        rb._epoch_from_env({"SOURCE_DATE_EPOCH": "not-an-int"})
    with pytest.raises(ValueError):
        rb._epoch_from_env({"SOURCE_DATE_EPOCH": str(rb.ZIP_MAX_EPOCH + 1)})


# -------------------------------------------------------------- double build


@pytest.fixture(scope="module")
def built(tmp_path_factory):
    from analysis.validation import reproducible_build as rb
    out = tmp_path_factory.mktemp("rsx_t114_build")
    ok, info = rb.run_reproducible(REPO, out_dir=out)
    wheel1 = out / "a" / info["wheel"]
    return ok, info, wheel1


def test_double_build_byte_identical(built):
    ok, info, wheel1 = built
    assert info["identical"] is True, info
    assert info["sha256_build1"] == info["sha256_build2"]
    assert info["verified"] is True, (info["verify1"], info["verify2"])
    assert ok is True
    assert wheel1.is_file()


def test_wheel_name_and_version_single_sourced(built):
    from core.config import TOOL_VERSION
    from analysis.validation import reproducible_build as rb
    _, info, wheel1 = built
    assert wheel1.name == "rsecopsx-%s-py3-none-any.whl" % TOOL_VERSION
    assert info["version"] == TOOL_VERSION
    assert info["wheel"] == wheel1.name


def test_metadata_equals_pyproject(built):
    import tomllib
    from core.config import TOOL_VERSION
    _, _, wheel1 = built
    proj = tomllib.loads(
        (REPO / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    dist = "rsecopsx-%s.dist-info" % TOOL_VERSION
    with zipfile.ZipFile(wheel1) as zf:
        meta = zf.read(dist + "/METADATA").decode("utf-8")
    assert "Name: rsecopsx\n" in meta
    assert "Version: %s\n" % TOOL_VERSION in meta
    assert "Summary: %s\n" % proj["description"] in meta
    assert "Requires-Python: %s\n" % proj["requires-python"] in meta
    for extra in sorted(proj["optional-dependencies"]):
        assert "Provides-Extra: %s\n" % extra in meta
        for req in proj["optional-dependencies"][extra]:
            assert 'Requires-Dist: %s; extra == "%s"\n' % (req, extra) in meta


def test_entry_points_match_pyproject(built):
    import tomllib
    from core.config import TOOL_VERSION
    _, _, wheel1 = built
    proj = tomllib.loads(
        (REPO / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    dist = "rsecopsx-%s.dist-info" % TOOL_VERSION
    with zipfile.ZipFile(wheel1) as zf:
        text = zf.read(dist + "/entry_points.txt").decode("utf-8")
    for entry, target in proj["scripts"].items():
        assert "%s = %s\n" % (entry, target) in text


def test_wheel_layout_and_timestamps(built):
    from core.config import TOOL_VERSION
    _, _, wheel1 = built
    dist = "rsecopsx-%s.dist-info" % TOOL_VERSION
    with zipfile.ZipFile(wheel1) as zf:
        names = zf.namelist()
        assert names == sorted(names)
        assert zf.testzip() is None
        times = {i.date_time for i in zf.infolist()}
        assert len(times) == 1, times
        stamps = times.pop()
        assert stamps[:3] == (1980, 1, 1)  # default SOURCE_DATE_EPOCH
        for name in names:
            assert not name.startswith("/")
            assert "\\" not in name
            assert ":" not in name
            assert ".." not in name.split("/")
            top = name.split("/")[0]
            if "/" in name and not name.endswith(
                    ("METADATA", "WHEEL", "RECORD", "entry_points.txt")):
                # either a package module or dist-info content
                assert top in {"accuracy", "analysis", "core", "reporting",
                               "scanner", dist}, name
            assert not name.endswith((".pyc", ".pyo"))
            for banned in ("tests/", "data/", "dump/", "pyproject.toml",
                           "__pycache__"):
                assert banned not in name, name
        assert dist + "/RECORD" in names
        assert "main.py" in names


def test_record_digests_re_verify(built):
    # Independent recompute with hashlib/base64 directly -- NOT via the
    # module's _sha256_b64 (a mutated helper would stay self-consistent
    # between writer and verify_wheel; mutation M4 taught that).
    import base64
    import hashlib
    from core.config import TOOL_VERSION
    _, _, wheel1 = built
    dist = "rsecopsx-%s.dist-info" % TOOL_VERSION
    with zipfile.ZipFile(wheel1) as zf:
        record = zf.read(dist + "/RECORD").decode("utf-8")
        members = {n: zf.read(n) for n in zf.namelist()}
    for row in record.splitlines():
        arcname, spec, size = row.split(",")
        if arcname.endswith("/RECORD"):
            assert spec == "" and size == ""
            continue
        assert spec.startswith("sha256=")
        assert size.isdigit()
        expected = base64.urlsafe_b64encode(
            hashlib.sha256(members[arcname]).digest()
        ).rstrip(b"=").decode()
        assert spec[len("sha256="):] == expected, arcname
        assert int(size) == len(members[arcname]), arcname


def test_tampered_member_fails_verify(built, tmp_path):
    from analysis.validation import reproducible_build as rb
    _, _, wheel1 = built
    tampered = tmp_path / "rsx_t114_tampered.whl"
    with zipfile.ZipFile(wheel1) as src:
        with zipfile.ZipFile(tampered, "w") as dst:
            for info in src.infolist():
                data = src.read(info.filename)
                if info.filename.endswith("main.py"):
                    data += b"# tampered\n"
                dst.writestr(info, data)
    ok, why = rb.verify_wheel(tampered)
    assert ok is False
    assert "mismatch" in why, why


def test_missing_pyproject_raises(tmp_path):
    from analysis.validation import reproducible_build as rb
    with pytest.raises(ValueError):
        rb.build_wheel(tmp_path / "rsx_t114_absent", tmp_path / "x.whl")


# ---------------------------------------------------------------- synthetic tree


def _synthetic(root: pathlib.Path) -> pathlib.Path:
    (root / "core").mkdir(parents=True)
    (root / "README.md").write_text("# synth\n", encoding="utf-8")
    (root / "main.py").write_text("def main():\n    return 0\n",
                                  encoding="utf-8")
    (root / "core" / "__init__.py").write_text("", encoding="utf-8")
    (root / "core" / "config.py").write_text("TOOL_VERSION = 'v0.0-synth'\n",
                                             encoding="utf-8")
    (root / "pyproject.toml").write_text(
        '[project]\nname = "synth"\ndescription = "synth wheel"\n'
        'requires-python = ">=3.12"\nreadme = "README.md"\n'
        '[tool.setuptools.packages.find]\ninclude = ["core*"]\n',
        encoding="utf-8")
    return root


def test_package_dirs_derived_from_pyproject():
    from analysis.validation import reproducible_build as rb
    import tomllib
    data = tomllib.loads(
        (REPO / "pyproject.toml").read_text(encoding="utf-8"))
    dirs = rb._package_dirs(REPO, data)
    # order follows pyproject's declared include order (deterministic)
    assert dirs == ["core", "scanner", "analysis", "accuracy",
                    "reporting"], dirs
    # a vanished include pattern is a broken build, not a thin wheel
    with pytest.raises(ValueError):
        rb._package_dirs(REPO, {"tool": {"setuptools": {"packages":
            {"find": {"include": ["ghost*"]}}}}})
    with pytest.raises(ValueError):
        rb._package_dirs(REPO, {})


def test_synthetic_build_content_sensitive(tmp_path):
    from analysis.validation import reproducible_build as rb
    root = _synthetic(tmp_path / "rsx_t114_synth")
    sha1 = rb.build_wheel(root, tmp_path / "s1.whl")
    sha2 = rb.build_wheel(root, tmp_path / "s2.whl")
    assert sha1 == sha2  # same tree -> identical (in-process determinism)
    (root / "core" / "extra.py").write_text("X = 1\n", encoding="utf-8")
    sha3 = rb.build_wheel(root, tmp_path / "s3.whl")
    assert sha3 != sha1  # content change -> different artifact
    ok, why = rb.verify_wheel(tmp_path / "s3.whl")
    assert ok, why


def test_child_cli_on_synthetic_tree(tmp_path):
    """The hidden _one child runs standalone (rc 0 + prints sha256)."""
    root = _synthetic(tmp_path / "rsx_t114_child")
    out = tmp_path / "rsx_t114_child.whl"
    proc = subprocess.run(
        [sys.executable, "-m", "analysis.validation.reproducible_build",
         "_one", "--source", str(root), "--out", str(out)],
        cwd=str(REPO), capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stderr
    printed = proc.stdout.strip().splitlines()[-1]
    assert len(printed) == 64, printed
    assert out.is_file()


# ---------------------------------------------------------------------- CLI


def test_cli_exit_codes(capsys, tmp_path, monkeypatch):
    from analysis.validation import reproducible_build as rb
    # 0: real double build on this repo
    assert rb.main(["build", "--source", str(REPO)]) == 0
    out = capsys.readouterr().out
    assert "REPRODUCIBLE" in out
    assert "setuptools NOT adopted" in out
    # 2: no subcommand
    assert rb.main([]) == 2
    # 2: missing source tree
    assert rb.main(["build", "--source",
                    str(tmp_path / "rsx_t114_nope")]) == 2
    # 1: sha mismatch wiring
    fake = {
        "schema": rb.SCHEMA, "source": "x", "wheel": "w.whl",
        "version": "v0", "epoch": rb.ZIP_MIN_EPOCH,
        "sha256_build1": "a" * 64, "sha256_build2": "b" * 64,
        "identical": False, "verified": False,
        "verify1": "ok", "verify2": "ok", "kept_dir": None,
    }
    monkeypatch.setattr(rb, "run_reproducible",
                        lambda *a, **k: (False, fake))
    assert rb.main(["build"]) == 1
    out = capsys.readouterr().out
    assert "NOT REPRODUCIBLE" in out
    # 1: identical but invalid wheel wiring
    fake2 = dict(fake, identical=True, verified=False,
                 sha256_build2="a" * 64)
    monkeypatch.setattr(rb, "run_reproducible",
                        lambda *a, **k: (False, fake2))
    assert rb.main(["build"]) == 1
    out = capsys.readouterr().out
    assert "REPRODUCIBLE BUT INVALID WHEEL" in out


def test_cli_json_output(capsys):
    from analysis.validation import reproducible_build as rb
    rc = rb.main(["build", "--source", str(REPO), "--json"])
    payload = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert rc == 0
    assert payload["identical"] is True
    assert payload["verified"] is True
    assert payload["schema"] == rb.SCHEMA


def test_cli_module_entry_smoke():
    """`python -m analysis.validation.reproducible_build build` runs."""
    proc = subprocess.run(
        [sys.executable, "-m", "analysis.validation.reproducible_build",
         "build", "--json"],
        cwd=str(REPO), capture_output=True, text=True, timeout=300)
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout.strip().splitlines()[-1])
    assert payload["identical"] is True


def test_tool_version_single_sourced():
    from core.config import TOOL_VERSION
    assert "from core.config import TOOL_VERSION" in _src()
    assert isinstance(TOOL_VERSION, str) and TOOL_VERSION
