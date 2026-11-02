"""T-9.18 SBOM of the scanner itself (task.md section 13).

Pins the self-SBOM pipeline:
* tools/emit_self_sbom.py builds a CycloneDX 1.5 document FROM THE
  REPO (pyproject.toml extras + build requires, rust/Cargo.toml direct
  deps resolved through Cargo.lock with their sha256 checksums, the
  Dockerfile base image) -- declared supply chain, offline, no network;
* the committed artifact supplychain/rsecopsx_sbom.json is verified
  by `--check` (byte-compare of a fresh generation, rc 0/1/2) so a
  dependency edit without a re-emit fails CI;
* ci_matrix runs that check as the 12th gate `self_sbom`;
* determinism by construction: NO metadata.timestamp, content-derived
  uuid5 serialNumber, sort_keys serialization, components sorted.
"""
from __future__ import annotations

import ast
import importlib.util
import json
import pathlib
import subprocess
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
TOOL_SRC = REPO / "tools" / "emit_self_sbom.py"
ARTIFACT = REPO / "supplychain" / "rsecopsx_sbom.json"
CI_SRC = REPO / "analysis" / "validation" / "ci_matrix.py"


def _tool_src() -> str:
    return TOOL_SRC.read_text(encoding="utf-8")


def _load_tool():
    """Import the tool module (scripts/ has no package)."""
    spec = importlib.util.spec_from_file_location(
        "rsx_emit_self_sbom", TOOL_SRC)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------- disclosure


def test_disclosure_needles_tool():
    src = _tool_src()
    needles = (
        "SBOM of the scanner itself (task.md section 13",
        "CycloneDX",
        "Cargo.lock",
        "metadata.timestamp",
        "offline",
        "rc 0/1/2",
    )
    for needle in needles:
        assert needle in src, "tool disclosure missing: %r" % needle


def test_tool_imports_are_stdlib_plus_core():
    # core only for the TOOL_VERSION single-source (t114 pattern).
    tree = ast.parse(_tool_src())
    allowed = {"__future__", "argparse", "json", "pathlib", "re", "sys",
               "tomllib", "uuid", "core"}
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                found.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                found.add(node.module.split(".")[0])
    assert found <= allowed, found - allowed


# ------------------------------------------------------------------ artifact


def _artifact() -> dict:
    return json.loads(ARTIFACT.read_text(encoding="utf-8"))


def test_artifact_is_valid_cyclonedx_shape():
    doc = _artifact()
    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] == "1.5"
    assert doc["version"] == 1
    assert doc["serialNumber"].startswith("urn:uuid:")
    meta = doc["metadata"]
    assert meta["component"]["name"] == "rsecopsx"
    from core.config import TOOL_VERSION
    assert meta["component"]["version"] == TOOL_VERSION
    assert doc["components"], "component inventory must not be empty"


def test_no_wall_clock_anywhere():
    # Determinism by construction: no timestamp/ageing keys anywhere in
    # the document (same pin as t113's signed payload).
    banned = {"timestamp", "generated", "generatedat", "created",
              "createdat", "date", "now", "time"}
    doc = _artifact()

    def walk(obj):
        if isinstance(obj, dict):
            for key, val in obj.items():
                assert str(key).lower() not in banned, key
                walk(val)
        elif isinstance(obj, list):
            for item in obj:
                walk(item)

    walk(doc)


def test_generation_is_byte_deterministic():
    mod = _load_tool()
    first = mod.render_document(mod.build_document(REPO))
    second = mod.render_document(mod.build_document(REPO))
    assert first == second, "two generations differ"
    committed = ARTIFACT.read_text(encoding="utf-8")
    assert first == committed, (
        "committed artifact drifted from a fresh generation "
        "-- re-run tools/emit_self_sbom.py")


def test_serial_is_content_derived():
    # serialNumber = uuid5 over the canonical sorted components payload:
    # content-bound, stable across runs, changes iff the inventory does.
    import uuid as _uuid
    mod = _load_tool()
    doc = json.loads(mod.render_document(mod.build_document(REPO)))
    payload = json.dumps(doc["components"], sort_keys=True)
    expect = "urn:uuid:" + str(
        _uuid.uuid5(_uuid.NAMESPACE_URL, "rsecopsx/self-sbom/" + payload))
    assert doc["serialNumber"] == expect


# ---------------------------------------------------------------- inventory


def test_component_inventory_pins():
    doc = _artifact()
    by_purl = {c.get("purl"): c for c in doc["components"]}
    for purl in (
        "pkg:pypi/setuptools",          # build-system.requires
        "pkg:pypi/PyYAML",              # optional extras
        "pkg:pypi/reportlab",
        "pkg:pypi/openpyxl",
        "pkg:cargo/regex",              # native engine direct dep
        "pkg:cargo/pyo3",
        "pkg:docker/python@3.14-slim-bookworm",  # Dockerfile FROM
    ):
        assert purl in by_purl, purl
    # scopes: build + native chain + base image required; enrichers optional
    assert by_purl["pkg:pypi/setuptools"]["scope"] == "required"
    assert by_purl["pkg:pypi/PyYAML"]["scope"] == "optional"
    assert by_purl["pkg:cargo/regex"]["scope"] == "required"
    # Cargo.lock resolution: regex carries an exact version + sha256
    regex = by_purl["pkg:cargo/regex"]
    assert regex["version"][0].isdigit(), regex["version"]
    hashes = regex.get("hashes") or []
    assert hashes and hashes[0]["alg"] == "SHA-256"
    assert len(hashes[0]["content"]) == 64
    # python components declare CONSTRAINTS (no lock by design: scan
    # mode has zero required runtime deps -- nothing to lock)
    assert by_purl["pkg:pypi/PyYAML"]["version"].startswith(">=")


def test_components_sorted():
    doc = _artifact()
    keys = [(c.get("name", ""), c.get("purl", "")) for c in doc["components"]]
    assert keys == sorted(keys), "components are not in the pinned order"


def test_cargo_lock_transitive_coverage():
    # The committed Cargo.lock is the actual supply chain the native
    # core compiles from; the SBOM must cover transitive crates too,
    # not just the direct table.
    import tomllib
    lock = tomllib.loads(
        (REPO / "rust" / "Cargo.lock").read_text(encoding="utf-8"))
    locked = {p["name"] for p in lock["package"]
              if p["name"] != "rsecopsx_core"}
    doc = _artifact()
    have = {c.get("name") for c in doc["components"]
            if str(c.get("purl", "")).startswith("pkg:cargo/")}
    missing = locked - have
    assert not missing, "Cargo.lock packages missing from SBOM: %s" % (
        sorted(missing)[:10],)


# ----------------------------------------------------------------- check CLI


def test_check_passes_fresh():
    proc = subprocess.run(
        [sys.executable, str(TOOL_SRC), "--check"],
        cwd=str(REPO), capture_output=True, text=True, encoding="utf-8",
        errors="replace", timeout=60)
    assert proc.returncode == 0, (proc.stdout[-1500:], proc.stderr[-1500:])


def test_check_fails_on_drift(tmp_path):
    drifted = tmp_path / "rsecopsx_sbom.json"
    doc = _artifact()
    doc["components"].pop()          # inventory shrinks -> must be caught
    drifted.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n",
                       encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, str(TOOL_SRC), "--check", "--path", str(drifted)],
        cwd=str(REPO), capture_output=True, text=True, encoding="utf-8",
        errors="replace", timeout=60)
    assert proc.returncode == 1, (proc.stdout[-1500:], proc.stderr[-1500:])


def test_missing_root_is_could_not_run(tmp_path):
    proc = subprocess.run(
        [sys.executable, str(TOOL_SRC), "--check", "--root", str(tmp_path)],
        cwd=str(REPO), capture_output=True, text=True, encoding="utf-8",
        errors="replace", timeout=60)
    assert proc.returncode == 2, (proc.stdout[-1500:], proc.stderr[-1500:])


# ------------------------------------------------------------ ci_matrix gate


def test_ci_matrix_self_sbom_gate_wired(monkeypatch):
    """The freshness check runs as the 12th matrix gate."""
    from analysis.validation import ci_matrix

    recorded: list[dict] = []

    def _recorder(name, cmd, timeout=300):
        recorded.append({"name": name, "cmd": list(cmd),
                         "timeout": timeout})
        return {"name": name, "exit_code": 0, "passed": True,
                "stdout_tail": "", "stderr_tail": ""}

    monkeypatch.setattr(ci_matrix, "_run", _recorder)
    ci_matrix.run_ci_matrix()

    names = [g["name"] for g in recorded]
    assert "self_sbom" in names, names
    # Still the 12th gate (0-based index 11). T-14.2 appended
    # dead_code_audit as gate 13 in its own batch, so "last" moved --
    # the append-order tuple pin lives in test_t117 EXPECTED_GATES
    # (baseline updated in the same commit per ground rules).
    assert names.index("self_sbom") == 11, names
    assert len(names) == 13, names
    gate = next(g for g in recorded if g["name"] == "self_sbom")
    assert gate["cmd"] == [
        sys.executable, str(REPO / "tools" / "emit_self_sbom.py"),
        "--check",
    ]
    assert gate["timeout"] == 60, gate["timeout"]
