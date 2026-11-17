"""CycloneDX 1.6 offline schema validation — deterministic regression hardening.

Authorization: "CycloneDX 1.6 — Offline Schema Validation Remediation"
(2026-11-17).  Context: audit_output/B1_SKIP_PROMOTION_INVESTIGATION.md
(network-dependent conformance checks) and the B-1 integration regression
skip-count deviation.

Pre-fix behavior of ``_cyclonedx_schema_check`` for version 1.6: a live
``requests.get`` against raw.githubusercontent.com on every call (10 s
timeout).  Network failure returned ``{"valid": False, "errors": ["schema
fetch failed: ..."]}`` (the affected tests FAIL); import failure of
requests/jsonschema produced a result without ``"valid"`` (the affected
tests SKIP).  Either way validation depended on external state.

Remediated contract pinned here:
- 1.6 validates OFFLINE against the vendored, SHA-256-pinned schema
  (schemas/cyclonedx/1.6/ + MANIFEST.json); zero HTTP attempts.
- Integrity or presence failures fail explicitly (never silent, never a
  network fallback, never unverified content).
- The loaded schema is exactly CycloneDX 1.6 ($id pinned); its external
  $refs (spdx.schema.json, jsf-0.82.schema.json) resolve offline.
- Validation semantics are unchanged: previously-valid documents validate,
  previously-invalid documents fail with an error list.
"""

import copy
import json
from pathlib import Path

import pytest

from analysis.validation import sbom_conformance as sc

REPO = Path(__file__).resolve().parent.parent
VENDORED = REPO / "schemas" / "cyclonedx" / "1.6"


def _valid_doc():
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "timestamp": "2026-01-01T00:00:00Z",
            "component": {"type": "application", "name": "t", "version": "1"},
        },
        "components": [{"type": "library", "name": "x", "version": "1"}],
    }


def _invalid_doc():
    doc = _valid_doc()
    doc["components"][0]["type"] = "not-a-cyclonedx-component-type"
    return doc


def _spdx_doc():
    """Valid document exercising the vendored spdx license-id reference."""
    doc = _valid_doc()
    doc["components"][0]["licenses"] = [{"license": {"id": "Apache-2.0"}}]
    return doc


def _jsf_doc():
    """Valid document exercising the vendored jsf signature reference
    (URI-form proprietary algorithm per the jsf schema)."""
    doc = _valid_doc()
    doc["signature"] = {"algorithm": "https://example.com/proprietary-algo",
                        "value": "c2ln"}
    return doc


EXTERNAL_REFS = {"spdx.schema.json",
                 "jsf-0.82.schema.json#/definitions/signature"}
RESOURCE_IDS = {"http://cyclonedx.org/schema/spdx.schema.json",
                "http://cyclonedx.org/schema/jsf-0.82.schema.json"}


def _external_refs(schema):
    refs = []

    def walk(node):
        if isinstance(node, dict):
            for k, v in node.items():
                if k == "$ref" and isinstance(v, str):
                    refs.append(v)
                else:
                    walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)

    walk(schema)
    return {r for r in refs if not r.startswith("#")}


class _NetworkGuard:
    """Block the requests layer and record every attempted call."""

    def __init__(self):
        self.attempts = []

    def __enter__(self):
        import requests
        self._requests = requests
        self._saved = (requests.get, requests.Session.request,
                       requests.Session.send)

        def _blocked(name):
            def _fn(*args, **kwargs):
                self.attempts.append(name)
                raise requests.ConnectionError(
                    "network disabled by offline test")
            return _fn

        requests.get = _blocked("requests.get")
        requests.Session.request = _blocked("Session.request")
        requests.Session.send = _blocked("Session.send")
        return self

    def __exit__(self, *exc):
        (self._requests.get, self._requests.Session.request,
         self._requests.Session.send) = self._saved
        return False


# ---------------------------------------------------------------------------
# A/E. Offline success + network independence
# ---------------------------------------------------------------------------

def test_16_validates_offline_with_zero_http_attempts():
    with _NetworkGuard() as guard:
        results = sc._cyclonedx_schema_check(_valid_doc(),
                                             target_versions=("1.6",))
    entry = results.get("1.6", {})
    assert entry.get("valid") is True, entry
    assert entry.get("errors") == []
    assert guard.attempts == [], f"HTTP attempted offline: {guard.attempts}"


def test_16_dns_failure_causes_no_skip_and_no_failure():
    # DNS/network failure must not degrade 1.6 validation at all: the
    # result must be a definitive verdict (never a skip-shaped missing
    # "valid" key, never a fetch-failure error).
    with _NetworkGuard() as guard:
        results = sc._cyclonedx_schema_check(_valid_doc(),
                                             target_versions=("1.6",))
    entry = results.get("1.6", {})
    assert "valid" in entry, f"skip-shaped result on network failure: {entry}"
    assert entry["valid"] is True, entry
    assert guard.attempts == []


# ---------------------------------------------------------------------------
# B. Integrity verification
# ---------------------------------------------------------------------------

def test_tampered_schema_content_is_rejected(tmp_path, monkeypatch):
    import shutil
    target = tmp_path / "1.6"
    shutil.copytree(VENDORED, target)
    schema_path = target / "schema.json"
    data = schema_path.read_bytes()
    schema_path.write_bytes(data.replace(b'"bomFormat"', b'"bomFormatX"', 1))
    monkeypatch.setattr(sc, "_VENDORED_SCHEMA_DIR", target, raising=False)
    with _NetworkGuard() as guard:
        results = sc._cyclonedx_schema_check(_valid_doc(),
                                             target_versions=("1.6",))
    entry = results.get("1.6", {})
    assert entry.get("valid") is False, entry
    assert any("integrity failure" in e for e in entry.get("errors", [])), entry
    assert guard.attempts == [], "integrity failure must not fall back to network"


def test_missing_vendored_schema_fails_explicitly(tmp_path, monkeypatch):
    monkeypatch.setattr(sc, "_VENDORED_SCHEMA_DIR", tmp_path, raising=False)
    with _NetworkGuard() as guard:
        results = sc._cyclonedx_schema_check(_valid_doc(),
                                             target_versions=("1.6",))
    entry = results.get("1.6", {})
    assert "valid" in entry, f"must fail explicitly, not skip: {entry}"
    assert entry["valid"] is False
    assert any("vendored schema missing" in e
               for e in entry.get("errors", [])), entry
    assert guard.attempts == []


# ---------------------------------------------------------------------------
# C. Schema identity + offline external refs
# ---------------------------------------------------------------------------

def test_loaded_schema_is_exactly_cyclonedx_16():
    manifest = json.loads((VENDORED / "MANIFEST.json").read_text(
        encoding="utf-8"))
    assert manifest["schema_version"] == "1.6"
    assert manifest["canonical_id"] == \
        "http://cyclonedx.org/schema/bom-1.6.schema.json"
    loaded = sc._load_vendored_schema_16()
    assert loaded["schema"]["$id"] == \
        "http://cyclonedx.org/schema/bom-1.6.schema.json"
    assert loaded["schema"]["$schema"].startswith(
        "http://json-schema.org/draft-07")
    # no fallback to another version: the only resources are the two
    # vendored $ref targets, both 1.6-ecosystem files
    assert sorted(loaded["resources"]) == [
        "http://cyclonedx.org/schema/jsf-0.82.schema.json",
        "http://cyclonedx.org/schema/spdx.schema.json",
    ]


def test_external_refs_resolve_offline():
    # Force traversal of the vendored $ref branches (spdx licenseChoice +
    # jsf signature) with the network blocked; a malformed signature must
    # produce a definitive validation error naming the signature path --
    # proof the refs resolved locally.
    doc = _valid_doc()
    doc["components"][0]["licenses"] = [{"expression": "Apache-2.0"}]
    doc["signature"] = {"algorithm": "not-a-real-jsf-algorithm"}
    with _NetworkGuard() as guard:
        results = sc._cyclonedx_schema_check(doc, target_versions=("1.6",))
    entry = results.get("1.6", {})
    assert "valid" in entry, entry
    assert entry["valid"] is False, entry
    assert entry.get("errors"), entry
    # F-CDX16-R2 strengthening: the error must come from evaluating the
    # vendored jsf schema, not from a failed reference lookup -- an
    # unresolvable ref names its target ("Unresolvable: ...") and a
    # silently-skipped ref would validate the document as True.
    assert not any("Unresolvable" in e for e in entry["errors"]), entry
    assert any("is not valid under any of the given schemas" in e
               for e in entry["errors"]), entry
    assert guard.attempts == []


# ---------------------------------------------------------------------------
# D. Validation semantics preserved
# ---------------------------------------------------------------------------

def test_previously_valid_document_remains_valid():
    with _NetworkGuard():
        entry = sc._cyclonedx_schema_check(_valid_doc(),
                                           target_versions=("1.6",))["1.6"]
    assert entry["valid"] is True, entry


def test_previously_invalid_document_remains_invalid_with_errors():
    with _NetworkGuard():
        entry = sc._cyclonedx_schema_check(_invalid_doc(),
                                           target_versions=("1.6",))["1.6"]
    assert entry["valid"] is False, entry
    assert entry["errors"] and all(isinstance(e, str) for e in entry["errors"])


# ---------------------------------------------------------------------------
# E. DEV-1 regression guard: checkout-stable fixture bytes
# ---------------------------------------------------------------------------

def test_schema_fixture_checkout_bytes_and_attributes():
    """DEV-1: on-disk schema bytes must match the manifest pins, and
    .gitattributes must keep the fixture immune to EOL conversion
    (``schemas/** -text``).  Without the attribute rule a Windows
    checkout with core.autocrlf=true smudges LF to CRLF and the loader
    correctly rejects the changed bytes -- while the original worktree
    stays green (it holds LF), hiding the regression.  This guard fails
    wherever it runs if the rule is removed or the bytes drift.
    """
    import hashlib
    import subprocess
    manifest = json.loads((VENDORED / "MANIFEST.json").read_text(
        encoding="utf-8"))
    names = sorted(manifest["files"])
    for name in names:
        data = (VENDORED / name).read_bytes()
        assert hashlib.sha256(data).hexdigest() == \
            manifest["files"][name]["sha256"], name
    try:
        out = subprocess.run(
            ["git", "check-attr", "text", "--"] +
            [str(VENDORED / n) for n in names],
            capture_output=True, text=True, cwd=str(REPO), timeout=30)
    except (OSError, subprocess.SubprocessError):
        pytest.skip("git not available for attribute check")
    if out.returncode != 0:
        pytest.skip("git check-attr failed: %s" % out.stderr[:200])
    for line in out.stdout.splitlines():
        assert line.endswith(": text: unset"), line


# ---------------------------------------------------------------------------
# F. F-CDX16-R2/R3 test-quality remediation
# ---------------------------------------------------------------------------

def test_external_ref_inventory_and_local_resolution():
    """F-CDX16-R2: the bom schema's external $ref entries must be exactly
    the two vendored targets, each mapped to its intended local resource,
    and both must resolve through the real loader/validator path.  The
    positive verdicts below are only reachable when the referenced
    resources are dereferenced: an unresolvable or silently-skipped ref
    yields valid=False (see test_unresolved_external_ref_fails_explicitly
    and the red-first sabotage evidence)."""
    loaded = sc._load_vendored_schema_16()
    assert _external_refs(loaded["schema"]) == EXTERNAL_REFS
    assert set(loaded["resources"]) == RESOURCE_IDS
    with _NetworkGuard() as guard:
        spdx = sc._cyclonedx_schema_check(_spdx_doc(),
                                          target_versions=("1.6",))["1.6"]
        jsf = sc._cyclonedx_schema_check(_jsf_doc(),
                                         target_versions=("1.6",))["1.6"]
    assert spdx["valid"] is True, spdx
    assert spdx.get("errors") == [], spdx
    assert jsf["valid"] is True, jsf
    assert jsf.get("errors") == [], jsf
    assert guard.attempts == []


def test_unresolved_external_ref_fails_explicitly(tmp_path, monkeypatch):
    """F-CDX16-R2: retargeting an external $ref to a nonexistent file must
    fail validation explicitly.  The exercising document is schema-valid
    when both references resolve, so a resolver that silently skipped
    unresolved references would return valid=True and fail this test."""
    import hashlib
    import shutil
    target = tmp_path / "1.6"
    shutil.copytree(VENDORED, target)
    schema_path = target / "schema.json"
    raw = schema_path.read_bytes()
    tampered = raw.replace(
        b'"jsf-0.82.schema.json#/definitions/signature"',
        b'"nonexistent.schema.json#/definitions/signature"', 1)
    assert tampered != raw, "expected external ref not found in schema"
    schema_path.write_bytes(tampered)
    mpath = target / "MANIFEST.json"
    manifest = json.loads(mpath.read_text(encoding="utf-8"))
    manifest["files"]["schema.json"]["sha256"] = \
        hashlib.sha256(tampered).hexdigest()
    mpath.write_text(json.dumps(manifest), encoding="utf-8")
    monkeypatch.setattr(sc, "_VENDORED_SCHEMA_DIR", target, raising=False)
    doc = _jsf_doc()
    doc["components"][0]["licenses"] = [{"license": {"id": "Apache-2.0"}}]
    with _NetworkGuard() as guard:
        entry = sc._cyclonedx_schema_check(doc,
                                           target_versions=("1.6",))["1.6"]
    assert "valid" in entry, entry
    assert entry["valid"] is False, entry
    assert any("nonexistent.schema.json" in e
               for e in entry.get("errors", [])), entry
    assert guard.attempts == []


def test_wrong_schema_id_is_rejected_by_loader(tmp_path, monkeypatch):
    """F-CDX16-R3: the production loader must reject a schema whose $id is
    not the pinned identity -- explicit ``schema identity failure``, no
    fallback, no silent acceptance or substitution.  The tampered copy's
    manifest hash is updated so the SHA-256 gate passes and the $id check
    is the rejecting authority.  Fails if the loader accepts the
    incorrect $id."""
    import hashlib
    import shutil
    target = tmp_path / "1.6"
    shutil.copytree(VENDORED, target)
    schema_path = target / "schema.json"
    raw = schema_path.read_bytes()
    tampered = raw.replace(
        b"http://cyclonedx.org/schema/bom-1.6.schema.json",
        b"http://evil.example/schema/bom-1.6.json", 1)
    assert tampered != raw, "expected $id not found in schema"
    schema_path.write_bytes(tampered)
    mpath = target / "MANIFEST.json"
    manifest = json.loads(mpath.read_text(encoding="utf-8"))
    manifest["files"]["schema.json"]["sha256"] = \
        hashlib.sha256(tampered).hexdigest()
    mpath.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(RuntimeError) as exc:
        sc._load_vendored_schema_16(base_dir=target)
    msg = str(exc.value)
    assert "schema identity failure" in msg
    assert "http://evil.example/schema/bom-1.6.json" in msg
    assert "http://cyclonedx.org/schema/bom-1.6.schema.json" in msg
    monkeypatch.setattr(sc, "_VENDORED_SCHEMA_DIR", target, raising=False)
    with _NetworkGuard() as guard:
        entry = sc._cyclonedx_schema_check(_valid_doc(),
                                          target_versions=("1.6",))["1.6"]
    assert "valid" in entry, entry
    assert entry["valid"] is False, entry
    assert any("schema identity failure" in e
               for e in entry.get("errors", [])), entry
    assert guard.attempts == []
