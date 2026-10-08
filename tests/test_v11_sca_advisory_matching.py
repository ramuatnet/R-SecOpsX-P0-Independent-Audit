"""Regression contract for SBOM version resolution and advisory matching.

Benchmark reference: reports/benchmark_reconciliation_sca.md
Benchmark: ``sca-multilang-2026-10`` (ground truth from OSV.dev, established
before any compared tool ran).

Three defects are pinned here. Each was found by the benchmark rather than by
a unit test, so each now has a unit test to stop it coming back:

  1. ``_parse_requirements`` kept the pin operator, sending
     ``version="==2.19.1"`` to OSV. OSV cannot evaluate that against an
     affected range, so it returned *every* advisory ever filed for the
     package: 39 invented CVEs, CVE precision 49.3%.
  2. ``_parse_package_json`` stored the raw npm range (``^4.17.4``). Same
     failure: 4 invented CVEs and a false vulnerability match on ``ms@2.1.3``,
     a package with zero known CVEs.
  3. ``apply_vulnerability_overrides`` *replaced* the advisory set with the
     local override, discarding OSV: log4j-core collapsed from 7 CVEs to 2,
     losing CVE-2021-44832 and CVE-2021-45105.

None of these tests touch the network.
"""
from pathlib import Path
import json
import sys

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import scanner.sbom as sbom
from scanner.sbom import (
    _parse_package_json,
    _parse_package_lock,
    _parse_requirements,
    _resolve_npm_version,
    _resolve_pinned_version,
    apply_vulnerability_overrides,
)
from reporting.cyclonedx_export import build_cyclonedx


# ---------------------------------------------------------------------------
# 1. Python requirement specifier -> exact version
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "spec,expected",
    [
        ("==2.19.1", "2.19.1"),
        ("== 2.19.1", "2.19.1"),
        ("==2.19.1 ; python_version<'3.8'", "2.19.1"),
        ("==2.19.1  # pinned by security", "2.19.1"),
        # A range resolves to nothing: querying a guessed version would
        # invent CVEs, while "unknown" is skipped and only costs recall.
        ("", "unknown"),
        (">=1.0,<2.0", "unknown"),
        ("!=1.4", "unknown"),
        ("~=1.4.2", "unknown"),
        ("==2.19.*", "unknown"),
        ("==*", "unknown"),
        ("unknown", "unknown"),
        ("git+https://github.com/psf/requests.git", "unknown"),
        ("https://example.com/pkg.tar.gz", "unknown"),
    ],
)
def test_resolve_pinned_version(spec, expected):
    assert _resolve_pinned_version(spec) == expected


def test_resolved_version_never_carries_a_specifier():
    """The exact failure that produced 39 invented CVEs."""
    for spec in ("==2.19.1", ">=1.0,<2.0", "==2.19.*"):
        out = _resolve_pinned_version(spec)
        assert not out.startswith("="), spec
        assert "<" not in out and ">" not in out, spec


def test_parse_requirements_strips_the_pin(tmp_path):
    f = tmp_path / "requirements.txt"
    f.write_text(
        "# comment\n"
        "requests==2.19.1\n"
        "django==2.2.0\n"
        "flask[async]==2.0.1\n"
        "urllib3>=1.26,<2.0\n"
        "-r other.txt\n",
        encoding="utf-8",
    )
    got = {p["name"]: p["version"] for p in _parse_requirements(str(f))}
    assert got["requests"] == "2.19.1"
    assert got["django"] == "2.2.0"
    assert got["flask"] == "2.0.1"          # extras dropped, pin resolved
    assert got["urllib3"] == "unknown"      # range is not a resolved version
    assert "-r" not in got
    assert all(not v.startswith("=") for v in got.values())


def test_parse_requirements_line_numbers_survive(tmp_path):
    f = tmp_path / "requirements.txt"
    f.write_text("requests==2.19.1\nflask==2.0.0\n", encoding="utf-8")
    rows = _parse_requirements(str(f))
    assert [p["manifest_line"] for p in rows] == [1, 2]
    assert all(p["ecosystem"] == "PyPI" and p["direct"] for p in rows)


# ---------------------------------------------------------------------------
# 2. npm dependency ranges
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "spec,expected",
    [
        ("4.17.4", "4.17.4"),
        ("v4.17.4", "4.17.4"),
        ("2.1.3", "2.1.3"),
        ("1.0.0-beta.1", "1.0.0-beta.1"),
        # Ranges carry no resolved version.
        ("^4.17.4", "unknown"),
        ("~2.1.3", "unknown"),
        (">=4.17.1 <5.0.0", "unknown"),
        ("1.x", "unknown"),
        ("*", "unknown"),
        ("latest", "unknown"),
        ("next", "unknown"),
        ("npm:lodash@^4.17.4", "unknown"),
        ("git+https://github.com/lodash/lodash.git", "unknown"),
        ("https://example.com/a.tgz", "unknown"),
        (None, "unknown"),
        ("", "unknown"),
    ],
)
def test_resolve_npm_version(spec, expected):
    assert _resolve_npm_version(spec) == expected


def test_package_json_range_is_not_forwarded_as_a_version(tmp_path):
    f = tmp_path / "package.json"
    f.write_text(json.dumps({
        "name": "app", "version": "1.0.0",
        "dependencies": {"lodash": "^4.17.4", "ms": "~2.1.3"},
        "devDependencies": {"express": "4.17.1"},
    }), encoding="utf-8")

    got = {p["name"]: p["version"] for p in _parse_package_json(str(f))}
    assert got["lodash"] == "unknown"   # a range must never reach OSV
    assert got["ms"] == "unknown"
    assert got["express"] == "4.17.1"   # an exact pin is kept


def test_package_lock_supplies_the_resolved_version(tmp_path):
    (tmp_path / "node_modules" / "lodash").mkdir(parents=True)
    (tmp_path / "node_modules" / "ms").mkdir(parents=True)
    f = tmp_path / "package-lock.json"
    f.write_text(json.dumps({
        "name": "app", "version": "1.0.0", "lockfileVersion": 3,
        "packages": {
            "": {"name": "app", "dependencies": {"lodash": "^4.17.4"}},
            "node_modules/lodash": {"version": "4.17.4", "license": "MIT"},
            "node_modules/ms": {"version": "2.1.3", "license": "MIT"},
        },
    }), encoding="utf-8")

    got = {p["name"]: p for p in _parse_package_lock(str(f))}
    assert got["lodash"]["version"] == "4.17.4"
    assert got["ms"]["version"] == "2.1.3"


# ---------------------------------------------------------------------------
# 3. generate_sbom: one component, one version, direct flag preserved
# ---------------------------------------------------------------------------

@pytest.fixture
def offline_sbom(monkeypatch):
    """Run generate_sbom without the OSV network call."""
    monkeypatch.setattr(sbom, "enrich_packages_with_external_vulns",
                        lambda pkgs: pkgs)
    return sbom.generate_sbom


def test_manifest_and_lock_produce_a_single_component(tmp_path, offline_sbom):
    (tmp_path / "node_modules" / "lodash").mkdir(parents=True)
    (tmp_path / "node_modules" / "express").mkdir(parents=True)
    (tmp_path / "package.json").write_text(json.dumps({
        "name": "app", "version": "1.0.0",
        "dependencies": {"lodash": "^4.17.4", "express": "^4.17.1"},
    }), encoding="utf-8")
    (tmp_path / "package-lock.json").write_text(json.dumps({
        "name": "app", "version": "1.0.0", "lockfileVersion": 3,
        "packages": {
            "": {"name": "app"},
            "node_modules/lodash": {"version": "4.17.4", "license": "MIT"},
            "node_modules/express": {"version": "4.17.1", "license": "MIT"},
        },
    }), encoding="utf-8")

    pkgs = offline_sbom(str(tmp_path))
    by_name = {p["name"]: p for p in pkgs if p["ecosystem"] == "npm"}

    # The unresolvable range and the lockfile pin are one component: neither
    # may appear twice, and the resolved version must win.
    assert set(by_name) >= {"express", "lodash"}, set(by_name)
    assert len([p for p in pkgs if p["name"] == "lodash"]) == 1
    assert len([p for p in pkgs if p["name"] == "express"]) == 1
    assert by_name["lodash"]["version"] == "4.17.4"
    assert by_name["express"]["version"] == "4.17.1"

    # The lockfile stamps everything direct=False; the manifest knows better.
    assert by_name["lodash"]["direct"] is True
    assert by_name["express"]["direct"] is True


def test_unresolved_range_does_not_create_a_second_component(tmp_path,
                                                             offline_sbom):
    (tmp_path / "package.json").write_text(json.dumps({
        "name": "app", "version": "1.0.0",
        "dependencies": {"lodash": "^4.17.4"},
    }), encoding="utf-8")

    pkgs = offline_sbom(str(tmp_path))
    lodash = [p for p in pkgs if p["name"] == "lodash"]
    assert len(lodash) == 1
    assert lodash[0]["version"] == "unknown"   # no lockfile to resolve it
    assert lodash[0]["direct"] is True


def test_requirements_pin_reaches_the_sbom_clean(tmp_path, offline_sbom):
    (tmp_path / "requirements.txt").write_text(
        "requests==2.19.1\ndjango==2.2.0\n", encoding="utf-8")
    pkgs = offline_sbom(str(tmp_path))
    got = {p["name"]: p["version"] for p in pkgs
           if p["ecosystem"] == "PyPI"}
    assert got["requests"] == "2.19.1"
    assert got["django"] == "2.2.0"


# ---------------------------------------------------------------------------
# 4. PURL: a component identifier must be consumable
# ---------------------------------------------------------------------------

def test_cyclonedx_purl_has_no_specifier_operator():
    doc = build_cyclonedx({"sbom": [
        {"name": "requests", "version": "2.19.1", "ecosystem": "PyPI"},
        {"name": "lodash", "version": "4.17.4", "ecosystem": "npm"},
        {"name": "log4j-core", "version": "2.14.1", "ecosystem": "Maven",
         "groupId": "org.apache.logging.log4j"},
    ]})
    purls = [c.get("purl") for c in doc["components"] if c.get("purl")]
    assert "pkg:pypi/requests@2.19.1" in purls
    assert "pkg:npm/lodash@4.17.4" in purls
    assert not any("@" in p and "@=" in p for p in purls), purls
    assert all("=" not in p.split("@")[-1] for p in purls), purls


# ---------------------------------------------------------------------------
# 5. Local vulnerability overrides must add, never replace
# ---------------------------------------------------------------------------

_OVERRIDE = {
    "org.apache.logging.log4j:log4j-core": [
        {"cve": "CVE-2021-44228", "severity": "Critical", "cvss": 10.0,
         "affected": ["2.14.1"], "fixed_in": "2.25.4"},
        {"cve": "CVE-2021-45046", "severity": "Critical", "cvss": 9.0,
         "affected": ["2.14.1"], "fixed_in": "2.25.4"},
    ],
}


def _osv_record(ghsa: str, cve: str) -> dict:
    return {"id": ghsa, "cve": cve, "aliases": [cve, "PYSEC-2021-1"],
            "severity": "Critical", "cvss": 10.0, "summary": "x"}


def test_override_merges_instead_of_replacing(monkeypatch):
    monkeypatch.setattr(sbom, "VULNERABILITY_OVERRIDES", _OVERRIDE)
    pkg = {
        "name": "org.apache.logging.log4j:log4j-core",
        "version": "2.14.1",
        "vulnerabilities": [
            _osv_record("GHSA-jfh8-c2jp-5v3q", "CVE-2021-44228"),
            _osv_record("GHSA-2r62-7qfp-m6r3", "CVE-2021-45046"),
            _osv_record("GHSA-3xgq-45jj-v275", "CVE-2021-44832"),
            _osv_record("GHSA-6vgm-j846-v3vg", "CVE-2021-45105"),
        ],
        "cve": None,
    }
    out = apply_vulnerability_overrides([pkg])[0]

    cves = {v.get("cve") for v in out["vulnerabilities"]}
    # The four OSV records must all survive...
    assert {"CVE-2021-44228", "CVE-2021-45046", "CVE-2021-44832",
            "CVE-2021-45105"} <= cves, cves
    # ...and the two the override already covers must not be duplicated.
    assert len(out["vulnerabilities"]) == 4, out["vulnerabilities"]
    # The override still owns the headline fields.
    assert out["cve"] == "CVE-2021-44228"
    assert out["override_source"] == "Local Vulnerability Override"


def test_override_adds_a_cve_osv_did_not_have(monkeypatch):
    monkeypatch.setattr(sbom, "VULNERABILITY_OVERRIDES", _OVERRIDE)
    pkg = {
        "name": "org.apache.logging.log4j:log4j-core",
        "version": "2.14.1",
        "vulnerabilities": [
            _osv_record("GHSA-3xgq-45jj-v275", "CVE-2021-44832"),
        ],
        "cve": None,
    }
    out = apply_vulnerability_overrides([pkg])[0]
    cves = {v.get("cve") for v in out["vulnerabilities"]}
    assert "CVE-2021-44832" in cves          # OSV's own record kept
    assert "CVE-2021-44228" in cves          # local addition
    assert "CVE-2021-45046" in cves
    assert len(out["vulnerabilities"]) == 3


def test_override_does_not_fire_on_a_different_version(monkeypatch):
    monkeypatch.setattr(sbom, "VULNERABILITY_OVERRIDES", _OVERRIDE)
    original = [
        _osv_record("GHSA-3xgq-45jj-v275", "CVE-2021-44832"),
    ]
    pkg = {"name": "org.apache.logging.log4j:log4j-core",
           "version": "2.15.0",
           "vulnerabilities": list(original), "cve": None}
    out = apply_vulnerability_overrides([pkg])[0]
    assert out["vulnerabilities"] == original
    assert "override_source" not in out


def test_override_ignores_unrelated_packages(monkeypatch):
    monkeypatch.setattr(sbom, "VULNERABILITY_OVERRIDES", _OVERRIDE)
    pkg = {"name": "requests", "version": "2.19.1",
           "vulnerabilities": [], "cve": None}
    out = apply_vulnerability_overrides([pkg])[0]
    assert out["vulnerabilities"] == []
    assert out["cve"] is None


def test_override_merge_handles_a_package_with_no_advisories(monkeypatch):
    monkeypatch.setattr(sbom, "VULNERABILITY_OVERRIDES", _OVERRIDE)
    pkg = {"name": "org.apache.logging.log4j:log4j-core",
           "version": "2.14.1", "cve": None}
    out = apply_vulnerability_overrides([pkg])[0]
    assert {v.get("cve") for v in out["vulnerabilities"]} == {
        "CVE-2021-44228", "CVE-2021-45046"}
