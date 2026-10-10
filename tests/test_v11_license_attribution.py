"""Licence attribution: a project's licence is not its dependencies' licence.

Two parsers used to read the ROOT manifest's licence and stamp it onto every
dependency they emitted:

    scanner/sbom.py  _parse_pom_xml       root <licenses>  -> all 44 Maven deps
    scanner/sbom.py  _parse_package_json  root "license"   -> all 113 npm deps

That is a false statement about each dependency, and it was self-sealing:
core.license_catalog.infer_package_license() returns early for any non-UNKNOWN
value (line 1015), so the package table that KNOWS the right answer could never
correct it.  Measured on the two corpora before the fix:

    BenchmarkJava  44/44 reported "GNU General Public License, version 2 (GPL2)"
                   while the tool's own catalogue said Apache-2.0 for
                   jackson-databind, commons-dbcp and three Spring artefacts,
                   CDDL-1.1 for jaxb-api, BSD-3-Clause for hsqldb.
    juice-shop     113/113 reported MIT while the catalogue said ISC for
                   glob, graceful-fs and semver, Apache-2.0 for typescript.

Maven and package.json genuinely do not record a dependency's licence, so
"unknown" is the only honest value a parser can emit -- and it is precisely the
value that lets the catalogue answer.
"""
from __future__ import annotations

import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core.license_catalog import infer_package_license  # noqa: E402
from scanner.sbom import _parse_package_json, _parse_pom_xml  # noqa: E402


# The root licence is deliberately one that is WRONG for both dependencies.
POM = """<?xml version="1.0" encoding="UTF-8"?>
<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>org.example</groupId>
  <artifactId>demo</artifactId>
  <version>1.0</version>
  <licenses>
    <license>
      <name>GNU General Public License, version 2 (GPL2)</name>
      <url>https://choosealicense.com/licenses/gpl-2.0/</url>
    </license>
  </licenses>
  <dependencies>
    <dependency>
      <groupId>commons-codec</groupId>
      <artifactId>commons-codec</artifactId>
      <version>1.15</version>
    </dependency>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
      <version>2.9.8</version>
    </dependency>
  </dependencies>
</project>
"""

PKGJSON = json.dumps({
    "name": "demo",
    "version": "1.0.0",
    "license": "MIT",
    "dependencies": {
        "semver": "^7.0.0",
        "typescript": "^4.0.0",
        "express": "^4.17.1",
    },
}, indent=2)

ROOT_POM_LICENCE = "GNU General Public License, version 2 (GPL2)"
ROOT_PKG_LICENCE = "MIT"


def _pom(tmp_path: pathlib.Path) -> pathlib.Path:
    p = tmp_path / "pom.xml"
    p.write_text(POM, encoding="utf-8")
    return p


def _pkg(tmp_path: pathlib.Path) -> pathlib.Path:
    p = tmp_path / "package.json"
    p.write_text(PKGJSON, encoding="utf-8")
    return p


# ===========================================================================
# The defect: the root's licence must not reach a dependency
# ===========================================================================

def test_maven_dependencies_do_not_inherit_the_projects_licence(tmp_path):
    pkgs = _parse_pom_xml(str(_pom(tmp_path)))
    assert pkgs, "the fixture declares two dependencies"
    for p in pkgs:
        assert p["license"] == "unknown", (
            f"{p['name']} inherited the project's licence: {p['license']!r}")


def test_npm_dependencies_do_not_inherit_the_projects_licence(tmp_path):
    pkgs = _parse_package_json(str(_pkg(tmp_path)))
    assert len(pkgs) == 3, [p["name"] for p in pkgs]
    for p in pkgs:
        assert p["license"] == "unknown", (
            f"{p['name']} inherited the project's licence: {p['license']!r}")


def test_the_projects_licence_appears_nowhere_in_the_dependency_list(tmp_path):
    """NEGATIVE: not merely normalised, absent. A value that survives in any
    field will be picked up by an or-chain downstream and re-sprayed."""
    for fn, root_licence in ((_parse_pom_xml, ROOT_POM_LICENCE),
                             (_parse_package_json, ROOT_PKG_LICENCE)):
        pkgs = fn(str(_pom(tmp_path) if fn is _parse_pom_xml
                        else _pkg(tmp_path)))
        for p in pkgs:
            blob = json.dumps(p, sort_keys=True).lower()
            assert root_licence.lower() not in blob, (fn.__name__, p)


# ===========================================================================
# Why it matters: the catalogue can only correct an honestly absent value
# ===========================================================================

def test_the_catalogue_can_now_reach_a_known_maven_dependency(tmp_path):
    """Before the fix this returned 'GPL-2.0-only', because
    infer_package_license() returns early on any non-UNKNOWN value."""
    pkgs = {p["name"]: p for p in _parse_pom_xml(str(_pom(tmp_path)))}
    got = infer_package_license("com.fasterxml.jackson.core:jackson-databind",
                                pkgs["com.fasterxml.jackson.core:jackson-databind"]["license"])
    assert got == "Apache-2.0", got


def test_the_catalogue_recovers_the_four_proven_counter_examples(tmp_path):
    """glob/graceful-fs/semver are ISC; typescript is Apache-2.0. All four
    were published as MIT because the root project is MIT."""
    pkgs = {p["name"]: p for p in _parse_package_json(str(_pkg(tmp_path)))}
    expect = {"semver": "ISC", "typescript": "Apache-2.0"}
    for name, want in expect.items():
        got = infer_package_license(name, pkgs[name]["license"])
        assert got == want, f"{name}: want {want}, got {got}"


def test_a_genuinely_unknown_dependency_stays_unknown(tmp_path):
    """The honest half of the fix: no guessing for packages the catalogue
    does not carry.  'unknown' is the input; UNKNOWN is the output."""
    pkgs = _parse_pom_xml(str(_pom(tmp_path)))
    got = infer_package_license("org.example:not-in-any-catalogue",
                                pkgs[0]["license"])
    assert got == "UNKNOWN", got


# ===========================================================================
# The mechanism the bug depended on
# ===========================================================================

def test_the_catalogue_is_skipped_once_a_value_exists():
    """Documents the early-return at license_catalog.py:1015.  This is why the
    fix belongs in the PARSERS: no amount of catalogue data can override a
    value that is already present."""
    assert infer_package_license("semver", "MIT") == "MIT"
    assert infer_package_license("semver", "unknown") == "ISC"
