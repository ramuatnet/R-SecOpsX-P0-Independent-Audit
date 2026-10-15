"""A Maven property in a <version> element is a version, not an absence.

wrongsecrets (real scan, 2026-10-15) declares <lombok.version>1.18.48</...>,
<testcontainers.version>1.21.4</...> and <jruby.version>10.1.1.0</...> in the
very pom that references them as ${lombok.version}, ${testcontainers.version}
and ${jruby.version}.  The parser used to discard every ${...} reference as
"unknown", so 47 components reported no version although the manifest carried
one -- and the exact package+version match the licence-evidence resolver
performs could never succeed for them.

Resolution is LOCAL only: a property declared in a parent pom or an imported
BOM is not available offline, and the honest output for those stays "unknown".
"""
from __future__ import annotations

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scanner.sbom import _parse_pom_xml, _resolve_pom_property  # noqa: E402

PROPERTY_POM = """<?xml version="1.0" encoding="UTF-8"?>
<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>org.example</groupId>
  <artifactId>demo</artifactId>
  <version>1.4.2</version>
  <licenses>
    <license>
      <name>Apache License, Version 2.0</name>
    </license>
  </licenses>
  <properties>
    <lombok.version>1.18.48</lombok.version>
    <testcontainers.version>1.21.4</testcontainers.version>
    <chained.version>${lombok.version}</chained.version>
  </properties>
  <dependencies>
    <dependency>
      <groupId>org.projectlombok</groupId>
      <artifactId>lombok</artifactId>
      <version>${lombok.version}</version>
    </dependency>
    <dependency>
      <groupId>org.testcontainers</groupId>
      <artifactId>testcontainers</artifactId>
      <version>${testcontainers.version}</version>
    </dependency>
    <dependency>
      <groupId>org.example</groupId>
      <artifactId>chained</artifactId>
      <version>${chained.version}</version>
    </dependency>
    <dependency>
      <groupId>org.example</groupId>
      <artifactId>self-version</artifactId>
      <version>${project.version}</version>
    </dependency>
    <dependency>
      <groupId>org.example</groupId>
      <artifactId>undeclared-property</artifactId>
      <version>${not.declared.anywhere}</version>
    </dependency>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter</artifactId>
    </dependency>
    <dependency>
      <groupId>commons-codec</groupId>
      <artifactId>commons-codec</artifactId>
      <version>1.15</version>
    </dependency>
  </dependencies>
</project>
"""

PARENT_VERSION_POM = """<?xml version="1.0" encoding="UTF-8"?>
<project>
  <modelVersion>4.0.0</modelVersion>
  <parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
    <version>3.4.5</version>
  </parent>
  <groupId>org.example</groupId>
  <artifactId>child</artifactId>
  <dependencies>
    <dependency>
      <groupId>org.example</groupId>
      <artifactId>inherits-parent-version</artifactId>
      <version>${project.version}</version>
    </dependency>
  </dependencies>
</project>
"""


def _parse(tmp_path: pathlib.Path, text: str) -> dict:
    pom = tmp_path / "pom.xml"
    pom.write_text(text, encoding="utf-8")
    return {pkg["name"]: pkg for pkg in _parse_pom_xml(str(pom))}


def test_properties_declared_in_the_same_pom_resolve(tmp_path):
    pkgs = _parse(tmp_path, PROPERTY_POM)
    assert pkgs["org.projectlombok:lombok"]["version"] == "1.18.48"
    assert pkgs["org.testcontainers:testcontainers"]["version"] == "1.21.4"


def test_chained_property_references_resolve(tmp_path):
    pkgs = _parse(tmp_path, PROPERTY_POM)
    assert pkgs["org.example:chained"]["version"] == "1.18.48"


def test_project_version_property_resolves_from_the_poms_own_coordinates(tmp_path):
    pkgs = _parse(tmp_path, PROPERTY_POM)
    assert pkgs["org.example:self-version"]["version"] == "1.4.2"


def test_project_version_falls_back_to_the_parent_pom(tmp_path):
    pkgs = _parse(tmp_path, PARENT_VERSION_POM)
    assert pkgs["org.example:inherits-parent-version"]["version"] == "3.4.5"


def test_undeclared_property_stays_honestly_unknown(tmp_path):
    """Not available offline -> unknown, never a guess."""
    pkgs = _parse(tmp_path, PROPERTY_POM)
    assert pkgs["org.example:undeclared-property"]["version"] == "unknown"


def test_dependency_without_any_version_stays_unknown(tmp_path):
    """spring-boot-starter's version is managed by the parent's
    dependencyManagement, which is not in this file: 'unknown' is correct."""
    pkgs = _parse(tmp_path, PROPERTY_POM)
    assert pkgs["org.springframework.boot:spring-boot-starter"]["version"] == "unknown"


def test_literal_versions_are_untouched(tmp_path):
    pkgs = _parse(tmp_path, PROPERTY_POM)
    assert pkgs["commons-codec:commons-codec"]["version"] == "1.15"


def test_a_dependency_licence_is_still_not_the_projects_licence(tmp_path):
    """The version fix must not resurrect the attribution bug."""
    pkgs = _parse(tmp_path, PROPERTY_POM)
    for pkg in pkgs.values():
        assert pkg["license"] == "unknown", pkg


def test_resolve_pom_property_is_bounded_on_cycles():
    assert _resolve_pom_property("${a}", {"a": "${b}", "b": "${a}"}) == "unknown"


def test_resolve_pom_property_handles_partial_strings():
    assert _resolve_pom_property("v${rev}", {"rev": "9"}) == "v9"
