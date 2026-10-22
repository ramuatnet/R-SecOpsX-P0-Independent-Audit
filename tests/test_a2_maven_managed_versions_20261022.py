"""Red-first tests: A2 -- BOM-managed / parent-pom version resolution.

Re-derived from the post-batch-10 CNAP-vs-V11 join: WebGoat declares
jackson-databind without a <version>; the version is managed by the parent
chain (spring-boot-starter-parent:4.1.0 -> spring-boot-dependencies ->
${jackson.version}). G14 resolved only local "<artifactId>.version"
properties, so the pin stayed honestly unknown and its CVEs were dropped
while CNAP resolved them (batch-9 validation, §3 G14).

A2 follows parent chains and import-scoped BOMs on Maven Central with an
on-disk pom cache; every failure mode (offline, 404, cycle, budget) must
degrade to "unknown" -- never guess a version.
"""
import pytest

from scanner import sbom


ROOT_POM = """<project>
 <modelVersion>4.0.0</modelVersion>
 <parent>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-starter-parent</artifactId>
  <version>4.1.0</version>
 </parent>
 <groupId>org.owasp.webgoat</groupId>
 <artifactId>webgoat</artifactId>
 <dependencies>
  <dependency>
   <groupId>com.fasterxml.jackson.core</groupId>
   <artifactId>jackson-databind</artifactId>
  </dependency>
  <dependency>
   <groupId>com.thoughtworks.xstream</groupId>
   <artifactId>xstream</artifactId>
  </dependency>
 </dependencies>
 <properties>
  <xstream.version>1.4.5</xstream.version>
 </properties>
</project>"""

STARTER_PARENT = """<project>
 <modelVersion>4.0.0</modelVersion>
 <parent>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-dependencies</artifactId>
  <version>4.1.0</version>
 </parent>
 <groupId>org.springframework.boot</groupId>
 <artifactId>spring-boot-starter-parent</artifactId>
 <version>4.1.0</version>
 <dependencyManagement>
  <dependencies>
   <dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-dependencies</artifactId>
    <version>4.1.0</version>
    <type>pom</type>
    <scope>import</scope>
   </dependency>
  </dependencies>
 </dependencyManagement>
</project>"""

# Managed entry via its own property + an imported jackson-bom.
SPRING_BOOT_DEPENDENCIES = """<project>
 <modelVersion>4.0.0</modelVersion>
 <groupId>org.springframework.boot</groupId>
 <artifactId>spring-boot-dependencies</artifactId>
 <version>4.1.0</version>
 <properties>
  <jackson.version>2.21.4</jackson.version>
 </properties>
 <dependencyManagement>
  <dependencies>
   <dependency>
    <groupId>com.fasterxml.jackson.core</groupId>
    <artifactId>jackson-databind</artifactId>
    <version>${jackson.version}</version>
   </dependency>
   <dependency>
    <groupId>com.fasterxml.jackson</groupId>
    <artifactId>jackson-bom</artifactId>
    <version>${jackson.version}</version>
    <type>pom</type>
    <scope>import</scope>
   </dependency>
  </dependencies>
 </dependencyManagement>
</project>"""

# Managed ONLY through the import (no direct entry) at ${project.version}.
JACKSON_BOM = """<project>
 <modelVersion>4.0.0</modelVersion>
 <groupId>com.fasterxml.jackson</groupId>
 <artifactId>jackson-bom</artifactId>
 <version>2.21.4</version>
 <dependencyManagement>
  <dependencies>
   <dependency>
    <groupId>com.fasterxml.jackson.core</groupId>
    <artifactId>jackson-datatype-jsr310</artifactId>
    <version>${project.version}</version>
   </dependency>
  </dependencies>
 </dependencyManagement>
</project>"""

CANNED = {
    "org.springframework.boot:spring-boot-starter-parent:4.1.0": STARTER_PARENT,
    "org.springframework.boot:spring-boot-dependencies:4.1.0": SPRING_BOOT_DEPENDENCIES,
    "com.fasterxml.jackson:jackson-bom:2.21.4": JACKSON_BOM,
}


@pytest.fixture(autouse=True)
def _isolate(tmp_path):
    """Fresh memo + tmp disk cache + canned (offline) fetcher per test.
    The canned fetcher mirrors production write-through so the disk-cache
    test exercises the real persistence path."""
    import json as _json
    old_path = sbom._MAVEN_POM_CACHE_PATH
    sbom._MAVEN_POM_CACHE_PATH = tmp_path / ".maven_pom_cache.json"
    sbom._POM_FETCH_MEMO.clear()
    sbom._POM_MANAGED_MEMO.clear()
    calls = []

    def fake_fetch(g, a, v):
        key = "%s:%s:%s" % (g, a, v)
        calls.append(key)
        text = CANNED.get(key)
        if text is not None:
            try:
                cache = {}
                if sbom._MAVEN_POM_CACHE_PATH.exists():
                    cache = _json.loads(
                        sbom._MAVEN_POM_CACHE_PATH.read_text(encoding="utf-8"))
                cache[key] = text
                sbom._MAVEN_POM_CACHE_PATH.write_text(
                    _json.dumps(cache), encoding="utf-8")
            except Exception:
                pass
        return text

    sbom._fetch_calls = calls
    sbom._fetch_maven_pom = fake_fetch
    yield
    sbom._MAVEN_POM_CACHE_PATH = old_path
    sbom._POM_FETCH_MEMO.clear()
    sbom._POM_MANAGED_MEMO.clear()


def _write_pom(tmp_path, text, name="pom.xml"):
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return str(p)


def _by_artifact(pkgs):
    return {p["name"].split(":")[-1]: p["version"] for p in pkgs}


class TestA2ManagedVersionResolution:
    def test_parent_managed_property_resolves(self, tmp_path):
        """WebGoat shape: jackson-databind has no local version; the parent
        chain's dependencyManagement carries ${jackson.version} -> 2.21.4
        (the pin CNAP resolved and V11 reported unknown)."""
        pkgs = sbom._parse_pom_xml(_write_pom(tmp_path, ROOT_POM))
        assert _by_artifact(pkgs)["jackson-databind"] == "2.21.4"

    def test_local_property_still_wins_without_network(self, tmp_path):
        """G14 behavior unchanged: a local <artifactId>.version property
        resolves even when the whole fetch layer is dead (any call raises);
        the resolver failure degrades the chain-managed pins to unknown
        without touching local ones."""
        sbom._fetch_maven_pom = lambda g, a, v: (_ for _ in ()).throw(
            AssertionError("network must not be consulted"))
        pkgs = sbom._parse_pom_xml(_write_pom(tmp_path, ROOT_POM))
        assert _by_artifact(pkgs)["xstream"] == "1.4.5"
        assert not any("xstream" in c for c in sbom._fetch_calls)

    def test_imported_bom_resolves_via_project_version(self, tmp_path):
        """Coordinate managed ONLY inside an imported BOM at
        ${project.version} (jackson-datatype-jsr310)."""
        pom = ROOT_POM.replace(
            "<groupId>com.thoughtworks.xstream</groupId>\n   "
            "<artifactId>xstream</artifactId>",
            "<groupId>com.fasterxml.jackson.core</groupId>\n   "
            "<artifactId>jackson-datatype-jsr310</artifactId>")
        pkgs = sbom._parse_pom_xml(_write_pom(tmp_path, pom))
        assert _by_artifact(pkgs)["jackson-datatype-jsr310"] == "2.21.4"

    def test_offline_degrades_to_unknown(self, tmp_path):
        """No network and no cache -> honestly unknown, never a guess."""
        sbom._fetch_maven_pom = lambda g, a, v: None
        pkgs = sbom._parse_pom_xml(_write_pom(tmp_path, ROOT_POM))
        assert _by_artifact(pkgs)["jackson-databind"] == "unknown"

    def test_parent_cycle_is_bounded(self, tmp_path):
        """A pom whose parent is itself must not hang or crash."""
        cyclic = """<project>
 <parent><groupId>g</groupId><artifactId>self</artifactId><version>1</version></parent>
 <groupId>g</groupId><artifactId>self</artifactId><version>1</version>
 <dependencies><dependency><groupId>g</groupId><artifactId>missing</artifactId></dependency></dependencies>
</project>"""
        sbom._fetch_maven_pom = lambda g, a, v: cyclic if a == "self" else None
        pkgs = sbom._parse_pom_xml(_write_pom(tmp_path, cyclic))
        assert _by_artifact(pkgs)["missing"] == "unknown"

    def test_fetch_budget_bounds_import_chain(self, tmp_path):
        """A long import chain stops at the budget instead of walking
        the world."""
        def chain_fetch(g, a, v):
            n = int(v.split("-")[-1]) if "-" in v else 0
            nxt = n + 1
            return ('<project><artifactId>%s</artifactId><version>%s</version>'
                    "<dependencyManagement><dependencies><dependency>"
                    "<groupId>g</groupId><artifactId>chain</artifactId>"
                    "<version>%s</version><type>pom</type><scope>import</scope>"
                    "</dependency></dependencies></dependencyManagement></project>"
                    % (a, v, "bom-%d" % nxt))
        sbom._fetch_maven_pom = chain_fetch
        root = """<project>
 <parent><groupId>g</groupId><artifactId>chain</artifactId><version>bom-0</version></parent>
 <groupId>g</groupId><artifactId>root</artifactId>
 <dependencies><dependency><groupId>g</groupId><artifactId>missing</artifactId></dependency></dependencies>
</project>"""
        pkgs = sbom._parse_pom_xml(_write_pom(tmp_path, root))
        assert _by_artifact(pkgs)["missing"] == "unknown"
        assert len(sbom._fetch_calls) <= sbom._MAX_POM_FETCHES

    def test_disk_cache_prevents_refetch(self, tmp_path):
        """Second scan of the same pom resolves from the disk cache: the
        fetcher no longer knows the canned sources at all, so a successful
        resolution proves the cache file served every pom."""
        self.test_parent_managed_property_resolves(tmp_path)
        assert sbom._fetch_calls, "sanity: the first pass really fetched"
        sbom._POM_FETCH_MEMO.clear()
        sbom._POM_MANAGED_MEMO.clear()

        def cache_reading_fetch(g, a, v):
            import json as _json
            try:
                cache = _json.loads(
                    sbom._MAVEN_POM_CACHE_PATH.read_text(encoding="utf-8"))
            except Exception:
                return None
            return cache.get("%s:%s:%s" % (g, a, v))

        sbom._fetch_maven_pom = cache_reading_fetch
        pkgs = sbom._parse_pom_xml(_write_pom(tmp_path, ROOT_POM))
        assert _by_artifact(pkgs)["jackson-databind"] == "2.21.4"

    def test_explicit_version_never_fetches(self, tmp_path):
        pom = """<project>
 <groupId>g</groupId><artifactId>root</artifactId><version>1</version>
 <dependencies><dependency><groupId>g</groupId><artifactId>pinned</artifactId><version>9.9.9</version></dependency></dependencies>
</project>"""
        sbom._fetch_maven_pom = lambda g, a, v: (_ for _ in ()).throw(
            AssertionError("explicit versions need no resolution"))
        pkgs = sbom._parse_pom_xml(_write_pom(tmp_path, pom))
        assert _by_artifact(pkgs)["pinned"] == "9.9.9"

    def test_same_pom_dependency_management_resolves(self, tmp_path):
        """A pom managing versions in its OWN dependencyManagement (no
        parent involved) resolves too."""
        pom = """<project>
 <groupId>g</groupId><artifactId>root</artifactId><version>1</version>
 <dependencyManagement><dependencies><dependency>
  <groupId>g</groupId><artifactId>managed</artifactId><version>2.3.4</version>
 </dependency></dependencies></dependencyManagement>
 <dependencies><dependency><groupId>g</groupId><artifactId>managed</artifactId></dependency></dependencies>
</project>"""
        pkgs = sbom._parse_pom_xml(_write_pom(tmp_path, pom))
        assert _by_artifact(pkgs)["managed"] == "2.3.4"

    def test_target_family_bom_jumps_import_queue(self, tmp_path):
        """Spring Boot shape: the parent's dependencyManagement imports ~45
        BOMs and the target's family BOM (jackson-bom, group
        com.fasterxml.jackson for target com.fasterxml.jackson.core) sorts
        alphabetically in the MIDDLE. Imports whose group prefixes the
        target's group are walked first, and the walk stops once every
        requested coordinate is resolved -- otherwise the fetch budget is
        spent on unrelated BOMs and the pin stays unknown (measured on the
        real WebGoat scan: budget exhausted at grpc-bom)."""
        boms = []
        for i in range(12):
            boms.append(
                "<dependency><groupId>org.example</groupId>"
                "<artifactId>aaa-bom-%d</artifactId><version>1</version>"
                "<type>pom</type><scope>import</scope></dependency>" % i)
        parent = """<project>
 <groupId>g</groupId><artifactId>parent</artifactId><version>1</version>
 <dependencyManagement><dependencies>
  %s
  <dependency><groupId>com.fasterxml.jackson</groupId>
   <artifactId>jackson-bom</artifactId><version>2.21.4</version>
   <type>pom</type><scope>import</scope></dependency>
 </dependencies></dependencyManagement>
</project>""" % "\n  ".join(boms)
        jackson_bom = """<project>
 <groupId>com.fasterxml.jackson</groupId><artifactId>jackson-bom</artifactId>
 <version>2.21.4</version>
 <dependencyManagement><dependencies><dependency>
  <groupId>com.fasterxml.jackson.core</groupId>
  <artifactId>jackson-databind</artifactId><version>${project.version}</version>
 </dependency></dependencies></dependencyManagement>
</project>"""
        root = """<project>
 <parent><groupId>g</groupId><artifactId>parent</artifactId><version>1</version></parent>
 <groupId>g</groupId><artifactId>root</artifactId>
 <dependencies><dependency>
  <groupId>com.fasterxml.jackson.core</groupId>
  <artifactId>jackson-databind</artifactId>
 </dependency></dependencies>
</project>"""
        sbom._fetch_maven_pom = lambda g, a, v: (
            parent if a == "parent" else
            jackson_bom if a == "jackson-bom" else None)
        pkgs = sbom._parse_pom_xml(_write_pom(tmp_path, root))
        assert _by_artifact(pkgs)["jackson-databind"] == "2.21.4"
        # parent + jackson-bom only: the unrelated aaa-boms are never walked
        assert len(sbom._fetch_calls) <= 3, sbom._fetch_calls
