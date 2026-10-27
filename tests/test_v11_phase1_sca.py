"""Phase 1 remainder (gap plan 1.3/1.4/1.5): SCA breadth acceptance.

* 1.3 -- every manifest ecosystem flows through OSV normalization
  explicitly (crates.io/Packagist/RubyGems), unresolvable components are
  counted rather than silently dropped, and purls use the purl SPEC's
  types (cargo/composer/gem) for all three.
* 1.4 -- every named SBOM component carries a best-effort CPE 2.3
  identifier, emitted through the native CycloneDX ``cpe`` field and the
  SPDX ``cpe23Type`` external reference.
* 1.5 -- advisories carry per-record provenance (which database published
  them, distinct from who served them), the CDX source honours it, and the
  opt-in NVD CPE-matched secondary pass merges with CVE-identity dedup.
"""

import pytest

import json

from scanner import sbom
from scanner.cpe_builder import build_cpe, derive_vendor_product
from scanner.package_intelligence import build_purl
from scanner.nvd_client import normalize_nvd_cve
from scanner.vulnerability_intel import (
    advisory_origin,
    normalize_osv_vulnerability,
    query_osv_batch,
)
from reporting.cyclonedx_export import (
    _component as cdx_component,
    _purl as cdx_purl,
    _vulnerability_source as cdx_vuln_source,
    build_cyclonedx,
)
from reporting.spdx_export import _pkg_purl as spdx_purl, _external_refs


# ---------------------------------------------------------------------------
# 1.3 -- ecosystem normalization, unresolvable accounting, purl types
# ---------------------------------------------------------------------------


def test_ecosystem_map_covers_every_manifest_parser_emission():
    from scanner.vulnerability_intel import normalize_ecosystem
    # Ecosystem strings emitted by scanner/manifests/* must map explicitly,
    # not survive by coincidence of already being OSV-canonical.
    assert normalize_ecosystem("crates.io") == "crates.io"
    assert normalize_ecosystem("cargo") == "crates.io"
    assert normalize_ecosystem("Packagist") == "Packagist"
    assert normalize_ecosystem("composer") == "Packagist"
    assert normalize_ecosystem("RubyGems") == "RubyGems"
    assert normalize_ecosystem("gem") == "RubyGems"
    assert normalize_ecosystem("PyPI") == "PyPI"
    assert normalize_ecosystem("npm") == "npm"
    assert normalize_ecosystem("Maven") == "Maven"
    assert normalize_ecosystem("Go") == "Go"


def test_query_skips_unresolvable_components_with_a_counter(monkeypatch):
    """VCS/path references (ecosystem 'local') and unknown versions must be
    EXCLUDED from the batch and counted, never shipped to OSV as a query
    that cannot succeed."""
    import scanner.vulnerability_intel as vi
    monkeypatch.setattr(vi, "_load_cache", lambda: {})
    monkeypatch.setattr(vi, "_save_cache", lambda cache: None)
    monkeypatch.setattr(
        vi, "_post_json",
        lambda *a, **k: (_ for _ in ()).throw(
            AssertionError("unresolvable-only run must not hit the network")))

    result = query_osv_batch([
        {"name": "mypkg", "version": "1.0", "ecosystem": "local"},
        {"name": "noranges", "version": "unknown", "ecosystem": "PyPI"},
        {"name": "", "version": "1.0", "ecosystem": "PyPI"},
    ])
    assert result == {}
    assert vi.ADVISORY_SERVICE_STATUS["skipped_unresolvable"] == 3
    assert vi.ADVISORY_SERVICE_STATUS["queries_attempted"] == 0


def test_purl_uses_spec_types_for_new_ecosystems():
    assert build_purl("serde", "1.0.0", "crates.io") == "pkg:cargo/serde@1.0.0"
    assert build_purl("cargo", "1.0.0", "cargo") == "pkg:cargo/cargo@1.0.0"
    assert build_purl("monolog/monolog", "3.0.0", "Packagist") == \
        "pkg:composer/monolog/monolog@3.0.0"
    assert build_purl("rails", "7.0.4", "RubyGems") == "pkg:gem/rails@7.0.4"
    assert build_purl("gem", "1.0.0", "gem") == "pkg:gem/gem@1.0.0"
    # pypi normalization stays lowercase (purl spec).
    assert build_purl("Django", "2.2.0", "PyPI") == "pkg:pypi/django@2.2.0"


def test_cdx_and_spdx_purls_cover_emitted_ecosystem_strings():
    assert cdx_purl({"ecosystem": "crates.io", "name": "serde",
                     "version": "1.0.0"}) == "pkg:cargo/serde@1.0.0"
    assert cdx_purl({"ecosystem": "Packagist", "name": "monolog/monolog",
                     "version": "3.0.0"}) == \
        "pkg:composer/monolog/monolog@3.0.0"
    assert cdx_purl({"ecosystem": "RubyGems", "name": "rails",
                     "version": "7.0.4"}) == "pkg:gem/rails@7.0.4"
    assert cdx_purl({"ecosystem": "Go", "name": "github.com/gin-gonic/gin",
                     "version": "1.9.0"}) == \
        "pkg:golang/github.com/gin-gonic/gin@1.9.0"
    assert spdx_purl({"ecosystem": "crates.io", "name": "serde",
                      "version": "1.0.0"}) == "pkg:cargo/serde@1.0.0"
    assert spdx_purl({"ecosystem": "Packagist", "name": "symfony/console",
                      "version": "6.0"}) == "pkg:composer/symfony/console@6.0"


# ---------------------------------------------------------------------------
# 1.4 -- CPE emission
# ---------------------------------------------------------------------------


def test_cpe_field_count_and_shape():
    cpe = build_cpe("requests", "2.19.1", "PyPI")
    fields = cpe.split(":")
    assert cpe.startswith("cpe:2.3:a:")
    assert len(fields) == 13, cpe  # cpe, 2.3, part, + 10 components


def test_cpe_maven_group_becomes_vendor():
    cpe = build_cpe("org.apache.logging.log4j:log4j-core", "2.14.1", "Maven")
    assert cpe == "cpe:2.3:a:apache:log4j-core:2.14.1:*:*:*:*:*:*:*"
    assert build_cpe("com.google.guava:guava", "31.0", "Maven").split(":")[3] \
        == "google"


def test_cpe_npm_scope_and_unscoped():
    assert build_cpe("@babel/core", "7.0.0", "npm") == \
        "cpe:2.3:a:babel:core:7.0.0:*:*:*:*:*:*:*"
    assert build_cpe("lodash", "4.17.21", "npm") == \
        "cpe:2.3:a:lodash:lodash:4.17.21:*:*:*:*:*:*:*"


def test_cpe_pypi_known_vendor_and_fallback():
    assert build_cpe("requests", "2.19.1", "PyPI") == \
        "cpe:2.3:a:python:requests:2.19.1:*:*:*:*:*:*:*"
    assert build_cpe("django", "2.2.0", "PyPI") == \
        "cpe:2.3:a:djangoproject:django:2.2.0:*:*:*:*:*:*:*"
    # Unlisted packages self-vendor: a valid CPE that still matches NVD
    # product searches, rather than an invented vendor that matches nothing.
    assert build_cpe("SomePkg", "1.0", "PyPI") == \
        "cpe:2.3:a:somepkg:somepkg:1.0:*:*:*:*:*:*:*"


def test_cpe_go_owner_repo():
    assert build_cpe("github.com/gin-gonic/gin", "1.9.0", "Go") == \
        "cpe:2.3:a:gin-gonic:gin:1.9.0:*:*:*:*:*:*:*"


def test_cpe_escapes_wildcards_and_quotes():
    cpe = build_cpe("pkg", '1.0*beta?"', "PyPI")
    assert r"1.0\*beta\?\"" in cpe, cpe


def test_cpe_unknown_version_is_any_and_no_name_is_empty():
    assert build_cpe("lodash", "unknown", "npm").split(":")[5] == "*"
    assert build_cpe("", "1.0", "npm") == ""


def test_derive_vendor_product_never_empty_for_named_package():
    for name, eco in [("foo", "PyPI"), ("x", "npm"), ("g", "Go"),
                      ("a:b", "Maven")]:
        vendor, product = derive_vendor_product(name, eco)
        assert vendor and product


def test_cdx_component_emits_native_cpe_field():
    comp = cdx_component({
        "name": "log4j-core", "version": "2.14.1", "ecosystem": "Maven",
        "cpe": "cpe:2.3:a:apache:log4j-core:2.14.1:*:*:*:*:*:*:*",
    })
    assert comp["cpe"] == "cpe:2.3:a:apache:log4j-core:2.14.1:*:*:*:*:*:*:*"
    # A malformed value must NOT reach the BOM.
    comp2 = cdx_component({"name": "x", "version": "1", "cpe": "nonsense"})
    assert "cpe" not in comp2


def test_spdx_external_refs_include_cpe23():
    refs = _external_refs({
        "name": "log4j-core", "version": "2.14.1", "ecosystem": "Maven",
        "cpe": "cpe:2.3:a:apache:log4j-core:2.14.1:*:*:*:*:*:*:*",
    }, "SPDXRef-1")
    cpe_refs = [r for r in refs if r["referenceType"] == "cpe23Type"]
    assert len(cpe_refs) == 1
    assert cpe_refs[0]["referenceLocator"].startswith("cpe:2.3:a:apache:")


def test_sbom_generates_cpe_for_every_named_component(tmp_path,
                                                     monkeypatch):
    """Acceptance for 1.4 on the real pipeline: a project mixing a
    requirements file with a Cargo.lock yields CPEs on every ecosystem."""
    monkeypatch.setattr(sbom, "enrich_packages_with_external_vulns",
                        lambda pkgs: pkgs)
    (tmp_path / "requirements.txt").write_text("requests==2.19.1\n",
                                               encoding="utf-8")
    (tmp_path / "Cargo.lock").write_text(
        '[[package]]\nname = "serde"\nversion = "1.0.100"\n',
        encoding="utf-8")

    pkgs = sbom.generate_sbom(str(tmp_path))
    by_name = {p["name"]: p for p in pkgs}
    assert by_name["requests"]["cpe"] == \
        "cpe:2.3:a:python:requests:2.19.1:*:*:*:*:*:*:*"
    assert by_name["serde"]["cpe"] == \
        "cpe:2.3:a:serde-rs:serde:1.0.100:*:*:*:*:*:*:*"
    assert all(p.get("cpe", "").startswith("cpe:2.3:")
               for p in pkgs if p.get("name"))


# ---------------------------------------------------------------------------
# 1.5 -- provenance tokens + NVD secondary enrichment
# ---------------------------------------------------------------------------


def test_advisory_origin_from_id_namespace():
    assert advisory_origin("GHSA-jfh8-c2jp-5v3q") == "GitHub"
    assert advisory_origin("CVE-2021-44228") == "NVD"
    assert advisory_origin("PYSEC-2021-34") == "PyPA"
    assert advisory_origin("RUSTSEC-2021-0001") == "RustSec"
    assert advisory_origin("GO-2021-0001") == "Go"
    assert advisory_origin("OSV-2023-123") == "OSV"


def test_normalized_osv_record_carries_origin_and_provider():
    rec = normalize_osv_vulnerability({
        "id": "GHSA-jfh8-c2jp-5v3q",
        "aliases": ["CVE-2021-44228"],
        "summary": "log4shell",
    })
    # Provenance: the GitHub Advisory DB OWNS the record; OSV merely
    # served it. The CVE alias must not erase that.
    assert rec["source"] == "GitHub"
    assert rec["advisory_origin"] == "GitHub"
    assert rec["provider"] == "OSV"
    assert rec["cve"] == "CVE-2021-44228"


def test_cdx_vulnerability_source_honours_record_provenance():
    record = {
        "cve": "CVE-2021-44228", "advisory_id": "GHSA-jfh8-c2jp-5v3q",
        "id": "GHSA-jfh8-c2jp-5v3q",
        "advisory_origin": "GitHub", "source": "GitHub", "provider": "OSV",
    }
    src = cdx_vuln_source(record)
    assert src["name"] == "GitHub Security Advisory"
    assert "GHSA-jfh8-c2jp-5v3q" in src["url"]

    # PyPA/RustSec/Go origins are named, not flattened to "R-SecOpsX".
    pypa = cdx_vuln_source({"advisory_id": "PYSEC-2021-34",
                            "advisory_origin": "PyPA", "source": "PyPA"})
    assert "PyPA" in pypa["name"]

    # Legacy records without provenance keep the prefix fallback.
    assert cdx_vuln_source({"cve": "CVE-2021-44228"})["name"] == "NVD"


def test_nvd_normalize_maps_onto_the_advisory_record_shape():
    from scanner.nvd_client import normalize_nvd_cve
    item = {
        "cve": {
            "id": "CVE-2022-22965",
            "published": "2022-03-31T00:00:00",
            "lastModified": "2022-04-01T00:00:00",
            "descriptions": [{"lang": "en", "value": "spring4shell"}],
            "metrics": {"cvssMetricV31": [{
                "type": "Primary",
                "cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL",
                             "version": "3.1",
                             "vectorString": "CVSS:3.1/AV:N/AC:L"},
            }]},
        },
    }
    rec = normalize_nvd_cve(item, "cpe:2.3:a:spring:spring:*:*:*:*:*:*:*:*")
    assert rec["cve"] == "CVE-2022-22965"
    assert rec["severity"] == "Critical"
    assert rec["cvss"] == 9.8
    assert rec["source"] == "NVD" and rec["provider"] == "NVD"
    # The report must be able to say HOW identity was established: an NVD
    # CPE virtual match is a range match, not an exact-version query.
    assert rec["matching_method"] == "nvd_cpe_virtual_match"


def test_nvd_client_fails_open_and_discloses(tmp_path, monkeypatch):
    import scanner.nvd_client as nvd
    monkeypatch.setattr(nvd, "NVD_CACHE_FILE", tmp_path / "nvd_cache.json")
    nvd.NVD_SERVICE_STATUS.clear()

    def _boom(req, timeout=None):
        raise OSError("connection refused")

    monkeypatch.setattr(nvd.urllib.request, "urlopen",
                        lambda req, timeout=None, *a, **k: _boom(req))
    assert nvd.query_nvd_by_cpe("cpe:2.3:a:python:requests:*:*:*:*:*:*:*:*") == []
    assert nvd.NVD_SERVICE_STATUS["available"] is False
    assert nvd.NVD_SERVICE_STATUS["failures"][0]["error_type"] == "OSError"

    # Non-CPE input never reaches the network at all.
    assert nvd.query_nvd_by_cpe("") == []
    assert nvd.query_nvd_by_cpe("pkg:npm/lodash@4.17.21") == []


def test_nvd_client_zero_results_is_an_answer_not_an_error(tmp_path,
                                                           monkeypatch):
    """The NVD omits the vulnerabilities list entirely on zero matches; that
    must count as an answered query (and be cached), never as a shape
    error."""
    import scanner.nvd_client as nvd
    monkeypatch.setattr(nvd, "NVD_CACHE_FILE", tmp_path / "nvd_cache.json")
    nvd.NVD_SERVICE_STATUS.clear()

    body = json.dumps({"totalResults": 0}).encode()

    class _Resp:
        def read(self):
            return body

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    monkeypatch.setattr(
        nvd.urllib.request, "urlopen",
        lambda req, timeout=None, *a, **k: _Resp())
    assert nvd.query_nvd_by_cpe("cpe:2.3:a:x:y:*:*:*:*:*:*:*:*") == []
    assert nvd.NVD_SERVICE_STATUS["available"] is True
    assert nvd.NVD_SERVICE_STATUS["queries_answered"] == 1
    assert nvd.NVD_SERVICE_STATUS["failures"] == []
    # The empty answer is cached: a second call must not hit the network.
    monkeypatch.setattr(
        nvd.urllib.request, "urlopen",
        lambda req, timeout=None, *a, **k: (_ for _ in ()).throw(
            AssertionError("cached empty answer must not re-query")))
    assert nvd.query_nvd_by_cpe("cpe:2.3:a:x:y:*:*:*:*:*:*:*:*") == []


def test_nvd_enrichment_merges_with_cve_identity_dedup(tmp_path, monkeypatch):
    """The NVD pass only contributes CVEs OSV did not already report; a CVE
    OSV carries must not appear twice wearing two provenance labels."""
    import scanner.vulnerability_intel as vi
    import scanner.nvd_client as nvd
    monkeypatch.setenv("RSX_NVD_ENRICH", "1")
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    monkeypatch.setattr(nvd, "NVD_CACHE_FILE", tmp_path / "nvd_cache.json")

    osv_ghsa = normalize_osv_vulnerability({
        "id": "GHSA-jfh8-c2jp-5v3q",
        "aliases": ["CVE-2021-44228"],
        "summary": "log4shell",
        "published": "2021-12-10",
        "severity": "CRITICAL",
    })
    monkeypatch.setattr(
        vi, "query_osv_batch",
        lambda pkgs: {"PyPI|log4jpy|1.0": [osv_ghsa]})

    nvd_unique = dict(normalize_nvd_cve(
        {"cve": {"id": "CVE-2020-9999",
                 "descriptions": [{"lang": "en", "value": "other"}]}},
        "cpe:2.3:a:x:y:*:*:*:*:*:*:*:*"))
    nvd_dup = dict(nvd_unique, **{"cve": "CVE-2021-44228"})
    seen_cpes = []

    def _fake_query(cpe):
        seen_cpes.append(cpe)
        return [nvd_dup, nvd_unique]

    monkeypatch.setattr(nvd, "query_nvd_by_cpe", _fake_query)

    pkgs = [{"name": "log4jpy", "version": "1.0", "ecosystem": "PyPI"}]
    vi.enrich_packages_with_external_vulns(pkgs)

    cves = [v["cve"] for v in pkgs[0]["vulnerabilities"]]
    assert cves.count("CVE-2021-44228") == 1, cves  # deduplicated
    assert "CVE-2020-9999" in cves                   # genuinely new
    assert pkgs[0]["vulnerability_source"] == "OSV+NVD"
    origins = {v["cve"]: v["advisory_origin"]
               for v in pkgs[0]["vulnerabilities"]}
    assert origins["CVE-2021-44228"] == "GitHub"   # OSV's record kept
    assert origins["CVE-2020-9999"] == "NVD"
    # The CPE used for the virtual match was a real CPE 2.3 application key.
    assert seen_cpes and seen_cpes[0].startswith("cpe:2.3:a:")


def test_stale_cache_records_get_provenance_backfilled(monkeypatch):
    """Records cached before the provenance fields existed carry no
    advisory_origin; it is derivable from the id, so it must be backfilled
    at read time instead of forcing a network refetch."""
    import scanner.vulnerability_intel as vi
    stale = {"id": "RUSTSEC-2021-0139", "advisory_id": "RUSTSEC-2021-0139",
             "published": "2021-05-01", "severity": "Medium"}
    monkeypatch.setattr(
        vi, "query_osv_batch",
        lambda pkgs: {"crates.io|ansi_term|0.12.1": [stale]})
    monkeypatch.delenv("RSX_NVD_ENRICH", raising=False)

    pkgs = [{"name": "ansi_term", "version": "0.12.1",
             "ecosystem": "crates.io"}]
    vi.enrich_packages_with_external_vulns(pkgs)
    rec = pkgs[0]["vulnerabilities"][0]
    assert rec["advisory_origin"] == "RustSec"
    assert rec["source"] == "RustSec"
    assert rec["provider"] == "OSV"


def test_nvd_enrichment_disabled_by_default(tmp_path, monkeypatch):
    """No env flag -> no NVD budget spent, no network path entered."""
    import scanner.vulnerability_intel as vi
    monkeypatch.delenv("RSX_NVD_ENRICH", raising=False)
    monkeypatch.setattr(
        vi, "query_osv_batch", lambda pkgs: {})
    called = []

    import scanner.nvd_client as nvd
    monkeypatch.setattr(nvd, "query_nvd_by_cpe",
                        lambda cpe: called.append(cpe) or [])

    pkgs = [{"name": "requests", "version": "2.19.1", "ecosystem": "PyPI"}]
    vi.enrich_packages_with_external_vulns(pkgs)
    assert called == []
    assert pkgs[0].get("vulnerabilities") is None
