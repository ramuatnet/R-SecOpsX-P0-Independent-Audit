"""Regression tests: trust and exposure signals read declaration fields only.

Both engines used to evaluate their regexes over the ENTIRE sbom record.
That matched text which merely *describes* a package, not how it is
declared or resolved:

* the CPE builder (V1.11) stamps ``cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*``
  onto every component -- its wildcards satisfy the UNPINNED ``\\*`` pattern,
  so 822 of 823 components of a production scan were reported UNPINNED/HIGH
  (``unpinned_dependencies: 823`` in SARIF/XLSX, a SUPPLY_CHAIN_TRUST_RISK
  release gate included);
* advisory prose ("upgrade to the **latest** version", a github.com advisory
  link, a ``../`` example, ``/admin`` and ``:9200`` inside impact text)
  satisfied the remaining trust patterns;
* a component literally NAMED dotenv satisfied ENV_EXPOSURE at CRITICAL;
* ``published_date`` on a record holds the ADVISORY's publication date
  (written by vulnerability_age_engine), so every newly disclosed CVE was
  counted as RECENTLY_PUBLISHED_PACKAGE freshness risk.

The fixes: each pattern is scoped to the fields where its condition can be
true (declaration / resolution / name), the component exposure scan reads
only surface-declaration fields, and freshness reads only package-release
keys.  These tests pin both the positive controls and the FP regressions.
"""
from __future__ import annotations

from analysis.exposure_surface_engine import enrich_exposure_surface_intelligence
from analysis.supply_chain_trust_engine import (
    _is_unpinned_version,
    _looks_recent,
    enrich_supply_chain_trust,
)


def _describe_only_package(name: str = "left-pad") -> dict:
    """A pinned package whose descriptive fields match every trust pattern."""
    return {
        "name": name,
        "version": "6.1.0",
        "ecosystem": "npm",
        "cpe": "cpe:2.3:a:vendor:pkg:6.1.0:*:*:*:*:*:*:*",
        "purl": f"pkg:npm/{name}@6.1.0",
        "description": (
            "Upgrade to the latest version. See "
            "https://github.com/adaltas/node-csv/security/advisories/GHSA-x "
            "for details; a ../ path example at http://127.0.0.1/."
        ),
        "vulnerabilities": [
            {
                "id": "GHSA-xxxx-yyyy-zzzz",
                "details": (
                    "Users should upgrade to the latest release. "
                    "Advisory: https://github.com/org/repo/security, "
                    "config written to ../output via http://example.test."
                ),
            }
        ],
    }


# --------------------------------------------------------------------------
# supply_chain_trust_engine
# --------------------------------------------------------------------------

def test_cpe_wildcards_and_advisory_prose_produce_no_trust_indicators():
    pkg = _describe_only_package()
    enriched, summary = enrich_supply_chain_trust([pkg])

    assert enriched[0]["supply_chain_trust_intelligence"]["indicators"] == []
    assert enriched[0]["supply_chain_trust_intelligence"]["risk_level"] == "NONE"
    assert summary["total_supply_chain_trust_indicators"] == 0
    assert summary["unpinned_dependencies"] == 0
    assert summary["git_dependencies"] == 0
    assert summary["mutable_tags"] == 0
    assert summary["high_affected_components"] == 0
    assert summary["unique_high_component_risks"] == 0
    assert summary["summary_status"] == "NO_SUPPLY_CHAIN_TRUST_RISK_IDENTIFIED"


def test_unpinned_range_in_version_is_still_counted():
    pkg = {"name": "a", "version": "latest", "ecosystem": "npm"}
    enriched, summary = enrich_supply_chain_trust([pkg])

    names = {i["indicator"] for i in
             enriched[0]["supply_chain_trust_intelligence"]["indicators"]}
    assert "UNPINNED_VERSION" in names
    assert summary["unpinned_dependencies"] == 1
    assert summary["high_affected_components"] == 1
    assert summary["summary_status"] == "SUPPLY_CHAIN_TRUST_RISK_IDENTIFIED"


def test_caret_range_in_declared_range_is_unpinned():
    pkg = {"name": "b", "version": "unknown",
           "declared_range": "^1.2.3", "ecosystem": "npm"}
    _, summary = enrich_supply_chain_trust([pkg])
    assert summary["unpinned_dependencies"] == 1


def test_git_resolution_url_is_still_detected():
    pkg = {"name": "c", "version": "1.0.0",
           "resolved": "git+ssh://git@github.com/org/repo.git"}
    enriched, summary = enrich_supply_chain_trust([pkg])

    names = {i["indicator"] for i in
             enriched[0]["supply_chain_trust_intelligence"]["indicators"]}
    assert "GIT_DEPENDENCY" in names
    assert summary["git_dependencies"] == 1


def test_go_module_path_in_name_is_not_a_git_dependency():
    # github.com in a module path is identity, not a git checkout spec.
    pkg = {"name": "github.com/gin-gonic/gin", "version": "v1.9.1"}
    _, summary = enrich_supply_chain_trust([pkg])
    assert summary["git_dependencies"] == 0
    assert summary["total_supply_chain_trust_indicators"] == 0


def test_name_hygiene_patterns_use_the_name_field():
    scoped, summary_a = enrich_supply_chain_trust(
        [{"name": "@internal/tools", "version": "1.0.0"}])
    names = {i["indicator"] for i in
             scoped[0]["supply_chain_trust_intelligence"]["indicators"]}
    assert "PRIVATE_NAMESPACE_HINT" in names
    assert summary_a["private_namespace_hints"] == 1

    tmp, summary_b = enrich_supply_chain_trust(
        [{"name": "scratch-tmp", "version": "1.0.0"}])
    names = {i["indicator"] for i in
             tmp[0]["supply_chain_trust_intelligence"]["indicators"]}
    assert "SUSPICIOUS_NAME_PATTERN" in names
    assert summary_b["total_supply_chain_trust_indicators"] >= 1


def test_advisory_published_date_is_not_package_freshness():
    # published_date carries the ADVISORY date on this platform.
    pkg = {"name": "d", "version": "1.0.0",
           "published_date": "2026-10-10T00:00:00Z"}
    enriched, summary = enrich_supply_chain_trust([pkg])

    names = {i["indicator"] for i in
             enriched[0]["supply_chain_trust_intelligence"]["indicators"]}
    assert "RECENTLY_PUBLISHED_PACKAGE" not in names
    assert summary["recent_packages"] == 0


def test_package_release_date_still_counts_as_freshness():
    pkg = {"name": "e", "version": "1.0.0",
           "release_date": "2026-10-10T00:00:00Z"}
    enriched, summary = enrich_supply_chain_trust([pkg])

    names = {i["indicator"] for i in
             enriched[0]["supply_chain_trust_intelligence"]["indicators"]}
    assert "RECENTLY_PUBLISHED_PACKAGE" in names
    assert summary["recent_packages"] == 1
    recent = next(i for i in enriched[0]["supply_chain_trust_intelligence"]
                  ["indicators"] if i["indicator"] == "RECENTLY_PUBLISHED_PACKAGE")
    assert recent["evidence_match"] == "2026-10-10T00:00:00Z"


def test_is_unpinned_version_matrix():
    for value in (None, "", "*", "latest", "unknown", ">=1.0", "^2.0.0", "1.x"):
        assert _is_unpinned_version(value) is True, value
    for value in ("1.2.3", "v1.9.1", "2.0.0-rc.1"):
        assert _is_unpinned_version(value) is False, value


def test_looks_recent_ignores_missing_and_advisory_dates():
    assert _looks_recent({}) is False
    assert _looks_recent({"published_date": "2026-10-10T00:00:00Z"}) is False
    assert _looks_recent({"release_date": "2026-10-10T00:00:00Z"}) is True


# --------------------------------------------------------------------------
# exposure_surface_engine
# --------------------------------------------------------------------------

def test_dotenv_name_and_advisory_prose_produce_no_component_exposure():
    pkg = _describe_only_package(
        name="@adaline/gateway/node_modules/dotenv")
    pkg["vulnerabilities"][0]["details"] += " bypass /admin and hit :9200."

    enriched, summary = enrich_exposure_surface_intelligence([pkg])

    intel = enriched[0]["exposure_surface_intelligence"]
    assert intel["exposure_surface_detected"] is False
    assert intel["indicators"] == []
    assert summary["component_exposure_indicators"] == 0
    assert summary["critical_affected_components"] == 0
    assert summary["high_affected_components"] == 0


def test_surface_declaration_field_is_still_evaluated():
    pkg = {"name": "f", "version": "1.0.0",
           "homepage": "http://10.0.0.5:9229/debug"}
    enriched, summary = enrich_exposure_surface_intelligence([pkg])

    names = {i["indicator"] for i in
             enriched[0]["exposure_surface_intelligence"]["indicators"]}
    assert "DEBUG_PORT_EXPOSED" in names
    assert summary["component_exposure_indicators"] >= 1


def test_global_finding_context_still_scanned_as_whole_text():
    findings = [{"file": "app.py", "snippet": "mount docs/swagger-ui/index.html"}]
    _, summary = enrich_exposure_surface_intelligence([], findings=findings)

    names = {i["indicator"] for i in summary["global_indicators"]}
    assert "SWAGGER_UI_EXPOSED" in names
    assert summary["global_exposure_indicators"] >= 1
