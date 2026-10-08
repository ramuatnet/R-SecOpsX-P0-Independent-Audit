"""Tests for the SPDX 2.3 exporter.

The schema declares ``additionalProperties: false`` at the document level and on
every package, so the failure mode this file is really about is producing a
document that looks fine and is rejected by a consumer. Most assertions below are
therefore about forbidden keys, required keys, closed enums, and identifier
uniqueness -- not about whether the output "looks reasonable".

The three honesty properties are pinned separately at the end, because they are
the ones that would let the document assert things that never happened.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from reporting.spdx_export import (  # noqa: E402
    NOASSERTION,
    SPDX_DATA_LICENSE,
    SPDX_DOCUMENT_ID,
    SPDX_VERSION,
    _real_version,
    build_spdx,
    validate_spdx,
    write_spdx_report,
)

ART = Path(r"C:\Users\janan\AppData\Local\Temp\opencode\artifact_1914_snapshot\clean_report.json")


@pytest.fixture(scope="module")
def payload():
    if not ART.exists():
        pytest.skip("Juice Shop artifact snapshot not present")
    return json.loads(ART.read_text(encoding="utf-8", errors="replace"))


@pytest.fixture(scope="module")
def doc(payload):
    return build_spdx(payload)


# ===========================================================================
# Document identity
# ===========================================================================

def test_required_document_keys_are_present(doc):
    for key in ("SPDXID", "creationInfo", "dataLicense", "name", "spdxVersion"):
        assert key in doc, key
    assert doc["spdxVersion"] == SPDX_VERSION == "SPDX-2.3"
    assert doc["dataLicense"] == SPDX_DATA_LICENSE == "CC0-1.0"
    assert doc["SPDXID"] == SPDX_DOCUMENT_ID


def test_data_license_is_cc0_and_not_configurable(doc):
    """SPX requires SPDX metadata to be CC0. Making it configurable would let a
    caller emit a document the specification forbids."""
    assert doc["dataLicense"] == "CC0-1.0"


def test_creation_info_has_creators_and_created(doc):
    ci = doc["creationInfo"]
    assert ci.get("created")
    assert re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$", ci["created"])
    assert ci["creators"] and any("R-SecOpsX" in c for c in ci["creators"])


def test_document_namespace_is_an_absolute_unique_uri(doc):
    ns = doc["documentNamespace"]
    assert ns.startswith("https://")
    other = build_spdx(doc and {"metadata": {"project_name": "different"}})
    assert other["documentNamespace"] != ns


# ===========================================================================
# Schema conformance -- the reason this exporter validates before writing
# ===========================================================================

def test_document_validates_against_the_pinned_rules(doc):
    problems = validate_spdx(doc)
    assert problems == [], problems


def test_validator_rejects_a_forbidden_document_property(doc):
    """NEGATIVE: `additionalProperties: false` at the document level means a
    vendor extension block makes the document invalid."""
    bad = dict(doc)
    bad["rsecopsx"] = {"custom": True}
    problems = validate_spdx(bad)
    assert any("forbids" in p for p in problems), problems


def test_validator_rejects_a_forbidden_package_property(doc):
    bad = json.loads(json.dumps(doc))
    bad["packages"][0]["customField"] = 1
    problems = validate_spdx(bad)
    assert any("forbidden properties" in p for p in problems), problems


def test_validator_rejects_a_missing_required_package_key(doc):
    bad = json.loads(json.dumps(doc))
    del bad["packages"][0]["downloadLocation"]
    problems = validate_spdx(bad)
    assert any("downloadLocation" in p for p in problems), problems


def test_validator_rejects_a_relationship_type_outside_the_enum(doc):
    """NEGATIVE: an invented relationshipType is rejected by real consumers."""
    bad = json.loads(json.dumps(doc))
    bad["relationships"][0]["relationshipType"] = "TOTALLY_MADE_UP"
    problems = validate_spdx(bad)
    assert any("enum" in p for p in problems), problems


def test_validator_rejects_a_dangling_relationship_target(doc):
    bad = json.loads(json.dumps(doc))
    bad["relationships"][0]["relatedSpdxElement"] = "SPDXRef-Package-does-not-exist"
    problems = validate_spdx(bad)
    assert any("unknown id" in p for p in problems), problems


def test_validator_rejects_a_bad_annotation_type(doc):
    bad = json.loads(json.dumps(doc))
    bad["annotations"][0]["annotationType"] = "CRITICAL"
    problems = validate_spdx(bad)
    assert any("annotationType" in p for p in problems), problems


def test_validator_rejects_duplicate_spdxids(doc):
    bad = json.loads(json.dumps(doc))
    bad["packages"][1]["SPDXID"] = bad["packages"][0]["SPDXID"]
    problems = validate_spdx(bad)
    assert any("duplicate SPDXID" in p for p in problems), problems


def test_write_refuses_to_emit_an_invalid_document(tmp_path, monkeypatch):
    """The write path must not paper over a validation failure.

    `build_spdx` only produces valid documents, so the invalid case is injected
    at the validator boundary: what is under test is that `write_spdx_report`
    raises rather than writing a document it just proved invalid.
    """
    import reporting.spdx_export as sx

    monkeypatch.setattr(sx, "validate_spdx", lambda d: ["injected failure"])
    with pytest.raises(ValueError) as exc:
        sx.write_spdx_report({}, str(tmp_path / "bad.spdx.json"))
    assert "injected failure" in str(exc.value)
    assert not (tmp_path / "bad.spdx.json").exists(), "an invalid document was written"


# ===========================================================================
# Packages
# ===========================================================================

def test_every_sbom_component_becomes_a_package(payload, doc):
    assert len(doc["packages"]) == len(payload.get("sbom") or [])


def test_document_describes_matches_the_package_ids(doc):
    assert set(doc["documentDescribes"]) == {p["SPDXID"] for p in doc["packages"]}


def test_every_package_has_a_describes_relationship(doc):
    described = {
        r["relatedSpdxElement"] for r in doc["relationships"]
        if r["relationshipType"] == "DESCRIBES"
        and r["spdxElementId"] == SPDX_DOCUMENT_ID
    }
    assert described == {p["SPDXID"] for p in doc["packages"]}


def test_spdxids_are_injective_over_the_real_corpus(doc):
    """NEGATIVE: an SPDXID derived only from a truncated name collapses every
    component that differs only in characters the legal charset drops."""
    ids = [p["SPDXID"] for p in doc["packages"]]
    assert len(ids) == len(set(ids))
    for sid in ids:
        assert re.match(r"^SPDXRef-Package-[A-Za-z0-9.\-]+$", sid), sid


def test_spdxids_stay_legal_with_awkward_package_names():
    """Scoped npm names carry '@' and '/', which SPDXID forbids."""
    d = build_spdx({"sbom": [
        {"name": "@scope/pkg", "version": "1.0.0", "ecosystem": "npm"},
        {"name": "@scope/pkg", "version": "1.0.1", "ecosystem": "npm"},
        {"name": "@other/pkg", "version": "1.0.0", "ecosystem": "npm"},
    ]})
    ids = [p["SPDXID"] for p in d["packages"]]
    assert len(set(ids)) == 3
    assert validate_spdx(d) == []


# ===========================================================================
# HONESTY PROPERTY 1 -- unpinned versions are not filled with a placeholder
# ===========================================================================

def test_placeholder_version_is_treated_as_absent():
    for bad in ("unknown", "UNKNOWN", "none", "null", "n/a", "", "  ", "*"):
        assert _real_version({"version": bad}) == ""


def test_a_real_version_is_kept():
    assert _real_version({"version": "0.4.0"}) == "0.4.0"
    assert _real_version({"resolved_version": "1.2.3"}) == "1.2.3"


def test_no_package_ships_a_placeholder_as_its_version(doc):
    """NEGATIVE: 162 of 168 Juice Shop components are unpinned. Writing
    versionInfo='unknown' would put a fabricated version into a package
    identity and is exactly what NOASSERTION semantics exist to prevent."""
    for p in doc["packages"]:
        assert p.get("versionInfo") != "unknown"
        if p.get("versionInfo"):
            assert p["versionInfo"] not in ("unknown", "none", "null", "n/a", "")


def test_unpinned_packages_say_so_in_the_comment(doc):
    unpinned = [p for p in doc["packages"] if not p.get("versionInfo")]
    assert unpinned, "expected some unpinned components on this corpus"
    for p in unpinned:
        assert "version not pinned" in (p.get("comment") or "")


# ===========================================================================
# HONESTY PROPERTY 2 -- filesAnalyzed is never true
# ===========================================================================

def test_files_analyzed_is_false_on_every_package(doc):
    """NEGATIVE: R-SecOpsX reads a manifest. It never unpacks a package. Claiming
    file-level analysis would make any consumer's file-level inference unsound.
    """
    for p in doc["packages"]:
        assert p.get("filesAnalyzed") is False, p["name"]


def test_no_package_carries_a_verification_code(doc):
    for p in doc["packages"]:
        assert "packageVerificationCode" not in p


def test_source_info_states_packages_were_not_downloaded(doc):
    for p in doc["packages"][:20]:
        assert "not downloaded" in p.get("sourceInfo", "")


# ===========================================================================
# HONESTY PROPERTY 3 -- unknown values are NOASSERTION, never invented
# ===========================================================================

def test_download_location_is_noassertion_or_a_real_url(payload, doc):
    for p in doc["packages"]:
        loc = p["downloadLocation"]
        assert loc == NOASSERTION or loc.startswith(("http://", "https://")), loc


def test_no_registry_url_is_synthesised(doc):
    """NEGATIVE: a plausible-looking npmjs.com URL for a package this tool never
    contacted is a fabrication."""
    assert not any("npmjs.com" in p["downloadLocation"] for p in doc["packages"])


def test_a_real_download_location_is_used_when_present():
    d = build_spdx({"sbom": [{
        "name": "x", "version": "1", "ecosystem": "npm",
        "download_location": "https://registry.npmjs.org/x/-/x-1.tgz",
    }]})
    assert d["packages"][0]["downloadLocation"] == "https://registry.npmjs.org/x/-/x-1.tgz"


def test_license_concluded_is_always_noassertion(doc):
    """NEGATIVE: this tool never reviewed a package's licence text, so it must
    not state a concluded licence."""
    for p in doc["packages"]:
        assert p["licenseConcluded"] == NOASSERTION


def test_license_declared_falls_back_to_noassertion_not_a_guess():
    d = build_spdx({"sbom": [{"name": "x", "version": "1", "license": "UNKNOWN"}]})
    assert d["packages"][0]["licenseDeclared"] == NOASSERTION


def test_copyright_text_is_noassertion_when_absent(doc):
    for p in doc["packages"][:30]:
        assert p["copyrightText"] == NOASSERTION


# ===========================================================================
# Vulnerability evidence
# ===========================================================================

def test_vulnerable_components_carry_an_annotation(payload, doc):
    """The whole point of emitting SPDX for a security tool: a consumer must be
    able to see which components are known-vulnerable."""
    vulns = [p for p in payload.get("sbom") or []
             if p.get("cve") or p.get("cve_list")]
    assert vulns, "expected vulnerable components on this corpus"
    annotated = [p for p in doc["packages"] if p.get("annotations")]
    assert len(annotated) == len(vulns), (len(annotated), len(vulns))


def test_vulnerability_annotation_names_the_advisories_and_reachability(doc):
    e = [p for p in doc["packages"] if p["name"] == "jsonwebtoken"]
    assert e, "jsonwebtoken should be in the SBOM"
    comment = e[0]["annotations"][0]["comment"]
    assert "CVE-2015-9235" in comment
    assert "reachability" in comment
    assert "no package was downloaded or executed" in comment


def test_cvss_is_reported_only_when_the_payload_carries_one():
    """NEGATIVE: this sbom entry has four advisories with per-advisory scores and
    no single top-level CVSS, so none is emitted. Picking the highest would be a
    judgement the payload did not record."""
    d = build_spdx({"sbom": [{
        "name": "x", "version": "1", "ecosystem": "npm", "cve": "CVE-2020-1",
    }]})
    comment = d["packages"][0]["annotations"][0]["comment"]
    assert "cvss" not in comment

    d2 = build_spdx({"sbom": [{
        "name": "x", "version": "1", "ecosystem": "npm",
        "cve": "CVE-2020-1", "cvss_score": 7.5,
    }]})
    assert "cvss: 7.5" in d2["packages"][0]["annotations"][0]["comment"]


def test_a_clean_component_gets_no_reassuring_annotation(doc):
    """NEGATIVE: 'nothing to report' is not evidence of safety, so a clean
    package must get no annotation rather than a comforting one."""
    vulns = {p["name"] for p in doc["packages"] if p.get("annotations")}
    assert len(vulns) < len(doc["packages"]), "expected some unannotated components"
    for p in doc["packages"]:
        if p["name"] not in vulns:
            assert not p.get("annotations")


def test_security_external_refs_are_emitted_for_cve_components(doc):
    e = [p for p in doc["packages"] if p["name"] == "express-jwt"][0]
    refs = e.get("externalRefs") or []
    cats = {r["referenceCategory"] for r in refs}
    assert "PACKAGE-MANAGER" in cats
    assert "SECURITY" in cats


def test_purl_external_ref_locator_is_a_purl(doc):
    for p in doc["packages"]:
        for r in (p.get("externalRefs") or []):
            if r["referenceType"] == "purl":
                assert r["referenceLocator"].startswith("pkg:"), r
                assert " " not in r["referenceLocator"]


# ===========================================================================
# Document annotation: the verdict, and what it must NOT claim
# ===========================================================================

def test_document_annotation_states_the_scope_limits(doc):
    comment = doc["annotations"][0]["comment"]
    assert "filesAnalyzed is false" in comment
    assert "NO COMPLIANCE ATTESTATION" in comment


def test_document_annotation_reports_disposition_counts(payload, doc):
    """The per-finding disposition G-090 added must reach the machine-readable
    export, not just the PDF."""
    comment = doc["annotations"][0]["comment"]
    assert "sast findings" in comment
    assert "reportable" in comment
    assert "decision state not recorded" in comment


def test_document_annotation_makes_no_provenance_claim(doc):
    """NEGATIVE and load-bearing: V11 is not the builder of the software it
    scans. SLSA/in-toto provenance is deliberately absent and must stay absent.

    The words may appear ONLY inside the sentence that disclaims them. That is
    the difference between documenting an omission and making a claim, so the
    assertion is positional rather than a bare substring search.
    """
    comment = doc["creationInfo"]["comment"]
    assert "cannot attest how it was built" in comment
    # Split on sentence-final periods only. Splitting on ':' as well would break
    # "...is included:" into a fragment with no verb and no disclaimer signal.
    for token in ("slsa", "in-toto", "provenance"):
        for sentence in re.split(r"(?<=\.)\s+", comment):
            if token in sentence.lower():
                low = sentence.lower()
                assert ("is not included" in low or "no " in low[:20]
                        or "cannot attest" in low), (
                    f"{token!r} appears outside a disclaimer: {sentence!r}")

    # SPDX has no provenance field, so there is nowhere for a claim to hide.
    text = json.dumps(doc).lower()
    for forbidden in ("provenance_predicate", "slsa_provenance", "attestation_predicate"):
        assert forbidden not in text


def test_document_annotation_states_the_release_decision(payload, doc):
    rr = payload.get("release_readiness") or {}
    if rr.get("release_decision"):
        assert rr["release_decision"] in doc["annotations"][0]["comment"]


# ===========================================================================
# Dependency relationships
# ===========================================================================

def test_only_verified_edges_become_relationships(payload, doc):
    """NEGATIVE: an inferred dependency edge would be a wrong claim about the
    dependency graph. The Juice Shop graph verified 0 edges, so 0 must appear."""
    graph = payload.get("dependency_graph") or {}
    verified = graph.get("verified_edges") or graph.get("edges") or []
    dep_rels = [r for r in doc["relationships"] if r["relationshipType"] == "DEPENDS_ON"]
    assert len(dep_rels) <= len(verified)


def test_a_verified_edge_is_emitted_when_both_endpoints_resolve():
    d = build_spdx({
        "sbom": [
            {"name": "a", "version": "1.0.0", "ecosystem": "npm"},
            {"name": "b", "version": "2.0.0", "ecosystem": "npm"},
        ],
        "dependency_graph": {"verified_edges": [
            {"from": "a", "from_version": "1.0.0", "to": "b", "to_version": "2.0.0"},
        ]},
    })
    rels = [r for r in d["relationships"] if r["relationshipType"] == "DEPENDS_ON"]
    assert len(rels) == 1
    assert validate_spdx(d) == []


def test_an_edge_to_an_unknown_component_is_skipped_not_invented():
    d = build_spdx({
        "sbom": [{"name": "a", "version": "1.0.0", "ecosystem": "npm"}],
        "dependency_graph": {"verified_edges": [
            {"from": "a", "from_version": "1.0.0", "to": "ghost", "to_version": "9"},
        ]},
    })
    assert [r for r in d["relationships"] if r["relationshipType"] == "DEPENDS_ON"] == []
    assert validate_spdx(d) == []


# ===========================================================================
# Degenerate inputs
# ===========================================================================

def test_empty_payload_still_produces_a_valid_document():
    d = build_spdx({})
    assert validate_spdx(d) == []
    assert d["packages"] == []
    assert d["documentDescribes"] == []


def test_malformed_sbom_entries_are_skipped():
    d = build_spdx({"sbom": [None, {}, {"name": ""}, {"name": "ok", "version": "1"}]})
    assert len(d["packages"]) == 1
    assert validate_spdx(d) == []


def test_write_produces_parseable_json(payload, tmp_path):
    out = write_spdx_report(payload, str(tmp_path / "s.spdx.json"))
    parsed = json.loads(Path(out).read_text(encoding="utf-8"))
    assert parsed["spdxVersion"] == "SPDX-2.3"
    assert parsed["packages"]


# ===========================================================================
# Conformance probe wiring
# ===========================================================================

def test_spdx_probe_has_a_matching_production_source():
    from analysis.benchmark_conformance_baseline import STANDARD_BASELINE
    from core.conformance_baseline import production_sources

    sources = production_sources(ROOT)
    std = next(s for s in STANDARD_BASELINE if s["key"] == "SUPPLY_CHAIN")
    probe = next(p for p in std["probes"] if p["name"] == "spdx_export")
    hits = [rel for rel, text in sources.items() if re.search(probe["pattern"], text)]
    assert hits, "the spdx_export probe matches no production source"


def test_main_emits_the_spdx_artifact():
    main_src = (ROOT / "main.py").read_text(encoding="utf-8")
    assert "write_spdx_report" in main_src
    assert "Security_SPDX.spdx.json" in main_src