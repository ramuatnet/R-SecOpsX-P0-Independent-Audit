"""Tests for OWASP ASVS v4.0.3 requirement-level mapping.

The negative assertions are the point. ASVS is a verification standard, so the
two easy ways to be wrong are (a) calling a mapped requirement an unmet one, and
(b) presenting a reachability ratio as a compliance score. Both would convert a
finding into a compliance verdict that no source scan is entitled to make.

Provenance is asserted too: the catalogue is generated from a pinned upstream
CSV, so the digest is pinned here and a future edit to the tables without a
regeneration is detectable.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core.asvs_mappings import (  # noqa: E402
    ASVS_BY_CWE,
    ASVS_BY_VULN_TYPE,
    ASVS_CATALOGUE_SENTINEL,
    ASVS_CHAPTERS,
    ASVS_CSV_SHA256,
    ASVS_DATASET_LABEL,
    ASVS_EXCLUDED_TOMBSTONES,
    ASVS_ID_PREFIX,
    ASVS_LICENSE,
    ASVS_REQUIREMENTS,
    ASVS_SECTIONS,
    ASVS_VERSION,
    DIRECT,
    EVIDENCE_RUNTIME,
    EVIDENCE_STATIC,
    RELATED,
    UNMAPPED,
    UNMAPPED_RATIONALE,
    asvs_catalogue_cwe_coverage,
    asvs_coverage,
    asvs_reference,
    enrich_with_asvs,
    evidence_class,
    qualified,
    requirement_label,
    unreferenced_cwe,
)
from reporting import excel_report  # noqa: E402
from reporting.pdf_report import _asvs_section  # noqa: E402

REQ_ID = re.compile(r"^V\d+\.\d+\.\d{1,2}$")


def _pdf_text(elements) -> str:
    from reportlab.platypus import Paragraph, Table

    parts = []

    def walk(el):
        if isinstance(el, Paragraph):
            parts.append(el.getPlainText())
        elif isinstance(el, Table):
            for row in el._cellvalues:
                for cell in row:
                    walk(cell)
        elif isinstance(el, (list, tuple)):
            for sub in el:
                walk(sub)

    walk(elements)
    return re.sub(r"\s+", " ", " ".join(parts))


# ===========================================================================
# Provenance and pinning
# ===========================================================================

def test_version_is_pinned_not_latest():
    assert ASVS_VERSION == "4.0.3"
    assert ASVS_DATASET_LABEL == "OWASP ASVS v4.0.3"
    assert ASVS_LICENSE == "CC BY-SA 4.0"


def test_catalogue_digest_is_pinned():
    assert re.fullmatch(r"[0-9A-F]{64}", ASVS_CSV_SHA256), ASVS_CSV_SHA256
    assert ASVS_CSV_SHA256 == ASVS_CATALOGUE_SENTINEL["csv_sha256"]


def test_catalogue_sizes_are_self_consistent():
    s = ASVS_CATALOGUE_SENTINEL
    assert s["live_requirements"] == len(ASVS_REQUIREMENTS) == 278
    assert s["tombstones"] == len(ASVS_EXCLUDED_TOMBSTONES) == 8
    assert s["chapters"] == len(ASVS_CHAPTERS) == 14
    assert s["sections"] == len(ASVS_SECTIONS)
    assert s["cwe_edges"] == len(ASVS_BY_CWE)
    assert s["vuln_type_edges"] == sum(len(v) for v in ASVS_BY_VULN_TYPE.values())
    assert s["live_requirements"] + s["tombstones"] == 286


# ===========================================================================
# Catalogue integrity
# ===========================================================================

def test_every_requirement_id_is_well_formed():
    for rid in ASVS_REQUIREMENTS:
        assert REQ_ID.match(rid), f"malformed requirement id {rid}"


def test_no_tombstone_is_present_as_a_requirement():
    """NEGATIVE: a `[DELETED, DUPLICATE OF x.y.z]` row is not a requirement."""
    for rid in ASVS_EXCLUDED_TOMBSTONES:
        assert rid not in ASVS_REQUIREMENTS, f"tombstone {rid} leaked into the catalogue"
    for rid in ASVS_EXCLUDED_TOMBSTONES.values():
        assert "DELETED" in rid.upper()


def test_the_eight_tombstones_are_exactly_the_ones_asvs_published():
    """ASVS's own tombstones, listed so a catalogue change is visible."""
    assert set(ASVS_EXCLUDED_TOMBSTONES) == {
        "V1.4.2", "V1.4.3", "V1.12.1", "V4.1.4",
        "V7.3.2", "V13.1.2", "V13.2.4", "V14.3.1",
    }


def test_v8_3_8_is_retained_despite_containing_the_word_deleted():
    """Regression guard for a real near-miss.

    Filtering tombstones by the substring 'DELETED' removes V8.3.8, whose text
    contains 'deleted' in its data-retention sense. It is a live requirement and
    must survive.
    """
    assert "V8.3.8" in ASVS_REQUIREMENTS
    assert "V8.3.8" not in ASVS_EXCLUDED_TOMBSTONES


def test_every_requirement_points_at_a_known_chapter_and_section():
    for rid, spec in ASVS_REQUIREMENTS.items():
        assert spec["chapter"] in ASVS_CHAPTERS, f"{rid} unknown chapter"
        assert spec["section"] in ASVS_SECTIONS, f"{rid} unknown section"


def test_all_fourteen_chapters_v1_to_v14_are_present():
    assert set(ASVS_CHAPTERS) == {f"V{n}" for n in range(1, 15)}


# ===========================================================================
# Verification levels are preserved verbatim, never normalised
# ===========================================================================

def test_non_boolean_verification_levels_survive_the_catalogue():
    """NEGATIVE: a verifier that reads 'L2 = 30 days' as a boolean loses the
    qualifier, and repairing the upstream 'o' typo would be guessing at the
    source."""
    # V2.10.1 Service Authentication -- upstream annotates L2/L3 with the
    # mechanism class rather than a checkmark.
    v2101 = ASVS_REQUIREMENTS["V2.10.1"]
    assert v2101["level2"] == "OS assisted"
    assert v2101["level3"] == "HSM"
    # V3.3.2 Session Termination -- upstream puts a duration in the level cell.
    v332 = ASVS_REQUIREMENTS["V3.3.2"]
    assert "days" in v332["level1"]
    assert "inactivity" in v332["level2"]


def test_checkmark_levels_are_present_and_untouched():
    assert ASVS_REQUIREMENTS["V5.3.4"]["level1"] == "\u2713"


def test_a_verification_level_is_never_replaced_by_a_boolean():
    for rid, spec in ASVS_REQUIREMENTS.items():
        for lvl in ("level1", "level2", "level3"):
            v = spec[lvl]
            assert v in ("", "\u2713", "o", "OS assisted", "HSM") or v, rid
            assert not isinstance(v, bool), f"{rid}.{lvl} was coerced to a bool"


# ===========================================================================
# Identifier formatting -- version-qualified per OWASP's guidance
# ===========================================================================

def test_qualified_id_carries_the_version():
    assert qualified("V5.3.4") == "ASVS-v4.0.3-V5.3.4"
    assert ASVS_ID_PREFIX == "ASVS-v4.0.3-"


def test_qualification_is_idempotent():
    once = qualified("V5.3.4")
    assert qualified(once) == once


def test_qualified_id_of_nothing_is_empty_not_a_phantom_id():
    assert qualified("") == ""
    assert qualified(None) == ""


def test_requirement_label_includes_the_version():
    label = requirement_label("V5.3.4")
    assert label.startswith("ASVS-v4.0.3-V5.3.4")
    assert "Validation" in label


# ===========================================================================
# Resolution
# ===========================================================================

def test_cwe_edge_produces_a_direct_mapping():
    r = asvs_reference("", "", "CWE-798")
    assert r["asvs_mapping_mode"] == DIRECT
    assert r["asvs_requirement"] == "V2.10.4"
    assert r["asvs_id"] == "ASVS-v4.0.3-V2.10.4"


def test_cwe_matching_tolerates_a_trailing_description():
    """Findings carry both 'CWE-798' and 'CWE-798 - Use of Hard-coded Credentials'."""
    bare = asvs_reference("", "", "CWE-798")
    decorated = asvs_reference("", "", "CWE-798 - Use of Hard-coded Credentials")
    assert decorated["asvs_id"] == bare["asvs_id"]
    assert decorated["asvs_mapping_mode"] == DIRECT


def test_cwe_matching_is_case_insensitive():
    assert asvs_reference("", "", "cwe-502")["asvs_mapping_mode"] == DIRECT


def test_vuln_type_edge_is_related_never_direct():
    """NEGATIVE: the curated table is this project's judgement, so presenting it
    with the same weight as ASVS's own cross-reference would be a false
    provenance claim."""
    r = asvs_reference("", "eval_call", "")
    assert r["asvs_mapping_mode"] == RELATED
    assert r["asvs_id"] == "ASVS-v4.0.3-V5.2.4"


def test_a_direct_cwe_edge_outranks_a_related_vuln_type_edge():
    r = asvs_reference("", "hardcoded_secret", "CWE-798")
    assert r["asvs_mapping_mode"] == DIRECT


def test_unmapped_is_reported_with_a_rationale_and_never_dropped():
    """NEGATIVE: a dropped unmapped finding inflates the mapped ratio."""
    r = asvs_reference("", "a_vuln_type_nobody_mapped", "")
    assert r["asvs_mapping_mode"] == UNMAPPED
    assert r["asvs_id"] == ""
    assert r["asvs_rationale"] == UNMAPPED_RATIONALE


def test_unmapped_rationale_does_not_claim_a_clean_result():
    assert "not a clean result" in UNMAPPED_RATIONALE.lower()


def test_resolution_fails_closed_on_garbage_input():
    for bad in ("", None, "   ", "not-a-cwe", "CWE-", "CWE-abc"):
        assert asvs_reference(bad, bad, bad)["asvs_mapping_mode"] == UNMAPPED


def test_related_ids_are_qualified_too():
    r = asvs_reference("", "eval_call", "")
    for rel in r["asvs_related"]:
        assert rel.startswith(ASVS_ID_PREFIX), rel


def test_enrich_writes_every_asvs_field_onto_the_finding():
    f = {"rule_id": "X", "vuln_type": "sql_injection", "cwe": "CWE-89"}
    enrich_with_asvs(f)
    for key in ("asvs_id", "asvs_requirement", "asvs_label", "asvs_chapter",
                "asvs_section", "asvs_section_name", "asvs_levels",
                "asvs_evidence_class", "asvs_related", "asvs_mapping_mode",
                "asvs_rationale", "asvs_dataset", "asvs_version", "asvs_semantics"):
        assert key in f, f"missing {key}"
    assert f["asvs_dataset"] == ASVS_DATASET_LABEL


def test_enrich_never_places_a_bare_requirement_id_in_the_id_field():
    f = {"cwe": "CWE-89", "vuln_type": "sql_injection"}
    enrich_with_asvs(f)
    assert f["asvs_id"].startswith(ASVS_ID_PREFIX)


# ===========================================================================
# Semantics: the claim this module is allowed to make
# ===========================================================================

def test_every_reference_carries_the_evidence_relevance_semantics():
    """NEGATIVE and load-bearing: a mapped requirement is not an unmet one."""
    for cwe in ("CWE-798", "CWE-89", "CWE-79", "CWE-918"):
        sem = asvs_reference("", "", cwe)["asvs_semantics"]
        assert "NOT" in sem
        assert "unmet" in sem
        assert "compliance claim" in sem


def test_rationale_for_direct_states_that_the_linkage_is_owasp_own():
    r = asvs_reference("", "", "CWE-798")
    assert "its own enumeration" in r["asvs_rationale"]


def test_rationale_for_related_disclaims_being_an_asvs_cross_reference():
    r = asvs_reference("", "eval_call", "")
    assert "Not an ASVS cross-reference" in r["asvs_rationale"]


# ===========================================================================
# Evidence class
# ===========================================================================

def test_a_requirement_with_a_cwe_edge_is_classed_static_evidence():
    assert evidence_class("V5.3.4") == EVIDENCE_STATIC


def test_evidence_class_is_derived_from_the_dataset():
    cov = asvs_catalogue_cwe_coverage()
    assert cov["total"] == 278
    assert cov["with_cwe_edge"] == 268
    assert cov["with_cwe_edge"] + cov["without_cwe_edge"] == cov["total"]
    # A requirement with no ASVS-published CWE cannot be static evidence.
    for rid, spec in ASVS_REQUIREMENTS.items():
        if not spec["cwe"]:
            assert evidence_class(rid) == EVIDENCE_RUNTIME, rid


# ===========================================================================
# Unreferenced CWE classes
# ===========================================================================

def test_unreferenced_cwe_is_reported_not_invented_around():
    """NEGATIVE: a weakness class ASVS does not enumerate has no requirement to
    attribute, and mapping it to a plausible neighbour would be fabrication."""
    out = unreferenced_cwe(["CWE-798", "CWE-943", "CWE-321", "CWE-9999"])
    assert "CWE-943" in out
    assert "CWE-321" in out
    assert "CWE-9999" in out
    assert "CWE-798" not in out
    for reason in out.values():
        assert "does not cite" in reason


def test_unreferenced_cwe_tolerates_decorated_input():
    assert "CWE-943" in unreferenced_cwe(["CWE-943 - Cross-site Scripting"])


def test_unreferenced_cwe_ignores_nonsense():
    assert unreferenced_cwe(["", None, "nonsense"]) == {}


# ===========================================================================
# Coverage
# ===========================================================================

def test_coverage_states_every_denominator():
    cov = asvs_coverage(["CWE-798", "CWE-89", "CWE-9999"], ["eval_call"])
    assert cov["catalogue_size"] == 278
    assert cov["requirements_reachable_count"] <= 278
    assert cov["tombstones_excluded"] == 8
    assert "not compliance" in cov["semantics"].lower()


def test_coverage_reachability_is_never_one_on_a_partial_corpus():
    """NEGATIVE: two different ratios exist here and only one may be quoted.

    `combined.coverage_ratio` is over the CWE/vuln_type keys the CALLER
    supplied, so supplying one well-mapped CWE legitimately gives 1.0. That says
    nothing about ASVS. The ratio that would be a false claim is catalogue
    reachability, and it must stay far below 1.
    """
    cov = asvs_coverage(["CWE-798"], [])
    # Caller-supplied-key ratio: 1 of 1 supplied keys mapped. Not a claim about ASVS.
    assert cov["combined"]["coverage_ratio"] == 1.0
    # Catalogue reachability: 3 of 278. THIS is the number that must not be
    # presented as compliance.
    assert cov["requirements_reachable_count"] == 3
    assert cov["requirements_reachable_count"] < cov["catalogue_size"]
    catalogue_ratio = cov["requirements_reachable_count"] / cov["catalogue_size"]
    assert catalogue_ratio < 0.05, catalogue_ratio


def test_coverage_handles_empty_input_without_dividing_by_zero():
    cov = asvs_coverage([], [])
    assert cov["combined"]["coverage_ratio"] == 0.0
    assert cov["combined"]["total"] == 0
    assert cov["requirements_reachable_count"] == 0


def test_coverage_reports_unmapped_rather_than_only_the_mapped():
    cov = asvs_coverage(["CWE-798", "CWE-9999"], ["nope"])
    assert cov["cwe"]["unmapped"] == ["CWE-9999"]
    assert cov["vuln_type"]["unmapped"] == ["nope"]


# ===========================================================================
# PDF section
# ===========================================================================

def test_asvs_section_reports_mapped_and_unmapped_separately():
    """NEGATIVE: counting "any resolution" as attributed reports a corpus where
    most findings resolved to UNMAPPED as fully attributed."""
    text = _pdf_text(_asvs_section(_summary_payload()))
    assert "Findings mapped: 1" in text
    assert "findings resolved UNMAPPED: 1" in text


def test_asvs_section_states_absence_rather_than_zero():
    text = _pdf_text(_asvs_section({}))
    assert "No ASVS requirement-level mapping was produced" in text
    assert "no requirement status is claimed" in text.lower()


def test_asvs_section_surfaces_an_evaluation_failure():
    text = _pdf_text(_asvs_section({"asvs_summary": {
        "status": "REVIEW_REQUIRED", "error": "boom"}}))
    assert "boom" in text
    assert "no requirement status is claimed" in text.lower()


def _summary_payload():
    cov = asvs_coverage(["CWE-798", "CWE-943"], ["eval_call"])
    cov["findings_mapped"] = 1
    cov["findings_unmapped"] = 1
    cov["findings_resolved"] = 2
    cov["unreferenced_cwe"] = unreferenced_cwe(["CWE-943"])
    return {"asvs_summary": cov}


def test_asvs_section_never_calls_a_reached_requirement_unmet():
    text = _pdf_text(_asvs_section(_summary_payload()))
    assert "does NOT mean the requirement is unmet" in text
    assert "neither passed nor failed" in text


def test_asvs_section_never_presents_the_ratio_as_compliance():
    text = _pdf_text(_asvs_section(_summary_payload()))
    low = text.lower()
    assert "reachability, not compliance" in low
    assert "not an asvs coverage score" in low
    assert "not an asvs compliance claim" in low


def test_asvs_section_renders_the_mode_table():
    """Regression guard: by_mode lives on the families, not on `combined`.

    Reading it off `combined` yields {} and silently drops this whole table, so
    a DIRECT/RELATED/UNMAPPED distinction would vanish from the report with no
    error anywhere.
    """
    text = _pdf_text(_asvs_section(_summary_payload()))
    assert "Resolution Mode" in text
    assert DIRECT in text
    assert RELATED in text
    assert UNMAPPED in text
    assert "ASVS's OWN CWE cross-reference" in text
    assert "this project's vuln_type table" in text


def test_asvs_section_states_the_catalogue_and_the_tombstones():
    text = _pdf_text(_asvs_section(_summary_payload()))
    assert "278 live requirements" in text
    assert "tombstones" in text
    assert "14 chapters" in text


def test_asvs_section_lists_reached_requirements_version_qualified():
    text = _pdf_text(_asvs_section(_summary_payload()))
    assert "ASVS-v4.0.3-V" in text
    for rid in re.findall(r"(?<![.\w])V\d+\.\d+\.\d+\b", text):
        assert ASVS_ID_PREFIX + rid in text, f"bare id {rid} rendered"


def test_asvs_section_records_the_licence_and_digest():
    text = _pdf_text(_asvs_section(_summary_payload()))
    assert ASVS_LICENSE in text
    assert ASVS_CSV_SHA256[:16] in text


def test_asvs_section_discloses_uncited_weakness_classes():
    text = _pdf_text(_asvs_section(_summary_payload()))
    assert "CWE-943" in text
    assert "declared limits" in text


# ===========================================================================
# Excel sheet
# ===========================================================================

def test_asvs_sheet_reports_no_mapping_rather_than_zero_requirements():
    from openpyxl import Workbook, load_workbook
    import tempfile

    ws = Workbook().active
    excel_report._asvs_sheet(ws, {})
    with tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False) as fh:
        path = fh.name
    ws.parent.save(path)
    sheet = load_workbook(path)["ASVS Mapping"]
    blob = " ".join(str(sheet.cell(row=r, column=1).value)
                    for r in range(1, sheet.max_row + 1)
                    if sheet.cell(row=r, column=1).value)
    assert "No ASVS requirement-level mapping was produced" in blob
    assert "no requirement status is claimed" in blob.lower()


def test_asvs_sheet_puts_the_semantics_before_any_number():
    from openpyxl import Workbook, load_workbook
    import tempfile

    ws = Workbook().active
    excel_report._asvs_sheet(ws, _summary_payload())
    with tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False) as fh:
        path = fh.name
    ws.parent.save(path)
    sheet = load_workbook(path)["ASVS Mapping"]

    rows = {r: str(sheet.cell(row=r, column=1).value or "")
            for r in range(1, sheet.max_row + 1)}
    semantics_at = min(r for r, v in rows.items() if v.startswith("SEMANTICS"))
    last_requirement = max(
        r for r in range(3, sheet.max_row + 1)
        if str(sheet.cell(row=r, column=1).value or "").startswith(ASVS_ID_PREFIX)
    )
    assert semantics_at > last_requirement, (
        "the SEMANTICS block must sit below the requirement table so a reader "
        "cannot take a number without the caveat in view")


def test_asvs_sheet_lists_every_requirement_version_qualified():
    from openpyxl import Workbook, load_workbook
    import tempfile

    ws = Workbook().active
    excel_report._asvs_sheet(ws, _summary_payload())
    with tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False) as fh:
        path = fh.name
    ws.parent.save(path)
    sheet = load_workbook(path)["ASVS Mapping"]
    ids = [sheet.cell(row=r, column=1).value for r in range(1, sheet.max_row + 1)]
    n = sum(1 for v in ids if isinstance(v, str) and v.startswith(ASVS_ID_PREFIX))
    assert n == 278
    # No tombstone may appear as a requirement row.
    for tomb in ASVS_EXCLUDED_TOMBSTONES:
        assert (ASVS_ID_PREFIX + tomb) not in ids


def test_asvs_sheet_labels_no_as_not_evidenced_not_as_passed():
    from openpyxl import Workbook, load_workbook
    import tempfile

    ws = Workbook().active
    excel_report._asvs_sheet(ws, _summary_payload())
    with tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False) as fh:
        path = fh.name
    ws.parent.save(path)
    sheet = load_workbook(path)["ASVS Mapping"]
    blob = " ".join(str(sheet.cell(row=r, column=1).value)
                    for r in range(1, sheet.max_row + 1)
                    if sheet.cell(row=r, column=1).value)
    assert "NOT EVIDENCED AS MET" in blob
    assert "this is reachability, NOT compliance" in blob
    assert ASVS_LICENSE in blob
    assert ASVS_CSV_SHA256 in blob


def test_asvs_sheet_marks_only_reached_requirements_yes():
    from openpyxl import Workbook, load_workbook
    import tempfile

    ws = Workbook().active
    excel_report._asvs_sheet(ws, _summary_payload())
    with tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False) as fh:
        path = fh.name
    ws.parent.save(path)
    sheet = load_workbook(path)["ASVS Mapping"]
    yes = 0
    for r in range(3, sheet.max_row + 1):
        v = sheet.cell(row=r, column=1).value
        if isinstance(v, str) and v.startswith(ASVS_ID_PREFIX):
            if sheet.cell(row=r, column=5).value == "YES":
                yes += 1
    cov = _summary_payload()["asvs_summary"]["requirements_reachable_count"]
    assert yes == cov, f"{yes} YES rows vs {cov} reachable requirements"


# ===========================================================================
# Registry conformance
# ===========================================================================

def test_asvs_probe_regex_matches_this_catalogue():
    """The conformance probe looks for V4.x.y / V5.x.y; the catalogue must
    actually satisfy it, or the standard would be marked NOT_VERIFIED while
    being implemented."""
    from analysis.benchmark_conformance_baseline import STANDARD_BASELINE

    std = next(s for s in STANDARD_BASELINE if s["key"] == "ASVS")
    req_probe = next(p for p in std["probes"] if p["name"] == "asvs_requirement_ids")
    matches = [rid for rid in ASVS_REQUIREMENTS if re.search(req_probe["pattern"], rid)]
    assert len(matches) >= 20, f"only {len(matches)} requirements satisfy the probe"
    assert "V5.3.4" in matches or "V4.2.1" in matches


def test_asvs_probes_all_have_a_matching_target():
    """Every ASVS code probe must match somewhere in production source.

    Deliberately NOT narrowed to core/asvs_mappings.py: the pre-existing
    `asvs_domain_taxonomy` probe is satisfied by the chapter taxonomy in
    analysis/security_control_coverage_engine.py, which is where it belongs.
    Checking production source as a whole is what the benchmark does.
    """
    from analysis.benchmark_conformance_baseline import STANDARD_BASELINE
    from core.conformance_baseline import production_sources

    sources = production_sources(ROOT)
    std = next(s for s in STANDARD_BASELINE if s["key"] == "ASVS")
    for probe in std["probes"]:
        if probe["kind"] != "code":
            continue
        hits = [rel for rel, text in sources.items()
                if re.search(probe["pattern"], text)]
        assert hits, (
            f"ASVS probe {probe['name']} matches no production source, so the "
            f"standard can never be verified")