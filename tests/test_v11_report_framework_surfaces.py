"""Tests for the D4 / D5 report fixes and the NIST AML + SSDF report surfaces.

Three defects are pinned here, each from a measurement rather than a
specification:

D4a  `compliance_summary` was a mid-pipeline snapshot. On the Juice Shop report
     06102026 1914 it stated CWE 21 / OWASP 21 / PCI DSS 19 while the findings
     actually written carried 22 / 22 / 20 -- one artifact, two answers to the
     same question. It is now recomputed immediately before serialization.

D4b  The summary mixed units in one flat int->int map with no labelling, so
     "NIST 800-53: 102" read as coverage when 80 of those 102 findings carry the
     identical generic fallback triple (RA-5 / A.8.8 / CC7.1).

D5   `decision_state`, `reportable_finding` and `evidence_valid` were computed
     for every finding and never rendered. The tests below pin the rule that
     makes rendering them safe: an absent value never becomes a positive claim.

The load-bearing negative assertions are marked NEGATIVE. They are the point.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core.nist_aml_mappings import (  # noqa: E402
    NISTAML_ATTACKS,
    NISTAML_DATASET_LABEL,
    NISTAML_DETECTION_GAPS,
    nistaml_reference,
)
from core.ssdf_mappings import evaluate_ssdf_alignment  # noqa: E402
from reporting import excel_report  # noqa: E402
from scanner.compliance_mapper import (  # noqa: E402
    COMPLIANCE_GENERIC_FRAMEWORKS,
    COMPLIANCE_SUMMARY_UNIT,
    GENERIC_MAPPING,
    compliance_summary,
    compliance_summary_detail,
)
from reporting.executive_pdf_report import (  # noqa: E402
    _compliance_executive_summary,
    _executive_ai_framework_summary,
)
from reporting.pdf_report import (  # noqa: E402
    _NOT_RECORDED,
    _decision_state_display,
    _evidence_valid_display,
    _findings_section,
    _nistaml_rows,
    _nistaml_section,
    _reportable_display,
    _ssdf_alignment_section,
)

GENERIC_TRIPLE = {
    "NIST 800-53": ["RA-5"],
    "ISO 27001": ["A.8.8"],
    "SOC 2": ["CC7.1"],
}


def _finding(**kw):
    base = {"severity": "High", "title": "t", "vuln_type": "v", "file": "a.ts"}
    base.update(kw)
    return base


def _pdf_text(elements) -> str:
    """Flatten a ReportLab flowable list to text.

    Table cells in narrow columns wrap mid-label, so whitespace is normalised
    before probing; otherwise a two-word label fails the probe while rendering
    correctly.
    """
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
# D4a -- compliance_summary must describe the findings it is given
# ===========================================================================

def test_compliance_summary_is_reproducible_from_the_population_it_describes():
    """NEGATIVE (the D4a defect): the summary must never disagree with findings.

    The shipped defect was a snapshot taken mid-pipeline, so the report stated
    one PCI DSS count in compliance_summary and a different one in findings[].
    Any disagreement between the two is the bug.
    """
    findings = [
        _finding(compliance_controls={"PCI DSS": ["6.2.4"], "NIST 800-53": ["SI-10"]}),
        _finding(compliance_controls={"PCI DSS": [], "NIST 800-53": ["RA-5"]}),
        _finding(compliance_controls={}),
    ]
    summary = compliance_summary(findings)
    assert summary == {"NIST 800-53": 2, "PCI DSS": 1}, summary


def test_empty_control_value_does_not_inflate_a_framework_count():
    """NEGATIVE: a framework key with no control id carries no mapping."""
    findings = [_finding(compliance_controls={"PCI DSS": [], "CWE": []})]
    assert compliance_summary(findings) == {}, compliance_summary(findings)


def test_compliance_summary_is_order_independent():
    a = [_finding(compliance_controls={"PCI DSS": ["6.2.4"], "CWE": ["CWE-89"]})]
    b = [_finding(compliance_controls={"CWE": ["CWE-89"], "PCI DSS": ["6.2.4"]})]
    assert compliance_summary(a) == compliance_summary(b)


def test_compliance_summary_tolerates_missing_and_malformed_containers():
    findings = [
        _finding(),
        _finding(compliance_controls=None),
        _finding(compliance_controls=["not", "a", "dict"]),
        _finding(compliance_controls={"PCI DSS": "6.2.4, 8.3.2"}),
        _finding(compliance_controls={"ISO 27001": []}),
    ]
    summary = compliance_summary(findings)
    assert summary == {"PCI DSS": 1}, summary


def test_compliance_summary_accepts_scalar_and_comma_string_values():
    findings = [
        _finding(compliance_controls={"NIST 800-53": "RA-5"}),
        _finding(compliance_controls={"NIST 800-53": "RA-5, SI-10"}),
    ]
    assert compliance_summary(findings) == {"NIST 800-53": 2}


# ===========================================================================
# D4b -- the unit must be declared, and the generic fallback separated out
# ===========================================================================

def test_compliance_summary_detail_declares_its_unit():
    """NEGATIVE: an unlabelled int map invites being read as coverage."""
    detail = compliance_summary_detail([_finding(compliance_controls=GENERIC_TRIPLE)])
    assert detail["unit"] == COMPLIANCE_SUMMARY_UNIT
    assert "coverage" not in detail["unit"]
    assert detail["caveat"]


def test_detail_separates_generic_fallback_from_finding_specific_controls():
    """NEGATIVE: the D4b defect was 102/102 NIST presented as coverage.

    80 of 102 Juice Shop findings carry the identical generic triple, so a
    count of 102 says nothing about 102 distinct control decisions. The
    specific population must be countable separately.
    """
    findings = [_finding(compliance_controls=dict(GENERIC_TRIPLE)) for _ in range(80)]
    findings.append(_finding(compliance_controls={
        "NIST 800-53": ["IA-5", "SC-12", "SC-28"],
        "ISO 27001": ["A.5.17", "A.8.24"],
        "SOC 2": ["CC6.1", "CC6.6"],
    }))

    detail = compliance_summary_detail(findings)

    assert detail["population"] == 81
    assert detail["counts"]["NIST 800-53"] == 81
    assert detail["generic_fallback"]["findings_receiving_generic_only"] == 80
    assert detail["specific_mapping"]["findings_with_finding_specific_controls"] == 1
    # The generic count and the specific count must not be confusable.
    assert detail["generic_fallback"]["findings_receiving_generic_only"] != \
        detail["specific_mapping"]["findings_with_finding_specific_controls"]


def test_detail_declares_exactly_which_frameworks_are_applied_to_every_finding():
    assert set(COMPLIANCE_GENERIC_FRAMEWORKS) == {"NIST 800-53", "ISO 27001", "SOC 2"}
    detail = compliance_summary_detail([_finding(compliance_controls=dict(GENERIC_TRIPLE))])
    assert detail["generic_fallback"]["control_ids"]["NIST 800-53"] == ["RA-5"]
    assert set(detail["generic_fallback"]["control_ids"]) == set(GENERIC_MAPPING["frameworks"])


def test_detail_counts_findings_with_no_generic_framework_at_all():
    findings = [_finding(compliance_controls={"PCI DSS": ["6.2.4"]})]
    detail = compliance_summary_detail(findings)
    assert detail["specific_mapping"]["findings_with_none_of_the_generic_frameworks"] == 1
    assert detail["generic_fallback"]["findings_receiving_generic_only"] == 0


def test_detail_population_zero_does_not_divide_by_zero():
    detail = compliance_summary_detail([])
    assert detail["population"] == 0
    assert detail["counts"] == {}
    assert detail["generic_fallback"]["findings_receiving_generic_only"] == 0


# ===========================================================================
# D4b -- the executive PDF must state the unit of each row
# ===========================================================================

def test_executive_observed_mappings_table_has_a_unit_column():
    """NEGATIVE: six numbers in one unlabelled column, two different units."""
    text = _pdf_text(_compliance_executive_summary({}))
    assert "Observed Mappings" in text
    assert "Unit" in text
    assert "distinct categories observed" in text
    assert "findings carrying a mapping" in text


def test_executive_table_labels_each_framework_with_its_own_unit():
    payload = {
        "owasp": {"A01": {}, "A03": {}},
        "mitre": [{"id": "T1190"}],
        "grouped": [
            {"owasp": "A01:2021", "mitre": "T1190", "pci_dss": "6.2.4",
             "nist": "RA-5", "iso27001": "A.8.8", "soc2": "CC7.1"},
            {"owasp": "A01:2021", "mitre": "", "pci_dss": "",
             "nist": "", "iso27001": "", "soc2": ""},
        ],
    }
    text = _pdf_text(_compliance_executive_summary(payload))
    # OWASP/MITRE count categories, the rest count findings -- stated, not implied.
    assert "distinct categories observed" in text
    assert "findings carrying a mapping" in text
    assert "not a certification or compliance attestation" in text.lower()


def test_executive_footnote_explains_the_generic_fallback():
    text = _pdf_text(_compliance_executive_summary({}))
    low = text.lower()
    assert "not comparable" in low
    assert "generic fallback" in low
    assert "compliance_summary_detail" in text


# ===========================================================================
# D5 -- decision fields, and the absence rule
# ===========================================================================

def test_absent_decision_state_never_renders_as_a_pass():
    """NEGATIVE: absence is not "fine", it is "never recorded"."""
    assert _decision_state_display({}) == _NOT_RECORDED
    assert _decision_state_display({"decision_state": None}) == _NOT_RECORDED
    assert _decision_state_display({"decision_state": ""}) == _NOT_RECORDED
    assert _decision_state_display({"decision_state": "   "}) == _NOT_RECORDED
    assert _decision_state_display(None) == _NOT_RECORDED


def test_present_decision_state_renders_verbatim():
    assert _decision_state_display({"decision_state": "REVIEW_REQUIRED"}) == "REVIEW_REQUIRED"
    assert _decision_state_display({"decision_state": "CONFIRMED"}) == "CONFIRMED"


def test_absent_reportable_never_renders_as_yes_or_no():
    """NEGATIVE: the failure this guards is `None -> "not reportable"`, which
    converts a missing decision into a negative finding about the code."""
    assert _reportable_display({}) == _NOT_RECORDED
    assert _reportable_display({"reportable_finding": None}) == _NOT_RECORDED
    assert _reportable_display({"reportable_finding": ""}) == _NOT_RECORDED
    assert _reportable_display({"reportable_finding": "maybe"}) == _NOT_RECORDED


def test_reportable_renders_both_verdicts():
    assert _reportable_display({"reportable_finding": True}) == "YES"
    assert _reportable_display({"reportable_finding": False}) == "NO"
    assert _reportable_display({"reportable_finding": "true"}) == "YES"
    assert _reportable_display({"reportable_finding": "False"}) == "NO"


def test_absent_evidence_valid_never_renders_as_valid():
    """NEGATIVE: the failure this guards is `None -> VALID`, i.e. asserting
    evidence exists when none was recorded."""
    assert _evidence_valid_display({}) == _NOT_RECORDED
    assert _evidence_valid_display({"evidence_valid": None}) == _NOT_RECORDED
    assert _evidence_valid_display({"evidence_valid": ""}) == _NOT_RECORDED
    assert _evidence_valid_display({"evidence_valid": "unclear"}) == _NOT_RECORDED


def test_evidence_valid_renders_verdict_and_invalid_carries_a_reason():
    assert _evidence_valid_display({"evidence_valid": True}) == "VALID"
    assert _evidence_valid_display({"evidence_valid": False}) == "INVALID"
    detailed = _evidence_valid_display(
        {"evidence_valid": False, "evidence_reason": "snippet absent"})
    assert detailed.startswith("INVALID")
    assert "snippet absent" in detailed


def test_findings_section_renders_all_three_decision_fields():
    payload = {
        "grouped": [
            _finding(decision_state="REVIEW_REQUIRED", reportable_finding=True,
                     evidence_valid=True, file="a.ts", line=1),
            _finding(reportable_finding=False, evidence_valid=False,
                     evidence_reason="no snippet", file="b.ts", line=2),
        ]
    }
    text = _pdf_text(_findings_section(payload))
    assert "Decision State" in text
    assert "Reportable" in text
    assert "Evidence Valid" in text
    assert "REVIEW_REQUIRED" in text
    assert "NO" in text
    assert "VALID" in text
    assert "INVALID" in text
    assert "no snippet" in text


def test_findings_section_renders_not_recorded_when_fields_are_absent():
    """NEGATIVE: a finding with no decision fields must not render as clean."""
    payload = {"grouped": [_finding(file="a.ts", line=1)]}
    text = _pdf_text(_findings_section(payload))
    assert _NOT_RECORDED in text
    # And crucially it must not have acquired a verdict.
    assert "Reportable YES" not in text


def test_findings_section_handles_empty_grouped_list():
    text = _pdf_text(_findings_section({"grouped": []}))
    assert "No findings detected." in text


# ===========================================================================
# NIST AML section
# ===========================================================================

def test_nistaml_section_states_absence_when_no_finding_is_attributed():
    """NEGATIVE: a corpus with no AI findings must NOT get the catalogue
    printed as though it were observed."""
    text = _pdf_text(_nistaml_section({"findings": [_finding()]}))
    assert "No finding in this report carries NIST AML attack-class attribution" in text
    assert "NOT an observation" in text or "reference scope" in text
    # The ratio must still be stated honestly as zero.
    assert "of 17 in the catalogue" in text


def test_nistaml_rows_ignores_findings_without_the_attribution_field():
    """NEGATIVE: presence of the key is the signal; a finding that never went
    through attribution must not be counted as contributing."""
    by_attack, objectives, contributing, unmapped = _nistaml_rows(
        {"findings": [_finding()]})
    assert contributing == 0
    assert unmapped == 0
    assert by_attack == {}
    assert objectives == {}


def test_nistaml_rows_counts_unmapped_separately_from_observed():
    findings = [
        _finding(rule_id="ADV01_EVASION_ATTACK_INDICATOR"),
        _finding(rule_id="NOT_IN_CATALOGUE_AT_ALL"),
        _finding(),
    ]
    for f in findings:
        f.update(nistaml_reference(f.get("rule_id", ""), ""))
    by_attack, objectives, contributing, unmapped = _nistaml_rows({"findings": findings})
    assert contributing == 3
    assert unmapped == 2
    assert len(by_attack) == 1
    aid = next(iter(by_attack))
    assert aid == "NISTAML.022"
    assert by_attack[aid]["findings"] == 1


def test_nistaml_section_renders_observed_classes_with_a_denominator():
    f = _finding(rule_id="ADV01_EVASION_ATTACK_INDICATOR")
    f.update(nistaml_reference(f["rule_id"], ""))
    text = _pdf_text(_nistaml_section({"findings": [f]}))
    assert "NISTAML.022" in text
    assert "Evasion" in text
    assert f"of {len(NISTAML_ATTACKS)} in the catalogue" in text
    assert "ratio 0." in text


def test_nistaml_section_lists_every_recorded_detection_gap():
    text = _pdf_text(_nistaml_section({"findings": []}))
    for gid in NISTAML_DETECTION_GAPS:
        assert gid in text, f"{gid} missing from the gap table"
    assert "G-088" in text


def test_nistaml_dataset_label_is_stated_in_the_section():
    text = _pdf_text(_nistaml_section({"findings": []}))
    assert NISTAML_DATASET_LABEL in text


# ===========================================================================
# SSDF section
# ===========================================================================

def test_ssdf_section_states_absence_rather_than_zero():
    """NEGATIVE: no alignment produced must not read as zero practices met."""
    text = _pdf_text(_ssdf_alignment_section({}))
    assert "No SSDF alignment was produced" in text
    assert "must not be read as zero practices met" in text


def test_ssdf_section_states_evaluation_failure_without_claiming_status():
    text = _pdf_text(_ssdf_alignment_section(
        {"ssdf_alignment": {"status": "REVIEW_REQUIRED", "error": "boom"}}))
    assert "could not be evaluated: boom" in text
    assert "No practice status is claimed" in text


def test_ssdf_section_names_the_not_attestable_bucket_as_the_honest_result():
    payload = {"ssdf_alignment": evaluate_ssdf_alignment(
        {"sbom": [1], "secret_intelligence_summary": {"total": 1}})}
    text = _pdf_text(_ssdf_alignment_section(payload))
    assert "NOT_ATTESTABLE_BY_A_SCANNER" in text
    assert "honest result" in text
    assert "can attest in either direction" in text


def test_ssdf_section_renders_every_practice_with_its_status():
    payload = {"ssdf_alignment": evaluate_ssdf_alignment({"sbom": [1]})}
    align = payload["ssdf_alignment"]
    text = _pdf_text(_ssdf_alignment_section(payload))
    for p in align["practices"]:
        assert p["practice_id"] in text
    assert str(align["total_practices"]) in text


def test_ssdf_section_attaches_no_practice_id_to_any_finding():
    """NEGATIVE, and the most important assertion in this file.

    SSDF is a process framework. A static scanner cannot evidence an
    organisational practice, so rendering a practice id against a finding would
    convert absence into assurance.
    """
    findings = [_finding(severity="Critical", title="hardcoded secret")]
    align = evaluate_ssdf_alignment({"sbom": [1], "secret_intelligence_summary": {}})
    payload = {"findings": findings, "ssdf_alignment": align}

    for f in findings:
        joined = " ".join(f"{k}={v}" for k, v in f.items())
        assert "PS.1" not in joined
        assert "RV.1" not in joined
        for pid in (p["practice_id"] for p in align["practices"]):
            assert pid not in joined, f"{pid} leaked onto a finding"

    text = _pdf_text(_ssdf_alignment_section(payload))
    assert "No practice identifier is attached to any finding" in text


# ===========================================================================
# Executive AI framework headline block
# ===========================================================================

def test_executive_ai_block_reports_not_evaluated_when_no_alignment():
    text = _pdf_text(_executive_ai_framework_summary({}))
    assert "NIST SSDF" in text
    assert "NOT EVALUATED" in text
    assert "not a claim that zero practices were met" in text.lower()


def test_executive_ai_block_reports_not_applicable_when_no_ai_findings():
    text = _pdf_text(_executive_ai_framework_summary({"findings": [_finding()]}))
    assert "NOT APPLICABLE" in text
    assert "absence of AI findings, not evidence that the corpus is free" in text


def test_executive_ai_block_refuses_to_quote_a_ratio_without_its_context():
    f = _finding(rule_id="ADV01_EVASION_ATTACK_INDICATOR")
    f.update(nistaml_reference(f["rule_id"], ""))
    payload = {"findings": [f],
               "ssdf_alignment": evaluate_ssdf_alignment({"sbom": [1]})}
    text = _pdf_text(_executive_ai_framework_summary(payload))
    assert "catalogue attack classes" in text
    assert "wider than the implemented rule set" in text
    assert "G-088" in text
    assert "not certifications" in text.lower() or "not certifications" in text


def test_executive_ai_block_survives_alignment_error():
    text = _pdf_text(_executive_ai_framework_summary(
        {"ssdf_alignment": {"status": "REVIEW_REQUIRED", "error": "kaboom"}}))
    assert "NOT EVALUATED (alignment error)" in text
    assert "kaboom" in text


# ===========================================================================
# Excel surfaces
# ===========================================================================

@pytest.fixture(scope="module")
def workbooks(tmp_path_factory):
    """Build all three workbooks once from a payload with real SSDF alignment
    and real NISTAML attribution."""
    from openpyxl import load_workbook

    findings = []
    for rid in ("ADV01_EVASION_ATTACK_INDICATOR", "ADV02_GRADIENT_EXTRACTION"):
        f = _finding(rule_id=rid, severity="Medium", title=rid)
        f.update(nistaml_reference(rid, ""))
        findings.append(f)
    findings.append(_finding(rule_id="NOT_IN_CATALOGUE", severity="Low", title="plain"))

    payload = {
        "findings": findings,
        "grouped": findings,
        "sbom": [{"name": "a", "version": "1"}],
        "secret_intelligence_summary": {"total_secrets": 1},
        "metadata": {"total_findings": len(findings)},
    }
    payload["ssdf_alignment"] = evaluate_ssdf_alignment(payload)

    out = tmp_path_factory.mktemp("wb")
    paths = {
        "Security_Report": out / "Security_Report.xlsx",
        "Security_Executive_Report": out / "Security_Executive_Report.xlsx",
        "Security_Technical_Report": out / "Security_Technical_Report.xlsx",
    }
    excel_report.generate_excel_report(payload, str(paths["Security_Report"]))
    excel_report.generate_executive_excel_report(payload, str(paths["Security_Executive_Report"]))
    excel_report.generate_technical_excel_report(payload, str(paths["Security_Technical_Report"]))
    return payload, {k: load_workbook(v) for k, v in paths.items()}


@pytest.mark.parametrize("name", [
    "Security_Report", "Security_Executive_Report", "Security_Technical_Report",
])
def test_every_workbook_carries_both_new_sheets(workbooks, name):
    _, wbs = workbooks
    sheets = wbs[name].sheetnames
    assert "NIST AML Mapping" in sheets, f"{name} is missing NIST AML Mapping"
    assert "SSDF Alignment" in sheets, f"{name} is missing SSDF Alignment"


@pytest.mark.parametrize("name", [
    "Security_Report", "Security_Executive_Report", "Security_Technical_Report",
])
def test_ssdf_sheet_lists_all_practices_with_status(workbooks, name):
    payload, wbs = workbooks
    ws = wbs[name]["SSDF Alignment"]
    col = [ws.cell(row=r, column=1).value for r in range(1, ws.max_row + 1)]
    ids = [v.split(":")[0] for v in col
           if isinstance(v, str) and re.match(r"^(PO|PS|PW|RV)\.\d", v)]
    assert len(ids) == payload["ssdf_alignment"]["total_practices"] == 15
    assert len(set(ids)) == 15


@pytest.mark.parametrize("name", [
    "Security_Report", "Security_Executive_Report", "Security_Technical_Report",
])
def test_ssdf_sheet_states_the_scope_caveats(workbooks, name):
    _, wbs = workbooks
    ws = wbs[name]["SSDF Alignment"]
    blob = " ".join(str(ws.cell(row=r, column=1).value)
                    for r in range(1, ws.max_row + 1)
                    if ws.cell(row=r, column=1).value)
    assert "NOT_ATTESTABLE_BY_A_SCANNER" in blob
    assert "largest bucket" in blob
    assert "convert absence into assurance" in blob


@pytest.mark.parametrize("name", [
    "Security_Report", "Security_Executive_Report", "Security_Technical_Report",
])
def test_nistaml_sheet_lists_the_whole_catalogue_and_marks_observation(workbooks, name):
    _, wbs = workbooks
    ws = wbs[name]["NIST AML Mapping"]
    rows = {}
    for r in range(1, ws.max_row + 1):
        k = ws.cell(row=r, column=1).value
        if isinstance(k, str) and re.match(r"^NISTAML\.\d+$", k):
            rows[k] = (ws.cell(row=r, column=8).value, ws.cell(row=r, column=5).value)
    assert len(rows) == len(NISTAML_ATTACKS) == 17
    yes = [k for k, v in rows.items() if v[0] == "YES"]
    assert len(yes) == 2, f"expected the 2 attributed classes, got {yes}"
    # Every non-observed row must have a zero finding count. `_jsonish` writes
    # scalars as text, so compare numerically rather than by identity.
    for k, v in rows.items():
        if v[0] != "YES":
            assert int(v[1]) == 0, f"{k} marked not observed but reports {v[1]} findings"


@pytest.mark.parametrize("name", [
    "Security_Report", "Security_Executive_Report", "Security_Technical_Report",
])
def test_nistaml_sheet_states_the_denominator_and_gap_meaning(workbooks, name):
    _, wbs = workbooks
    ws = wbs[name]["NIST AML Mapping"]
    blob = " ".join(str(ws.cell(row=r, column=1).value)
                    for r in range(1, ws.max_row + 1)
                    if ws.cell(row=r, column=1).value)
    assert "Catalogue attack classes: 17" in blob
    assert "G-088" in blob
    # NEGATIVE: an unobserved catalogue entry must not read as a finding.
    assert "not a finding" in blob.lower()


def test_nistaml_sheet_reports_no_attribution_when_there_are_no_ai_findings():
    from openpyxl import Workbook, load_workbook
    import tempfile

    ws = Workbook().active
    excel_report._nistaml_sheet(ws, {"findings": [_finding()]})
    with tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False) as fh:
        path = fh.name
    ws.parent.save(path)
    sheet = load_workbook(path)["NIST AML Mapping"]
    blob = " ".join(str(sheet.cell(row=r, column=1).value)
                    for r in range(1, sheet.max_row + 1)
                    if sheet.cell(row=r, column=1).value)
    assert "no AI/LLM findings" in blob
    assert "Attack classes attributed in this scan: 0" in blob


def test_ssdf_sheet_reports_no_alignment_rather_than_zero_practices():
    from openpyxl import Workbook, load_workbook
    import tempfile

    ws = Workbook().active
    excel_report._ssdf_sheet(ws, {})
    with tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False) as fh:
        path = fh.name
    ws.parent.save(path)
    sheet = load_workbook(path)["SSDF Alignment"]
    blob = " ".join(str(sheet.cell(row=r, column=1).value)
                    for r in range(1, sheet.max_row + 1)
                    if sheet.cell(row=r, column=1).value)
    assert "No SSDF alignment was produced" in blob
    assert "must NOT be read as zero practices met" in blob