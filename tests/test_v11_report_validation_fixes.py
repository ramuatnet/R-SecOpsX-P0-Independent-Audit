# -*- coding: utf-8 -*-
"""Red-first pins for the juice-shop-git Security_Report.pdf validation fixes.

End-to-end validation of the delivered report
(``prodtest/reports/juice-shop-git/Security_Report.pdf``, 189 pages, scan
2026-11-03) passed with five real defects (D1-D5) plus three cosmetics. Each
pin below is the measurement that caught the defect, inverted:

D1  The NIST AML prose said "The remaining 17 catalogue attack classes have
    no detection rule ... see reports/gap_register.json (G-088)" directly
    above a 7-row gap table. The count must be ``len(NISTAML_DETECTION_GAPS)``
    (the recorded gaps), not ``catalogue - observed`` (unobserved classes),
    and the citation must name the register shipped beside the report.

D2  Advisory cells were truncated with no ellipsis and no "and N more":
    PDF SBOM ``cves[:3] + advisories[:2]``, SCA priority ``ids[:5]``,
    Excel exploitable ``_pkg_cve_list(pkg)[:6]`` -- while the captions next
    to them ("13 unique CVEs") state the full count. Excel's
    ``_pkg_cve_list`` also never read ``cve_list``/``advisory_ids``, so
    GHSAs were missing from "CVE / Advisory" entirely.

D3  The accuracy layer (``metadata.accuracy_summary``: 23 LIKELY_FALSE_POSITIVE,
    38 NEEDS_REVIEW, ... ) reached clean_report.json but zero PDF pages and
    no Excel column: a reader could not tell which findings the pipeline
    itself doubts.

D4  The AML prose and the Excel AML sheet cite ``gap_register.json`` (G-088),
    a gitignored repo file that was never copied into the output directory.

D5  ``executive_decision.executive_decision`` (DO_NOT_RELEASE, P0, confidence
    0.95) appeared on zero PDF pages: the conclusion only prints it in the
    ``blocking`` branch, and this corpus lands in ``remediation_required``.

Cosmetic b  Excel "Benchmark Disposition" was '--' for all 63 rows while the
            PDF derived real text from ``benchmark_ground_truth.status``.
Cosmetic c  ``normalize_report_insights`` CRITICAL branch required the plural
            "vulnerabilities", so the producer's singular "vulnerability"
            (n==1) never matched -- and a plural rewrite against a
            singular distribution would have produced "2 critical
            vulnerability".
Cosmetic e  The ASVS by_mode table header said "Findings" while DIRECT+RELATED
            +UNMAPPED counted attribution columns (CWE + vuln_type, up to 2
            per finding), not distinct findings.
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
    NISTAML_DETECTION_GAPS,
)
from reporting import excel_report  # noqa: E402
from reporting.pdf_report import (  # noqa: E402
    _asvs_section,
    _conclusion,
    _findings_section,
    _nistaml_section,
    _sbom_section,
    _sca_remediation_priority_section,
)
from reporting.report_mappings import normalize_report_insights  # noqa: E402


def _pdf_text(elements) -> str:
    """Flatten a ReportLab flowable list to whitespace-normalised text."""
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
# Cosmetic c -- CRITICAL insight must track the distribution's count AND the
# noun the producer emitted.
# ===========================================================================


def test_critical_singular_insight_is_rewritten_to_the_distribution():
    """NEGATIVE: producer emits singular "vulnerability" when n==1.

    The old regex accepted only "findings|vulnerabilities", so a stored
    "CRITICAL: 1 critical vulnerability identified" was never rewritten to
    match a distribution that had since changed -- and the plural branch
    would have written "2 critical vulnerability" if it had matched.
    """
    out = normalize_report_insights(
        ["CRITICAL: 1 critical vulnerability identified — "
         "immediate remediation required before next deployment."],
        {"Critical": 2, "High": 4, "Medium": 0, "Low": 0, "Info": 0},
    )
    assert out[0].startswith("CRITICAL: 2 critical vulnerabilities identified")
    assert "immediate remediation required" in out[0]


def test_critical_plural_insight_collapses_to_singular_distribution():
    out = normalize_report_insights(
        ["CRITICAL: 5 critical vulnerabilities identified — rest"],
        {"Critical": 1, "High": 0, "Medium": 0, "Low": 0, "Info": 0},
    )
    assert out[0].startswith("CRITICAL: 1 critical vulnerability identified")
    assert out[0].endswith("— rest")


def test_critical_normalisation_is_idempotent():
    dist = {"Critical": 1, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    once = normalize_report_insights(
        ["CRITICAL: 3 critical vulnerabilities identified — x"], dist)
    assert normalize_report_insights(once, dist) == once


# ===========================================================================
# Cosmetic b -- Excel benchmark disposition must match the PDF's derivation.
# ===========================================================================


def test_excel_benchmark_note_matches_the_pdf_for_every_fixture():
    """NEGATIVE: Excel returned '' wherever the PDF rendered real text.

    Both renderers had a ``_v17923_benchmark_note``; only the PDF one fell
    back to ``benchmark_ground_truth.status``, so all 63 Excel rows read
    '--' while the PDF said "unresolved"/"intentional".
    """
    from reporting.pdf_report import _v17923_benchmark_note as pdf_note

    fixtures = [
        {"benchmark_ground_truth": {"status": "UNRESOLVED"}},
        {"benchmark_ground_truth": {"status": "DECLARED_INTENTIONAL"}},
        {"benchmark_note": "explicit note wins",
         "benchmark_ground_truth": {"status": "UNRESOLVED"}},
        {},
    ]
    for fixture in fixtures:
        assert excel_report._v17923_benchmark_note(fixture) == pdf_note(fixture), fixture
    unresolved = {"benchmark_ground_truth": {"status": "UNRESOLVED"}}
    assert excel_report._v17923_benchmark_note(unresolved) != "", (
        "UNRESOLVED must render the same adjudication text as the PDF"
    )


# ===========================================================================
# D1 -- AML gap prose must count the recorded gaps, and cite the shipped
# register, not a repo-relative path the reader never receives (D4 wording).
# ===========================================================================


def test_nistaml_gap_prose_counts_gaps_not_unobserved_classes():
    """NEGATIVE: the shipped PDF said "The remaining 17 ..." over a 7-row table.

    ``catalogue - observed`` counts attack classes with no *observation*,
    which is a different set from the classes with no *detection rule*.
    """
    text = _pdf_text(_nistaml_section({"findings": []}))
    gaps = len(NISTAML_DETECTION_GAPS)
    catalogue = len(NISTAML_ATTACKS)
    assert gaps > 0 and catalogue > gaps
    assert "The remaining" not in text
    assert (
        f"{gaps} of the {catalogue} catalogue attack classes are recorded as "
        "detection gaps (no detection rule in this release)"
    ) in text
    # D4 wording: name the file shipped beside the report, not the repo path.
    assert "gap_register.json (G-088)" in text
    assert "reports/gap_register.json" not in text


def test_excel_nistaml_footer_cites_the_shipped_register():
    """The Excel AML sheet footer must use the same citation as the PDF."""
    import inspect

    source = inspect.getsource(excel_report)
    assert "reports/gap_register.json" not in source, (
        "Excel must not cite the gitignored repo path; cite the copy shipped "
        "beside the report"
    )
    assert "gap_register.json (G-088)" in source


# ===========================================================================
# D2 -- every advisory id must survive into the rendered cells.
# ===========================================================================


def _vuln_pkg(**overrides):
    pkg = {
        "name": "jsonwebtoken",
        "version": "8.5.1",
        "severity": "High",
        "cve_list": [f"CVE-2024-{n:04d}" for n in range(1, 9)],
        "advisory_ids": [f"GHSA-aaaa-bbbb-cccc-{i}" for i in range(1, 9)],
        "vulnerability_age_days": 30,
        "epss_score": 0.123,
        "kev_status": "",
        "exploitability_decision": "PRIORITY_PATCH",
        "reachable": True,
        "reachability_priority": "REACHABLE_VULNERABLE",
        "fixed_versions": ["9.0.0"],
    }
    pkg.update(overrides)
    return pkg


def _all_ids(pkg):
    return list(pkg["cve_list"]) + [a for a in pkg["advisory_ids"]]


def test_sbom_section_lists_every_advisory_id():
    """NEGATIVE: the SBOM table printed 5 of 16 ids with no ellipsis."""
    pkg = _vuln_pkg()
    payload = {
        "sbom": [pkg],
        "metadata": {
            "sbom_packages": 1,
            "cve_count": len(pkg["cve_list"]),
            "advisory_count": len(pkg["advisory_ids"]),
            "unique_vulnerable_packages": 1,
            "vulnerable_advisory_records": 1,
        },
    }
    text = _pdf_text(_sbom_section(payload))
    missing = [i for i in _all_ids(pkg) if i not in text]
    assert not missing, f"SBOM table dropped advisory ids: {missing}"


def test_sca_priority_section_lists_every_advisory_id():
    """NEGATIVE: the page-5 priority table used ids[:5]."""
    pkg = _vuln_pkg(severity="Critical")
    text = _pdf_text(_sca_remediation_priority_section({"sbom": [pkg]}))
    missing = [i for i in _all_ids(pkg) if i not in text]
    assert not missing, f"SCA priority table dropped advisory ids: {missing}"


def test_excel_pkg_cve_list_reads_the_list_and_advisory_keys():
    """NEGATIVE: _pkg_cve_list ignored cve_list/advisory_ids, so GHSAs
    never reached the Excel 'CVE / Advisory' cells."""
    pkg = _vuln_pkg()
    listed = excel_report._pkg_cve_list(pkg)
    missing = [i for i in _all_ids(pkg) if i not in listed]
    assert not missing, f"_pkg_cve_list dropped ids: {missing}"


def test_excel_exploitable_sheet_lists_every_advisory_id():
    """NEGATIVE: the Exploitable CVEs cell used _pkg_cve_list(pkg)[:6]."""
    from openpyxl import Workbook

    pkg = _vuln_pkg()
    payload = {"sbom": [pkg], "metadata": {}}
    ws = Workbook().active
    excel_report._exploitable_cves(ws, payload)
    # Row 3 is the only data row; column 5 is "CVE / Advisory".
    cell = ws.cell(row=3, column=5).value
    assert cell, "vulnerable package row missing from Exploitable CVEs sheet"
    missing = [i for i in _all_ids(pkg) if i not in str(cell)]
    assert not missing, f"Exploitable CVEs cell dropped ids: {missing}"


# ===========================================================================
# D3 -- accuracy-layer verdicts must reach both artifacts.
# ===========================================================================


def _accuracy_payload():
    finding = {
        "severity": "Low",
        "title": "track order id in URL",
        "vuln_type": "Information Exposure",
        "file": "frontend/src/app/track-order/trackOrder.ts",
        "line": 18,
        "rule_id": "LLM04",
        "confidence": "Medium",
        "accuracy": {
            "verdict": "LIKELY_FALSE_POSITIVE",
            "confidence": 0.87,
        },
    }
    return {
        "grouped": [finding],
        "findings": [finding],
        "metadata": {
            "total_findings": 1,
            "severity_distribution": {"Critical": 0, "High": 0, "Medium": 0,
                                      "Low": 1, "Info": 0},
            "accuracy_summary": {
                "filtered": 1,
                "total": 63,
                "verdicts": {
                    "LIKELY_FALSE_POSITIVE": 23,
                    "MISLABELED": 1,
                    "NEEDS_REVIEW": 38,
                    "TRUE_POSITIVE": 1,
                },
            },
        },
    }


def test_pdf_findings_section_surfaces_accuracy_verdict_and_summary():
    """NEGATIVE: the shipped PDF contained zero accuracy verdicts.

    Only the one INVALID evidence row was disclosed; the finding cards and
    the section preamble never mentioned the accuracy audit at all.
    """
    payload = _accuracy_payload()
    text = _pdf_text(_findings_section(payload))
    # Section-level disclosure from metadata.accuracy_summary.
    assert "Accuracy layer" in text
    assert "LIKELY_FALSE_POSITIVE: 23" in text
    assert "NEEDS_REVIEW: 38" in text
    # Card-level row for the individual finding.
    assert "LIKELY_FALSE_POSITIVE" in text


def test_excel_findings_sheet_has_an_accuracy_verdict_column():
    """NEGATIVE: the 34-column Excel Findings sheet had no verdict column."""
    from openpyxl import Workbook

    payload = _accuracy_payload()
    ws = Workbook().active
    excel_report._findings(ws, payload)
    header = [
        ws.cell(row=2, column=c).value
        for c in range(1, ws.max_column + 1)
    ]
    assert "Accuracy Verdict" in header, header
    col = header.index("Accuracy Verdict") + 1
    value = ws.cell(row=3, column=col).value
    assert value == "LIKELY_FALSE_POSITIVE"


def test_excel_summary_sheet_reports_accuracy_counts():
    from openpyxl import Workbook

    payload = _accuracy_payload()
    ws = Workbook().active
    excel_report._summary(ws, payload)
    labels = {
        ws.cell(row=r, column=1).value: ws.cell(row=r, column=2).value
        for r in range(1, ws.max_row + 1)
    }
    assert "Accuracy Layer Verdicts" in labels, sorted(labels)
    assert "LIKELY_FALSE_POSITIVE=23" in str(labels["Accuracy Layer Verdicts"])


# ===========================================================================
# D5 -- the executive decision must be visible in the branch this corpus
# actually lands in (remediation_required), not only in `blocking`.
# ===========================================================================


def test_conclusion_remediation_branch_surfaces_executive_decision():
    """NEGATIVE: DO_NOT_RELEASE appeared on zero pages of the shipped PDF.

    The JSON carried executive_decision=DO_NOT_RELEASE (P0, confidence 0.95)
    while release_readiness.release_decision=REMEDIATE_BEFORE_RELEASE, and
    only the blocking branch prints the executive line.
    """
    payload = {
        "metadata": {
            "total_findings": 63,
            "risk_score": 48.1,
            "severity_distribution": {
                "Critical": 2, "High": 4, "Medium": 34, "Low": 26, "Info": 17,
            },
            "canonical_release_decision": "REMEDIATE_BEFORE_RELEASE",
        },
        "release_readiness": {
            "release_decision": "REMEDIATE_BEFORE_RELEASE",
            "blocking_gates": [{"gate_id": "G-001", "reason": "reason"}],
            "review_gates": [],
        },
        "executive_decision": {
            "executive_decision": "DO_NOT_RELEASE",
            "confidence": 0.95,
            "drivers": ["CLOUD", "CONTAINER"],
        },
        "grouped": [],
    }
    text = _pdf_text(_conclusion(payload))
    assert "DO_NOT_RELEASE" in text
    assert "Executive decision" in text


def test_conclusion_review_branch_surfaces_executive_decision():
    payload = {
        "metadata": {
            "total_findings": 3,
            "risk_score": 20.0,
            "severity_distribution": {
                "Critical": 0, "High": 1, "Medium": 1, "Low": 1, "Info": 0,
            },
        },
        "release_readiness": {
            "release_decision": "SECURITY_REVIEW_REQUIRED",
            "blocking_gates": [],
            "review_gates": [],
        },
        "executive_decision": {
            "executive_decision": "SECURITY_REVIEW_REQUIRED",
            "confidence": 0.8,
        },
        "grouped": [],
    }
    text = _pdf_text(_conclusion(payload))
    assert "Executive decision" in text


# ===========================================================================
# D4 -- gap_register.json must be shipped next to the report artifacts.
# ===========================================================================


def test_ship_gap_register_copies_the_register_beside_the_report(tmp_path):
    from reporting.companion_artifacts import ship_gap_register

    src = tmp_path / "register_src.json"
    src.write_text('{"gaps": [{"id": "G-088"}]}', encoding="utf-8")
    out = tmp_path / "out"
    out.mkdir()
    ok = ship_gap_register(out, source=src)
    assert ok is True
    copied = out / "gap_register.json"
    assert copied.is_file()
    assert copied.read_text(encoding="utf-8") == src.read_text(encoding="utf-8")


def test_ship_gap_register_with_missing_source_is_a_noop(tmp_path):
    from reporting.companion_artifacts import ship_gap_register

    out = tmp_path / "out"
    out.mkdir()
    ok = ship_gap_register(out, source=tmp_path / "does_not_exist.json")
    assert ok is False
    assert not (out / "gap_register.json").exists()


def test_ship_gap_register_default_source_is_the_repo_register(tmp_path):
    from reporting.companion_artifacts import ship_gap_register

    repo_src = ROOT / "reports" / "gap_register.json"
    if not repo_src.is_file():
        pytest.skip("reports/gap_register.json absent from this checkout")
    out = tmp_path / "out"
    out.mkdir()
    ok = ship_gap_register(out)
    assert ok is True
    assert (out / "gap_register.json").read_bytes() == repo_src.read_bytes()


# ===========================================================================
# Cosmetic e -- ASVS by_mode counts attribution columns, not findings.
# ===========================================================================


def test_asvs_by_mode_table_counts_attributions_not_findings():
    """NEGATIVE: header said "Findings" while DIRECT+RELATED+UNMAPPED
    summed to 126 = 63 findings x 2 attribution columns (CWE + vuln_type).
    """
    summary = {
        "status": "OK",
        "catalogue_size": 278,
        "requirements_reachable": ["ASVS-v4.0.3-1.2.3"],
        "cwe": {"by_mode": {"DIRECT": 56, "RELATED": 6, "UNMAPPED": 64}},
        "vuln_type": {"by_mode": {}},
        "findings_mapped": 63,
        "findings_unmapped": 0,
    }
    text = _pdf_text(_asvs_section({"asvs_summary": summary}))
    assert "Resolution Mode Attributions" in text
    assert "Resolution Mode Findings" not in text
    assert "not distinct findings" in text
