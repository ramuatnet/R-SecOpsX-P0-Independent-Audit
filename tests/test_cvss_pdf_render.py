"""The report must name the CVSS version in the two tables that print a score.

Rendering is where this could still go wrong: the helper can be correct and a
table can pass a different field to it, or the widened column can still be too
narrow. So both tables are exercised with real flowables and their cells are
read column-by-column rather than searched as one blob -- searching the whole
page for a number proves nothing about which column printed it.
"""

import re
from pathlib import Path

import pytest

from reporting.pdf_report import _sca_remediation_priority_section, _sbom_section

PDF_SOURCE = Path(__file__).resolve().parents[1] / "reporting" / "pdf_report.py"

# column indices in each table's header row
DEP_NCOLS, DEP_CVSS = 10, 4
SCA_NCOLS, SCA_CVSS = 8, 4


def _cell_text(cell) -> str:
    if isinstance(cell, str):
        return cell
    return getattr(cell, "text", None) or ""


def _column(story, ncols: int, index: int) -> list[str]:
    """Every rendered cell in one column, in row order."""
    for flowable in story:
        cells = getattr(flowable, "_cellvalues", None)
        if cells and len(cells[0]) == ncols:
            return [_cell_text(row[index])
                    for row in cells[1:] if len(row) > index]
    raise AssertionError(f"no {ncols}-column table in story")


def _story_text(story) -> str:
    """Every string a reader could actually see in the rendered flowables."""
    chunks = []

    def _walk(flowable):
        text = getattr(flowable, "text", None)
        if isinstance(text, str):
            chunks.append(text)
            return
        cells = getattr(flowable, "_cellvalues", None)
        if cells:
            for row in cells:
                for cell in row:
                    if isinstance(cell, str):
                        chunks.append(cell)
                    elif hasattr(cell, "_cellvalues"):
                        _walk(cell)
                    else:
                        inner = getattr(cell, "text", None)
                        if isinstance(inner, str):
                            chunks.append(inner)
                        elif inner is not None:
                            _walk(inner)

    for flowable in story:
        _walk(flowable)
    return "\n".join(chunks)


def _pkg(**kw):
    base = {
        "name": "demo",
        "version": "1.2.3",
        "ecosystem": "npm",
        "purl": "pkg:npm/demo@1.2.3",
        "severity": "Critical",
        "highest_vulnerability_severity": "Critical",
        "vulnerabilities": [{"id": "GHSA-xxxx-yyyy-zzzz", "summary": "demo"}],
        "cve_list": ["CVE-2024-0001"],
        "advisory_ids": [],
        "cvss": 9.8,
    }
    base.update(kw)
    return base


def _dep_payload(*pkgs):
    return {"sbom": list(pkgs), "metadata": {}}


def _sca_payload(*pkgs):
    return {"sbom": list(pkgs)}


def _dep_cells(**kw) -> list[str]:
    return _column(_sbom_section(_dep_payload(_pkg(**kw))),
                   DEP_NCOLS, DEP_CVSS)


def _sca_cells(**kw) -> list[str]:
    return _column(_sca_remediation_priority_section(_sca_payload(_pkg(**kw))),
                   SCA_NCOLS, SCA_CVSS)


# ------------------------------------------------------- dependency table ----
def test_dependency_cell_names_the_version_and_score():
    assert _dep_cells(cvss_version="4.0", cvss_preferred_score=6.9) == [
        "CVSS 4.0 — 6.9"
    ]


def test_dependency_cell_never_prints_the_31_number_for_a_40_primary():
    """The legacy scalar is 9.8 -- its 3.1 sibling's score. If that leaked
    into this column the report would be relabelling a 3.1 number as 4.0."""
    cells = _dep_cells(cvss_version="4.0", cvss_preferred_score=6.9, cvss=9.8)
    assert cells == ["CVSS 4.0 — 6.9"]
    assert not any("9.8" in c for c in cells)


def test_dependency_cell_dashes_a_package_with_no_vulnerability():
    cells = _dep_cells(vulnerabilities=[], cve_list=[], advisory_ids=[],
                       severity="Unknown", cvss=None,
                       cvss_version=None, cvss_preferred_score=None)
    assert cells == ["--"]


def test_a_package_with_a_finding_is_never_dashed():
    """A dash denies the finding; an absent score affirms it. Swapping them
    would understate a live vulnerability."""
    for kw in ({"cvss_version": "4.0", "cvss_preferred_score": None},
               {"cvss_version": None, "cvss_preferred_score": None},
               {"cvss_version": "3.1", "cvss_preferred_score": None}):
        cells = _dep_cells(cvss=None, **kw)
        assert cells != ["--"], kw
        assert "score unavailable" in cells[0], kw


def test_dependency_cell_says_unavailable_when_a_finding_has_no_score():
    assert _dep_cells(cvss_version="4.0", cvss_preferred_score=None,
                      cvss=None) == ["CVSS 4.0 — score unavailable"]


def test_dependency_cell_admits_an_unknown_version_rather_than_guessing():
    assert _dep_cells(cvss_version=None, cvss_preferred_score=7.5,
                      cvss=7.5) == ["CVSS version unknown — 7.5"]


def test_dependency_cell_renders_a_legacy_payload_that_has_no_version_keys():
    """A payload written before this change carries only the legacy scalar."""
    cells = _dep_cells(cvss_version=None, cvss_preferred_score=None, cvss=5.3)
    assert cells == ["CVSS version unknown — 5.3"]


def test_dependency_table_still_totals_exactly_the_frame():
    """Widening CVSS by shaving Type and Reachable must not drift the total."""
    src = PDF_SOURCE.read_text(encoding="utf-8-sig")
    m = re.search(r"colWidths=\[([^\]]*3\.08\*cm[^\]]*)\]", src)
    assert m, "dependency colWidths not found"
    body = re.sub(r"#[^\n]*", "", m.group(1)).replace("\n", " ")
    widths = [float(x.replace("*cm", "").strip())
              for x in body.split(",") if x.strip()]
    assert len(widths) == DEP_NCOLS
    assert abs(sum(widths) - 17.40) < 1e-6, sum(widths)
    assert widths[0] == 3.08, "Package column must not be shaved"
    assert widths[3] == 3.04, "Advisory column must not be shaved"
    assert widths[4] == 2.04, "CVSS column should be 2.04cm"


def test_dependency_section_explains_the_new_cell():
    text = _story_text(_sbom_section(_dep_payload(_pkg())))
    assert "score unavailable</i> means the vulnerability exists" in text
    assert "--</b> means no vulnerability was recorded" in text


# -------------------------------------------------------------- SCA table ----
def test_sca_cell_names_the_version_and_score():
    assert _sca_cells(cvss_version="4.0", cvss_preferred_score=6.9) == [
        "CVSS 4.0 — 6.9"
    ]


def test_sca_cell_keeps_a_31_primary_on_its_own_number():
    assert _sca_cells(cvss_version="3.1", cvss_preferred_score=9.8,
                      cvss=9.8) == ["CVSS 3.1 — 9.8"]


def test_sca_cell_never_prints_a_bare_number_for_a_40_primary():
    cells = _sca_cells(cvss_version="4.0", cvss_preferred_score=6.9, cvss=9.8)
    assert cells == ["CVSS 4.0 — 6.9"]
    assert not any("9.8" in c for c in cells)


def test_sca_cell_admits_an_unknown_version_without_naming_one():
    cells = _sca_cells(cvss_version="UNKNOWN", cvss_preferred_score=7.5)
    assert cells == ["CVSS version unknown — 7.5"]
    assert not any("UNKNOWN" in c for c in cells)


def test_sca_table_fits_inside_the_frame_after_widening_cvss():
    src = PDF_SOURCE.read_text(encoding="utf-8-sig")
    m = re.search(r"colWidths=\[([^\]]*1\.55\*cm[^\]]*)\]", src)
    assert m, "SCA colWidths not found"
    body = re.sub(r"#[^\n]*", "", m.group(1)).replace("\n", " ")
    widths = [float(x.replace("*cm", "").strip())
              for x in body.split(",") if x.strip()]
    assert len(widths) == SCA_NCOLS
    assert sum(widths) <= 17.40, sum(widths)
    assert widths[4] == 2.0, "SCA CVSS column should be 2.0cm"


# -------------------------------------------------------------- the source ----
def test_pdf_keeps_its_utf8_bom():
    """An earlier uncommitted patch dropped it silently; never again."""
    assert PDF_SOURCE.read_bytes().startswith(b"\xef\xbb\xbf")


@pytest.mark.parametrize("story,expected", [
    (_sbom_section(_dep_payload(
        _pkg(cvss_version="4.0", cvss_preferred_score=6.9))), "CVSS 4.0 — 6.9"),
])
def test_rendered_cells_use_the_em_dash_the_glyph_check_covers(story, expected):
    assert expected in _column(story, DEP_NCOLS, DEP_CVSS)
    assert "\u2014" in expected
