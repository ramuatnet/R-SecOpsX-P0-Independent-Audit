"""The full-SBOM and licensing tables sort and dash by one shared rule.

A production report rendered @gradio/client 2.0.0 with CVE "--", CVSS "--",
EPSS "--", Severity "Unknown", Age "Not applicable" and Reachable "Yes".
Three vocabularies for "there is no vulnerability here", and the "Yes" read
as an exploitability claim when it only meant the package's import had been
observed. The Type legend (D/T) was printed *after* the 823-row table, so a
reader 10 pages in could not find it. The SBOM listed components in manifest
order, scattering 32 vulnerable rows across 823, and the licensing tables
listed them the same way.

This file pins the replacement contract, on both renderers, from one fixture:

  * a component with no advisory dashes every advisory-derived cell
    (severity, age, reachable, KEV, patch urgency, age bucket) -- the dash
    already shown in CVE / CVSS / EPSS -- while "Unknown"/"score
    unavailable" remain words for values an advisory genuinely lacks;
  * both renderers order rows with sbom_display_sort_key: vulnerable first
    by severity (Critical > High > Medium > Low), then clean components
    alphabetically, name then version;
  * the Type, Severity/Age/Reachable and CVSS legends render BEFORE the
    first row of the PDF table, exactly once each;
  * both licensing tables order rows with license_sort_key (resolved
    licence, then component) and hand the payload back untouched.
"""

import copy

from openpyxl import Workbook

from reporting.excel_report import _licensing_details, _sbom
from reporting.pdf_report import _licensing_section, _sbom_section
from reporting.report_mappings import (
    license_sort_key,
    pkg_has_advisory,
    sbom_display_sort_key,
)

PDF_NCOLS = 10
PKG_COL, SEV_COL, AGE_COL, REACH_COL = 0, 6, 7, 8


def _clean(name, version="1.0.0", **kw):
    """A component with no advisory -- shaped like the @gradio/client row."""
    base = {
        "name": name, "version": version, "direct": True,
        "dependency_type": "Direct",
        "severity": "Unknown",
        "vulnerability_age": "Not applicable",
        "vulnerability_age_days": None,
        "vulnerability_age_bucket": "NOT_APPLICABLE",
        "reachable": True, "reachability_status": "OBSERVED_IMPORT",
        "reachability_priority": "NOT_APPLICABLE",
        "epss_score": None, "kev_status": False,
        "patch_urgency": "STANDARD", "fixed_in": "--",
    }
    base.update(kw)
    return base


def _vuln(name, severity, cve, **kw):
    base = {
        "name": name, "version": "1.0.0", "direct": True,
        "dependency_type": "Transitive",
        "severity": severity, "cve": cve,
        "vulnerabilities": [{"id": cve, "summary": "demo"}],
        "cve_list": [cve],
        "vulnerability_age_days": 30,
        "vulnerability_age_bucket": "AGING",
        "reachable": False,
        "epss_score": 0.5, "kev_status": False,
        "patch_urgency": "STANDARD",
        "fixed_in": "2.0.0",
    }
    base.update(kw)
    return base


def _payload(*pkgs):
    return {"sbom": list(pkgs), "metadata": {}}


# ---------------------------------------------------------------- helpers ---

def _cell_text(cell) -> str:
    if isinstance(cell, str):
        return cell
    return getattr(cell, "text", None) or ""


def _table_cells(story, ncols=PDF_NCOLS):
    for flowable in story:
        cells = getattr(flowable, "_cellvalues", None)
        if cells and len(cells[0]) == ncols:
            return cells
    raise AssertionError(f"no {ncols}-column table in story")


def _pdf_columns(story):
    """Package / Severity / Age / Reachable columns, data rows in order."""
    cells = _table_cells(story)
    return [ [_cell_text(row[i]) for row in cells[1:]] for i in (PKG_COL, SEV_COL, AGE_COL, REACH_COL) ]


def _write(writer, payload):
    wb = Workbook()
    writer(wb.active, payload)
    return wb.active


def _sheet_column(ws, header, header_row=2):
    col = next((c.column for c in ws[header_row] if c.value == header), None)
    assert col, f"no {header!r} header on {ws.title}"
    return col


def _sheet_rows(ws, header, header_row=2):
    """Values under a header, skipping legend/meta rows (text in col A only)."""
    col = _sheet_column(ws, header, header_row)
    out = []
    for row in ws.iter_rows(min_row=header_row + 1, min_col=1):
        first = row[0].value
        if first is None or (isinstance(first, str) and
                             first.startswith(("Legend:", "EPSS provenance"))):
            continue
        cell = next((c for c in row if c.column == col), None)
        out.append("" if cell is None or cell.value is None else str(cell.value))
    return out


# ------------------------------------------------- shared sort primitives ---
def test_predicate_unions_every_field_the_two_renderers_used_alone():
    assert pkg_has_advisory({"vulnerabilities": [{"id": "GHSA-x"}]})
    assert pkg_has_advisory({"cve": "CVE-2024-0001"})
    assert pkg_has_advisory({"advisory_id": "GHSA-xxxx"})          # PDF-only field
    assert pkg_has_advisory({"advisory_ids": ["GHSA-yyyy"]})
    assert pkg_has_advisory({"cve_list": ["CVE-2024-0002"]})
    assert pkg_has_advisory({"additional_cves": ["CVE-2024-0003"]})  # Excel-only field
    assert not pkg_has_advisory({"name": "gradio", "severity": "Unknown"})
    assert not pkg_has_advisory(None) and not pkg_has_advisory("pkg")


def test_sort_puts_severity_above_alphabet_and_clean_rows_last():
    crit = _vuln("zzz-critical", "Critical", "CVE-2024-1")
    high = _vuln("aaa-high", "High", "CVE-2024-2")
    clean = _clean("mmm-clean")
    # severity beats the name (zzz-critical is alphabetically last),
    # and clean rows sort after every vulnerable row
    assert sbom_display_sort_key(crit) < sbom_display_sort_key(high)
    assert sbom_display_sort_key(high) < sbom_display_sort_key(clean)
    shuffled = [clean, high, crit]
    shuffled.sort(key=sbom_display_sort_key)
    assert shuffled == [crit, high, clean]


def test_license_key_accepts_both_source_shapes_and_groups_by_licence():
    pdf_row = {"package": "a-pkg", "license_resolved": "MIT"}
    xls_row = {"name": "a-pkg", "license_resolved": "MIT"}
    other = {"package": "a-pkg", "license_resolved": "Apache-2.0"}
    assert license_sort_key(other) < license_sort_key(pdf_row)
    assert license_sort_key(pdf_row) == license_sort_key(xls_row)
    # absent licence never sorts before a real one
    assert license_sort_key({"package": "x"}) >= license_sort_key(
        {"package": "x", "license_resolved": "0BSD"})


# ------------------------------------------------------- PDF SBOM table -----
def test_pdf_clean_row_dashes_every_advisory_derived_cell():
    pkg = _clean("@gradio/client", version="2.0.0")
    pkg_sev, pkg_age, pkg_reach = _pdf_columns(_sbom_section(_payload(pkg)))[1:]
    assert pkg_sev == ["--"], "severity must dash where CVE/CVSS/EPSS dash"
    assert pkg_age == ["--"], "age must dash where CVE/CVSS/EPSS dash"
    assert pkg_reach == ["--"], (
        "Reachable on a row with no advisory is not a Yes/No question -- "
        "the old 'Yes' (import observed) read as an exploitability claim")


def test_pdf_vulnerable_row_keeps_its_real_values_and_words():
    pkg = _vuln("pkg-high", "High", "CVE-2024-0001")
    pkg_sev, pkg_age, pkg_reach = _pdf_columns(_sbom_section(_payload(pkg)))[1:]
    assert pkg_sev == ["High"]
    assert pkg_age[0].startswith("30d")          # real age, not a dash
    assert pkg_reach == ["No"]                   # Yes/No only WITH an advisory
    # a genuinely unpublished value stays a word, never a dash
    unknown = _vuln("pkg-unknown", "Unknown", "CVE-2024-0002",
                    vulnerability_age_days=None, vulnerability_age=None)
    sev, age, _ = _pdf_columns(_sbom_section(_payload(unknown)))[1:]
    assert sev == ["Unknown"] and age == ["Unknown"]


def test_pdf_orders_rows_vulnerable_by_severity_then_clean_alphabetically():
    clean_z = _clean("zzz-clean")
    clean_a = _clean("aaa-clean")
    low = _vuln("bbb-low", "Low", "CVE-2024-3")
    crit = _vuln("zzz-critical", "Critical", "CVE-2024-1")
    high = _vuln("aaa-high", "High", "CVE-2024-2")
    names, *_ = _pdf_columns(_sbom_section(_payload(clean_z, low, clean_a, high, crit)))
    assert names == ["zzz-critical", "aaa-high", "bbb-low", "aaa-clean", "zzz-clean"]


def test_pdf_legends_render_above_the_table_and_only_once():
    story = _sbom_section(_payload(_clean("gradio"), _vuln("pkg", "High", "CVE-1")))
    table_at = next(i for i, f in enumerate(story)
                    if getattr(f, "_cellvalues", None)
                    and len(f._cellvalues[0]) == PDF_NCOLS)
    texts = [getattr(f, "text", "") for f in story if hasattr(f, "text")]
    type_at = next(i for i, t in enumerate(texts) if "D = declared directly in a manifest" in t)
    reach_at = next(i for i, t in enumerate(texts) if "Severity / Age / Reachable" in t)
    cvss_at = next(i for i, t in enumerate(texts) if "<b>CVSS:</b>" in t)
    assert max(type_at, reach_at, cvss_at) < table_at, (
        "legends printed after an 823-row table are never read")
    joined = "\n".join(texts)
    assert joined.count("D = declared directly in a manifest") == 1
    assert joined.count("Severity / Age / Reachable") == 1
    # the test-pinned CVSS wording survives the move
    assert "score unavailable</i> means the vulnerability exists" in joined
    assert "--</b> means no vulnerability was recorded" in joined
    # the reader is told how the table is ordered
    assert "listed first ordered by severity" in joined


# -------------------------------------------------------- PDF licensing -----
def test_pdf_licensing_groups_by_resolved_licence_and_keeps_payload():
    payload = {"license_evidence": [
        {"package": "m-pkg", "version": "1.0", "license_resolved": "MIT",
         "license_declared": "MIT", "license_category": "Permissive",
         "license_resolution_status": "RESOLVED_FROM_CANONICAL_REPORT"},
        {"package": "z-pkg", "version": "1.0", "license_resolved": "LGPL-3.0-or-later",
         "license_declared": "LGPL-3.0-or-later", "license_category": "Custom / Review",
         "license_resolution_status": "RESOLVED_FROM_CANONICAL_REPORT"},
        {"package": "a-pkg", "version": "1.0", "license_resolved": "MIT",
         "license_declared": "MIT", "license_category": "Permissive",
         "license_resolution_status": "RESOLVED_FROM_CANONICAL_REPORT"},
    ]}
    before = copy.deepcopy(payload)
    cells = _table_cells(_licensing_section(payload), ncols=7)
    rendered = [tuple(_cell_text(c) for c in row) for row in cells[1:]]
    # LGPL-3.0-or-later groups first: ordering is by resolved licence, then
    # component -- not by component alone.
    assert [r[0] for r in rendered] == ["z-pkg", "a-pkg", "m-pkg"]
    assert [r[3] for r in rendered] == ["LGPL-3.0-or-later", "MIT", "MIT"]
    assert payload == before, "presentation sort must not mutate the payload"


# ---------------------------------------------------------- Excel sheets ----
def test_excel_sbom_dashes_the_same_cells_as_the_pdf():
    ws = _write(_sbom, {"sbom": [_clean("@gradio/client", version="2.0.0")]})
    row = {h: v for h, v in zip(
        [c.value for c in ws[2]],
        [c.value for c in ws[3]])}
    assert row["Severity"] == "--"
    assert row["Age Bucket"] == "--"
    assert row["Age Days"] == "--"
    assert row["Reachable Vulnerable"] == "--"
    assert row["KEV"] == "--"
    assert row["Patch Urgency"] == "--"
    assert row["Exploitability Decision"] == "--"
    assert row["CVE / Advisory"] == "--"


def test_excel_sbom_vulnerable_row_keeps_its_values():
    ws = _write(_sbom, {"sbom": [
        _vuln("pkg-high", "High", "CVE-2024-0001", kev_status="CVE-2024-0001",
              vulnerability_age_days=30),
    ]})
    row = {h: v for h, v in zip([c.value for c in ws[2]],
                                [c.value for c in ws[3]])}
    assert row["Severity"] == "High"
    assert row["KEV"] == "Yes"
    assert str(row["Age Days"]) == "30"
    assert row["Age Bucket"] == "AGING"


def test_excel_sbom_uses_the_same_order_as_the_pdf():
    pkgs = [_clean("zzz-clean"), _vuln("bbb-low", "Low", "CVE-2024-3"),
            _clean("aaa-clean"), _vuln("zzz-critical", "Critical", "CVE-2024-1"),
            _vuln("aaa-high", "High", "CVE-2024-2")]
    ws = _write(_sbom, {"sbom": pkgs})
    assert _sheet_rows(ws, "Component") == [
        "zzz-critical", "aaa-high", "bbb-low", "aaa-clean", "zzz-clean"]


def test_excel_sbom_prints_its_legend_beneath_the_data():
    ws = _write(_sbom, {"sbom": [_clean("gradio"), _vuln("pkg", "High", "CVE-1")]})
    legend = [str(c.value) for row in ws.iter_rows()
              for c in row if isinstance(c.value, str) and c.value.startswith("Legend:")]
    assert legend, "the sheet must explain Type, Reachable and the dash on its own"
    assert "Direct = declared in a manifest" in legend[0]
    assert "-- = no advisory recorded" in legend[0]


def test_excel_licensing_groups_by_resolved_licence():
    ws = _write(_licensing_details, {"sbom": [
        {"name": "m-pkg", "version": "1.0", "license_resolved": "MIT",
         "license_declared": "MIT"},
        {"name": "z-pkg", "version": "1.0", "license_resolved": "LGPL-3.0-or-later",
         "license_declared": "LGPL-3.0-or-later"},
        {"name": "a-pkg", "version": "1.0", "license_resolved": "MIT",
         "license_declared": "MIT"},
    ]})
    comps = _sheet_rows(ws, "Component", header_row=11)
    lics = _sheet_rows(ws, "Resolved License", header_row=11)
    assert comps == ["z-pkg", "a-pkg", "m-pkg"]
    assert lics == ["LGPL-3.0-or-later", "MIT", "MIT"]
