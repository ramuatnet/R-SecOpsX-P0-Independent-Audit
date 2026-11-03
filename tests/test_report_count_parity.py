# -*- coding: utf-8 -*-
"""taskf.md Phase 0 — reproduce DEF-A (count parity) and DEF-B (SBOM honesty).

Why this file exists: the same scan currently reports different totals on
different artifacts (XLSX Summary cell, PDF cover severity line, SPA embedded
JSON) and the SBOM version cell prints a bare placeholder that cannot be
distilled from an honest "we do not know" state.  This module pins both
defects with extractors that read the numbers BACK OUT of the finished
artifacts, so a fix must actually land in the rendered bytes -- editing the
payload alone cannot turn these tests green.

Refuses to do: fix anything.  Phase 0 is red-first (taskf ground rule 1/3);
product code must stay untouched until Gate 0 has been observed failing for
the documented reasons.

Fixture contract (taskf T-0.1), verified by test_fixture_contract:
  3 raw IaC detections -> 1 grouped record (identical snippet, no group_key),
  flask   = KNOWN_VULNS entry with published severity + fixed version,
  colorama= advisory stub with NO published severity,
  certifi = advisory stub with NO fixed version,
  six     = clean package, no advisory,
  express = range ``^4.17.4`` with no lockfile pin (version "unknown"),
  at least one package with direct=False (transitive guess table).
"""
from __future__ import annotations

import json
import os
import re
import shutil
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import openpyxl  # noqa: E402
import pymupdf  # noqa: E402

from core import report_aggregates  # noqa: E402
from core.analyzer import build_report_payload  # noqa: E402
from core.finding_model import normalize_payload  # noqa: E402
from reporting import excel_report, triage_spa  # noqa: E402
from reporting.excel_report import generate_excel_report  # noqa: E402
from reporting.pdf_report import generate_pdf_report  # noqa: E402
from scanner import vulnerability_intel  # noqa: E402
from scanner.iac_terraform import scan_terraform  # noqa: E402
from scanner.sbom import generate_sbom  # noqa: E402

FIXTURE_SRC = Path(__file__).resolve().parent / "fixtures" / "count_parity"
CORPUS_ROOT = Path(__file__).resolve().parent / "vuln-test-corpus"

# OSV advisory stubs injected at the network boundary (taskf T-0.1).
# Both records deliberately omit one field so the SBOM must render the
# absence honestly instead of a placeholder word:
#   colorama -- no severity key  (advisory without published severity)
#   certifi  -- no fixed_versions key (advisory without fixed version)
# ``cve`` is carried directly: scanner.vulnerability_intel reads
# worst["cve"], never the aliases list, when it stamps pkg["cve"].
_OSV_STUBS: dict[str, dict] = {
    "colorama": {
        "id": "GHSA-aaaa-bbbb-cccc",
        "advisory_id": "GHSA-aaaa-bbbb-cccc",
        "cve": "CVE-2024-11111",
        "aliases": ["CVE-2024-11111"],
        "summary": "advisory without published severity",
        "fixed_versions": ["0.4.7"],
        # no "severity" on purpose
    },
    "certifi": {
        "id": "GHSA-dddd-eeee-ffff",
        "advisory_id": "GHSA-dddd-eeee-ffff",
        "cve": "CVE-2024-22222",
        "aliases": ["CVE-2024-22222"],
        "severity": "HIGH",
        "summary": "advisory without fixed version",
        # no "fixed_versions" on purpose
    },
}


def _fake_query_osv_batch(packages: list[dict]) -> dict:
    """Offline stand-in for query_osv_batch: stub records, never a socket.

    Mirrors the real batch contract -- key is ``_cache_key(name, version,
    ecosystem)``, unresolvable versions are not queried, unknown packages
    return nothing.  A fresh dict copy per call keeps the shared stub
    records immutable when enrichment backfills provenance keys.
    """
    out: dict[str, list[dict]] = {}
    for pkg in packages:
        name = str(pkg.get("name") or "").strip()
        version = str(pkg.get("version") or "").strip()
        if name not in _OSV_STUBS or version.lower() in {"", "unknown"}:
            continue
        eco = vulnerability_intel.normalize_ecosystem(pkg.get("ecosystem", ""))
        key = vulnerability_intel._cache_key(name, version, eco)
        out[key] = [dict(_OSV_STUBS[name])]
    return out


def _fake_query_nvd_secondary(packages, osv_results):  # noqa: ANN001
    """NVD pass is opt-in (RSX_NVD_ENRICH); force it dark for the fixture."""
    return {}


@pytest.fixture(scope="module")
def fx(tmp_path_factory):
    """Copy the fixture, scan it, build the payload, render all three artifacts.

    The OSV/NVD stubs are installed for the build only (network boundary),
    then removed -- rendering must work on the payload alone.
    """
    work = tmp_path_factory.mktemp("count_parity")
    target = work / "project"
    shutil.copytree(FIXTURE_SRC, target)

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(vulnerability_intel, "query_osv_batch", _fake_query_osv_batch)
        mp.setattr(vulnerability_intel, "_query_nvd_secondary",
                   _fake_query_nvd_secondary)
        raw = scan_terraform(str(target))
        normalized = [
            normalize_payload({"findings": [f]})["findings"][0] for f in raw
        ]
        sbom = generate_sbom(str(target))
        payload = build_report_payload(normalized, sbom, str(target))

    xlsx_path = work / "Security_Report.xlsx"
    pdf_path = work / "Security_Report.pdf"
    html_path = work / "triage.html"
    generate_excel_report(payload, str(xlsx_path))
    generate_pdf_report(payload, str(pdf_path))
    html_path.write_bytes(triage_spa.build(payload, embedded=True))

    return SimpleNamespace(
        payload=payload,
        raw_count=len(raw),
        xlsx=xlsx_path,
        pdf=pdf_path,
        html=html_path,
    )


# --------------------------------------------------------------------------
# Artifact extractors -- numbers read back OUT of the finished files.
# --------------------------------------------------------------------------

# Phase 0 label is the bare "Total Findings"; Phase 4 (taskf T-4.2) renames
# it to name its population.  Both spellings resolve to the same cell so the
# test survives the renderer migration without weakening.
_TOTAL_LABEL = re.compile(r"^(Total Findings|Total reported items)\b", re.I)


def _xlsx_summary_total(xlsx_path: Path) -> int:
    """The Summary sheet's headline total cell."""
    wb = openpyxl.load_workbook(str(xlsx_path), data_only=True)
    try:
        ws = wb["Summary"]
        for row in ws.iter_rows(min_row=1, max_col=2, values_only=True):
            label = str(row[0]).strip() if row and row[0] is not None else ""
            if _TOTAL_LABEL.match(label):
                return int(str(row[1]).strip())
        raise AssertionError("Summary sheet has no total row "
                             f"(labels seen: none matched {_TOTAL_LABEL.pattern})")
    finally:
        wb.close()


def _xlsx_severity_sum(xlsx_path: Path) -> int:
    """Sum of the Summary sheet's severity table rows (Critical..Info)."""
    wb = openpyxl.load_workbook(str(xlsx_path), data_only=True)
    try:
        ws = wb["Summary"]
        total = 0
        in_dist = False
        for row in ws.iter_rows(min_row=1, max_col=2, values_only=True):
            label = str(row[0]).strip() if row and row[0] is not None else ""
            if label == "SEVERITY DISTRIBUTION":
                in_dist = True
                continue
            if label == "INTELLIGENCE INSIGHTS":
                break
            if in_dist and label in {"Critical", "High", "Medium", "Low", "Info"}:
                total += int(str(row[1] or 0).strip() or 0)
        return total
    finally:
        wb.close()


def _pdf_text(pdf_path: Path) -> str:
    doc = pymupdf.open(str(pdf_path))
    try:
        return "\n".join(page.get_text() for page in doc)
    finally:
        doc.close()


def _pdf_combined_severity_sum(pdf_text: str) -> int:
    """Cover's Combined Severity line, summed.

    This is the DEF-A canary: pre-fix it reads the SAST-only distribution
    while the XLSX headline reads SAST+SCA, so the two disagree on the same
    payload.  The optional Info group appears once Phase 4 renders the full
    five-bucket combined distribution.
    """
    m = re.search(
        r"Combined\s+Severity\s+C:(\d+)\s+H:(\d+)\s+M:(\d+)\s+L:(\d+)"
        r"(?:\s+I:(\d+))?",
        pdf_text,
    )
    if not m:
        raise AssertionError("PDF cover has no 'Combined Severity C:.. H:.. "
                             "M:.. L:..' line")
    return sum(int(g) for g in m.groups() if g is not None)


def _pdf_headline_totals(pdf_text: str) -> list[int]:
    """Every ``identified N unique findings`` occurrence (cover/exec/conclusion)."""
    return [int(x) for x in
            re.findall(r"identified\s+(\d+)\s+unique findings", pdf_text)]


def _spa_embedded(html_text: str) -> dict:
    m = re.search(r'id="rsx-triage-data"[^>]*>(.*?)</script>',
                  html_text, re.S)
    if not m:
        raise AssertionError("SPA page has no rsx-triage-data script tag")
    return json.loads(m.group(1))


def sbom_row(payload: dict, name: str) -> dict:
    """Rendered SBOM cells for one package, as the sheet would print them."""
    for pkg in payload.get("sbom") or []:
        if str(pkg.get("name")) == name:
            return {
                "pkg": pkg,
                "version": excel_report._sbom_current_version(pkg),
                "component": excel_report._sbom_component(pkg),
                "purl": excel_report._sbom_purl(pkg),
            }
    raise AssertionError(f"no SBOM package named {name!r}")


# --------------------------------------------------------------------------
# Tests
# --------------------------------------------------------------------------

def test_fixture_contract_groups_three_raw_to_one_and_states(fx):
    """T-0.1: the fixture provides every shape the parity/vocabulary tests need."""
    assert fx.raw_count == 3, (
        f"fixture must produce 3 raw IaC detections, got {fx.raw_count}")
    grouped = fx.payload.get("grouped") or []
    assert len(grouped) == 1, (
        f"fixture must group 3 raw detections down to 1 record, got {len(grouped)}")

    pkgs = {str(p.get("name")): p for p in fx.payload.get("sbom") or []}
    for required in ("flask", "six", "colorama", "certifi", "express"):
        assert required in pkgs, f"fixture SBOM missing {required!r}"

    flask = pkgs["flask"]
    assert str(flask.get("severity") or "").lower() == "high", (
        f"flask must carry the KNOWN_VULNS published severity, got {flask.get('severity')!r}")
    assert flask.get("cve") == "CVE-2018-1000656", (
        f"flask must carry the KNOWN_VULNS CVE, got {flask.get('cve')!r}")

    colorama = pkgs["colorama"]
    assert colorama.get("vulnerabilities"), (
        "colorama must carry the stubbed advisory (no-severity case)")
    assert not colorama.get("severity"), (
        "colorama advisory must have NO published severity, "
        f"got {colorama.get('severity')!r}")

    certifi = pkgs["certifi"]
    assert certifi.get("vulnerabilities"), (
        "certifi must carry the stubbed advisory (no-fixed-version case)")
    assert not (certifi.get("fixed_versions") or []), (
        f"certifi advisory must have NO fixed version, "
        f"got {certifi.get('fixed_versions')!r}")

    six = pkgs["six"]
    assert not (six.get("vulnerabilities") or six.get("cve")
                or six.get("cvss")), (
        "six must stay clean (no advisory) -- "
        f"vulns={six.get('vulnerabilities')} cve={six.get('cve')} "
        f"cvss={six.get('cvss')}")

    express = pkgs["express"]
    assert str(express.get("version")) == "unknown", (
        "express must be the unresolvable range ^4.17.4 (no lockfile pin), "
        f"got {express.get('version')!r}")
    assert express.get("direct") is True, (
        f"express is a manifest direct dependency, got direct={express.get('direct')!r}")

    assert any(not p.get("direct") for p in fx.payload.get("sbom") or []), (
        "fixture must contain at least one direct=False (transitive) package")


def test_count_parity_across_artifacts_and_aggregate(fx):
    """T-0.2 / T-4.4: one aggregate, every artifact agrees with it.

    Pre-fix this fails on ``{summary, pdf_total, html_total} == {agg_total}``
    because payload has no ``aggregates`` key at all (agg_total is None) and
    because the PDF cover severity line disagrees with the XLSX headline on
    the very same payload -- the documented DEF-A divergence.
    """
    payload = fx.payload
    meta = payload.get("metadata") or {}
    counts = (payload.get("aggregates") or {}).get("counts") or {}
    agg_total = counts.get("total_reported")

    summary = _xlsx_summary_total(fx.xlsx)
    severity_sum = _xlsx_severity_sum(fx.xlsx)
    pdf_text = _pdf_text(fx.pdf)
    pdf_total = _pdf_combined_severity_sum(pdf_text)
    pdf_headlines = _pdf_headline_totals(pdf_text)
    embedded = _spa_embedded(fx.html.read_text(encoding="utf-8"))
    html_total = int(embedded["report"]["total_findings"])
    spa_rows = len(embedded.get("findings") or [])

    populations = (
        f"populations (DEF-A): total_findings={meta.get('total_findings')} "
        f"sast_findings={meta.get('sast_findings')} "
        f"sca_findings={meta.get('sca_findings')} "
        f"len_grouped={len(payload.get('grouped') or [])} "
        f"len_findings={len(payload.get('findings') or [])} "
        f"xlsx_severity_sum={severity_sum} spa_rows={spa_rows} "
        f"pdf_headlines={pdf_headlines}"
    )

    assert {summary, pdf_total, html_total} == {agg_total}, (
        f"count parity broken: summary={summary} pdf_total={pdf_total} "
        f"html_total={html_total} agg_total={agg_total} | {populations}"
    )

    # Reached only once the headline identity holds: the severity table must
    # sum to its own population (taskf T-4.4 second assert).
    assert severity_sum == agg_total, (
        f"severity table does not reconcile: xlsx_severity_sum={severity_sum} "
        f"agg_total={agg_total} | {populations}"
    )


def test_sbom_version_names_its_absence_reason(fx):
    """T-0.3: the express version cell must say WHY it is unknown.

    Pre-fix ``_sbom_current_version`` passes the producer's bare ``"unknown"``
    straight through (taskf DEF-B).  Post-fix it routes through value_state
    and renders the MANIFEST_RANGE reason string.
    """
    rendered = sbom_row(fx.payload, "express")["version"]
    assert rendered == "unknown (manifest declares a range, no lockfile pin)", (
        "express version cell must name its absence reason; "
        f"got {rendered!r}"
    )


# --------------------------------------------------------------------------
# Gate 4 -- the same parity asserted on real populations, not just the fixture
# --------------------------------------------------------------------------

def _scan_family(family, casedir, name):
    """Raw engine output for one corpus case (production input shape).

    Dispatch mirrors ``analysis.validation.run``: each family answers a
    different scoring question, so each gets its own scanner.  Copied rather
    than imported because tests are not a package (same table as
    tests/test_report_aggregates.py).
    """
    from analysis.validation import run as vrun

    if family == "sca":
        return vrun._scan_sca(casedir)
    if family == "cbom":
        return vrun._scan_cbom(casedir, name)
    if family in ("sast", "ai_ml"):
        return vrun._scan_sast(casedir, name)
    if family == "secrets":
        return vrun._scan_secrets(casedir, name)
    if family == "iac":
        return vrun._scan_iac(casedir, name)
    if family == "sbom":
        return vrun._scan_sbom(casedir, name)
    raise ValueError(f"unknown corpus family: {family!r}")


def _render_and_extract(payload, out_dir: Path, stem: str) -> dict:
    """Render all three artifacts for one payload; read every total back out.

    The numbers come from the finished bytes (openpyxl cell, PDF text regex,
    embedded JSON tag) -- never from the payload -- so a renderer that
    re-derives a count anywhere fails here even if the payload is perfect.
    """
    xlsx = out_dir / f"{stem}.xlsx"
    pdf = out_dir / f"{stem}.pdf"
    generate_excel_report(payload, str(xlsx))
    generate_pdf_report(payload, str(pdf))
    html_text = triage_spa.build(payload, embedded=True).decode("utf-8")

    agg = payload.get("aggregates") or report_aggregates.build(payload)
    embedded = _spa_embedded(html_text)
    return {
        "xlsx_total": _xlsx_summary_total(xlsx),
        "xlsx_severity_sum": _xlsx_severity_sum(xlsx),
        "pdf_severity_sum": _pdf_combined_severity_sum(_pdf_text(pdf)),
        "spa_total": int(embedded["report"]["total_findings"]),
        "agg_total": int(agg["counts"]["total_reported"]),
    }


def _assert_parity(x: dict, where: str) -> None:
    """One population, every artifact.  A break raises; nothing picks a side."""
    trio = {x["xlsx_total"], x["pdf_severity_sum"], x["spa_total"]}
    assert trio == {x["agg_total"]}, (
        f"count parity broken on {where}: xlsx={x['xlsx_total']} "
        f"pdf={x['pdf_severity_sum']} spa={x['spa_total']} "
        f"agg={x['agg_total']}"
    )
    # The severity table must sum to its own population (taskf T-4.4).
    assert x["xlsx_severity_sum"] == x["agg_total"], (
        f"severity table does not reconcile on {where}: "
        f"xlsx_severity_sum={x['xlsx_severity_sum']} agg={x['agg_total']}"
    )


def test_count_parity_on_the_golden_corpus(tmp_path):
    """Gate 4: every golden-corpus payload renders three agreeing artifacts.

    Each labelled case runs through its family engine (OSV/NVD stubbed to
    empty -- offline by taskf ground rule 8), the payload is built through
    ``build_report_payload`` exactly as production does, and XLSX/PDF/SPA are
    rendered fresh and read back.  A failure here is real engine output
    escaping the single-source contract, not a fixture artifact.
    """
    from analysis.validation import run as vrun

    assert CORPUS_ROOT.is_dir(), f"golden corpus missing at {CORPUS_ROOT}"
    failures: list[tuple[str, list[str]]] = []
    scanned = 0

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(vulnerability_intel, "query_osv_batch",
                   lambda packages: {})
        mp.setattr(vulnerability_intel, "_query_nvd_secondary",
                   lambda packages, osv_results: {})
        for i, (family, casedir, path) in enumerate(
                vrun._iter_case_dirs(CORPUS_ROOT)):
            rel = path.relative_to(CORPUS_ROOT).as_posix()
            try:
                findings = _scan_family(family, casedir, path.name)
                payload = build_report_payload(findings, [], str(casedir))
                x = _render_and_extract(payload, tmp_path, f"case_{i:03d}")
            except Exception as exc:  # noqa: BLE001 - reported, not swallowed
                failures.append((rel, [f"{type(exc).__name__}: {exc}"]))
                continue
            try:
                _assert_parity(x, f"corpus case {rel}")
            except AssertionError as exc:
                failures.append((rel, [str(exc)]))
            scanned += 1

    assert scanned > 0, "corpus scan produced no cases"
    assert not failures, (
        "artifact count parity broke on golden-corpus cases: "
        + json.dumps(failures[:10], indent=2, ensure_ascii=False)
    )


def test_count_parity_on_the_prodtest_targets(tmp_path):
    """Gate 4: the same parity on every canonical prodtest report.

    The target list is the canonical one ``analysis.validation.parity_gate``
    sweeps (the historic "13 prodtest targets" of taskf/task.md; the list has
    since grown -- a superset satisfies the gate).  Reports load exactly as
    the pipeline wrote them; the aggregate is attached the way
    T-1.2 wires it for any payload that predates the builder, because that is
    what the renderers see in production ingest paths too.
    """
    from analysis.validation.parity_gate import PRODTEST_DIR, PRODTEST_TARGETS

    def _report_path(name: str) -> Path:
        return PRODTEST_DIR / "reports" / name / "clean_report.json"

    # The historic gate says "the 13 prodtest targets"; the canonical list
    # has since grown, and BenchmarkJava (the OWASP oracle, tracked
    # separately everywhere else) rides along when its report is present --
    # together a strict superset of any list taskf could have meant.
    names = [*PRODTEST_TARGETS, "BenchmarkJava-master"]
    present = [n for n in names if _report_path(n).is_file()]
    if not present:
        pytest.skip("prodtest corpus artifacts are not present")

    failures: list[tuple[str, list[str]]] = []
    for i, name in enumerate(present):
        report_path = _report_path(name)
        try:
            payload = json.loads(report_path.read_text(encoding="utf-8"))
            if not isinstance(payload.get("aggregates"), dict):
                payload["aggregates"] = report_aggregates.build(payload)
            x = _render_and_extract(payload, tmp_path, f"prod_{i:02d}")
        except Exception as exc:  # noqa: BLE001 - reported, not swallowed
            failures.append((name, [f"{type(exc).__name__}: {exc}"]))
            continue
        try:
            _assert_parity(x, f"prodtest target {name}")
        except AssertionError as exc:
            failures.append((name, [str(exc)]))

    assert not failures, (
        "artifact count parity broke on prodtest targets: "
        + json.dumps(failures[:10], indent=2, ensure_ascii=False)
    )
