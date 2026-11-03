# -*- coding: utf-8 -*-
"""taskf.md Phase 3 -- producer population (T-3.1..T-3.4), Gate 3.

Why this file exists: DEF-B's root cause was the PRODUCER -- no parser
wrote ``purl``/``component``/``dependency_type``/``cvss_version``, ranges
were resolved to ``"unknown"`` with the raw spec discarded, and
fabricated transitives were indistinguishable from manifest entries.
This file pins the replacement contract:

  * ``scanner.purl`` (T-3.1): exact pins only -- ``None`` for placeholders,
    ranges/globs, URLs and unknown ecosystems; npm scopes percent-encoded;
    Maven splits ``group:artifact``; deterministic and offline;
  * ``finalize_sbom_packages`` stamps (T-3.2): component,
    dependency_type, purl, cvss_version on offline-table scores,
    reachability_source, and the version reason ladder (express carries
    MANIFEST_RANGE end to end, no cell reads a bare placeholder);
  * ``_add_transitive`` fabrications (T-3.3): ``transitive_guess`` +
    ``dependency_type`` so a guessed component admits the guess;
  * on the count_parity fixture, neither renderer's SBOM surfaces ever
    print a bare ``unknown``/``Unknown``/``Review`` cell (Gate 3 Accept).

Refuses to: touch detection rules, grow KNOWN_VULNS (DEF-C), migrate
counts to aggregates (Phase 4), or reach the network -- OSV/NVD are
stubbed at the boundary, exactly as the parity fixture does it.
"""
from __future__ import annotations

import os
import pathlib
import shutil
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from openpyxl import Workbook  # noqa: E402

from reporting import excel_report, pdf_report  # noqa: E402
from scanner import vulnerability_intel  # noqa: E402
from scanner.purl import purl  # noqa: E402
from scanner.sbom import (  # noqa: E402
    _add_transitive,
    finalize_sbom_packages,
    generate_sbom,
)
from test_report_count_parity import (  # noqa: E402 - sibling fixture contract
    FIXTURE_SRC,
    _fake_query_nvd_secondary,
    _fake_query_osv_batch,
)

#: Words that must never be the WHOLE cell in any SBOM surface
#: (ground rule 5 / taskf DoD).  ``unknown (reason)`` forms are allowed --
#: they name the absence instead of hiding it.
_BARE_WORDS = {"unknown", "review", "none", "n/a", "na", "null"}
_FIXED_SENTENCE = "no fixed version identified"


# ------------------------------------------------------------------ purl --
def test_purl_pins_exact_versions_only():
    """T-3.1: an unresolvable version yields None, never a fake purl."""
    assert purl("flask", "1.0.2", "PyPI") == "pkg:pypi/flask@1.0.2"
    # Placeholders and absences
    assert purl("express", "unknown", "npm") is None
    assert purl("express", None, "npm") is None
    assert purl("express", "", "npm") is None
    assert purl("express", "  ", "npm") is None
    # Ranges, globs, intervals -- not versions at all
    assert purl("express", "^4.17.4", "npm") is None
    assert purl("express", "~2.1.3", "npm") is None
    assert purl("express", "1.x", "npm") is None
    assert purl("express", ">=1,<2", "PyPI") is None
    assert purl("demo", "[1.0,2.0)", "Maven") is None
    # URLs / VCS / workspace references
    assert purl("express", "https://example.test/x.tgz", "npm") is None
    assert purl("express", "git+https://example.test/x.git", "npm") is None
    # Names and ecosystems we refuse to invent
    assert purl("unknown", "1.0.0", "npm") is None
    assert purl("", "1.0.0", "npm") is None
    assert purl("flask", "1.0.2", "local") is None
    assert purl("flask", "1.0.2", "something-else") is None


def test_purl_scope_and_coordinate_shapes():
    """T-3.1: npm scope encoding, Maven group:artifact split, type map."""
    assert purl("@babel/core", "7.0.0", "npm") == \
        "pkg:npm/%40babel/core@7.0.0"
    assert purl("com.fasterxml.jackson.core:jackson-databind", "2.15.0",
                "Maven") == \
        "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.15.0"
    # A maven name without the colon is not a coordinate -> None
    assert purl("commons-lang3", "3.14.0", "Maven") is None
    # Placeholder group/artifact parts are not a coordinate either
    assert purl("unknown:unknown", "1.0.0", "Maven") is None
    # The rest of the supported type map, keyed on the spellings the
    # manifest parsers actually emit
    assert purl("serde", "1.0.0", "crates.io") == "pkg:cargo/serde@1.0.0"
    assert purl("rails", "7.0.0", "RubyGems") == "pkg:gem/rails@7.0.0"
    assert purl("vendor/pkg", "1.0.0", "Packagist") == \
        "pkg:composer/vendor/pkg@1.0.0"
    assert purl("github.com/x/y", "v1.2.3", "Go") == \
        "pkg:golang/github.com/x/y@v1.2.3"
    assert purl("Newtonsoft.Json", "13.0.1", "NuGet") == \
        "pkg:nuget/Newtonsoft.Json@13.0.1"
    # Build metadata percent-encodes; pre-release travels verbatim
    assert purl("pkg", "1.0+build.5", "npm") == "pkg:npm/pkg@1.0%2Bbuild.5"
    assert purl("pkg", "1.0.0-rc.1", "npm") == "pkg:npm/pkg@1.0.0-rc.1"


def test_purl_is_deterministic_offline_and_pure():
    """Ground rule 8: local string arithmetic only; same input, same purl."""
    import scanner.purl as purl_mod

    src = pathlib.Path(purl_mod.__file__).read_text(encoding="utf-8")
    assert "urllib.request" not in src, "purl generation must stay offline"
    assert "socket" not in src, "purl generation must stay offline"

    args = ("flask", "1.0.2", "PyPI")
    assert purl(*args) == purl(*args) == "pkg:pypi/flask@1.0.2"

    pkg = {"name": "flask", "version": "1.0.2", "ecosystem": "PyPI"}
    before = dict(pkg)
    purl(pkg["name"], pkg["version"], pkg["ecosystem"])
    assert pkg == before, "purl() must not mutate its inputs"


# --------------------------------------------------------- finalize stamp --
@pytest.fixture()
def _dark_external_advisory(monkeypatch):
    """Offline: identity the OSV/NVD pass inside finalize (no sockets)."""
    from scanner import sbom as sbom_mod
    monkeypatch.setattr(sbom_mod, "enrich_packages_with_external_vulns",
                        lambda pkgs: list(pkgs))


def test_finalize_stamps_the_report_fields(_dark_external_advisory):
    """T-3.2: component/purl/type/cvss_version/source + the version ladder."""
    pkgs = [
        # Resolvable pin: full stamps, no version provenance needed.
        {"name": "flask", "version": "1.0.2", "ecosystem": "PyPI",
         "license": "unknown", "direct": True},
        # The express shape: direct npm range, raw spec kept.
        {"name": "express", "version": "unknown",
         "requested_version": "^4.17.4", "ecosystem": "npm",
         "license": "unknown", "direct": True},
        # A fabricated transitive (as _add_transitive writes it).
        {"name": "jinja2", "version": "unknown", "ecosystem": "npm",
         "license": "unknown", "direct": False, "transitive_guess": True,
         "dependency_type": "Transitive"},
        # Maven: property/BOM-managed version stays unresolved.
        {"name": "com.example:demo", "version": "unknown",
         "requested_version": "${demo.version}", "ecosystem": "Maven",
         "license": "unknown", "direct": True},
        # Local/VCS reference.
        {"name": "./local-pkg", "version": "unknown", "ecosystem": "local",
         "license": "unknown", "direct": True, "local_reference": True},
        # Direct manifest entry whose version was never declared at all.
        {"name": "zzz-never-declared", "version": "unknown",
         "ecosystem": "npm", "license": "unknown", "direct": True},
        # Transitive guess the licence catalogue will not know.
        {"name": "zzz-fabricated-dep", "version": "unknown",
         "ecosystem": "npm", "license": "unknown", "direct": False,
         "transitive_guess": True, "dependency_type": "Transitive"},
    ]
    out = finalize_sbom_packages(pkgs, add_transitive=False)
    by = {p["name"]: p for p in out}

    # -- resolvable pin -----------------------------------------------
    flask = by["flask"]
    assert flask["component"] == "flask"
    assert flask["dependency_type"] == "Direct"
    assert flask["purl"] == "pkg:pypi/flask@1.0.2"
    # KNOWN_VULNS scored it: the offline table's scores are CVSS 3.1
    assert flask["cvss_version"] == "3.1"
    # enrich_with_cve seeds `reachable` on every record -> source stamped
    assert flask["reachability_source"] == "STATIC_TABLE"
    assert "version" not in (flask.get("field_provenance") or {}), (
        "a resolved pin needs no absence reason")

    # -- reason ladder ------------------------------------------------
    express = by["express"]
    express_prov = express.get("field_provenance") or {}
    assert express_prov.get("version") == {
        "state": "UNKNOWN", "reason": "MANIFEST_RANGE"}
    assert express["dependency_type"] == "Direct"
    assert express["component"] == "express"
    assert not express.get("purl"), "a range must not yield a purl"

    jinja = by["jinja2"]
    assert (jinja.get("field_provenance") or {}).get("version") == {
        "state": "UNKNOWN", "reason": "TRANSITIVE_GUESS"}
    assert jinja["dependency_type"] == "Transitive"

    maven = by["com.example:demo"]
    assert (maven.get("field_provenance") or {}).get("version") == {
        "state": "UNKNOWN", "reason": "PROPERTY_UNRESOLVED"}

    local = by["./local-pkg"]
    assert (local.get("field_provenance") or {}).get("version") == {
        "state": "UNKNOWN", "reason": "LOCAL_REFERENCE"}

    undeclared = by["zzz-never-declared"]
    assert (undeclared.get("field_provenance") or {}).get("version") == {
        "state": "UNKNOWN", "reason": "NO_LOCKFILE"}

    # -- licence provenance (stamped AFTER catalogue inference) -------
    never = by["zzz-never-declared"]
    lic_prov = (never.get("field_provenance") or {}).get("license") or {}
    assert lic_prov.get("reason") == "PROPERTY_UNRESOLVED"
    assert "state" not in lic_prov, (
        "reason-only so a later catalogue fill still resolves VALUE")
    fabricated = by["zzz-fabricated-dep"]
    assert ((fabricated.get("field_provenance") or {}).get("license")
            or {}).get("reason") == "TRANSITIVE_GUESS"


def test_add_transitive_marks_fabrications():
    """T-3.3: a component invented from the 4-entry table admits it."""
    base = [{"name": "flask", "version": "1.0.2", "ecosystem": "PyPI",
             "license": "MIT", "direct": True,
             "manifest_file": "requirements.txt", "manifest_line": 1}]
    out = _add_transitive(base)
    fabricated = [p for p in out if p["name"] in {
        "jinja2", "werkzeug", "itsdangerous", "click", "blinker"}]
    assert fabricated, "TRANSITIVE_DEPS[flask] must inject components"
    for p in fabricated:
        assert p["transitive_guess"] is True
        assert p["dependency_type"] == "Transitive"
        assert p["direct"] is False
        assert p["version"] == "unknown"
    # The manifest entry itself is not re-marked
    assert "transitive_guess" not in base[0]
    assert base[0].get("dependency_type") is None


# ----------------------------------------------------- fixture integration --
@pytest.fixture(scope="module")
def fixture_sbom(tmp_path_factory):
    """The count_parity fixture's SBOM, built through the real pipeline.

    OSV/NVD stubbed at the network boundary (same contract as the parity
    test) so the run is offline; rendering below works on the SBOM alone.
    """
    work = tmp_path_factory.mktemp("sbom_report_fields")
    target = work / "project"
    shutil.copytree(FIXTURE_SRC, target)
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(vulnerability_intel, "query_osv_batch",
                   _fake_query_osv_batch)
        mp.setattr(vulnerability_intel, "_query_nvd_secondary",
                   _fake_query_nvd_secondary)
        return generate_sbom(str(target))


def _pkg(sbom, name):
    for p in sbom:
        if str(p.get("name")) == name:
            return p
    raise AssertionError(f"fixture SBOM missing {name!r}")


def test_fixture_express_names_its_manifest_range(fixture_sbom):
    """Gate 3 Accept: express carries MANIFEST_RANGE, cell names the why."""
    express = _pkg(fixture_sbom, "express")
    prov = express.get("field_provenance") or {}
    assert (prov.get("version") or {}).get("reason") == "MANIFEST_RANGE", (
        f"expected MANIFEST_RANGE provenance, got {prov!r}")
    # Rendered through the Excel helper the parity test reads back out
    # (T-0.3 asserts the same string at the artifact level).
    assert excel_report._sbom_current_version(express) == \
        "unknown (manifest declares a range, no lockfile pin)"


def test_fixture_purl_populated_for_every_resolvable_component(fixture_sbom):
    """Gate 3 Accept: every exact pin gets a purl; nothing unresolvable does."""
    by = {str(p.get("name")): p for p in fixture_sbom}
    for name, want in {
        "flask": "pkg:pypi/flask@1.0.2",
        "six": "pkg:pypi/six@1.16.0",
        "colorama": "pkg:pypi/colorama@0.4.6",
        "certifi": "pkg:pypi/certifi@2024.2.2",
    }.items():
        assert by[name].get("purl") == want, name
    assert not by["express"].get("purl"), (
        "a range must not yield a versionless or range purl")
    # No placeholder-version component anywhere may claim a purl
    for p in fixture_sbom:
        if str(p.get("version") or "").strip().casefold() in {
                "", "unknown"}:
            assert not p.get("purl"), p.get("name")


def test_fixture_cvss_version_and_reachability_source(fixture_sbom):
    """T-3.2/T-3.4: offline-table scores name their standard; source shows."""
    flask = _pkg(fixture_sbom, "flask")
    assert flask.get("cvss_version") == "3.1", (
        "KNOWN_VULNS scores are CVSS 3.1 and must say so")
    assert flask.get("reachability_source") == "STATIC_TABLE"
    six = _pkg(fixture_sbom, "six")
    assert six.get("reachability_source") == "STATIC_TABLE", (
        "reachable is seeded on every record -> source travels with it")


def _cell_texts_from_story(story) -> list[str]:
    """Every string a PDF story would print: paragraphs and table cells."""
    texts: list[str] = []
    for flowable in story:
        raw = getattr(flowable, "text", None)
        if isinstance(raw, str):
            texts.append(raw)
        cells = getattr(flowable, "_cellvalues", None)
        if cells:
            for row in cells:
                for c in row:
                    if isinstance(c, str):
                        texts.append(c)
                    else:
                        inner = getattr(c, "text", None)
                        if isinstance(inner, str):
                            texts.append(inner)
    return texts


def _assert_no_bare_word(texts, surface):
    for text in texts:
        norm = str(text).strip().casefold()
        assert norm not in _BARE_WORDS, (
            f"{surface} printed a bare placeholder {text!r} "
            "(ground rule 5 / taskf Gate 3)")
        assert not norm.startswith(_FIXED_SENTENCE), (
            f"{surface} printed the synthesized fixed-version sentence "
            f"in {text!r} (taskf DEF-B)")


def test_fixture_sbom_cells_never_read_a_bare_placeholder(fixture_sbom):
    """Gate 3 Accept: no SBOM cell on the fixture reads bare unknown/Unknown.

    Scans every cell of the Excel SBOM and SCA sheets and every string the
    PDF SBOM and remediation-priority stories would print.  ``unknown
    (reason)`` forms pass -- they name the absence; the bare word does not.
    """
    payload = {"sbom": fixture_sbom, "metadata": {}}

    # Excel: SBOM sheet + vulnerable-only SCA sheet
    for writer, title in ((excel_report._sbom, "xlsx SBOM"),
                          (excel_report._sca_findings, "xlsx SCA")):
        wb = Workbook()
        writer(wb.active, payload)
        texts = [str(c.value) for row in wb.active.iter_rows()
                 for c in row if c.value is not None]
        _assert_no_bare_word(texts, title)

    # PDF: SBOM table + Critical/High remediation priorities
    for story in (pdf_report._sbom_section(payload),
                  pdf_report._sca_remediation_priority_section(payload)):
        _assert_no_bare_word(_cell_texts_from_story(story), "pdf story")
