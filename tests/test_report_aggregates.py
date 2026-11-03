# -*- coding: utf-8 -*-
"""taskf.md Phase 1 -- canonical aggregate (T-1.1) + parity gate (T-1.2/T-1.3).

Why these tests exist: DEF-A was three totals across three artifacts because
every renderer re-derived counts from a different field.  This file pins the
ONE aggregate -- its identities, its labelled units, its legacy carry, its
fail-loud contract -- and asserts the identity holds across the golden
corpus, i.e. on the real finding shapes the engines actually emit.

Refuses to do: enforce legacy agreement.  metadata.total_findings
disagreeing with the canonical total is reported
(consistency.legacy_metadata_total_matches) and must NOT fail the build --
that is the designed signal for a late pipeline pass that moved the
population (taskf T-1.1, reported not enforced).
"""
from __future__ import annotations

import json
import logging
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from core import report_aggregates  # noqa: E402
from core.analyzer import build_report_payload  # noqa: E402
from scanner import vulnerability_intel  # noqa: E402

CORPUS_ROOT = pathlib.Path(__file__).resolve().parent / "vuln-test-corpus"


def _vulnerable_pkg(name, *, severity, cvss=None, vulns=None, cve=None):
    pkg = {"name": name, "version": "1.0.0", "ecosystem": "pypi",
           "direct": True}
    if cvss is not None:
        pkg["cvss"] = cvss
    if vulns is not None:
        pkg["vulnerabilities"] = vulns
    if cve is not None:
        pkg["cve"] = cve
    if severity is not None:
        pkg["severity"] = severity
    return pkg


def _payload(**overrides):
    base = {
        "metadata": {
            "total_findings": 4,
            "sast_findings": 2,
            "sca_findings": 2,
            "severity_distribution": {"Critical": 2, "High": 2},
        },
        "findings": [
            {"severity": "Critical", "vuln_type": "sqli"},
            {"severity": "High", "vuln_type": "cmdi"},
        ],
        "grouped": [
            {"severity": "Critical", "vuln_type": "sqli"},
            {"severity": "High", "vuln_type": "cmdi"},
        ],
        "sbom": [
            _vulnerable_pkg("pkg-a", severity="High", cvss=7.5,
                            vulns=[{"id": "GHSA-1"}], cve="CVE-1"),
            _vulnerable_pkg("pkg-b", severity=None, cvss=None,
                            vulns=[{"id": "GHSA-2"}], cve="CVE-2"),
            _vulnerable_pkg("pkg-clean", severity=None, cvss=None),
        ],
    }
    base.update(overrides)
    return base


# --------------------------------------------------------------------------
# T-1.1 -- identities, units, legacy carry
# --------------------------------------------------------------------------

def test_identities_hold_and_populations_are_named():
    agg = report_aggregates.build(_payload())
    counts = agg["counts"]

    # Populations stay distinct and are NAMED (non-goal: never collapse).
    assert counts["sast_records"] == 2
    assert counts["sca_vulnerable_packages"] == 2
    assert counts["grouped_records"] == 2
    assert counts["total_reported"] == 4
    assert counts["total_reported"] == (
        counts["sast_records"] + counts["sca_vulnerable_packages"])

    # The enforced identity: the severity table sums to its own population.
    combined = agg["severity"]["combined"]
    assert sum(combined.values()) == counts["total_reported"]
    assert combined == {"Critical": 1, "High": 2, "Medium": 0,
                        "Low": 0, "Info": 1}

    # The no-severity advisory is counted in Info AND reported as unrated --
    # not silently dropped from the table.
    assert agg["severity"]["sca_unrated"] == 1
    assert agg["severity"]["sast"]["Critical"] == 1
    assert agg["severity"]["sca"]["High"] == 1
    assert agg["severity"]["scope"]

    assert agg["schema"] == report_aggregates.SCHEMA
    assert agg["consistency"]["ok"] is True
    assert agg["consistency"]["failing"] == []
    assert set(agg["consistency"]["checks"]) == {
        "total_equals_sast_plus_sca",
        "combined_severity_sums_to_total",
    }


def test_every_exported_field_carries_a_label_and_a_unit():
    """Ground rule 4: no bare numbers -- label AND unit per field."""
    agg = report_aggregates.build(_payload())
    units = report_aggregates.COUNT_UNITS

    assert agg["units"] is units

    for key in agg["counts"]:
        path = f"counts.{key}"
        assert path in units, f"{path} has no COUNT_UNITS entry"
        assert units[path].get("label"), f"{path} has no label"
        assert units[path].get("unit"), f"{path} has no unit"
        assert report_aggregates.value_at(agg, path) is not None

    for sev in report_aggregates.SEVERITIES:
        path = f"severity.combined.{sev}"
        assert path in units, f"{path} has no COUNT_UNITS entry"
        assert units[path].get("label") and units[path].get("unit")

    assert "severity.sca_unrated" in units
    assert report_aggregates.value_at(agg, "severity.sca_unrated") == 1


def test_legacy_values_are_carried_but_never_enforced():
    """T-1.1: legacy_metadata_total_matches is reported, not enforced."""
    payload = _payload(metadata={
        "total_findings": 99,           # stale on purpose
        "severity_distribution": {"Critical": 5},  # the displaced value
    })
    agg = report_aggregates.build(payload)

    # The displaced metadata value stays diffable.
    assert agg["legacy_severity_distribution"] == {"Critical": 5}

    cons = agg["consistency"]
    assert cons["legacy_metadata_total_matches"] is False
    # Reported, NOT enforced: a pre-existing disagreement is the signal,
    # not a scan failure.
    assert cons["ok"] is True
    assert cons["failing"] == []
    assert "aggregates_inconsistent" not in payload["metadata"]


def test_fail_loud_flags_the_payload_and_logs_the_failing_checks(
        caplog):
    """T-1.3: a parity break raises a loud signal, never a silent side-pick."""
    payload = _payload(findings=[
        {"severity": "High", "vuln_type": "cmdi"},
        "corrupt-not-a-dict",   # in the population, cannot be bucketed
    ], grouped=[], metadata={"total_findings": 2})

    with caplog.at_level(logging.ERROR, logger="core.report_aggregates"):
        agg = report_aggregates.build(payload)

    cons = agg["consistency"]
    assert cons["ok"] is False
    assert cons["failing"] == ["combined_severity_sums_to_total"]
    assert payload["metadata"]["aggregates_inconsistent"] is True
    assert "report aggregates inconsistent" in caplog.text
    assert "combined_severity_sums_to_total" in caplog.text

    # A later clean build clears a stale flag (idempotent rebuild).
    clean = _payload()
    clean["metadata"]["aggregates_inconsistent"] = True
    report_aggregates.build(clean)
    assert "aggregates_inconsistent" not in clean["metadata"]


def test_build_is_deterministic_byte_for_byte():
    payload = _payload()
    a = report_aggregates.build(payload)
    b = report_aggregates.build(payload)
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


def test_ingest_style_payload_with_no_findings_still_builds():
    """Risk register: --sbom ingest has no findings; the aggregate tolerates it."""
    payload = {
        "metadata": {},
        "findings": [],
        "grouped": [],
        "sbom": [
            _vulnerable_pkg("vuln-1", severity="Critical", cvss=9.8,
                            vulns=[{"id": "GHSA-x"}], cve="CVE-X"),
            _vulnerable_pkg("clean-1", severity=None),
        ],
    }
    agg = report_aggregates.build(payload)
    assert agg["counts"] == {
        "total_reported": 1,
        "sast_records": 0,
        "sca_vulnerable_packages": 1,
        "grouped_records": 0,
    }
    assert sum(agg["severity"]["combined"].values()) == 1
    assert agg["consistency"]["ok"] is True


def test_build_report_payload_wires_the_aggregate():
    """T-1.2: payload['aggregates'] exists straight out of the builder."""
    payload = build_report_payload(
        [{"severity": "High", "vuln_type": "sqli", "file": "a.py",
          "line": 1, "snippet": "x", "rule_id": "R1",
          "confidence": "HIGH", "classification": "vulnerability"}],
        [], ".",
    )
    agg = payload.get("aggregates")
    assert isinstance(agg, dict)
    assert agg["consistency"]["ok"] is True
    assert agg["counts"]["total_reported"] == (
        agg["counts"]["sast_records"] + agg["counts"]["sca_vulnerable_packages"])
    assert sum(agg["severity"]["combined"].values()) == \
        agg["counts"]["total_reported"]


# --------------------------------------------------------------------------
# Gate 1 second half -- identity across the golden corpus
# --------------------------------------------------------------------------

def _scan_family(family, casedir, name):
    """Raw engine output for one corpus case (production input shape)."""
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


def test_identity_holds_across_the_golden_corpus():
    """Every corpus case builds an aggregate whose consistency.ok is True.

    The corpus is scanned with OSV/NVD stubbed to empty: the identity is a
    structural property of the payload, and the batch is offline by
    contract (taskf ground rule 8).  A failure here means a real engine
    output shape escapes the bucketing -- exactly the silent-drop class
    ground rule 12 exists to catch.
    """
    from analysis.validation import run as vrun

    assert CORPUS_ROOT.is_dir(), f"golden corpus missing at {CORPUS_ROOT}"

    failures: list[tuple[str, list]] = []
    scanned = 0

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(vulnerability_intel, "query_osv_batch",
                   lambda packages: {})
        mp.setattr(vulnerability_intel, "_query_nvd_secondary",
                   lambda packages, osv_results: {})
        for family, casedir, path in vrun._iter_case_dirs(CORPUS_ROOT):
            try:
                findings = _scan_family(family, casedir, path.name)
                payload = build_report_payload(findings, [], str(casedir))
            except Exception as exc:  # noqa: BLE001 - reported, not swallowed
                failures.append((str(path.relative_to(CORPUS_ROOT)),
                                 [f"{type(exc).__name__}: {exc}"]))
                continue
            cons = (payload.get("aggregates") or {}).get("consistency") or {}
            if not cons.get("ok"):
                failures.append((str(path.relative_to(CORPUS_ROOT)),
                                 list(cons.get("failing") or [])))
            scanned += 1

    assert scanned > 0, "corpus scan produced no cases"
    assert not failures, (
        "aggregate identity broke on golden-corpus cases: "
        + json.dumps(failures[:10], indent=2)
    )
