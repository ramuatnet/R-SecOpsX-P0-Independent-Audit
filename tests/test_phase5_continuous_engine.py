"""Phase 5.3: continuous re-scan — advisory re-check + KEV/EPSS re-evaluation.

WHAT THIS DELIVERS
------------------
Gap-plan row 5.3 ("continuous mode: scheduled re-scan + EPSS/KEV
re-evaluation of stored findings", verify: "re-run picks up new CVEs for
old deps"). analysis/continuous_engine.py answers two questions from a
stored clean_report.json WITHOUT re-scanning code:

* advisory re-check: the stored SBOM inventory goes through the scan's
  own enrichment path and the fresh advisory identities are diffed
  against the stored ones (id+alias identity on both sides);
* intel re-evaluation: every stored vulnerability identity — in
  findings[] (SAST/IaC/secrets) AND on sbom[].vulnerabilities (SCA,
  where this tool's CVEs actually live) — is checked against the
  current CISA KEV catalog and EPSS scores.

WHAT THESE TESTS PIN
--------------------
* newly_kev semantics relative to the stored report, seed-table
  fallback, and the live-catalog evidence/assumption distinction (a
  miss against a FETCHED catalog is evidence; a seed-only miss is an
  assumption);
* EPSS scores attach with the scan-time buckets; >= 0.50 is surfaced;
* GHSA-only findings are disclosed, not guessed (the alias map
  resolves what it can);
* severity is NEVER rewritten by intel (the policy, pinned);
* the V2.2 alias lesson: a re-issued advisory that merely gained an
  alias is not a "new CVE";
* advisory failures are disclosed, never rendered as "no new CVEs";
* CLI: artifact written, dir-or-file input, exit 1 on unreadable
  report, --offline never touches a feed (these tests run offline by
  construction; the benchmark harness is the authority for live runs).
"""
from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from analysis import continuous_engine  # noqa: E402
from analysis.continuous_engine import (  # noqa: E402
    CONTINUOUS_SCHEMA,
    EPSS_HIGH_THRESHOLD,
    GHSA_TO_CVE_ALIAS,
    build_continuous_report,
    recheck_advisories,
    reevaluate_findings,
    reevaluate_sbom_packages,
)
from analysis.live_intel_feeds import EPSSScore, KEVRecord  # noqa: E402


# ---------------------------------------------------------------------------
# Stub feeds: no network, full control over hit/miss/provenance.
# ---------------------------------------------------------------------------

class _StubKevFeed:
    def __init__(self, records=None, catalog_ok=True):
        self._records = records or {}
        self.catalog_loaded = catalog_ok
        self.catalog_version = "2026.10.04" if catalog_ok else None
        self.date_released = "2026-10-04" if catalog_ok else None

    def lookup(self, cve):
        return self._records.get(cve)


class _StubEpssFeed:
    def __init__(self, scores):
        self._scores = scores

    def scores_for(self, cves):
        return {c: self._scores[c] for c in cves if c in self._scores}


def _kev_record(cve="CVE-2021-44228", **overrides):
    fields = dict(
        cve=cve, vendor="Apache", product="Log4j", name="Log4j RCE",
        date_added="2021-12-10", due_date="2021-12-24",
        ransomware_use="Known", catalog_version="2026.10.04",
        date_released="2026-10-04", provenance="LIVE_FEED",
    )
    fields.update(overrides)
    return KEVRecord(**fields)


def _epss(cve, score, percentile=0.999):
    return EPSSScore(
        cve=cve, score=score, percentile=percentile,
        as_of="2026-10-10", source="FIRST_ORG_EPSS", provenance="LIVE_FEED",
    )


def _finding(rule_id="CVE-2021-44228", severity="High", **extra):
    finding = {
        "rule_id": rule_id,
        "severity": severity,
        "file": "pom.xml",
        "line": 12,
    }
    finding.update(extra)
    return finding


# ---------------------------------------------------------------------------
# Intel re-evaluation.
# ---------------------------------------------------------------------------

def test_kev_hit_attaches_record_and_flags_newly_kev():
    feed = _StubKevFeed({"CVE-2021-44228": _kev_record()})
    findings, summary = reevaluate_findings(
        [_finding()], kev_feed=feed, epss_feed=None)

    entry = findings[0]["intel_reevaluation"]
    assert entry["kev"] is True
    assert entry["cve"] == "CVE-2021-44228"
    assert entry["kev_record"]["date_added"] == "2021-12-10"
    assert entry["kev_record"]["ransomware_use"] == "Known"

    hits = summary["kev_hits"]
    assert len(hits) == 1
    assert hits[0]["rule_id"] == "CVE-2021-44228"
    assert hits[0]["due_date"] == "2021-12-24"


def test_finding_the_scan_already_marked_exploited_is_not_newly_kev():
    feed = _StubKevFeed({"CVE-2021-44228": _kev_record()})
    _, summary = reevaluate_findings(
        [_finding(kev_status=True)], kev_feed=feed, epss_feed=None)
    assert summary["kev_hits"] == []


def test_seed_table_falls_back_when_no_catalog_is_available():
    """Offline run: the seed map still answers, honestly labelled."""
    findings, summary = reevaluate_findings(
        [_finding()], kev_feed=None, epss_feed=None)
    assert findings[0]["intel_reevaluation"]["kev"] is True
    assert findings[0]["intel_reevaluation"]["kev_provenance"] == "STATIC_REFERENCE"
    assert summary["live_feeds_used"] is False
    assert summary["kev_catalog"] is None


def test_miss_against_a_fetched_catalog_is_evidence():
    feed = _StubKevFeed({}, catalog_ok=True)  # whole catalog consulted
    findings, _ = reevaluate_findings(
        [_finding(rule_id="CVE-2026-0001")],  # not in the seed table
        kev_feed=feed, epss_feed=None)
    entry = findings[0]["intel_reevaluation"]
    assert entry["kev"] is False
    assert entry["kev_provenance"] == "LIVE_FEED"


def test_miss_with_only_the_seed_table_is_an_assumption():
    feed = _StubKevFeed({}, catalog_ok=False)
    findings, _ = reevaluate_findings(
        [_finding(rule_id="CVE-2026-0001")], kev_feed=feed, epss_feed=None)
    assert findings[0]["intel_reevaluation"]["kev_provenance"] == "STATIC_REFERENCE"


def test_epss_scores_attach_with_the_scan_time_buckets():
    feed = _StubEpssFeed({
        "CVE-2021-44228": _epss("CVE-2021-44228", 0.93),
        "CVE-2020-1111": _epss("CVE-2020-1111", 0.02),
    })
    findings, summary = reevaluate_findings(
        [_finding(), _finding(rule_id="CVE-2020-1111")],
        kev_feed=None, epss_feed=feed)

    high = findings[0]["intel_reevaluation"]
    assert high["epss_score"] == 0.93
    assert high["epss_bucket"] == "VERY_HIGH_EXPLOIT_PROBABILITY"
    assert high["epss_provenance"] == "LIVE_FEED"

    low = findings[1]["intel_reevaluation"]
    assert low["epss_bucket"] == "LOW_EXPLOIT_PROBABILITY"

    surfaced = [row["cve"] for row in summary["epss_high"]]
    assert surfaced == ["CVE-2021-44228"]
    assert EPSS_HIGH_THRESHOLD == 0.50
    assert summary["epss_as_of"] == "2026-10-10"


def test_findings_without_cve_identity_are_counted_not_guessed():
    findings, summary = reevaluate_findings(
        [_finding(rule_id="TOTALLY_CUSTOM_RULE")], kev_feed=None)
    assert findings[0]["intel_reevaluation"]["cve"] is None
    assert summary["with_cve_identity"] == 0
    assert summary["no_cve_identity"] == 1


def test_ghsa_only_findings_are_disclosed():
    findings, summary = reevaluate_findings(
        [_finding(rule_id="GHSA-aaaa-bbbb-cccc")], kev_feed=None)
    assert findings[0]["intel_reevaluation"]["cve"] is None
    assert summary["ghsa_only"] == 1


def test_ghsa_with_a_known_alias_resolves_instead_of_being_disclosed():
    ghsa = next(iter(GHSA_TO_CVE_ALIAS))  # whatever the map carries
    expected = GHSA_TO_CVE_ALIAS[ghsa]
    findings, summary = reevaluate_findings(
        [_finding(rule_id=ghsa)], kev_feed=None)
    assert findings[0]["intel_reevaluation"]["cve"] == expected
    assert summary["ghsa_only"] == 0


def test_the_callers_findings_are_never_mutated():
    original = [_finding()]
    snapshot = copy.deepcopy(original)
    reevaluate_findings(original, kev_feed=None)
    assert original == snapshot


def test_severity_is_never_rewritten_by_intel():
    """The policy, pinned: intel escalates the queue, not the verdict."""
    feed = _StubKevFeed({"CVE-2021-44228": _kev_record()})
    findings, summary = reevaluate_findings(
        [_finding(severity="Low")], kev_feed=feed, epss_feed=None)
    assert findings[0]["severity"] == "Low"
    assert "never rewrite" in summary["severity_policy"]


def test_reevaluation_is_deterministic():
    feed = _StubKevFeed({"CVE-2021-44228": _kev_record()})
    epss = _StubEpssFeed({"CVE-2021-44228": _epss("CVE-2021-44228", 0.77)})
    a = reevaluate_findings([_finding()], kev_feed=feed, epss_feed=epss)
    b = reevaluate_findings([_finding()], kev_feed=feed, epss_feed=epss)
    assert json.dumps(a, default=str, sort_keys=True) == \
        json.dumps(b, default=str, sort_keys=True)


def test_non_dict_findings_are_skipped_survivably():
    findings, summary = reevaluate_findings(
        ["junk", _finding()], kev_feed=None)
    assert "intel_reevaluation" not in findings[0]
    assert "intel_reevaluation" in findings[1]
    assert summary["findings"] == 2


# ---------------------------------------------------------------------------
# Advisory re-check ("new CVEs for old deps").
# ---------------------------------------------------------------------------

def _stored_payload():
    return {
        "metadata": {"tool": "R-SecOpsX SAST v2.0", "target": "/repo"},
        "findings": [],
        "sbom": [{
            "name": "requests",
            "version": "2.19.1",
            "ecosystem": "PyPI",
            "vulnerabilities": [{
                "cve": "CVE-2018-18074",
                "advisory_id": "GHSA-x84v-x525-5hhx",
                "aliases": ["GHSA-x84v-x525-5hhx"],
            }],
        }],
    }


def test_recheck_surfaces_a_genuinely_new_advisory(monkeypatch):
    def _fake_enrich(pkgs):
        for pkg in pkgs:
            pkg["vulnerabilities"] = [
                {"cve": "CVE-2018-18074", "advisory_id": "GHSA-x84v-x525-5hhx",
                 "aliases": ["GHSA-x84v-x525-5hhx"]},
                {"cve": "CVE-2026-9999", "advisory_id": "GHSA-new0-0000-0000",
                 "aliases": ["GHSA-new0-0000-0000"], "severity": "HIGH"},
            ]

    monkeypatch.setattr(continuous_engine,
                        "enrich_packages_with_external_vulns", _fake_enrich)
    summary = recheck_advisories(_stored_payload()["sbom"])

    assert summary["checked"] is True
    assert summary["packages_with_new_advisories"] == 1
    assert summary["new_advisory_count"] == 1
    entry = summary["new_advisories"][0]
    assert entry["name"] == "requests"
    assert entry["new_advisories"][0]["cve"] == "CVE-2026-9999"
    assert summary["advisory_service"]["service"] == "OSV"


def test_a_re_issued_advisory_that_gained_an_alias_is_not_new(monkeypatch):
    def _fake_enrich(pkgs):
        for pkg in pkgs:
            pkg["vulnerabilities"] = [{
                "cve": "CVE-2018-18074",
                "advisory_id": "GHSA-x84v-x525-5hhx",
                # Re-issued: same primary, now with an extra alias.
                "aliases": ["GHSA-x84v-x525-5hhx", "CVE-2018-18074-ALIAS"],
            }]

    monkeypatch.setattr(continuous_engine,
                        "enrich_packages_with_external_vulns", _fake_enrich)
    summary = recheck_advisories(_stored_payload()["sbom"])
    assert summary["packages_with_new_advisories"] == 0
    assert summary["new_advisories"] == []


def test_enrichment_failure_is_disclosed_not_rendered_as_nothing_new(
        monkeypatch):
    def _boom(pkgs):
        raise RuntimeError("OSV unreachable")

    monkeypatch.setattr(continuous_engine,
                        "enrich_packages_with_external_vulns", _boom)
    summary = recheck_advisories(_stored_payload()["sbom"])
    assert summary["checked"] is False
    assert "OSV unreachable" in summary["error"]
    assert summary["new_advisories"] == []


def test_reports_without_named_packages_say_so():
    summary = recheck_advisories([])
    assert summary["checked"] is False
    assert "no named SBOM packages" in summary["error"]


# ---------------------------------------------------------------------------
# SBOM package source (SCA CVEs live here, not in findings[]).
# ---------------------------------------------------------------------------

def _stored_package(cve="CVE-2018-18074", **extra):
    pkg = {
        "name": "requests",
        "version": "2.19.1",
        "ecosystem": "PyPI",
        "vulnerabilities": [{"cve": cve, "advisory_id": "GHSA-x84v-x525-5hhx",
                             "aliases": ["GHSA-x84v-x525-5hhx"]}],
    }
    pkg.update(extra)
    return pkg


def test_package_source_gets_kev_hits_tagged_as_packages():
    pkg = _stored_package(cve="CVE-2021-44228")
    packages, summary = reevaluate_sbom_packages(
        [pkg], kev_feed=None, epss_feed=None)

    assert packages[0]["intel_reevaluation"]["kev"] is True
    hits = summary["kev_hits"]
    assert len(hits) == 1
    assert hits[0]["source"] == "package"
    assert hits[0]["name"] == "requests"
    assert summary["with_cve_identity"] == 1


def test_package_the_scan_already_marked_exploited_is_not_newly():
    pkg = _stored_package(cve="CVE-2021-44228", kev_status=True)
    _, summary = reevaluate_sbom_packages([pkg], kev_feed=None)
    assert summary["kev_hits"] == []


def test_package_high_epss_repeats_only_when_the_scan_did_not_flag_it():
    feed = _StubEpssFeed({"CVE-2021-44228": _epss("CVE-2021-44228", 0.93)})

    flagged = _stored_package(cve="CVE-2021-44228", epss_score=0.91)
    _, summary = reevaluate_sbom_packages([flagged], epss_feed=feed)
    assert summary["epss_high"] == [], "already flagged at scan time"

    unflagged = _stored_package(cve="CVE-2021-44228", epss_score=0.10)
    _, summary = reevaluate_sbom_packages([unflagged], epss_feed=feed)
    assert len(summary["epss_high"]) == 1
    assert summary["epss_high"][0]["source"] == "package"


def test_the_callers_package_list_is_never_mutated():
    original = [_stored_package(cve="CVE-2021-44228")]
    snapshot = copy.deepcopy(original)
    reevaluate_sbom_packages(original, kev_feed=None)
    assert original == snapshot


def test_merged_summary_covers_both_sources_with_source_tags():
    report = build_continuous_report(
        {"findings": [_finding()], "sbom": [_stored_package(
            cve="CVE-2021-44228")]},
        kev_feed=None, epss_feed=None, recheck=False)

    intel = report["continuous_reevaluation"]["intel_reevaluation"]
    assert intel["findings"] == 1
    assert intel["packages"] == 1
    sources = sorted(hit["source"] for hit in intel["kev_hits"])
    assert sources == ["finding", "package"]


# ---------------------------------------------------------------------------
# Assembly + CLI.
# ---------------------------------------------------------------------------

def test_build_report_is_a_deepcopy_with_the_schema_block(monkeypatch):
    monkeypatch.setattr(
        continuous_engine, "enrich_packages_with_external_vulns",
        lambda pkgs: None)
    payload = _stored_payload()
    snapshot = copy.deepcopy(payload)

    report = build_continuous_report(payload, kev_feed=None,
                                     epss_feed=None, recheck=True)
    assert payload == snapshot
    block = report["continuous_reevaluation"]
    assert block["schema"] == CONTINUOUS_SCHEMA
    assert block["generated_from"] == "clean_report.json"
    assert "intel_reevaluation" in block
    assert "advisory_recheck" in block


def test_no_advisories_mode_records_the_disabled_reason():
    report = build_continuous_report(_stored_payload(), recheck=False)
    advisory = report["continuous_reevaluation"]["advisory_recheck"]
    assert advisory["checked"] is False
    assert "--no-advisories" in advisory["error"]


def test_cli_writes_the_artifact_from_a_directory_input(tmp_path, capsys):
    report_dir = tmp_path / "scan_out"
    report_dir.mkdir()
    payload = _stored_payload()
    payload["findings"] = [_finding()]
    (report_dir / "clean_report.json").write_text(
        json.dumps(payload), encoding="utf-8")

    rc = continuous_engine.main([
        "--report", str(report_dir), "--offline", "--no-advisories",
    ])

    assert rc == 0
    artifact = report_dir / "Security_Continuous.json"
    assert artifact.exists()
    written = json.loads(artifact.read_text(encoding="utf-8"))
    assert written["continuous_reevaluation"]["schema"] == CONTINUOUS_SCHEMA
    # The seed KEV table answers even fully offline.
    intel = written["continuous_reevaluation"]["intel_reevaluation"]
    assert len(intel["kev_hits"]) == 1
    assert intel["provenance"]["kev"] == "STATIC_REFERENCE"
    out = capsys.readouterr().out
    assert "1 findings + 1 packages re-evaluated" in out
    assert "newly KEV: 1" in out


def test_cli_accepts_a_file_path_and_respects_out(tmp_path):
    report_file = tmp_path / "clean_report.json"
    report_file.write_text(json.dumps(_stored_payload()), encoding="utf-8")
    out_file = tmp_path / "custom.json"

    rc = continuous_engine.main([
        "--report", str(report_file), "--offline", "--no-advisories",
        "--out", str(out_file),
    ])

    assert rc == 0
    assert out_file.exists()
    assert not (tmp_path / "Security_Continuous.json").exists()


def test_cli_exits_1_on_an_unreadable_report(tmp_path, capsys):
    rc = continuous_engine.main([
        "--report", str(tmp_path / "missing.json"), "--offline",
    ])
    assert rc == 1
    assert "cannot read" in capsys.readouterr().err


def test_cli_exits_1_on_a_non_object_report(tmp_path):
    report_file = tmp_path / "clean_report.json"
    report_file.write_text("[1, 2, 3]", encoding="utf-8")
    rc = continuous_engine.main([
        "--report", str(report_file), "--offline",
    ])
    assert rc == 1
