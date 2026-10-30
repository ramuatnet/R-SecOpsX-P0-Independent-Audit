"""V0.3: the differential runner must not be able to report agreement it
never established.

WHAT THE THREE BUGS WERE
------------------------
Every one of these was found by running the real peer tools, and every one
produced output that looked like a tool disagreement while being entirely the
runner's own doing:

  1. ``_run_rsecopsx`` emitted the advisory as ``id``, but the normalizer
     reads ``cve``. Every record therefore had ``cve=None`` and fell through
     to an empty location identity -- ``('', '')``. Four distinct findings
     collapsed into one key, and the report read ``in_both: 0`` against a
     peer that had found the very same advisory. A reader would have taken
     that as R-SecOpsX and grype agreeing on nothing.

  2. grype's CVE is in ``cwes[].cve``. ``relatedVulnerabilities`` was
     ``null`` and ``advisories`` was ``[]``, so the conventional alias lookup
     found nothing and grype reported ``GHSA-prr3-c3m5-p7q2`` where we
     reported ``CVE-2023-48631`` -- one shared finding reported as two
     disagreements.

  3. trivy had a runner and an entry in PEER_TOOLS but no normalizer at all.
     Every trivy finding was skipped as "unknown source", the peer side
     reported zero findings, and the run returned "4 disagreements" from a
     tool that was never actually compared. This is precisely what the
     BLOCKED status exists to prevent, and it happened anyway -- in a place
     the BLOCKED check did not cover.

Bug 3 is the one worth dwelling on. A peer that produces no findings and a
peer that could not be run are indistinguishable in the counts, so the
distinction has to be made explicit. These tests assert it directly: a run
in which the peer contributed nothing must not be reported as agreement.

WHAT IS DELIBERATELY NOT TESTED
-------------------------------
Whether a disagreement is RIGHT. ``only_in_rsecopsx`` may be a peer blind
spot or a false positive of ours, and only a human triaging the finding can
say which. Encoding a verdict here would turn a measurement tool into a
grading tool that grades itself.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from analysis import differential  # noqa: E402
from analysis.validation.compare import identity  # noqa: E402
from analysis.validation.normalize import (  # noqa: E402
    SOURCES, normalize_finding, normalize_findings)


# --------------------------------------------------------------------------
# Shapes captured from the real tools, not invented.
# --------------------------------------------------------------------------

GRYPE_MATCH = {
    # Captured from `grype sbom:... --output json` on the corpus SBOM.
    # Note relatedVulnerabilities: null and advisories: [] -- the CVE is
    # only in cwes[].cve, which is the whole reason that lookup exists.
    "vulnerability": {
        "id": "GHSA-prr3-c3m5-p7q2",
        "severity": "Medium",
        "relatedVulnerabilities": None,
        "advisories": [],
        "cwes": [{"cve": "CVE-2023-48631", "cwe": "CWE-20",
                  "source": "nvd@nist.gov", "type": "Primary"}],
    },
    "artifact": {"name": "@adobe/css-tools", "version": "4.3.1"},
}

TRIVY_VULN = {
    # Captured from `trivy sbom <file> --format json`.
    "VulnerabilityID": "CVE-2025-48924",
    "PkgName": "commons-lang:commons-lang",
    "InstalledVersion": "2.6",
    "Severity": "CRITICAL",
    "Title": "commons-lang: Denial of Service",
}


def _bom() -> Path:
    """A CycloneDX SBOM shaped like the real exporter's output."""
    return None


def _make_sbom(tmp_path: Path, vulnerabilities: list[dict] | None = None,
               components: list[dict] | None = None) -> Path:
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "components": components or [
            {"type": "library", "name": "@adobe/css-tools",
             "version": "4.3.1",
             "bom-ref": "pkg:npm/@adobe/css-tools@4.3.1",
             "purl": "pkg:npm/@adobe/css-tools@4.3.1"},
        ],
        "vulnerabilities": vulnerabilities if vulnerabilities is not None else [
            {
                "id": "CVE-2023-48631",
                "ratings": [{"severity": "medium", "method": "CVSSv31",
                             "score": 5.0}],
                "affects": [{"ref": "pkg:npm/@adobe/css-tools@4.3.1"}],
                "properties": [
                    {"name": "rsecopsx:cve", "value": "CVE-2023-48631"},
                    {"name": "rsecopsx:advisory_id",
                     "value": "GHSA-prr3-c3m5-p7q2"},
                    {"name": "rsecopsx:severity", "value": "Medium"},
                ],
                "description": "Regular Expression Complexity",
            },
        ],
    }
    path = tmp_path / "bom.json"
    path.write_text(json.dumps(bom, indent=2), encoding="utf-8")
    return path


# --------------------------------------------------------------------------
# 1. our own SBOM must produce a CVE the comparator can key on
# --------------------------------------------------------------------------


def test_our_sbom_findings_carry_a_cve_not_an_id(tmp_path):
    """Bug 1. The record used ``id``; the normalizer reads ``cve``.

    Four findings collapsed to the empty location identity ``('', '')`` and
    the report read ``in_both: 0`` against a peer that had found the same
    advisory. That output looks like two tools disagreeing about everything.
    """
    sbom = _make_sbom(tmp_path, vulnerabilities=[
        {"id": "CVE-2023-48631",
         "ratings": [{"severity": "medium"}],
         "affects": [{"ref": "pkg:npm/@adobe/css-tools@4.3.1"}],
         "properties": [{"name": "rsecopsx:cve", "value": "CVE-2023-48631"}],
         "description": "x"},
        {"id": "CVE-2024-24762",
         "ratings": [{"severity": "high"}],
         "affects": [{"ref": "pkg:npm/@adobe/css-tools@4.3.1"}],
         "properties": [{"name": "rsecopsx:cve", "value": "CVE-2024-24762"}],
         "description": "y"},
    ])

    findings, error = differential._run_rsecopsx(sbom)

    assert error is None
    assert len(findings) == 2
    assert {f["cve"] for f in findings} == {"CVE-2023-48631", "CVE-2024-24762"}
    # The identity must be CVE-backed, not the empty location key.
    keys = {identity(f) for f in findings}
    assert len(keys) == 2, "findings collapsed into %r" % keys
    assert all(k[0] == "cve" for k in keys), keys
    assert ("location", ("", "")) not in keys


def test_our_sbom_findings_resolve_package_and_version(tmp_path):
    """SCA identity is ``(package, version, cve)``. Without the first two the
    finding would match any other package carrying the same CVE."""
    sbom = _make_sbom(tmp_path)
    findings, error = differential._run_rsecopsx(sbom)

    assert error is None
    assert findings[0]["package"] == "@adobe/css-tools"
    assert findings[0]["version"] == "4.3.1"


def test_severity_uses_the_canonical_spelling_not_the_raw_ratings_value(tmp_path):
    """``ratings`` carries "medium" (lower case); the canonical vocabulary is
    "Medium". The exporter also writes ``rsecopsx:severity`` in canonical
    form, and that spelling must win."""
    sbom = _make_sbom(tmp_path)
    findings, _ = differential._run_rsecopsx(sbom)

    assert findings[0]["severity"] == "Medium"


def test_an_empty_ratings_array_does_not_crash_the_run(tmp_path):
    """``vuln["ratings"][0]`` raises IndexError on ``"ratings": []``. An
    unrated finding is normal data, and one must not abort the whole
    differential."""
    sbom = _make_sbom(tmp_path, vulnerabilities=[
        {"id": "CVE-2023-48631", "ratings": [],
         "affects": [{"ref": "pkg:npm/@adobe/css-tools@4.3.1"}],
         "properties": [], "description": "no rating"},
    ])

    findings, error = differential._run_rsecopsx(sbom)

    assert error is None
    assert len(findings) == 1
    assert findings[0]["severity"] is None


def test_an_unreadable_sbom_is_an_error_not_an_empty_result(tmp_path):
    """An empty result set reads as "we found nothing". An unreadable file
    means we never looked."""
    bad = tmp_path / "broken.json"
    bad.write_text("{not json", encoding="utf-8")

    findings, error = differential._run_rsecopsx(bad)

    assert findings == []
    assert error is not None
    assert "cannot read SBOM" in error


# --------------------------------------------------------------------------
# 2. grype's CVE must be found wherever grype actually puts it
# --------------------------------------------------------------------------


def test_grype_cve_is_read_from_cwes_when_aliases_are_empty():
    """Bug 2. On the real corpus SBOM, ``relatedVulnerabilities`` is null and
    ``advisories`` is [], while ``cwes[].cve`` carries the CVE. Checking only
    the conventional places meant grype said GHSA-prr3-c3m5-p7q2 and we said
    CVE-2023-48631 for one advisory -- one match reported as two
    disagreements.
    """
    out = normalize_finding(GRYPE_MATCH, "grype")

    assert out["cve"] == "CVE-2023-48631"
    # grype's own identifier is preserved as the rule id -- the CVE field is
    # aliased, the tool's report is not rewritten.
    assert out["rule_id"] == "GHSA-prr3-c3m5-p7q2"


def test_grype_and_our_sbm_agree_on_the_same_advisory(tmp_path):
    """The regression this all reduces to: the same advisory, named
    differently by each side, must land in ``in_both``."""
    sbom = _make_sbom(tmp_path)
    ours, err = differential._run_rsecopsx(sbom)
    assert err is None

    theirs = normalize_findings([GRYPE_MATCH], "grype")
    in_both, only_ours, only_peer = differential._diff(ours, theirs)

    assert len(in_both) == 1
    assert only_ours == []
    assert only_peer == []


def test_a_real_difference_is_still_reported_as_a_difference(tmp_path):
    """Alias resolution must not become so generous that distinct findings
    merge. Two different advisories on one package stay distinct."""
    sbom = _make_sbom(tmp_path)
    ours, _ = differential._run_rsecopsx(sbom)

    other = dict(GRYPE_MATCH)
    other["vulnerability"] = dict(GRYPE_MATCH["vulnerability"],
                                  id="GHSA-different-advisory",
                                  cwes=[{"cve": "CVE-9999-99999"}])
    theirs = normalize_findings([other], "grype")

    in_both, only_ours, only_peer = differential._diff(ours, theirs)

    assert in_both == []
    assert len(only_ours) == 1
    assert len(only_peer) == 1


def test_a_finding_the_peer_never_reported_is_not_silently_dropped(tmp_path):
    sbom = _make_sbom(tmp_path, vulnerabilities=[
        {"id": "CVE-2023-48631", "ratings": [{"severity": "medium"}],
         "affects": [{"ref": "pkg:npm/@adobe/css-tools@4.3.1"}],
         "properties": [{"name": "rsecopsx:cve", "value": "CVE-2023-48631"}],
         "description": "a"},
        {"id": "CVE-2026-7246", "ratings": [{"severity": "high"}],
         "affects": [{"ref": "pkg:npm/@adobe/css-tools@4.3.1"}],
         "properties": [{"name": "rsecopsx:cve", "value": "CVE-2026-7246"}],
         "description": "b"},
    ])
    ours, _ = differential._run_rsecopsx(sbom)
    theirs = normalize_findings([GRYPE_MATCH], "grype")

    _, only_ours, only_peer = differential._diff(ours, theirs)

    assert len(only_ours) == 1
    assert only_ours[0]["cve"] == "CVE-2026-7246"
    assert only_peer == []


# --------------------------------------------------------------------------
# 3. every declared peer tool must actually have a normalizer
# --------------------------------------------------------------------------


def test_every_peer_tool_can_actually_normalize_a_record():
    """Bug 3, in its general form -- and a stronger form than membership.

    PEER_TOOLS declared trivy, but SOURCES and _NORMALIZERS had no trivy, so
    every trivy finding was skipped as "unknown source". The peer reported
    zero findings and the run returned "4 disagreements" against a tool that
    was never compared.

    Asserting membership in SOURCES is not enough: that list is a
    declaration, and the registry that actually routes a record to a parser
    is _NORMALIZERS. Unregistering kics from _NORMALIZERS while leaving it in
    SOURCES survived the membership version of this test -- the mutation
    changed nothing the test could see, because the test was looking at the
    sign on the door rather than whether anyone was inside.

    So this normalizes a real record for every declared peer tool. A tool
    that cannot do that would skip its findings and report false agreement.
    """
    samples = {
        "grype": GRYPE_MATCH,
        "trivy": TRIVY_VULN,
        "kics": {"query_id": "abc-123", "query_name": "AWS AMI Not Encrypted",
                 "severity": "HIGH", "file_name": "main.tf", "line": 12,
                 "search_key": 'aws_ami["example"]'},
        "semgrep": {"check_id": "java.lang.security.audit.sqli",
                    "path": "src/S.java", "start": {"line": 23},
                    "extra": {"severity": "ERROR",
                              "metadata": {"cwe": ["CWE-89: SQL injection"]}}},
        "checkov": {"check_id": "CKV_AWS_18", "file": "main.tf",
                    "file_line_range": [12, 14], "severity": "HIGH"},
        "gitleaks": {"RuleID": "aws-access-key", "File": "config.env",
                     "StartLine": 3, "Secret": "AKIA..."},
    }

    for tool in differential.PEER_TOOLS:
        assert tool in samples, (
            "no sample record is defined for peer tool %r; add one, or drop "
            "the tool from PEER_TOOLS" % tool)

        out = normalize_finding(samples[tool], tool)
        # The registry must have had an entry -- falling through to the
        # empty-dict error branch would silently produce a finding with no
        # identity at all, which is how a peer ends up reporting nothing.
        assert out["_source_finding"] is samples[tool], (
            "%s: the record was not routed through a normalizer" % tool)
        for key in ("rule_id", "file", "line", "severity", "cwe", "package",
                    "cve"):
            assert key in out, "%s: canonical key %r is missing" % (tool, key)


def test_kics_findings_are_flattened_one_record_per_file():
    """kics nests findings as ``queries[].files[]``, and one query may span
    several files. Feeding the query through raw would produce ONE record for
    all of them, understating the peer and making our own count look inflated
    by comparison -- a diff whose inputs are not what either tool reported.
    """
    queries = [
        {"query_id": "q1", "query_name": "First", "severity": "HIGH",
         "files": [{"file_name": "a.tf", "line": 3},
                   {"file_name": "b.tf", "line": 9}]},
        {"query_id": "q2", "query_name": "Second", "severity": "LOW",
         "files": [{"file_name": "c.tf", "line": 21}]},
    ]

    out = normalize_findings(queries, "kics")

    assert len(out) == 3, "expected one record per file, got %d" % len(out)
    assert {f["file"] for f in out} == {"a.tf", "b.tf", "c.tf"}
    # The query's severity and id must reach every file it covers.
    by_file = {f["file"]: f for f in out}
    assert by_file["a.tf"]["rule_id"] == "q1"
    assert by_file["b.tf"]["severity"] == "High"
    assert by_file["c.tf"]["rule_id"] == "q2"
    assert by_file["c.tf"]["line"] == 21


def test_kics_severity_maps_through_the_canonical_vocabulary():
    out = normalize_finding({"query_id": "q", "severity": "HIGH",
                             "file_name": "main.tf", "line": 1}, "kics")
    assert out["severity"] == "High"

    unknown = normalize_finding({"query_id": "q", "severity": "UNKNOWN",
                                 "file_name": "main.tf", "line": 1}, "kics")
    assert unknown["severity"] is None


def test_trivy_normalizes_to_canonical_fields():
    out = normalize_finding(TRIVY_VULN, "trivy")

    assert out["cve"] == "CVE-2025-48924"
    assert out["package"] == "commons-lang:commons-lang"
    assert out["version"] == "2.6"
    assert out["severity"] == "Critical"
    # trivy reports a package, not a line. None must survive so the finding
    # matches on component identity instead of a line that does not exist.
    assert out["line"] is None


def test_trivy_severity_spelling_is_tolerated():
    """trivy emits "CRITICAL" on some versions and "Critical" on others. A
    lookup keyed on one spelling drops the severity on the other, and a
    dropped severity reads as "trivy did not say" -- a different claim from
    "trivy said Critical"."""
    for spelling in ("CRITICAL", "Critical", "critical"):
        out = normalize_finding(dict(TRIVY_VULN, Severity=spelling), "trivy")
        assert out["severity"] == "Critical", spelling


def test_trivy_unknown_severity_stays_absent_rather_than_becoming_low():
    """"Unknown" means the source never stated a grade. Filing it as Low
    would invent an assessment and move the finding down a tier."""
    out = normalize_finding(dict(TRIVY_VULN, Severity="Unknown"), "trivy")
    assert out["severity"] is None


def test_a_trivy_ghsa_id_is_not_presented_as_a_cve():
    """Keeping GHSA in the CVE field would make the comparator treat a GHSA
    identifier as a CVE and potentially match it against an unrelated one."""
    out = normalize_finding(dict(TRIVY_VULN,
                                 VulnerabilityID="GHSA-xxxx-yyyy-zzzz",
                                 PrimaryURL="https://github.com/advisories/x"),
                            "trivy")
    assert out["rule_id"] == "GHSA-xxxx-yyyy-zzzz"
    assert out["cve"] is None


# --------------------------------------------------------------------------
# BLOCKED is not PASS
# --------------------------------------------------------------------------


def test_an_absent_peer_reports_blocked_not_agreement():
    """If a missing tool produced an empty result set, the run would report
    "no disagreements" -- perfect agreement between two tools, one of which
    was never asked. That is the most misleading output this module could
    produce.

    The peer's absence has to be forced: this machine now HAS semgrep on
    PATH, so without forcing ``shutil.which`` to fail the availability gate
    opens, the target check fires instead, and reasons[0] names the missing
    target rather than the missing peer -- asserting the peer reason then
    depends on what happens to be installed. Forcing keeps the intent
    (absent peer, not absent target) independent of the environment, the
    same way the runner-gap test below forces availability open.
    """
    original_which = differential.shutil.which
    differential.shutil.which = lambda *_args, **_kw: None
    try:
        result = differential.run_differential("any.json", "semgrep")
    finally:
        differential.shutil.which = original_which

    assert result["status"] == differential.STATUS_BLOCKED
    assert result["reasons"]
    assert "semgrep" in result["reasons"][0]
    # Not 0. Zero would read as "measured and agreed".
    assert result["unexplained_disagreements"] is None
    assert "not agreement" in " ".join(result["notes"])


def test_a_missing_target_reports_blocked(tmp_path):
    result = differential.run_differential(
        str(tmp_path / "nope.json"), "grype")

    assert result["status"] == differential.STATUS_BLOCKED
    assert result["unexplained_disagreements"] is None


def test_a_tool_with_a_declaration_but_no_runner_reports_blocked(tmp_path):
    """A peer that is installed but has no runner must not fall through to an
    empty result set.

    Availability has to be forced True here: checkov is not installed on this
    machine, so the availability check fires first and returns a legitimate
    BLOCKED for a different reason. Without forcing it, this test would have
    passed while asserting nothing about the runner gap it names -- it would
    have been checking the availability path twice.
    """
    sbom = _make_sbom(tmp_path)

    # checkov is listed in PEER_TOOLS but has no runner in _PEER_RUNNERS.
    original = differential.peer_available
    differential.peer_available = lambda tool: (True, "/forced/installed")
    try:
        result = differential.run_differential(str(sbom), "checkov")
    finally:
        differential.peer_available = original

    assert result["status"] == differential.STATUS_BLOCKED
    assert any("no runner is implemented" in r for r in result["reasons"])
    # And the report must say so rather than showing an empty diff.
    assert "no comparison was made" in " ".join(result["notes"])


def test_an_unknown_tool_is_blocked_rather_than_silently_ignored():
    result = differential.run_differential("x.json", "made-up-tool")
    assert result["status"] == differential.STATUS_BLOCKED


# --------------------------------------------------------------------------
# exit codes
# --------------------------------------------------------------------------


def test_exit_codes_distinguish_success_disagreement_and_blocked():
    """Exit 2 must never be mistaken for exit 0. Both are non-zero, but only
    0 means 'measured and agreed'."""
    assert differential.EXIT_OK == 0
    assert differential.EXIT_DISAGREEMENTS == 1
    assert differential.EXIT_BLOCKED == 2
    assert len({differential.EXIT_OK, differential.EXIT_DISAGREEMENTS,
                differential.EXIT_BLOCKED}) == 3


def test_the_cli_exits_2_for_an_absent_peer(capsys, tmp_path):
    assert differential.main(["--tool", "semgrep",
                              "--target", str(tmp_path / "x.json")]) == 2
    out = capsys.readouterr().out
    assert "BLOCKED" in out
    assert "NOT agreement" in out


def test_the_cli_exits_1_when_disagreements_remain(tmp_path, capsys):
    sbom = _make_sbom(tmp_path)

    def fake_peer(path, extra, timeout):
        return [], None

    # Hermetic: force the availability gate open so this exercises the exit
    # code contract without requiring the grype binary to be installed (CI
    # runner has no grype). Mirrors test_a_peer_with_no_runner_is_blocked.
    avail_orig = differential.peer_available
    differential.peer_available = lambda tool: (True, "/forced/installed")
    original = differential._PEER_RUNNERS.get("grype")
    differential._PEER_RUNNERS["grype"] = fake_peer
    try:
        code = differential.main(["--tool", "grype", "--target", str(sbom)])
    finally:
        differential.peer_available = avail_orig
        if original is None:
            differential._PEER_RUNNERS.pop("grype", None)
        else:
            differential._PEER_RUNNERS["grype"] = original

    assert code == 1
    assert "unexplained disagreements: 1" in capsys.readouterr().out


def test_the_cli_exits_0_only_when_the_sides_agree(tmp_path, capsys):
    sbom = _make_sbom(tmp_path)

    def agreeing_peer(path, extra, timeout):
        # Report the same advisory under grype's own naming. If alias
        # resolution works, this is a match and the run is clean.
        return [dict(GRYPE_MATCH)], None

    # Hermetic: force the availability gate open (CI runner has no grype).
    avail_orig = differential.peer_available
    differential.peer_available = lambda tool: (True, "/forced/installed")
    original = differential._PEER_RUNNERS.get("grype")
    differential._PEER_RUNNERS["grype"] = agreeing_peer
    try:
        code = differential.main(["--tool", "grype", "--target", str(sbom)])
    finally:
        differential.peer_available = avail_orig
        if original is None:
            differential._PEER_RUNNERS.pop("grype", None)
        else:
            differential._PEER_RUNNERS["grype"] = original

    assert code == 0, capsys.readouterr().out
    assert "in both             1" in capsys.readouterr().out


def test_a_blocked_report_says_nothing_was_compared(capsys):
    """A reader must not be able to mistake BLOCKED for a clean diff."""
    result = differential._blocked("grype", Path("x.json"), ["missing"])

    text = differential.format_report(result)

    assert "BLOCKED" in text
    assert "NOT agreement" in text
    assert "missing" in text


def test_a_run_report_states_that_a_disagreement_is_not_a_verdict(capsys):
    """The runner must not imply it has decided who is right. It cannot know
    -- only the caller knows what has already been triaged."""
    result = differential._blocked("grype", Path("x.json"), ["r"])
    result = dict(result, status=differential.STATUS_RAN,
                  counts={"rsecopsx": 1, "peer": 0, "in_both": 0,
                          "only_in_rsecopsx": 1, "only_in_peer": 0},
                  unexplained_disagreements=1,
                  only_in_rsecopsx=[{"package": "x", "version": "1",
                                     "cve": "CVE-1", "file": None,
                                     "rule_id": "CVE-1"}],
                  only_in_peer=[])

    text = differential.format_report(result)

    assert "not a verdict" in text
    assert "does not" in text


# --------------------------------------------------------------------------
# the diff itself
# --------------------------------------------------------------------------


def test_the_diff_counts_reconcile():
    """``in_both + only_ours == ours``. A diff whose parts do not sum to its
    inputs has lost or duplicated a finding, and the report would mislead."""
    sbom_free_ours = normalize_findings([
        {"rule_id": "CVE-1", "cve": "CVE-1", "package": "a", "version": "1"},
        {"rule_id": "CVE-2", "cve": "CVE-2", "package": "b", "version": "2"},
    ], "rsecopsx")
    theirs = normalize_findings([
        {"vulnerability": {"id": "CVE-2", "severity": "High"},
         "artifact": {"name": "b", "version": "2"}},
        {"vulnerability": {"id": "CVE-3", "severity": "High"},
         "artifact": {"name": "c", "version": "3"}},
    ], "grype")

    in_both, only_ours, only_peer = differential._diff(sbom_free_ours, theirs)

    assert len(in_both) + len(only_ours) == len(sbom_free_ours)
    assert len(in_both) + len(only_peer) == len(theirs)
    assert len(in_both) == 1
    assert len(only_ours) == 1
    assert len(only_peer) == 1


# --------------------------------------------------------------------------
# alias CVEs (V2.2): one advisory can carry several CVE ids
# --------------------------------------------------------------------------


def _cluster_sbom(tmp_path: Path) -> Path:
    """A record shaped like the exporter's after the alias fix: the
    cluster's primary CVE in ``id``/``rsecopsx:cve``, the sibling ids
    cross-linked under ``references``."""
    return _make_sbom(tmp_path, vulnerabilities=[
        {"id": "CVE-2021-23337",
         "ratings": [{"severity": "high"}],
         "affects": [{"ref": "pkg:npm/@adobe/css-tools@4.3.1"}],
         "properties": [
             {"name": "rsecopsx:cve", "value": "CVE-2021-23337"},
             {"name": "rsecopsx:advisory_id", "value": "GHSA-35jh-r3h4-6jhm"},
             {"name": "rsecopsx:severity", "value": "High"},
         ],
         "references": [
             {"source": {"name": "OSV"}, "id": "CVE-2026-4800"},
             {"source": {"name": "OSV"}, "id": "GHSA-R5FR-RJXR-66JC"},
         ],
         "description": "x"},
    ])


def test_each_alias_cve_becomes_its_own_identity(tmp_path):
    """The live V2.2 run found grype reporting CVE-2026-4800 and
    CVE-2026-2950 on lodash where we reported nothing -- OSV carries the
    sibling CVE as an alias of an advisory we DID report, and the SBOM
    now cross-links it. Each alias CVE is a fact a consumer can search
    for, so each gets its own identity."""
    findings, error = differential._run_rsecopsx(_cluster_sbom(tmp_path))

    assert error is None
    assert {f["cve"] for f in findings} == {"CVE-2021-23337", "CVE-2026-4800"}
    keys = {identity(f) for f in findings}
    assert len(keys) == 2, "records collapsed into %r" % keys
    assert all(k[0] == "cve" for k in keys), keys


def test_a_twin_ghsa_reference_is_not_admitted_as_a_cve_identity(tmp_path):
    """Peers key identity on the CVE and keep their GHSA in ``rule_id``;
    admitting a GHSA string into the ``cve`` field would invent a
    disagreement against every tool that reports the same advisory."""
    findings, error = differential._run_rsecopsx(_cluster_sbom(tmp_path))

    assert error is None
    assert findings
    assert all(str(f["cve"]).upper().startswith("CVE-") for f in findings)


def test_the_sibling_cve_a_peer_reports_is_in_both_not_peer_only(tmp_path):
    """End-to-end shape of the live disagreement: grype's two matches for
    one advisory cluster must both land in ``in_both``, with neither
    side left holding a finding the other never made."""
    ours, error = differential._run_rsecopsx(_cluster_sbom(tmp_path))
    assert error is None
    theirs = normalize_findings([
        {"vulnerability": {"id": "GHSA-35jh-r3h4-6jhm",
                           "relatedVulnerabilities": [{"id": "CVE-2021-23337"}],
                           "severity": "High"},
         "artifact": {"name": "@adobe/css-tools", "version": "4.3.1"}},
        {"vulnerability": {"id": "GHSA-r5fr-rjxr-66jc",
                           "relatedVulnerabilities": [{"id": "CVE-2026-4800"}],
                           "severity": "High"},
         "artifact": {"name": "@adobe/css-tools", "version": "4.3.1"}},
    ], "grype")

    in_both, only_ours, only_peer = differential._diff(ours, theirs)

    assert [f.get("cve") for f in only_peer] == [], \
        "sibling CVE still reported as peer-only"
    assert only_ours == []
    assert len(in_both) == 2
