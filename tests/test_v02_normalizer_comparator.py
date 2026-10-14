"""V0.2: the normalizer, comparator and metrics must be trustworthy before
any number they produce can be quoted.

WHY THIS FILE EXISTS
--------------------
V0.1 measured the corpus with a throwaway script and reported 33% recall.
Building V0.2 dropped that to 11%, then returned it to 44% -- and neither
move touched a single label or rule. Both were harness bugs:

  * findings were passed to the comparator raw while the labels were
    normalized, so the labels bucketed by canonical class (SAST-SQLI) and
    the findings by their CWE (CWE-89). Two sides of one comparison that
    never shared an identity, which reported 60 false positives for a tool
    that had found 16 things correctly.
  * one case directory holds BOTH the safe and the vulnerable fixture, so
    scoring each against the directory's findings credited the vulnerable
    file's bugs to the safe one and vice versa. 30 java false positives
    where the two files produce 17 findings between them.

Neither was visible in the output. Both looked like tool behaviour. That is
why every function here is tested against a hand-built expectation rather
than against whatever the code currently does: a comparator that is subtly
wrong produces confident numbers, and confident wrong numbers are the worst
artefact this phase could ship.

THE TESTS THAT MATTER MOST
--------------------------
The four below are load-bearing rather than conventional:

  * test_a_raw_finding_and_its_normalized_form_share_an_identity -- the bug
    that cost 33 points of recall. If a finding's CWE and its class ever
    stop agreeing, everything downstream silently stops matching.
  * test_a_finding_on_the_wrong_line_of_the_right_cwe_is_a_false_positive
    -- my first ad-hoc script counted these as neither hit nor extra, so
    three findings vanished from both tallies. Line proximity is not
    agreement.
  * test_a_neighbour_fixture_cannot_score_against_this_one -- the scoping
    bug. A safe fixture must not inherit the real bugs beside it.
  * test_an_empty_run_is_not_a_pass -- a gate that succeeds because it found
    nothing to check reports health that was never established.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from analysis.validation import compare, metrics  # noqa: E402
from analysis.validation.normalize import (  # noqa: E402
    canonical_class, normalize_finding, normalize_findings, SOURCES)

# --------------------------------------------------------------------------
# normalize
# --------------------------------------------------------------------------


def test_every_documented_source_has_a_normalizer():
    """The handoff names six sources. A normalizer that silently does not
    exist raises on first use, in the middle of a diff, after the peer scan
    has already been paid for."""
    for source in SOURCES:
        finding = normalize_finding(_sample_for(source), source)
        assert finding["_source"] == source


def _sample_for(source: str) -> dict:
    """One representative record per emitter, shaped as that tool emits it."""
    return {
        "rsecopsx": {"rule_id": "JAVA_JDBC_SQL_CONCAT", "file": "a\\b\\S.java",
                     "line": 23, "severity": "High", "cwe": "CWE-89",
                     "snippet": "stmt.executeQuery(sql)"},
        "sarif": {"ruleId": "JAVA_JDBC_SQL_CONCAT", "level": "error",
                  "locations": [{"physicalLocation": {
                      "artifactLocation": {"uri": "src/S.java"},
                      "region": {"startLine": 23}}}],
                  "properties": {"cwe": "CWE-89", "security-severity": "8.1"}},
        "grype": {"vulnerability": {"id": "CVE-2021-44228", "severity": "Critical"},
                  "artifact": {"name": "log4j-core", "version": "2.14.1"}},
        "semgrep": {"check_id": "java.lang.security.audit.sqli",
                    "path": "src/S.java", "start": {"line": 23},
                    "extra": {"severity": "ERROR",
                              "metadata": {"cwe": ["CWE-89: SQL injection"]}}},
        "checkov": {"check_id": "CKV_AWS_18", "file": "main.tf",
                    "file_line_range": [12, 14], "severity": "HIGH"},
        "gitleaks": {"RuleID": "aws-access-key", "File": "config.env",
                     "StartLine": 3, "Secret": "AKIA..."},
    }


def test_a_raw_finding_and_its_normalized_form_share_an_identity():
    """The bug that cost 33 points of recall.

    The comparator keys on CWE or canonical class. If normalizing a finding
    ever stopped deriving its class from its CWE, labels and findings would
    bucket under different keys and nothing would match -- reporting a
    correct tool as wrong on every single finding.
    """
    raw = {"rule_id": "GO_SQL_FMT_SPRINTF", "file": "a.go", "line": 35,
           "severity": "High", "cwe": "CWE-89", "snippet": "db.Query(q)"}
    normalized = normalize_finding(raw, "rsecopsx")

    assert normalized["cwe"] == "CWE-89"
    assert normalized["class"] == "SAST-SQLI"
    assert compare.identity(normalized) == compare.identity(
        {"class": "SAST-SQLI", "cwe": "CWE-89", "basename": "a.go"})


def test_identity_ignores_rule_id_spelling():
    """TAINT_SQL_INJECTION, JAVA_JDBC_SQL_CONCAT and semgrep's audit rule all
    name one defect. A comparator keyed on the literal spelling would report
    three separate detections of it."""
    a = normalize_finding({"rule_id": "TAINT_SQL_INJECTION", "cwe": "CWE-89",
                           "file": "S.java", "line": 23}, "rsecopsx")
    b = normalize_finding({"rule_id": "JAVA_JDBC_SQL_CONCAT", "cwe": "CWE-89",
                           "file": "S.java", "line": 23}, "rsecopsx")
    assert a["class"] == b["class"] == "SAST-SQLI"
    assert compare.identity(a) == compare.identity(b)


def test_paths_normalise_across_separators():
    """R-SecOpsX emits Windows absolute paths, SARIF emits URIs. A literal
    comparison reports every finding as unique because src\\a.py != src/a.py."""
    a = normalize_finding({"rule_id": "R", "cwe": "CWE-89",
                           "file": "C:\\proj\\src\\a.py", "line": 1}, "rsecopsx")
    b = normalize_finding({"rule_id": "R", "cwe": "CWE-89",
                           "file": "src/a.py", "line": 1}, "rsecopsx")
    assert a["basename"] == b["basename"] == "a.py"


def test_an_absent_severity_stays_absent():
    """gitleaks has no severity at all. Inventing "High" for every hit would
    make it look decisive while saying nothing the tool ever chose."""
    out = normalize_finding(_sample_for("gitleaks"), "gitleaks")
    assert out["severity"] is None
    assert out["cwe"] is None


def test_a_severity_is_never_inferred_from_a_number_alone():
    """A numeric 3.1 does not become "High" by looking like one. Mapping
    scores is allowed only where a tool publishes the score AS its severity."""
    out = normalize_finding({"ruleId": "R", "level": "warning",
                             "locations": [{"physicalLocation": {
                                 "artifactLocation": {"uri": "a.py"},
                                 "region": {"startLine": 1}}}],
                             "properties": {}}, "sarif")
    # SARIF 'warning' maps through SARIF's own documented semantics.
    assert out["severity"] == "Medium"


def test_sarif_security_severity_overrides_the_operational_level():
    """security-severity is computed for the specific finding; level is often
    defaulted from the rule. The specific value should win."""
    out = normalize_finding({"ruleId": "R", "level": "warning",
                             "locations": [{"physicalLocation": {
                                 "artifactLocation": {"uri": "a.py"},
                                 "region": {"startLine": 1}}}],
                             "properties": {"security-severity": "9.8"}},
                            "sarif")
    assert out["severity"] == "Critical"


def test_zero_is_a_line_number_not_an_absent_one():
    """0 is a real line and None is not. A truthiness check would treat them
    alike and lose the difference that decides whether two findings match."""
    out = normalize_finding({"rule_id": "R", "cwe": "CWE-89", "file": "a.py",
                             "line": 0}, "rsecopsx")
    assert out["line"] == 0


def test_the_original_record_is_preserved():
    """A disagreement must be traceable to what the tool actually said."""
    raw = {"rule_id": "R", "cwe": "CWE-89", "file": "a.py", "line": 1,
           "severity": "nonsense-value"}
    out = normalize_finding(raw, "rsecopsx")
    assert out["_source_finding"] is raw
    assert out["_source_finding"]["severity"] == "nonsense-value"


def test_an_unknown_source_raises_rather_than_guessing():
    """Guessing a shape would produce a record that looks authoritative and
    is fabricated."""
    with pytest.raises(ValueError):
        normalize_finding({}, "made-up-tool")


def test_one_bad_record_does_not_discard_the_batch():
    """Four hundred peer findings must not be lost to one malformed entry --
    the diff would then understate the peer and read as agreement that was
    never established."""
    good = _sample_for("gitleaks")
    out = normalize_findings([good, "not-a-dict", good], "gitleaks")
    assert len(out) == 2


# --------------------------------------------------------------------------
# compare
# --------------------------------------------------------------------------


def _loc(rule_id, cwe, line, basename="a.py"):
    return normalize_finding({"rule_id": rule_id, "cwe": cwe, "file": basename,
                              "line": line}, "rsecopsx")


def test_a_finding_on_the_wrong_line_of_the_right_cwe_is_a_false_positive():
    """Line proximity is not agreement.

    My first measurement counted a finding as an extra only when its LINE
    was unlabelled, so a CWE-79 finding sitting on a CWE-89 label's line was
    counted as neither a hit nor an extra. Three findings disappeared from
    both tallies and the tool looked better than it was.
    """
    expected = [_loc("SAST-SQLI", "CWE-89", 23)]
    actual = [_loc("JAVA_J5_XSS", "CWE-79", 23)]

    result = compare.compare_findings(actual, expected)

    assert result["counts"]["tp"] == 0
    assert result["counts"]["fp"] == 1
    assert result["counts"]["fn"] == 1


def test_line_zero_default_reproduces_strict_matching():
    """The default must stay 0 so the V0.1 figures remain comparable and
    nothing is hidden by the upgrade."""
    expected = [_loc("SAST-SQLI", "CWE-89", 23)]
    actual = [_loc("JAVA_JDBC_SQL_CONCAT", "CWE-89", 22)]

    assert compare.compare_findings(actual, expected)["counts"]["tp"] == 0
    assert compare.compare_findings(actual, expected, line_tolerance=1)["counts"]["tp"] == 1


def test_a_neighbour_line_matches_only_within_tolerance():
    """Two findings one line apart are one finding; fifteen apart may be two
    injections in a long method, and collapsing them would hide a real one."""
    expected = [_loc("SAST-SQLI", "CWE-89", 23)]
    near = [_loc("JAVA_JDBC_SQL_CONCAT", "CWE-89", 24)]
    far = [_loc("JAVA_JDBC_SQL_CONCAT", "CWE-89", 38)]

    assert compare.compare_findings(near, expected, 1)["counts"]["tp"] == 1
    assert compare.compare_findings(far, expected, 1)["counts"]["tp"] == 0
    assert compare.compare_findings(far, expected, 15)["counts"]["tp"] == 1


def test_the_closest_finding_wins_the_match():
    """A first-come matcher lets a far match consume the expectation, leaving
    the correct near match to be counted as a false positive -- reporting the
    scanner as both wrong and right for one finding."""
    expected = [_loc("SAST-SQLI", "CWE-89", 23)]
    actual = [_loc("FAR_RULE", "CWE-89", 38), _loc("NEAR_RULE", "CWE-89", 23)]

    result = compare.compare_findings(actual, expected, line_tolerance=20)

    assert result["tp"][0]["actual"]["rule_id"] == "NEAR_RULE"
    assert result["tp"][0]["line_delta"] == 0


def test_sca_findings_match_on_component_not_on_line():
    """An advisory is a claim about a component, not about a place in code.
    grype reports no line at all, and requiring one would score it a miss
    for a property it never had."""
    expected = [normalize_finding({"rule_id": "SCA-VULN-DEP", "line": 4,
                                   "package": "click", "version": "8.1.7",
                                   "cve": "CVE-2026-7246"}, "rsecopsx")]
    actual = [normalize_finding({"rule_id": "PYSEC-2026-2132", "line": None,
                                 "package": "Click", "version": "8.1.7",
                                 "cve": "CVE-2026-7246"}, "rsecopsx")]

    result = compare.compare_findings(actual, expected)

    assert result["counts"]["tp"] == 1
    assert result["counts"]["fp"] == 0


def test_a_different_version_of_the_same_package_is_not_a_match():
    """The version is part of the identity. Dropping it would credit a tool
    for flagging a patched release as vulnerable."""
    expected = [normalize_finding({"package": "click", "version": "8.1.7",
                                   "cve": "CVE-2026-7246"}, "rsecopsx")]
    actual = [normalize_finding({"package": "click", "version": "8.3.3",
                                 "cve": "CVE-2026-7246"}, "rsecopsx")]

    assert compare.compare_findings(actual, expected)["counts"]["tp"] == 0


def test_silence_scores_zero_not_perfection():
    """A tool that reports nothing must not score perfect precision, or a
    corpus whose findings are all missed reads as well-tuned."""
    result = compare.compare_findings([], [_loc("SAST-SQLI", "CWE-89", 1)])
    assert result["precision"] == 0.0
    assert result["recall"] == 0.0
    assert result["f1"] == 0.0


def test_perfect_agreement_scores_one():
    finding = _loc("SAST-SQLI", "CWE-89", 23)
    result = compare.compare_findings([finding], [finding])
    assert (result["precision"], result["recall"], result["f1"]) == (1.0, 1.0, 1.0)


# --------------------------------------------------------------------------
# false-positive classification
# --------------------------------------------------------------------------


def test_duplicates_and_spurious_findings_are_separated():
    """"18 false positives" describes two unrelated problems. A duplicate is
    a reporting problem; a spurious finding is a rule problem, and
    deduplication would not make it correct."""
    expected = [_loc("SAST-SQLI", "CWE-89", 23)]
    actual = [
        _loc("JAVA_TAINT_SQL_INJECTION", "CWE-89", 23),   # matches
        _loc("JAVA_JDBC_SQL_CONCAT", "CWE-89", 22),       # duplicate
        _loc("JAVA_J5_XSS", "CWE-79", 23),                # spurious
    ]

    split = compare.classify_false_positives(
        compare.compare_findings(actual, expected))

    assert split["duplicate_count"] == 1
    assert split["spurious_count"] == 1
    assert split["duplicates"][0]["rule_id"] == "JAVA_JDBC_SQL_CONCAT"
    assert split["duplicates"][0]["line_delta"] == 1
    assert split["spurious"][0]["rule_id"] == "JAVA_J5_XSS"


def test_a_far_finding_of_the_same_class_is_not_called_a_duplicate():
    """Two CWE-89 findings fifteen lines apart may be two injections. Folding
    them together would hide a real second finding behind 'duplicate'."""
    expected = [_loc("SAST-SQLI", "CWE-89", 23)]
    actual = [_loc("A", "CWE-89", 23), _loc("B", "CWE-89", 38)]

    split = compare.classify_false_positives(
        compare.compare_findings(actual, expected, line_tolerance=20))

    assert split["spurious_count"] == 1


# --------------------------------------------------------------------------
# metrics
# --------------------------------------------------------------------------


def _comp(tp=0, fp=0, fn=0, language=None, rules=()):
    pairs = [{"expected": {"rule_id": r, "class": r, "cwe": None},
              "actual": {"rule_id": r, "class": r, "cwe": None}}
             for r in rules[:tp]]
    fn_list = [{"rule_id": r, "class": r, "cwe": None}
               for r in rules[tp:tp + fn]]
    return {"tp": pairs, "fp": [{"rule_id": "x", "class": "SAST-XSS", "cwe": "CWE-79"}] * fp,
            "fn": fn_list, "language": language,
            "counts": {"tp": tp, "fp": fp, "fn": fn,
                       "expected": tp + fn, "actual": tp + fp}}


def test_metrics_buckets_by_rule_keyed_on_class_not_rule_id():
    """A bucket per rule ID would split one class across several names and
    hide whether the class as a whole is being found."""
    result = metrics.metrics([_comp(tp=1, rules=("SAST-SQLI",))])

    assert "SAST-SQLI" in result["by_rule"]
    assert result["by_rule"]["SAST-SQLI"]["tp"] == 1


def test_metrics_counts_a_class_that_found_nothing():
    """Omitting a zero bucket would hide exactly the classes worth worrying
    about -- a rule that never fires looks like a rule that was never asked."""
    result = metrics.metrics([_comp(fn=2, rules=("SAST-DESER", "SAST-DESER"))])

    assert result["by_rule"]["SAST-DESER"]["fn"] == 2
    assert result["by_rule"]["SAST-DESER"]["recall"] == 0.0


def test_metrics_preserves_raw_counts_beside_the_ratios():
    """Precision of 1.0 on two findings and on four hundred are not the same
    statement, and only one should change anyone's mind."""
    small = metrics.metrics([_comp(tp=2, rules=("A", "A"))])["overall"]
    large = metrics.metrics([_comp(tp=200, rules=("A",) * 200)])["overall"]

    assert small["precision"] == large["precision"] == 1.0
    assert small["expected"] == 2
    assert large["expected"] == 200


def test_an_empty_comparison_scores_zero_rather_than_one():
    """This is the trap the C++ and Rust fixtures fell into in V0.1: 8
    findings scored as detection misses when the truth was that no rules
    exist for those languages. A harness must not turn absent coverage into
    a perfect score."""
    result = metrics.metrics([_comp(language="cpp")])

    assert result["by_language"]["cpp"]["precision"] == 0.0
    assert result["by_language"]["cpp"]["recall"] == 0.0


def test_metrics_reports_nothing_was_measured():
    """Distinguishes 'measured and clean' from 'measured nothing'. The second
    must never be allowed to read as a pass."""
    assert not metrics.has_expectations(metrics.metrics([]))
    assert metrics.has_expectations(metrics.metrics([_comp(tp=1, rules=("A",))]))


def test_format_table_renders_the_overall_row():
    text = metrics.format_table(metrics.metrics([_comp(tp=1, fp=1, rules=("A",))]))
    assert "OVERALL" in text
    assert "precision" in text


# --------------------------------------------------------------------------
# the runner, against the real corpus
# --------------------------------------------------------------------------


def test_the_committed_corpus_is_measurable():
    """The whole point of V0.2: one command, one number, from the corpus that
    is actually committed."""
    from analysis.validation.run import run_corpus
    from analysis.validation.corpus import CORPUS_ROOT

    result = run_corpus(CORPUS_ROOT)

    assert not result["problems"], result["problems"]
    assert result["overall"]["expected"] > 0
    # SCA is anchored to OSV and was measured at 4/4 in V0.1. It is the one
    # family with an external authority, so it is the one that must hold.
    assert result["by_rule"]["SCA-VULN-DEP"]["recall"] == 1.0


def test_osv_mirror_records_collapse_to_one_claim(monkeypatch):
    """OSV publishes one claim through several records (the same CVE as a
    GHSA and a PYSEC entry -- 141 advisories for 136 CVEs in the prodtest
    measurement). The product's report rows are one per package keyed to its
    primary CVE, so ``_scan_sca`` must not turn a mirrored record into a
    second finding: the comparator scores it a duplicate false positive the
    product never emits. Observed live when the corpus's pypi fixture was
    re-pinned to pyyaml==5.3.1 and the live query returned both twins.

    The collapse is scoped to (package, version, CVE): a CVE is the claim
    identifier. Two records sharing no CVE are two claims and keep the
    per-record treatment, as do CVE-less records.
    """
    from pathlib import Path

    import scanner.sbom as sbom
    import scanner.vulnerability_intel as vi
    from analysis.validation.run import _scan_sca

    monkeypatch.setattr(sbom, "generate_sbom", lambda case_dir: [{}])
    monkeypatch.setattr(vi, "query_osv_batch", lambda packages: {
        "PyPI|pyyaml|5.3.1": [
            {"id": "GHSA-8q59-q68h-6hv4", "cve": "CVE-2020-14343",
             "severity": "Critical", "summary": "Improper Input Validation"},
            {"id": "PYSEC-2021-142", "cve": "CVE-2020-14343",
             "severity": "Critical", "summary": None},
            {"id": "PYSEC-OTHER-1", "cve": "CVE-2019-0001",
             "severity": "High", "summary": "a different claim"},
        ],
        "npm|nocve|1.0.0": [
            {"id": "GHSA-aaaa-1111-xxxx", "cve": None},
            {"id": "GHSA-bbbb-2222-yyyy", "cve": None},
        ],
    })

    findings = _scan_sca(Path("."))

    pyyaml = [f for f in findings if f["package"] == "pyyaml"]
    # twins collapsed to one, the distinct CVE kept
    assert sorted(f["rule_id"] for f in pyyaml) == [
        "GHSA-8q59-q68h-6hv4", "PYSEC-OTHER-1"]
    # CVE-less records assert separate things: per-record treatment stands
    assert len([f for f in findings if f["package"] == "nocve"]) == 2


def test_sast_findings_are_normalized_before_they_are_compared():
    """The gap the teeth check found.

    ``_scan_sca`` emits canonical records already, but ``_scan_sast`` returns
    the scanner's own rich shape -- absolute paths, ``snippet`` rather than
    ``evidence``, and no canonical ``class``. Passing those through raw makes
    the two sides of the comparison bucket under different keys (labels as
    SAST-SQLI, findings as CWE-89), so nothing matches and measured recall
    collapses from 44% to 11% while every label stays valid.

    Checking SCA recall alone cannot catch this, because SCA never touches
    that line. This asserts the SAST side produces matches on its own terms.
    """
    from analysis.validation.run import run_corpus
    from analysis.validation.corpus import CORPUS_ROOT

    result = run_corpus(CORPUS_ROOT)

    sast_classes = {k: v for k, v in result["by_rule"].items()
                    if k.startswith("SAST-")}
    assert sast_classes, "no SAST class was scored at all"

    matched = [k for k, v in sast_classes.items() if v["tp"] > 0]
    assert matched, (
        "no SAST finding matched any label -- the actual findings are almost "
        "certainly not being normalized before comparison, so they bucket by "
        "CWE while the labels bucket by canonical class. Overall recall would "
        "read near 11%%, which is the signature of that bug, not of a scanner "
        "that bad. Matched SAST classes: %s"
        % {k: v["tp"] for k, v in sast_classes.items()})

    # And the overall figure must reflect SAST, not be carried by SCA alone.
    assert result["overall"]["tp"] > result["by_rule"].get(
        "SCA-VULN-DEP", {}).get("tp", 0), (
        "every true positive came from SCA; SAST contributed none")


def test_a_neighbour_fixture_cannot_score_against_this_one():
    """One case directory holds both the safe and the vulnerable fixture.
    Without the per-fixture filter, the safe file inherits the real bugs
    beside it as false positives -- which is exactly what produced 30 java
    false positives from 17 findings."""
    from analysis.validation.run import _scan_sast, _iter_case_dirs
    from analysis.validation.corpus import CORPUS_ROOT

    java_dir = None
    for _family, case_dir, path in _iter_case_dirs(CORPUS_ROOT):
        if path.name == "SafeServlet.java":
            java_dir = case_dir
            break
    assert java_dir is not None

    safe_findings = _scan_sast(java_dir, "SafeServlet.java")
    assert all(Path(str(f.get("file", ""))).name == "SafeServlet.java"
               for f in safe_findings)

    vulnerable_findings = _scan_sast(java_dir, "VulnerableServlet.java")
    assert all(Path(str(f.get("file", ""))).name == "VulnerableServlet.java"
               for f in vulnerable_findings)
    # The two must not be the same set, or the filter is not filtering.
    assert len(vulnerable_findings) != len(safe_findings)


def test_a_label_that_no_longer_matches_is_reported_not_silenced():
    """A corpus defect must surface as a problem, not vanish into a low
    score. The runner exits 1 so it cannot be mistaken for a detection gap."""
    from analysis.validation.run import run_corpus
    from analysis.validation.corpus import CORPUS_ROOT

    result = run_corpus(CORPUS_ROOT)
    assert result["problems"] == []


def test_the_cli_exits_non_zero_when_it_scores_nothing():
    """A gate that returns success because it found nothing to check reports
    health that was never established, and keeps reporting it after the
    corpus breaks."""
    from analysis.validation.run import main

    empty = Path(__file__).resolve().parent.parent / "does_not_exist_corpus"
    assert main(["--corpus", str(empty)]) == 2


def test_the_cli_prints_a_table_for_the_committed_corpus(capsys):
    from analysis.validation.run import main
    from analysis.validation.corpus import CORPUS_ROOT

    main(["--corpus", str(CORPUS_ROOT)])
    out = capsys.readouterr().out

    assert "OVERALL" in out
    assert "precision" in out
    # The duplicate/spurious split is the actionable part of the report.
    assert "false positives, split by cause" in out
