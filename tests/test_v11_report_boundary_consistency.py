"""Serialization-boundary report consistency (J-series).

A validation pass over a real Juice Shop scan found three classes of defect
that all share one root cause: aggregates and console output were produced
from a *pre-prune* finding population and never refreshed after the
serialization boundary mutated `findings[]`.

  J-1  Console reported ``1439 unique findings`` and a severity table that
       did not match the ``1293``-total ``clean_report.json`` written seconds
       later, because the summary block ran *before*
       ``_final_report_integrity_pass()`` / ``_apply_final_report_safety()``.
  J-2  ``owasp`` summed to 1436 against a 1290-entry ``findings`` array, and
       ``insights`` still claimed 9 SSRF / 4 deserialization / 141 hardcoded
       credential findings against final counts of 6 / 1 / 3. ``mitre`` was
       built from the same stale population.
  J-3  The Analysis Context line printed "0 synthetic findings excluded"
       while 218 ``benchmark_synthetic`` findings were inside the primary
       count -- true but read as "there are none".
  J-4  Ground truth reported only the finding -> challenge direction (15
       declared-intentional, 1275 unresolved) with no denominator, so 13/116
       challenge coverage was invisible.

A fourth, independent defect is a detection-scope one:

  J-5  A generic key/value parser read UI labels out of translation
       catalogues and demo rows out of seed datasets as deployable
       configuration credentials: 1188 of 1290 findings (92%) on that corpus
       were the ``key=[REDACTED]`` shape against files such as
       ``frontend/src/assets/i18n/ar_SA.json`` and ``data/static/users.yml``.

Every fix here is pinned both by a behavioural test and by a source-ordering
test, because the J-1/J-2 defects are ordering bugs that a unit test of the
helper alone would not catch.
"""
from __future__ import annotations

import textwrap
from pathlib import Path

import pytest


def _main_source() -> str:
    return (Path(__file__).resolve().parents[1] / "main.py").read_text(encoding="utf-8")


def _payload(findings: list[dict]) -> dict:
    return {
        "metadata": {"sast_findings": len(findings), "sca_findings": 0,
                     "total_findings": len(findings), "risk_score": 10.0},
        "findings": findings,
        "sbom": [],
        "attack_paths": [],
    }


def _finding(rule_id: str, vuln_type: str, *, severity: str = "High",
             occurrences: list | None = None, snippet: str = "x = 1") -> dict:
    return {
        "rule_id": rule_id,
        "title": f"{rule_id} finding",
        "vuln_type": vuln_type,
        "severity": severity,
        "confidence": "High",
        "file": "app.py",
        "line": 3,
        "snippet": snippet,
        "evidence": [snippet],
        "owasp": "A03:2021 - Injection" if vuln_type == "sql_injection"
        else "A10:2021 - Server-Side Request Forgery",
        "mitre": "T1190",
        "instances": 1,
        "occurrences": [{"file": "app.py", "line": 3, "snippet": snippet}]
        if occurrences is None else occurrences,
    }


# ---------------------------------------------------------------------------
# J-2 -- finding-derived aggregates are rebuilt from the final population
# ---------------------------------------------------------------------------


def test_rebuild_owasp_sum_equals_final_finding_count():
    from main import _rebuild_finding_derived_aggregates

    payload = _payload([_finding("SQLI", "sql_injection"), _finding("SSRF", "ssrf")])
    # Simulate the pre-prune state the defect shipped with: an aggregate that
    # describes 9 findings while findings[] holds 2.
    payload["owasp"] = {f"STALE{i}": {"category": f"STALE{i}", "count": 7}
                        for i in range(9)}

    out = _rebuild_finding_derived_aggregates(payload)

    total = sum(v["count"] for v in out["owasp"].values())
    assert total == len(out["findings"]) == 2
    assert set(out["owasp"]) == {"A03", "A10"}


def test_rebuild_mitre_reflects_final_findings_only():
    from main import _rebuild_finding_derived_aggregates

    payload = _payload([_finding("SSRF", "ssrf")])
    payload["findings"][0]["mitre"] = ["T1083"]
    payload["mitre"] = [{"id": "T1195", "description": "stale"},
                        {"id": "T1552", "description": "stale"}]

    out = _rebuild_finding_derived_aggregates(payload)

    assert [m["id"] for m in out["mitre"]] == ["T1083"]


def test_rebuild_insight_counts_match_final_findings():
    from main import _rebuild_finding_derived_aggregates

    payload = _payload([_finding("SSRF", "ssrf")])
    # The shipped defect: an insight that outlives the findings it counts.
    payload["insights"] = ["SSRF RISK: 9 Server-Side Request Forgery "
                           "vulnerabilities detected. keep"]

    out = _rebuild_finding_derived_aggregates(payload)

    ssrf = [i for i in out["insights"] if i.startswith("SSRF RISK:")]
    assert len(ssrf) == 1
    assert ssrf[0].startswith("SSRF RISK: 1 Server-Side Request Forgery vulnerability detected")


def test_rebuild_drops_insights_for_findings_that_no_longer_exist():
    from main import _rebuild_finding_derived_aggregates

    # Empty final population: every count-bearing insight must disappear.
    payload = _payload([])
    payload["insights"] = ["SSRF RISK: 9 Server-Side Request Forgery vulnerabilities detected.",
                           "DESERIALIZATION: 4 insecure deserialization sinks detected."]

    out = _rebuild_finding_derived_aggregates(payload)

    assert not any(i.startswith(("SSRF RISK:", "DESERIALIZATION:")) for i in out["insights"])
    assert out["owasp"] == {}


def test_rebuild_is_read_only_with_respect_to_findings():
    from main import _rebuild_finding_derived_aggregates

    findings = [_finding("SQLI", "sql_injection"), _finding("SSRF", "ssrf", severity="Low")]
    payload = _payload(findings)
    before = [dict(f) for f in payload["findings"]]

    out = _rebuild_finding_derived_aggregates(payload)

    assert out["findings"] == before
    assert [f["severity"] for f in out["findings"]] == ["High", "Low"]


def test_rebuild_fails_open_when_aggregate_builder_raises(monkeypatch):
    from main import _rebuild_finding_derived_aggregates
    import core.analyzer as analyzer

    payload = _payload([_finding("SSRF", "ssrf")])
    payload["owasp"] = {"A10": {"category": "A10:2021 - Server-Side Request Forgery", "count": 1}}
    payload["insights"] = ["EXISTING ENTRY"]

    def boom(_findings):
        raise RuntimeError("aggregate builder unavailable")

    monkeypatch.setattr(analyzer, "_build_owasp_summary", boom)
    out = _rebuild_finding_derived_aggregates(payload)

    # Fail open: never drop an aggregate because a rebuild failed.
    assert out["owasp"] == payload["owasp"]
    assert out["insights"] == ["EXISTING ENTRY"]
    assert len(out["findings"]) == 1


def test_integrity_pass_then_rebuild_stay_consistent():
    from main import _final_report_integrity_pass, _rebuild_finding_derived_aggregates

    kept = _finding("SQLI", "sql_injection")
    dropped = _finding("SSRF", "ssrf")
    dropped["occurrences"] = []          # every occurrence pruned by the gate
    payload = _payload([kept, dropped])
    payload["owasp"] = {"A03": {"category": "A03:2021 - Injection", "count": 1},
                        "A10": {"category": "A10:2021 - Server-Side Request Forgery",
                                "count": 1}}

    payload = _final_report_integrity_pass(payload)
    assert len(payload["findings"]) == 1, "integrity pass must drop the empty shell"

    payload = _rebuild_finding_derived_aggregates(payload)
    assert sum(v["count"] for v in payload["owasp"].values()) == len(payload["findings"])
    assert "A10" not in payload["owasp"]


def test_supply_chain_refresh_only_rewrites_that_entry():
    from main import _refresh_supply_chain_insight

    payload = _payload([])
    payload["sbom"] = [{"cvss": 8.1, "name": "vuln-pkg"}]
    payload["reachable_vulnerable_packages"] = [{"name": "vuln-pkg"}]
    payload["insights"] = [
        "SUPPLY CHAIN: 7 dependency packages with CVSS >= 7.0 detected. stale",
        "UNRELATED ENTRY",
    ]

    _refresh_supply_chain_insight(payload)

    supply = [i for i in payload["insights"] if i.startswith("SUPPLY CHAIN:")]
    assert len(supply) == 1
    assert supply[0].startswith("SUPPLY CHAIN: 1 dependency packages with CVSS >= 7.0 detected. 1 vulnerable")
    assert "UNRELATED ENTRY" in payload["insights"]


def test_supply_chain_refresh_leaves_insights_absent_alone():
    from main import _refresh_supply_chain_insight

    payload = _payload([])
    payload.pop("insights", None)
    _refresh_supply_chain_insight(payload)
    assert "insights" not in payload


# ---------------------------------------------------------------------------
# J-1 -- console summary is printed after the payload stops changing
# ---------------------------------------------------------------------------


def test_console_summary_runs_after_every_payload_mutation():
    src = _main_source()
    positions = {
        "integrity": src.index("payload = _final_report_integrity_pass(payload)"),
        "safety": src.index("payload = _apply_final_report_safety(payload)"),
        "rebuild": src.index("payload = _rebuild_finding_derived_aggregates(payload)"),
        "risk line": src.index('_safe_print(\n        f"       => {total} unique findings'),
        # indented call site -- the plain substring also matches the def line
        "dist": src.index("\n    _print_dist(dist)"),
        "write": src.index('_step("Writing JSON report")'),
        "insights": src.index('INTELLIGENCE INSIGHTS:'),
    }
    ordered = sorted(positions, key=positions.get)
    # Every payload mutation must precede the print, or the console will
    # disagree with the clean_report.json written seconds later. The print is
    # now deliberately LAST -- after JSON, the performance table, the output
    # file list and the insights -- so the verdict sits at the bottom of the
    # scroll instead of minutes above it. Asserted exactly: a loose "at least"
    # form would let the summary drift back up the console unnoticed.
    assert ordered == ["integrity", "safety", "rebuild", "write",
                       "insights", "risk line", "dist"], (
        "the console summary must be produced from the payload that is "
        f"actually serialized, or it will disagree with the JSON artifact: {ordered}"
    )
    assert "FINAL RESULTS" in src, "the summary must be labelled at the end"


def test_final_results_block_is_the_last_thing_printed():
    src = _main_source()
    results_at = src.index("FINAL RESULTS")
    insights_at = src.index("INTELLIGENCE INSIGHTS:")
    done_at = src.index("[DONE]  Scan complete")
    files_at = src.index('Output files:')
    # Narration first, verdict last.
    assert done_at < files_at < insights_at < results_at, (
        "FINAL RESULTS must come after [DONE], the output file list and the "
        "insights, otherwise it is not at the end of the console"
    )
    # ...and still inside main(), before the __main__ guard.
    assert results_at < src.index('if __name__ == "__main__":')


def test_analysis_context_is_printed_once_per_population_and_agrees_with_the_artifact():
    src = _main_source()
    raw_at = src.index("=> Analysis Context (raw, pre-dedup): ")
    final_at = src.index("=> Analysis Context (final report): ")
    safety_at = src.index("payload = _apply_final_report_safety(payload)")
    write_at = src.index('_step("Writing JSON report")')

    # The classification-time reading may be pre-dedup only if it says so.
    # The artifact-facing reading must be produced AFTER the last payload
    # mutation; it is printed at the very end of the console (after the write)
    # so the verdict is at the bottom of the scroll. Printing it later than the
    # write does not weaken the check -- it still reads the payload that was
    # written -- but printing it before the last mutation would.
    assert raw_at < safety_at < write_at < final_at, (
        "the final Analysis Context line must be computed from the payload "
        f"after every mutation: raw={raw_at} safety={safety_at} "
        f"write={write_at} final={final_at}"
    )
    # The shipped wording quoted a bare count with no population named, which
    # is what made "0 synthetic findings excluded" read as "there are none".
    assert "preserved_for_evaluation'))} findings preserved for evaluation" not in src
    assert "synthetic findings excluded from primary count" not in src
    # The final reading must be checkable field for field against clean_report.json.
    assert "_final_synthetic} of {len(_final_findings)} findings are benchmark-synthetic" in src
    assert "_final_suppressed} suppressed from primary count" in src
    assert "_final_preserved} preserved for evaluation" in src


def test_ground_truth_coverage_is_printed_with_a_denominator():
    src = _main_source()
    assert "Ground truth coverage:" in src
    assert "{_gt.get('challenges_covered_count', 0)}/{_gt.get('challenges_total', 0)}" in src


# ---------------------------------------------------------------------------
# J-5 -- translation catalogues and seed datasets are not configuration
# ---------------------------------------------------------------------------


_I18N_TEXT = textwrap.dedent("""\
    {
      "MANDATORY_PASSWORD": "Mandatory password",
      "LABEL_PASSWORD": "Password label value",
      "signing_material": "-----BEGIN RSA PRIVATE KEY-----"
    }
""")


def _scan(tmp_path: Path, rel: str, text: str) -> list[dict]:
    from scanner.secret_intelligence import scan_file

    path = tmp_path / "proj" / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return scan_file(str(path))


def _rules(findings: list[dict]) -> set[str]:
    return {str(f.get("rule_id")) for f in findings}


@pytest.mark.parametrize(
    "rel",
    [
        "frontend/src/assets/i18n/ar_SA.json",
        "data/static/i18n/fr_FR.json",
        "src/locales/de_DE.json",
        "app/translations/es_ES.json",
        "data/static/users.yml",
        "data/seed/demo.json",
    ],
)
def test_translation_and_seed_paths_are_not_config_credentials(tmp_path, rel):
    text = "MANDATORY_PASSWORD: Mandatory password\n" if rel.endswith((".yml", ".yaml")) else _I18N_TEXT
    rules = _rules(_scan(tmp_path, rel, text))
    assert "CONFIG_CONTEXTUAL_CREDENTIAL" not in rules


@pytest.mark.parametrize("rel", ["config/app.json", "data/users.yml", ".github/workflows/ci.json"])
def test_real_configuration_paths_still_flag(tmp_path, rel):
    """The same key/value content outside the withheld paths must still report.

    Without this control the withholding test would pass just as happily if
    the rule had been disabled outright.
    """
    text = "MANDATORY_PASSWORD: Mandatory password\n" if rel.endswith((".yml", ".yaml")) else _I18N_TEXT
    rules = _rules(_scan(tmp_path, rel, text))
    assert "CONFIG_CONTEXTUAL_CREDENTIAL" in rules


def test_withholding_is_narrow_to_the_key_value_interpretation(tmp_path):
    """Known-signature / PEM / URI / JWT detection still runs on those files."""
    rules = _rules(_scan(tmp_path, "frontend/src/assets/i18n/ar_SA.json", _I18N_TEXT))
    assert "CONFIG_CONTEXTUAL_CREDENTIAL" not in rules
    assert "PEM_PRIVATE_KEY" in rules


@pytest.mark.parametrize(
    "path,expected",
    [
        (r"proj\i18n\ar_SA.json", True),
        (r"proj\src\locales\de_DE.json", True),
        (r"proj\data\static\users.yml", True),
        (r"proj\data\seed\demo.yml", True),
        (r"proj\config\app.yml", False),
        (r"proj\data\users.yml", False),
        (r"proj\routes\chat.ts", False),
        (r"proj\.github\workflows\ci.yml", False),
        (r"proj\static\logo.svg", False),
    ],
)
def test_is_translated_text_or_seed_dataset_scoping(path, expected):
    from scanner.secret_intelligence import _is_translated_text_or_seed_dataset

    assert _is_translated_text_or_seed_dataset(Path(path)) is expected


# ---------------------------------------------------------------------------
# J-4 -- challenge -> finding coverage, i.e. the missing denominator
# ---------------------------------------------------------------------------


_CHALLENGES = textwrap.dedent("""\
    - key: reflectedErrorChallenge
      name: Reflected Error
      category: XSS
      difficulty: 1
      tags: [xss]
    - key: unionSqlInjection
      name: SQL Injection
      category: Injection
      difficulty: 2
      tags: [sqli]
""")


def _juice_payload() -> dict:
    return {
        "metadata": {},
        "findings": [
            {
                "rule_id": "XSS_REFLECTED",
                "title": "Reflected Error cross-site scripting",
                "vuln_type": "xss",
                "severity": "Medium",
                "snippet": "challengeUtils.solveIf(challenges.reflectedErrorChallenge, true)",
                "line": 10,
                "file": "routes/xss.ts",
            },
            {
                "rule_id": "SQL_INJECTION",
                "title": "Union based SQL injection",
                "vuln_type": "sql_injection",
                "severity": "High",
                "snippet": "db.query(sql)",
                "line": 20,
                "file": "routes/sqli.ts",
            },
        ],
    }


def test_ground_truth_reports_challenge_coverage_direction(tmp_path):
    from analysis.juice_shop_ground_truth import enrich_juice_shop_ground_truth

    challenge_dir = tmp_path / "data" / "static"
    challenge_dir.mkdir(parents=True)
    (challenge_dir / "challenges.yml").write_text(_CHALLENGES, encoding="utf-8")

    out = enrich_juice_shop_ground_truth(_juice_payload(), tmp_path)
    summary = out["metadata"]["benchmark_ground_truth"]

    assert summary["ground_truth_source_status"] == "LOADED"
    assert summary["challenges_total"] == 2
    assert summary["challenges_covered"] == ["reflectedErrorChallenge"]
    assert summary["challenges_covered_count"] == 1
    assert summary["challenges_missed"] == ["unionSqlInjection"]
    assert summary["challenges_missed_count"] == 1
    assert summary["challenge_recall"] == 0.5
    assert summary["challenge_coverage_status"] == "PARTIAL"
    # The forward direction is unchanged: 1 declared / 1 unresolved.
    assert summary["declared_intentional_findings"] == 1
    assert summary["unresolved_findings"] == 1
    assert summary["matching_basis_counts"] == {"DIRECT_CHALLENGE_KEY_EVIDENCE": 1}


def test_ground_truth_missed_is_scanner_coverage_not_a_claim_of_absence(tmp_path):
    from analysis.juice_shop_ground_truth import enrich_juice_shop_ground_truth

    challenge_dir = tmp_path / "data" / "static"
    challenge_dir.mkdir(parents=True)
    (challenge_dir / "challenges.yml").write_text(_CHALLENGES, encoding="utf-8")

    out = enrich_juice_shop_ground_truth(_juice_payload(), tmp_path)
    summary = out["metadata"]["benchmark_ground_truth"]

    assert "NOT_PROOF_OF_ABSENCE" in summary["coverage_caveat"]
    # Coverage is reported per challenge; no finding is relabelled because
    # some *other* challenge went uncovered.
    statuses = {f["benchmark_ground_truth"]["status"] for f in out["findings"]}
    assert statuses == {"DECLARED_INTENTIONAL", "UNRESOLVED"}
    assert summary["challenges_missed_count"] == 1
    assert summary["declared_intentional_findings"] == 1


def test_ground_truth_noop_without_a_challenge_inventory(tmp_path):
    from analysis.juice_shop_ground_truth import enrich_juice_shop_ground_truth

    payload = _juice_payload()
    payload["metadata"] = {"marker": 1}
    out = enrich_juice_shop_ground_truth(payload, tmp_path)

    assert out["metadata"].get("benchmark_ground_truth") is None
    assert out["metadata"]["marker"] == 1


# ---------------------------------------------------------------------------
# G-053 -- one scan must publish one set of insight counts in all four
# artifacts (console, clean_report.json, PDF, Excel).
# ---------------------------------------------------------------------------


def test_high_risk_insight_is_rewritten_to_the_reported_distribution():
    from reporting.report_mappings import normalize_report_insights

    # generate_insights() counts the SAST-only population, while the severity
    # table printed directly beneath it counts SAST plus unique vulnerable
    # dependency packages. On Juice Shop that was 2 in the insight against 4
    # in the table.
    out = normalize_report_insights(
        ["HIGH RISK: 2 high-severity findings present. "
         "Schedule remediation within 7 days per SLA guidelines."],
        {"Critical": 1, "High": 4, "Medium": 42, "Low": 58, "Info": 0},
    )
    assert out[0].startswith("HIGH RISK: 4 high-severity findings present")
    assert "Schedule remediation within 7 days" in out[0]


def test_high_risk_accepts_the_idor_wording_too():
    from reporting.report_mappings import normalize_report_insights

    # core/idoranalyzer.py emits "high-severity issues", not "findings".
    out = normalize_report_insights(
        ["HIGH RISK: 3 high-severity issues present. rest"],
        {"Critical": 0, "High": 5, "Medium": 0, "Low": 0, "Info": 0},
    )
    assert out[0].startswith("HIGH RISK: 5 high-severity findings present")


def test_insight_normalisation_is_idempotent():
    from reporting.report_mappings import normalize_report_insights

    dist = {"Critical": 1, "High": 4, "Medium": 42, "Low": 58, "Info": 0}
    once = normalize_report_insights(
        ["HIGH RISK: 2 high-severity findings present. x"], dist)
    assert normalize_report_insights(once, dist) == once


def test_compliance_risk_matches_the_combined_distribution():
    from reporting.report_mappings import normalize_report_insights

    # The PDF already rewrote this to 5 (Critical 1 + High 4) while the
    # console and clean_report.json kept the raw 2.
    out = normalize_report_insights(
        ["COMPLIANCE RISK: 2 Critical/High findings require review against PCI DSS."],
        {"Critical": 1, "High": 4, "Medium": 42, "Low": 58, "Info": 0},
    )
    assert out[0].startswith("COMPLIANCE RISK: 5 Critical/High findings")


def test_insights_outside_the_severity_branches_keep_their_counts():
    from reporting.report_mappings import normalize_report_insights

    out = normalize_report_insights(
        ["SSRF RISK: 6 Server-Side Request Forgery vulnerabilities detected.",
         "SUPPLY CHAIN: 2 dependency packages with CVSS >= 7.0 detected."],
        {"Critical": 1, "High": 4},
    )
    assert "6 Server-Side Request Forgery" in out[0]
    assert "2 dependency packages" in out[1]


def test_console_and_json_insights_are_normalised_before_anything_reads_them():
    src = _main_source()
    dist_at = src.index('meta["severity_distribution"] = dist')
    norm_at = src.index('normalize_report_insights(payload["insights"], dist)')
    consume_at = src.index('for ins in payload.get("insights", []):')

    # payload["insights"] is read raw by the console loop and written raw to
    # clean_report.json, while pdf_report.py and excel_report.py normalise on
    # their own. Normalising once, after the distribution is final and before
    # any consumer runs, is what makes all four artifacts agree.
    assert dist_at < norm_at < consume_at, (
        "insight normalisation must run after severity_distribution is final "
        "and before the console/JSON read payload[\"insights\"]"
    )


def test_normalisation_fails_open_without_dropping_the_report():
    src = _main_source()
    body = src[src.index('normalize_report_insights(payload["insights"], dist)'):]
    body = body[: body.index("One canonical release decision")]
    assert "except Exception:" in body
    # Fail open must leave the insights in place, not delete them.
    assert 'payload["insights"] = []' not in body


def test_the_false_sast_contract_comment_is_gone():
    src = (Path(__file__).resolve().parents[1] / "core" / "analyzer.py").read_text(
        encoding="utf-8")
    # It used to assert that metadata.severity_distribution was built from
    # this same SAST population; main.py builds it as SAST plus unique
    # vulnerable dependency packages and labels the scope explicitly.
    assert "is the same finalized SAST population used by" not in src
    assert "severity_distribution_sast" in src
