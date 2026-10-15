"""The policy catalogue must agree with the evidence it is classifying.

Audited on a real scan (wrongsecrets, 2026-10-15): the report's own category
column called 654 components "Permissive" while the final policy engine
returned UNCLASSIFIED_LICENSE / REVIEW_REQUIRED for eight of them -- npm
components declaring BlueOak-1.0.0, Python-2.0, CC-BY-4.0 and three SPDX
OR-expressions.  The two numbers disagreed because the decision layer carried
a narrower licence set than the category pass.  These tests pin the single
catalogue (core.license_catalog) both layers now read, the compound-expression
rules that replace blanket rejection, and the one-version engine labels the
audit also flagged (V3 in detail rows, V1 in the summary of the same run).
"""
from __future__ import annotations

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from analysis.license_policy_engine import (  # noqa: E402
    enrich_license_policy,
    license_policy_summary,
)


def _row(name: str, version: str, license_value: str) -> dict:
    return {
        "name": name,
        "version": version,
        "license": license_value,
        "license_declared": license_value,
        "license_resolution_status": "RESOLVED_FROM_CANONICAL_REPORT",
    }


def _policy(license_value: str, name: str = "pkg") -> dict:
    return enrich_license_policy([_row(name, "1.0.0", license_value)])[0]


# The eight components a real scan classified twice, differently.
REALWORLD_CASES = [
    ("minimatch", "BlueOak-1.0.0"),
    ("argparse", "Python-2.0"),
    ("caniuse-lite", "CC-BY-4.0"),
    ("type-fest", "(MIT OR CC0-1.0)"),
    ("opener", "(WTFPL OR MIT)"),
    ("json-schema", "(AFL-2.1 OR BSD-3-Clause)"),
]


def test_permissive_identifiers_and_all_permissive_or_expressions_are_allowed():
    for name, lic in REALWORLD_CASES:
        item = _policy(lic, name)
        assert item["license_risk"] == "LOW", (name, lic, item["license_risk"])
        assert item["license_issue"] == "PERMISSIVE_LICENSE", (
            name, lic, item["license_issue"])
        assert item["license_policy_decision"] == "ALLOW", (
            name, lic, item["license_policy_decision"])


def test_category_and_policy_issue_no_longer_disagree():
    """654 category=Permissive vs 646 PERMISSIVE_LICENSE was the audit's
    headline inconsistency: every permissive-classified row must carry the
    permissive policy issue."""
    rows = enrich_license_policy(
        [_row(n, "1.0.0", lic) for n, lic in REALWORLD_CASES]
        + [_row("plain", "1.0.0", "MIT")]
    )
    permissive = [r for r in rows if r["license_risk"] == "LOW"]
    assert len(permissive) == len(rows)
    for item in rows:
        assert item["license_issue"] == "PERMISSIVE_LICENSE", item


def test_bare_spdx_expressions_from_lockfiles_also_classify():
    """npm lockfiles and CycloneDX carry the unparenthesised form too:
    "MIT OR Apache-2.0" (biome binaries), "Apache-2.0 AND MIT" (@swc/core)."""
    for lic in ("MIT OR Apache-2.0", "(MIT OR Apache-2.0)"):
        item = _policy(lic, "biome")
        assert item["license_policy_decision"] == "ALLOW", (lic, item)
        assert item["license_notice_required"] is True, (lic, item)

    and_item = _policy("Apache-2.0 AND MIT", "swc")
    assert and_item["license_policy_decision"] == "ALLOW", and_item


def test_and_expression_with_copyleft_governs_by_most_restrictive():
    """sharp declares "Apache-2.0 AND LGPL-3.0-or-later": every obligation
    applies, so the LGPL part governs."""
    item = _policy("Apache-2.0 AND LGPL-3.0-or-later", "sharp")
    assert item["license_risk"] == "MEDIUM", item
    assert item["license_policy_decision"] == "APPROVE_WITH_CONDITIONS", item
    assert item["license_issue"] == "COPYLEFT_OR_RECIPROCAL_LICENSE", item


def test_mit_no_attribution_is_permissive_without_a_notice_requirement():
    item = _policy("MIT-0", "color-helpers")
    assert item["license_risk"] == "LOW", item
    assert item["license_policy_decision"] == "ALLOW", item
    assert item["license_notice_required"] is False, item


def test_mixed_or_expression_stays_under_review():
    """(GPL-2.0 OR MIT) is distributable under MIT, but only once the consumer
    records which option it honours -- ALLOW would be guessing for them."""
    item = _policy("(GPL-2.0 OR MIT)", "mixed-lib")
    assert item["license_policy_decision"] == "REVIEW_REQUIRED", item
    assert item["license_issue"] == "MIXED_LICENSE_EXPRESSION", item
    # node-forge's exact declaration: distributable, but only once the
    # consumer records which option it honours.
    forge = _policy("(BSD-3-Clause OR GPL-2.0)", "node-forge")
    assert forge["license_policy_decision"] == "REVIEW_REQUIRED", forge


def test_high_risk_option_in_or_expression_is_still_review():
    item = _policy("(MIT OR AGPL-3.0)", "sneaky-lib")
    assert item["license_policy_decision"] == "REVIEW_REQUIRED", item


def test_and_expression_applies_every_obligation():
    item = _policy("(MIT AND MPL-2.0)", "and-lib")
    assert item["license_risk"] == "MEDIUM", item
    assert item["license_policy_decision"] == "APPROVE_WITH_CONDITIONS", item


def test_nested_expression_still_falls_through_to_review():
    item = _policy("(MIT OR (GPL-2.0 AND ISC))", "nested-lib")
    assert item["license_policy_decision"] == "REVIEW_REQUIRED", item
    assert item["license_issue"] == "UNCLASSIFIED_LICENSE", item


def test_unclassifiable_option_in_expression_stays_review():
    item = _policy("(MIT OR Some-Future-License)", "future-lib")
    assert item["license_policy_decision"] == "REVIEW_REQUIRED", item


def test_attribution_obligations_survive_the_expression():
    item = _policy("(MIT OR CC0-1.0)", "type-fest")
    assert item["license_notice_required"] is True, item


def test_strong_copyleft_is_still_the_only_legal_escalation():
    item = _policy("AGPL-3.0", "agpl-lib")
    assert item["license_policy_decision"] == "LEGAL_REVIEW_REQUIRED", item
    summary = license_policy_summary([item])
    assert summary["legal_review_required_components"] == 1


def test_unknown_license_reason_points_at_policy_review():
    """The old reason said "legal review may be required" next to a summary
    reporting legal_review_required = 0; the routing must be explicit."""
    item = _policy("unknown", "unknown-lib")
    assert item["license_policy_decision"] == "REVIEW_REQUIRED", item
    assert "policy review" in item["license_reason"].lower(), item["license_reason"]


def test_engine_label_is_one_version_everywhere():
    """V3 in the detail rows and V1 in the summary of the same run was the
    audit's 'confirm which engine produced the results' finding: the per-item
    method must extend the summary status."""
    rows = enrich_license_policy(
        [_row(n, "1.0.0", lic) for n, lic in REALWORLD_CASES])
    summary = license_policy_summary(rows)
    status = summary["summary_status"]
    assert status.startswith("RULE_BASED_LICENSE_POLICY_V"), status
    for item in rows:
        assert item["license_policy_method"].startswith(status), (
            item["license_policy_method"], status)


def test_review_required_counts_drop_to_the_genuinely_unknown():
    """131 = 123 unknown + 8 mislabelled permissive; only the unknowns should
    remain under review once the catalogue recognises the eight."""
    rows = enrich_license_policy(
        [_row(n, "1.0.0", lic) for n, lic in REALWORLD_CASES]
        + [_row(f"unknown-{i}", "1.0.0", "unknown") for i in range(3)]
    )
    summary = license_policy_summary(rows)
    assert summary["decision_counts"].get("REVIEW_REQUIRED") == 3, (
        summary["decision_counts"])
    assert summary["issue_counts"].get("UNCLASSIFIED_LICENSE") in (None, 0), (
        summary["issue_counts"])
    assert summary["decision_counts"].get("ALLOW") == len(REALWORLD_CASES)


def test_declared_value_precedence_is_unchanged():
    """The evidence-precedence contract (resolved beats declared) must survive
    the catalogue delegation."""
    row = _row("lib", "1.0.0", "unknown")
    row["license_resolved"] = "MIT"
    item = enrich_license_policy([row])[0]
    assert item["license_policy_source"] == "QUALIFIED_RESOLVED_EVIDENCE", item
    assert item["license_policy_decision"] == "ALLOW", item
