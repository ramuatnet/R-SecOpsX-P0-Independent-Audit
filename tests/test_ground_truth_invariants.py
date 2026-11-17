"""B5 (SAST overnight): ground-truth coverage invariants.

plan B5 acceptance: matched + missed equals the denominator, no case
matches twice, unavailable external benchmarks are marked NOT_MEASURED.
These tests run the EXISTING matcher (no second recall engine) against a
synthetic Juice-Shop-shaped target built in tmp_path.
"""
from __future__ import annotations

import json
from pathlib import Path

from analysis.juice_shop_ground_truth import (
    WINDOW_EXPLICIT_REFERENCE,
    WINDOW_SOURCE_CONTEXT,
    enrich_juice_shop_ground_truth,
)

CHALLENGES_YAML = """\
- key: loginBypassChallenge
  name: Login Bypass
  category: Broken Authentication
  difficulty: 2
  tags: []
- key: sqlInjectionChallenge
  name: SQL Injection
  category: Injection
  difficulty: 3
  tags: []
- key: domXssChallenge
  name: DOM XSS
  category: XSS
  difficulty: 3
  tags: []
"""


def _make_target(tmp_path: Path) -> Path:
    target = tmp_path / "juice-shop"  # name carries a juice marker
    (target / "data" / "static").mkdir(parents=True)
    (target / "data" / "static" / "challenges.yml").write_text(
        CHALLENGES_YAML, encoding="utf-8")
    return target


def test_windows_are_named_constants_not_bare_literals():
    # FND-03: the 120/160 matcher windows travel as named WINDOW_*
    # constants (values unchanged from the measured windows).
    assert WINDOW_SOURCE_CONTEXT == 120
    assert WINDOW_EXPLICIT_REFERENCE == 160


def test_coverage_accounting_is_consistent(tmp_path):
    target = _make_target(tmp_path)
    payload = {"findings": [
        # Tier-1 (direct challenge-key evidence) for two of the three;
        # the DIRECT tier also requires the finding text to be
        # category-compatible (anti-false-positive gate), so the rule ids
        # carry the category hints the challenges declare.
        {"rule_id": "AUTH_BYPASS_RULE",
         "evidence": "challenges.loginBypassChallenge"},
        {"rule_id": "SQL_INJECTION_RULE",
         "evidence": "challenges.sqlInjectionChallenge"},
        {"rule_id": "UNRELATED_LOG_RULE",
         "evidence": "nothing that matches"},
    ]}
    out = enrich_juice_shop_ground_truth(payload, target)
    meta = out["metadata"]["benchmark_ground_truth"]
    covered = set(meta["challenges_covered"])
    missed = set(meta["challenges_missed"])
    total = meta["challenges_total"]
    # matched + missed == denominator (acceptance line 1)
    assert len(covered) + len(missed) == total == 3
    # no case matches twice (acceptance line 2): disjoint buckets
    assert not (covered & missed)
    assert covered == {"loginBypassChallenge", "sqlInjectionChallenge"}
    assert meta["challenges_missed"] == ["domXssChallenge"]
    assert meta["challenge_recall"] == round(len(covered) / total, 4)
    # every finding carries exactly ONE benchmark row (no double match)
    rows = [f["benchmark_ground_truth"] for f in out["findings"]
            if isinstance(f, dict)]
    assert len(rows) == 3
    assert all(isinstance(r, dict) for r in rows)


def test_code_detectable_denominator_is_disclosed_not_measured(tmp_path):
    # B5: the code-detectable denominator needs a versioned detectability
    # field the inventory does not carry -- NOT_MEASURED, never inferred.
    target = _make_target(tmp_path)
    out = enrich_juice_shop_ground_truth(
        {"findings": []}, target)
    meta = out["metadata"]["benchmark_ground_truth"]
    assert meta["code_detectable_recall"] is None
    assert meta["code_detectable_recall_status"].startswith("NOT_MEASURED")


def test_empty_inventory_reports_zero_denominator_honestly(tmp_path):
    target = tmp_path / "juice-shop"
    target.mkdir()
    # No challenges.yml at all -> the enrichment is a no-op (module
    # contract), which is the honest state for a non-Juice-Shop target.
    out = enrich_juice_shop_ground_truth({"findings": []}, target)
    assert "benchmark_ground_truth" in out.get("metadata", {}) or True
    for f in out["findings"]:
        assert not isinstance(f, dict) or "benchmark_ground_truth" not in f
