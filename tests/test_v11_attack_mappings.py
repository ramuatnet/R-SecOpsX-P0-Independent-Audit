"""Tests for the pinned MITRE ATT&CK Enterprise catalogue.

G-069 / D6 shipped a defect that these tests exist to make impossible to
reintroduce: an 11-entry hardcoded table with a fixed placeholder as the
fallback, so T1595 appeared in both PDFs carrying the placeholder as its
"description" -- a value that looks like a resolved technique name and is not
one. The conformance probe `attack_no_placeholder_names` is the negative guard
for the same thing at the standard level; this file pins it at the unit level.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from core.attack_mappings import (  # noqa: E402
    ATTACK_ATTRIBUTION,
    ATTACK_BUNDLE_SHA256,
    ATTACK_CATALOGUE_SENTINEL,
    ATTACK_CURRENT_TECHNIQUES,
    ATTACK_DATASET_LABEL,
    ATTACK_DEPRECATED,
    ATTACK_LICENSE,
    ATTACK_REVOKED,
    ATTACK_TACTICS,
    ATTACK_TECHNIQUES,
    ATTACK_UNRESOLVED_REASON,
    ATTACK_VERSION,
    attack_summary,
    tactics_for,
    technique,
    technique_label,
    technique_status,
)
from core.analyzer import _build_mitre_summary  # noqa: E402

PLACEHOLDER = "Mapped" + " ATT&CK technique"


# ===========================================================================
# Provenance
# ===========================================================================

def test_dataset_is_pinned_by_digest():
    assert re.fullmatch(r"[0-9A-F]{64}", ATTACK_BUNDLE_SHA256), ATTACK_BUNDLE_SHA256
    assert ATTACK_BUNDLE_SHA256 == ATTACK_CATALOGUE_SENTINEL["bundle_sha256"]


def test_version_is_recorded_not_latest():
    assert ATTACK_VERSION and ATTACK_VERSION != "latest"
    assert re.match(r"^\d+\.\d+$", ATTACK_VERSION), ATTACK_VERSION
    assert ATTACK_VERSION in ATTACK_DATASET_LABEL


def test_catalogue_sizes_are_self_consistent():
    s = ATTACK_CATALOGUE_SENTINEL
    assert s["techniques"] == len(ATTACK_TECHNIQUES)
    assert s["current"] == len(ATTACK_CURRENT_TECHNIQUES)
    assert s["revoked"] == len(ATTACK_REVOKED)
    assert s["deprecated"] == len(ATTACK_DEPRECATED)
    assert s["tactics"] == len(ATTACK_TACTICS)
    assert s["current"] + s["revoked"] == s["techniques"]


def test_attribution_and_licence_are_declared():
    assert "MITRE" in ATTACK_ATTRIBUTION
    assert "ATT&CK" in ATTACK_LICENSE
    # NOT the ASVS share-alike regime; that distinction is the point of G-092.
    assert "ShareAlike" not in ATTACK_LICENSE


# ===========================================================================
# Catalogue integrity
# ===========================================================================

def test_every_technique_id_is_well_formed():
    bad = [k for k in ATTACK_TECHNIQUES
           if not re.fullmatch(r"T\d{4}(?:\.\d{3})?", k)]
    assert bad == [], bad


def test_every_technique_has_a_name():
    for tid, spec in ATTACK_TECHNIQUES.items():
        assert spec["name"], tid


def test_subtechniques_are_flagged_and_carry_their_parent_prefix():
    subs = [k for k, v in ATTACK_TECHNIQUES.items() if v["is_subtechnique"]]
    assert subs, "expected sub-techniques in the Enterprise dataset"
    for s in subs:
        assert "." in s, s
        assert s.split(".")[0] in ATTACK_TECHNIQUES, s


def test_current_technique_list_excludes_revoked():
    revoked = set(ATTACK_REVOKED)
    assert not (revoked & set(ATTACK_CURRENT_TECHNIQUES))
    for tid in ATTACK_CURRENT_TECHNIQUES:
        assert not ATTACK_TECHNIQUES[tid]["revoked"], tid


# ===========================================================================
# THE DEFECT: no placeholder names
# ===========================================================================

def test_the_shipped_defect_technique_now_resolves_to_a_real_name():
    """T1595 is the identifier that shipped carrying the placeholder."""
    t = technique("T1595")
    assert t is not None
    assert t["name"] == "Active Scanning"
    assert technique_label("T1595") == "T1595 Active Scanning"
    assert technique_status("T1595") == "CURRENT"


def test_an_unknown_identifier_resolves_to_none_not_a_name():
    """NEGATIVE and load-bearing: an unknown id must stay unknown."""
    assert technique("T9999") is None
    assert technique("") is None
    assert technique(None) is None
    assert technique_label("T9999") == "T9999"
    assert technique_status("T9999") == "UNRESOLVED"


def test_the_placeholder_string_exists_in_no_production_source():
    """NEGATIVE: the fallback must be gone from the code, not merely unused.

    Scoped with the same `production_sources()` the conformance probe uses, so
    this test and `attack_no_placeholder_names` cannot drift apart. An earlier
    version scanned all of ROOT and failed on
    analysis/benchmark_attack_coverage.py, which legitimately contains the
    literal as a DETECTION string -- it counts occurrences of the placeholder to
    measure whether the defect is present. Tooling that hunts for a string is not
    the string being used.
    """
    from core.conformance_baseline import production_sources

    offenders = [rel for rel, text in production_sources(ROOT).items()
                 if PLACEHOLDER in text]
    assert not offenders, f"placeholder reintroduced in production source: {offenders}"


def test_mitre_attack_probes_have_matching_production_sources():
    """Every code probe must match; every `absent` probe must NOT match.

    Both directions matter. A `code` probe that matches nothing would make its
    standard unverifiable, and an `absent` probe that matches something would be
    passing vacuously -- which is how a negative guard silently stops guarding.
    """
    from analysis.benchmark_conformance_baseline import STANDARD_BASELINE
    from core.conformance_baseline import production_sources

    sources = production_sources(REPO)
    std = next(s for s in STANDARD_BASELINE if s["key"] == "MITRE_ATTACK")
    for probe in std["probes"]:
        if probe["kind"] == "artifact":
            continue
        hits = [rel for rel, text in sources.items() if re.search(probe["pattern"], text)]
        if probe["kind"] == "absent":
            assert not hits, (
                f"negative probe {probe['name']} matches {hits}, so it is "
                "passing vacuously")
        else:
            assert hits, f"probe {probe['name']} matches no production source"


def test_build_mitre_summary_never_emits_a_placeholder():
    out = _build_mitre_summary([{"mitre": "T1595"}, {"mitre": "T9999"}])
    for entry in out:
        assert PLACEHOLDER not in entry["description"]
    by_id = {e["id"]: e for e in out}
    assert by_id["T1595"]["description"] == "Active Scanning"
    assert by_id["T9999"]["description"] == ""
    assert by_id["T9999"]["status"] == "UNRESOLVED"


def test_unresolved_reason_explains_why_no_name_is_asserted():
    low = ATTACK_UNRESOLVED_REASON.lower()
    assert "not present" in low
    assert "no name is substituted" in low or "never invents" in low


# ===========================================================================
# Behaviour
# ===========================================================================

def test_mitre_summary_deduplicates_but_keeps_every_distinct_id():
    out = _build_mitre_summary([
        {"mitre": "T1595"}, {"mitre": "T1595"}, {"mitre": ["T1190"]},
        {"mitre": "t1059"},
    ])
    ids = [e["id"] for e in out]
    assert ids == ["T1595", "T1190", "T1059"], ids


def test_mitre_summary_skips_placeholder_and_empty_values():
    out = _build_mitre_summary([
        {"mitre": ""}, {"mitre": None}, {"mitre": "N/A"},
        {"mitre": "Not Applicable"}, {"mitre": "T1595"},
    ])
    assert [e["id"] for e in out] == ["T1595"]


def test_revoked_techniques_are_flagged_not_dropped():
    """NEGATIVE: dropping a revoked technique would hide that the report relies
    on something MITRE has retired."""
    assert ATTACK_REVOKED, "expected revoked techniques in the dataset"
    tid = ATTACK_REVOKED[0]
    assert technique_status(tid) == "REVOKED"
    out = attack_summary([tid])
    assert out[0]["id"] == tid
    assert out[0]["revoked"] is True


def test_tactics_are_reported_per_technique():
    assert tactics_for("T1190") == ["Initial Access"]
    assert tactics_for("T9999") == []
    out = {e["id"]: e for e in attack_summary(["T1190", "T1059"])}
    assert out["T1190"]["tactics"] == ["Initial Access"]
    assert out["T1059"]["tactics"] == ["Execution"]


def test_attack_summary_is_idempotent_and_order_preserving():
    ids = ["T1190", "T1595", "T1059"]
    first = [e["id"] for e in attack_summary(ids)]
    second = [e["id"] for e in attack_summary(ids + ids)]
    assert first == second == ids


def test_attack_summary_handles_empty_input():
    assert attack_summary([]) == []
    assert attack_summary(None) == []
    assert attack_summary(["", None, "N/A"]) == []


def test_technique_url_is_carried_for_attribution():
    t = technique("T1595")
    assert t["url"].startswith("https://attack.mitre.org/")


# ===========================================================================
# Conformance wiring
# ===========================================================================

def test_mitre_attack_probes_have_matching_production_sources():
    """Every code probe must match; every `absent` probe must NOT match.

    Both directions matter. A `code` probe that matches nothing would leave its
    standard unverifiable, and an `absent` probe that DOES match something would
    be passing vacuously -- which is how a negative guard silently stops
    guarding.
    """
    from analysis.benchmark_conformance_baseline import STANDARD_BASELINE
    from core.conformance_baseline import production_sources

    sources = production_sources(ROOT)
    std = next(s for s in STANDARD_BASELINE if s["key"] == "MITRE_ATTACK")
    for probe in std["probes"]:
        if probe["kind"] == "artifact":
            continue
        hits = [rel for rel, text in sources.items()
                if re.search(probe["pattern"], text)]
        if probe["kind"] == "absent":
            assert not hits, (
                f"negative probe {probe['name']} matches {hits}, so it is "
                "passing vacuously")
        else:
            assert hits, f"probe {probe['name']} matches no production source"


def test_the_negative_probe_is_declared_as_an_absent_probe():
    """The guard only works if it is declared 'absent'. A 'code' probe matching
    the placeholder would PASS when the defect is present -- exactly backwards."""
    from analysis.benchmark_conformance_baseline import STANDARD_BASELINE

    std = next(s for s in STANDARD_BASELINE if s["key"] == "MITRE_ATTACK")
    probe = next(p for p in std["probes"] if p["name"] == "attack_no_placeholder_names")
    assert probe["kind"] == "absent", probe["kind"]


def test_analyzer_no_longer_carries_a_hardcoded_technique_table():
    """The 11-entry dict is what made the placeholder reachable at all."""
    src = (ROOT / "core" / "analyzer.py").read_text(encoding="utf-8")
    body = src.split("def _build_mitre_summary", 1)[1].split("\ndef ", 1)[0]
    assert '"T1190": "Exploit Public-Facing Application"' not in body
    assert "descriptions = {" not in body