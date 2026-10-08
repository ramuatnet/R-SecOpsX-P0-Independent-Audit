"""Tests for attack-path PUBLICATION across all renderers.

The defect these exist to prevent is specific and was live:

    The technical PDF rendered all 8 of babyagi-main's paths as
        Chain #01  MEDIUM  Risk: 0
        Chain:
        (empty)
        PATTERN-ONLY - Candidate attack path. Manual validation is required
    while the artifact held all 8 as `attack_path_status: confirmed` with real
    source-to-sink nodes. The executive PDF had no attack-path content at all,
    and the workbook's Entry Point / Impact cells were blank.

Three wrongnesses, one cause: the renderers read the LEGACY record shape that
core/attack_graph.py stopped emitting and formatted the defaults for the rest.

The most serious was the label. Calling eight taint-confirmed paths
"PATTERN-ONLY ... Manual validation is required" UNDERSTATES validated evidence
and tells the reader to redo finished work. Understating evidence is as much a
false statement as overstating it, so the label direction is asserted, not just
its presence.
"""
from __future__ import annotations

import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from reporting.attack_path_view import (  # noqa: E402
    CANDIDATE,
    CONFIRMED,
    SHAPE_CURRENT,
    SHAPE_LEGACY,
    attack_path_view,
    attack_path_views,
    evidence_label,
    introduction,
    shape_mix,
)

# A record in the CURRENT shape, as core/attack_graph.py emits it.
#
# No braces around the route parameter. The producer used to emit
# "route parameter {function_name}" -- `name` is already the identifier, so the
# braces made a rendered narrative read as an unfilled template placeholder. That
# was corrected in scanner/taint_engine.py, and this fixture is updated to match
# what the producer actually emits, so `chain == path` remains a true invariant
# here. The pre-fix form is covered separately by
# test_legacy_route_parameter_braces_are_stripped_for_display.
CURRENT = {
    "path": ["route parameter function_name", "function_name",
             "g.functionz.executor.execute"],
    "source": "route parameter function_name",
    "sink": "g.functionz.executor.execute",
    "finding_id": "abc-123",
    "rule_id": "TAINT_SQL_INJECTION",
    "attack_path_status": "confirmed",
    "evidence_valid": True,
}
# The pre-fix brace form, which persists in artifacts already on disk.
BRACED_CURRENT = {
    "path": ["route parameter {function_name}", "function_name",
             "g.functionz.executor.execute"],
    "source": "route parameter {function_name}",
    "sink": "g.functionz.executor.execute",
    "attack_path_status": "confirmed",
    "evidence_valid": True,
}
# A record in the LEGACY shape, still present in three corpus artifacts.
LEGACY = {
    "title": "Attack Path: Credential Exposure",
    "severity": "High",
    "risk_score": 50.5,
    "evidence_type": "taint-confirmed",
    "evidence_note": "Data flow confirmed by AST taint analysis.",
    "steps": ["Source Code / VCS", "Credential Exposure", "Authenticated Service"],
    "chains_to": ["Escalated Privileges"],
}


# ===========================================================================
# Both shapes must resolve, because both exist in the corpus
# ===========================================================================

def test_current_shape_chain_is_read():
    v = attack_path_view(CURRENT)
    assert v["shape"] == SHAPE_CURRENT
    assert v["chain"] == CURRENT["path"]
    assert v["source"] == CURRENT["source"]
    assert v["sink"] == CURRENT["sink"]


def test_legacy_route_parameter_braces_are_stripped_for_display():
    """Artifacts written before the producer fix must still read as code.

    Three corpus report directories hold records in the brace form. A placeholder
    inside a CONFIRMED evidence chain is worse than cosmetic: it implies the
    scanner never identified the source, which is the opposite of what the record
    asserts.
    """
    v = attack_path_view(BRACED_CURRENT)

    assert v["chain"][0] == "route parameter function_name"
    assert v["source"] == "route parameter function_name"
    assert "{" not in " ".join(v["chain"])
    # The non-placeholder nodes must be untouched.
    assert v["chain"][1] == "function_name"
    assert v["chain"][2] == "g.functionz.executor.execute"
    assert v["sink"] == "g.functionz.executor.execute"


def test_brace_stripping_does_not_mutate_the_input_record():
    """The view normalises a copy. A renderer must not rewrite the artifact."""
    original = dict(BRACED_CURRENT)
    original["path"] = list(BRACED_CURRENT["path"])

    attack_path_view(BRACED_CURRENT)

    assert BRACED_CURRENT["path"] == original["path"]
    assert BRACED_CURRENT["source"] == original["source"]


def test_legacy_shape_chain_is_read():
    v = attack_path_view(LEGACY)
    assert v["shape"] == SHAPE_LEGACY
    assert v["chain"] == LEGACY["steps"]
    assert v["risk_score"] == 50.5


def test_shape_mix_is_reported_not_guessed():
    mix = shape_mix(attack_path_views([CURRENT, CURRENT, LEGACY]))
    assert mix["total"] == 3
    assert mix["by_shape"][SHAPE_CURRENT] == 2
    assert mix["by_shape"][SHAPE_LEGACY] == 1
    # Legacy one is taint-confirmed too, so all three are confirmed.
    assert mix["confirmed"] == 3


def test_absent_risk_score_stays_none_and_is_not_zeroed():
    """NEGATIVE and load-bearing.

    `ap.get('risk_score', 0)` is how "Risk: 0" reached a report: a formatted
    default that reads like a measurement. Absent must stay absent.
    """
    v = attack_path_view(CURRENT)
    assert v["risk_score"] is None, v["risk_score"]
    assert mix_risk_none(attack_path_views([CURRENT])) is True


def mix_risk_none(views):
    return all(v["risk_score"] is None for v in views)


# ===========================================================================
# THE LABEL. Understating is as bad as overstating.
# ===========================================================================

def test_confirmed_current_record_is_never_labelled_pattern_only():
    """The regression, stated as an assertion.

    A current-shape record with `attack_path_status: confirmed` and NO
    `evidence_type` at all is the exact case the renderer got wrong: it read a
    defaulted `evidence_type` and produced PATTERN-ONLY.
    """
    v = attack_path_view(CURRENT)
    assert "evidence_type" not in CURRENT, "fixture must not carry the legacy field"
    assert v["status"] == CONFIRMED
    assert v["confirmed"] is True
    label = evidence_label(v)
    assert "CONFIRMED" in label
    assert "PATTERN-ONLY" not in label
    assert "Manual validation" not in label


def test_evidence_valid_true_alone_is_enough_to_confirm():
    v = attack_path_view({"path": ["a", "b"], "evidence_valid": True})
    assert v["status"] == CONFIRMED


def test_missing_evidence_state_is_not_guessed():
    """NEGATIVE: silence is neither confirmation nor a candidate claim."""
    v = attack_path_view({"path": ["a", "b"]})
    assert v["status"] is None
    assert v["confirmed"] is False
    label = evidence_label(v)
    assert "STATUS NOT RECORDED" in label
    assert "neither confirmed nor asserted" in label


def test_legacy_pattern_detected_is_still_a_candidate():
    v = attack_path_view({**LEGACY, "evidence_type": "pattern-detected"})
    assert v["status"] == CANDIDATE
    assert "PATTERN-ONLY" in evidence_label(v)


# ===========================================================================
# The lead paragraph must not assert a status the data does not support
# ===========================================================================

def test_introduction_reflects_the_confirmed_count():
    intro = introduction(attack_path_views([CURRENT, CURRENT]))
    assert "All 2 carry validated source-to-sink evidence" in intro
    assert "Manual validation is required" not in intro


def test_introduction_separates_confirmed_from_candidate():
    intro = introduction(attack_path_views(
        [CURRENT, {**LEGACY, "evidence_type": "pattern-detected"}]))
    assert "1 carry validated source-to-sink evidence and are CONFIRMED" in intro
    assert "1 are pattern-level candidates requiring manual validation" in intro


def test_introduction_flags_records_with_no_state():
    intro = introduction(attack_path_views([{"path": ["a", "b"]}]))
    assert "no recorded evidence state" in intro


def test_introduction_of_nothing_is_empty():
    assert introduction([]) == ""


# ===========================================================================
# No invention
# ===========================================================================

def test_salvage_uses_observed_endpoints_only():
    """A record with source/sink but no `path` still has TWO OBSERVED nodes.

    Joining them is a presentation of what was recorded, not an inferred
    intermediate edge: no hop between them is asserted.
    """
    v = attack_path_view({"source": "req", "sink": "exec(",
                          "attack_path_status": "candidate"})
    assert v["chain"] == ["req", "exec("]


def test_empty_record_yields_no_chain_and_no_status():
    v = attack_path_view({})
    assert v["chain"] == []
    assert v["status"] is None
    assert v["risk_score"] is None


def test_non_dict_is_tolerated():
    for bad in (None, "x", 42, []):
        v = attack_path_view(bad)
        assert v["chain"] == [] and v["status"] is None


def test_title_falls_back_to_the_rule_id():
    assert "TAINT_SQL_INJECTION" in attack_path_view(CURRENT)["title"]
    assert attack_path_view({})["title"] == "Attack Path"


# ===========================================================================
# The renderers must go through the view
# ===========================================================================

@pytest.mark.parametrize("rel", [
    "reporting/pdf_report.py",
    "reporting/excel_report.py",
    "reporting/executive_pdf_report.py",
])
def test_renderer_uses_the_shared_view(rel):
    src = (ROOT / rel).read_text(encoding="utf-8")
    assert "attack_path_view" in src, f"{rel} does not import the shared view"


@pytest.mark.parametrize("rel,forbidden", [
    ("reporting/pdf_report.py", 'ap.get("evidence_type", "pattern-detected")'),
    ("reporting/excel_report.py", 'ap.get("evidence_type") or "pattern-detected"'),
    ("reporting/pdf_report.py", 'ap.get("steps",[])'),
    ("reporting/excel_report.py", 'ap.get("steps", [])'),
])
def test_renderer_no_longer_reads_the_legacy_fields_directly(rel, forbidden):
    src = (ROOT / rel).read_text(encoding="utf-8")
    assert forbidden not in src, (
        f"{rel} still reads a legacy attack-path field directly, which is how the "
        f"empty chains and mislabels appeared")


def test_executive_report_has_attack_path_content():
    """It previously had none at all, so the section must exist."""
    src = (ROOT / "reporting" / "executive_pdf_report.py").read_text(encoding="utf-8")
    assert "def _executive_attack_path_summary" in src
    assert "_executive_attack_path_summary(payload)" in src


def test_executive_section_states_absence_honestly():
    src = (ROOT / "reporting" / "executive_pdf_report.py").read_text(encoding="utf-8")
    assert "NOT a statement that the application has no" in src, (
        "an empty exploit-chain section must not read as an all-clear")


def test_executive_section_does_not_claim_live_exploitability():
    src = (ROOT / "reporting" / "executive_pdf_report.py").read_text(encoding="utf-8")
    assert "does not assert that the chain is" in src