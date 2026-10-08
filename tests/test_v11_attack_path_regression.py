"""Regression guard for the attack-path correlation regression.

`core/attack_graph.py::get_attack_paths` used to wrap a STRING `taint_path` in a
single-element list, so `len(nodes) >= 2` was never satisfied and every attack
path was dropped. Because `taint_path` is emitted as a string ("body -> fetch("),
the net effect was that attack-path correlation reported zero paths on the entire
16-project prodtest corpus while the 2026-09-23 report on the same corpus
reported 4.

The tests below pin both directions that matter: a real arrow-separated chain is
now a path, and anything that is NOT a chain still does not become one. The
second half is what stops the fix from manufacturing attack paths.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core.attack_graph import get_attack_paths  # noqa: E402

ARROW = " -> "
ARTIFACTS = Path(r"C:\Users\janan\AppData\Local\Temp\opencode\artifact_1914_snapshot\clean_report.json")
PRODTEST = Path(r"D:\Data\Code test\prodtest\reports")


# ===========================================================================
# The regression itself
# ===========================================================================

def test_string_taint_path_yields_a_path():
    """The emitted representation is a string; it must resolve."""
    out = get_attack_paths([{"taint_path": "body -> fetch(", "rule_id": "X"}])
    assert len(out) == 1, out
    assert out[0]["path"] == ["body", "fetch("]
    assert out[0]["source"] == "body"
    assert out[0]["sink"] == "fetch("


def test_multi_hop_string_chain_is_split_into_all_nodes():
    out = get_attack_paths([{"taint_path": "req -> parse -> exec(", "rule_id": "X"}])
    assert out[0]["path"] == ["req", "parse", "exec("]
    assert out[0]["source"] == "req"
    assert out[0]["sink"] == "exec("


def test_list_form_still_works_and_is_not_double_split():
    """The list form was always handled; the fix must not break it."""
    out = get_attack_paths([{"taint_path": ["body", "fetch("], "rule_id": "X"}])
    assert out[0]["path"] == ["body", "fetch("]


def test_arrow_segments_are_trimmed():
    """ASVS's D1 fix was the same class of defect: rendering/parsing must not
    depend on incidental whitespace."""
    out = get_attack_paths([{"taint_path": "  body   ->   fetch(  ", "rule_id": "X"}])
    assert out[0]["path"] == ["body", "fetch("]


# ===========================================================================
# NEGATIVE: the fix must not invent attack paths
# ===========================================================================

def test_bare_expression_with_no_arrow_is_not_a_path():
    """NEGATIVE and load-bearing: no arrow means no observed chain."""
    out = get_attack_paths([{"taint_path": "justAnExpression", "rule_id": "X"}])
    assert out == [], out


def test_empty_or_arrow_only_paths_are_dropped():
    for bad in ("", "   ", "->", " -> ", "a -> ", " -> b", "a ->  -> b"):
        out = get_attack_paths([{"taint_path": bad, "rule_id": "X"}])
        assert out == [], f"{bad!r} produced {out}"


def test_other_punctuation_is_not_treated_as_a_chain():
    """NEGATIVE: splitting on some other separator would fabricate paths that
    were never observed."""
    for bad in ("body,fetch(", "body|fetch(", "body>fetch(", "body/fetch("):
        out = get_attack_paths([{"taint_path": bad, "rule_id": "X"}])
        assert out == [], f"{bad!r} produced {out}"


def test_no_taint_and_no_source_sink_is_not_a_path():
    assert get_attack_paths([{"rule_id": "X"}]) == []
    assert get_attack_paths([{"rule_id": "X", "source": "req"}]) == []
    assert get_attack_paths([{"rule_id": "X", "sink": "exec("}]) == []


def test_source_and_sink_fields_still_produce_a_candidate_path():
    """The pre-existing source/sink branch is untouched by the fix."""
    out = get_attack_paths([{"rule_id": "X", "source": "req", "sink": "find("}])
    assert len(out) == 1
    assert out[0]["source"] == "req" and out[0]["sink"] == "find("


def test_empty_findings_list_is_handled():
    assert get_attack_paths([]) == []


def test_non_dict_entries_are_skipped():
    out = get_attack_paths([None, "junk", 42, {"taint_path": "a -> b", "rule_id": "X"}])
    assert len(out) == 1


# ===========================================================================
# Status semantics must not be loosened by the fix
# ===========================================================================

def test_evidence_valid_true_marks_the_path_confirmed():
    out = get_attack_paths([{"taint_path": "body -> fetch(", "evidence_valid": True}])
    assert out[0]["attack_path_status"] == "confirmed"


def test_missing_evidence_valid_leaves_the_path_a_candidate():
    """NEGATIVE: resolving the path must not upgrade its confidence. A candidate
    stays a candidate, because the string fix says nothing about reachability."""
    for f in ({"taint_path": "body -> fetch("},
              {"taint_path": "body -> fetch(", "evidence_valid": None},
              {"taint_path": "body -> fetch(", "evidence_valid": False}):
        out = get_attack_paths([f])
        assert out[0]["attack_path_status"] == "candidate", f


# ===========================================================================
# Corpus-level: the regression was measurable, so the fix must be measurable
# ===========================================================================

@pytest.mark.skipif(not ARTIFACTS.exists(), reason="artifact snapshot not present")
def test_artifact_findings_with_taint_paths_now_yield_paths():
    """NEGATIVE, corpus-level: this is the assertion that failed silently.

    The shipped artifact carries 12 findings whose taint_path is a string. Before
    the fix these produced ZERO attack paths. If any future change reintroduces the
    single-element wrap, this test fails on the count rather than the metric
    quietly dropping to zero in a report nobody reads.
    """
    rep = json.loads(ARTIFACTS.read_text(encoding="utf-8", errors="replace"))
    findings = rep.get("findings") or []

    with_taint = [f for f in findings if isinstance(f, dict) and f.get("taint_path")]
    assert with_taint, "fixture should carry string taint paths"

    paths = get_attack_paths(findings)
    assert paths, (
        f"{len(with_taint)} findings carry taint_path but the resolver produced no "
        "paths -- this is the attack-path regression")

    for p in paths:
        assert len(p["path"]) >= 2, p
        assert ARROW.strip() not in p["path"][0], (
            f"an unsplit chain leaked into a path node: {p}")


@pytest.mark.skipif(not ARTIFACTS.exists(), reason="artifact snapshot not present")
def test_resolved_paths_never_exceed_the_findings_carrying_evidence():
    """Guards against the fix inflating the path count."""
    rep = json.loads(ARTIFACTS.read_text(encoding="utf-8", errors="replace"))
    findings = rep.get("findings") or []
    eligible = sum(1 for f in findings
                   if isinstance(f, dict) and (
                       f.get("taint_path") or (f.get("source") and f.get("sink"))))
    assert len(get_attack_paths(findings)) <= eligible


def test_the_pdf_renderer_and_the_resolver_agree_on_the_string_form():
    """Why the regression survived review: two ends of the pipeline disagreed.

    `reporting/pdf_report.py` detects a taint-validated finding by testing for the
    arrow in the string form. If that ever changes, this test flags that the two
    representations have drifted again.
    """
    src = (ROOT / "reporting" / "pdf_report.py").read_text(encoding="utf-8")
    assert "->" in src and "taint_path" in src
    # And the resolver must still accept what the renderer treats as taint.
    assert get_attack_paths([{"taint_path": "a -> b"}])