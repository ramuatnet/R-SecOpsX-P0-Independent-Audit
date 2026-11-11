# -*- coding: utf-8 -*-
"""taskf.md Phase 2 -- the value vocabulary (T-2.1).

Why these tests exist: DEF-B's root cause is three indistinguishable
missing-value states.  This file pins the ONE formatter's contract: the
state/reason vocabulary, the resolution ladder (provenance first, then
value, then reason, then the advisory branch, then ABSENT), the exact
reader-facing wording of every reason, and the invariant that no code path
can ever print a bare unknown word (ground rule 5).

Refuses to do: touch a renderer.  The literal ban is
tests/test_no_renderer_literal_defaults.py; this file is pure vocabulary.
"""
from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from core import value_state  # noqa: E402
from core.value_state import (  # noqa: E402
    ABSENT,
    MANIFEST_RANGE,
    NO_ADVISORY,
    NOT_APPLICABLE,
    NOT_PUBLISHED,
    UNKNOWN,
    VALUE,
    cell,
    render,
    resolve,
)


# ---------------------------------------------------------- vocabulary ----
def test_states_and_reasons_match_taskf_spelling():
    """T-2.1 names the vocabulary exactly; a rename silently breaks provenance."""
    assert {ABSENT, NOT_APPLICABLE, UNKNOWN, VALUE} == {
        "ABSENT", "NOT_APPLICABLE", "UNKNOWN", "VALUE"}
    assert set(value_state.REASON_TEXT) == {
        "MANIFEST_RANGE", "LOCAL_REFERENCE", "NO_LOCKFILE",
        "TRANSITIVE_GUESS", "PROPERTY_UNRESOLVED", "NO_ADVISORY",
        "NOT_PUBLISHED",
        # R1/W2 (GAP-14): per-field provenance reasons for purl, cvss,
        # dependency_type (gate evidence basis) and parent.
        "PURL_DERIVED", "PURL_UNRESOLVABLE", "OFFLINE_CVSS_TABLE",
        "GATE_MANIFEST_DIRECT", "GATE_NAMED_PARENT", "GATE_PATH_HEAD",
        "GATE_LOCKFILE_MEMBERSHIP", "GATE_VERIFIED_TRANSITIVE",
        "GATE_NO_EVIDENCE",
        "VERIFIED_PARENT_EDGE", "PARENT_AMBIGUOUS_MULTIPLE_VERSIONS",
        "PARENT_AMBIGUOUS_MULTIPLE_PARENTS", "PARENT_ROOT_DECLARED",
    }
    # T-0.3 pins this sentence verbatim.
    assert value_state.REASON_TEXT[MANIFEST_RANGE] == \
        "manifest declares a range, no lockfile pin"
    assert value_state.REASON_TEXT[NOT_PUBLISHED] == "not published"


# --------------------------------------------------------------- ladder ----
def test_advisory_field_without_advisory_dashes_even_with_a_seeded_value():
    """Producer seeds severity/age on EVERY package; no advisory voids them."""
    pkg = {"name": "gradio", "severity": "Unknown",
           "vulnerability_age": "Not applicable"}
    state, reason, _ = resolve(pkg, "severity", has_advisory=False)
    assert (state, reason) == (UNKNOWN, NO_ADVISORY)
    assert cell(pkg, "severity", has_advisory=False) == "--"
    assert cell(pkg, "vulnerability_age", has_advisory=False) == "--"


def test_advisory_field_with_advisory_and_no_value_names_the_gap():
    pkg = {"name": "colorama", "vulnerabilities": [{"id": "GHSA-x"}]}
    state, reason, _ = resolve(pkg, "severity", has_advisory=True)
    assert (state, reason) == (UNKNOWN, NOT_PUBLISHED)
    assert cell(pkg, "severity", has_advisory=True) == \
        "unknown (not published)"
    # The seeded placeholder word is never what prints.
    assert cell({"severity": "Unknown", "cve": "CVE-1"},
                "severity", has_advisory=True) == "unknown (not published)"


def test_advisory_field_with_real_value_prints_the_value():
    pkg = {"severity": "High", "cve": "CVE-2018-1000656"}
    assert cell(pkg, "severity", has_advisory=True) == "High"


def test_non_advisory_placeholder_without_provenance_is_absent():
    """license/version placeholders: no advisory ladder, so ABSENT -> --."""
    assert cell({"license": "unknown"}, "license", has_advisory=False) == "--"
    state, reason, _ = resolve({"version": "unknown"}, "version")
    assert (state, reason) == (ABSENT, None)


def test_provenance_state_trumps_the_ladder():
    pkg = {
        "version": "unknown",
        "field_provenance": {
            "version": {"state": "UNKNOWN", "reason": "MANIFEST_RANGE"},
        },
    }
    state, reason, _ = resolve(pkg, "version")
    assert (state, reason) == (UNKNOWN, MANIFEST_RANGE)
    assert cell(pkg, "version") == \
        "unknown (manifest declares a range, no lockfile pin)"

    # A provenance VALUE with a real field prints the value.
    pkg2 = {"version": "1.2.3",
            "field_provenance": {"version": {"state": "VALUE"}}}
    assert cell(pkg2, "version") == "1.2.3"

    # A provenance VALUE whose field is only a placeholder falls through
    # to the ladder instead of printing a phantom.
    pkg3 = {"version": "unknown",
            "field_provenance": {"version": {"state": "VALUE"}}}
    state3, reason3, _ = resolve(pkg3, "version")
    assert (state3, reason3) == (ABSENT, None)

    # Provenance NOT_APPLICABLE dashes without consulting the value.
    pkg4 = {"version": "9.9.9",
            "field_provenance": {"version": {"state": "NOT_APPLICABLE"}}}
    assert cell(pkg4, "version") == "--"


def test_provenance_reason_without_state_names_the_gap():
    pkg = {
        "version": "unknown",
        "field_provenance": {"version": {"reason": "TRANSITIVE_GUESS"}},
    }
    assert cell(pkg, "version") == "unknown (transitive guess)"


def test_alias_chains_skip_placeholders():
    """A seeded 'unknown' in the primary key must not mask a real value."""
    pkg = {"severity": "unknown", "highest_vulnerability_severity": "High",
           "cve": "CVE-1"}
    assert cell(pkg, "severity", has_advisory=True) == "High"
    # ...and the chain still resolves when only the secondary key exists.
    assert cell({"highest_vulnerability_severity": "Low", "cve": "CVE-1"},
                "severity", has_advisory=True) == "Low"


def test_placeholders_include_the_producers_synthesized_sentence():
    pkg = {"fixed_versions": [
        "No fixed version identified in current advisory dataset."],
        "cve": "CVE-1"}
    state, reason, _ = resolve(pkg, "fixed_versions", has_advisory=True)
    assert (state, reason) == (UNKNOWN, NOT_PUBLISHED)
    # Never the sentence itself, in any casing.
    assert "No fixed version identified" not in cell(
        pkg, "fixed_versions", has_advisory=True)


# --------------------------------------------------------------- render ----
def test_render_rules_are_total_and_never_bare():
    assert render(ABSENT, None, None) == "--"
    assert render(NOT_APPLICABLE, None, None) == "--"
    assert render(UNKNOWN, NO_ADVISORY, None) == "--"
    # UNKNOWN without a reason must not print the bare word.
    assert render(UNKNOWN, None, None) == "--"
    assert render(UNKNOWN, MANIFEST_RANGE, None) == \
        "unknown (manifest declares a range, no lockfile pin)"
    assert render(VALUE, None, "MIT") == "MIT"
    assert render(VALUE, None, ["1.0.2", "1.0.3"]) == "1.0.2, 1.0.3"


def test_no_state_reason_combination_prints_a_bare_unknown_word():
    """Ground rule 5: only ``--`` or ``unknown (reason)`` may come out."""
    reasons = [None, *value_state.REASON_TEXT]
    for state in (ABSENT, NOT_APPLICABLE, UNKNOWN, VALUE):
        for reason in reasons:
            out = render(state, reason, "1.2.3")
            assert out not in {"Unknown", "UNKNOWN", "unknown", "Review"}, (
                f"render({state!r}, {reason!r}, ...) printed {out!r}")


def test_cell_tolerates_non_dict_records():
    assert cell(None, "version") == "--"
    assert cell("not-a-dict", "severity") == "--"


def test_quantum_status_unknown_is_a_classifier_answer_not_a_placeholder():
    """CBOM's classifier emits UNKNOWN as a real enum value (its prose says so)."""
    assert cell({"quantum_status": "UNKNOWN"}, "quantum_status") == "UNKNOWN"
    assert cell({"quantum_status": "PQC"}, "quantum_status") == "PQC"
    # A missing field still dashes -- only a PRESENT value prints.
    assert cell({}, "quantum_status") == "--"


def test_lists_drop_placeholder_elements_before_joining():
    assert cell({"fixed_versions": ["1.0.2", "unknown", "1.0.3"],
                 "cve": "CVE-1"},
                "fixed_versions", has_advisory=True) == "1.0.2, 1.0.3"
    # An all-placeholder list is a gap, not a value.
    assert cell({"fixed_versions": ["unknown", "--"], "cve": "CVE-1"},
                "fixed_versions", has_advisory=True) == "unknown (not published)"
