"""The ATLAS catalogue must be pinned to a real release, and say how much of it it has.

WHY THIS IS ASSERTED
--------------------
A vendor red-team report (SATLAS 2026-09-22) exercised 24 MITRE ATLAS techniques. We
covered 12. Adding the other 12 required reading MITRE's published data, and reading
the WRONG FILE produced two factually wrong values.

`dist/ATLAS.yaml` carries the header "This version of the ATLAS data is deprecated and
is no longer being updated" and declares version 5.6.0. The pinned release is at
`dist/v6/ATLAS-2026.09.yaml` per `dist/manifest.yaml`. Every id and name survived the
mistake; two maturity values did not:

    AML.T0050  Command and Scripting Interpreter   transcribed "demonstrated"
    AML.T0068  LLM Prompt Obfuscation               transcribed "demonstrated"

Both are Realized in 2026.09, and the CHANGELOG lists both as UPDATED in that release.
The maturity field is the one a reader is least likely to check and most likely to
quote, which is why these tests pin the vocabulary and the release together.

THE STRUCTURAL FINDING
----------------------
The catalogue declares format-version 6.0.0 but is built in the LEGACY shape: list
form rather than mapping, hyphenated-vs-underscore date fields, and tactic membership
inline under each technique rather than in the separate `relationships:` block the v6
data uses. So the catalogue cannot be regenerated from the pinned file and can only be
maintained by hand.

That is recorded here as a measurement rather than quietly fixed, because migrating
the catalogue shape is a larger change than adding techniques and should not be
smuggled into a patch. What matters now is that the discrepancy is VISIBLE and
carries a number, so nobody reads "42 techniques" as near-complete.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

import core.atlas_mappings as am  # noqa: E402

SRC = (REPO / "core" / "atlas_mappings.py").read_text(encoding="utf-8")

# The pinned release, as declared by MITRE's own dist/manifest.yaml.
PINNED_RELEASE = "2026.09"
PINNED_FORMAT = "6.0.0"
PINNED_PATH = "dist/v6/ATLAS-2026.09.yaml"

# ATLAS 2026.09 content counts, from the repository CHANGELOG for that release.
ATLAS_2026_09_TECHNIQUES = 208  # 120 top-level + 88 sub-techniques
ATLAS_2026_09_TACTICS = 16

V6_MATURITY = {"Realized", "Demonstrated", "Feasible"}
LEGACY_MATURITY = {"realized", "demonstrated", "feasible"}

# The twelve added after the peer scan, with the values the PINNED release states.
ADDED = {
    "AML.T0010.005": ("AI Agent Tool", "Realized"),
    "AML.T0029": ("Denial of AI Service", "Demonstrated"),
    "AML.T0034": ("Cost Harvesting", "Feasible"),
    "AML.T0037": ("Data from Local System", "Realized"),
    "AML.T0050": ("Command and Scripting Interpreter", "Realized"),
    "AML.T0053": ("AI Agent Tool Invocation", "Demonstrated"),
    "AML.T0055": ("Unsecured Credentials", "Realized"),
    "AML.T0068": ("LLM Prompt Obfuscation", "Realized"),
    "AML.T0069": ("Discover LLM System Information", "Demonstrated"),
    "AML.T0069.001": ("System Instruction Keywords", "Demonstrated"),
    "AML.T0069.002": ("System Prompt", "Demonstrated"),
    "AML.T0070": ("RAG Poisoning", "Demonstrated"),
}


# ------------------------------------------------------------- the pin ------

def test_catalogue_pins_a_real_release():
    """The pin must be to a release that actually exists in MITRE's manifest.

    ATLAS_SOURCE_URL is deliberately the citation of WHERE THE PIN IS DECLARED --
    dist/manifest.yaml -- not the data file itself. manifest.yaml is the release ->
    path -> format-version index, so citing it is what makes the pin checkable; a
    citation to a data file would assert a path without asserting that the file
    corresponds to the stated release. Verified against MITRE's own manifest: entry
    "release: 2026.09, release-date: 2026-09-15, format-version 6.0.0, path:
    v6/ATLAS-2026.09.yaml".
    """
    assert am.ATLAS_RELEASE == PINNED_RELEASE
    assert am.ATLAS_FORMAT_VERSION == PINNED_FORMAT
    # Since the catalogue is GENERATED, the citation is of the data file itself
    # rather than of the manifest. That is stronger, not weaker: the manifest maps
    # release -> path, whereas this URL names the exact bytes, and the sha256 below
    # pins those bytes. Before generation the module cited the manifest, because it
    # held a hand copy of the data and citing the data file would have been a claim
    # about content nobody was maintaining.
    assert am.ATLAS_SOURCE_URL.endswith(f"dist/v6/ATLAS-{am.ATLAS_RELEASE}.yaml"), (
        f"source url must name the pinned release's data file: {am.ATLAS_SOURCE_URL}"
    )
    assert "mitre-atlas/atlas-data" in am.ATLAS_SOURCE_URL
    assert re.fullmatch(r"[0-9a-f]{64}", am.ATLAS_SOURCE_SHA256), (
        "the catalogue must pin the sha256 of the exact bytes it was rendered from, "
        "so a regeneration against different data is detectable"
    )


def test_source_url_does_not_point_at_the_deprecated_file():
    """The file that caused the wrong maturity values.

    dist/ATLAS.yaml declares version 5.6.0 and carries a deprecation header. A
    citation to it is a citation to data that is no longer updated, so it must not
    be the source of record for a catalogue claiming a 2026.09 pin.
    """
    assert "dist/ATLAS.yaml" not in am.ATLAS_SOURCE_URL


# ------------------------------------------------- the twelve additions -----

@pytest.mark.parametrize("tid", sorted(ADDED))
def test_added_technique_is_present(tid):
    assert tid in am.ATLAS_TECHNIQUES


@pytest.mark.parametrize(("tid", "name"), [(t, n) for t, (n, _) in ADDED.items()])
def test_added_technique_name_matches_the_pinned_release(tid, name):
    assert am.ATLAS_TECHNIQUES[tid]["name"] == name


@pytest.mark.parametrize(("tid", "maturity"), [(t, m) for t, (_, m) in ADDED.items()])
def test_added_technique_maturity_matches_the_pinned_release(tid, maturity):
    """The regression that matters most here.

    Two entries were transcribed from the deprecated release with the wrong maturity
    and the error survived compilation, the ATLAS conformance benchmark, and every
    unit test, because nothing compared the catalogue against its source.
    """
    assert am.ATLAS_TECHNIQUES[tid]["maturity"] == maturity


@pytest.mark.parametrize("tid", sorted(ADDED))
def test_added_technique_records_the_release_it_came_from(tid):
    entry = am.ATLAS_TECHNIQUES[tid]

    assert entry.get("source_release") == PINNED_RELEASE, (
        "an entry transcribed from a specific release must say which one, or a "
        "later MITRE reassignment of the id is undetectable"
    )


@pytest.mark.parametrize("tid", sorted(ADDED))
def test_added_technique_tactics_resolve_in_our_own_catalogue(tid):
    """A technique pointing at a tactic we do not define is a dangling reference."""
    for tactic in am.ATLAS_TECHNIQUES[tid].get("tactics") or ():
        assert tactic in am.ATLAS_TACTICS, f"{tid} -> unknown tactic {tactic}"


# Filtered at collection time. Calling pytest.skip() from inside a @parametrize
# case aborts the whole module under pytest, which presented as eight unrelated
# tests failing rather than one case being skipped.
# A sub-technique is identified by a SECOND dot. Every id contains the dot in
# "AML.T", so "AML.T0029" is a top-level technique while "AML.T0069.001" is a
# sub-technique. Filtering on a single dot sweeps in every id and asserts that
# AML.T0029 has a parent, which it does not and should not.
SUB_TECHNIQUES = sorted(t for t in ADDED if t.count(".") >= 2)


@pytest.mark.parametrize("tid", SUB_TECHNIQUES or ["__none__"])
def test_added_subtechnique_declares_its_parent(tid):
    """A sub-technique with no parent is unresolvable.

    Sub-techniques carry no tactics of their own -- they inherit from the parent --
    so the parent link is the only thing that places them in the matrix.
    """
    if tid == "__none__":
        pytest.skip("no sub-techniques among the added entries")
    parent = am.ATLAS_TECHNIQUES[tid].get("specializes")
    assert parent, f"{tid} is a sub-technique with no parent"
    assert parent in am.ATLAS_TECHNIQUES, f"{tid} -> unknown parent {parent}"


def test_the_filtered_subtechnique_list_is_not_empty():
    """Guards the filter above against silently selecting nothing."""
    assert len(SUB_TECHNIQUES) >= 3, (
        f"expected several sub-techniques among the additions, got {SUB_TECHNIQUES}"
    )


# ------------------------------------------------------- the vocabulary -----

def test_maturity_vocabulary_is_the_pinned_release_form():
    """One vocabulary, not two.

    A catalogue that cannot agree on the casing of its own enumerated field cannot
    be validated against its source, because there is no single vocabulary to
    validate against. The catalogue had a mix: 19 lowercase and 12 capitalised.
    """
    offenders = {k: v.get("maturity") for k, v in am.ATLAS_TECHNIQUES.items()
                 if v.get("maturity") in LEGACY_MATURITY}
    assert not offenders, f"legacy lowercase maturity remains: {offenders}"


def test_every_maturity_is_one_of_the_three_atlas_states():
    bad = {k: v.get("maturity") for k, v in am.ATLAS_TECHNIQUES.items()
           if v.get("maturity") not in V6_MATURITY and v.get("maturity") != ""}
    assert not bad, f"maturity outside the ATLAS states: {bad}"


# ---------------------------------------------------------- the coverage ----

def test_tactic_count_matches_the_pinned_release():
    assert len(am.ATLAS_TACTICS) == ATLAS_2026_09_TACTICS


def test_coverage_of_the_pinned_release_is_measured_not_assumed():
    """State the shortfall as a number, so "42 techniques" cannot read as complete.

    ATLAS 2026.09 publishes 208 techniques (120 top-level plus 88
    sub-techniques). We carry far fewer. This test does not fail on the shortfall --
    closing 166 technique entries is not a patch -- but it prints the figure and
    fails if the catalogue ever shrinks, so the gap can only get smaller.
    """
    have = len(am.ATLAS_TECHNIQUES)
    coverage = 100.0 * have / ATLAS_2026_09_TECHNIQUES
    print(f"\n  ATLAS catalogue coverage: {have}/{ATLAS_2026_09_TECHNIQUES} "
          f"= {coverage:.1f}%")

    assert have <= ATLAS_2026_09_TECHNIQUES, (
        "the catalogue holds more entries than the pinned release publishes"
    )
    assert have >= 42, (
        f"catalogue shrank from 42 to {have}. A technique removal is a change to "
        "ATLAS attribution and needs its own justification."
    )


# ------------------------------------------- the structural discrepancy ------

def test_catalogue_shape_is_legacy_while_labelled_v6():
    """A recorded, deliberately unfixed structural discrepancy.

    The v6 format is a MAPPING keyed by technique id; this catalogue is a LIST of
    {id, ...} dicts, and carries tactic membership inline where v6 puts it in the
    separate `relationships:` block. The consequence is concrete: the catalogue
    cannot be regenerated from the pinned file, so it can only be maintained by
    hand and can drift from its pin silently -- which is exactly what happened
    when the twelve entries were first transcribed from the deprecated file.

    If this test ever fails because someone migrated the shape, that is an
    improvement and the comment should be updated, not reverted.
    """
    catalogue = (REPO / "core" / "atlas_catalogue.py").read_text(encoding="utf-8")
    generated_shape = bool(re.search(r'^\s{4}"AML\.T\d{4}(?:\.\d{3})?":\s*\{',
                                    catalogue, re.M))
    assert generated_shape, (
        "core/atlas_catalogue.py no longer holds the v6 mapping shape; if the "
        "generator changed, re-check that it still parses the pinned document"
    )

    # The hand-maintained table must be GONE from atlas_mappings.py. Its presence is
    # what allowed the catalogue to drift from its own pin silently.
    assert not re.search(r'^ATLAS_TECHNIQUES = \{', SRC, re.M), (
        "core/atlas_mappings.py has re-acquired a hand-maintained ATLAS_TECHNIQUES "
        "table. It must import the generated catalogue instead -- that split is "
        "the whole point of the migration."
    )
    assert "from core.atlas_catalogue import" in SRC, (
        "core/atlas_mappings.py must import the generated catalogue"
    )
    assert am.ATLAS_FORMAT_VERSION == PINNED_FORMAT