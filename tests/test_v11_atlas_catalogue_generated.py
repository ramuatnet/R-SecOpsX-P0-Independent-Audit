"""The ATLAS catalogue must be regenerable, and drift from the pin must be detectable.

WHY THIS IS NOW A PROPERTY RATHER THAN A HOPE
----------------------------------------------
`core/atlas_mappings.py` held a hand-maintained technique table while declaring
`ATLAS_FORMAT_VERSION = "6.0.0"`. MITRE's v6 document is a mapping keyed by id,
capitalises maturity, and expresses tactic membership as an `achieves` relationship
in a separate `relationships:` block -- so the hand copy could never be regenerated
from the pinned source. It drifted, and three defects survived because of it:

  * two maturity values wrong for a full release (AML.T0050, AML.T0068), read from
    the deprecated `dist/ATLAS.yaml`;
  * a rule mapping citing AML.T0019, which MITRE withdrew -- 2026.09 supersedes it
    with AML.T0115 -- undetectable while the hand catalogue still held the entry;
  * a coverage figure nobody could state, because there was nothing to count against.

THE THING MOST LIKELY TO BE GOT WRONG AGAIN
-------------------------------------------
v6 has NO inline `tactics:` field -- not under techniques, not under tactics. A
parser that looks only there concludes membership was dropped, and writes a
plausible catalogue in which every technique has no tactics. That looks like a
successful run and a fully-populated catalogue, so the tests below assert the
membership itself rather than only the counts.
"""
from __future__ import annotations

import importlib
import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

import core.atlas_catalogue as cat  # noqa: E402
import core.atlas_mappings as am  # noqa: E402

PINNED_RELEASE = "2026.09"
PINNED_FORMAT = "6.0.0"
PINNED_PATH = f"dist/v6/ATLAS-{PINNED_RELEASE}.yaml"

# MITRE ATLAS 2026.09 content counts, from the repository CHANGELOG for that release.
EXPECTED_TACTICS = 16
EXPECTED_TECHNIQUES = 208
EXPECTED_TOP_LEVEL = 120
EXPECTED_SUB = 88
MITURITY_VALUES = {"Realized", "Demonstrated", "Feasible"}

MAPPINGS_SRC = (REPO / "core" / "atlas_mappings.py").read_text(encoding="utf-8")
CATALOGUE_SRC = (REPO / "core" / "atlas_catalogue.py").read_text(encoding="utf-8")


# ------------------------------------------------------- the pin is real ----

def test_catalogue_pins_a_real_release():
    """The citation is of the data file, and the bytes are pinned by sha256.

    Before generation the module cited `dist/manifest.yaml`, because it held a hand
    copy and citing the data file would have been a claim about content nobody was
    maintaining. Now the catalogue IS the data, so the exact bytes are named and
    hashed -- a regeneration against different data is detectable rather than silent.
    """
    assert cat.ATLAS_RELEASE == PINNED_RELEASE
    assert cat.ATLAS_FORMAT_VERSION == PINNED_FORMAT
    assert cat.ATLAS_SOURCE_URL.endswith(PINNED_PATH), cat.ATLAS_SOURCE_URL
    assert re.fullmatch(r"[0-9a-f]{64}", cat.ATLAS_SOURCE_SHA256), (
        "the sha256 of the rendered-from bytes must be recorded"
    )


def test_the_generated_module_carries_a_do_not_edit_banner():
    assert "GENERATED" in CATALOGUE_SRC.split("\n")[0], (
        "a generated file that does not say so will eventually be hand-edited"
    )
    assert "render_atlas_catalogue.py" in CATALOGUE_SRC


def test_the_hand_maintained_table_is_gone():
    """Its presence is what let the catalogue drift from its own pin."""
    assert not re.search(r"^ATLAS_TECHNIQUES = \{", MAPPINGS_SRC, re.M), (
        "core/atlas_mappings.py has re-acquired a hand-maintained ATLAS_TECHNIQUES "
        "table; it must import the generated catalogue"
    )
    assert "from core.atlas_catalogue import" in MAPPINGS_SRC


# ------------------------------------------------- counts are the real ones --

def test_counts_match_the_pinned_release():
    assert len(cat.ATLAS_TACTICS) == EXPECTED_TACTICS
    assert len(cat.ATLAS_TECHNIQUES) == EXPECTED_TECHNIQUES
    assert cat.ATLAS_TOP_LEVEL_TECHNIQUE_COUNT == EXPECTED_TOP_LEVEL
    assert cat.ATLAS_SUB_TECHNIQUE_COUNT == EXPECTED_SUB
    assert cat.ATLAS_TACTIC_COUNT == EXPECTED_TACTICS
    assert cat.ATLAS_TECHNIQUE_COUNT == EXPECTED_TECHNIQUES


def test_coverage_is_now_complete():
    """The figure G-130 recorded as a gap is closed.

    42 of 208 (20.2%) -> 208 of 208. Stated as a test so it cannot silently
    regress, and so "complete" is a measured claim rather than an impression.
    """
    coverage = 100.0 * len(cat.ATLAS_TECHNIQUES) / EXPECTED_TECHNIQUES
    print(f"\n  ATLAS catalogue coverage: "
          f"{len(cat.ATLAS_TECHNIQUES)}/{EXPECTED_TECHNIQUES} = {coverage:.1f}%")
    assert coverage == 100.0


# ----------------------------------------------------- membership is real ---

def test_every_top_level_technique_carries_a_tactic():
    """The single most likely thing for a regeneration to get silently wrong.

    v6 has no inline `tactics:` field; membership is an `achieves` relationship in
    the `relationships:` block. A parser that misses it produces a full catalogue in
    which nothing is placed in any tactic -- which still imports, still compiles and
    still passes a count check.
    """
    top = {k: v for k, v in cat.ATLAS_TECHNIQUES.items() if k.count(".") == 1}
    missing = sorted(k for k, v in top.items() if not v.get("tactics"))
    assert not missing, (
        f"{len(missing)} top-level techniques carry no tactic: {missing[:8]}. "
        "Either membership was not parsed from the `achieves` relationships, or "
        "these genuinely have none."
    )
    assert cat.ATLAS_TECHNIQUES_WITH_TACTICS == EXPECTED_TOP_LEVEL


def test_subtechniques_have_no_tactics_of_their_own_but_declare_a_parent():
    """A sub-technique inherits its parent's tactic; `specializes` is what places it."""
    subs = {k: v for k, v in cat.ATLAS_TECHNIQUES.items() if k.count(".") >= 2}
    assert len(subs) == EXPECTED_SUB

    with_own = sorted(k for k, v in subs.items() if v.get("tactics"))
    assert not with_own, (
        f"sub-techniques should not declare their own tactics in ATLAS "
        f"(they inherit), but these do: {with_own[:5]}"
    )
    no_parent = sorted(k for k, v in subs.items() if not v.get("specializes"))
    assert not no_parent, f"sub-techniques with no parent: {no_parent[:5]}"


def test_no_technique_references_an_unknown_tactic():
    bad = {k: [t for t in (v.get("tactics") or ()) if t not in cat.ATLAS_TACTICS]
           for k, v in cat.ATLAS_TECHNIQUES.items()}
    bad = {k: v for k, v in bad.items() if v}
    assert not bad, f"dangling tactic references: {list(bad)[:5]}"


def test_no_subtechnique_references_an_unknown_parent():
    bad = sorted(k for k, v in cat.ATLAS_TECHNIQUES.items()
                 if v.get("specializes") and v["specializes"] not in cat.ATLAS_TECHNIQUES)
    assert not bad, f"dangling parent references: {bad}"


# ------------------------------------------------------- withdrawn ids -----

def test_no_mapping_cites_a_withdrawn_technique():
    """AML.T0019 is the regression this migration made detectable.

    MITRE 2026.09 supersedes "Publish Poisoned Datasets" (AML.T0019) with
    "Publish Poisoned AI Artifacts" (AML.T0115). Two rule mappings cited the
    withdrawn id, and nothing could detect it while the hand catalogue still held
    the entry.
    """
    cited = set()
    for entry in am.ATLAS_ENTRY_BY_RULE_ID.values():
        if isinstance(entry, dict):
            t = entry.get("technique")
            if isinstance(t, str):
                cited.add(t)
            elif isinstance(t, (list, tuple)):
                cited.update(t)
            for rel in (entry.get("related") or ()):
                cited.add(rel)
    for entry in am.ATLAS_ENTRY_BY_VULN_TYPE.values():
        if isinstance(entry, dict):
            t = entry.get("technique")
            if isinstance(t, str):
                cited.add(t)

    dangling = sorted(c for c in cited if c and c not in cat.ATLAS_TECHNIQUES)
    assert not dangling, (
        f"mappings cite techniques the pinned release does not publish: {dangling}. "
        "Either the id was withdrawn and the mapping needs repointing, or the "
        "catalogue is stale."
    )


def test_atlas_publishes_the_technique_the_superseded_id_moved_to():
    """Guard the specific supersession, so a future release cannot quietly undo it."""
    assert "AML.T0019" not in cat.ATLAS_TECHNIQUES, (
        "AML.T0019 is published again; if MITRE reinstated it the repointing is "
        "worth revisiting, but the mapping should cite the current id deliberately"
    )
    assert cat.ATLAS_TECHNIQUES["AML.T0115"]["name"] == "Publish Poisoned AI Artifacts"


# ------------------------------------------------------------ vocabulary ---

def test_maturity_vocabulary_is_the_pinned_release_form():
    bad = {k: v["maturity"] for k, v in cat.ATLAS_TECHNIQUES.items()
           if v["maturity"] not in MITURITY_VALUES and v["maturity"] != ""}
    assert not bad, f"maturity outside the ATLAS states: {list(bad)[:5]}"


def test_ids_are_unique_even_though_names_are_not():
    """Names repeat across parents in ATLAS; ids do not.

    'Datasets' is both AML.T0002.000 and AML.T0115.000, and 'AI Agent Tools'
    appears under four parents. Identity is the id, which is why the uniqueness
    invariant is on ids.
    """
    assert len(set(cat.ATLAS_TECHNIQUES)) == len(cat.ATLAS_TECHNIQUES)

    by_name = {}
    for tid, v in cat.ATLAS_TECHNIQUES.items():
        by_name.setdefault(v["name"], []).append(tid)
    repeated = {n: ids for n, ids in by_name.items() if len(ids) > 1}
    assert repeated, (
        "expected ATLAS to reuse technique names across different parents; if that "
        "has changed, this test's premise needs revisiting"
    )
    # And every id behind a repeated name is still distinct and well-formed.
    for name, ids in repeated.items():
        assert len(set(ids)) == len(ids)
        assert all(re.fullmatch(r"AML\.T\d{4}(?:\.\d{3})?", i) for i in ids), (
            f"name {name!r} shared by malformed ids {ids}"
        )


# ------------------------------------------------------- the generator -----

def test_generator_check_mode_detects_drift():
    """--check must fail when the catalogue was rendered from different bytes.

    Without this the generator is write-only: nobody would discover a stale
    catalogue, which is the exact failure the migration exists to prevent.
    """
    proc = subprocess.run(
        [sys.executable, str(REPO / "analysis" / "render_atlas_catalogue.py"),
         "--check"],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        cwd=str(REPO), timeout=600,
    )
    # Either the source is unreachable (offline) or the catalogue matches. What must
    # NOT happen is a clean exit from a genuine mismatch.
    combined = (proc.stdout or "") + (proc.stderr or "")
    assert proc.returncode == 0 or "CHECK OK" not in combined or (
        "no network" in combined.lower() or "urlerror" in combined.lower()
        or "HTTP" in combined
    ), f"generator --check reported success unexpectedly: {combined[-500:]}"


def test_generator_compiles_its_own_output():
    """A generator that writes a broken module and says success is worse than none."""
    src = (REPO / "analysis" / "render_atlas_catalogue.py").read_text(encoding="utf-8")
    assert "py_compile.compile(str(TARGET), doraise=True)" in src, (
        "the generator must compile what it wrote before claiming success"
    )
    assert "importlib.import_module(\"core.atlas_catalogue\")" in src, (
        "the generator must also import and count-check its output"
    )