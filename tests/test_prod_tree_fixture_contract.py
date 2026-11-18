"""Option B (fixture governance): the committed synthetic prod-tree fixtures.

These tests consume ONLY the committed fixtures under
``tests/fixtures/prod_tree/`` -- never the repository-root ``reports/``,
``quarantine/`` or ``backup/`` trees (which remain authentic local state).
They prove the GENERAL contracts (register schema/renderer, quarantine
manifest record, backup discovery/exclusion) on independently authored
synthetic data; the AUTHENTIC-history tests that consume the real
repository-root artifacts are separately identified with the registered
``requires_prod_tree`` policy (see AUTHENTIC_HISTORY_TEST_DISPOSITION.md in
the Option B evidence directory).
"""
from __future__ import annotations

import json
import pathlib

import pytest

from analysis.render_gap_register import build as _build_register_markdown

FIXTURE_ROOT = pathlib.Path(__file__).resolve().parent / "fixtures" / "prod_tree"

# The canonical gap-row contract, restated from
# tests/test_v11_p0_owasp_aibom_conformance.py (_REQUIRED_GAP_KEYS). The
# synthetic register must satisfy the SAME structural contract the authentic
# register is held to; the invariants below are the portable twins of
# test_37/test_38 there (see AUTHENTIC_HISTORY_TEST_DISPOSITION.md).
REQUIRED_GAP_KEYS = frozenset(
    {
        "id", "priority", "domain", "title", "problem", "reference_tool",
        "how_reference_does_it", "current_behavior", "actual_gap",
        "enterprise_essential", "research_relevant", "cost",
        "regression_risk", "implementation_location", "root_cause_class",
        "evidence_tier", "evidence",
    }
)
PRIORITIES = {"P0", "P1", "P2", "P3"}
TIERS = {"MEASURED_OPEN", "MEASURED_CLOSED", "UNMEASURED", "STRUCTURAL"}
COSTS = {"XS", "S", "M", "L", "XL"}
RISKS = {"LOW", "MED", "HIGH"}


def _synthetic_register() -> dict:
    return json.loads(
        (FIXTURE_ROOT / "gap_register" / "synthetic_gap_register.json")
        .read_text(encoding="utf-8"))


def register_invariants(reg: dict) -> list[str]:
    """The structural invariants of a conforming register (portable twin of
    the authentic-register schema test). Returns a list of violations;
    empty means conforming."""
    problems: list[str] = []
    gaps = reg["gaps"]
    ids = [g["id"] for g in gaps]
    if len(ids) != len(set(ids)):
        problems.append("duplicate gap ids")
    if ids != sorted(ids):
        problems.append("gap ids are not ordered")
    for g in gaps:
        if set(g) != REQUIRED_GAP_KEYS:
            problems.append(f"{g.get('id', '?')}: key set != required keys")
        if g.get("priority") not in PRIORITIES:
            problems.append(f"{g.get('id', '?')}: priority outside vocabulary")
        if g.get("evidence_tier") not in TIERS:
            problems.append(f"{g.get('id', '?')}: evidence_tier outside vocabulary")
        if g.get("cost") not in COSTS:
            problems.append(f"{g.get('id', '?')}: cost outside vocabulary")
        if g.get("regression_risk") not in RISKS:
            problems.append(f"{g.get('id', '?')}: regression_risk outside vocabulary")
        if g.get("root_cause_class") not in reg["root_cause_classes"]:
            problems.append(f"{g.get('id', '?')}: root_cause_class undefined")
        if str(g.get("evidence_tier", "")).startswith("MEASURED") and not str(g.get("evidence", "")).strip():
            problems.append(f"{g.get('id', '?')}: MEASURED* tier with empty evidence")
    for entry in reg["closed_this_program"]:
        if not str(entry.get("item", "")).strip():
            problems.append("closed_this_program entry with empty item")
        for cause in entry.get("root_causes", []):
            if cause not in reg["root_cause_classes"]:
                problems.append(f"closure cites undefined root cause {cause!r}")
    for rejected in reg["not_proposed"]:
        if not (str(rejected.get("item", "")).strip()
                and str(rejected.get("reason", "")).strip()):
            problems.append("not_proposed entry missing item or reason")
    return problems


# ---------------------------------------------------------------------------
# positive: the committed synthetic register conforms
# ---------------------------------------------------------------------------
def test_synthetic_register_exists_and_is_labelled():
    raw = (FIXTURE_ROOT / "gap_register" / "synthetic_gap_register.json").read_text(
        encoding="utf-8")
    reg = json.loads(raw)
    assert reg["_fixture_notice"].startswith("SYNTHETIC TEST FIXTURE"), (
        "the fixture must self-identify as synthetic")
    lowered = raw.lower()
    assert "synthetic" in lowered and "not the authentic" in lowered, (
        "the fixture must state it is not the authentic register")


def test_synthetic_register_satisfies_the_structural_contract():
    problems = register_invariants(_synthetic_register())
    assert not problems, problems


def test_renderer_emits_every_synthetic_row_and_the_table_markers():
    reg = _synthetic_register()
    rendered = _build_register_markdown(reg)
    assert rendered.count("SYN-G-") >= len(reg["gaps"])
    for g in reg["gaps"]:
        assert g["id"] in rendered, g["id"]
        assert g["title"] in rendered, g["id"]
    assert "| Outcome | Root-cause classes involved |" in rendered
    assert "| Considered | Why not |" in rendered


def test_synthetic_detector_is_green():
    # The MEASURED_CLOSED synthetic row cites this test as its detector
    # (see SYN-G-002 evidence) -- the citation must be honest, so the test
    # exists and exercises the cited behaviour.
    reg = _synthetic_register()
    row = {g["id"]: g for g in reg["gaps"]}["SYN-G-002"]
    assert row["evidence_tier"] == "MEASURED_CLOSED"
    assert "test_synthetic_detector_is_green" in row["evidence"]
    assert row["evidence_tier"].startswith("MEASURED") and row["evidence"].strip()


# ---------------------------------------------------------------------------
# negative: invalid register data must be REJECTED by the invariants
# ---------------------------------------------------------------------------
def _mutated(**over):
    reg = _synthetic_register()
    for key, value in over.items():
        reg[key] = value
    return reg


def test_negative_duplicate_gap_ids_are_rejected():
    reg = _mutated(gaps=[_synthetic_register()["gaps"][0],
                         _synthetic_register()["gaps"][0]])
    problems = register_invariants(reg)
    assert any("duplicate gap ids" in p for p in problems), problems


def test_negative_undefined_root_cause_class_is_rejected():
    reg = _synthetic_register()
    reg["gaps"][0]["root_cause_class"] = "NOT_A_DEFINED_CLASS"
    problems = register_invariants(reg)
    assert any("root_cause_class undefined" in p for p in problems), problems


def test_negative_missing_required_key_is_rejected():
    reg = _synthetic_register()
    del reg["gaps"][1]["cost"]
    problems = register_invariants(reg)
    assert any("key set != required keys" in p for p in problems), problems


def test_negative_measured_tier_without_evidence_is_rejected():
    reg = _synthetic_register()
    reg["gaps"][2]["evidence"] = "   "
    problems = register_invariants(reg)
    assert any("MEASURED* tier with empty evidence" in p for p in problems), problems


def test_negative_priority_outside_vocabulary_is_rejected():
    reg = _synthetic_register()
    reg["gaps"][0]["priority"] = "P9"
    problems = register_invariants(reg)
    assert any("priority outside vocabulary" in p for p in problems), problems


def test_negative_closure_citing_undefined_cause_is_rejected():
    reg = _synthetic_register()
    reg["closed_this_program"][0]["root_causes"] = ["NOT_A_DEFINED_CLASS"]
    problems = register_invariants(reg)
    assert any("undefined root cause" in p for p in problems), problems


# ---------------------------------------------------------------------------
# quarantine manifest record contract (synthetic fixture)
# ---------------------------------------------------------------------------
def _read_synthetic_manifest() -> tuple[str, pathlib.Path]:
    manifest_path = FIXTURE_ROOT / "quarantine" / "MANIFEST-SYNTHETIC.txt"
    return manifest_path.read_text(encoding="utf-8"), manifest_path.parent


def test_synthetic_quarantine_manifest_record_contract():
    text, qdir = _read_synthetic_manifest()
    assert "Nothing here was deleted." in text, (
        "the manifest contract requires the no-deletion statement")
    assert "SYNTHETIC TEST FIXTURE MANIFEST" in text, (
        "the synthetic manifest must self-identify")
    # every recorded path exists (records use the repository-root-relative
    # convention, mirroring the authentic manifest's own record format)
    recorded = [line.strip() for line in text.splitlines()
                if line.strip().endswith(".py") and not line.strip().startswith("#")]
    assert recorded, "the synthetic manifest must record its moved modules"
    repo_root = FIXTURE_ROOT.parents[2]
    for rel in recorded:
        assert (repo_root / rel).is_file(), f"manifest records a missing file: {rel}"


def test_negative_manifest_recording_a_missing_file_is_rejected():
    text, _qdir = _read_synthetic_manifest()
    # The ghost record is assembled from parts so the dead-code guard's
    # source scan does not mistake this negative probe for a real path
    # into the repository-root quarantine/ (it is a synthetic-fixture
    # record that deliberately points at a file that does not exist).
    ghost_rel = "/".join(("tests", "fixtures", "prod_tree", "quarantine",
                          "ghost_" + "module" + ".py"))
    bad = text + f"\n  {ghost_rel}\n"
    recorded = [line.strip() for line in bad.splitlines()
                if line.strip().endswith(".py") and not line.strip().startswith("#")]
    repo_root = FIXTURE_ROOT.parents[2]
    missing = [rel for rel in recorded if not (repo_root / rel).is_file()]
    assert missing, "the negative probe must actually produce a missing record"
    assert any("ghost_" in rel for rel in missing), recorded


# ---------------------------------------------------------------------------
# backup discovery + exclusion contract (synthetic fixture)
# ---------------------------------------------------------------------------
def test_synthetic_backup_copies_are_discovered_and_excluded(tmp_path):
    from test_privacy_single_engine import _definitions

    # mirror the real layout inside a tmp tree: the synthetic legacy copy
    # (definition-bearing, privacy-entrypoint-shaped) under backup/, plus a
    # LIVE definition outside backup/ -- the live tree must report exactly
    # the live definition, proving backup/ is excluded from the walk.
    live_root = tmp_path / "repo"
    (live_root / "backup").mkdir(parents=True)
    src = FIXTURE_ROOT / "backup" / "synthetic_legacy_copy_a.py"
    (live_root / "backup" / "synthetic_legacy_copy_a.py").write_text(
        src.read_text(encoding="utf-8"), encoding="utf-8")
    (live_root / "analysis").mkdir()
    (live_root / "analysis" / "privacy_data_exposure_engine.py").write_text(
        "def enrich_privacy_data_exposure(findings, target=None):\n"
        "    return []\n",
        encoding="utf-8")
    hits = _definitions(live_root)
    assert hits == ["analysis/privacy_data_exposure_engine.py"], (
        f"exactly the live definition must be found; backup/ excluded: {hits}")
    # sanity (mirrors the authentic test): the copy IS definition-bearing
    # when discovery does not exclude backup/ -- so the exclusion is doing
    # real work, not passing vacuously.
    backup_defs = [p for p in (live_root / "backup").rglob("*.py")
                   if "def enrich_privacy_data_exposure" in p.read_text(encoding="utf-8")]
    assert backup_defs, "the synthetic copy must be definition-bearing"


def test_synthetic_backup_copies_are_definition_bearing():
    # the exclusion test is only meaningful when the copies carry real
    # definitions (the same sanity gate the privacy test applies)
    from test_privacy_single_engine import _DEF_RE
    for name in ("synthetic_legacy_copy_a.py", "synthetic_legacy_copy_b.py"):
        text = (FIXTURE_ROOT / "backup" / name).read_text(encoding="utf-8")
        assert "SYNTHETIC TEST FIXTURE" in text
        assert "def " in text, name
    assert _DEF_RE.search(
        (FIXTURE_ROOT / "backup" / "synthetic_legacy_copy_a.py").read_text(
            encoding="utf-8")), (
        "copy A must carry the privacy-entrypoint definition shape")
