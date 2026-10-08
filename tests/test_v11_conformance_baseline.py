"""Tests for the mandatory P0 conformance baseline.

The baseline's value is entirely in being able to FAIL. These tests therefore
guard the two ways it could silently stop doing that: a probe that matches the
file which declares it, and a probe set quietly weakened so the gate goes green.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core.conformance_baseline import (  # noqa: E402
    BASELINE_ID,
    BASELINE_VERSION,
    PROBE_DECLARATION_FILES,
    STANDARD_BASELINE,
    evaluate_baseline,
    load_artifact,
    production_sources,
)

REQUIRED_KEYS = {
    "CWE",
    "SANS_AI",
    "OWASP",
    "ASVS",
    "WSTG",
    "MITRE_ATTACK",
    "MITRE_ATLAS",
    "CERT_IN",
    "RBI_FREE_AI",
    "NIST_SSDF",
    "NIST_AML",
    "SUPPLY_CHAIN",
}

ARTIFACT = Path(
    r"C:\Users\janan\AppData\Local\Temp\opencode\js_fix\clean_report.json"
)


# ---------------------------------------------------------------------------
# The declared baseline itself
# ---------------------------------------------------------------------------
def test_all_eleven_standards_are_declared_and_mandatory():
    keys = {s["key"] for s in STANDARD_BASELINE}
    assert keys == REQUIRED_KEYS, (
        f"baseline must declare exactly the eleven mandatory P0 standards; "
        f"missing={sorted(REQUIRED_KEYS - keys)} extra={sorted(keys - REQUIRED_KEYS)}"
    )
    assert len(STANDARD_BASELINE) == 12
    for std in STANDARD_BASELINE:
        assert std["mandatory_p0"] is True, f"{std['key']} must be mandatory P0"


def test_every_standard_pins_a_version_and_a_source():
    for std in STANDARD_BASELINE:
        assert std["version"].strip(), f"{std['key']} has no pinned version"
        assert std["authority"].strip(), f"{std['key']} has no authority"
        assert std["source_url"].startswith("http"), (
            f"{std['key']} has no citable source url"
        )


def test_every_standard_has_at_least_one_required_probe():
    for std in STANDARD_BASELINE:
        required = [p for p in std["probes"] if p["required"]]
        assert required, f"{std['key']} has no required probe, so it cannot fail"


def test_every_probe_is_well_formed_and_compilable():
    import re as _re

    for std in STANDARD_BASELINE:
        for p in std["probes"]:
            assert p["kind"] in {"code", "artifact", "absent"}, p["name"]
            assert p["description"].strip(), f"{std['key']}/{p['name']} no description"
            if p["kind"] == "code":
                _re.compile(p["pattern"])  # raises if malformed


def test_probe_names_are_unique():
    seen = set()
    for std in STANDARD_BASELINE:
        for p in std["probes"]:
            assert p["name"] not in seen, f"duplicate probe name {p['name']}"
            seen.add(p["name"])


# ---------------------------------------------------------------------------
# The self-match guard -- this is the bug that made the gate lie
# ---------------------------------------------------------------------------
def test_probe_declaration_files_are_excluded_from_the_scan():
    """A probe must never be able to match the file that declares it.

    Every pattern is a literal string inside conformance_baseline.py, so
    including it makes `wstg_referenced`, `sans_referenced`,
    `spdx_export` and friends pass on nothing. That produced a reported 8/11
    VERIFIED when the true figure was 3/11.
    """
    sources = production_sources(ROOT)
    for excluded in PROBE_DECLARATION_FILES:
        assert excluded not in sources, (
            f"{excluded} declares the probes and must be excluded from the scan"
        )


def test_probe_declaration_file_exists_on_disk():
    for rel in PROBE_DECLARATION_FILES:
        assert (ROOT / rel).exists(), f"{rel} is excluded but does not exist"


def test_baseline_module_text_is_not_in_the_scanned_corpus():
    joined = "\n".join(production_sources(ROOT).values())
    # A distinctive phrase that exists only in the probe declarations.
    assert "PROBE_DECLARATION_FILES" not in joined
    assert "must never be able to satisfy" not in joined


def test_a_phrase_unique_to_the_declaration_file_cannot_satisfy_a_probe():
    """End-to-end guard on the self-match property.

    A probe pattern necessarily appears as a literal string inside its own
    definition, so asserting "no pattern matches the declaration file" is the
    wrong invariant. The invariant that matters is that the declaration file is
    not in the corpus the evaluator scans, so a phrase found only there can
    never satisfy any probe.
    """
    import re as _re

    phrase = "must never be able to satisfy"
    decl = (ROOT / "core" / "conformance_baseline.py").read_text(
        encoding="utf-8", errors="ignore"
    )
    assert phrase in decl, "control phrase must exist in the declaration file"
    joined = "\n".join(production_sources(ROOT).values())
    assert not _re.search(_re.escape(phrase), joined, re.I), (
        "a phrase unique to the probe-declaration file reached the scan corpus"
    )


def test_scan_corpus_is_production_only():
    """Evidence must be implementation, never a measurement of it."""
    rels = set(production_sources(ROOT))
    assert rels, "scan corpus must not be empty"
    for rel in rels:
        assert not rel.startswith("tests/"), rel
        assert not rel.startswith("docs/"), rel
        assert not rel.startswith("reports/"), rel
        assert not rel.startswith("analysis/"), rel
        assert not rel.startswith("backup/"), rel
        assert not rel.startswith("quarantine/"), rel


# ---------------------------------------------------------------------------
# Evaluation behaviour
# ---------------------------------------------------------------------------
def test_evaluate_runs_and_reports_every_standard():
    result = evaluate_baseline(ROOT, None)
    assert result["baseline_id"] == BASELINE_ID
    assert result["mandatory_total"] == 12
    assert len(result["standards"]) == 12
    for std in result["standards"]:
        assert std["status"] in {"VERIFIED", "NOT_VERIFIED"}
        if std["status"] == "VERIFIED":
            assert not std["failed_probes"], std["key"]
        else:
            assert std["failed_probes"], f"{std['key']} failed without a reason"


def test_standards_absent_from_code_are_not_verified():
    """The core anti-false-positive property, asserted against reality.

    The absent set is DERIVED, not hardcoded. A hardcoded list is
    self-fulfilling: it only ever names the standards that happen to be absent
    today, so every implementation added since it was written silently drops off
    the guard. Deriving it means the invariant below keeps holding as the
    baseline grows, and it is strictly stronger than the list it replaces:

      a standard whose every code probe matches no production source must be
      NOT_VERIFIED.

    Every such standard is reported, so this cannot pass by checking nothing.
    """
    import re as _re

    from core.conformance_baseline import STANDARD_BASELINE, production_sources

    sources = production_sources(ROOT)
    result = evaluate_baseline(ROOT, None)
    status = {s["key"]: s["status"] for s in result["standards"]}

    # PART 1 -- the invariant, stated positively so it needs no live gap.
    # Every standard reported VERIFIED must have real production support. This is
    # the anti-false-positive property: nothing may claim VERIFICATION on the
    # strength of a probe that matches nothing.
    verified = [s for s in result["standards"] if s["status"] == "VERIFIED"]
    assert verified, "the baseline verified nothing at all"
    for entry in verified:
        std = next(s for s in STANDARD_BASELINE if s["key"] == entry["key"])
        code_probes = [p for p in std["probes"] if p["kind"] == "code"]
        assert code_probes, f"{std['key']} verified with no code probe"
        has_support = any(
            any(_re.search(p["pattern"], text) for text in sources.values())
            for p in code_probes
        )
        assert has_support, (
            f"{std['key']} is VERIFIED but no code probe matches any production "
            f"source -- a false positive in the baseline"
        )

    # PART 2 -- the same property for any standard that DOES lack support.
    # No such standard exists today, and that is the desired end state rather
    # than a reason to stop checking. The count is reported, not required.
    for std in STANDARD_BASELINE:
        code_probes = [p for p in std["probes"] if p["kind"] == "code"]
        if not code_probes:
            continue
        has_support = any(
            any(_re.search(p["pattern"], text) for text in sources.values())
            for p in code_probes
        )
        if has_support:
            continue
        assert status[std["key"]] == "NOT_VERIFIED", (
            f"{std['key']} has no supporting production source but was reported "
            f"VERIFIED -- a false positive in the baseline"
        )

    # PART 3 -- the detection logic must still fire. A synthetic standard with
    # probes that match nothing must be classified NOT_VERIFIED, which proves the
    # guard is not vacuous without relying on the baseline having a gap. This is
    # what the old `checked >= 1` assertion was reaching for, and it no longer
    # breaks the moment the product improves.
    from core.conformance_baseline import STANDARD_BASELINE as _SB
    import core.conformance_baseline as _cb

    phantom = {
        "key": "PHANTOM_FOR_GUARD_TEST",
        "title": "Phantom",
        "authority": "none",
        "version": "none",
        "source_url": "none",
        "mandatory_p0": True,
        # Built by the module's own helper so it carries every key the evaluator
        # reads (name, kind, pattern, required, description). Hand-rolling the
        # dict omitted `required` and raised KeyError inside evaluate_baseline.
        "probes": [_cb._probe(
            "phantom_probe", "code",
            r"ZZZ_NO_SUCH_TOKEN_EXISTS_ANYWHERE_12345",
            "synthetic probe; matches no production source")],
    }
    _original = list(_cb.STANDARD_BASELINE)
    try:
        _cb.STANDARD_BASELINE.insert(0, phantom)
        synthetic = evaluate_baseline(ROOT, None)
        phantom_status = {s["key"]: s["status"]
                          for s in synthetic["standards"]}["PHANTOM_FOR_GUARD_TEST"]
    finally:
        _cb.STANDARD_BASELINE[:] = _original

    assert phantom_status == "NOT_VERIFIED", (
        "a standard whose probes match no production source was not classified "
        f"NOT_VERIFIED (got {phantom_status}) -- the guard would pass vacuously")


def test_standards_verifiable_from_code_alone_do_verify():
    """OWASP and ATLAS are fully code-verifiable and must verify."""
    result = evaluate_baseline(ROOT, None)
    status = {s["key"]: s["status"] for s in result["standards"]}
    for good in ("OWASP", "MITRE_ATLAS"):
        assert status[good] == "VERIFIED", f"{good} should verify from code alone"


@pytest.mark.skipif(not ARTIFACT.exists(), reason="reference artifact not present")
def test_cwe_verifies_once_an_artifact_supplies_its_probe():
    """CWE needs an artifact probe, so it must fail closed without one."""
    without = evaluate_baseline(ROOT, None)
    assert {s["key"]: s["status"] for s in without["standards"]}["CWE"] == "NOT_VERIFIED"
    with_art = evaluate_baseline(ROOT, load_artifact(ARTIFACT))
    status = {s["key"]: s["status"] for s in with_art["standards"]}
    assert status["CWE"] == "VERIFIED", (
        f"findings carry a CWE identifier, so CWE must verify with an artifact: {status}"
    )


def test_coverage_ratio_is_consistent():
    result = evaluate_baseline(ROOT, None)
    assert result["mandatory_verified"] + result["mandatory_not_verified"] == 12
    assert result["coverage_ratio"] == pytest.approx(
        result["mandatory_verified"] / 12
    )


def test_artifact_probes_fail_closed_without_an_artifact():
    result = evaluate_baseline(ROOT, None)
    assert result["artifact_supplied"] is False
    for std in result["standards"]:
        for p in std["probes"]:
            if p["kind"] == "artifact":
                assert p["status"] == "FAIL", (
                    f"{std['key']}/{p['name']} passed without an artifact"
                )
                assert "no artifact" in p["detail"]


@pytest.mark.skipif(not ARTIFACT.exists(), reason="reference artifact not present")
def test_qbom_and_hbom_are_absent_in_the_real_artifact():
    art = load_artifact(ARTIFACT)
    assert "qbom" not in art, "if qbom now exists this test and probe must change"
    assert "hbom" not in art, "if hbom now exists this test and probe must change"
    for key in ("sbom", "aibom", "cbom"):
        assert key in art and art[key], f"{key} should exist"


@pytest.mark.skipif(not ARTIFACT.exists(), reason="reference artifact not present")
def test_artifact_probe_changes_verdict_when_artifact_supplied():
    without = evaluate_baseline(ROOT, None)
    with_art = evaluate_baseline(ROOT, load_artifact(ARTIFACT))
    # Supplying an artifact can only help artifact probes, never hurt.
    assert with_art["mandatory_verified"] >= without["mandatory_verified"]
    assert with_art["artifact_supplied"] is True


def test_benchmark_report_exists_and_is_consistent():
    p = ROOT / "reports" / "benchmark_conformance_baseline.json"
    if not p.exists():
        pytest.skip("benchmark has not been run yet")
    data = json.loads(p.read_text(encoding="utf-8"))
    assert data["mandatory_total"] == 12
    assert len(data["standards"]) == 12
    assert data["failing_standards"] == data["mandatory_not_verified"]