"""T-14.4 (task.md section 14 "Docs"): one README that is actually a README.

task.md section 14:

    **Docs:** one README that is actually a README (currently the README
    is a *patch integration note*).

The old README.md was a 22-line "Evidence Normalization Integration v1"
patch note (apply this script, back up that file, refuse duplicate
patching) with an absolute path baked in. This test pins the
replacement: a real project README -- what the tool is, how to install
and run it, what it writes, the offline/airgap invariant, how
validation works, where the docs live -- with no absolute paths and
none of the patch-note instructions.
"""
from __future__ import annotations

import pathlib
import re

REPO = pathlib.Path(__file__).resolve().parent.parent
README = REPO / "README.md"


def _text() -> str:
    assert README.exists(), "README.md is missing"
    return README.read_text(encoding="utf-8")


def test_readme_is_substantial():
    # A README that is actually a README, not a stub or a note.
    lines = _text().splitlines()
    assert len(lines) >= 60, (
        f"README.md is only {len(lines)} lines -- that is a note, "
        "not a project README (task.md section 14)")
    assert lines[0].startswith("# R-SecOpsX"), lines[0]


def test_readme_has_the_sections_a_reader_needs():
    text = _text()
    required = (
        "## Overview",
        "## Requirements",
        "## Quick start",
        "## Usage",
        "## Output artifacts",
        "## Offline and airgap invariant",
        "## Validation",
        "## Project layout",
        "## Documentation",
        "## License",
    )
    for heading in required:
        assert heading in text, f"README.md is missing the {heading!r} section"


def test_readme_is_not_the_old_patch_note():
    text = _text()
    for residue in (
        "Evidence Normalization Integration",
        "Backup `finding_model.py`",
        "Refuse duplicate patching",
        "patch integration",
    ):
        assert residue not in text, (
            f"README.md still carries the patch-note residue {residue!r} "
            "(task.md section 14 says the README must stop being one)")


def test_readme_has_no_absolute_paths():
    # Ground rule: no absolute paths in source/docs. Drive letters,
    # UNC roots and home directories are all banned.
    text = _text()
    offenders = re.findall(r"[A-Za-z]:[\\/][^\s`\"')]*", text)
    offenders += re.findall(r"\\\\[A-Za-z0-9._-]+\\", text)
    offenders += re.findall(r"/home/[A-Za-z0-9._-]+", text)
    assert not offenders, f"README.md contains absolute paths: {offenders}"


def test_readme_documents_the_entry_points_and_flags():
    text = _text()
    for needle in (
        "main.py",
        "rsecopsx",
        "--fail-on",
        "--policy",
        "--explain-drops",
        "--explain-verdict",
        "--explain-score",
        "--telemetry",
        "clean_report.json",
    ):
        assert needle in text, f"README.md does not mention {needle!r}"


def test_readme_states_the_offline_invariant_and_validation():
    text = _text()
    lowered = text.lower()
    assert "offline" in lowered
    assert "airgap" in lowered
    # the validation entry points a contributor would actually run
    for needle in (
        "python -m analysis.validation.run",
        "python -m analysis.validation.replay",
        "python -m analysis.validation.ci_matrix",
    ):
        assert needle in text, f"README.md does not mention {needle!r}"


def test_readme_points_at_the_tracked_docs():
    text = _text()
    # only tracked docs/ files may be referenced (untracked plans would
    # be dangling links for anyone who clones the repo)
    for doc in (
        "docs/accuracy_layer.md",
        "docs/ufib_acceptance_matrix.md",
        "docs/gap_analysis.md",
    ):
        assert doc in text, f"README.md does not link {doc}"
    assert "docs/PRODUCT_ARCHITECTURE.md" not in text, (
        "docs/PRODUCT_ARCHITECTURE.md is untracked -- do not link it")


def test_readme_license_matches_pyproject():
    text = _text()
    assert "Proprietary" in text, (
        "pyproject declares license = Proprietary; README must say so")
