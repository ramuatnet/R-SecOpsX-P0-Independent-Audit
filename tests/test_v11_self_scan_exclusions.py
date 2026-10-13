"""Every artifact this tool writes must be excluded from its own scan.

Matching is by exact filename, lowercased. So a bare "qbom.json" entry does NOT
cover "Security_QBOM.qbom.json", and the scanner reads its own output back as
scanned input. That gap existed for the prefixed artifacts already in
production -- six of them -- and was invisible because nothing asserted the
relationship.

This test derives the list of written artifacts from main.py's own write sites
rather than from a hand-maintained duplicate, so adding a new artifact without
excluding it fails here instead of silently polluting a later scan.

The derivation spans helper modules too: reporting/ writes some artifacts under
a local receiver name (`out / "Security_..."`) instead of `output_dir / "..."`.
That blind spot shipped two unexcluded JSON artifacts once (Phase 5.2) -- the
main.py-only regex could not see them and every assertion below passed
vacuously. Helper write sites are now discovered alongside main.py's.
"""
from __future__ import annotations

import pathlib
import re
from collections import Counter

from scanner.sast import EXCLUDED_FILES, _skip as is_excluded

REPO = pathlib.Path(__file__).resolve().parent.parent
MAIN = REPO / "main.py"

# `output_dir / "Name.ext"` -- the write sites for artifacts that land in the
# scanned output directory.
_WRITE_RE = re.compile(r'output_dir\s*/\s*"([^"]+)"')

# Helper-module write sites: any receiver name (`out / "Security_..."`),
# restricted to extensions that could ever be written as artifacts.
_HELPER_WRITE_RE = re.compile(r'\w+\s*/\s*"([^"]+\.(?:json|csv|sarif|pdf|xlsx))"')


def _written_artifacts() -> set[str]:
    source = MAIN.read_text(encoding="utf-8")
    found = set(_WRITE_RE.findall(source))
    for path in sorted((REPO / "reporting").glob("*.py")):
        try:
            found.update(_HELPER_WRITE_RE.findall(path.read_text(encoding="utf-8")))
        except OSError:
            continue
    return found


def _json_artifacts() -> set[str]:
    """Only JSON is a self-scan input. PDFs and XLSX are not parsed as source."""
    return {n for n in _written_artifacts() if n.lower().endswith(".json")}


_CLI_DEFAULT_RE = re.compile(r'add_argument\(\s*"--output"[^)]*default\s*=\s*"([^"]+)"')


def _cli_default_outputs() -> set[str]:
    """Default `--output` names of the standalone scanner CLIs.

    These are real artifacts even though no `output_dir / "..."` write site
    produces them, so an exclusion list that omitted them would be correct about
    main.py and wrong about the tool as a whole.
    """
    found: set[str] = set()
    for path in (REPO / "scanner").glob("*.py"):
        try:
            found.update(_CLI_DEFAULT_RE.findall(path.read_text(encoding="utf-8")))
        except OSError:
            continue
    return {n.lower() for n in found}


def test_write_sites_are_discovered():
    """Guard against the discovery regex silently matching nothing.

    A test that passes because it inspected an empty set is worse than no test.
    Both the main.py pass and the helper-module pass must fire: the helper pass
    is what keeps reporting/-written artifacts (webhook JSONs) visible.
    """
    found = _written_artifacts()
    assert len(found) >= 10, (
        f"only found {len(found)} output_dir write sites: {sorted(found)}. "
        "The discovery pattern no longer matches main.py."
    )
    assert "clean_report.json" in found
    assert "Security_Findings_Webhook.json" in found, (
        "the helper-module discovery pass found no webhook artifacts -- the "
        "reporting/ write sites are invisible to the exclusion checks again"
    )
    assert "Security_DefectDojo_Import.json" in found


def test_every_written_json_artifact_is_excluded_from_self_scan():
    """The self-scan hazard, asserted rather than assumed."""
    excluded = {str(n).lower() for n in EXCLUDED_FILES}
    missing = sorted(n for n in _json_artifacts() if n.lower() not in excluded)

    assert not missing, (
        "these artifacts are written into the scanned directory but are not in "
        f"scanner.sast.EXCLUDED_FILES, so a re-scan reads them as input: {missing}"
    )


def test_exclusions_actually_take_effect():
    """EXCLUDED_FILES membership alone does not prove the exclusion fires.

    This asserts the behaviour of the predicate, because the set and the
    predicate are separate code paths and only one of them has been wrong before.
    """
    for name in _json_artifacts():
        path = pathlib.Path("C:/any/scan/output") / name
        assert is_excluded(path), f"{name} is listed but is_excluded() returns False"


def test_source_files_are_not_excluded():
    """The exclusion must not be so broad that real source stops being scanned."""
    for name in ("main.py", "scanner/sast.py", "package.json", "app.ts"):
        assert not is_excluded(pathlib.Path("C:/proj") / name), (
            f"{name} is real scanned input and must not be excluded"
        )


def test_excluded_set_has_no_duplicates():
    """A set literal hides duplicates; a list would not.

    Comments inside the literal are stripped first, because the block quotes
    filenames when explaining them -- counting those as members would report
    documentation as duplication.
    """
    counts = Counter()
    source = (REPO / "scanner" / "sast.py").read_text(encoding="utf-8")
    block = source.split("EXCLUDED_FILES = {", 1)[1].split("}", 1)[0]
    code = re.sub(r"#.*", "", block)
    for token in re.findall(r'"([^"]+)"', code):
        counts[token.lower()] += 1

    dupes = [n for n, c in counts.items() if c > 1]
    assert not dupes, f"EXCLUDED_FILES lists these more than once: {dupes}"


# Names with no producer anywhere in this codebase: nothing writes them, in any
# module, by any pattern. They are RETAINED rather than removed, because an
# exclusion for an artifact nothing currently produces costs nothing, whereas
# removing one that some external build or older report stage does produce lets the
# scanner read a generated report back as source. A false negative in a security
# tool is worse than a stale entry.
#
# Pinned so that a genuinely NEW stale entry -- one added by mistake -- still fails
# here, and so that promoting one of these to a real artifact does not.
_LEGACY_UNPRODUCED_ARTIFACTS = {
    "bom.json",
    "qbom.json",
    "sarif.json",
    "sbom.json",
    "scan_manifest.json",
}


def test_every_exclusion_entry_is_a_known_artifact():
    """No exclusion may be stale for an unknown reason.

    Entries may name an artifact written by main.py's report stage or by a
    standalone scanner CLI (`scanner/aibom.py --output aibom.json`), so both
    sources are consulted. Anything neither produces must be in the pinned legacy
    list above, with its reason recorded -- otherwise the set silently accumulates
    entries that look protective while matching nothing, which is how
    `Security_QBOM.qbom.json` went unexcluded while `qbom.json` sat there
    appearing to cover it.
    """
    known = {n.lower() for n in _written_artifacts()} | _cli_default_outputs()
    unexplained = sorted(
        n for n in (str(x).lower() for x in EXCLUDED_FILES)
        if n not in known and n not in _LEGACY_UNPRODUCED_ARTIFACTS
    )
    assert not unexplained, (
        f"EXCLUDED_FILES lists names no artifact producer writes and that are not "
        f"in _LEGACY_UNPRODUCED_ARTIFACTS: {unexplained}. Either the artifact was "
        "renamed or the entry is stale."
    )


def test_legacy_exclusions_are_still_legacy():
    """If one of these becomes a real artifact, promote it and re-check it.

    Without this the pinned list would quietly become a place to hide entries that
    should have been cleaned up.
    """
    known = {n.lower() for n in _written_artifacts()} | _cli_default_outputs()
    promoted = sorted(_LEGACY_UNPRODUCED_ARTIFACTS & known)
    assert not promoted, (
        f"these are now genuinely produced artifacts, so they belong in the real "
        f"write-site set rather than the legacy allowlist: {promoted}"
    )


def test_taint_engine_artifact_list_agrees_with_sast():
    """Two exclusion lists exist and they had drifted.

    `scanner/taint_engine.py` keeps its own ARTIFACT_FILE_NAMES. It was missing
    `qbom.json` and every prefixed artifact, so the taint engine would have read a
    generated report as a source file while the SAST scanner correctly skipped it.
    """
    from scanner.taint_engine import ARTIFACT_FILE_NAMES

    assert set(ARTIFACT_FILE_NAMES) == set(EXCLUDED_FILES), (
        "the two self-scan exclusion lists differ: "
        f"only in sast={sorted(set(EXCLUDED_FILES) - set(ARTIFACT_FILE_NAMES))}, "
        f"only in taint={sorted(set(ARTIFACT_FILE_NAMES) - set(EXCLUDED_FILES))}"
    )