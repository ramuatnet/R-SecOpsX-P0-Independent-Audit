"""Tests for the requirements-parser crash and the WSTG catalogue.

The sbom fix matters because the failure was not a degraded result, it was NO
result: `pkgs.append` sat outside its `if m:` guard, so a local-path requirement
(`/autogen_python/packages/autogen-core`) raised AttributeError, propagated out of
`generate_sbom`, and aborted the whole scan with rc=1 and no artifact. Four
requirements files in autogen-main trigger it.

The negative tests are the important ones. The obvious "fix" -- skip unmatched
lines -- would let the scan complete while silently dropping 12 declared
dependencies from the SBOM, which is worse than the crash because it looks
handled. These tests require the local reference to be RECORDED.
"""
from __future__ import annotations

import pathlib
import sys
import tempfile

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core import wstg_mappings as W  # noqa: E402
from scanner.sbom import (  # noqa: E402
    _LOCAL_REQUIREMENT_RE,
    _parse_requirements,
    requirements_unparsed_count,
)

AUTOGEN = pathlib.Path(
    r"D:\Data\Code test\prodtest\AI Benchmarks\autogen-main")


# ===========================================================================
# The crash
# ===========================================================================

def _write(text: str) -> str:
    fd, path = tempfile.mkstemp(suffix=".txt")
    with open(fd, "w", encoding="utf-8") as fh:
        fh.write(text)
    return path


@pytest.mark.parametrize("line", [
    "/autogen_python/packages/autogen-core",
    "./local/pkg",
    "../up/pkg",
    "~/pkg",
    ".",
])
def test_a_local_requirement_does_not_crash_the_parser(line):
    """The regression itself. Each of these previously raised AttributeError."""
    path = _write(f"# comment\n{line}\nrequests==2.31.0\n")
    pkgs = _parse_requirements(path)          # must not raise
    assert len(pkgs) == 2, pkgs


def test_a_local_reference_is_recorded_not_dropped():
    """NEGATIVE and load-bearing.

    Skipping the line would let the scan finish while a declared dependency
    vanished from the SBOM. A missing SBOM entry is indistinguishable downstream
    from an absent dependency.
    """
    path = _write("/autogen_python/packages/autogen-core\nrequests==2.31.0\n")
    pkgs = _parse_requirements(path)
    local = [p for p in pkgs if p.get("local_reference")]
    assert len(local) == 1, pkgs
    assert local[0]["name"] == "/autogen_python/packages/autogen-core"
    # "unknown" matches how an unresolvable partial pin is already reported.
    assert local[0]["version"] == "unknown"
    # NOT "PyPI": claiming a PyPI identity for a filesystem path fabricates a
    # package that does not exist.
    assert local[0]["ecosystem"] == "local"
    assert local[0]["manifest_line"] == 1


@pytest.mark.parametrize("text,expect", [
    ("/abs/path\n", True),
    ("./rel\n", True),
    ("../up\n", True),
    ("~/home\n", True),
    (".\n", True),
    ("C:/Users/x\n", True),
    ("git+https://github.com/a/b.git\n", True),
    ("file:///tmp/p\n", True),
    ("requests>=2.31.0\n", False),
    ("Django==4.2\n", False),
    ("autogen-ext[openai]>=0.5.4\n", False),
])
def test_local_reference_classification(text, expect):
    got = bool(_LOCAL_REQUIREMENT_RE.match(text.strip()))
    assert got is expect, text


def test_ordinary_pinned_packages_are_unaffected():
    path = _write("requests==2.31.0\nDjango~=4.2\nnumpy>=1.24,<2\n")
    pkgs = _parse_requirements(path)
    assert [p["name"] for p in pkgs] == ["requests", "Django", "numpy"]
    assert all(p["ecosystem"] == "PyPI" for p in pkgs)
    assert all(not p.get("local_reference") for p in pkgs)
    assert pkgs[0]["version"] == "2.31.0"


def test_extras_and_comments_are_still_stripped():
    path = _write("# comment\n-r other.txt\n-e .\nflask[async]==3.0.0\n")
    pkgs = _parse_requirements(path)
    assert [p["name"] for p in pkgs] == ["flask"], pkgs


def test_malformed_line_does_not_abort_the_remaining_file():
    """Fail open per line: a bad line must not cost the good ones."""
    path = _write("\x00\x01binary\nrequests==2.31.0\nDjango==4.2\n")
    pkgs = _parse_requirements(path)
    assert len(pkgs) >= 2, pkgs


def test_empty_manifest_is_safe():
    path = _write("")
    assert _parse_requirements(path) == []


def test_unparsed_counter_is_a_function_not_a_dead_name():
    """NEGATIVE: it exists so an unmodelled line is visible, not hidden."""
    assert isinstance(requirements_unparsed_count(), int)


# ===========================================================================
# Against the real corpus
# ===========================================================================

@pytest.mark.skipif(not AUTOGEN.exists(), reason="corpus not present")
def test_every_autogen_requirements_file_parses_without_raising():
    files = sorted(AUTOGEN.rglob("requirements*.txt"))
    assert files, "corpus layout changed"
    crashes = []
    local = 0
    for f in files:
        try:
            local += sum(1 for p in _parse_requirements(str(f))
                         if p.get("local_reference"))
        except Exception as exc:                                # noqa: BLE001
            crashes.append((f.name, type(exc).__name__))
    assert not crashes, crashes
    assert local > 0, "the local references autogen declares must be recorded"


# ===========================================================================
# WSTG: the claims it must not make
# ===========================================================================

def test_wstg_catalogue_is_pinned_and_complete():
    assert W.WSTG_VERSION == "v4.2"
    assert len(W.WSTG_CATALOGUE_SHA256) == 64
    assert len(W.WSTG_TEST_CASES) == 97
    assert len(W.WSTG_CATEGORIES) == 12
    assert all(c.startswith("WSTG-") for c in W.WSTG_TEST_CASES)


def test_wstg_status_disclaims_performing_the_tests():
    """NEGATIVE and load-bearing: WSTG is a testing guide.

    A report implying "tested per WSTG" would be false -- this tool performs static
    source analysis, and most WSTG cases need a running application.
    """
    blob = " ".join([W.WSTG_STATUS, W.WSTG_SEMANTICS]).lower()
    assert "testing guide" in blob
    assert "does not mean" in blob or "not a claim" in blob


def test_wstg_licence_is_not_guessed():
    """The checkout has no LICENSE file. Asserting CC BY-SA as was done for ASVS,
    or CC BY as for SANS, would have been an invention."""
    assert W.WSTG_LICENSE.startswith("UNVERIFIED")
    assert "WSTG_LICENCE_GAP" in dir(W)


def test_not_static_attestable_cases_are_declared_not_counted():
    total = len(W.WSTG_TEST_CASES)
    static = len(W.WSTG_STATIC_ATTESTABLE_IDS)
    assert static == 72
    assert total - static == 25 or total - static >= 20
    assert W.WSTG_NOT_STATIC_ATTESTABLE
    for wid, why in W.WSTG_NOT_STATIC_ATTESTABLE.items():
        assert wid in W.WSTG_TEST_CASES, wid
        assert why and len(why) > 10, wid


def test_every_mapping_target_exists_in_the_catalogue():
    for rid, entry in W.WSTG_BY_RULE_ID.items():
        assert entry["case"] in W.WSTG_TEST_CASES, (rid, entry["case"])
        assert entry["mode"] in {W.DIRECT, W.RELATED}, rid
        assert entry["rationale"] and len(entry["rationale"]) > 15, rid


def test_xxe_does_not_claim_a_dedicated_wstg_case_exists():
    """WSTG v4.2 has no XXE case. It maps RELATED to the XML-injection case with
    a rationale saying so, rather than inventing WSTG-XXE-nn."""
    spec = next(k for k, v in W.WSTG_BY_RULE_ID.items() if "XXE" in v["case"]
                or k == "JAVA_XXE_PARSER")
    entry = W.WSTG_BY_RULE_ID[spec]
    assert entry["mode"] == W.RELATED
    assert "no dedicated XXE test case" in entry["rationale"]


def test_cookie_rule_maps_to_the_cookie_attribute_case():
    ref = W.wstg_reference("JAVA_WEB_COOKIE_MISSING_SECURITY_FLAGS")
    assert ref["wstg_case"] == "WSTG-SESS-02"
    assert ref["wstg_mapping_mode"] == W.DIRECT
    assert ref["wstg_static_attestable"] is True


def test_unmapped_wstg_does_not_claim_conformance():
    ref = W.wstg_reference("SOME_UNKNOWN_RULE")
    assert ref["wstg_mapping_mode"] == W.UNMAPPED
    assert ref["wstg_case"] == ""
    assert "scope" in ref["wstg_rationale"].lower()


def test_wstg_resolution_fails_closed():
    for bad in ("", None, "   "):
        assert W.wstg_reference(bad)["wstg_mapping_mode"] == W.UNMAPPED


def test_wstg_coverage_states_its_denominators():
    cov = W.wstg_coverage(["JAVA_J5_SQL", "NOPE"])
    assert cov["catalogue_size"] == 97
    assert cov["catalogue_categories"] == 12
    assert cov["catalogue_static_attestable"] == 72
    assert cov["catalogue_not_static_attestable"] == 25
    low = cov["semantics"].lower()
    assert "not conformance" in low
    assert "not a certification score" in low


def test_wstg_is_wired_into_main():
    src = (ROOT / "main.py").read_text(encoding="utf-8")
    assert "wstg_summary" in src
    assert "wstg_mappings" in src


def test_wstg_probes_have_matching_production_sources():
    import re

    from analysis.benchmark_conformance_baseline import STANDARD_BASELINE
    from core.conformance_baseline import production_sources

    sources = production_sources(ROOT)
    std = next(s for s in STANDARD_BASELINE if s["key"] == "WSTG")
    for probe in std["probes"]:
        if probe["kind"] == "artifact":
            continue
        hits = [r for r, t in sources.items() if re.search(probe["pattern"], t)]
        if probe["kind"] == "absent":
            assert not hits, f"{probe['name']} matching {hits} -- vacuous guard"
        else:
            assert hits, f"WSTG probe {probe['name']} matches no production source"