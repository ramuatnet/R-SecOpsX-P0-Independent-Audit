"""Phase 2: SBOM consume -- reader, ingest CLI mode, quality score, baseline diff.

WHAT IS COVERED AND WHY
-----------------------
Phase 2 closes the "produce only" gap: the tool can now LOAD an SBOM
someone else produced (scanner/sbom_reader.py), run it through the same
enrichment tail as a scan (scanner/sbom.py::finalize_sbom_packages),
score it sbomqs-style (analysis/sbom_quality.py) and diff it against a
previous inventory (scanner/sbom_baseline.py), all wired into main.py as
`--sbom <file>` / `--baseline <file>`.

Contract points that MUST stay asserted:

* membership: an ingested SBOM is authoritative for which components
  exist -- finalize is called with add_transitive=False, our knowledge
  base never invents members in someone else's inventory.
* no source, no findings: ingest mode must produce ZERO findings. The
  engines that walk the target (secrets reads .json!, privacy yields a
  lone scannable file) are skipped with disclosure, not scored as zero.
* identity: baseline diff identity is the VERSIONLESS purl when both
  sides have one (a purl carries its version qualifier -- version must
  never be part of identity), else name+ecosystem wholesale.
* honest scoring: factors that cannot be computed offline are listed in
  `not_covered` / `factors_excluded`, never guessed; the score normalises
  over computable factors only, with scored/total disclosed.
* exit codes: unreadable or unrecognised --sbom input exits 2; a broken
  --baseline degrades to payload["baseline_diff"]["status"] == "error"
  and never fails the run.

The CLI tests are deliberate subprocess runs with no mocking (same
rationale as tests/test_v11_entrypoint_smoke.py): a mocked main() proves
the wiring compiles, not that it runs.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from analysis.sbom_quality import _is_pinned, score_sbom
from scanner.sbom_baseline import diff_baseline, load_baseline
from scanner.sbom_reader import (
    SbomReadError,
    _ecosystem_from_purl,
    ingest_sbom,
    parse_purl,
    read_sbom,
)

REPO = Path(__file__).resolve().parent.parent
MAIN = REPO / "main.py"
FIXTURES = Path(__file__).resolve().parent / "sbom_fixtures"
CDX = FIXTURES / "ingest_cdx_16.json"
SPDX = FIXTURES / "ingest_spdx_23.json"


# ---------------------------------------------------------------------------
# scanner/sbom_reader.py -- purl parsing and ecosystem mapping
# ---------------------------------------------------------------------------

class TestParsePurl:
    def test_full_parts(self):
        parsed = parse_purl("pkg:maven/org.apache.commons/commons-text@1.9")
        assert parsed == {
            "type": "maven",
            "namespace": "org.apache.commons",
            "name": "commons-text",
            "version": "1.9",
        }

    def test_no_namespace(self):
        parsed = parse_purl("pkg:npm/lodash@4.17.15")
        assert parsed["namespace"] == ""
        assert parsed["name"] == "lodash"
        assert parsed["version"] == "4.17.15"

    def test_versionless_purl_does_not_eat_the_name(self):
        # Regression: rpartition("@") on a versionless purl put the whole
        # remainder into `version` and left name empty.
        parsed = parse_purl("pkg:npm/lodash")
        assert parsed["name"] == "lodash"
        assert parsed["version"] == ""

    def test_qualifiers_and_fragment_stripped(self):
        parsed = parse_purl("pkg:pypi/flask@3.0.3?extras=dev#egg")
        assert parsed["name"] == "flask"
        assert parsed["version"] == "3.0.3"

    @pytest.mark.parametrize("value", ["lodash", "", "pkg:", "not-a-purl"])
    def test_garbage_is_empty_parts_not_error(self, value):
        assert parse_purl(value)["type"] == ""
        assert parse_purl(value)["name"] == "" or value == "pkg:"


class TestEcosystemMapping:
    @pytest.mark.parametrize("purl,expected", [
        ("pkg:pypi/flask@3.0.3", "PyPI"),
        ("pkg:npm/lodash@4.17.15", "npm"),
        ("pkg:maven/org.apache.commons/commons-text@1.9", "Maven"),
        ("pkg:cargo/serde@1.0.0", "crates.io"),
        ("pkg:composer/laravel/framework@10.0.0", "Packagist"),
        ("pkg:gem/rails@7.1.0", "RubyGems"),
        ("pkg:nuget/Newtonsoft.Json@13.0.1", "NuGet"),
        ("pkg:golang/github.com/foo/bar@v1.2.3", "Go"),
        # unmapped type passes through verbatim (advisory query then
        # accounts for it under skipped_unresolvable rather than guessing)
        ("pkg:apk/alpine/curl@8.5.0", "apk"),
        ("", "unknown"),
    ])
    def test_maps(self, purl, expected):
        assert _ecosystem_from_purl(purl) == expected


# ---------------------------------------------------------------------------
# scanner/sbom_reader.py -- document parsing
# ---------------------------------------------------------------------------

def test_read_cyclonedx_fixture():
    doc = read_sbom(str(CDX))
    assert doc["format"] == "cyclonedx"
    assert doc["spec_version"] == "1.6"
    assert doc["serial_number"].startswith("urn:uuid:")
    assert doc["created"] == "2026-01-15T10:00:00Z"
    assert doc["tools"] == ["acme-sbom-plugin"]

    by_name = {c["name"]: c for c in doc["components"]}
    assert set(by_name) == {
        "lodash", "flask", "org.apache.commons:commons-text", "internal-widget",
    }

    lodash = by_name["lodash"]
    assert lodash["ecosystem"] == "npm"
    assert lodash["license"] == "MIT"           # {license:{id}} form
    assert lodash["purl"] == "pkg:npm/lodash@4.17.15"
    assert lodash["direct"] is True
    assert lodash["sbom_ref"] == "pkg:npm/lodash@4.17.15"
    assert lodash["ingested_from"].endswith("ingest_cdx_16.json")

    maven = by_name["org.apache.commons:commons-text"]
    assert maven["ecosystem"] == "Maven"
    assert maven["license"] == "Apache-2.0"      # {expression} form
    assert maven["version"] == "1.9"
    # renamed to the group:artifact form the pipeline uses
    assert maven["name"] == "org.apache.commons:commons-text"

    flask = by_name["flask"]
    assert flask["ecosystem"] == "PyPI"
    assert flask["license"] == "BSD-3-Clause"    # {license:{name}} form

    widget = by_name["internal-widget"]
    assert widget["direct"] is False             # scope=excluded
    assert widget["ecosystem"] == "unknown"      # no purl anywhere

    assert len(doc["dependencies"]) == 2
    assert doc["dependencies"][0]["depends_on"] == ["pkg:pypi/flask@3.0.3"]
    assert len(doc["vulnerabilities"]) == 1
    assert doc["vulnerabilities"][0]["id"] == "CVE-2022-42889"
    assert doc["warnings"] == []


def test_read_cyclonedx_16_tool_components_shape(tmp_path):
    """CDX 1.6 encodes metadata.tools as {components: [...]}. Iterating
    that dict as a list would yield the KEY 'components' as a tool name."""
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "metadata": {"tools": {"components": [
            {"name": "trivy", "version": "0.50.0"},
            {"name": "syft", "version": "1.0.0"},
        ]}},
        "components": [{"type": "library", "name": "x", "version": "1.0"}],
    }
    path = tmp_path / "tools16.cdx.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    assert read_sbom(str(path))["tools"] == ["trivy", "syft"]


def test_read_spdx_fixture():
    doc = read_sbom(str(SPDX))
    assert doc["format"] == "spdx"
    assert doc["spec_version"] == "SPDX-2.3"
    assert doc["serial_number"] == "https://example.invalid/spdx/ingest-spdx-sample"
    assert doc["created"] == "2026-01-15T10:00:00Z"
    assert doc["tools"] == ["Tool: acme-sbom-plugin-1.0.0"]

    by_name = {c["name"]: c for c in doc["components"]}
    assert len(by_name) == 3

    flask = by_name["flask"]
    assert flask["ecosystem"] == "PyPI"
    # declared wins over NOASSERTION concluded
    assert flask["license"] == "BSD-3-Clause"
    # DESCRIBES target and DEPENDS_ON subject -> direct
    assert flask["direct"] is True

    lodash = by_name["lodash"]
    assert lodash["license"] == "MIT"            # concluded fallback
    assert lodash["direct"] is False             # only an object of DEPENDS_ON

    maven = by_name["org.apache.commons:commons-text"]
    assert maven["ecosystem"] == "Maven"
    assert maven["cpe"].startswith("cpe:2.3:a:apache:commons-text")
    assert maven["direct"] is False

    assert len(doc["dependencies"]) == 3         # every relationship kept
    assert doc["vulnerabilities"] == []          # SPDX has no VEX section


@pytest.mark.parametrize("content,needle", [
    ("not json at all", "not valid JSON"),
    ('{"foo": 1}', "not a recognised SBOM"),
    ('<?xml version="1.0"?><bom xmlns="http://cyclonedx.org/schema/bom"></bom>',
     "XML"),
    ("spdxVersion: SPDX-2.3\nname: x\n", "YAML"),
    ("[1, 2, 3]", "must be an object"),
])
def test_read_sbom_rejects_unsupported(tmp_path, content, needle):
    path = tmp_path / "input"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(SbomReadError, match=needle):
        read_sbom(str(path))


def test_read_sbom_missing_file(tmp_path):
    with pytest.raises(SbomReadError, match="does not exist"):
        read_sbom(str(tmp_path / "nope.json"))


def test_ingest_never_invents_members(monkeypatch):
    """The ingested SBOM decides WHICH components exist: finalize must be
    called with add_transitive=False (our transitive knowledge base would
    inject version-"unknown" guesses into someone else's inventory)."""
    import scanner.sbom as sbom_mod

    captured = {}

    def fake_finalize(packages, add_transitive=True):
        captured["count"] = len(packages)
        captured["add_transitive"] = add_transitive
        for pkg in packages:
            pkg.setdefault("vulnerabilities", [])
        return packages

    monkeypatch.setattr(sbom_mod, "finalize_sbom_packages", fake_finalize)
    doc = ingest_sbom(str(CDX))
    assert captured == {"count": 4, "add_transitive": False}
    assert len(doc["components"]) == 4


# ---------------------------------------------------------------------------
# analysis/sbom_quality.py -- sbomqs-style scoring
# ---------------------------------------------------------------------------

def _complete_packages():
    return [
        {"name": "a", "version": "1.2.3", "ecosystem": "PyPI",
         "license": "MIT", "purl": "pkg:pypi/a@1.2.3",
         "hashes": [{"alg": "SHA-256", "content": "00" * 32}],
         "supplier": "Acme", "vulnerabilities": []},
        {"name": "b", "version": "2.0.0", "ecosystem": "npm",
         "license": "Apache-2.0", "purl": "pkg:npm/b@2.0.0",
         "hashes": [{"alg": "SHA-256", "content": "11" * 32}],
         "supplier": "Acme", "vulnerabilities": []},
    ]


def test_quality_complete_inventory_scores_full():
    q = score_sbom(
        _complete_packages(),
        doc={"created": "2026-01-15T10:00:00Z", "tools": ["ci"],
             "dependencies": [{"ref": "a", "depends_on": ["b"]}]},
    )
    assert q["score"] == 100.0
    assert q["grade"] == "A"
    assert q["scored_factors"] == q["total_factors"]
    assert q["factors_excluded"] == []
    assert "known_vulnerabilities" in [f["name"] for f in q["factors"]]


def test_quality_advisory_factor_excluded_when_unchecked():
    # advisory_checked=False: a vulnerability count would be a guess.
    q = score_sbom(
        _complete_packages(),
        doc={"created": "2026-01-15T10:00:00Z", "tools": ["ci"],
             "dependencies": [{"ref": "a", "depends_on": ["b"]}]},
        advisory_checked=False,
    )
    assert [f["name"] for f in q["factors_excluded"]] == ["known_vulnerabilities"]
    assert q["scored_factors"] + 1 == q["total_factors"]
    # score normalises over COMPUTABLE factors, with counts disclosed
    assert q["score"] == 100.0
    assert q["scored_factors"] < q["total_factors"]


def test_quality_advisory_auto_detect_is_conservative():
    # Only vuln-having packages carry the key -> mixed presence cannot
    # prove the query ran -> factor excluded (conservative direction).
    pkgs = [
        {"name": "a", "version": "1.0.0",
         "vulnerabilities": [{"id": "GHSA-x"}]},
        {"name": "b", "version": "1.0.0"},
    ]
    q = score_sbom(pkgs)
    assert [f["name"] for f in q["factors_excluded"]] == ["known_vulnerabilities"]


def test_quality_empty_inventory():
    q = score_sbom([])
    assert q["score"] == 0.0
    assert q["grade"] == "F"
    assert "no components" in q["note"]


def test_quality_incomplete_inventory_scores_low_and_discloses():
    q = score_sbom([{"name": "x", "version": "unknown"},
                    {"name": "y", "version": "*"}])
    assert q["score"] < 40
    assert q["grade"] in ("D", "F")
    assert "known_vulnerabilities" in [f["name"] for f in q["factors_excluded"]]
    # sbomqs factors we refuse to guess are disclosed, not silently dropped
    assert any("widely_adopted" in s for s in q["not_covered"])
    assert any("up_to_date_version" in s for s in q["not_covered"])
    assert any("data_fidelity" in s for s in q["not_covered"])


@pytest.mark.parametrize("version,pinned", [
    ("1.2.3", True), ("v1.2.3", True), ("4.17.15", True), ("1.9", True),
    ("1.0.0-beta", True),
    ("^1.2.3", False), ("~1.2", False), ("1.2.x", False),
    (">=1.0", False), ("unknown", False), ("*", False), ("", False),
    ("1.2.3 || 2.0.0", False),
])
def test_is_pinned(version, pinned):
    assert _is_pinned(version) is pinned


# ---------------------------------------------------------------------------
# scanner/sbom_baseline.py -- identity and delta
# ---------------------------------------------------------------------------

def test_diff_purl_identity_is_versionless():
    current = [
        {"name": "flask", "version": "3.0.3", "ecosystem": "PyPI",
         "purl": "pkg:pypi/flask@3.0.3"},
        {"name": "lodash", "version": "4.17.16", "ecosystem": "npm",
         "purl": "pkg:npm/lodash@4.17.16"},
    ]
    baseline = [
        {"name": "flask", "version": "3.0.1", "ecosystem": "PyPI",
         "purl": "pkg:pypi/flask@3.0.1"},
        {"name": "requests", "version": "2.19.1", "ecosystem": "PyPI",
         "purl": "pkg:pypi/requests@2.19.1"},
    ]
    delta = diff_baseline(current, baseline)
    # a version bump is a CHANGE, never a remove+add pair -- the purl's
    # version qualifier is stripped from identity for exactly this reason
    assert delta["summary"] == {
        "added": 1, "removed": 1, "changed": 1,
        "vulnerabilities_new": 0, "vulnerabilities_resolved": 0,
    }
    assert delta["changed"][0] == {
        "name": "flask", "ecosystem": "PyPI",
        "from_version": "3.0.1", "to_version": "3.0.3",
    }
    assert delta["added"][0]["name"] == "lodash"
    assert delta["removed"][0]["name"] == "requests"


def test_diff_falls_back_wholesale_when_one_side_lacks_purl():
    # Mixed identity schemes would never match; the whole diff drops to
    # name+ecosystem (casefolded) instead of silently miscounting.
    current = [{"name": "Flask", "version": "3.0.3", "ecosystem": "PyPI",
                "purl": "pkg:pypi/flask@3.0.3"}]
    baseline = [{"name": "flask", "version": "3.0.1", "ecosystem": "PyPI"}]
    delta = diff_baseline(current, baseline)
    assert delta["summary"]["changed"] == 1
    assert delta["summary"]["added"] == 0
    assert delta["summary"]["removed"] == 0


def test_diff_keeps_same_name_apart_across_ecosystems():
    current = [{"name": "lodash", "version": "1.0.0", "ecosystem": "npm"},
               {"name": "lodash", "version": "2.0.0", "ecosystem": "PyPI"}]
    baseline = [{"name": "lodash", "version": "1.0.0", "ecosystem": "npm"}]
    delta = diff_baseline(current, baseline)
    assert delta["summary"]["added"] == 1
    assert delta["summary"]["changed"] == 0


def test_diff_vulnerability_delta_and_data_flag():
    current = [{"name": "a", "version": "1", "ecosystem": "PyPI",
                "vulnerabilities": [{"id": "CVE-NEW"}, {"id": "CVE-SAME"}]}]
    baseline = [{"name": "a", "version": "1", "ecosystem": "PyPI",
                 "vulnerabilities": [{"id": "CVE-OLD"}, {"id": "CVE-SAME"}]}]
    delta = diff_baseline(current, baseline)
    assert delta["vulnerabilities_new"] == [
        {"package": "a", "version": "1", "id": "CVE-NEW"}]
    assert delta["vulnerabilities_resolved"] == [
        {"package": "a", "version": "1", "id": "CVE-OLD"}]
    assert delta["baseline_had_vulnerability_data"] is True


def test_diff_baseline_without_vuln_data_is_disclosed():
    current = [{"name": "a", "version": "1", "ecosystem": "PyPI",
                "vulnerabilities": [{"id": "CVE-X"}]}]
    delta = diff_baseline(current,
                          [{"name": "a", "version": "1", "ecosystem": "PyPI"}])
    # "no advisories before" vs "no advisories RECORDED before" is the
    # difference this flag exists for
    assert delta["baseline_had_vulnerability_data"] is False
    assert delta["summary"]["vulnerabilities_new"] == 1


def test_load_baseline_accepts_three_shapes(tmp_path):
    # 1. bare package list
    pkgs, desc = load_baseline([{"name": "a"}])
    assert pkgs == [{"name": "a"}]
    assert desc == "package list"

    # 2. previous clean_report.json payload
    report = tmp_path / "clean_report.json"
    report.write_text(
        json.dumps({"sbom": [{"name": "a", "version": "1"}]}),
        encoding="utf-8")
    pkgs, desc = load_baseline(str(report))
    assert pkgs[0]["name"] == "a"
    assert desc.endswith("clean_report.json")

    # 3. raw CycloneDX file: NORMALISED through the reader, never
    #    returned as native component dicts that would not match
    pkgs, _ = load_baseline(str(CDX))
    assert {p["name"] for p in pkgs} == {
        "lodash", "flask", "org.apache.commons:commons-text", "internal-widget"}
    assert all("ingested_from" in p for p in pkgs)


def test_load_baseline_accepts_ingest_document(tmp_path):
    # an already-normalised read_sbom() document written back to disk
    doc = read_sbom(str(CDX))
    path = tmp_path / "ingest_doc.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    pkgs, _ = load_baseline(str(path))
    assert len(pkgs) == 4


def test_load_baseline_error_shapes(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_baseline(str(tmp_path / "missing.json"))

    empty = tmp_path / "empty_obj.json"
    empty.write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="no recognisable inventory"):
        load_baseline(str(empty))

    with pytest.raises(TypeError):
        load_baseline(42)

    # SbomReadError is mapped to ValueError: main.py catches
    # OSError/ValueError/TypeError, not SbomReadError
    garbage = tmp_path / "garbage.json"
    garbage.write_text("this is not json", encoding="utf-8")
    with pytest.raises(ValueError):
        load_baseline(str(garbage))


# ---------------------------------------------------------------------------
# main.py -- `--sbom` / `--baseline` end to end (subprocess, no mocking)
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def ingest_run(tmp_path_factory):
    """One heavy CLI run covering ingest + baseline together."""
    outdir = tmp_path_factory.mktemp("ingest_out")
    baseline = (tmp_path_factory.mktemp("ingest_baseline")
                / "previous_clean_report.json")
    baseline.write_text(json.dumps({"sbom": [
        {"name": "flask", "version": "3.0.1", "ecosystem": "PyPI",
         "purl": "pkg:pypi/flask@3.0.1"},
        {"name": "requests", "version": "2.19.1", "ecosystem": "PyPI",
         "purl": "pkg:pypi/requests@2.19.1"},
        {"name": "lodash", "version": "4.17.15", "ecosystem": "npm",
         "purl": "pkg:npm/lodash@4.17.15"},
    ]}), encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, str(MAIN),
         "--sbom", str(CDX),
         "--baseline", str(baseline),
         "--output-dir", str(outdir),
         "--no-pdf", "--no-excel", "--workers", "1"],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        cwd=str(REPO), timeout=1800,
    )
    report_path = outdir / "clean_report.json"
    report = None
    if report_path.is_file():
        report = json.loads(report_path.read_text(encoding="utf-8"))
    return proc, report, outdir


def test_cli_ingest_exits_zero(ingest_run):
    proc, report, _ = ingest_run
    assert proc.returncode == 0, (
        f"main.py --sbom exited {proc.returncode}\n"
        f"STDOUT tail:\n{proc.stdout[-4000:]}\n"
        f"STDERR tail:\n{proc.stderr[-4000:]}")
    assert report is not None, "clean_report.json was not written"


def test_cli_ingest_report_shape(ingest_run):
    _, report, _ = ingest_run

    assert report["metadata"]["scan_mode"] == "sbom_ingest"
    ingest = report["sbom_ingest"]
    assert ingest["format"] == "cyclonedx"
    assert ingest["spec_version"] == "1.6"
    assert ingest["component_count"] == 4
    assert ingest["declared_vulnerability_records"] == 1
    assert ingest["source_file"].endswith("ingest_cdx_16.json")

    # no source tree -> no SOURCE findings AT ALL: the SBOM document's own
    # bytes must never produce findings (secrets reads .json; privacy
    # yields a lone scannable file). Advisory-derived SCA packages are
    # counted separately under metadata.total_findings by design --
    # payload["findings"] is the source population.
    assert report.get("findings") == []
    assert (report["metadata"].get("severity_distribution_scope")
            == "SAST_findings_plus_unique_vulnerable_dependency_packages")
    # when advisories resolved (network/cache), the vulnerable ingested
    # packages must reach the combined count -- conditional so the test
    # stays deterministic on an offline runner
    if any(p.get("vulnerabilities") for p in report["sbom"]):
        assert report["metadata"]["total_findings"] >= 1
    assert report["reachability_summary"]["status"] == "skipped"
    assert report["privacy_data_exposure_summary"]["summary_status"] == "SKIPPED"

    names = {p["name"] for p in report["sbom"]}
    assert names == {"lodash", "flask", "org.apache.commons:commons-text",
                     "internal-widget"}

    # dependency edges come from the source document, labelled as such
    graph = report["dependency_graph"]
    assert graph["engine"] == "SBOM_INGEST_RELATIONSHIPS"
    assert graph["graph_status"] == "DECLARED_IN_SOURCE_SBOM"
    assert graph["verified_edge_count"] == 1


def test_cli_ingest_quality_and_baseline(ingest_run):
    _, report, _ = ingest_run

    q = report["sbom_quality"]
    assert q["component_count"] == 4
    assert 0.0 <= q["score"] <= 100.0
    assert q["grade"] in list("ABCDF")
    assert q["scored_factors"] + len(q["factors_excluded"]) == q["total_factors"]
    factor_names = [f["name"] for f in q["factors"]]
    assert "ntia_unique_identifier" in factor_names
    assert "license_quality" in factor_names
    assert "strict_pinning" in factor_names
    # not guessed, disclosed
    assert any("widely_adopted" in s for s in q["not_covered"])

    b = report["baseline_diff"]
    # name-identity mode (internal-widget has no purl):
    assert b["summary"]["added"] == 2      # maven lib + internal-widget
    assert b["summary"]["removed"] == 1    # requests
    assert b["summary"]["changed"] == 1    # flask 3.0.1 -> 3.0.3
    assert b["baseline_had_vulnerability_data"] is False
    # summary counts and list lengths never disagree (network-independent)
    assert b["summary"]["vulnerabilities_new"] == len(b["vulnerabilities_new"])
    assert (b["summary"]["vulnerabilities_resolved"]
            == len(b["vulnerabilities_resolved"]))


def test_cli_missing_sbom_file_exits_2(tmp_path):
    proc = subprocess.run(
        [sys.executable, str(MAIN), "--sbom", str(tmp_path / "nope.json"),
         "--no-pdf", "--no-excel"],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        cwd=str(REPO), timeout=600)
    assert proc.returncode == 2
    assert "does not exist" in (proc.stdout + proc.stderr)


def test_cli_invalid_sbom_document_exits_2(tmp_path):
    bad = tmp_path / "not_an_sbom.json"
    bad.write_text(json.dumps({"hello": "world"}), encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, str(MAIN), "--sbom", str(bad),
         "--no-pdf", "--no-excel"],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        cwd=str(REPO), timeout=600)
    assert proc.returncode == 2
    assert "not a recognised SBOM" in (proc.stdout + proc.stderr)
