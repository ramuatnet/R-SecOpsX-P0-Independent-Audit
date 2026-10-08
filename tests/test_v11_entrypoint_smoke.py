"""End-to-end smoke test: the entrypoint must actually run.

WHY THIS EXISTS
---------------
A defect was introduced where `payload["sbom_advisory_status"] = ...` was placed
before `payload` existed -- it is built much later by `build_report_payload()`. The
result was `UnboundLocalError` on every single scan: rc=1, no artifact, nothing but
a traceback.

It passed:
  - the compile gate (183 files, 0 failures) -- `payload` is a valid local name
  - all 1046 unit tests -- none of them execute main()

Both gates are necessary and neither is sufficient. The class of defect is "the
entrypoint is broken and nothing notices", and the only thing that catches it is
running the entrypoint.

This is deliberately a subprocess test with no mocking. A mocked test of main()
proves the wiring compiles, not that the wiring runs.

Runtime is kept low with --no-pdf and --no-excel; the point is control flow, not
renderers. PDF and XLSX have their own coverage.
"""
from __future__ import annotations

import json
import pathlib
import subprocess
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
MAIN = REPO / "main.py"


@pytest.fixture(scope="module")
def tiny_project(tmp_path_factory) -> pathlib.Path:
    """The smallest project that still exercises SBOM, CBOM and the report path."""
    project = tmp_path_factory.mktemp("smoke_proj")
    (project / "app.py").write_text(
        "import hashlib\n"
        "\n"
        "API_KEY = 'sk-live-0000000000000000000000000000abcd'\n"
        "\n"
        "def handler(request):\n"
        "    h = hashlib.md5(request.args['q'].encode()).hexdigest()\n"
        "    import subprocess\n"
        "    subprocess.call('ls ' + request.args['q'], shell=True)\n"
        "    return h\n",
        encoding="utf-8",
    )
    (project / "requirements.txt").write_text(
        "requests==2.31.0\n", encoding="utf-8")
    return project


@pytest.fixture(scope="module")
def scan_result(tiny_project, tmp_path_factory):
    outdir = tmp_path_factory.mktemp("smoke_out")
    proc = subprocess.run(
        [sys.executable, str(MAIN), str(tiny_project),
         "--output", str(outdir), "--no-pdf", "--no-excel", "--workers", "2"],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        cwd=str(REPO), timeout=1800,
    )
    return proc, outdir


def test_entrypoint_exits_zero(scan_result):
    """An UnboundLocalError, a bad import or a missing file must fail here."""
    proc, _ = scan_result

    assert proc.returncode == 0, (
        f"main.py exited {proc.returncode}.\n"
        f"--- stdout tail ---\n{(proc.stdout or '')[-3000:]}\n"
        f"--- stderr tail ---\n{(proc.stderr or '')[-3000:]}"
    )


def test_entrypoint_writes_its_artifact(scan_result):
    """rc=0 is not sufficient: an entrypoint can exit cleanly writing nothing."""
    _proc, outdir = scan_result
    artifact = outdir / "clean_report.json"

    assert artifact.exists(), (
        f"rc=0 but no clean_report.json in {outdir}: "
        f"{sorted(p.name for p in outdir.iterdir())}"
    )

    payload = json.loads(artifact.read_text(encoding="utf-8"))
    assert payload.get("findings") is not None
    assert "metadata" in payload


def test_every_qbom_layer_is_written(scan_result):
    """Both QBOM artifacts, because they are separate layers and both are gated."""
    _proc, outdir = scan_result

    for name in ("Security_QBOM.qbom.json", "Security_QBOM.pq.json"):
        assert (outdir / name).exists(), f"{name} was not written"


def test_advisory_disclosure_reaches_the_artifact(scan_result):
    """The field that motivated this test must survive into the payload.

    Placed where `payload` does not exist yet, it crashed every scan while the
    compile gate and every unit test stayed green.
    """
    _proc, outdir = scan_result
    payload = json.loads(
        (outdir / "clean_report.json").read_text(encoding="utf-8"))

    assert "sbom_advisory_status" in payload, (
        "the advisory disclosure is missing from the payload, so a report cannot "
        "distinguish 'no known CVEs' from 'the CVE database was unreachable'"
    )
    status = payload["sbom_advisory_status"]
    assert "available" in status
    assert status.get("disclosure")


def test_pq_qbom_reaches_the_payload_and_classifies(scan_result):
    """The PQ layer must carry classified assets, not just an empty shell.

    Asserting that the file exists would pass even if every classification were
    dropped on the way to disk -- which is what happened once already, with an
    attack-path renderer that produced a plausible empty Chain.
    """
    _proc, outdir = scan_result
    payload = json.loads(
        (outdir / "clean_report.json").read_text(encoding="utf-8"))

    assert "qbom_pq" in payload, "payload['qbom_pq'] was never written"
    pq = payload["qbom_pq"]

    assert pq["bom_type"] == "PQ_QBOM"
    assert "classification_rules" in pq
    assert "exposure_summary" in pq

    summary = pq["exposure_summary"]
    for field in ("total_usage_sites", "total_assets", "classified",
                  "unclassified", "by_quantum_status"):
        assert field in summary, f"exposure_summary is missing {field}"


def test_table8_cryptographic_asset_carries_data_not_a_pointer(scan_result):
    """The Table 8 element must carry classified assets, not a cross-reference.

    This element used to read `{"reference": "see the CBOM artifact", "table":
    "Table 9"}` while being marked OBSERVABLE_FROM_SOURCE -- claiming coverage and
    saying nothing, which is worse than marking it not-observable because a reader
    counts it as covered. A file-exists check cannot see that; only inspecting the
    element's contents can.
    """
    _proc, outdir = scan_result
    payload = json.loads(
        (outdir / "clean_report.json").read_text(encoding="utf-8"))

    element = payload["qbom"]["minimum_elements"]["cryptographic_asset"]["value"]

    assert isinstance(element, dict), "the element must be a populated object"
    assert "total_assets_in_cbom" in element
    assert "classification_coverage" in element
    assert "by_quantum_status" in element
    assert "assets" in element

    # The old shape had exactly one key. Its absence is the regression guard.
    assert "reference" not in element, (
        "the element reverted to a cross-reference to the CBOM artifact"
    )


def test_scan_detects_the_seeded_weak_hash(scan_result):
    """The smoke project seeds an MD5 use. If nothing is detected, the 'rc=0'
    assertion above is satisfied by a scanner that does not work."""
    _proc, outdir = scan_result
    payload = json.loads(
        (outdir / "clean_report.json").read_text(encoding="utf-8"))

    findings = payload.get("findings") or []
    assert findings, "the scanner produced no findings at all"

    blob = json.dumps(findings).lower()
    assert "md5" in blob, "the seeded MD5 use was not reported"