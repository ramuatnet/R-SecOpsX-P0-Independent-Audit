"""T-14.3 (task.md section 14 "Observability"): structured scan telemetry.

task.md section 14:

    **Observability:** structured scan telemetry (stage timings, drop
    counts, regex timeouts).

The three ingredients already existed in fragments -- stage timings in
_SCAN_TIMING / Scan_Performance.json, drop counts behind --explain-drops,
regex budget in metadata.regex_budget (breach-only) -- but no single
structured artifact carried all three. --telemetry writes telemetry.json
beside clean_report.json with schema rsecopsx.scan_telemetry/v1: scan
header, stage rows, drop summary counts, regex budget metadata.

Flag-off is invariant (drops/verdicts precedent): no telemetry.json and
no payload key without the flag -- stage timings are wall-clock, so an
unconditional write would add a nondeterministic file to every output
dir. The artifact is written via output_dir / "telemetry.json", so the
dual self-scan exclusion (file_index.EXCLUDED_FILES +
taint_engine.ARTIFACT_FILE_NAMES) ships in the same batch.

Disclosure: telemetry.json carries wall-clock durations by design; the
t115 deterministic-output double-run runs flag-off (RUN_ARGS), so the
artifact is outside that contract -- disclosed, not silently assumed.
"""
from __future__ import annotations

import json
import pathlib
import subprocess
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

MAIN = REPO / "main.py"
TELEMETRY_SRC = REPO / "core" / "telemetry.py"


# ---------------------------------------------------------------------------
# 1. disclosure needles (the greppable contract)
# ---------------------------------------------------------------------------
def test_disclosure_needles_in_main():
    src = MAIN.read_text(encoding="utf-8")
    for needle in (
        "T-14.3",
        "--telemetry",
        "telemetry.json",
        "section 14",
    ):
        assert needle in src, "main.py telemetry disclosure missing: %r" % needle


def test_disclosure_needles_in_module():
    src = TELEMETRY_SRC.read_text(encoding="utf-8")
    for needle in (
        "T-14.3",
        "stage timings",
        "drop counts",
        "regex timeouts",
        "rsecopsx.scan_telemetry/v1",
    ):
        assert needle in src, (
            "core/telemetry.py disclosure missing: %r" % needle)


# ---------------------------------------------------------------------------
# 2. builder: schema, sections, passthrough, defensive edges
# ---------------------------------------------------------------------------
def test_schema_constant():
    from core.telemetry import TELEMETRY_SCHEMA
    assert TELEMETRY_SCHEMA == "rsecopsx.scan_telemetry/v1"


def _scan_timing_fixture() -> dict:
    return {
        "started_at": "2026-11-02 10:00:00.000",
        "completed_at": "2026-11-02 10:00:05.000",
        "total_seconds": 5.0,
        "total_duration": "00:05.00",
        "stages": [
            {"stage": "Walk", "start_at": "a", "end_at": "b",
             "seconds": 1.5, "gap_seconds": 0.0},
            {"stage": "Scan", "start_at": "c", "end_at": "d",
             "seconds": 3.25, "gap_seconds": 0.1},
        ],
    }


def _drops_fixture() -> dict:
    return {
        "total_findings_removed": 2,
        "by_pass": {"noise_filter": 2},
        "by_decision": {"suppressed": 2},
        "occurrence_drops_on_reported_findings": 0,
    }


def _regex_fixture() -> dict:
    return {
        "budget_ms": 250,
        "checks": 10,
        "total_ms": 12.3,
        "timeouts": [
            {"rule_id": "PY_CMD_INJECTION", "file": "a.py",
             "budget_ms": 250, "mode": "finditer"},
        ],
    }


def test_build_document_shape_and_passthrough():
    from core.telemetry import TELEMETRY_SCHEMA, build_document
    doc = build_document(_scan_timing_fixture(), _drops_fixture(),
                         _regex_fixture())
    assert doc["schema"] == TELEMETRY_SCHEMA
    scan = doc["scan"]
    assert scan["started_at"] == "2026-11-02 10:00:00.000"
    assert scan["completed_at"] == "2026-11-02 10:00:05.000"
    assert scan["total_seconds"] == 5.0
    assert scan["total_duration"] == "00:05.00"
    assert [s["stage"] for s in doc["stages"]] == ["Walk", "Scan"]
    assert doc["stages"][1]["seconds"] == 3.25
    assert doc["drops"] == _drops_fixture()
    assert doc["regex"] == _regex_fixture()
    assert doc["regex"]["timeouts"][0]["rule_id"] == "PY_CMD_INJECTION"


def test_build_document_empty_inputs_still_valid():
    from core.telemetry import TELEMETRY_SCHEMA, build_document
    doc = build_document({}, {}, {})
    assert doc["schema"] == TELEMETRY_SCHEMA
    assert doc["stages"] == []
    assert doc["drops"] == {}
    assert doc["regex"] == {}
    assert doc["scan"]["total_seconds"] is None
    # never raises on absent stage lists (sbom-ingest edge)
    doc2 = build_document({"stages": None}, None, None)
    assert doc2["stages"] == []


def test_non_dict_stage_rows_are_annotated_not_crashed():
    # Ground rule 3 (no silent drops): a junk stage row is skipped WITH a
    # machine-readable count, never deleted silently and never a crash.
    from core.telemetry import build_document
    doc = build_document({"stages": [{"stage": "Ok"}, "junk", None]},
                         {}, {})
    assert [s["stage"] for s in doc["stages"]] == ["Ok"]
    assert doc["scan"]["stages_skipped_not_objects"] == 2


def test_document_is_byte_identical_across_builds():
    import copy
    from core.telemetry import build_document
    args = (_scan_timing_fixture(), _drops_fixture(), _regex_fixture())
    d1 = build_document(*args)
    d2 = build_document(*copy.deepcopy(args))
    assert (json.dumps(d1, sort_keys=True, default=str)
            == json.dumps(d2, sort_keys=True, default=str))


# ---------------------------------------------------------------------------
# 3. CLI wiring (source pins -- the e2e scans below prove the runtime)
# ---------------------------------------------------------------------------
def test_cli_flag_declared():
    src = MAIN.read_text(encoding="utf-8")
    assert '"--telemetry"' in src, "--telemetry flag not declared"
    assert 'dest="telemetry"' in src, "argparse dest not wired"
    assert "args.telemetry" in src, "flag never consumed"


# ---------------------------------------------------------------------------
# 4. self-scan dual exclusion (write site + both lists, same batch)
# ---------------------------------------------------------------------------
def test_telemetry_json_excluded_from_self_scan():
    from core.file_index import EXCLUDED_FILES
    from scanner.taint_engine import ARTIFACT_FILE_NAMES
    assert "telemetry.json" in EXCLUDED_FILES
    assert "telemetry.json" in ARTIFACT_FILE_NAMES
    assert set(ARTIFACT_FILE_NAMES) == set(EXCLUDED_FILES)


# ---------------------------------------------------------------------------
# 5. e2e: flag on writes the artifact; flag off writes nothing
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module")
def scan_with_flag(tmp_path_factory):
    proj = tmp_path_factory.mktemp("rsx_t1403_proj_on")
    (proj / "vuln.py").write_text(
        "import subprocess\n"
        "def handler(request):\n"
        "    subprocess.call('ls ' + request.args['q'], shell=True)\n",
        encoding="utf-8")
    outdir = tmp_path_factory.mktemp("rsx_t1403_out_on")
    proc = subprocess.run(
        [sys.executable, str(MAIN), str(proj),
         "--output-dir", str(outdir), "--no-pdf", "--no-excel",
         "--telemetry", "--workers", "1"],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        cwd=str(REPO), timeout=1800,
    )
    return proc, outdir


@pytest.fixture(scope="module")
def scan_without_flag(tmp_path_factory):
    proj = tmp_path_factory.mktemp("rsx_t1403_proj_off")
    (proj / "vuln.py").write_text(
        "import subprocess\n"
        "def handler(request):\n"
        "    subprocess.call('ls ' + request.args['q'], shell=True)\n",
        encoding="utf-8")
    outdir = tmp_path_factory.mktemp("rsx_t1403_out_off")
    proc = subprocess.run(
        [sys.executable, str(MAIN), str(proj),
         "--output-dir", str(outdir), "--no-pdf", "--no-excel",
         "--workers", "1"],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        cwd=str(REPO), timeout=1800,
    )
    return proc, outdir


def test_cli_scan_exits_zero(scan_with_flag):
    proc, _outdir = scan_with_flag
    assert proc.returncode == 0, (
        f"main.py exited {proc.returncode}.\n"
        f"--- stdout tail ---\n{(proc.stdout or '')[-3000:]}\n"
        f"--- stderr tail ---\n{(proc.stderr or '')[-3000:]}"
    )


def test_cli_writes_telemetry_json(scan_with_flag):
    _proc, outdir = scan_with_flag
    path = outdir / "telemetry.json"
    assert path.exists(), "--telemetry must write telemetry.json"
    doc = json.loads(path.read_text(encoding="utf-8"))
    from core.telemetry import TELEMETRY_SCHEMA
    assert doc["schema"] == TELEMETRY_SCHEMA
    # all three sections the task names, present on a real scan
    assert isinstance(doc["stages"], list) and doc["stages"], doc["stages"]
    assert "total_seconds" in doc["scan"]
    assert doc["scan"]["total_seconds"] > 0
    assert "total_findings_removed" in doc["drops"]
    assert isinstance(doc["drops"]["by_pass"], dict)
    assert "budget_ms" in doc["regex"]
    assert isinstance(doc["regex"]["checks"], int)
    assert isinstance(doc["regex"]["timeouts"], list)
    # stage rows carry the timing fields
    row = doc["stages"][0]
    for key in ("stage", "start_at", "end_at", "seconds", "gap_seconds"):
        assert key in row, key


def test_cli_flag_off_writes_no_telemetry(scan_without_flag):
    proc, outdir = scan_without_flag
    assert proc.returncode == 0, (
        f"main.py exited {proc.returncode}.\n"
        f"--- stderr tail ---\n{(proc.stderr or '')[-3000:]}"
    )
    assert not (outdir / "telemetry.json").exists(), (
        "without --telemetry no telemetry.json may appear"
    )
    report = json.loads((outdir / "clean_report.json").read_text(
        encoding="utf-8"))
    assert "telemetry" not in report, (
        "flag-off payload must not gain telemetry keys (byte-identity)"
    )
    assert "telemetry" not in (report.get("metadata") or {}), (
        "flag-off metadata must not gain a telemetry key (byte-identity)"
    )
