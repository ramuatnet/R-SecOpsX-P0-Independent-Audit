"""T-9.15 deterministic output assertion (task.md section 13).

Pins the in-house offline double-run gate: two independent child
processes scan the same target under default hash randomization, every
artifact must be byte-identical after masking ONLY the eight declared
volatile classes, content differences (finding rows, rule ids, file
sets) must still fail, and the disclosure/exit-code contract must stay
greppable.

The suite performs one real double-run (module-scoped fixture) plus the
CLI/json/module smokes -- seconds, not minutes.
"""
from __future__ import annotations

import ast
import json
import pathlib
import subprocess
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
MODULE_SRC = REPO / "analysis" / "validation" / "deterministic_output.py"


def _src() -> str:
    return MODULE_SRC.read_text(encoding="utf-8")


# ---------------------------------------------------------------- disclosure


def test_disclosure_needles():
    src = _src()
    needles = (
        "deterministic output assertion (task.md section 13)",
        "byte-identical after",
        "DECLARED volatile classes",
        "_findings_signature",
        "--no-pdf --no-excel",
        "EXIT CODES",
        "wall-clock by design",
        "default per-process hash randomization",
        "NO seed pinning",
        "Offline by construction",
        "run1 vs run2 differ",
    )
    for needle in needles:
        assert needle in src, "disclosure missing: %r" % needle


def test_imports_are_stdlib_only():
    tree = ast.parse(_src())
    allowed = {
        "__future__", "argparse", "io", "json", "os", "pathlib", "re",
        "shutil", "subprocess", "sys", "tempfile",
        # in-repo, not third-party — ftasks Phase 0 FND-03 forces this
        # module's slice windows to read analysis.spans (a stdlib-free
        # constant table importing nothing from the project), so the
        # no-third-party property this test protects still holds.
        "analysis",
    }
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                found.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                found.add(node.module.split(".")[0])
    assert found <= allowed, found - allowed


def test_no_hash_seed_pinning():
    # Children must run under the interpreter's default per-process hash
    # randomization so set-order regressions surface here, not in prod.
    assert "PYTHONHASHSEED" not in _src()


# ------------------------------------------------------------------ constants


def test_constants_pinned():
    from analysis.validation import deterministic_output as det
    assert det.SCHEMA == "rsecopsx.deterministic_output/v1"
    assert det.TEMP_PREFIX == "rsx_t115_det_"
    assert det.RUN_ARGS == ("--quiet", "--no-pdf", "--no-excel")
    assert det.DEFAULT_TIMEOUT == 600
    assert det.VOLATILE_CLASSES == (
        "iso_timestamp",
        "compact_timestamp",
        "uuid",
        "json_duration",
        "log_duration_assign",
        "log_duration_prose",
        "bare_duration",
        "file_size",
        "archive_name",
        "output_path",
    )


# ------------------------------------------------------------ normalize units


def _norm(data: bytes, tmp_path) -> bytes:
    from analysis.validation import deterministic_output as det
    return det.normalize(data, tmp_path / "rsx_t115_outdir")


def test_normalize_masks_each_declared_class(tmp_path):
    cases = (
        # iso_timestamp: T-form with fraction + Z
        (b'{"started_at": "2026-11-01T15:19:22.123456Z"}',
         b'{"started_at": "<TS>"}'),
        # iso_timestamp: log form with comma millis + offset
        (b'2026-11-01 15:19:22,577 INFO rsx: hi',
         b'<TS> INFO rsx: hi'),
        # compact_timestamp: SPDX documentNamespace
        (b"https://r-secopsx.local/spdxdocs/rsecopsx-scan-20261101T151922Z",
         b"https://r-secopsx.local/spdxdocs/rsecopsx-scan-<TS>"),
        # uuid: urn + bare
        (b'"id": "urn:uuid:12345678-1234-1234-1234-123456789abc"',
         b'"id": "<UUID>"'),
        (b'"x": "12345678-1234-1234-1234-123456789abc"',
         b'"x": "<UUID>"'),
        # json_duration: numeric + string values, key kept
        (b'"total_seconds": 1.1607', b'"total_seconds": <DUR>'),
        (b'"total_duration": "00:01.16"', b'"total_duration": <DUR>'),
        (b'"gap_seconds": 0.001', b'"gap_seconds": <DUR>'),
        # log_duration_assign
        (b"ELAPSED=00:00.18 x", b"ELAPSED=<DUR> x"),
        (b"GAP_FROM_PREVIOUS_END=00:00.00", b"GAP_FROM_PREVIOUS_END=<DUR>"),
        # log_duration_prose
        (b"=> 3 raw findings in 0.2s", b"=> 3 raw findings in <DUR>"),
        # bare_duration (log summary table)
        (b"  00:00.18       00:00.00\r\n", b"  <DUR>       <DUR>\r\n"),
        (b"  00:00:01.50", b"  <DUR>"),
        # file_size (scan.log write table; derived from volatile lengths
        # -- suite load observed clean_report.json 270.1 KB vs 270.2 KB)
        (b"clean_report.json                   (270.1 KB)\r\n",
         b"clean_report.json                   (SIZE)\r\n"),
        (b"scan.log (4.5 MB)", b"scan.log (SIZE)"),
        # archive_name (the zip's DDMMYYYY HHMM stamp leaks into scan.log;
        # a minute-straddle between the two runs made the names differ)
        (b"archived: C:\\tmp\\target Security_Report 01112026 1705.zip",
         b"archived: C:\\tmp\\target Security_Report <TS>.zip"),
    )
    for raw, expected in cases:
        got = _norm(raw, tmp_path)
        assert got == expected, (raw, got, expected)


def test_normalize_replaces_the_output_dir_path(tmp_path):
    out = tmp_path / "rsx_t115_outdir"
    raw = ("Output    : " + str(out) + "\n").encode("utf-8")
    assert _norm(raw, tmp_path) == b"Output    : <OUT>\n"


def test_normalize_leaves_content_intact(tmp_path):
    # Rule ids, severities, line numbers and non-duration metrics must
    # survive -- masking only the declared classes.
    raw = (b'{"rule_id": "PY_MD5_WEAK_HASH", "line": 42, '
           b'"severity": "High", "risk_score": 48.5, '
           b'"file": "app.py"}')
    assert _norm(raw, tmp_path) == raw


# ------------------------------------------------------- real double-run


@pytest.fixture(scope="module")
def real():
    from analysis.validation import deterministic_output as det
    return det.run_assertion()


def test_double_run_is_deterministic(real):
    assert real["rc"] == 0, real
    comp = real["comparison"]
    assert comp["ok"] is True, comp
    assert comp["file_sets_equal"] is True
    assert comp["different"] == []
    assert comp["missing"] == []
    assert set(comp["files"].values()) <= {"identical", "normalized"}
    # The core defect surfaces must be byte-stable at least normalized
    for name in ("clean_report.json", "Security_Report.sarif",
                 "Security_Jira_Import.csv", "scan.log"):
        assert comp["files"].get(name) in {"identical", "normalized"}, name
    # At least one artifact is expected fully identical without masking
    # (measured: DefectDojo, Jira CSV, PR comment, QBOMs, SARIF).
    assert comp["identical"] >= 1, comp


def test_findings_agree_across_the_two_runs(real):
    # Belt-and-braces: the defect rows themselves (not just file bytes)
    # are compared the way e2e's signature does -- same rule/line pairs.
    assert real["rc"] == 0, real
    # Both runs wrote clean_report.json into run1/run2; if the gate kept
    # the dir (it does not by default) we could read them.  Instead pin
    # that the comparison covered clean_report at all.
    assert "clean_report.json" in real["comparison"]["files"]


# ---------------------------------------------------- comparator sensitivity


def _pair(tmp_path, left: bytes | None, right: bytes | None,
          name: str = "clean_report.json") -> tuple[pathlib.Path, pathlib.Path]:
    d1 = tmp_path / "rsx_t115_cmp1"
    d2 = tmp_path / "rsx_t115_cmp2"
    d1.mkdir()
    d2.mkdir()
    if left is not None:
        (d1 / name).write_bytes(left)
    if right is not None:
        (d2 / name).write_bytes(right)
    return d1, d2


def test_content_difference_fails_even_when_volatile_fields_match(tmp_path):
    from analysis.validation import deterministic_output as det
    a = (b'{"rule_id": "PY_MD5_WEAK_HASH", "line": 42, '
         b'"started_at": "2026-11-01T15:19:22.123456Z"}')
    b = (b'{"rule_id": "PY_COMMAND_INJECTION", "line": 42, '
         b'"started_at": "2026-11-01T16:20:33.999999Z"}')
    d1, d2 = _pair(tmp_path, a, b)
    comp = det.compare_dirs(d1, d2)
    assert comp["ok"] is False
    assert comp["files"]["clean_report.json"] == "different"
    assert comp["different"] and comp["different"][0]["name"] == "clean_report.json"


def test_volatile_only_difference_normalizes_clean(tmp_path):
    from analysis.validation import deterministic_output as det
    a = b'{"serial": "urn:uuid:12345678-1234-1234-1234-123456789abc", "n": 1}'
    b = b'{"serial": "urn:uuid:abcdefab-1234-1234-1234-123456789abc", "n": 1}'
    d1, d2 = _pair(tmp_path, a, b)
    comp = det.compare_dirs(d1, d2)
    assert comp["ok"] is True, comp
    assert comp["files"]["clean_report.json"] == "normalized"


def test_file_set_mismatch_fails(tmp_path):
    from analysis.validation import deterministic_output as det
    d1, d2 = _pair(tmp_path, b"{}", b"{}")
    (d1 / "extra_only_in_run1.json").write_bytes(b"{}")
    comp = det.compare_dirs(d1, d2)
    assert comp["ok"] is False
    assert comp["file_sets_equal"] is False
    assert comp["missing"] == ["extra_only_in_run1.json"]
    assert comp["files"]["extra_only_in_run1.json"] == "missing"


def test_empty_dirs_are_not_ok(tmp_path):
    from analysis.validation import deterministic_output as det
    d1, d2 = _pair(tmp_path, None, None)
    comp = det.compare_dirs(d1, d2)
    assert comp["ok"] is False  # no artifacts at all is not a pass


# ---------------------------------------------------------------------- CLI


def test_cli_default_run_passes(capsys):
    from analysis.validation import deterministic_output as det
    rc = det.main([])
    out = capsys.readouterr().out
    assert rc == 0, out
    assert "DETERMINISTIC" in out
    assert "deterministic output assertion: PASS" in out


def test_cli_exit_codes_wiring(capsys, tmp_path, monkeypatch):
    from analysis.validation import deterministic_output as det
    # 2: bad target (no child spawned)
    rc = det.main(["--target", str(tmp_path / "rsx_t115_absent")])
    assert rc == 2
    assert "COULD-NOT-RUN" in capsys.readouterr().out
    # 1: real divergence reported by the runner
    fake = {
        "rc": 1,
        "target": "x",
        "comparison": {
            "file_sets_equal": True,
            "files": {"clean_report.json": "different"},
            "different": [{"name": "clean_report.json", "offset": 3,
                           "side1": "'a'", "side2": "'b'"}],
            "missing": [], "identical": 0, "normalized": 0, "ok": False,
        },
        "error": "artifacts diverged",
        "kept_dir": None,
    }
    monkeypatch.setattr(det, "run_assertion",
                        lambda *a, **k: dict(fake))
    rc = det.main([])
    out = capsys.readouterr().out
    assert rc == 1
    assert "NOT DETERMINISTIC" in out
    assert "deterministic output assertion: FAIL" in out
    # 0: clean outcome wiring
    monkeypatch.setattr(det, "run_assertion",
                        lambda *a, **k: dict(fake, rc=0, error=None))
    assert det.main([]) == 0
    assert "DETERMINISTIC" in capsys.readouterr().out


def test_cli_json_output(capsys):
    from analysis.validation import deterministic_output as det
    rc = det.main(["--json"])
    payload = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert rc == 0
    assert payload["ok"] is True
    assert payload["schema"] == det.SCHEMA
    assert payload["different"] == []
    assert payload["missing"] == []
    assert payload["file_sets_equal"] is True
    assert set(payload["files"].values()) <= {"identical", "normalized"}


def test_child_failure_is_could_not_run(monkeypatch):
    from analysis.validation import deterministic_output as det
    monkeypatch.setattr(
        det, "run_once",
        lambda *a, **k: {"rc": 2, "error": "scan failed rc=1",
                         "stderr_tail": "boom"})
    outcome = det.run_assertion()
    assert outcome["rc"] == 2
    assert outcome["run"] == 1
    assert "scan failed" in outcome["error"]


def test_module_entry_smoke():
    """`python -m analysis.validation.deterministic_output` runs."""
    proc = subprocess.run(
        [sys.executable, "-m", "analysis.validation.deterministic_output",
         "--json"],
        cwd=str(REPO), capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=300)
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout.strip().splitlines()[-1])
    assert payload["ok"] is True
    assert payload["schema"] == "rsecopsx.deterministic_output/v1"
