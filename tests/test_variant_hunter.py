"""T-3.3 variant hunter: transform correctness + one live scan case.

Transform tests are pure text ops on synthetic Python (fast, no scan).
The single end-to-end case scans a tmp shell=True fixture through a
real variant to prove the detection predicate works against the live
engine -- kept to one case so the suite cost stays bounded.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from analysis.validation import variant_hunter as vh


FIXTURE = (
    "from flask import request\n"
    "import os\n"
    "import subprocess\n"
    "\n"
    "def run():\n"
    "    name = request.args.get('name')\n"
    "    os.system('echo ' + name)\n"
    "    subprocess.check_output('ls ' + name, shell=True)\n"
    "\n"
    "def other():\n"
    "    print('hello')\n"
    "    return 1\n"
)
ANCHOR_LINE = 8  # subprocess.check_output(..., shell=True)
EVIDENCE = "subprocess.check_output('ls ' + name, shell=True)"


def _files():
    return {"app.py": FIXTURE}


def test_rename_identifier_changes_symbol_everywhere():
    out = vh.TRANSFORMS["rename_identifier"](_files(), "app.py",
                                              ANCHOR_LINE, EVIDENCE)
    assert out is not None
    assert "import ren_subprocess" in out["app.py"]
    assert "ren_subprocess.check_output" in out["app.py"]
    # Bare occurrences of the old symbol are gone.
    body = out["app.py"].replace("ren_subprocess", "")
    assert "subprocess" not in body


def test_rename_identifier_is_word_boundary_safe():
    # The anchor's first candidate is `output`; a substring replace
    # would corrupt `check_output` into `check_ren_output`.
    files = {"t.py": (
        "def run():\n"
        "    output = check_output('ls', shell=True)\n"
        "    return output\n"
    )}
    out = vh.TRANSFORMS["rename_identifier"](files, "t.py", 2,
                                             "check_output('ls', shell=True)")
    assert out is not None
    body = out["t.py"]
    assert "ren_output = check_output('ls', shell=True)" in body
    assert "return ren_output" in body
    assert "check_ren_output" not in body


def test_extract_to_var_hoists_evidence():
    out = vh.TRANSFORMS["extract_to_var"](_files(), "app.py",
                                          ANCHOR_LINE, EVIDENCE)
    assert out is not None
    # The hoisted line keeps the anchor's indentation (module-scope
    # insert would be a syntax error, not a variant).
    assert "    _variant_tmp = " + EVIDENCE in out["app.py"]
    assert EVIDENCE in out["app.py"]


def test_extract_to_var_inapplicable_when_evidence_absent():
    out = vh.TRANSFORMS["extract_to_var"](_files(), "app.py", 9,
                                          "nothing-matches-this")
    assert out is None


def test_concat_to_fstring_rewrites_concat():
    out = vh.TRANSFORMS["concat_to_fstring"](_files(), "app.py", 7,
                                             "echo ")
    assert out is not None
    assert 'f"echo {name}"' in out["app.py"]
    assert "'echo ' + name" not in out["app.py"]


def test_wrap_in_helper_moves_line_into_def():
    out = vh.TRANSFORMS["wrap_in_helper"](_files(), "app.py",
                                          ANCHOR_LINE, EVIDENCE)
    assert out is not None
    body = out["app.py"]
    assert "def _variant_helper():" in body
    assert "    " + EVIDENCE in body
    assert "\n_variant_helper()\n" in body


def test_move_across_module_splits_files():
    out = vh.TRANSFORMS["move_across_module"](_files(), "app.py",
                                              ANCHOR_LINE, EVIDENCE)
    assert out is not None
    assert "_variant_moved_mod.py" in out
    assert EVIDENCE in out["_variant_moved_mod.py"]
    assert "from _variant_moved_mod import run_moved" in out["app.py"]


def test_add_try_catch_indents_anchor():
    out = vh.TRANSFORMS["add_try_catch"](_files(), "app.py",
                                         ANCHOR_LINE, EVIDENCE)
    assert out is not None
    assert "try:\n    " + EVIDENCE in out["app.py"]
    assert "except Exception:" in out["app.py"]


def test_alias_import_rewrites_module_reference():
    out = vh.TRANSFORMS["alias_import"](_files(), "app.py",
                                        ANCHOR_LINE, EVIDENCE)
    assert out is not None
    assert "import subprocess as subprocess_aliased" in out["app.py"]
    assert "subprocess_aliased.check_output" in out["app.py"]


def test_alias_import_inapplicable_without_import():
    files = {"b.py": "subprocess.check_output('ls', shell=True)\n"}
    out = vh.TRANSFORMS["alias_import"](files, "b.py", 1,
                                        "subprocess.check_output('ls', shell=True)")
    assert out is None


def test_minify_strips_comments_and_blanks():
    out = vh.TRANSFORMS["minify"](_files(), "app.py", ANCHOR_LINE, EVIDENCE)
    assert out is not None
    assert "#" not in out["app.py"]
    assert "\n\n" not in out["app.py"]


def test_reorder_statements_moves_donor_within_block():
    out = vh.TRANSFORMS["reorder_statements"](_files(), "app.py",
                                              ANCHOR_LINE, EVIDENCE)
    assert out is not None
    # The donor must stay in the anchor's block (same indent) and must
    # not be the source assignment the sink reads.
    lines = out["app.py"].splitlines()
    anchor_i = next(i for i, ln in enumerate(lines) if "shell=True" in ln)
    os_i = next(i for i, ln in enumerate(lines) if "os.system" in ln)
    assert os_i == anchor_i + 1  # os.system moved AFTER the anchor
    assert lines[anchor_i - 1].startswith("    ")


def test_reorder_refuses_to_move_the_source():
    # The ONLY other in-block statement defines `name`, which the
    # anchor reads -- moving it would delete the chain.
    files = {"s.py": (
        "def run():\n"
        "    name = get_name()\n"
        "    subprocess.check_output('ls ' + name, shell=True)\n"
    )}
    out = vh.TRANSFORMS["reorder_statements"](files, "s.py", 3,
                                              "subprocess.check_output")
    assert out is None


def test_change_encoding_url_encodes_literal():
    out = vh.TRANSFORMS["change_encoding"](_files(), "app.py",
                                           ANCHOR_LINE, EVIDENCE)
    assert out is not None
    assert "%20" in out["app.py"]


def test_add_sanitizer_wraps_evidence():
    out = vh._t_add_sanitizer(_files(), "app.py", ANCHOR_LINE, EVIDENCE)
    assert out is not None
    assert f"str({EVIDENCE})" in out["app.py"]


def test_transforms_are_registered_and_disclosed():
    assert set(vh.TRANSFORMS) == {
        "rename_identifier", "extract_to_var", "concat_to_fstring",
        "wrap_in_helper", "move_across_module", "add_try_catch",
        "alias_import", "minify", "reorder_statements", "change_encoding",
    }
    assert "inline_var" in vh.TRANSFORMS_NOT_IMPLEMENTED
    assert vh.SANITIZER_PROBE == "add_sanitizer"
    assert vh.SANITIZER_PROBE not in vh.TRANSFORMS


def test_family_hit_prefers_rule_then_cwe():
    findings = [{"rule_id": "PYTHON_SHELL_INJECTION", "cwe": "CWE-78"}]
    assert vh._family_hit(findings, "PYTHON_SHELL_INJECTION", "CWE-999")
    assert vh._family_hit(findings, "OTHER_RULE", "CWE-78")
    assert not vh._family_hit(findings, "OTHER_RULE", "CWE-999")
    assert not vh._family_hit([], "PYTHON_SHELL_INJECTION", "CWE-78")


def test_check_baseline_flags_regression_and_absence(tmp_path, monkeypatch):
    import json

    baseline = {
        "schema": vh.REPORT_SCHEMA,
        "per_rule": {
            "RULE_A": {"stability": 0.9, "applicable": 10, "detected": 9},
            "RULE_B": {"stability": 1.0, "applicable": 5, "detected": 5},
        },
    }
    bpath = tmp_path / "baseline.json"
    bpath.write_text(json.dumps(baseline), encoding="utf-8")
    monkeypatch.setattr(vh, "BASELINE_PATH", bpath)

    report = {"per_rule": {
        "RULE_A": {"stability": 0.8},   # 10pp drop -> fail
        "RULE_B": {"stability": 1.0},   # unchanged
        "RULE_C": {"stability": 0.5},   # new rule -> fail (update baseline)
    }}
    failures = vh.check_baseline(report, tolerance=0.05)
    assert any("RULE_A" in f and "regressed" in f for f in failures)
    assert any("RULE_C" in f and "not in baseline" in f for f in failures)
    assert not any("RULE_B" in f for f in failures)

    # A baseline rule vanishing from the run is also a failure.
    report2 = {"per_rule": {"RULE_A": {"stability": 0.9}}}
    failures2 = vh.check_baseline(report2, tolerance=0.05)
    assert any("RULE_B" in f and "absent" in f for f in failures2)

    # Within tolerance passes.
    report3 = {"per_rule": {
        "RULE_A": {"stability": 0.87},
        "RULE_B": {"stability": 1.0},
    }}
    assert vh.check_baseline(report3, tolerance=0.05) == []

    # Missing baseline file is a loud failure, not a silent pass.
    monkeypatch.setattr(vh, "BASELINE_PATH", tmp_path / "nope.json")
    assert any("baseline missing" in f
               for f in vh.check_baseline(report3, 0.05))


def test_render_markdown_contains_tables_and_fns():
    report = {
        "schema": vh.REPORT_SCHEMA,
        "engine": "py",
        "transforms": ["minify", "rename_identifier"],
        "transforms_not_implemented": ["inline_var"],
        "sanitizer_probe": "add_sanitizer",
        "skipped_non_python_fixtures": 3,
        "baseline_misses": [],
        "transform_errors": [],
        "per_rule": {"R1": {
            "stability": 0.5, "applicable": 4, "detected": 2,
            "cases": [
                {"fixture": "a.py", "transform": "minify", "detected": True},
                {"fixture": "a.py", "transform": "rename_identifier",
                 "detected": False},
            ],
            "sanitizer_probe": {"still_flagged": 1, "runs": 1},
        }},
        "per_transform": {},
        "reverse": {"new_fn_count": 1, "new_fns": [
            {"class": "shell_injection", "cwe": "CWE-78",
             "fixture": "s.py", "payload": "; id"},
        ]},
    }
    md = vh.render_markdown(report)
    assert "| R1 | 0.5 | 2/4 | 1/1 |" in md
    assert "FN shell_injection (CWE-78)" in md
    assert "inline_var" in md


def test_live_scan_detects_renamed_shell_sink(tmp_path):
    """One end-to-end: rename the module on a live shell=True sink and
    rescan through scan_directory (the gated, production path). The
    source->sink chain survives the rename, so the family must still
    fire -- stability contribution = 1 for this case."""
    from scanner.sast import scan_directory

    base_dir = tmp_path / "src"
    base_dir.mkdir()
    (base_dir / "vuln.py").write_text(FIXTURE, encoding="utf-8")
    base = scan_directory(str(base_dir), workers=1)
    assert vh._family_hit(base, "SUBPROCESS_SHELL_TRUE", "CWE-78"), \
        [f.get("rule_id") for f in base]

    out = vh.TRANSFORMS["rename_identifier"](_files(), "app.py",
                                             ANCHOR_LINE, EVIDENCE)
    case = tmp_path / "case"
    case.mkdir()
    (case / "app.py").write_text(out["app.py"], encoding="utf-8")
    findings = scan_directory(str(case), workers=1)
    assert vh._family_hit(findings, "SUBPROCESS_SHELL_TRUE", "CWE-78"), \
        [f.get("rule_id") for f in findings]
