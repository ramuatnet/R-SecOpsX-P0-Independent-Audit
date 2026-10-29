"""T-1.5: the parity gate's pure logic.

No engine scans here -- the gate itself is the ci_matrix `engine_parity`
entry. These tests pin the normalization, the annotation schema and the
delta classifier (the machine-readable vocabulary that keeps "annotated
divergence" from becoming a silent drop), and they import the module so
the dead-code guard sees it as reachable.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in {p for p in sys.path}:
    sys.path.insert(0, str(REPO))

from analysis.validation import parity_gate as pg  # noqa: E402


def _finding(**over):
    row = {
        "rule_id": "R1",
        "file": str(REPO / "tests" / "vuln-test-corpus" / "a.py"),
        "line": 3,
        "snippet": "eval(x)",
        "severity": "High",
        "engine": "scanner.sast",
        "evidence": "a.py:3: eval(x)",
        "group_key": "R1|a.py|3|eval(x)",
        "language": "python",
    }
    row.update(over)
    return row


def test_rel_is_posix_inside_root_and_normalised_outside(tmp_path):
    inside = pg._rel(str(tmp_path / "sub" / "a.py"), tmp_path)
    assert inside == "sub/a.py"
    assert "\\" not in inside
    # Outside the root (same drive): absolute, posix, lowercased -- both
    # engines must still compare equal on drive-letter case.
    (tmp_path / "root").mkdir()
    outside = pg._rel(str(tmp_path / "other" / "b.py"), tmp_path / "root")
    assert outside == str(tmp_path / "other" / "b.py").replace("\\", "/").lower()
    assert "\\" not in outside


def test_row_drops_derived_fields_and_rewrites_file(tmp_path):
    row = pg._row(_finding(file=str(tmp_path / "a.py")), tmp_path)
    for key in ("engine", "evidence", "group_key"):
        assert key not in row
    assert row["file"] == "a.py"
    assert row["rule_id"] == "R1" and row["line"] == 3


def test_classify_is_exhaustive_and_honest():
    other: list = []
    # Python-only regex syntax, disclosed by the engine itself.
    cls, _ = pg._classify("py", _finding(rule_id="EVAL_CALL"), other,
                          {"EVAL_CALL"})
    assert cls == "unsupported_regex_crate"
    # Taint ids on both naming conventions.
    for rid in ("TAINT_SHELL", "JAVA_TAINT_COMMAND_INJECTION"):
        cls, _ = pg._classify("py", _finding(rule_id=rid), other, set())
        assert cls == "taint_not_ported", rid
    # Same anchor, taint-layer metadata on the row: collision, not drift.
    enriched = _finding(taint_chain="req -> sink", taint_path="a -> b")
    cls, _ = pg._classify("py", enriched, [enriched], set())
    assert cls == "taint_metadata_collision"
    # Same anchor, metadata without taint flow: field drift (snippet...).
    py_row = _finding(snippet="eval(")
    rust_row = _finding(snippet="return eval(x)")
    cls, _ = pg._classify("py", py_row, [rust_row], set())
    assert cls == "anchor_field_drift"
    cls, _ = pg._classify("rust", rust_row, [py_row], set())
    assert cls == "anchor_field_drift"
    # Same rule+file, different line: re-anchor.
    cls, _ = pg._classify("py", _finding(line=9), [_finding(line=3)], set())
    assert cls == "focus_reanchor"
    # Nothing on the other side at all.
    cls, _ = pg._classify("py", _finding(rule_id="MYSTERY"), other, set())
    assert cls == "py_only_unexplained"
    cls, _ = pg._classify("rust", _finding(rule_id="RUST_ONLY"), other, set())
    assert cls == "py_suppression_not_ported"


def test_annotations_round_trip(tmp_path):
    path = tmp_path / "known_divergences.json"
    ann = {
        "target": "corpus",
        "side": "py",
        "row_hash": "abc123",
        "rule_id": "R1",
        "file": "a.py",
        "line": 3,
        "class": "focus_reanchor",
        "reason": "same rule+file at different lines",
    }
    # Duplicate rows collapse to one annotation (set semantics).
    pg._update_annotations([ann, dict(ann)], path=path)
    loaded_doc = json.loads(path.read_text(encoding="utf-8"))
    assert loaded_doc["schema"] == pg.ANNOTATION_SCHEMA
    assert len(loaded_doc["annotations"]) == 1

    # _load_annotations reads the COMMITTED file when present: it must
    # parse, match the schema and hash-key without collisions.
    if pg.ANNOTATIONS_PATH.exists():
        committed = pg._load_annotations()
        assert committed, "committed annotations must not be empty"
        for (target, row_hash), a in committed.items():
            assert a["target"] == target and a["row_hash"] == row_hash
            assert a["class"] and a["reason"], a


def test_committed_annotations_classes_are_known_vocabulary():
    if not pg.ANNOTATIONS_PATH.exists():
        return
    known = {
        "unsupported_regex_crate",
        "taint_not_ported",
        "taint_metadata_collision",
        "anchor_field_drift",
        "focus_reanchor",
        "py_suppression_not_ported",
    }
    doc = json.loads(pg.ANNOTATIONS_PATH.read_text(encoding="utf-8"))
    assert doc["schema"] == pg.ANNOTATION_SCHEMA
    for a in doc["annotations"]:
        assert a["class"] in known, a
        assert a["side"] in {"py", "rust"}, a
        assert a["reason"], a
