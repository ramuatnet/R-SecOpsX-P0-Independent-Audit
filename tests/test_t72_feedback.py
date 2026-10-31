"""T-7.2: feedback store -- triage outcomes, verification results,
fix state, re-scan deltas, FP -> confidence decay, score deltas +
regression alerts.

Headline assertions (task.md PHASE 7):
  * triage (TP/FP/wontfix), verification, fix state recorded as
    append-only history -- deterministic, never raises;
  * FP feedback -> confidence decay (halving, floored, order-
    sensitive: a later TP restores confidence);
  * re-scan -> per-key score delta AND regression alerts
    (fixed-then-present = regressed; FP'd-then-present =
    fp_reappears), every row explainable;
  * store-derived (context, feedback) plug straight into the T-7.1
    scoring service: fp -> feedback contribution -2.0 visible in
    the explain row, identical inputs -> identical scores.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from analysis.feedback import delta as gdelta
from analysis.feedback import model as gfmodel
from analysis.feedback.connect import main
from analysis.feedback.model import (
    apply_events,
    empty_store,
    finding_key,
    score_inputs_for,
)
from analysis.scoring.score import score_finding

AS_OF = datetime(2026, 10, 31, 12, 0, 0, tzinfo=timezone.utc)
AS_OF_TEXT = "2026-10-31T12:00:00+00:00"

V_NET_LOW = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N"


def _finding(**kw):
    row = {"rule_id": "R1", "title": "t", "file": "app/a.py", "line": 7,
           "severity": "medium"}
    row.update(kw)
    return row


def _event(**kw):
    ev = {"type": "triage", "outcome": "fp", "rule_id": "R1",
          "file": "app/a.py", "line": 7}
    ev.update(kw)
    return ev


def _store_row(store, rule_id="R1", file="app/a.py", line=7):
    return next(r for r in store["findings"]
                if r["rule_id"] == rule_id and r["file"] == file
                and r["line"] == line)


# --------------------------------------------------------------------------
# events: triage / verification / fix state
# --------------------------------------------------------------------------

def test_triage_fp_applies_and_decays_confidence():
    store, skips = apply_events(empty_store(AS_OF),
                                [_event(type="triage", outcome="fp")],
                                AS_OF)
    assert skips == []
    row = _store_row(store)
    assert row["triage"] == "fp"
    assert row["confidence"] == 0.5
    assert row["fp_count"] == 1
    assert len(row["history"]) == 1
    assert row["history"][0]["type"] == "triage"
    assert row["history"][0]["as_of"] == AS_OF_TEXT


def test_confidence_decay_is_order_sensitive():
    # fp, fp, tp -> restore to 1.0 (later TP wins)
    store, _ = apply_events(empty_store(AS_OF), [
        _event(outcome="fp"), _event(outcome="fp"),
        _event(outcome="tp"),
    ], AS_OF)
    row = _store_row(store)
    assert row["triage"] == "tp"
    assert row["confidence"] == 1.0
    # tp then fp -> 0.5
    store2, _ = apply_events(empty_store(AS_OF), [
        _event(outcome="tp"), _event(outcome="fp"),
    ], AS_OF)
    assert _store_row(store2)["confidence"] == 0.5


def test_confidence_floors_after_many_fps():
    events = [_event(outcome="fp") for _ in range(6)]
    store, _ = apply_events(empty_store(AS_OF), events, AS_OF)
    row = _store_row(store)
    assert row["fp_count"] == 6
    assert row["confidence"] == gfmodel.FLOOR_CONFIDENCE
    assert gfmodel.FLOOR_CONFIDENCE == 0.05


def test_wontfix_records_without_confidence_change():
    store, _ = apply_events(empty_store(AS_OF),
                            [_event(outcome="wontfix")], AS_OF)
    row = _store_row(store)
    assert row["triage"] == "wontfix"
    assert row["confidence"] == 1.0
    assert row["fp_count"] == 0


def test_verification_events_update_status():
    store, _ = apply_events(empty_store(AS_OF), [
        _event(type="verification", outcome="reproduced"),
        {"type": "verification", "outcome": "disproven",
         "rule_id": "R1", "file": "app/a.py", "line": 7},
    ], AS_OF)
    row = _store_row(store)
    assert row["verification"] == "disproven"
    assert len(row["history"]) == 2


def test_fix_and_reopen_events_set_fix_state():
    store, _ = apply_events(empty_store(AS_OF),
                            [_event(type="fix")], AS_OF)
    assert _store_row(store)["fix_state"] == "fixed"
    store2, _ = apply_events(store, [_event(type="reopen")], AS_OF)
    assert _store_row(store2)["fix_state"] == "open"


def test_event_payload_list_and_wrapper_equivalent():
    events = [_event(outcome="tp")]
    a, _ = apply_events(empty_store(AS_OF), events, AS_OF)
    b, _ = apply_events(empty_store(AS_OF), {"events": events}, AS_OF)
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


def test_bad_events_annotated_never_raised():
    store, skips = apply_events(empty_store(AS_OF), [
        "junk",
        _event(type="dance"),                      # unknown type
        _event(outcome="meh"),                     # unknown triage vocab
        _event(type="verification", outcome="maybe"),
        {"type": "triage", "outcome": "fp"},       # missing identity
        _event(at="whenever"),                     # bad timestamp
        _event(outcome="fp"),
    ], AS_OF)
    reasons = [s["reason"] for s in skips]
    assert "event_rows_not_objects" in reasons
    assert "event_type_unknown" in reasons
    assert "event_outcome_unknown" in reasons
    assert "event_verification_unknown" in reasons
    assert "event_missing_identity" in reasons
    assert "event_bad_at" in reasons
    row = _store_row(store)
    assert row["fp_count"] == 1                   # only the valid event


def test_bad_events_shape_skip():
    store, skips = apply_events(empty_store(AS_OF),
                                {"nope": []}, AS_OF)
    assert store["findings"] == []
    assert any(s["reason"] == "bad_events_shape" for s in skips)


def test_history_cap_disclosed_and_confidence_still_correct(monkeypatch):
    monkeypatch.setattr(gfmodel, "MAX_HISTORY", 2)
    store, skips = apply_events(
        empty_store(AS_OF),
        [_event(outcome="fp") for _ in range(3)], AS_OF)
    row = _store_row(store)
    assert len(row["history"]) == 2
    assert row.get("history_truncated") is True
    assert row["confidence"] == 0.125             # all 3 fps counted
    assert any(s["reason"] == "cap_history_2" for s in skips)


def test_events_cap_disclosed(monkeypatch):
    monkeypatch.setattr(gfmodel, "MAX_EVENTS", 1)
    store, skips = apply_events(
        empty_store(AS_OF),
        [_event(outcome="fp"), _event(outcome="tp")], AS_OF)
    row = _store_row(store)
    assert row["confidence"] == 0.5               # second event capped
    assert any(s["reason"] == "cap_events_1" for s in skips)


def test_findings_sorted_and_identical_inputs_identical_store():
    ev_a = {"type": "triage", "outcome": "fp", "rule_id": "B",
            "file": "z.py", "line": 3}
    ev_b = {"type": "triage", "outcome": "tp", "rule_id": "A",
            "file": "a.py", "line": 1}
    s1, _ = apply_events(empty_store(AS_OF), [ev_a, ev_b], AS_OF)
    s2, _ = apply_events(empty_store(AS_OF), [ev_a, ev_b], AS_OF)
    assert json.dumps(s1, sort_keys=True) == json.dumps(s2, sort_keys=True)
    keys = [finding_key(r) for r in s1["findings"]]
    assert keys == sorted(keys)


def test_finding_key_normalizes_path_and_missing_identity():
    a = finding_key(_finding(file="App\\A.PY", line=7))
    b = finding_key(_finding(file="app/a.py", line=7))
    assert a == b
    assert finding_key({"rule_id": "R1", "line": 1}) is None
    assert finding_key("junk") is None


def test_score_inputs_derive_from_store_row():
    store, _ = apply_events(empty_store(AS_OF), [
        _event(outcome="fp"),
        _event(type="verification", outcome="reproduced"),
    ], AS_OF)
    ctx, fb = score_inputs_for(_store_row(store))
    assert ctx == {"verification": "reproduced"}
    assert fb == {"triage": "fp"}
    ctx2, fb2 = score_inputs_for({"rule_id": "X", "triage": None,
                                  "verification": None})
    assert ctx2 == {} and fb2 == {}


def test_store_payload_bad_shape_and_bad_rows_annotated():
    from analysis.feedback.connect import _load_store, _store_from_payload
    good, skips = _load_store(None)
    assert good["findings"] == []
    assert any(s["reason"] == "not_provided" for s in skips)
    _, skip = _store_from_payload({"schema": "wrong/v0", "findings": []})
    assert skip is not None and skip["reason"] == "wrong_schema"
    _, skip2 = _store_from_payload({"schema": gfmodel.SCHEMA,
                                    "findings": "nope"})
    assert skip2 is not None and skip2["reason"] == "bad_store_shape"


# --------------------------------------------------------------------------
# re-scan: kinds, score deltas, regression alerts, store updates
# --------------------------------------------------------------------------

def test_rescan_kinds_new_fixed_persistent():
    old = [_finding(), _finding(rule_id="GONE", file="b.py", line=1)]
    new = [_finding(), _finding(rule_id="FRESH", file="c.py", line=2)]
    out = gdelta.rescan(empty_store(AS_OF), empty_store(AS_OF),
                        old, new, {}, AS_OF)
    kinds = {(d["rule_id"], d["file"], d["line"]): d["kind"]
             for d in out["deltas"]}
    assert kinds[("R1", "app/a.py", 7)] == "persistent"
    assert kinds[("GONE", "b.py", 1)] == "fixed"
    assert kinds[("FRESH", "c.py", 2)] == "new"


def test_rescan_key_normalizes_path_across_scans():
    old = [_finding(file="D:\\proj\\App\\A.py")]
    new = [_finding(file="d:/proj/app/a.PY")]
    out = gdelta.rescan(empty_store(AS_OF), empty_store(AS_OF),
                        old, new, {}, AS_OF)
    assert [d["kind"] for d in out["deltas"]] == ["persistent"]


def test_regressed_kind_and_alert_when_store_says_fixed():
    store0, _ = apply_events(empty_store(AS_OF),
                             [_event(type="fix")], AS_OF)
    new = [_finding()]
    out = gdelta.rescan(store0, store0, [], new, {}, AS_OF)
    assert [d["kind"] for d in out["deltas"]] == ["regressed"]
    assert [a["reason"] for a in out["alerts"]] == ["regressed"]
    alert = out["alerts"][0]
    assert alert["rule_id"] == "R1"
    assert "regression" in alert["explanation"].lower()
    assert alert["confidence"] == 1.0


def test_fp_reappears_alert_carries_decayed_confidence():
    store0, _ = apply_events(empty_store(AS_OF),
                             [_event(outcome="fp")], AS_OF)
    old, new = [], [_finding()]
    out = gdelta.rescan(store0, store0, old, new, {}, AS_OF)
    assert [a["reason"] for a in out["alerts"]] == ["fp_reappears"]
    assert out["alerts"][0]["confidence"] == 0.5
    assert out["deltas"][0]["kind"] == "new"


def test_score_delta_on_content_change():
    old = [_finding(severity="medium")]          # base 4.5
    new = [_finding(severity="high")]            # base 7.5
    out = gdelta.rescan(empty_store(AS_OF), empty_store(AS_OF),
                        old, new, {}, AS_OF)
    row = next(d for d in out["deltas"] if d["kind"] == "persistent")
    assert row["prev_score"] == 4.5
    assert row["score"] == 7.5
    assert row["score_delta"] == 3.0
    assert out["stats"]["score_delta_total"] == 3.0


def test_fp_event_in_same_batch_lowers_score_delta():
    store0 = empty_store(AS_OF)
    store1, _ = apply_events(store0, [_event(outcome="fp")], AS_OF)
    rows = [_finding(severity="low")]            # base 2.0, fp -> 0.0
    out = gdelta.rescan(store0, store1, rows, rows, {}, AS_OF)
    row = out["deltas"][0]
    assert row["prev_score"] == 2.0
    assert row["score"] == 0.0                   # clamped at floor
    assert row["score_delta"] == -2.0
    assert row["confidence"] == 0.5


def test_new_and_fixed_score_deltas_sign():
    old = [_finding(severity="high")]            # 7.5 disappears
    new = [_finding(rule_id="N1", file="n.py", line=1, severity="low")]
    out = gdelta.rescan(empty_store(AS_OF), empty_store(AS_OF),
                        old, new, {}, AS_OF)
    by_kind = {d["kind"]: d for d in out["deltas"]}
    assert by_kind["fixed"]["score_delta"] == -7.5
    assert by_kind["new"]["score_delta"] == 2.0
    assert out["stats"]["score_delta_total"] == -5.5


def test_identical_scans_all_persistent_zero_delta_byte_identical():
    rows = [_finding(), _finding(rule_id="R2", file="b.py", line=2)]
    a = gdelta.rescan(empty_store(AS_OF), empty_store(AS_OF),
                      rows, rows, {}, AS_OF)
    b = gdelta.rescan(empty_store(AS_OF), empty_store(AS_OF),
                      rows, rows, {}, AS_OF)
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)
    assert [d["kind"] for d in a["deltas"]] == ["persistent", "persistent"]
    assert all(d["score_delta"] == 0.0 for d in a["deltas"])
    assert a["alerts"] == []


def test_delta_rows_explainable_and_sorted_with_alerts():
    old = [_finding(rule_id="B", file="z.py", line=9),
           _finding(rule_id="A", file="a.py", line=1)]
    new = [_finding(rule_id="A", file="a.py", line=1)]
    out = gdelta.rescan(empty_store(AS_OF), empty_store(AS_OF),
                        old, new, {}, AS_OF)
    for d in out["deltas"]:
        assert d["explanation"]
        assert d["evidence"] is not None
    keys = [(d["rule_id"], d["file"], d["line"]) for d in out["deltas"]]
    assert keys == sorted(keys)
    akeys = [(a["rule_id"], a["file"], a["line"], a["reason"])
             for a in out["alerts"]]
    assert akeys == sorted(akeys)


def test_invalid_and_duplicate_scan_rows_annotated():
    old = [_finding(), _finding(), "junk"]
    new = [_finding()]
    out = gdelta.rescan(empty_store(AS_OF), empty_store(AS_OF),
                        old, new, {}, AS_OF)
    reasons = [s["reason"] for s in out["skips"]]
    assert "old_rows_not_objects" in reasons
    assert "duplicate_keys" in reasons
    assert [d["kind"] for d in out["deltas"]] == ["persistent"]


def test_store_updates_from_rescan_transitions():
    store0 = empty_store(AS_OF)
    gone = _finding(rule_id="GONE", file="g.py", line=3)
    fresh = _finding(rule_id="N1", file="n.py", line=1)
    out = gdelta.rescan(store0, store0, [gone], [fresh], {}, AS_OF)
    store2 = out["store"]
    fixed = _store_row(store2, rule_id="GONE", file="g.py", line=3)
    assert fixed["fix_state"] == "fixed"
    assert fixed["history"][-1]["type"] == "rescan"
    created = _store_row(store2, rule_id="N1", file="n.py", line=1)
    assert created["fix_state"] == "open"
    assert created["confidence"] == 1.0
    # re-appearance afterwards flips the row back to open + alert
    out2 = gdelta.rescan(store2, store2, [], [gone], {}, AS_OF)
    assert _store_row(out2["store"], rule_id="GONE",
                      file="g.py", line=3)["fix_state"] == "open"
    assert out2["alerts"][0]["reason"] == "regressed"


def test_rescan_both_sides_empty_is_fine():
    out = gdelta.rescan(empty_store(AS_OF), empty_store(AS_OF),
                        [], [], {}, AS_OF)
    assert out["deltas"] == [] and out["alerts"] == []
    assert out["stats"]["score_delta_total"] == 0.0


def test_store_rows_cap_disclosed(monkeypatch):
    monkeypatch.setattr(gfmodel, "MAX_STORE_FINDINGS", 1)
    old = [_finding(), _finding(rule_id="X", file="x.py", line=1)]
    new = []
    out = gdelta.rescan(empty_store(AS_OF), empty_store(AS_OF),
                        old, new, {}, AS_OF)
    assert any(s["reason"] == "cap_store_findings_1"
               for s in out["skips"])
    assert len(out["store"]["findings"]) <= 1


# --------------------------------------------------------------------------
# scoring integration (shared PHASE 7 gate)
# --------------------------------------------------------------------------

def test_store_feedback_drives_scoring_explain_contributions():
    store, _ = apply_events(empty_store(AS_OF), [
        _event(outcome="fp"),
        _event(type="verification", outcome="reproduced"),
    ], AS_OF)
    ctx, fb = score_inputs_for(_store_row(store))
    row = score_finding(_finding(cvss_vector=V_NET_LOW),
                        context=ctx, feedback=fb, as_of=AS_OF)
    by = {c["factor"]: c for c in row["contributions"]}
    assert by["verification"]["delta"] == 1.0
    assert row["feedback"]["delta"] == -2.0
    # identical inputs -> identical scores (byte-level)
    row2 = score_finding(_finding(cvss_vector=V_NET_LOW),
                         context=ctx, feedback=fb, as_of=AS_OF)
    assert json.dumps(row, sort_keys=True) == json.dumps(row2,
                                                         sort_keys=True)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def test_cli_default_zero_io_byte_identical(capsys):
    rc1 = main(["--as-of", "2026-10-31T12:00:00Z"])
    out1 = capsys.readouterr().out
    rc2 = main(["--as-of", "2026-10-31T12:00:00Z"])
    out2 = capsys.readouterr().out
    assert rc1 == 0 and rc2 == 0
    assert out1 == out2
    doc = json.loads(out1)
    assert doc["schema"] == gfmodel.SCHEMA
    assert doc["findings"] == [] and doc["deltas"] == []
    assert doc["alerts"] == []
    assert {s["target"] for s in doc["skips"]} == {"store", "events",
                                                   "old", "new"}
    assert all(s["reason"] == "not_provided" for s in doc["skips"])


def test_cli_bad_as_of_rc2(capsys):
    assert main(["--as-of", "whenever"]) == 2


def test_cli_record_mode_stdout(tmp_path, capsys):
    events = tmp_path / "rsx_t72_events.json"
    events.write_text(json.dumps([
        {"type": "triage", "outcome": "fp", "rule_id": "R1",
         "file": "app/a.py", "line": 7},
        {"type": "triage", "outcome": "meh", "rule_id": "R2",
         "file": "b.py", "line": 1},
    ]), encoding="utf-8")
    rc = main(["--events", str(events), "--as-of",
               "2026-10-31T12:00:00Z"])
    out = capsys.readouterr().out
    assert rc == 0
    doc = json.loads(out)
    row = _store_row(doc)
    assert row["confidence"] == 0.5
    assert any(s["reason"] == "event_outcome_unknown"
               for s in doc["skips"])
    assert doc["stats"]["events_applied"] == 1


def test_cli_rescan_mode_emits_deltas_and_updates_store(tmp_path, capsys):
    old = tmp_path / "rsx_t72_old.json"
    new = tmp_path / "rsx_t72_new.json"
    old.write_text(json.dumps([_finding(severity="medium")]),
                   encoding="utf-8")
    new.write_text(json.dumps([_finding(severity="high")]),
                   encoding="utf-8")
    rc = main(["--old", str(old), "--new", str(new), "--as-of",
               "2026-10-31T12:00:00Z"])
    out = capsys.readouterr().out
    assert rc == 0
    doc = json.loads(out)
    assert len(doc["deltas"]) == 1
    assert doc["deltas"][0]["score_delta"] == 3.0
    assert doc["stats"]["by_kind"]["persistent"] == 1


def test_cli_one_sided_rescan_is_skip_not_crash(tmp_path, capsys):
    old = tmp_path / "rsx_t72_only_old.json"
    old.write_text(json.dumps([_finding()]), encoding="utf-8")
    rc = main(["--old", str(old), "--as-of", "2026-10-31T12:00:00Z"])
    out = capsys.readouterr().out
    assert rc == 0
    doc = json.loads(out)
    assert doc["deltas"] == []
    assert any(s["reason"] == "rescan_needs_both" for s in doc["skips"])


def test_cli_missing_files_are_annotated_skips(tmp_path, capsys):
    rc = main(["--store", str(tmp_path / "rsx_t72_absent.json"),
               "--old", str(tmp_path / "rsx_t72_absent2.json"),
               "--new", str(tmp_path / "rsx_t72_absent3.json"),
               "--as-of", "2026-10-31T12:00:00Z"])
    out = capsys.readouterr().out
    assert rc == 0
    reasons = [s["reason"] for s in json.loads(out)["skips"]]
    assert any("FileNotFoundError" in r for r in reasons)
    assert "rescan_needs_both" in reasons or "not_provided" in reasons


def test_cli_out_file_byte_identical_two_runs(tmp_path):
    events = tmp_path / "rsx_t72_ev2.json"
    events.write_text(json.dumps([_event(outcome="tp")]),
                       encoding="utf-8")
    out_a = tmp_path / "rsx_t72_a.json"
    out_b = tmp_path / "rsx_t72_b.json"
    assert main(["--events", str(events), "--as-of",
                 "2026-10-31T12:00:00Z", "--out",
                 str(out_a)]) == 0
    assert main(["--events", str(events), "--as-of",
                 "2026-10-31T12:00:00Z", "--out",
                 str(out_b)]) == 0
    assert out_a.read_bytes() == out_b.read_bytes()


def test_feedback_sources_offline_pinned():
    import pathlib
    import analysis.feedback as pkg
    pkg_dir = pathlib.Path(pkg.__file__).parent
    forbidden = ("urllib", "socket", "boto3", "requests",
                 "os.environ", "http.client")
    for src in sorted(pkg_dir.glob("*.py")):
        text = src.read_text(encoding="utf-8")
        for token in forbidden:
            assert token not in text, f"{src.name} contains {token!r}"


def test_analysis_feedback_submodules_not_shadowed():
    import analysis.feedback as pkg
    assert pkg.model.__name__ == "analysis.feedback.model"
    assert pkg.delta.__name__ == "analysis.feedback.delta"
    assert callable(pkg.apply_events)
