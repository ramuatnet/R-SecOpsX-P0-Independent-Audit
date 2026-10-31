"""T-7.1: scoring service -- score = f(base, modifiers, feedback).

Headline assertions (task.md PHASE 7):
  * base = CVSS4 (official FIRST calculator via scanner.cvss4, with a
    DISCLOSED severity fallback -- never a silent guess);
  * every score emits per-factor signed contributions for all eight
    modifiers (reachability, internet exposure, verification status,
    KEV, EPSS, age, control gaps, blast radius) plus feedback;
  * Deterministic. Explainable.  Identical inputs -> identical bytes;
  * monotonicity: REPRODUCED must not lower score; unreachable must
    not raise it (asserted over a grid of bases x modifier packs);
  * gate: --explain-score shows contributions.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from analysis.scoring import score as gscore
from analysis.scoring.connect import collect_scores, main
from analysis.scoring.score import score_finding, score_findings

AS_OF = datetime(2026, 10, 31, 12, 0, 0, tzinfo=timezone.utc)

V_FULL = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
V_NET_LOW = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N"
V_LOCAL = "CVSS:4.0/AV:L/AC:H/AT:P/PR:L/UI:P/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"

FACTOR_ORDER = ["reachability", "internet_exposure", "verification", "kev",
                "epss", "age", "control_gaps", "blast_radius"]


def _finding(**kw):
    row = {"rule_id": "R1", "title": "t", "file": "a.py", "line": 1,
           "severity": "high"}
    row.update(kw)
    return row


def _by_factor(row):
    return {c["factor"]: c for c in row["contributions"]}


# --------------------------------------------------------------------------
# base resolution (CVSS4, disclosed fallback)
# --------------------------------------------------------------------------

def test_base_from_cvss4_vector_uses_official_calculator():
    row = score_finding(_finding(cvss_vector=V_FULL), as_of=AS_OF)
    assert row["base"]["source"] == "cvss4_vector"
    assert row["base"]["value"] == 10.0
    assert row["base"]["vector"] == V_FULL
    row2 = score_finding(_finding(cvss_vector=V_NET_LOW), as_of=AS_OF)
    assert row2["base"]["value"] == 6.9


def test_base_from_explicit_numeric_score():
    row = score_finding(_finding(cvss_score=5.5), as_of=AS_OF)
    assert row["base"]["source"] == "cvss_score"
    assert row["base"]["value"] == 5.5


def test_base_falls_back_to_severity_and_discloses():
    row = score_finding(_finding(severity="medium"), as_of=AS_OF)
    assert row["base"]["source"] == "severity_default"
    assert row["base"]["value"] == 4.5
    unknown = score_finding(_finding(severity="banana"), as_of=AS_OF)
    assert unknown["base"]["value"] == 0.0
    assert unknown["base"]["note"] == "unknown_severity"


def test_invalid_vector_never_raises_and_is_disclosed():
    row = score_finding(_finding(cvss_vector="garbage",
                                 severity="high"), as_of=AS_OF)
    assert row["base"]["source"] == "severity_default"
    assert row["base"]["value"] == 7.5
    assert row["base"]["note"] == "invalid_vector"
    none_vec = score_finding(_finding(cvss_vector=123), as_of=AS_OF)
    assert none_vec["base"]["note"] == "invalid_vector"


# --------------------------------------------------------------------------
# contributions: all factors, signed, explainable
# --------------------------------------------------------------------------

def test_contributions_emit_all_factors_in_spec_order():
    row = score_finding(_finding(), as_of=AS_OF)
    factors = [c["factor"] for c in row["contributions"]]
    assert factors == FACTOR_ORDER
    for c in row["contributions"]:
        assert isinstance(c["delta"], float)
        assert "detail" in c
    assert row["feedback"]["delta"] == 0.0
    assert row["feedback"]["detail"]["triage"] is None


def test_each_modifier_signed_correctly():
    ctx = {
        "reachable": True,
        "internet_exposed": True,
        "verification": "reproduced",
        "kev": True,
        "epss": 0.5,
        "first_seen": (AS_OF - timedelta(days=180)).isoformat(),
        "control_gaps": 100,
        "blast_radius": "data",
    }
    row = score_finding(_finding(cvss_vector=V_NET_LOW), context=ctx,
                        as_of=AS_OF)
    d = _by_factor(row)
    assert d["reachability"]["delta"] == 1.0
    assert d["internet_exposure"]["delta"] == 1.5
    assert d["verification"]["delta"] == 1.0
    assert d["kev"]["delta"] == 2.0
    assert d["epss"]["delta"] == 1.0
    assert d["age"]["delta"] == -2.0
    assert d["control_gaps"]["delta"] == 1.5
    assert d["control_gaps"]["detail"]["capped"] is True
    assert d["blast_radius"]["delta"] == 1.5
    assert row["base"]["value"] == 6.9


def test_negative_signals_produce_negative_contributions():
    ctx = {"reachable": False, "verification": "disproven",
           "first_seen": (AS_OF - timedelta(days=400)).isoformat()}
    row = score_finding(_finding(cvss_vector=V_FULL), context=ctx,
                        as_of=AS_OF)
    d = _by_factor(row)
    assert d["reachability"]["delta"] == -1.0
    assert d["verification"]["delta"] == -3.0
    assert d["age"]["delta"] == -2.0      # floor of the decay


def test_unknown_signals_emit_zero_with_detail():
    row = score_finding(_finding(), context={"reachable": None},
                        as_of=AS_OF)
    d = _by_factor(row)
    assert d["reachability"]["delta"] == 0.0
    assert d["reachability"]["detail"]["reachable"] is None
    assert d["kev"]["detail"]["kev"] is False
    assert d["epss"]["detail"]["epss"] is None


def test_epss_bounded_and_clamped_with_disclosure():
    row1 = score_finding(_finding(), context={"epss": 1.0}, as_of=AS_OF)
    assert _by_factor(row1)["epss"]["delta"] == 2.0
    row2 = score_finding(_finding(), context={"epss": 1.7}, as_of=AS_OF)
    c2 = _by_factor(row2)["epss"]
    assert c2["delta"] == 2.0
    assert c2["detail"]["note"] == "clamped"
    row3 = score_finding(_finding(), context={"epss": -0.2}, as_of=AS_OF)
    c3 = _by_factor(row3)["epss"]
    assert c3["delta"] == 0.0
    assert c3["detail"]["note"] == "clamped"
    row4 = score_finding(_finding(), context={"epss": "abc"},
                         as_of=AS_OF)
    assert _by_factor(row4)["epss"]["delta"] == 0.0


def test_age_decay_monotone_zero_for_missing_or_future():
    miss = score_finding(_finding(), as_of=AS_OF)
    assert _by_factor(miss)["age"]["delta"] == 0.0
    assert _by_factor(miss)["age"]["detail"]["note"] == \
        "missing_first_seen"
    fut = score_finding(
        _finding(),
        context={"first_seen": (AS_OF + timedelta(days=5)).isoformat()},
        as_of=AS_OF)
    assert _by_factor(fut)["age"]["delta"] == 0.0
    assert _by_factor(fut)["age"]["detail"]["note"] == "future_first_seen"
    d90 = score_finding(
        _finding(),
        context={"first_seen": (AS_OF - timedelta(days=90)).isoformat()},
        as_of=AS_OF)
    d180 = score_finding(
        _finding(),
        context={"first_seen": (AS_OF - timedelta(days=180)).isoformat()},
        as_of=AS_OF)
    assert _by_factor(d90)["age"]["delta"] == -1.0
    assert _by_factor(d180)["age"]["delta"] == -2.0
    bad = score_finding(_finding(),
                        context={"first_seen": "not-a-date"},
                        as_of=AS_OF)
    assert _by_factor(bad)["age"]["delta"] == 0.0
    assert _by_factor(bad)["age"]["detail"]["note"] == \
        "unparseable_first_seen"


def test_control_gaps_accept_int_or_list_and_cap_disclosed():
    row = score_finding(_finding(), context={"control_gaps": 2},
                        as_of=AS_OF)
    c = _by_factor(row)["control_gaps"]
    assert c["delta"] == 1.0
    assert "capped" not in c["detail"]
    row2 = score_finding(_finding(),
                         context={"control_gaps": ["a", "b", "c", "d"]},
                         as_of=AS_OF)
    assert _by_factor(row2)["control_gaps"]["delta"] == 1.5
    assert _by_factor(row2)["control_gaps"]["detail"]["gaps"] == 4


def test_blast_radius_enum_and_unknown_zero():
    assert _by_factor(score_finding(
        _finding(), context={"blast_radius": "local"},
        as_of=AS_OF))["blast_radius"]["delta"] == 0.5
    assert _by_factor(score_finding(
        _finding(), context={"blast_radius": "service"},
        as_of=AS_OF))["blast_radius"]["delta"] == 1.0
    unk = _by_factor(score_finding(
        _finding(), context={"blast_radius": "banana"},
        as_of=AS_OF))["blast_radius"]
    assert unk["delta"] == 0.0
    assert unk["detail"]["note"] == "unknown_blast_radius"


def test_verification_states_and_unknown_note():
    repro = _by_factor(score_finding(
        _finding(), context={"verification": "reproduced"},
        as_of=AS_OF))["verification"]
    assert repro["delta"] == 1.0
    dis = _by_factor(score_finding(
        _finding(), context={"verification": "disproven"},
        as_of=AS_OF))["verification"]
    assert dis["delta"] == -3.0
    unk = _by_factor(score_finding(
        _finding(), context={"verification": "maybe"},
        as_of=AS_OF))["verification"]
    assert unk["delta"] == 0.0
    assert unk["detail"]["note"] == "unknown_verification"


def test_feedback_triage_signed_rows():
    fp = score_finding(_finding(), feedback={"triage": "fp"},
                       as_of=AS_OF)
    assert fp["feedback"]["delta"] == -2.0
    assert fp["feedback"]["detail"]["triage"] == "fp"
    tp = score_finding(_finding(), feedback={"triage": "tp"},
                       as_of=AS_OF)
    assert tp["feedback"]["delta"] == 0.5
    wf = score_finding(_finding(), feedback={"triage": "wontfix"},
                       as_of=AS_OF)
    assert wf["feedback"]["delta"] == 0.0
    assert wf["feedback"]["detail"]["note"] == "wontfix_no_score_change"
    unk = score_finding(_finding(), feedback={"triage": "shrug"},
                        as_of=AS_OF)
    assert unk["feedback"]["delta"] == 0.0
    assert unk["feedback"]["detail"]["note"] == "unknown_triage"


# --------------------------------------------------------------------------
# final score: clamp, round, band, explain shape
# --------------------------------------------------------------------------

def test_score_clamps_high_and_low_and_flags_it():
    hot = score_finding(
        _finding(cvss_vector=V_FULL),
        context={"reachable": True, "internet_exposed": True,
                 "verification": "reproduced", "kev": True,
                 "epss": 1.0, "blast_radius": "data"},
        as_of=AS_OF)
    assert hot["score"] == 10.0
    assert hot["clamped"] is True
    cold = score_finding(
        _finding(cvss_score=1.0),
        context={"reachable": False, "verification": "disproven",
                 "first_seen": (AS_OF - timedelta(days=365)).isoformat()},
        feedback={"triage": "fp"}, as_of=AS_OF)
    assert cold["score"] == 0.0
    assert cold["clamped"] is True


def test_band_thresholds():
    cases = [(0.0, "none"), (0.1, "low"), (3.9, "low"),
             (4.0, "medium"), (6.9, "medium"), (7.0, "high"),
             (8.9, "high"), (9.0, "critical"), (10.0, "critical")]
    for value, band in cases:
        assert gscore.band_of(value) == band


def test_explain_row_shape_is_complete():
    row = score_finding(_finding(cvss_vector=V_NET_LOW),
                        context={"reachable": True}, as_of=AS_OF)
    assert set(row) == {"rule_id", "score", "band", "base", "contributions",
                        "feedback", "raw", "clamped"}
    assert row["raw"] == pytest.approx(7.9)
    assert row["score"] == 7.9
    assert row["band"] == "high"


def test_identical_inputs_identical_scores():
    ctx = {"reachable": True, "epss": 0.33, "kev": False,
           "first_seen": "2026-01-01T00:00:00+00:00"}
    a = score_finding(_finding(cvss_vector=V_NET_LOW), context=ctx,
                      feedback={"triage": "tp"}, as_of=AS_OF)
    b = score_finding(_finding(cvss_vector=V_NET_LOW), context=ctx,
                      feedback={"triage": "tp"}, as_of=AS_OF)
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


# --------------------------------------------------------------------------
# monotonicity (task.md asserted properties)
# --------------------------------------------------------------------------

_BASES = [{"cvss_vector": v} for v in (V_LOCAL, V_NET_LOW, V_FULL)] + [
    {"cvss_score": 0.5}, {"cvss_score": 4.5}, {"cvss_score": 7.5},
    {"severity": "low"}, {"severity": "critical"}, {}]

_NEG_PACK = {"reachable": False, "internet_exposed": False,
             "verification": "disproven", "kev": False, "epss": 0.0,
             "first_seen": "2025-01-01T00:00:00+00:00",
             "control_gaps": ["a"], "blast_radius": "none"}
_POS_PACK = {"reachable": True, "internet_exposed": True,
             "verification": "unverified", "kev": True, "epss": 1.0,
             "first_seen": (AS_OF - timedelta(days=10)).isoformat(),
             "control_gaps": 3, "blast_radius": "data"}


@pytest.mark.parametrize("base", _BASES)
@pytest.mark.parametrize("pack", [_NEG_PACK, _POS_PACK, {}])
@pytest.mark.parametrize("fb", [{}, {"triage": "fp"}, {"triage": "tp"}])
def test_reproduced_never_lowers_score(base, pack, fb):
    unverified = score_finding(_finding(**base), context=dict(pack),
                               feedback=fb, as_of=AS_OF)
    reproduced = score_finding(
        _finding(**base),
        context={**pack, "verification": "reproduced"},
        feedback=fb, as_of=AS_OF)
    assert reproduced["score"] >= unverified["score"]


@pytest.mark.parametrize("base", _BASES)
@pytest.mark.parametrize("pack", [_NEG_PACK, _POS_PACK, {}])
def test_unreachable_never_raises_score(base, pack):
    known = score_finding(
        _finding(**base),
        context={**pack, "verification": "unverified"},
        as_of=AS_OF)
    unreachable = score_finding(
        _finding(**base),
        context={**pack, "reachable": False,
                 "verification": "unverified"},
        as_of=AS_OF)
    unknown = score_finding(
        _finding(**base),
        context={**pack, "reachable": None,
                 "verification": "unverified"},
        as_of=AS_OF)
    assert unreachable["score"] <= known["score"]
    assert unreachable["score"] <= unknown["score"]


# --------------------------------------------------------------------------
# batch + ingest + CLI
# --------------------------------------------------------------------------

def test_score_findings_payload_and_list_equivalent():
    rows = [_finding(rule_id="A"), _finding(rule_id="B")]
    a = score_findings(rows, as_of=AS_OF)
    b = score_findings({"findings": rows}, as_of=AS_OF)
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)
    assert len(a["scores"]) == 2


def test_per_row_context_overrides_shared_default():
    rows = [_finding(rule_id="A"),
            _finding(rule_id="B",
                     score_context={"reachable": True},
                     score_feedback={"triage": "fp"})]
    art = score_findings(rows, context={"reachable": False},
                         feedback={}, as_of=AS_OF)
    by_id = {r["rule_id"]: r for r in art["scores"]}
    assert _by_factor(by_id["A"])["reachability"]["delta"] == -1.0
    assert _by_factor(by_id["B"])["reachability"]["delta"] == 1.0
    assert by_id["B"]["feedback"]["delta"] == -2.0
    assert by_id["A"]["feedback"]["delta"] == 0.0


def test_invalid_rows_annotated_never_silent():
    art = score_findings([_finding(rule_id="ok"), "junk", 7], as_of=AS_OF)
    assert len(art["scores"]) == 1
    skip = next(s for s in art["skips"]
                if s["reason"] == "finding_rows_not_objects")
    assert skip["detail"]["count"] == 2


def test_findings_cap_disclosed(monkeypatch):
    monkeypatch.setattr(gscore, "MAX_FINDINGS", 1)
    art = score_findings([_finding(rule_id="A"), _finding(rule_id="B")],
                         as_of=AS_OF)
    assert len(art["scores"]) == 1
    assert any(s["reason"] == "cap_findings_1" for s in art["skips"])


def test_malformed_types_never_raise():
    row = score_finding(
        _finding(severity=5, cvss_vector={"x": 1}, cvss_score="n/a"),
        context={"reachable": "yes", "internet_exposed": 1,
                 "kev": "no", "epss": object(),
                 "first_seen": object(), "control_gaps": "lots",
                 "blast_radius": 7},
        feedback={"triage": 9}, as_of=AS_OF)
    assert 0.0 <= row["score"] <= 10.0
    d = _by_factor(row)
    assert d["reachability"]["delta"] == 0.0   # "yes" is not a bool
    assert d["control_gaps"]["delta"] == 0.0   # "lots" is not a count
    assert d["age"]["detail"]["note"] == "unparseable_first_seen"


def test_cli_default_zero_io_byte_identical(capsys):
    rc1 = main(["--as-of", "2026-10-31T12:00:00Z"])
    out1 = capsys.readouterr().out
    rc2 = main(["--as-of", "2026-10-31T12:00:00Z"])
    out2 = capsys.readouterr().out
    assert rc1 == 0 and rc2 == 0
    assert out1 == out2
    doc = json.loads(out1)
    assert doc["schema"] == gscore.SCHEMA
    assert doc["scores"] == []
    assert any(s["reason"] == "not_provided" for s in doc["skips"])


def test_cli_explain_score_shows_contributions(tmp_path, capsys):
    finding = tmp_path / "rsx_t71_finding.json"
    finding.write_text(json.dumps(_finding(cvss_vector=V_NET_LOW,
                                           score_context={
                                               "reachable": True})),
                       encoding="utf-8")
    rc = main(["--finding", str(finding),
               "--as-of", "2026-10-31T12:00:00Z", "--explain-score"])
    out = capsys.readouterr().out
    assert rc == 0
    doc = json.loads(out)
    row = doc["scores"][0]
    factors = [c["factor"] for c in row["contributions"]]
    assert factors == FACTOR_ORDER
    assert row["base"]["source"] == "cvss4_vector"
    assert row["feedback"]["delta"] == 0.0


def test_cli_without_flag_is_compact(tmp_path, capsys):
    finding = tmp_path / "rsx_t71_finding2.json"
    finding.write_text(json.dumps(_finding()), encoding="utf-8")
    rc = main(["--finding", str(finding),
               "--as-of", "2026-10-31T12:00:00Z"])
    out = capsys.readouterr().out
    assert rc == 0
    doc = json.loads(out)
    row = doc["scores"][0]
    assert set(row) == {"rule_id", "score", "band"}


def test_cli_context_and_feedback_files(tmp_path, capsys):
    finding = tmp_path / "rsx_t71_f3.json"
    finding.write_text(json.dumps(_finding(cvss_vector=V_FULL)),
                       encoding="utf-8")
    ctx = tmp_path / "rsx_t71_ctx.json"
    ctx.write_text(json.dumps({"reachable": False,
                               "verification": "unverified"}),
                   encoding="utf-8")
    fb = tmp_path / "rsx_t71_fb.json"
    fb.write_text(json.dumps({"triage": "fp"}), encoding="utf-8")
    rc = main(["--finding", str(finding), "--context", str(ctx),
               "--feedback", str(fb), "--explain-score",
               "--as-of", "2026-10-31T12:00:00Z"])
    out = capsys.readouterr().out
    assert rc == 0
    doc = json.loads(out)
    row = doc["scores"][0]
    assert row["feedback"]["delta"] == -2.0
    d = _by_factor(row)
    assert d["reachability"]["delta"] == -1.0


def test_cli_out_file_byte_identical_two_runs(tmp_path):
    out_a = tmp_path / "rsx_t71_a.json"
    out_b = tmp_path / "rsx_t71_b.json"
    assert main(["--as-of", "2026-10-31T12:00:00Z",
                 "--explain-score", "--out", str(out_a)]) == 0
    assert main(["--as-of", "2026-10-31T12:00:00Z",
                 "--explain-score", "--out", str(out_b)]) == 0
    assert out_a.read_bytes() == out_b.read_bytes()


def test_cli_bad_as_of_rc2(capsys):
    assert main(["--as-of", "whenever"]) == 2


def test_collect_scores_missing_file_is_skip_not_crash(tmp_path):
    art = collect_scores(finding=str(tmp_path / "rsx_t71_absent.json"),
                         as_of=AS_OF)
    assert any("FileNotFoundError" in s["reason"] for s in art["skips"])
    assert art["scores"] == []


def test_scoring_sources_offline_pinned():
    import pathlib
    import analysis.scoring as pkg
    pkg_dir = pathlib.Path(pkg.__file__).parent
    forbidden = ("urllib", "socket", "boto3", "requests",
                 "os.environ", "http.client")
    for src in sorted(pkg_dir.glob("*.py")):
        text = src.read_text(encoding="utf-8")
        for token in forbidden:
            assert token not in text, f"{src.name} contains {token!r}"


def test_analysis_scoring_submodules_not_shadowed():
    import analysis.scoring as pkg
    assert pkg.score.__name__ == "analysis.scoring.score"
    assert pkg.connect.__name__ == "analysis.scoring.connect"
    assert callable(pkg.score_finding)
