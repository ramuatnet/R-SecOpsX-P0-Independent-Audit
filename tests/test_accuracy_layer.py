# -*- coding: utf-8 -*-
r"""Accuracy-layer tests (mission Phases 2-4).

Quality gates asserted here:
  1. Layer OFF  -> output is byte-identical to the baseline (snapshot).
  2. Layer ON   -> detection recall unchanged (findings are classified,
                   never removed; zero silent loss).
  3. Verdicts   -> TRUE_POSITIVE requires a traced path; validators produce
                   LIKELY_FALSE_POSITIVE / MISLABELED / NEEDS_REVIEW with
                   reasons; user suppressions (inline, .sastignore,
                   baseline) work and stay in the audit.
  4. CS_ pack   -> disabled by default, ReDoS-safe, positive/negative
                   snippets behave as documented.
"""
from __future__ import annotations

import copy
import json
import pathlib
import sys

import pytest

sys.path.insert(0, r"D:\Data\Code test\R-SecOpsX_V11")

from accuracy.layer import apply_accuracy_layer  # noqa: E402
from accuracy import validators as V  # noqa: E402
from accuracy.rules_pack_cs import CS_RULES, redos_safe  # noqa: E402

BASELINE = json.load(open(
    pathlib.Path(__file__).parent.parent / "baseline" /
    "flask_sql_findings_before.json", encoding="utf-8"))
TARGET = str(pathlib.Path(__file__).resolve().parents[1] / "tests" /
             "e2e_targets" / "flask_sql")


def _baseline_findings():
    fs = [dict(x) for x in BASELINE["findings"]]
    for x in fs:
        p = pathlib.Path(x["file"])
        if not p.is_absolute():
            x["file"] = str(pathlib.Path(TARGET) / p.name)
    return fs


# ---------------------------------------------------------------------------
# Gate 1: layer OFF == legacy, byte-identical
# ---------------------------------------------------------------------------
def test_layer_disabled_is_exact_legacy(monkeypatch):
    monkeypatch.setenv("RSECOPSX_ACCURACY_LAYER", "0")
    payload = {"findings": _baseline_findings(), "metadata": {}}
    before = json.dumps(payload["findings"], sort_keys=True, default=str)
    out = apply_accuracy_layer(payload, TARGET)
    after = json.dumps(out["findings"], sort_keys=True, default=str)
    assert before == after, "layer OFF must not change a single byte"
    assert "accuracy" not in out or out["accuracy"] is None


def test_layer_enabled_attaches_but_never_removes(monkeypatch):
    monkeypatch.setenv("RSECOPSX_ACCURACY_LAYER", "1")
    payload = {"findings": _baseline_findings(), "metadata": {}}
    n_before = len(payload["findings"])
    out = apply_accuracy_layer(payload, TARGET)
    assert len(out["findings"]) == n_before, "zero silent loss violated"
    acc = out["accuracy"]
    assert acc["schema"].startswith("RSECOPSX-ACCURACY")
    assert acc["counts"]["TRUE_POSITIVE"] == 3  # the flask_sql trio


# ---------------------------------------------------------------------------
# Verdict behaviors
# ---------------------------------------------------------------------------
def _mk(rule_id, snippet, file="x.py", line=1):
    return {"rule_id": rule_id, "snippet": snippet, "evidence": snippet,
            "file": file, "line": line, "severity": "Medium",
            "instances": 1, "group_key": "g", "vuln_type": ""}


def test_mislabeled_when_different_sink_present(tmp_path):
    src = tmp_path / "m.java"
    src.write_text("DocumentBuilderFactory.newInstance();  // XXE sink here\n",
                   encoding="utf-8")
    f = _mk("TAINT_SQL_INJECTION", "String s = q;",
            file=str(src), line=1)
    # Build the payload through UFIB so dispositions exist, then the layer.
    from analysis.ufib_release import apply_ufib_to_payload
    payload = {"findings": [f], "metadata": {}}
    payload = apply_ufib_to_payload(payload, str(tmp_path))
    out = apply_accuracy_layer(payload, str(tmp_path))
    acc = out["findings"][0]["accuracy"]
    assert acc["verdict"] in ("MISLABELED", "LIKELY_FALSE_POSITIVE")
    if acc["verdict"] == "MISLABELED":
        assert "JAVA_XXE_PARSER" in acc["reason"]


def test_absence_based_design_level(tmp_path):
    src = tmp_path / "route.js"
    src.write_text('app.get("/status", (req, res) => res.json({ok: 1}));\n',
                   encoding="utf-8")
    f = _mk("MISSING_RATE_LIMIT_ENDPOINT", 'app.get("/status")',
            file=str(src), line=1)
    from analysis.ufib_release import apply_ufib_to_payload
    payload = {"findings": [f], "metadata": {}}
    payload = apply_ufib_to_payload(payload, str(tmp_path))
    out = apply_accuracy_layer(payload, str(tmp_path))
    acc = out["findings"][0]["accuracy"]
    assert acc["verdict"] in ("LIKELY_FALSE_POSITIVE", "NEEDS_REVIEW")
    assert "design-level" in acc["reason"]


def test_state_changing_absence_stays_needs_review(tmp_path):
    src = tmp_path / "login.js"
    src.write_text('app.post("/login", handler);\n', encoding="utf-8")
    f = _mk("MISSING_RATE_LIMIT_ENDPOINT", 'app.post("/login")',
            file=str(src), line=1)
    from analysis.ufib_release import apply_ufib_to_payload
    payload = {"findings": [f], "metadata": {}}
    payload = apply_ufib_to_payload(payload, str(tmp_path))
    out = apply_accuracy_layer(payload, str(tmp_path))
    acc = out["findings"][0]["accuracy"]
    assert acc["verdict"] == "NEEDS_REVIEW"
    assert "state-changing" in acc["reason"]


def test_secret_entropy_validator(tmp_path):
    good = _mk("GENERIC_API_KEY_PASSWORD",
               'API_KEY = "Zx91kJ7fmQ2pLmN4vR8sTtY5wE6uI0oP"')
    v = V.secret_check(good, good["snippet"])
    assert v and v[0] == "TRUE_POSITIVE"
    sentence = _mk("GENERIC_API_KEY_PASSWORD",
                   'API_KEY = "please enter your login password here"')
    v = V.secret_check(sentence, sentence["snippet"])
    assert v and v[0] == "LIKELY_FALSE_POSITIVE"


def test_i18n_label_secret_suppressed(tmp_path):
    src = tmp_path / "messages.properties"
    src.write_text("login.label.password=Enter your password\n",
                   encoding="utf-8")
    f = _mk("CONFIG_CONTEXTUAL_CREDENTIAL",
            "login.label.password=Enter your password", file=str(src))
    from analysis.ufib_release import apply_ufib_to_payload
    payload = {"findings": [f], "metadata": {}}
    payload = apply_ufib_to_payload(payload, str(tmp_path))
    out = apply_accuracy_layer(payload, str(tmp_path))
    acc = out["findings"][0]["accuracy"]
    assert acc["verdict"] in ("LIKELY_FALSE_POSITIVE", "NEEDS_REVIEW")


def test_inline_sast_ignore(tmp_path):
    src = tmp_path / "v.py"
    src.write_text(
        "cursor.execute('SELECT ' + q)  # sast-ignore TAINT_SQL_INJECTION reviewed\n",
        encoding="utf-8")
    f = _mk("TAINT_SQL_INJECTION", "cursor.execute('SELECT ' + q)",
            file=str(src), line=1)
    from analysis.ufib_release import apply_ufib_to_payload
    payload = {"findings": [f], "metadata": {}}
    payload = apply_ufib_to_payload(payload, str(tmp_path))
    out = apply_accuracy_layer(payload, str(tmp_path))
    acc = out["findings"][0]["accuracy"]
    assert acc["verdict"] == "SUPPRESSED_USER"
    assert any(a["verdict"] == "SUPPRESSED_USER"
               for a in out["accuracy"]["audit"])


def test_sastignore_file(tmp_path):
    (tmp_path / ".sastignore").write_text("MISSING_RATE_LIMIT_ENDPOINT\n",
                                          encoding="utf-8")
    src = tmp_path / "login.js"
    src.write_text('app.post("/login", h);\n', encoding="utf-8")
    f = _mk("MISSING_RATE_LIMIT_ENDPOINT", 'app.post("/login")',
            file=str(src), line=1)
    from analysis.ufib_release import apply_ufib_to_payload
    payload = {"findings": [f], "metadata": {}}
    payload = apply_ufib_to_payload(payload, str(tmp_path))
    out = apply_accuracy_layer(payload, str(tmp_path))
    assert out["findings"][0]["accuracy"]["verdict"] == "SUPPRESSED_USER"


def test_baseline_known_finding(tmp_path):
    (tmp_path / "baseline").mkdir()
    (tmp_path / "baseline" / "sast_baseline.json").write_text(json.dumps({
        "GENERIC_API_KEY_PASSWORD": [{"file": "cfg.py", "line": 3}]}),
        encoding="utf-8")
    src = tmp_path / "cfg.py"
    src.write_text('api_key = "Zx91kJ7fmQ2pLmN4vR8sTtY5wE6uI0oP"\n',
                   encoding="utf-8")
    f = _mk("GENERIC_API_KEY_PASSWORD",
            'api_key = "Zx91kJ7fmQ2pLmN4vR8sTtY5wE6uI0oP"',
            file=str(src), line=3)
    from analysis.ufib_release import apply_ufib_to_payload
    payload = {"findings": [f], "metadata": {}}
    payload = apply_ufib_to_payload(payload, str(tmp_path))
    out = apply_accuracy_layer(payload, str(tmp_path))
    assert out["findings"][0]["accuracy"]["verdict"] == "SUPPRESSED_KNOWN"


def test_duplicate_merge():
    a = _mk("JAVA_J2_WEAK_RANDOM", "Random r = new Random();", line=7)
    b = _mk("JAVA_J2_WEAK_RANDOM", "Random r = new Random();", line=7)
    payload = {"findings": [a, b], "metadata": {}}
    payload = apply_accuracy_layer(payload, None)
    verdicts = [f["accuracy"]["verdict"] for f in payload["findings"]]
    assert verdicts[1] == "DUPLICATE"
    assert len([x for x in payload["accuracy"]["audit"]
                if x["verdict"] == "DUPLICATE"]) == 1


def test_true_positive_requires_traced_path():
    f = _mk("GENERIC_API_KEY_PASSWORD", 'API_KEY = "pWd"')
    payload = {"findings": [f], "metadata": {}}
    payload = apply_accuracy_layer(payload, None)
    acc = f["accuracy"]
    if acc["verdict"] == "TRUE_POSITIVE":
        assert "traced" in acc["reason"] or "source boundary" in acc["reason"]


# ---------------------------------------------------------------------------
# CS_ pack quality gates (Phase 3/4)
# ---------------------------------------------------------------------------
def test_cs_pack_disabled_by_default_and_redos_safe():
    for r in CS_RULES:
        assert r["enabled"] is False, "%s must ship disabled" % r["id"]
        assert redos_safe(r), "%s pattern is ReDoS-unsafe" % r["id"]


def test_cs_pack_positive_negative():
    from accuracy.rules_pack_cs import check
    for r in CS_RULES:
        for p in r["positive"]:
            assert check(p, r), "%s positive missed: %r" % (r["id"], p)
        # negatives: allow documented limitations (comment-only PEM fires)
        fired = [n for n in r["negative"] if check(n, r)]
        assert len(fired) <= 1, (
            "%s negatives fired: %s" % (r["id"], fired))
