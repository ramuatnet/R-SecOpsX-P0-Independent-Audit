"""logger.info(user.email) is a PII disclosure; it used to be invisible.

The shipped PII_LOGGING rule begins ``\\b(?:print|logger\\.|console\\.log|log\\.)
\\s*\\(`` -- it needs ``(`` immediately after the receiver. Production code
writes ``logger.info(``, ``log.debug(``, ``LOGGER.warn(`` and
``System.out.println(``, none of which match. Its field alternation also
requires ``user.email``, so Java getters (``user.getEmail()``) were missed too.

_RSECOPSX_ORIGINAL_PRIVACY_EXPOSURE_RULES was None because the names the
preservation block looks for (_PRIVACY_EXPOSURE_RULES / PRIVACY_EXPOSURE_RULES)
were never defined, so the bounded path only knew the transfer syntax.

This adds a second rule object -- the legacy rule string is asserted unchanged
below -- and supplies the compiled rule set the engine was already looking for.
Set RSECOPSX_PRIVACY_EXPOSURE_RULES=0 for the previous behaviour.
"""

from __future__ import annotations

import pathlib
import re
import tempfile

import pytest

import analysis.privacy_data_exposure_engine as engine
from analysis.privacy_data_exposure_engine import (
    EXPOSURE_PATTERNS,
    _privacy_exposure_hits_fast,
    _privacy_exposure_rules_enabled,
    enrich_privacy_data_exposure,
)


def _scan(relative: str, body: str) -> list:
    with tempfile.TemporaryDirectory(prefix="rsx_log_sink_") as raw:
        target = pathlib.Path(raw) / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body, encoding="utf-8")
        return enrich_privacy_data_exposure(
            raw, findings=[], live_progress=False).get("indicators") or []


def _only(rows: list) -> dict:
    assert len(rows) == 1, rows
    return rows[0]


def test_python_logger_info_is_a_high_log_exposure():
    row = _only(_scan("src/pay/audit.py",
                      "import logging\nlogger = logging.getLogger()\n"
                      "def audit(user):\n    logger.info(user.email)\n"))
    assert row["indicator"] == "PII_LOGGING"
    assert row["risk_level"] == "HIGH"
    assert row["privacy_evidence_state"] == "EXPOSED"
    assert row["static_exposure_confirmed"] is True


def test_java_slf4j_is_a_high_log_exposure():
    row = _only(_scan("src/main/java/corp/Audit.java", (
        "public class Audit {\n"
        "  public void audit(User user) {\n"
        '    LOGGER.info("audit email=" + user.getEmail());\n'
        "  }\n}\n")))
    assert row["indicator"] == "PII_LOGGING"
    assert row["risk_level"] == "HIGH"


def test_java_system_out_is_a_high_log_exposure():
    row = _only(_scan("src/main/java/corp/Dump.java", (
        "public class Dump {\n"
        "  public void dump(User user) {\n"
        "    System.out.println(user.email);\n"
        "  }\n}\n")))
    assert row["indicator"] == "PII_LOGGING"
    assert row["risk_level"] == "HIGH"


def test_typescript_console_info_is_a_high_log_exposure():
    row = _only(_scan("src/app/header.component.ts", (
        "export class Header {\n"
        "  log(user: User) {\n"
        "    console.info('email', user.email);\n"
        "  }\n}\n")))
    assert row["indicator"] == "PII_LOGGING"
    assert row["risk_level"] == "HIGH"


def _comment_or_string_only(relative: str, body: str):
    with tempfile.TemporaryDirectory(prefix="rsx_log_sink_neg_") as raw:
        target = pathlib.Path(raw) / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body, encoding="utf-8")
        rows = enrich_privacy_data_exposure(
            raw, findings=[], live_progress=False).get("indicators") or []
    # PII observation is a separate question (it may still note a field name
    # mentioned in a comment). What must not happen is an EXPOSED verdict.
    assert not [r for r in rows if r.get("privacy_evidence_state") == "EXPOSED"], rows
    assert not [r for r in rows
                if r.get("indicator") in {"PII_LOGGING", "PII_THIRD_PARTY_TRANSFER"}], rows


def test_a_commented_out_log_call_is_not_exposure():
    _comment_or_string_only("src/app/a.ts", (
        "export class A {\n"
        "  // console.info('email', user.email)\n"
        "  /* logger.info(user.email) */\n"
        "  note = \"logger.info(user.email)\";\n}\n"))


def test_a_log_call_without_pii_is_not_exposure():
    _comment_or_string_only("src/main/java/corp/B.java", (
        "public class B {\n"
        "  public void audit(String message) {\n"
        "    LOGGER.info(message);\n"
        "  }\n}\n"))


def test_transfer_sink_still_reports():
    assert [h[0] for h in _privacy_exposure_hits_fast(
        'axios.post("/pay", user.email)')] == ["PII_THIRD_PARTY_TRANSFER"]


def test_the_legacy_rule_object_is_unchanged():
    legacy = dict((name, pattern) for name, pattern, _r, _i in EXPOSURE_PATTERNS)
    assert r"\b(?:print|logger\.|console\.log|log\.)\s*\(" in legacy["PII_LOGGING"]
    # The expanded rule is a second object, not an edit of the first.
    assert engine._PRIVACY_LOG_SINK_EXPANDED_RE.pattern != legacy["PII_LOGGING"]


def test_compiled_rule_set_is_supplied_to_the_bounded_path():
    rules = engine._RSECOPSX_ORIGINAL_PRIVACY_EXPOSURE_RULES
    assert isinstance(rules, tuple) and rules
    names = [rule[0] for rule in rules]
    assert "PII_LOGGING" in names and "PII_THIRD_PARTY_TRANSFER" in names
    assert all(hasattr(rule[1], "search") for rule in rules)


@pytest.mark.parametrize("value, expected", [
    ("0", False), ("false", False), ("off", False), ("no", False),
    ("1", True), ("true", True), ("", True),
])
def test_flag_parsing(monkeypatch, value, expected):
    monkeypatch.setenv("RSECOPSX_PRIVACY_EXPOSURE_RULES", value)
    assert _privacy_exposure_rules_enabled() is expected


def test_flag_unset_means_enabled(monkeypatch):
    monkeypatch.delenv("RSECOPSX_PRIVACY_EXPOSURE_RULES", raising=False)
    assert _privacy_exposure_rules_enabled() is True


def _summary(relative: str, body: str) -> dict:
    with tempfile.TemporaryDirectory(prefix="rsx_log_sink_sum_") as raw:
        target = pathlib.Path(raw) / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body, encoding="utf-8")
        return enrich_privacy_data_exposure(
            raw, findings=[], live_progress=False)


def test_log_row_in_a_vendor_mentioning_file_is_not_counted_as_a_transfer():
    summary = _summary("src/pay/api.ts", (
        "// analytics export\n"
        "export class Sink {\n"
        "  audit(user: User) {\n"
        "    console.log(user.email);\n"
        "  }\n}\n"))
    exposed = [r for r in summary["indicators"] if r.get("privacy_evidence_state") == "EXPOSED"]
    assert [r["indicator"] for r in exposed] == ["PII_LOGGING"]
    assert summary["third_party_transfer_indicators"] == 0


def test_transfer_row_is_counted_even_without_a_vendor_word():
    summary = _summary("src/pay/api.py", (
        "def send(user):\n"
        '    requests.post("https://collector.example/x", json={"email": user.email})\n'))
    exposed = [r for r in summary["indicators"] if r.get("privacy_evidence_state") == "EXPOSED"]
    assert [r["indicator"] for r in exposed] == ["PII_THIRD_PARTY_TRANSFER"]
    assert summary["third_party_transfer_indicators"] == 1
