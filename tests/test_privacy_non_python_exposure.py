"""The exposure layer must be able to read Java and TypeScript at all.

_privacy_sanitized_exposure_text() was a Python AST round-trip. Every non
Python file failed to parse and sanitised to "", so _privacy_exposure_hits_*
returned before looking at a single rule. On the delivered estate (Java
services, Angular TypeScript) no exposure could ever be established -- the
STR report's 268 privacy rows are 100% OBSERVED_ONLY for that reason, not
because the code was clean.

The fallback strips comments and blanks string literals lexically, which is
the same guarantee the AST path gives: a comment or a string cannot create
exposure on its own. Only executable text can.
"""

from __future__ import annotations

import pathlib
import tempfile

from analysis.privacy_data_exposure_engine import (
    _privacy_exposure_hits_fast,
    _privacy_sanitized_exposure_text,
    enrich_privacy_data_exposure,
)

JAVA = """package com.htc.rbi.service;
import org.slf4j.Logger;
public class CustomerService {
    private static final Logger LOGGER = LoggerFactory.getLogger(CustomerService.class);
    public void audit(User user) {
        http.post("/collect", user.email);
    }
}
"""

TS = """import { Injectable } from '@angular/core';
@Injectable({ providedIn: 'root' })
export class PayComponent {
  send(user: User): void {
    axios.post('/pay', user.email);
  }
}
"""

JAVA_COMMENT_ONLY = """public class Notes {
    // http.post("/collect", user.email);
    /* axios.post('/pay', user.email); */
    private String note = "http.post(\\"/collect\\", user.email);";
}
"""

TS_COMMENT_ONLY = """export class Notes {
  // axios.post('/pay', user.email)
  /* fetch('/collect', user.email) */
  note = "axios.post('/pay', user.email)";
}
"""


def test_java_source_survives_sanitisation():
    clean = _privacy_sanitized_exposure_text(JAVA)
    assert clean.strip(), "Java sanitised to nothing"
    assert "user.email" in clean


def test_typescript_source_survives_sanitisation():
    clean = _privacy_sanitized_exposure_text(TS)
    assert clean.strip(), "TypeScript sanitised to nothing"
    assert "user.email" in clean


def test_comments_and_literals_are_removed_from_java():
    clean = _privacy_sanitized_exposure_text(JAVA)
    assert 'audit trail' not in clean
    assert "remove before release" not in clean
    assert '"collect"' not in clean


def test_a_comment_or_string_alone_never_creates_java_exposure():
    assert _privacy_exposure_hits_fast(JAVA_COMMENT_ONLY) == []


def test_a_comment_or_string_alone_never_creates_typescript_exposure():
    assert _privacy_exposure_hits_fast(TS_COMMENT_ONLY) == []


def test_java_transfer_sink_is_now_detected():
    assert [h[0] for h in _privacy_exposure_hits_fast(JAVA)] == [
        "PII_THIRD_PARTY_TRANSFER"]


def test_typescript_transfer_sink_is_now_detected():
    assert [h[0] for h in _privacy_exposure_hits_fast(TS)] == [
        "PII_THIRD_PARTY_TRANSFER"]


def test_python_keeps_the_ast_path():
    src = 'def f(user):\n    # http.post("/x", user.email)\n    return user.email\n'
    clean = _privacy_sanitized_exposure_text(src)
    assert "#" not in clean
    assert "http.post" not in clean
    assert "user.email" in clean


def _scan(relative: str, body: str) -> list:
    with tempfile.TemporaryDirectory(prefix="rsx_nonpython_") as raw:
        target = pathlib.Path(raw) / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body, encoding="utf-8")
        return enrich_privacy_data_exposure(
            raw, findings=[], live_progress=False).get("indicators") or []


def test_java_file_now_reports_a_third_party_transfer():
    rows = _scan("src/main/java/corp/PayService.java", JAVA)
    assert len(rows) == 1, rows
    assert rows[0]["indicator"] == "PII_THIRD_PARTY_TRANSFER"
    assert rows[0]["risk_level"] == "HIGH"
    assert rows[0]["static_exposure_confirmed"] is True


def test_typescript_file_now_reports_a_third_party_transfer():
    rows = _scan("src/app/pay.component.ts", TS)
    assert len(rows) == 1, rows
    assert rows[0]["indicator"] == "PII_THIRD_PARTY_TRANSFER"
    assert rows[0]["risk_level"] == "HIGH"
