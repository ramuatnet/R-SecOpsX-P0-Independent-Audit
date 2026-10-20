"""
tests/test_v11_evidex_sink_metadata_recovery.py

RSECOPSX_EVIDEX_SINK_CALL_RECOVERY_20261020

The Java taint line layer (JAVA_TAINT_PATH_TRAVERSAL /
JAVA_TAINT_COMMAND_INJECTION and friends) emits its sink in the `sink_call`
field.  EVIDEX's sink-candidate extractor only consulted `sink_category`,
`sink` and `sink_expr`, so every line-layer finding whose sink could not be
re-matched from the raw evidence text produced candidates == set() and was
marked evidence_valid=False.  enrich_finding() (core/analyzer.py) returns {}
for evidence_valid=False findings, which silently deletes them at report
intake.  Measured on the OWASP BenchmarkJava 1.2 oracle (2,740 labelled
tests), via the exact main.py post-processing stages:

    line layer detects     pathtraver 133/133, cmdi 104/126
    enrich_finding keeps   pathtraver   5/133, cmdi  91/104
    report aligned recall  pathtraver  27.8%,   cmdi  89.7%

Two sink shapes defeat the alias table for *any* text re-match:

  * package-qualified file sinks:  ``new java.io.FileInputStream(...)``  --
    the alias is spelled ``new fileinputstream(`` and ``java.io.`` sits
    between the two tokens, so no alias can ever match.  J5 findings with
    the identical snippet survived only because J5 populates `sink`, and
    ``file`` is a substring of ``fileinputstream`` in the explicit-map path.

  * ProcessBuilder chains whose taint path never spells the class name:
    ``... -> pb.command(...) -> pb.start(`` -- the alias ``processbuilder(``
    cannot match a flow expressed through the ``pb`` local.

The fix (core/analyzer.py):
  1. _evidex_sink_candidates() also consults `sink_call` (the field the
     line layer actually emits) for the explicit-map token check.  ``file``
     is a substring of the qualified form, so ``new java.io.FileInputStream(``
     yields the ``file`` candidate it always deserved.
  2. Terminal inference from a validated ``source -> sink`` taint_path now
     recognises file APIs (``... -> new java.io.FileOutputStream(``) and
     process launches (``... -> pb.start(``).  This runs ONLY on taint
     paths containing the `` -> `` separator, so prose-only evidence keeps
     its gate.

Counter-guards pin that the EVIDEX gate is NOT weakened: findings without
sink metadata and without a validated flow must remain invalid.

Every engine-level test drives the real scanner entry point
(scanner.taint_engine.analyze_file) on the same shapes measured on the
oracle, not on a literal the fix happens to emit.
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.analyzer import (  # noqa: E402
    _evidex_sink_candidates,
    _validate_security_evidence,
    build_report_payload,
    enrich_finding,
)
from scanner.taint_engine import analyze_file  # noqa: E402


# ---------------------------------------------------------------------------
# Real-engine fixtures: the exact shapes BenchmarkJava pathtraver/cmdi
# positives produce (package-qualified sinks, ProcessBuilder via pb.command).
# ---------------------------------------------------------------------------

_TRAV_QUALIFIED_SRC = '''import java.io.*;
import javax.servlet.http.*;

class TravQualified {
  public void service(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String fileName = request.getParameter("f");
    java.io.FileOutputStream fos = new java.io.FileOutputStream(fileName, false);
    fos.close();
  }
}
'''

_CMD_PB_CHAIN_SRC = '''import java.util.*;
import javax.servlet.http.*;

class CmdPbCommand {
  public void service(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String param = request.getParameter("c");
    List<String> argList = new ArrayList<>();
    argList.add(param);
    ProcessBuilder pb = new ProcessBuilder("sh", "-c", "");
    pb.command(argList);
    Process p = pb.start();
    p.waitFor();
  }
}
'''


def _scan_source(name: str, source: str) -> list[dict]:
    with tempfile.TemporaryDirectory(prefix="evidex_recovery_") as tmp:
        path = os.path.join(tmp, name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(source)
        return [dict(f) for f in analyze_file(path)]


# ---------------------------------------------------------------------------
# 1. Real engine -> EVIDEX must validate qualified file sinks (RED: dropped).
# ---------------------------------------------------------------------------

def test_line_layer_qualified_file_sink_validates():
    hits = [f for f in _scan_source("TravQualified.java", _TRAV_QUALIFIED_SRC)
            if f.get("rule_id") == "JAVA_TAINT_PATH_TRAVERSAL"]
    assert hits, "fixture must fire the line-layer path traversal rule"
    hit = hits[0]
    assert hit.get("sink_call"), "line layer records its sink in sink_call"
    result = _validate_security_evidence(dict(hit))
    assert result.get("valid") is True, (
        "package-qualified java.io sinks must validate from sink_call; "
        f"got reason={result.get('reason')!r} candidates={result.get('sink_candidates')!r}"
    )
    assert "file" in (result.get("sink_candidates") or set())


def test_line_layer_qualified_file_sink_survives_enrichment():
    hits = [f for f in _scan_source("TravQualified.java", _TRAV_QUALIFIED_SRC)
            if f.get("rule_id") == "JAVA_TAINT_PATH_TRAVERSAL"]
    assert hits
    kept = enrich_finding(dict(hits[0]))
    assert kept, "enrich_finding must not discard a validated line-layer finding"
    assert kept.get("evidence_valid") is not False


# ---------------------------------------------------------------------------
# 2. Real engine -> ProcessBuilder chain whose taint path never names the
#    class must validate (RED: dropped).
# ---------------------------------------------------------------------------

def test_line_layer_processbuilder_chain_validates():
    hits = [f for f in _scan_source("CmdPbCommand.java", _CMD_PB_CHAIN_SRC)
            if f.get("rule_id") == "JAVA_TAINT_COMMAND_INJECTION"]
    assert hits, "fixture must fire the line-layer command injection rule"
    hit = hits[0]
    assert "pb.start" in str(hit.get("sink_call") or "").replace(" ", "")
    result = _validate_security_evidence(dict(hit))
    assert result.get("valid") is True, (
        "pb.start( sinks must validate from the taint-path terminal; "
        f"got reason={result.get('reason')!r} candidates={result.get('sink_candidates')!r}"
    )
    assert "command" in (result.get("sink_candidates") or set())
    kept = enrich_finding(dict(hit))
    assert kept, "enrich_finding must not discard the ProcessBuilder finding"


# ---------------------------------------------------------------------------
# 3. Unit contracts: sink_call feeds the explicit-map path; the validated
#    taint-path terminal feeds file/command terminals.
# ---------------------------------------------------------------------------

def test_sink_call_feeds_explicit_sink_candidates():
    finding = {
        "vuln_type": "path_traversal",
        "sink_call": "new java.io.FileInputStream(",
    }
    cands = _evidex_sink_candidates(finding, "")
    assert "file" in cands


def test_taint_path_terminal_infers_file_candidate():
    finding = {
        "vuln_type": "path_traversal",
        "taint_path": "fileName -> new java.io.FileOutputStream(",
    }
    cands = _evidex_sink_candidates(finding, "")
    assert "file" in cands


def test_taint_path_terminal_infers_command_candidate():
    finding = {
        "vuln_type": "command_injection",
        "taint_path": "param -> argList -> pb.command(...) -> pb.start(",
    }
    cands = _evidex_sink_candidates(finding, "")
    assert "command" in cands


@pytest.mark.parametrize("taint_path", [
    # The four JDBC statement-preparation shapes the line layer emits that
    # carry no "execute"/"query" alias token anywhere in their evidence.
    "param -> sql -> prepareStatement(",
    "param -> sql -> prepareCall(",
    "param -> bar -> sql -> batchUpdate(",
    "param -> bar -> sql -> addBatch(",
])
def test_taint_path_terminal_infers_sql_candidate(taint_path):
    finding = {
        "vuln_type": "sql_injection",
        "sink_call": taint_path.rsplit("->", 1)[-1].strip(),
        "taint_path": taint_path,
    }
    cands = _evidex_sink_candidates(finding, "")
    assert "sql" in cands


# ---------------------------------------------------------------------------
# 4. Counter-guards: the EVIDEX gate must NOT weaken (GREEN now, stay green).
# ---------------------------------------------------------------------------

def test_prose_only_path_traversal_stays_invalid():
    finding = {
        "vuln_type": "path_traversal",
        "file": "src/App.java",
        "line": 12,
        "snippet": "The quick brown fox reads the requested location.",
    }
    result = _validate_security_evidence(dict(finding))
    assert not result.get("valid"), (
        "prose evidence with no sink metadata and no validated flow must stay invalid"
    )


def test_thread_start_without_flow_stays_invalid():
    finding = {
        "vuln_type": "command_injection",
        "file": "src/App.java",
        "line": 40,
        "snippet": "Thread t = new Thread(worker); t.start();",
    }
    result = _validate_security_evidence(dict(finding))
    assert not result.get("valid"), (
        "'.start' without a validated source->sink flow must not validate"
    )


def test_sink_field_findings_still_validate():
    # Regression: J5-style findings populate `sink` and must keep working.
    finding = {
        "vuln_type": "path_traversal",
        "sink": "new java.io.FileInputStream(",
        "snippet": "fis = new java.io.FileInputStream(fileName);",
    }
    result = _validate_security_evidence(dict(finding))
    assert result.get("valid") is True
    assert "file" in (result.get("sink_candidates") or set())


# ---------------------------------------------------------------------------
# 5. End to end: recovered findings must reach the report payload.
# ---------------------------------------------------------------------------

def test_recovered_findings_reach_report_payload():
    hits = []
    for name, src in (("TravQualified.java", _TRAV_QUALIFIED_SRC),
                      ("CmdPbCommand.java", _CMD_PB_CHAIN_SRC)):
        hits += _scan_source(name, src)
    assert hits
    payload = build_report_payload(list(hits), [], tempfile.gettempdir())
    findings = payload.get("findings") or []
    assert findings, "line-layer findings must survive to the report payload"
    kept_vulns = {str(f.get("vuln_type")) for f in findings}
    assert "path_traversal" in kept_vulns
    assert "command_injection" in kept_vulns
