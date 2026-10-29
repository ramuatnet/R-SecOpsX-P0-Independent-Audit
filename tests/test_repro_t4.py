"""T-4.1 repro sandbox + T-4.2 evidence/PoC bundler.

Covers: schema extension (VerificationStatus on Evidence), BLOCKED
handling, a real local bring-up against a fixture HTTP server, status
derivation (REPRODUCED/REFUTED/INCONCLUSIVE/BLOCKED/UNTESTED), manifest
hashes, canonical Evidence, and the coverage/refutation report math.
"""
from __future__ import annotations

import ast
import hashlib
import json
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from analysis.repro import bundler as bd
from analysis.repro.sandbox import (
    HttpPayload,
    ReproTarget,
    detect_runtime,
    run_repro,
)
from core.evidence_schema import (
    Evidence,
    EvidenceConfidence,
    EvidenceProvenance,
    EvidenceSource,
    EvidenceTimestamp,
    EvidenceType,
    EvidenceValidationError,
    VerificationStatus,
    utc_now_iso8601,
)


# --- fixture: stdlib HTTP server (written to tmp, launched as a target) ----
_SERVER_SRC = r'''
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

class H(BaseHTTPRequestHandler):
    def _reply(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n)
        payload = b"rsx-probe-marker" if b"rsx" in body else b"no-payload"
        out = b'{"echo": "' + payload + b'"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)
        print("served", self.command, self.path, flush=True)

    do_GET = do_POST = _reply

    def log_message(self, *a):
        pass

HTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
'''


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture()
def live_target(tmp_path):
    """(ReproTarget, base_url) for a real bring-up/teardown cycle."""
    script = tmp_path / "srv.py"
    script.write_text(_SERVER_SRC, encoding="utf-8")
    port = _free_port()
    base = f"http://127.0.0.1:{port}"
    target = ReproTarget(
        name="fixture-server",
        launch=(sys.executable, str(script), str(port)),
        workdir=str(tmp_path),
        base_url=base,
        ready_url=f"{base}/health",
        ready_timeout_s=15.0,
    )
    return target, base


def _finding(rule="TAINT_SQL_INJECTION", vuln="sql_injection",
             sev="High", chain=None, lang="python"):
    return {
        "rule_id": rule, "vuln_type": vuln, "severity": sev,
        "file": "app/views.py", "line": 42, "language": lang,
        "group_key": f"{vuln}|app/views.py|42|x",
        "taint_chain": chain or ["request.args", "q", "query"],
        "source_var": "q",
    }


def _capture(applied=True, blocked="", expect_resp=None):
    return {
        "target": "t",
        "runtime_used": "local",
        "blocked_reason": blocked,
        "payload_applied": applied,
        "request": {"method": "POST", "path": "/"},
        "response": expect_resp or {"status": 200, "body": "ok"},
        "errors": [],
        "env_fingerprint": {"image_digest": None, "tool_version": "v2.1"},
    }


# --- schema extension ------------------------------------------------------
def test_verification_status_lives_on_evidence():
    def ev(status=None):
        kwargs = dict(
            source=EvidenceSource(engine="e", component="c"),
            provenance=EvidenceProvenance(
                source="s", observed_at=utc_now_iso8601(),
                engine="e", component="c"),
            evidence_type=EvidenceType.DYNAMIC,
            content_or_context={"k": 1},
            confidence=EvidenceConfidence.HIGH,
        )
        if status is not None:
            kwargs["verification_status"] = status
        return Evidence.create(**kwargs)

    e = ev()
    assert e.verification_status is VerificationStatus.UNTESTED
    assert e.to_dict()["verification_status"] == "UNTESTED"
    e2 = ev(VerificationStatus.REPRODUCED)
    assert e2.to_dict()["verification_status"] == "REPRODUCED"
    bad = Evidence(
        evidence_id=str(__import__("uuid").uuid4()),
        source=EvidenceSource(engine="e", component="c"),
        timestamp=EvidenceTimestamp(utc_now_iso8601()),
        provenance=EvidenceProvenance(
            source="s", observed_at=utc_now_iso8601(),
            engine="e", component="c"),
        type=EvidenceType.DYNAMIC, content_or_context={},
        confidence=EvidenceConfidence.LOW,
        verification_status="NOT_A_STATUS",
    )
    # direct construction defers validation; validate()/to_dict() enforce it
    with pytest.raises(EvidenceValidationError):
        bad.validate()
    with pytest.raises(EvidenceValidationError):
        bad.to_dict()


def test_verification_status_set_is_exactly_the_spec():
    assert {v.value for v in VerificationStatus} == {
        "UNTESTED", "REPRODUCED", "REFUTED", "INCONCLUSIVE", "BLOCKED"}


# --- sandbox ---------------------------------------------------------------
def test_detect_runtime_never_raises():
    info = detect_runtime()
    assert info.kind in {"docker", "podman", "none"}
    assert isinstance(info.to_dict(), dict)


def test_forced_local_without_launch_is_blocked():
    cap = run_repro(ReproTarget(name="nothing"), HttpPayload(),
                    runtime="local")
    assert cap.blocked
    assert "launch" in cap.blocked_reason
    assert cap.env_fingerprint.get("os")
    assert not cap.payload_applied


def test_auto_without_anything_is_blocked():
    cap = run_repro(ReproTarget(name="nothing"), HttpPayload())
    assert cap.blocked
    assert cap.runtime_used == ""


def test_live_local_repro_captures_everything(live_target):
    target, base = live_target
    payload = HttpPayload(method="POST", path="/probe",
                          headers=(("Content-Type", "application/json"),),
                          body=b'{"q": "rsx probe"}')
    cap = run_repro(target, payload, runtime="local")
    assert not cap.blocked, cap.blocked_reason
    assert cap.runtime_used == "local"
    assert cap.payload_applied, cap.errors
    assert cap.response["status"] == 200
    assert "rsx-probe-marker" in cap.response["body"]
    assert cap.exit_code is not None
    assert "served" in cap.stdout
    assert cap.timing_ms.get("total", 0) > 0
    fp = cap.env_fingerprint
    assert fp["runtime"] == "docker" or fp["runtime"] in {"docker", "podman",
                                                          "none"}
    assert fp["image_digest"] in (None, "")
    d = cap.to_dict()
    json.dumps(d)  # must serialize for capture.json
    # teardown: the port is free again (server gone)
    time.sleep(0.1)
    with socket.socket() as s:
        assert s.connect_ex(("127.0.0.1", int(base.rsplit(":", 1)[1]))) != 0


# --- bundler: PoC generation + status --------------------------------------
def test_generate_poc_for_python_sqli_is_runnable(tmp_path):
    arts = dict(bd.generate_poc(_finding()))
    assert "poc.py" in arts
    ok, why = bd.poc_is_runnable("poc.py", arts["poc.py"])
    assert ok, why
    # runnable proof: executes and returns the usage exit code (3) without
    # a base url -- a generated PoC must actually run.
    poc = tmp_path / "poc.py"
    poc.write_text(arts["poc.py"], encoding="utf-8")
    proc = subprocess.run([sys.executable, str(poc)],
                          capture_output=True, text=True, timeout=30)
    assert proc.returncode == 3, proc.stderr


def test_generate_poc_unmodelled_family_is_empty():
    # Secret/hardcoded-credential findings have no attack payload model --
    # honest emptiness beats a decorative script.
    assert bd.generate_poc(_finding(rule="SAST-HARDCRED",
                                    vuln="hardcoded_secret")) == []


def test_status_derivation_table():
    assert bd.determine_status(None, None)[0] == "UNTESTED"
    assert bd.determine_status(_capture(blocked="daemon down"), None)[0] == \
        "BLOCKED"
    assert bd.determine_status(_capture(applied=False,
                                        expect_resp={}), None)[0] == "BLOCKED"
    assert bd.determine_status(_capture(), None)[0] == "INCONCLUSIVE"
    assert bd.determine_status(
        _capture(expect_resp={"status": 200, "body": "ok"}),
        {"status": 200})[0] == "REPRODUCED"
    assert bd.determine_status(
        _capture(expect_resp={"status": 200}),
        {"status": 500})[0] == "REFUTED"
    assert bd.determine_status(
        _capture(expect_resp={"body": "zzz"}), {"body_contains": "ok"})[0] == \
        "REFUTED"


def test_bundle_writes_manifest_with_hashes(tmp_path):
    f = _finding()
    man = bd.bundle_finding(f, tmp_path / "out")
    assert man["schema"] == bd.BUNDLE_SCHEMA
    assert man["verification_status"] == "UNTESTED"
    bdir = tmp_path / "out" / bd._finding_key(f)
    # recompute input sha from the finding itself
    expect_in = hashlib.sha256(
        json.dumps(f, sort_keys=True, default=str).encode()).hexdigest()
    assert man["input_sha256"] == expect_in
    for art in man["artifacts"]:
        disk = bdir / art["name"]
        assert hashlib.sha256(disk.read_bytes()).hexdigest() == \
            art["sha256"]
        assert art["runnable"] is True
    assert (bdir / "manifest.json").is_file()
    assert man["tool_version"]


def test_bundle_with_capture_and_expectation(tmp_path):
    f = _finding()
    man = bd.bundle_finding(f, tmp_path / "a",
                            capture=_capture(expect_resp={"status": 200}),
                            expect={"status": 200})
    assert man["verification_status"] == "REPRODUCED"
    man2 = bd.bundle_finding(f, tmp_path / "b",
                             capture=_capture(expect_resp={"status": 500}),
                             expect={"status": 200})
    assert man2["verification_status"] == "REFUTED"
    man3 = bd.bundle_finding(f, tmp_path / "c",
                             capture=_capture(blocked="no runtime"))
    assert man3["verification_status"] == "BLOCKED"
    # not modelled: UNTESTED with the machine-readable reason
    man4 = bd.bundle_finding(_finding(rule="SAST-HARDCRED",
                                      vuln="hardcoded_secret"),
                             tmp_path / "d")
    assert man4["verification_status"] == "UNTESTED"
    assert man4["status_reason"].startswith("NOT_MODELLED")


def test_evidence_for_bundle_is_canonical(tmp_path):
    f = _finding()
    man = bd.bundle_finding(f, tmp_path / "e",
                            capture=_capture(expect_resp={"status": 200}),
                            expect={"status": 200})
    ev = bd.evidence_for_bundle(man, _capture())
    assert ev.verification_status is VerificationStatus.REPRODUCED
    assert ev.type.value == "dynamic"
    # round-trips through the schema mapper
    from core.evidence_schema import evidence_from_mapping
    back = evidence_from_mapping(ev.to_dict())
    assert back.verification_status is VerificationStatus.REPRODUCED


# --- coverage / refutation report -----------------------------------------
def test_coverage_gate_and_refutation_rate(tmp_path):
    manifests = []
    # 4 High findings: 3 modelled with runnable PoC, 1 not modelled
    for i in range(3):
        manifests.append({
            "finding": {"severity": "High"},
            "artifacts": [{"name": "poc.py", "runnable": True}],
            "verification_status": "UNTESTED",
        })
    manifests.append({
        "finding": {"severity": "Critical"},
        "artifacts": [],
        "status_reason": "NOT_MODELLED: x",
        "verification_status": "UNTESTED",
    })
    manifests.append({
        "finding": {"severity": "Low"},  # outside the gate population
        "artifacts": [], "verification_status": "UNTESTED",
    })
    report = bd.coverage_report(manifests, tmp_path / "cov")
    assert report["gate"]["pass"] is True  # 3/4 = 75% >= 40%
    assert report["population"]["high_critical"] == 4
    assert report["population"]["high_critical_with_runnable_poc"] == 3
    assert report["population"]["not_modelled"] == 1
    # zero judged captures -> null, not a fake 0.0
    assert report["refutation_rate"]["rate"] is None
    assert report["refutation_rate"]["tested"] == 0
    assert (tmp_path / "cov" / "coverage_report.json").is_file()

    # judged captures compute the rate
    manifests[0]["verification_status"] = "REFUTED"
    manifests[1]["verification_status"] = "REPRODUCED"
    report2 = bd.coverage_report(manifests, tmp_path / "cov2")
    assert report2["refutation_rate"] == {
        "refuted": 1, "reproduced": 1, "tested": 2, "rate": 0.5,
        "note": report2["refutation_rate"]["note"],
    }


def test_coverage_gate_fails_below_threshold(tmp_path):
    manifests = [{
        "finding": {"severity": "High"},
        "artifacts": [{"name": "poc.py", "runnable": False}],
        "verification_status": "UNTESTED",
    }] * 5
    report = bd.coverage_report(manifests, tmp_path / "cov")
    assert report["gate"]["pass"] is False
    assert report["gate"]["measured"] == 0.0


def test_cli_end_to_end(tmp_path):
    findings = [_finding(), _finding(rule="SAST-HARDCRED",
                                     vuln="hardcoded_secret",
                                     chain=[], lang="generic")]
    fpath = tmp_path / "findings.json"
    fpath.write_text(json.dumps(findings), encoding="utf-8")
    rc = bd.main(["--findings", str(fpath), "--out",
                  str(tmp_path / "bundles"), "--expect-status", "200",
                  "--capture", str(_write_capture(tmp_path))])
    # 1 modelled High of 2 High/Critical = 50% -> gate passes; with the
    # capture + expectation the modelled one is judged REPRODUCED.
    assert rc == 0
    report = json.loads(
        (tmp_path / "bundles" / "coverage_report.json").read_text())
    assert report["by_status"].get("REPRODUCED") == 1
    assert report["by_status"].get("UNTESTED") == 1


def _write_capture(tmp_path) -> Path:
    cap = _capture(expect_resp={"status": 200, "body": "ok"})
    p = tmp_path / "cap.json"
    p.write_text(json.dumps(cap), encoding="utf-8")
    return p
