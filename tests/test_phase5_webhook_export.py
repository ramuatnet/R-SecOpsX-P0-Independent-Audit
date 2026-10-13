"""Phase 5.2: webhook / DefectDojo import JSON exports.

WHAT THIS DELIVERS
------------------
Gap-plan row 5.2 ("Webhook/JSON API output for DefectDojo/SecObserve
ingestion", verify: POST findings JSON -> DT import works). A scan must
not push into someone else's tracker, so the deliverable is the JSON that
makes the POST a copy-paste away:

* Security_Findings_Webhook.json — a reduced, redacted findings
  projection in the stable rsecopsx.findings-webhook/v1 schema;
* Security_DefectDojo_Import.json — the multipart POST blueprint for
  DefectDojo's import-scan API (endpoint, form fields, the SARIF
  artifact embedded base64, a ready curl command). The contract was
  verified against DefectDojo's API v2 documentation and their
  generated API client (scan_type enum includes SARIF).

WHAT THESE TESTS PIN
--------------------
* the projection carries only documented fields, 1:1 with the payload's
  findings, with the redaction guarantee intact;
* the blueprint's endpoint/content_type/scan_type, the REQUIRED
  engagement placeholder, and verified=false (a scanner cannot claim a
  human verified its findings);
* the embedded SARIF base64 decodes back to the artifact byte-for-byte;
* fail-open: a missing SARIF produces content_base64 null, never an
  exception;
* determinism of both artifacts.
"""
from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from reporting.webhook_export import (  # noqa: E402
    WEBHOOK_SCHEMA,
    build_defectdojo_import_blueprint,
    build_findings_webhook_payload,
    write_webhook_exports,
)


def _finding(rule_id="SQL_INJECTION", severity="High", **extra):
    finding = {
        "finding_id": "FINDING_ABC123",
        "rule_id": rule_id,
        "vuln_type": "sql_injection",
        "severity": severity,
        "cwe": "CWE-89",
        "file": "svc/User.py",
        "line": 42,
        "description": "Untrusted input reached the SQL sink.",
        "remediation": "Use parameterized queries.",
        "confidence": "high",
    }
    finding.update(extra)
    return finding


def _payload(*findings, target="/repo/app", tool="R-SecOpsX SAST v2.0"):
    return {
        "metadata": {"tool": tool, "target": target,
                     "scan_date": "2026-10-13T00:00:00Z"},
        "findings": list(findings),
    }


def _write(tmp_path, *findings, sarif_text='{"version":"2.1.0"}', **payload_kwargs):
    sarif = tmp_path / "Security_Report.sarif"
    sarif.write_text(sarif_text, encoding="utf-8")
    summary = write_webhook_exports(
        _payload(*findings, **payload_kwargs), str(tmp_path))
    webhook = json.loads(
        (tmp_path / "Security_Findings_Webhook.json").read_text("utf-8"))
    blueprint = json.loads(
        (tmp_path / "Security_DefectDojo_Import.json").read_text("utf-8"))
    return summary, webhook, blueprint


# ---------------------------------------------------------------------------
# Findings webhook projection.
# ---------------------------------------------------------------------------

def test_projection_is_one_to_one_and_carries_only_documented_keys(tmp_path):
    summary, webhook, _ = _write(tmp_path, _finding(), _finding("XSS", "Low"))
    assert summary["findings_webhook"]["findings"] == 2
    assert webhook["schema"] == WEBHOOK_SCHEMA
    assert webhook["summary"]["findings"] == 2
    assert webhook["summary"]["by_severity"] == {"High": 1, "Low": 1}
    for projected in webhook["findings"]:
        assert set(projected) <= {
            "finding_id", "rule_id", "vuln_type", "severity", "cwe",
            "file", "line", "description", "remediation", "confidence",
            "fix_snippet",
        }


def test_projection_context_comes_from_metadata(tmp_path):
    _, webhook, _ = _write(tmp_path, _finding(), target="/repo/app")
    assert webhook["tool"]["name"] == "R-SecOpsX SAST v2.0"
    assert webhook["project"]["target"] == "/repo/app"
    assert webhook["project"]["name"] == "app"
    assert webhook["generated_from"] == "clean_report.json"


def test_fix_snippet_rides_along_when_the_finding_has_one(tmp_path):
    snippet = {"kind": "parameterized_query", "language": "python",
               "before": "a", "after": "b", "template": True,
               "applied": False}
    _, webhook, _ = _write(tmp_path, _finding(fix_snippet=snippet))
    assert webhook["findings"][0]["fix_snippet"] == snippet
    # ...and is simply absent when the finding does not carry one.
    _, webhook2, _ = _write(tmp_path, _finding())
    assert "fix_snippet" not in webhook2["findings"][0]


def test_non_dict_findings_are_skipped():
    webhook = build_findings_webhook_payload(
        {"findings": [_finding(), "junk", None]})
    assert webhook["summary"]["findings"] == 1


def test_webhook_free_text_is_redacted(tmp_path):
    _, webhook, _ = _write(
        tmp_path,
        _finding(description="key: -----BEGIN RSA PRIVATE KEY-----\nMIIE\n"
                             "-----END RSA PRIVATE KEY-----"))
    text = json.dumps(webhook)
    assert "PRIVATE KEY" not in text and "MIIE" not in text


def test_webhook_projection_is_deterministic(tmp_path):
    payload = _payload(_finding(), _finding("CMD", "Critical"))
    a = build_findings_webhook_payload(json.loads(json.dumps(payload)))
    b = build_findings_webhook_payload(json.loads(json.dumps(payload)))
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


# ---------------------------------------------------------------------------
# DefectDojo import blueprint.
# ---------------------------------------------------------------------------

def test_blueprint_carries_the_documented_api_contract(tmp_path):
    _, _, blueprint = _write(tmp_path, _finding())
    assert blueprint["api"]["endpoint"] == "/api/v2/import-scan/"
    assert blueprint["api"]["method"] == "POST"
    assert blueprint["api"]["content_type"] == "multipart/form-data"
    assert blueprint["api"]["accept"] == "application/json"
    assert "Authorization: Token" in blueprint["api"]["authentication"]
    assert blueprint["api"]["reimport_endpoint"] == "/api/v2/reimport-scan/"


def test_blueprint_form_fields_preserve_the_report_and_honesty(tmp_path):
    _, _, blueprint = _write(tmp_path, _finding())
    fields = blueprint["form_fields"]
    assert fields["scan_type"] == "SARIF"
    # 1:1 with the report: nothing filtered at the boundary.
    assert fields["minimum_severity"] == "Info"
    assert fields["close_old_findings"] == "false"
    # A scanner cannot claim a human verified its own findings.
    assert fields["verified"] == "false"
    # The engagement lives in the target instance; a scan cannot know it.
    assert "REQUIRED" in fields["engagement"]
    assert fields["tags"] == "rsecopsx"


def test_blueprint_embeds_the_sarif_artifact_byte_for_byte(tmp_path):
    sarif_text = '{"version": "2.1.0", "runs": []}'
    _, _, blueprint = _write(tmp_path, _finding(), sarif_text=sarif_text)
    embedded = blueprint["file"]["content_base64"]
    assert embedded is not None
    assert base64.b64decode(embedded).decode("utf-8") == sarif_text
    assert blueprint["file"]["name"] == "Security_Report.sarif"
    assert blueprint["file"]["field"] == "file"


def test_blueprint_fails_open_when_sarif_is_missing(tmp_path):
    blueprint = build_defectdojo_import_blueprint(
        _payload(_finding()), tmp_path / "nope.sarif")
    assert blueprint["file"]["content_base64"] is None
    assert blueprint["notes"] and "could not be read" in blueprint["notes"][0]


def test_curl_command_is_ready_to_run_with_placeholders(tmp_path):
    _, _, blueprint = _write(tmp_path, _finding())
    curl = blueprint["curl"]
    assert "/api/v2/import-scan/" in curl
    assert "file=@Security_Report.sarif" in curl
    assert "scan_type=SARIF" in curl
    assert "engagement=<ENGAGEMENT-ID>" in curl
    assert "verified=false" in curl


def test_both_artifacts_are_deterministic(tmp_path):
    first = tmp_path / "one"
    second = tmp_path / "two"
    first.mkdir()
    second.mkdir()
    for d in (first, second):
        (d / "Security_Report.sarif").write_text('{"v":1}', encoding="utf-8")
    payload = _payload(_finding(), _finding("XSS", "Medium"))
    write_webhook_exports(payload, str(first))
    write_webhook_exports(payload, str(second))
    for name in ("Security_Findings_Webhook.json",
                 "Security_DefectDojo_Import.json"):
        assert (first / name).read_bytes() == (second / name).read_bytes()


def test_summary_block_reports_the_contract(tmp_path):
    summary, _, _ = _write(tmp_path, _finding())
    assert summary["defectdojo_import"]["live_push"] is False
    assert summary["defectdojo_import"]["scan_type"] == "SARIF"
    assert summary["defectdojo_import"]["sarif_embedded"] is True
    assert summary["findings_webhook"]["schema"] == WEBHOOK_SCHEMA
