"""Webhook / JSON API exports (Phase 5.2).

Two artifacts, both fail-open, neither performs a live push (a scan has no
business writing to someone else's tracker — the artifacts ARE the
contract, the same honesty as the Jira exporter):

* ``Security_Findings_Webhook.json`` — a reduced, redacted findings
  projection in a stable schema (``rsecopsx.findings-webhook/v2`` — v2
  discloses the additive ``finding_uid`` field, Phase B Wave 1): one
  object per finding with the fields a triage consumer needs and nothing
  it doesn't, plus tool/project context and severity counts. This is also
  the interchange shape for SecObserve-style ingestion (their findings
  API consumes a JSON findings list; that boundary is documented in the
  notes rather than fabricated field-by-field).

* ``Security_DefectDojo_Import.json`` — the multipart POST blueprint for
  DefectDojo's import-scan API (``POST /api/v2/import-scan/``, verified
  against DefectDojo's own API documentation and generated client:
  multipart/form-data, ``Authorization: Token <api-token>``, form fields
  engagement/scan_type/minimum_severity/active/verified/
  close_old_findings/tags). DefectDojo's ``scan_type`` enum includes
  ``SARIF``, so the blueprint embeds the exact SARIF artifact this scan
  produced (base64) plus a ready curl command. The engagement id stays a
  REQUIRED placeholder: it lives in the target DefectDojo instance and a
  scan cannot know it.

Honesty properties:
* ``verified=false`` in the blueprint — the tool cannot claim a human
  verified its own findings;
* ``minimum_severity=Info`` — the default, so the import is 1:1 with the
  report and no severity is silently dropped at the boundary;
* every free-text field in both artifacts is PEM-redacted on the way out.
"""
from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

from core.redaction import redact_pem_deep

WEBHOOK_SCHEMA = "rsecopsx.findings-webhook/v2"

# The projection: the fields a triage consumer needs, nothing it doesn't.
# finding_uid (Phase B Wave 1, additive) leads the tuple so the projection
# mirrors the identity preference chain (uid first, uuid5 finding_id kept
# byte-unchanged); the schema bumps v1 -> v2 to disclose the added field.
# fix_snippet is optional and rides along when the finding carries one
# (Phase 3.3 attaches it during enrichment).
_WEBHOOK_FINDING_FIELDS = (
    "finding_uid",
    "finding_id",
    "rule_id",
    "vuln_type",
    "severity",
    "cwe",
    "file",
    "line",
    "description",
    "remediation",
    "confidence",
    "fix_snippet",
)

_DEFECTDOJO_IMPORT_ENDPOINT = "/api/v2/import-scan/"
_DEFECTDOJO_REIMPORT_ENDPOINT = "/api/v2/reimport-scan/"


def _webhook_finding(finding: dict[str, Any]) -> dict[str, Any]:
    """One projected finding. Unknown fields do not travel."""
    projected: dict[str, Any] = {}
    for field in _WEBHOOK_FINDING_FIELDS:
        if field not in finding:
            continue
        value = finding[field]
        if field in ("description", "remediation"):
            value = redact_pem_deep(value) if isinstance(value, str) else value
        projected[field] = value
    return projected


def build_findings_webhook_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """The generic webhook payload: projection + context + counts."""
    findings = [
        _webhook_finding(f)
        for f in (payload.get("findings") or [])
        if isinstance(f, dict)
    ]

    by_severity: dict[str, int] = {}
    for finding in findings:
        severity = str(finding.get("severity") or "Unknown")
        by_severity[severity] = by_severity.get(severity, 0) + 1

    metadata = payload.get("metadata") or {}
    target = str(metadata.get("target") or "")

    return {
        "schema": WEBHOOK_SCHEMA,
        "tool": {
            "name": str(metadata.get("tool") or "rsecopsx"),
            "scan_date": metadata.get("scan_date"),
        },
        "project": {
            "target": target,
            "name": Path(target.replace("\\", "/")).name or None,
        },
        "generated_from": "clean_report.json",
        "summary": {
            "findings": len(findings),
            "by_severity": by_severity,
        },
        "findings": findings,
        "redaction": (
            "Projection of the PEM-redacted canonical report; free-text "
            "fields are redacted again on the way out. No unredacted "
            "upstream data is added here."
        ),
        "limits": [
            "A projection, not the full report: clean_report.json remains "
            "the system of record.",
            "Severity values are this tool's own scale; map them onto the "
            "consumer's scale at the boundary.",
        ],
    }


def build_defectdojo_import_blueprint(
    payload: dict[str, Any],
    sarif_path: str | Path,
) -> dict[str, Any]:
    """The DefectDojo import-scan POST blueprint (see module docstring)."""
    sarif_file = Path(sarif_path)
    content_base64: str | None = None
    notes: list[str] = []

    try:
        content_base64 = base64.b64encode(sarif_file.read_bytes()).decode("ascii")
    except OSError:
        notes.append(
            "SARIF artifact could not be read; content_base64 is null. The "
            "import file is Security_Report.sarif next to this blueprint — "
            "attach it manually or re-run the scan."
        )

    metadata = payload.get("metadata") or {}
    target = str(metadata.get("target") or "")
    curl = (
        "curl -X POST 'https://<defectdojo-host>" + _DEFECTDOJO_IMPORT_ENDPOINT + "' "
        "-H 'Authorization: Token <API-TOKEN>' "
        "-F 'file=@Security_Report.sarif' "
        "-F 'scan_type=SARIF' "
        "-F 'engagement=<ENGAGEMENT-ID>' "
        "-F 'minimum_severity=Info' "
        "-F 'active=true' "
        "-F 'verified=false' "
        "-F 'close_old_findings=false' "
        "-F 'tags=rsecopsx'"
    )

    blueprint = {
        "tool": "rsecopsx",
        "purpose": (
            "DefectDojo import-scan POST blueprint. POST this as "
            "multipart/form-data to the endpoint below with the SARIF file "
            "attached; field semantics verified against DefectDojo's API "
            "v2 documentation."
        ),
        "api": {
            "endpoint": _DEFECTDOJO_IMPORT_ENDPOINT,
            "method": "POST",
            "content_type": "multipart/form-data",
            "accept": "application/json",
            "authentication": "Authorization: Token <api-token>",
            "reimport_endpoint": _DEFECTDOJO_REIMPORT_ENDPOINT,
        },
        "file": {
            "field": "file",
            "name": sarif_file.name,
            "content_base64": content_base64,
        },
        "form_fields": {
            "scan_type": "SARIF",
            "minimum_severity": "Info",
            "active": "true",
            "verified": "false",
            "close_old_findings": "false",
            "engagement": (
                "<REQUIRED: DefectDojo engagement id -- the target "
                "engagement lives in the DefectDojo instance; a scan "
                "cannot know it>"
            ),
            "tags": "rsecopsx",
            "environment": "<optional: Development|Staging|Production>",
        },
        "curl": curl,
        "project_target": target,
        "notes": notes
        + [
            "scan_type=SARIF: DefectDojo's import parser registry accepts "
            "SARIF natively, so no custom parser is needed.",
            "verified=false on purpose: a scanner cannot claim a human "
            "verified its own findings.",
            "minimum_severity=Info (their default): the import is 1:1 with "
            "clean_report.json; filtering happens in DefectDojo, not here.",
            "For re-imports into an existing test use "
            + _DEFECTDOJO_REIMPORT_ENDPOINT
            + " with the test id instead of the engagement.",
        ],
    }
    return blueprint


def write_webhook_exports(
    payload: dict[str, Any],
    output_dir: str | Path,
    sarif_name: str = "Security_Report.sarif",
) -> dict[str, Any]:
    """Write both webhook artifacts; return a small summary."""
    out = Path(output_dir)

    webhook = build_findings_webhook_payload(payload)
    webhook_path = out / "Security_Findings_Webhook.json"
    with open(webhook_path, "w", encoding="utf-8") as handle:
        json.dump(webhook, handle, indent=2, default=str)

    blueprint = build_defectdojo_import_blueprint(
        payload, out / sarif_name)
    blueprint_path = out / "Security_DefectDojo_Import.json"
    with open(blueprint_path, "w", encoding="utf-8") as handle:
        json.dump(blueprint, handle, indent=2, default=str)

    return {
        "findings_webhook": {
            "file": webhook_path.name,
            "schema": WEBHOOK_SCHEMA,
            "findings": webhook["summary"]["findings"],
        },
        "defectdojo_import": {
            "file": blueprint_path.name,
            "endpoint": _DEFECTDOJO_IMPORT_ENDPOINT,
            "scan_type": "SARIF",
            "sarif_embedded": blueprint["file"]["content_base64"] is not None,
            "live_push": False,
        },
    }
