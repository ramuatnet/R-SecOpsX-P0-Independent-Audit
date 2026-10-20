"""V11 defect-fix batch — evidence-driven fixes from the three commercial-tool
comparisons (juice-shop / Lacework, BenchmarkJava / Lacework, AI-bench / CodeSec).

Each test is RED before the fix and pins the exact defect it closes:

Phase A (bug-class):
  A1  .mjs/.cjs were invisible to SAST (absent from SCANNABLE_EXT *and*
      LANG_BY_EXT) -> the JS/TS rules never fired on them.
  A2  top_cves emitted the same CVE once per package-location (cosmetic
      duplicate rows); it must dedupe by CVE id, best-ranked instance first.
  A3  Terraform and Kubernetes findings prepended the scan-target directory
      name to their report path ("proj/infra/main.tf") while every other
      engine emits a target-relative path ("infra/main.tf"), so SARIF/Jira
      URIs did not resolve inside the scanned tree.
  A4  Third-party scanner-result XML exports (findbugs/spotbugs BugCollection,
      OWASPZAPReport, pmd, sonar, visualcodegrepper) shipped inside a repo are
      tool output, not application source; secrets/SAST must not report
      credential strings that live inside them.
  A5  CVE-2026-90711 (proxy-addr npm 1.1.0-2.0.7) is a genuine advisory the
      offline fallback store lacked -> it must resolve offline.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from scanner import sast
from scanner.package_intelligence import KNOWN_ADVISORY_FALLBACKS, _fallback_advisory, _fallback_key
from scanner.secret_intelligence import scan_file as secret_scan_file
from scanner.iac_terraform import scan_terraform
from scanner.iac_kubernetes import scan_kubernetes


# ---------------------------------------------------------------------------
# A1 — .mjs / .cjs extension coverage
# ---------------------------------------------------------------------------

def test_mjs_and_cjs_are_scannable_and_mapped_to_javascript(tmp_path):
    for name in ("mod.mjs", "util.cjs"):
        p = tmp_path / name
        p.write_text("const x = eval(payload);\n", encoding="utf-8")
        assert sast._should_scan(p), f"{name} must be selected for scanning"
        assert sast._language(p) == "javascript", f"{name} must map to javascript"


def test_mjs_js_rule_actually_fires(tmp_path):
    p = tmp_path / "app.mjs"
    p.write_text("const result = eval(userInput);\n", encoding="utf-8")
    findings = sast.scan_file(str(p))
    assert any(f.get("vuln_type") == "code_injection" for f in findings), (
        "EVAL_CALL must fire on a .mjs file once the extension is mapped"
    )


def test_cjs_child_process_exec_fires(tmp_path):
    p = tmp_path / "runner.cjs"
    p.write_text(
        "const { exec } = require('child_process');\nexec(cmd);\n", encoding="utf-8"
    )
    findings = sast.scan_file(str(p))
    assert any(f.get("vuln_type") == "command_injection" for f in findings)


# ---------------------------------------------------------------------------
# A2 — top_cves CVE-id dedup
# ---------------------------------------------------------------------------

def _payload_with_duplicate_cve():
    # The same package+CVE resolved from two lockfile locations.
    def pkg(loc):
        return {
            "name": "lodash", "version": "4.17.21", "ecosystem": "npm",
            "cve_list": ["CVE-2026-4800"], "cvss": 7.5, "severity": "High",
            "purl": f"pkg:npm/lodash@4.17.21?loc={loc}",
        }
    return {"sbom": [pkg("a"), pkg("b")]}


def test_top_cves_dedupes_by_cve_id():
    from main import _build_dependency_reporting_views

    payload = _payload_with_duplicate_cve()
    _build_dependency_reporting_views(payload)
    cves = [r.get("cve") for r in payload["top_cves"]]
    assert cves.count("CVE-2026-4800") == 1, (
        f"top_cves must list each CVE once, got {cves}"
    )
    # The risk register (per-package view) still carries both instances.
    assert payload["metadata"]["cve_count"] == 1


def test_top_cves_keeps_distinct_cves():
    from main import _build_dependency_reporting_views

    payload = {"sbom": [
        {"name": "lodash", "version": "4.17.21", "ecosystem": "npm",
         "cve_list": ["CVE-2026-4800", "CVE-2021-23337"], "cvss": 7.5},
        {"name": "minimist", "version": "0.0.8", "ecosystem": "npm",
         "cve_list": ["CVE-2020-7598"], "cvss": 7.5},
    ]}
    _build_dependency_reporting_views(payload)
    cves = {r.get("cve") for r in payload["top_cves"]}
    assert cves == {"CVE-2026-4800", "CVE-2021-23337", "CVE-2020-7598"}


# ---------------------------------------------------------------------------
# A3 — Terraform / Kubernetes report-path contract
# ---------------------------------------------------------------------------

def test_terraform_path_has_no_target_dir_prefix(tmp_path):
    (tmp_path / "main.tf").write_text(
        'resource "aws_security_group" "web" {\n'
        '  ingress {\n'
        '    from_port   = 22\n'
        '    to_port     = 22\n'
        '    protocol    = "tcp"\n'
        '    cidr_blocks = ["0.0.0.0/0"]\n'
        '  }\n'
        '}\n',
        encoding="utf-8",
    )
    findings = scan_terraform(str(tmp_path))
    assert findings, "expected an open-ingress finding"
    for f in findings:
        assert f["file"] == "main.tf", (
            f"TF path must be target-relative, got {f['file']!r} "
            f"(must not carry the target dir {tmp_path.name!r})"
        )


def test_kubernetes_path_has_no_target_dir_prefix(tmp_path):
    (tmp_path / "pod.yaml").write_text(
        "apiVersion: v1\n"
        "kind: Pod\n"
        "metadata:\n"
        "  name: leaky\n"
        "spec:\n"
        "  containers:\n"
        "  - name: app\n"
        "    image: nginx\n"
        "    securityContext:\n"
        "      privileged: true\n",
        encoding="utf-8",
    )
    findings = scan_kubernetes(str(tmp_path))
    assert findings, "expected a privileged-container finding"
    for f in findings:
        assert f["file"] == "pod.yaml", (
            f"K8s path must be target-relative, got {f['file']!r}"
        )


# ---------------------------------------------------------------------------
# A4 — scanner-result XML exports are not application source
# ---------------------------------------------------------------------------

# Mirrors the REAL content that produced 6 false "findings" in the shipped
# BenchmarkJava findsecbugs exports: the BugCollection longMessage embeds an
# HTML-escaped Java source excerpt, which the secrets/hash rules then flag as
# if it were application source.
_BUGCOLLECTION = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<BugCollection version="1.4.6" analysis="fast">\n'
    '  <BugInstance type="HARD_CODED_PASSWORD" priority="1">\n'
    '    <Class classname="org.owasp.benchmark.helpers.SecureCoder"/>\n'
    '    <SourceLine sourcepath="SecureCoder.java" start="25"/>\n'
    '    <LongMessage>&lt;pre&gt;private String SECRET_PASSWORD = '
    '"letMeIn!";&lt;/pre&gt;</LongMessage>\n'
    '    <Message>&lt;pre&gt;private String SECRET_PASSWORD = '
    '"letMeIn!";&lt;/pre&gt;</Message>\n'
    '  </BugInstance>\n'
    '  <BugInstance type="WEAK_MESSAGE_DIGEST_MD5" priority="1">\n'
    '    <LongMessage>&lt;pre&gt;MessageDigest md5Digest = '
    'MessageDigest.getInstance(&quot;MD5&quot;);&lt;/pre&gt;</LongMessage>\n'
    '  </BugInstance>\n'
    '</BugCollection>\n'
)


def test_findsecbugs_result_export_is_not_scanned_for_secrets(tmp_path):
    p = tmp_path / "Benchmark_1.2-findsecbugs-v1.4.6-122.xml"
    p.write_text(_BUGCOLLECTION, encoding="utf-8")
    findings = secret_scan_file(str(p))
    assert findings == [], (
        f"scanner-result export must yield no secret findings, got {findings}"
    )


def test_zap_result_export_is_not_scanned_for_secrets(tmp_path):
    p = tmp_path / "zap-export.xml"
    p.write_text(
        '<?xml version="1.0"?>\n<OWASPZAPReport version="2.4">\n'
        '  <site name="http://x"><alertitem><alert>pw</alert>'
        '<evidence>SUPERSECRETPASSWORD123</evidence></alertitem></site>\n'
        '</OWASPZAPReport>\n',
        encoding="utf-8",
    )
    assert secret_scan_file(str(p)) == []


def test_plain_config_xml_still_scanned(tmp_path):
    # A normal application XML (root <config>) with a real secret must STILL be
    # scanned — the suppression is root-element-specific, not a blanket .xml
    # exemption. <password> element text is exactly what CONFIG_CONTEXTUAL_
    # CREDENTIAL flags in students.xml (which is correctly NOT suppressed).
    p = tmp_path / "appsettings.xml"
    p.write_text(
        "<config>\n"
        "  <password>SuperSecretPassw0rd!</password>\n"
        "</config>\n",
        encoding="utf-8",
    )
    findings = secret_scan_file(str(p))
    assert findings, "a real credential in a normal XML must still be flagged"


def test_sast_ignores_bugcollection_export(tmp_path):
    p = tmp_path / "results.xml"
    p.write_text(_BUGCOLLECTION, encoding="utf-8")
    assert sast._is_scanner_result_xml(p) is True
    p2 = tmp_path / "normal.xml"
    p2.write_text("<config><a>1</a></config>\n", encoding="utf-8")
    assert sast._is_scanner_result_xml(p2) is False


# ---------------------------------------------------------------------------
# A5 — CVE-2026-90711 offline fallback
# ---------------------------------------------------------------------------

def test_cve_2026_90711_fallback_present():
    key = _fallback_key({"ecosystem": "npm", "name": "proxy-addr", "version": "2.0.7"})
    adv = _fallback_advisory({"ecosystem": "npm", "name": "proxy-addr", "version": "2.0.7"})
    assert adv is not None, "proxy-addr 2.0.7 must resolve offline"
    assert adv["cve"] == "CVE-2026-90711"
    assert adv["fixed_in"] == "2.0.8"
    assert adv["severity"] == "Critical"
