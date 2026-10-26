# -*- coding: utf-8 -*-
r"""aclean report-validation batch (2026-10-26, I18-I20): false-positive
families measured across the production RBI2 scan (1615 rows, 70.2% scoring
LIKELY_FP under analysis/validation/triage_report.py).

Every test states both sides of the kill-only-on-proof contract: the false
shape must be gone, and a real detection of the same class must survive.

  I18  i18n resource bundles under ``src/main/resources/bundle/`` are
      translation files, not source. Their values carry credential-shaped
      words ("password", "token", "secret") as TRANSLATED OUTPUT -- the
      Indonesian login prompt "Masukkan password" is a UI string, not a
      committed secret -- and the generic key/value parser read every pair
      as CONFIG_CONTEXTUAL_CREDENTIAL. The aclean corpus held 6 such files
      at 61-64 rows each (~380 rows, 24% of the report). "bundle" joins the
      shared EXCLUDED_DIRS policy in both the SAST and Secret Intelligence
      engines; a real config file outside bundle/ keeps firing.

  I19  a scanner-result JSON export inside the scanned tree is tool output,
      not source. ``RBI7SASTSBOMSCA-result.json`` carried 98 rows whose
      snippets are that export's OWN evidence text -- the export quotes the
      repo it summarised, so reading it as source re-scans stale evidence
      and invents locations. Detection is by CONTENT (the report envelope:
      total_findings + tool + findings[].rule_id), never by filename, so an
      application JSON that merely has a "findings" array still scans.

  I20  TAINT_MULTIPART_TRAVERSAL's sink alternative ``File\( had no word
      boundary, so the "sink" matched inside identifiers:
      ``event.getFile()`` matched via getFile( and
      ``copyFile(String fileName, ...)`` matched via copyFile( -- the
      source token (``fileName``) and the "sink" token sat on the SAME
      line of a validation or a helper signature, 211 rows in the aclean
      corpus. ``\\bFile\\(`` kills both while every real constructor
      (``new File(``, ``java.io.File(``) and ``transferTo(`` keeps firing.
"""
from __future__ import annotations

import pathlib
import textwrap

_RATE_LIMIT = "MISSING_RATE_LIMIT_ENDPOINT"
_MULTIPART = "TAINT_MULTIPART_TRAVERSAL"
_CONFIG = "CONFIG_CONTEXTUAL_CREDENTIAL"


def _write(tmp_path, name: str, source: str) -> pathlib.Path:
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(source), encoding="utf-8")
    return path


def _sast(tmp_path, name: str, source: str) -> list[dict]:
    from scanner.sast import scan_file

    return scan_file(str(_write(tmp_path, name, source)))


def _secret(tmp_path, name: str, source: str) -> list[dict]:
    from scanner.secret_intelligence import scan_file

    return scan_file(str(_write(tmp_path, name, source)))


def _taint(tmp_path, name: str, source: str) -> list[dict]:
    from scanner.taint_engine import scan_file

    return scan_file(str(_write(tmp_path, name, source)))


def _ids(findings: list[dict]) -> set[str]:
    return {str(f.get("rule_id") or f.get("id")) for f in findings}


# ---------------------------------------------------------------------------
# I18 -- i18n resource bundles are translations, not committed configuration
# ---------------------------------------------------------------------------
def test_bundle_properties_skipped_by_sast(tmp_path):
    """The false shape: credential-shaped words as translation values."""
    src = _write(tmp_path, "src/main/resources/bundle/messages.properties", (
        "login.title=Sign in\n"
        "login.password=Enter your password\n"
        "api.token.label=API token\n"
        "oauth.client.secret.hint=Contact support for the client secret\n"
    ))
    from scanner.sast import _skip

    assert _skip(src)


def test_bundle_properties_skipped_by_secrets(tmp_path):
    from scanner.secret_intelligence import _skip

    src = _write(tmp_path, "src/main/resources/bundle/messages_hi.properties", (
        "login.password=\\u0932\\u094b\\u0917\\u093f\\u0928 \\u092a\\u093e\\u0938\\u0935\\u0930\\u094d\\u0921\n"
    ))
    assert _skip(src)


def test_bundle_directory_skipped(tmp_path):
    """The aclean rows sat under bundle/ in six modules; one probe covers the
    directory decision itself, independent of extension."""
    from scanner.sast import _skip

    src = _write(tmp_path, "bundle/Messages.java", "class Messages {}\n")
    assert _skip(src)


def test_config_file_outside_bundle_still_fires(tmp_path):
    """Control: a real committed credential outside bundle/ keeps its finding."""
    src = _write(tmp_path, "src/main/resources/application.properties", (
        "spring.datasource.password=Sup3rS3cretProdValue!\n"
        "api.signing.token=ghp_0123456789abcdefghijklmnopqrstuvwxyzAB\n"
    ))
    findings = _secret(tmp_path, "src/main/resources/application.properties", (
        "spring.datasource.password=Sup3rS3cretProdValue!\n"
        "api.signing.token=ghp_0123456789abcdefghijklmnopqrstuvwxyzAB\n"
    ))
    rule_ids = _ids(findings)
    assert any("CONFIG" in r or "SECRET" in r for r in rule_ids), rule_ids


# ---------------------------------------------------------------------------
# I19 -- a scanner-result JSON export is tool output, not source
# ---------------------------------------------------------------------------
def test_scanner_result_json_skipped(tmp_path):
    """The aclean export carried 98 rows read back from its own evidence."""
    body = (
        '{"metadata": {"tool": "R-SecOpsX SAST v2.1", "total_findings": 98},'
        ' "findings": [{"rule_id": "CONFIG_CONTEXTUAL_CREDENTIAL",'
        '  "severity": "Medium", "snippet": "password=..."}]}'
    )
    from scanner.sast import _skip

    assert _skip(_write(tmp_path, "RBI7SASTSBOMSCA-result.json", body))


def test_scanner_result_json_skipped_by_secrets(tmp_path):
    from scanner.secret_intelligence import _skip

    body = (
        '{"metadata": {"tool": "other-tool", "total_findings": 3},'
        ' "findings": [{"rule_id": "X", "evidence": "api_key=abc"}]}'
    )
    assert _skip(_write(tmp_path, "third_party-result.json", body))


def test_application_json_with_findings_array_still_scanned(tmp_path):
    """Control: the envelope markers, not the word "findings", decide."""
    from scanner.sast import _skip, _is_scanner_result_json

    src = _write(tmp_path, "search_response.json", (
        '{"status": "ok", "findings": ["nodule", "lesion"],'
        ' "patient": {"id": 7}}\n'
    ))
    assert not _skip(src)
    assert not _is_scanner_result_json(src)


def test_config_json_without_findings_key_still_scanned(tmp_path):
    from scanner.sast import _skip

    src = _write(tmp_path, "app.config.json", (
        '{"tool": "webpack", "mode": "production", "entry": "./src/index.js"}\n'
    ))
    assert not _skip(src)


# ---------------------------------------------------------------------------
# I20 -- the multipart sink must be a CONSTRUCTOR, not an identifier tail
# ---------------------------------------------------------------------------
def test_multipart_getfile_accessor_suppressed(tmp_path):
    """The exact aclean shape: source token and 'sink' on one validation line."""
    source = (
        "public void handleUpload(MultipartFile file) {\n"
        '    boolean ok = event.getFile().getFileName().endsWith(".csv");\n'
        "}\n"
    )
    findings = _taint(tmp_path, "UploadAction.java", source)
    assert _MULTIPART not in _ids(findings)


def test_multipart_helper_signature_suppressed(tmp_path):
    """copyFile(String fileName, ...) -- File( matched inside copyFile(."""
    source = (
        "public class FileUtil {\n"
        "    public static String copyFile(String fileName, InputStream in) {\n"
        '        return fileName;\n'
        "    }\n"
        "}\n"
    )
    findings = _taint(tmp_path, "FileUtil.java", source)
    assert _MULTIPART not in _ids(findings)


def test_multipart_real_constructor_survives(tmp_path):
    """Control: filename reaching a real File constructor keeps the finding."""
    source = (
        "public void store(MultipartFile file) throws IOException {\n"
        '    String fileName = file.getOriginalFilename();\n'
        "    File dest = new File(uploadDir + fileName);\n"
        "    file.transferTo(dest);\n"
        "}\n"
    )
    findings = _taint(tmp_path, "UploadStore.java", source)
    assert _MULTIPART in _ids(findings), _ids(findings)


def test_multipart_real_qualified_constructor_survives(tmp_path):
    """``new java.io.File(`` -- the boundary sits after the dot, so the
    qualified form the aclean service classes use is still reported."""
    source = (
        "public void save(MultipartFile file) {\n"
        '    String fileName = file.getOriginalFilename();\n'
        "    java.io.File target = new java.io.File(baseDir, fileName);\n"
        "}\n"
    )
    findings = _taint(tmp_path, "QualifiedStore.java", source)
    assert _MULTIPART in _ids(findings), _ids(findings)
