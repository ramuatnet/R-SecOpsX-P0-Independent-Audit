# -*- coding: utf-8 -*-
r"""prodtest report-validation batch (2026-10-19, G): the false-positive
families measured across the 13 fresh prodtest reports.

Every test states both sides of the kill-only-on-proof contract: the false
shape must be gone, and a real detection of the same class must survive.

  G1  LLM07's patterns ``shell.exec``/``tool.run``/``plugin.execute``/
      ``browser.open`` compiled with an UNESCAPED dot, so PHP
      ``shell_exec("apachectl -M | grep rewrite_module")`` in DVWA's
      setup.php/api index was "insecure plugin design" (2 rows).
  G2  LLM02 fired on RegExp ``.exec(`` -- backbone-min.js (WebGoat),
      fullcalendar.min.js (railsgoat) and LLMForge's
      ``/^LEVEL_(\d+)$/i.exec(levelId)`` are regex matching, not code
      execution; and on un-analyzable minified bundle lines (24k-32k
      chars) that carry zero AI context.
  G3  LLM05's bare ``pip\s+install`` pattern fired on non-AI projects'
      generic installs (argip setup.bat/ci.yml, wrongsecrets
      pre-commit/detect-secrets: 4 rows). The claim "LLM supply chain"
      needs an AI package on the line, a dependency-manifest install
      (the controls: ``-r requirements.txt``/``-e .``), or AI context
      in the file.
  G4  PRIVATE_KEY_HEADER fired on the PEM header STRING LITERAL alone
      (WebGoat CryptoUtil x2, wrongsecrets Challenge29: header
      replacement code with no key material anywhere) -- the rule's
      claim "private key material in source code" requires a key body.
  G5  The enterprise taint line layer accepted bare ``body``/``query``
      words as taint sources anywhere in a 19-line window, so
      vendored minified JS produced prototype-pollution rows (7 across
      WebGoat/railsgoat/dvpwa) and the SSRF cross-line bare-source gate
      missed capitalised tokens (``searchParams`` -> "Params" in
      WebGoat's browser lesson JS: the frozenset check was
      case-sensitive).
"""
from __future__ import annotations

import pathlib
import sys
import textwrap

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def _write(tmp_path, name: str, source: str):
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(source), encoding="utf-8")
    return path


def _sast(tmp_path, name: str, source: str) -> list[dict]:
    from scanner.sast import scan_file

    return scan_file(str(_write(tmp_path, name, source)))


def _llm(tmp_path, name: str, source: str) -> list[dict]:
    from scanner.llm_security import scan_llm_file

    text = textwrap.dedent(source)
    path = _write(tmp_path, name, text)
    return scan_llm_file(str(path), text)


def _taint(tmp_path, name: str, source: str) -> list[dict]:
    from scanner.taint_engine import analyze_file

    return analyze_file(str(_write(tmp_path, name, source)))


def _ids(findings: list[dict]) -> set[str]:
    return {str(f.get("rule_id") or f.get("id")) for f in findings}


# ---------------------------------------------------------------------------
# G1 -- LLM07: method-access idioms, not underscore-named PHP builtins
# ---------------------------------------------------------------------------
def test_llm07_underscore_shell_exec_php_suppressed(tmp_path):
    """DVWA setup.php:58 / vulnerabilities/api/index.php:33 -- the EXACT
    real line (space before the paren keeps LLM02's ``exec\\(`` rule pattern
    from matching, so LLM07's unescaped ``shell.exec`` dot was the row)."""
    findings = _llm(tmp_path, "setup.php", '''
        <?php
        if (PHP_OS == "Linux") {
            $out = shell_exec ("apachectl -M | grep rewrite_module");
        }
    ''')
    assert "LLM07_INSECURE_PLUGIN_DESIGN" not in _ids(findings)


def test_llm07_dotted_shell_exec_owned_by_autonomous_control(tmp_path):
    """Control: the dotted method-access shape keeps its detection -- the
    more specific Critical AUTONOMOUS_TOOL_EXECUTION owns ``shell.exec``
    and suppresses LLM07 on the same line by RULE_PRECEDENCE (unchanged)."""
    findings = _llm(tmp_path, "agent.js", '''
        const result = agent.shell.exec(payload);
    ''')
    assert "AUTONOMOUS_TOOL_EXECUTION" in _ids(findings)


def test_llm07_dotted_plugin_execute_still_reported(tmp_path):
    findings = _llm(tmp_path, "plugin.js", '''
        registry.plugin.execute(command, args);
    ''')
    assert "LLM07_INSECURE_PLUGIN_DESIGN" in _ids(findings)


# ---------------------------------------------------------------------------
# G2 -- LLM02: RegExp exec is regex matching; minified bundles need AI context
# ---------------------------------------------------------------------------
def test_llm02_regex_literal_exec_suppressed(tmp_path):
    """LLMForge rag_*_template.js: ``/^LEVEL_(\\d+)$/i.exec(levelId)``."""
    findings = _llm(tmp_path, "rag_template.js", '''
        function pick(levelId) {
            const match = /^LEVEL_(\\d+)$/i.exec(levelId);
            return match ? match[1] : null;
        }
    ''')
    assert "LLM02_INSECURE_OUTPUT_HANDLING" not in _ids(findings)


def test_llm02_minified_line_without_ai_context_suppressed(tmp_path):
    """backbone-min.js:1 / fullcalendar.min.js:6 -- ``t.exec(e)`` inside a
    24k-char vendor line with no AI presence anywhere in the file."""
    pad = "/* " + ("abcdefghij" * 220) + " */"  # > 2000 chars
    source = f"function parse(t, e) {{ {pad} var n = t.exec(e).slice(1); }}"
    findings = _llm(tmp_path, "vendor-min.js", source + "\n")
    assert "LLM02_INSECURE_OUTPUT_HANDLING" not in _ids(findings)


def test_llm02_minified_line_with_ai_context_still_reported(tmp_path):
    """Control: the same vendor line inside a file that does carry AI
    context keeps the finding (no weakening of AI-project detection)."""
    pad = "/* " + ("abcdefghij" * 220) + " */"
    source = (
        "// openai model prompt output\n"
        f"function parse(t, e) {{ {pad} var n = t.exec(e).slice(1); }}\n"
    )
    findings = _llm(tmp_path, "ai-vendor-min.js", source)
    assert "LLM02_INSECURE_OUTPUT_HANDLING" in _ids(findings)


def test_llm02_child_process_exec_unchanged(tmp_path):
    """Control: the B6 must-keep ``cp.exec`` shape."""
    findings = _llm(tmp_path, "cp.js", '''
        const cp = require("child_process");
        const out = cp.exec(cmd);
    ''')
    assert "LLM02_INSECURE_OUTPUT_HANDLING" in _ids(findings)


# ---------------------------------------------------------------------------
# G3 -- LLM05: generic pip installs in non-AI files are not LLM supply chain
# ---------------------------------------------------------------------------
def test_llm05_non_ai_pip_without_context_suppressed(tmp_path):
    """argip setup.bat line 1 (pydantic/fastapi/aiokafka, no AI terms)."""
    findings = _llm(tmp_path, "setup.bat", '''
        pip install pydantic pydantic-settings fastapi "uvicorn[standard]" aiokafka
        echo ERROR: pip install failed. Make sure Python is on PATH.
    ''')
    assert "LLM05_SUPPLY_CHAIN_VULNERABILITY" not in _ids(findings)


def test_llm05_manifest_install_still_reported(tmp_path):
    """Control: installing a declared dependency manifest (resolver.py)."""
    findings = _llm(tmp_path, "resolver.py", '''
        INSTALL_RESOLVER = "pip install -r requirements.txt"
    ''')
    assert "LLM05_SUPPLY_CHAIN_VULNERABILITY" in _ids(findings)


def test_llm05_editable_install_still_reported(tmp_path):
    """Control: the ci.yml fixture ``uv pip install -U -e .``."""
    findings = _llm(tmp_path, "ci.yml", '''
        steps:
          - run: uv pip install -U -e .
    ''')
    assert "LLM05_SUPPLY_CHAIN_VULNERABILITY" in _ids(findings)


def test_llm05_ai_package_still_reported(tmp_path):
    """Control: an AI package on the line is LLM supply chain."""
    findings = _llm(tmp_path, "hint.py", '''
        subprocess_check = None
        cmd = "pip install llama-index"
    ''')
    assert "LLM05_SUPPLY_CHAIN_VULNERABILITY" in _ids(findings)


def test_llm05_non_ai_project_tooling_suppressed(tmp_path):
    """wrongsecrets .github/scripts/setup-precommit.sh + scanner-comparison.yml."""
    findings = _llm(tmp_path, "setup-precommit.sh", '''
        #!/usr/bin/env bash
        python3 -m pip install --user pre-commit
    ''')
    assert "LLM05_SUPPLY_CHAIN_VULNERABILITY" not in _ids(findings)


# ---------------------------------------------------------------------------
# G2b break-shift -- PROMPT_TEMPLATE_SECRET_EXPOSURE on vendored bundles was
# masked behind LLM02's per-line break; with G2a/G2b killing those LLM02 rows
# the same minified-line coincidence surfaces (the g_after additions at
# bootstrap-editable.min.js:5 / jquery.min.js:2, both ``template.*token`` in
# a 62k/88k-char minified line with zero AI context).
# ---------------------------------------------------------------------------
def test_prompt_template_minified_bundle_line_suppressed(tmp_path):
    """``template`` and ``token`` co-occurring inside one giant vendor line."""
    pad = "z" * 2100
    source = (
        f"function tpl() {{ /* {pad} */ var t = template(token); "
        "return extend(t, defaults); }}\n"
    )
    findings = _llm(tmp_path, "jquery.min.js", source)
    assert "PROMPT_TEMPLATE_SECRET_EXPOSURE" not in _ids(findings)


# ---------------------------------------------------------------------------
# G4 -- PRIVATE_KEY_HEADER: the header marker is not key material
# ---------------------------------------------------------------------------
def test_pem_header_replacement_without_body_suppressed(tmp_path):
    """WebGoat CryptoUtil.java:49/137 + wrongsecrets Challenge29.java:59 --
    PEM-parsing code that strips/compares the header string literal."""
    findings = _sast(tmp_path, "Challenge29.java", '''
        class Challenge29 {
          String clean(String content) {
            content = content.replace("-----BEGIN PRIVATE KEY-----", "");
            content = content.replace("-----END PRIVATE KEY-----", "");
            return content;
          }
        }
    ''')
    assert "PRIVATE_KEY_HEADER" not in _ids(findings)


def test_pem_header_literal_without_body_suppressed(tmp_path):
    """CryptoUtil's ``String encodedString = "-----BEGIN PRIVATE KEY-----\\n";``"""
    findings = _sast(tmp_path, "CryptoUtil.java", '''
        class CryptoUtil {
          static final String HEADER = "-----BEGIN PRIVATE KEY-----\\n";
          static final String FOOTER = "-----END PRIVATE KEY-----\\n";
        }
    ''')
    assert "PRIVATE_KEY_HEADER" not in _ids(findings)


def test_embedded_pem_key_with_body_still_reported(tmp_path):
    """Control: an actual key block (header + base64 body + end marker)."""
    findings = _sast(tmp_path, "RealKey.java", '''
        class RealKey {
          static final String KEY = "-----BEGIN PRIVATE KEY-----\\n"
              + "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCxyz\\n"
              + "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789+/AAAABBBCCCDDDEEEFFF\\n"
              + "-----END PRIVATE KEY-----\\n";
        }
    ''')
    assert "PRIVATE_KEY_HEADER" in _ids(findings)


def test_multiline_pem_key_block_still_reported(tmp_path):
    """Control: the raw multi-line PEM form (config/fixture files)."""
    findings = _sast(tmp_path, "key.pem.txt", '''
        -----BEGIN PRIVATE KEY-----
        MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCxyz1234
        AbCdEfGhIjKlMnOpQrStUvWxYz0123456789+/AAAABBBCCCDDDEEEFFFg
        -----END PRIVATE KEY-----
    ''')
    assert "PRIVATE_KEY_HEADER" in _ids(findings)


# ---------------------------------------------------------------------------
# G5 -- prototype pollution: bare words are not taint across lines or in
# minified bundles
# ---------------------------------------------------------------------------
def test_pp_minified_same_line_bare_source_suppressed(tmp_path):
    """dvpwa jquery-3.2.1.min.js:2 / WebGoat jquery-1.10.2.min.js:5 and
    friends -- ``query`` and ``merge``/``Object.assign`` co-occurring on a
    24k-88k-char minified line is lexical coincidence, not statement
    evidence."""
    pad = "z" * 460
    source = (
        f"function apply() {{ /* {pad} */ var s = query; "
        "return Object.assign(defaults, s); }}\n"
    )
    findings = _taint(tmp_path, "jquery.min.js", source)
    assert "TAINT_PROTOTYPE_POLLUTION" not in _ids(findings)


def test_pp_cross_line_bare_source_suppressed(tmp_path):
    """wysihtml5-0.3.0.js:4768 -- the ``body`` word sits 3 lines before the
    ``.merge()`` sink in unrelated vendor state."""
    findings = _taint(tmp_path, "wysihtml5.js", '''
        function combine(defaults) {
            const payload = body;
            return Object.assign(defaults, payload);
        }
    ''')
    assert "TAINT_PROTOTYPE_POLLUTION" not in _ids(findings)


def test_pp_same_line_bare_source_normal_line_still_reported(tmp_path):
    """Control: a human-length line carrying both source and sink."""
    findings = _taint(tmp_path, "app.js", '''
        function combine(defaults) {
            return Object.assign(defaults, body);
        }
    ''')
    assert "TAINT_PROTOTYPE_POLLUTION" in _ids(findings)


def test_pp_cross_line_qualified_source_still_reported(tmp_path):
    """Control: the proven ``req.body`` alias flow keeps firing."""
    findings = _taint(tmp_path, "app.js", '''
        function combine(defaults) {
            const payload = req.body;
            return Object.assign(defaults, payload);
        }
    ''')
    assert "TAINT_PROTOTYPE_POLLUTION" in _ids(findings)


# ---------------------------------------------------------------------------
# G5b -- SSRF cross-line bare gate is case-insensitive
# ---------------------------------------------------------------------------
def test_ssrf_cross_line_capitalised_search_params_suppressed(tmp_path):
    """WebGoat security-misconfiguration-task2.js:32 -- ``Params`` came from
    ``url.searchParams`` (the URL API), cross-line from the fetch sink."""
    findings = _taint(tmp_path, "task2.js", '''
        function run(configButton, tokenField) {
            const url = new URL(configButton.getAttribute("data-url"), window.location.origin);
            url.searchParams.set("token", tokenField.value || "");
            const response = await fetch(url, { method: "GET" });
            return response;
        }
    ''')
    assert "TAINT_SSRF_EXPANDED" not in _ids(findings)


def test_ssrf_cross_line_lowercase_bare_source_suppressed(tmp_path):
    """Stability: the pre-existing lowercase bare cross-line gate."""
    findings = _taint(tmp_path, "proxy.js", '''
        const url = params.target;
        const response = await fetch(url);
    ''')
    assert "TAINT_SSRF_EXPANDED" not in _ids(findings)
