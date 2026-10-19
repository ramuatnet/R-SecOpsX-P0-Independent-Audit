# -*- coding: utf-8 -*-
r"""prodtest report-validation batch (2026-10-19, I): the second round of
false-positive families measured across the fresh prodtest scans (the 13
originals plus the 10 newly cloned public targets).

Every test states both sides of the kill-only-on-proof contract: the false
shape must be gone, and a real detection of the same class must survive.

  I1  MISSING_RATE_LIMIT_ENDPOINT's ``transfer`` alternative matched
      response-framing headers (express lib/response.js:202/209
      ``this.removeHeader('Transfer-Encoding')`` and test/res.send.js:597/604
      ``var transferEncodings = [...]``: 4 rows). Transfer-Encoding is
      HTTP framing, not a payment endpoint; the pattern now excludes
      anything followed by "encod".
  I2  forge build artifacts under ``contracts/out/`` are generated but
      tracked (ethernaut, 397 files, 14 rows: an IPFS CID substring that
      case-insensitively matched an AWS key, methodIdentifiers-as-credentials
      CONFIG rows, an ABI ``log`` function in a PROMPT_RESPONSE row).
      ``out`` joins the shared EXCLUDED_DIRS policy in both the SAST and
      Secret Intelligence engines.
  I3  AWS_ACCESS_KEY compiled with IGNORECASE, so the base58 CID
      ``QmTzWboptc2WjGQH4ShcN4XAkiaskScQ7fFtfgvMsW`` inside forge ABIs
      matched ``AKIA[0-9A-Z]{16}`` case-insensitively (ethernaut x2).
      AWS key IDs are uppercase; matching is case-sensitive now (the
      LLM02/LLM06 secret-evidence AWS pattern likewise).
  I4  LLM04's ``while True`` fired on every unbounded-looking loop in
      django/flask/crAPI/wrongsecrets (17 rows) even where the iteration
      demonstrably cannot spin: break/return/raise exits, input()/sleep()
      blocking, subprocess/requests/file-read I/O (crAPI
      merchant/views.py:83 retry loop with three breaks + requests.get;
      flask cli.py:216 path walk with break; the wrongsecrets sidecar
      ``while true; do ...; sleep 10; done`` one-liner). AI-context files
      keep the model-nexus benefit of the doubt (GenAI's interactive
      menus, pygoat's chatbot), and the proven ``while True: pass``
      CPU-spin control still fires.
  I5  PROMPT_TEMPLATE fired on django's template-engine vocabulary where
      the credential word is the parser's Token OBJECT
      (``e.token``, ``templatetag(parser, token)``: 3 rows). The rule
      claims prompt-template SECRET exposure: the credential word must
      appear as a BARE identifier and the file must carry no AI context
      (LLMForge's ``internal_doc_template.format(secret_token=...)`` is
      AI-context and keeps).
  I6  AI_PROVIDER_SECRET_EXPOSURE fired on reference-only declarations:
      getenv reads, compose ``${VAR:-}``, helm ``{{ .Values }}``, empty
      strings, and comments (crAPI x8). "Provider secret exposure" needs
      a committed literal value; GenAI's ``OPENAI_API_KEY = "sk-mock-key"``
      keeps, as do .env-style unquoted token literals.
  I7  PROMPT_RESPONSE_LOGGING matched substrings: "logic ... prompts"
      inside LLMForge prose, "Dialog" inside WebGoat's minified
      mode-java.js regex, an ABI function name (ethernaut), message-only
      strings (crAPI chat_api "...not provided"), a session-id debug line,
      and ``${response.status}`` (juice pr-compliance.yml:457). A finding
      now needs a real logging call, a sensitive token in CODE position
      (interpolation counts), and response/prompt data that is not
      status-metadata-only; crAPI Bot.tsx logging ``response.body`` keeps.
  I8  LLM02 fired on CPython's PYTHONSTARTUP feature (flask cli.py:1022
      ``eval(compile(f.read(), startup, "exec"), ctx)``; django shell.py:89
      ``exec(compile(pythonrc_code, pythonrc, "exec"))``) and on
      identifier-resolved constant argv (django release script
      ``subprocess.run(unzip_command)`` with a literal list -- extends the
      D1 fixed-argv exemption to identifier-resolved lists).
"""
from __future__ import annotations

import pathlib
import sys
import textwrap

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

_RATE_LIMIT = "MISSING_RATE_LIMIT_ENDPOINT"
_LLM02 = "LLM02_INSECURE_OUTPUT_HANDLING"
_LLM04 = "LLM04_MODEL_DENIAL_OF_SERVICE"
_PROMPT_TEMPLATE = "PROMPT_TEMPLATE_SECRET_EXPOSURE"
_PROMPT_RESPONSE = "PROMPT_RESPONSE_LOGGING_SENSITIVE_DATA"
_AI_PROVIDER = "AI_PROVIDER_SECRET_EXPOSURE"


def _write(tmp_path, name: str, source: str) -> pathlib.Path:
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


def _adv(tmp_path, name: str, source: str) -> list[dict]:
    from scanner.advanced_ai_security import scan_advanced_ai_file

    text = textwrap.dedent(source)
    path = _write(tmp_path, name, text)
    return scan_advanced_ai_file(str(path), text)


def _ids(findings: list[dict]) -> set[str]:
    return {str(f.get("rule_id") or f.get("id")) for f in findings}


# ---------------------------------------------------------------------------
# I1 -- MISSING_RATE_LIMIT: "transfer" is a payment verb, not HTTP framing
# ---------------------------------------------------------------------------
def test_rate_limit_transfer_encoding_headers_suppressed(tmp_path):
    """express lib/response.js:202/209 + test/res.send.js:597/604 -- the
    EXACT matched shapes (bare identifiers, as they sit in the real files
    outside string spans). The real route line keeps its finding; the
    framing-header lines must not."""
    source = (
        'const express = require("express");\n'
        "const app = express();\n"
        'app.post("/shop/" + checkout, handler);\n'
        "ServerResponse.prototype.removeHeader = function removeHeader(name) {\n"
        "    this.removeHeader(TRANSFER_ENCODING);\n"
        "    var transferEncodings = [name];\n"
        "};\n"
    )
    findings = _sast(tmp_path, "response.js", source)
    hit_lines = {
        f["line"] for f in findings if f.get("rule_id") == _RATE_LIMIT
    }
    assert hit_lines == {3}


def test_rate_limit_transfer_payment_route_still_reported(tmp_path):
    """Control: a real transfer endpoint definition keeps the finding."""
    source = (
        'const express = require("express");\n'
        "const app = express();\n"
        'app.post("/wallet/" + transfer, handler);\n'
    )
    findings = _sast(tmp_path, "wallet.js", source)
    assert _RATE_LIMIT in _ids(findings)


# ---------------------------------------------------------------------------
# I2 -- shared EXCLUDED_DIRS policy gains "out" (forge build artifacts)
# ---------------------------------------------------------------------------
def test_sast_skip_policy_excludes_out_dir():
    from scanner.sast import _skip

    assert _skip(pathlib.Path("target/contracts/out/Factory.sol/X.json")) is True
    assert _skip(pathlib.Path("target/contracts/src/X.json")) is False


def test_secret_skip_policy_excludes_out_dir():
    from scanner.secret_intelligence import _skip

    assert _skip(pathlib.Path("target/contracts/out/Factory.sol/X.json")) is True
    assert _skip(pathlib.Path("target/contracts/src/X.json")) is False


def test_out_dir_artifacts_not_reported_by_directory_scan(tmp_path):
    """Same fabricated artifact content under out/ vs src/: only the
    scanned source tree yields a finding."""
    from scanner.sast import scan_directory

    payload = '{"config": "AKIA1234567890ABCD00"}\n'
    _write(tmp_path, "contracts/out/Factory.sol/Factory.json", payload)
    _write(tmp_path, "contracts/src/Factory.json", payload)
    findings = scan_directory(str(tmp_path))
    files = [f["file"] for f in findings if f.get("rule_id") == "AWS_ACCESS_KEY"]
    assert len(files) == 1
    assert "out" not in files[0].replace("\\", "/").split("/")


def test_out_dir_secret_engine_skipped(tmp_path):
    from scanner.secret_intelligence import scan_file as _sec_scan

    payload = '{"key": "AKIA1234567890ABCD00"}\n'
    out_file = _write(tmp_path, "build/out/deploy.json", payload)
    src_file = _write(tmp_path, "build/src/deploy.json", payload)
    assert _sec_scan(str(out_file)) == []
    assert any(
        f.get("rule_id") == "AWS_ACCESS_KEY" for f in _sec_scan(str(src_file))
    )


# ---------------------------------------------------------------------------
# I3 -- AWS key matching is uppercase-only (base58 CIDs are not keys)
# ---------------------------------------------------------------------------
def test_aws_key_cid_mixed_case_suppressed(tmp_path):
    """ethernaut contracts/out ABIs embed the CID as a hex string; its
    ``AkiaskScQ7fFtfgvMsW`` substring used to match case-insensitively."""
    findings = _sast(
        tmp_path,
        "Artifact.json",
        '{"cid": "QmTzWboptc2WjGQH4ShcN4XAkiaskScQ7fFtfgvMsWuSRq"}\n',
    )
    assert "AWS_ACCESS_KEY" not in _ids(findings)


def test_aws_key_uppercase_still_reported(tmp_path):
    """Control: a real (uppercase) key ID keeps firing in the same file
    shape."""
    findings = _sast(
        tmp_path,
        "config.json",
        '{"aws": {"AWS_ACCESS_KEY_ID": "AKIA1234567890ABCDEF"}}\n',
    )
    assert "AWS_ACCESS_KEY" in _ids(findings)


def test_llm02_secret_evidence_aws_is_case_sensitive():
    from scanner.llm_security import _v11_llm02_secret_evidence

    cid = _v11_llm02_secret_evidence(
        'artifact = "QmTzWboptc2WjGQH4ShcN4XAkiaskScQ7fFtfgvMsWuSRq"'
    )["matches"]
    assert not any(m["type"] == "AWS_ACCESS_KEY" for m in cid)
    key = _v11_llm02_secret_evidence(
        'AWS_ACCESS_KEY_ID = "AKIA1234567890ABCDEF"'
    )["matches"]
    assert any(m["type"] == "AWS_ACCESS_KEY" for m in key)


# ---------------------------------------------------------------------------
# I4 -- LLM04: a while-True that demonstrably cannot spin is not model DoS
# ---------------------------------------------------------------------------
def test_llm04_break_exit_body_suppressed(tmp_path):
    """django views/debug.py:523 traceback-frame walk (break on
    IndexError)."""
    findings = _llm(tmp_path, "frames.py", '''
        def walk_frames(exc_value, tb):
            frames = []
            while True:
                frames.extend(get_traceback_frames(exc_value, tb))
                try:
                    exc_value = exceptions.pop()
                except IndexError:
                    break
                tb = exc_value.__traceback__
            return frames
    ''')
    assert _LLM04 not in _ids(findings)


def test_llm04_requests_retry_loop_suppressed(tmp_path):
    """crAPI merchant/views.py:83 mechanic retry loop: requests.get plus
    three breaks bound to the while (no nested loop)."""
    findings = _llm(tmp_path, "views.py", '''
        def repeat_get(request_data, number_of_repeats):
            repeat_count = 1
            while True:
                request_url = request_data["mechanic_api"]
                mechanic_response = requests.get(request_url, verify=False)
                if mechanic_response.status_code == 200:
                    break
                if repeat_count == number_of_repeats:
                    break
                repeat_count += 1
    ''')
    assert _LLM04 not in _ids(findings)


def test_llm04_sleep_one_liner_sidecar_suppressed(tmp_path):
    """wrongsecrets k8s/challenge53 sidecar: shell poll loop with
    ``sleep 10`` on the same line."""
    findings = _llm(tmp_path, "sidecar.yml", '''
        apiVersion: apps/v1
        kind: Deployment
        spec:
          template:
            spec:
              containers:
                - name: challenge53-sidecar
                  command: ["/bin/sh", "-c", "while true; do ls /shared-data; sleep 10; done"]
    ''')
    assert _LLM04 not in _ids(findings)


def test_llm04_path_walk_break_suppressed(tmp_path):
    """flask src/flask/cli.py:216 module-name walk (break when the path
    no longer has an __init__.py)."""
    findings = _llm(tmp_path, "cli.py", '''
        def find_modules(app_path):
            module_name = []
            while True:
                path, name = os.path.split(app_path)
                module_name.append(name)
                if not os.path.exists(os.path.join(path, "__init__.py")):
                    break
                app_path = path
    ''')
    assert _LLM04 not in _ids(findings)


def test_llm04_ai_context_loop_kept(tmp_path):
    """Control: GenAI/pygoat shape -- an interactive loop inside an AI
    file keeps the model-nexus benefit of the doubt."""
    findings = _llm(tmp_path, "PyGoatBot.py", '''
        # vulnerable llm chatbot used by the pygoat training lab
        from openai import OpenAI
        while True:
            try:
                user_input = input("You: ")
                if user_input.lower() == "exit":
                    break
            except EOFError:
                raise SystemExit
    ''')
    assert _LLM04 in _ids(findings)


def test_llm04_pure_cpu_spin_still_reported(tmp_path):
    """Control: ``while True: x = x + 1`` has no exit, no block, no I/O
    -- still the CPU spin the rule means."""
    findings = _llm(tmp_path, "spin.py", '''
        def heat():
            while True:
                x = x + 1
    ''')
    assert _LLM04 in _ids(findings)


def test_llm04_nested_for_break_is_not_exit_proof(tmp_path):
    """A ``break`` inside a NESTED for binds that for, not the while --
    the outer loop still has no exit, so the finding stays."""
    findings = _llm(tmp_path, "nested.py", '''
        def scan_batches(rows):
            while True:
                for row in rows:
                    if row.done:
                        break
                rows = rows.next_batch()
    ''')
    assert _LLM04 in _ids(findings)


# ---------------------------------------------------------------------------
# I5 -- PROMPT_TEMPLATE: bare credential identifier, no AI context
# ---------------------------------------------------------------------------
def test_prompt_template_token_object_suppressed(tmp_path):
    """django template/base.py:205/313 -- e.token / exception token are
    the parser's Token objects, not secrets."""
    findings = _llm(tmp_path, "base.py", '''
        class ExceptionReporter:
            def get_exception_info(self, exception, token):
                e.template_debug = self.get_exception_info(e, e.token)
                return template.get_exception_info(exception, token)
    ''')
    assert _PROMPT_TEMPLATE not in _ids(findings)


def test_prompt_template_templatetag_parser_suppressed(tmp_path):
    """django template/defaulttags.py:1484 -- ``def templatetag(parser,
    token)``; "token" is a parameter name."""
    findings = _llm(tmp_path, "defaulttags.py", '''
        from django.template import TemplateSyntaxError

        def templatetag(parser, token):
            bits = token.split_contents()
            return Node(bits)
    ''')
    assert _PROMPT_TEMPLATE not in _ids(findings)


def test_prompt_template_doc_template_literal_kept(tmp_path):
    """Control: LLMForge indirect_prompt_injection_lab.py:252 -- an AI
    file whose template embeds a secret token keeps."""
    findings = _llm(tmp_path, "indirect_prompt_injection_lab.py", '''
        # indirect prompt injection lab challenge for the llm training app
        def build_challenge(challenge, secret_token):
            return challenge.internal_doc_template.format(secret_token=secret_token or "")
    ''')
    assert _PROMPT_TEMPLATE in _ids(findings)


def test_prompt_template_string_embedded_token_kept(tmp_path):
    """Control (D2 shape): the token inside the template STRING -- the
    file has no AI context, but the credential word is not a bare
    identifier, so no suppression applies."""
    findings = _llm(tmp_path, "keep_token.py", '''
        prompt_template = "Hello, your access token: {token}"
    ''')
    assert _PROMPT_TEMPLATE in _ids(findings)


# ---------------------------------------------------------------------------
# I6 -- AI_PROVIDER: reference-only declarations are not exposure
# ---------------------------------------------------------------------------
def test_ai_provider_getenv_reference_suppressed(tmp_path):
    """crAPI services/chatbot config.py:17 + anthropic twin."""
    findings = _llm(tmp_path, "config.py", '''
        class ChatbotConfig:
            OPENAI_API_KEY = os.getenv("CHATBOT_OPENAI_API_KEY")
            ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY")
    ''')
    assert _AI_PROVIDER not in _ids(findings)


def test_ai_provider_compose_env_references_suppressed(tmp_path):
    """crAPI deploy/docker/docker-compose.yml:189/191/192/209."""
    findings = _llm(tmp_path, "docker-compose.yml", '''
        services:
          chatbot:
            environment:
              - CHATBOT_OPENAI_API_KEY=${CHATBOT_OPENAI_API_KEY:-}
              - ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY:-}
              - AZURE_OPENAI_API_KEY=${AZURE_OPENAI_API_KEY:-}
              - GOOGLE_APPLICATION_CREDENTIALS=${GOOGLE_APPLICATION_CREDENTIALS:-}
    ''')
    assert _AI_PROVIDER not in _ids(findings)


def test_ai_provider_helm_and_empty_value_suppressed(tmp_path):
    """crAPI deploy/k8s config.yaml:47 (empty string) and
    deploy/helm/templates config.yaml:48 (helm template)."""
    findings = _llm(tmp_path, "config.yaml", '''
        apiVersion: v1
        data:
          GOOGLE_APPLICATION_CREDENTIALS: ""
          ANTHROPIC_API_KEY: {{ .Values.anthropicApiKey | quote }}
    ''')
    assert _AI_PROVIDER not in _ids(findings)


def test_ai_provider_literal_key_kept(tmp_path):
    """Control: GenAI RAG_local/app/rag_engine.py:24 -- a committed
    literal keeps."""
    findings = _llm(tmp_path, "rag_engine.py", '''
        # sandbox model wiring for the openai rag app
        OPENAI_API_KEY = "sk-mock-key"
    ''')
    assert _AI_PROVIDER in _ids(findings)


def test_ai_provider_env_file_unquoted_literal_kept(tmp_path):
    """Control: .env-style unquoted token literals keep."""
    findings = _llm(tmp_path, "dotenv_loader.py", '''
        # dotenv style wiring
        OPENAI_API_KEY=sk-proj-Abc123XyZ7890
    ''')
    assert _AI_PROVIDER in _ids(findings)


def test_ai_provider_advanced_engine_comment_suppressed(tmp_path):
    """crAPI chat_api.py:56 -- the comment row came from the advanced AI
    engine (no comment gate of its own)."""
    assert _AI_PROVIDER not in _ids(
        _adv(tmp_path, "chat_api.py", '''
            # GOOGLE_APPLICATION_CREDENTIALS is optional if running in GCP with ADC
        ''')
    )


def test_ai_provider_advanced_engine_reference_suppressed(tmp_path):
    assert _AI_PROVIDER not in _ids(
        _adv(tmp_path, "chat_api.py", '''
            OPENAI_API_KEY = os.getenv("CHATBOT_OPENAI_API_KEY")
        ''')
    )


def test_ai_provider_advanced_engine_literal_kept(tmp_path):
    """Control: the same engine keeps a committed literal."""
    assert _AI_PROVIDER in _ids(
        _adv(tmp_path, "keys.py", '''
            ANTHROPIC_API_KEY = "sk-ant-real-key-1234567890"
        ''')
    )


# ---------------------------------------------------------------------------
# I7 -- PROMPT_RESPONSE_LOGGING: a logging call, a code-position token,
# and response/prompt data that is not status-metadata-only
# ---------------------------------------------------------------------------
def test_prompt_response_prose_substring_suppressed(tmp_path):
    """LLMForge bola_chatbot_controller.py:25 -- "logic ... prompts"
    inside an HTML prose string; there is no logging call."""
    findings = _llm(tmp_path, "bola_chatbot_controller.py", '''
        LAB_NOTES = (
            "<p>In LLM systems this can manifest when access control logic is delegated to the model via prompts - an attacker can manipulate the LLM to retrieve another user's records by asking, bypassing code-enforced checks.</p>"
        )
    ''')
    assert _PROMPT_RESPONSE not in _ids(findings)


def test_prompt_response_minified_vendor_regex_suppressed(tmp_path):
    """WebGoat mode-java.js:221 -- "Dialog" (a log substring) and
    "response" co-occurring inside a syntax-highlighting regex."""
    findings = _llm(tmp_path, "mode-java.js", '''
        CodeMirror.defineMode("java", function () {
            return { token: function (stream, state) { var re = /(shift|showModalessDialog|showModalDialog|scrollX)/; var response = stream.currentLine(); return response; } };
        });
    ''')
    assert _PROMPT_RESPONSE not in _ids(findings)


def test_prompt_response_message_only_api_key_suppressed(tmp_path):
    """crAPI chat_api.py:86/101 -- an error message that NAMES a key that
    was not provided."""
    findings = _llm(tmp_path, "chat_api.py", '''
        def get_client(api_key):
            if not api_key:
                logger.error("openai_api_key not provided")
                return None
    ''')
    assert _PROMPT_RESPONSE not in _ids(findings)


def test_prompt_response_session_debug_message_suppressed(tmp_path):
    """crAPI chat_service.py:63 -- response word inside the message,
    session_id outside."""
    findings = _llm(tmp_path, "chat_service.py", '''
        def run_agent(session_id):
            logger.debug("LangGraph agent response received - session_id: %s", session_id)
    ''')
    assert _PROMPT_RESPONSE not in _ids(findings)


def test_prompt_response_status_only_suppressed(tmp_path):
    """juice-shop .github/workflows/pr-compliance.yml:457 -- logs an HTTP
    status code, not model data."""
    findings = _llm(tmp_path, "pr-compliance.yml", '''
        jobs:
          compliance:
            steps:
              - name: Block spam
                run: |
                  const errorText = await response.text();
                  console.log(`Failed to block user ${author}: ${response.status} ${errorText}`);
    ''')
    assert _PROMPT_RESPONSE not in _ids(findings)


def test_prompt_response_model_body_kept(tmp_path):
    """Control: crAPI Bot.tsx:97 -- logs the model response BODY."""
    findings = _llm(tmp_path, "Bot.tsx", '''
        useEffect(() => {
          console.log("Initialization response:", response.body);
        }, []);
    ''')
    assert _PROMPT_RESPONSE in _ids(findings)


def test_prompt_response_fstring_prompt_var_kept(tmp_path):
    """Control: logging the actual prompt variable via interpolation."""
    findings = _llm(tmp_path, "inference.py", '''
        logger.info(f"prompt={prompt}")
    ''')
    assert _PROMPT_RESPONSE in _ids(findings)


# ---------------------------------------------------------------------------
# I8 -- LLM02: PYTHONSTARTUP feature + identifier-resolved constant argv
# ---------------------------------------------------------------------------
def test_llm02_pythonstartup_eval_suppressed(tmp_path):
    """flask src/flask/cli.py:1022."""
    findings = _llm(tmp_path, "cli.py", '''
        def run_startup(startup, ctx):
            if startup:
                with open(startup) as f:
                    eval(compile(f.read(), startup, "exec"), ctx)
    ''')
    assert _LLM02 not in _ids(findings)


def test_llm02_pythonrc_exec_suppressed(tmp_path):
    """django core/management/commands/shell.py:89."""
    findings = _llm(tmp_path, "shell.py", '''
        def import_pythonrc(pythonrc, imported_objects):
            with open(pythonrc) as handle:
                pythonrc_code = handle.read()
            exec(compile(pythonrc_code, pythonrc, "exec"), imported_objects)
    ''')
    assert _LLM02 not in _ids(findings)


def test_llm02_compile_untrusted_data_still_reported(tmp_path):
    """Control: compile() of untrusted data with a non-startup filename
    is still code execution."""
    findings = _llm(tmp_path, "sandbox.py", '''
        def run_payload(code, name):
            exec(compile(code, name, "exec"))
    ''')
    assert _LLM02 in _ids(findings)


def test_llm02_constant_argv_identifier_suppressed(tmp_path):
    """django scripts/do_django_release.py:195-202 -- unzip_command is a
    literal list; subprocess.run(identifier) cannot steer the program."""
    findings = _llm(tmp_path, "do_django_release.py", '''
        def unpack(archive_path, extract_dir):
            unzip_command = [
                "unzip", "-q", "-o", "-n",
                archive_path, "-d", extract_dir,
            ]
            subprocess.run(unzip_command)
    ''')
    assert _LLM02 not in _ids(findings)


def test_llm02_dynamic_argv_identifier_still_reported(tmp_path):
    """Control: an identifier that is NOT a constant list keeps."""
    findings = _llm(tmp_path, "run.py", '''
        def launch(cmd):
            subprocess.run(cmd)
    ''')
    assert _LLM02 in _ids(findings)


def test_llm02_non_literal_list_argv_still_reported(tmp_path):
    """Control: a list whose first element is not a literal program name
    keeps."""
    findings = _llm(tmp_path, "run2.py", '''
        def launch(targets):
            argv = [target for target in targets]
            subprocess.run(argv)
    ''')
    assert _LLM02 in _ids(findings)
