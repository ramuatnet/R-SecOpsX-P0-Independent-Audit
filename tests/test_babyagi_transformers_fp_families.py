# -*- coding: utf-8 -*-
r"""babyagi-main + transformers-main validation (2026-10-16): the detection
defect families found on the two large corpora, with the AgentGPT /
semantic-kernel / autogen families kept as stability.

The consultant validation traced the 12 Tier A families plus the PDF
performance defect:

  A1  sast EVAL_CALL matched ``\beval\s*(`` -- 2822/2822 transformers rows
      were receiver-mode ``model.eval()`` toggles; LLM02 additionally
      matched the substring ``eval(`` inside ``...TextRetrieval(config)``
      and any receiver ``.eval()``.
  A2  LLM10's ``save_pretrained`` matched 251 local dumps and method
      definitions with no transfer to a hub/remote at all.
  A3  LLM06 ``return.*token`` matched NLP vocabulary (``return tokenizer``,
      ``return self._all_special_tokens``) as credential disclosure.
  A4  SOURCE_HARDCODED_CREDENTIAL accepted identifier-substring nouns
      (``target_tokenizer``) and reference-shaped values
      (``token_type_ids``, ``torch.Tensor | None``, ``TILE_GLOBAL``,
      ``__start__``, ``]<]image[>[``) -- 42/42 measured rows were
      non-credential.
  A5  ``os.environ``/``os.getenv`` were taint sources, so reading a token
      from the deployment environment reported SSRF (4x transformers).
  A6  LLM05 ``pip install`` matched instructional docstring sentences.
  A7  identity PUBLIC_ROLE_TRUST / AZURE_OWNER_ROLE were word+DOTALL prose
      matchers (``authenticated principal ... *``, ``owner match``) and the
      release AI gate bound P0 to *independent* counts, letting 216
      unconfirmed criticals ride one confirmed neighbour into P0.
  A8  SBOM never read setup.py -- transformers' whole runtime
      install_requires (9 packages) was invisible.
  A9  SSRF sourced from the urllib module itself, accepted payload kwargs
      (``json=params``/``headers=``) as the URL, and had no httpx sinks.
      The end-to-end A/B rescan then exposed A9d: the rule compiles with
      re.IGNORECASE, so the C# ``Request\.`` alternative matched
      ``urllib.request.``/local ``request.`` case-insensitively and
      bypassed the A9a lookbehind -- six urllib Request/response-object
      rows survived (add_dates.py:80, get_ci_error_statistics.py:120,
      github_utils.py:221, update_pr_ci_dashboard_recap.py:73,
      integration_utils.py:2565, transformers_serve_cb_eval_job.py:29),
      and ``r\.URL`` matched inside ``urllib.error.URLError``.  A9e closed
      the residual AST leak at update_pr_ci_dashboard_recap.py:73: the
      ``urlencode`` payload encoder is nested inside the f-string, so the
      outermost-call sanitizer check missed it and the taint laundered
      through request_json() into urlopen(); class attribution is now
      occurrence-based (every contributor must pass the sanitizer).
  A10 bare ``execute`` accepted any dotted receiver, so a *function*
      executor (``g.functionz.executor.execute``) was SQL injection.
  A11 GraphQL BOLA used substring boundaries (``record_id:`` sources,
      ``user_db.`` sinks) and a bare ``schema`` word as context.
  A12 the client-side SSRF gate missed ``/static/`` bundles.

Every test states both sides of the kill-only-on-proof contract: the false
shape must be gone, and a real detection at the same location must survive.
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


def _sec(tmp_path, name: str, source: str) -> list[dict]:
    from scanner.secret_intelligence import scan_file

    return scan_file(str(_write(tmp_path, name, source)))


def _taint(tmp_path, name: str, source: str) -> list[dict]:
    from scanner.taint_engine import analyze_file

    return analyze_file(str(_write(tmp_path, name, source)))


def _ids(findings: list[dict]) -> set[str]:
    return {str(f.get("rule_id") or f.get("id")) for f in findings}


# ---------------------------------------------------------------------------
# A1 -- eval(): a dynamic-evaluation call, not a mode toggle or a substring
# ---------------------------------------------------------------------------
def test_eval_receiver_mode_suppressed(tmp_path):
    """2822/2822 transformer EVAL_CALL rows were this shape."""
    findings = _sast(tmp_path, "model.py", '''
        import torch
        model = torch.load("m.pt")
        model.eval()
        evaluator.eval()
    ''')
    assert "EVAL_CALL" not in _ids(findings)


def test_eval_identifier_ending_in_eval_suppressed(tmp_path):
    """``Retrieval(config)`` contains the substring ``eval(``."""
    findings = _sast(tmp_path, "vilt.py", '''
        model = ViltForImageAndTextRetrieval(config)
    ''')
    assert "EVAL_CALL" not in _ids(findings)


def test_eval_bare_call_still_reported(tmp_path):
    findings = _sast(tmp_path, "evals.py", '''
        def apply(code):
            return eval(code)
    ''')
    assert "EVAL_CALL" in _ids(findings)


def test_eval_known_dynamic_hosts_still_reported(tmp_path):
    findings = _sast(tmp_path, "host.js", '''
        function go(x) {
            window.eval(x);
            globalThis.eval(x);
        }
    ''')
    assert "EVAL_CALL" in _ids(findings)


def test_eval_php_call_still_reported(tmp_path):
    findings = _sast(tmp_path, "run.php", '''
        <?php
        function run($code) { eval($code); }
    ''')
    assert "EVAL_CALL" in _ids(findings)


def test_llm02_receiver_eval_suppressed(tmp_path):
    findings = _llm(tmp_path, "eval_model.py", '''
        model.eval()
        converter.eval()
    ''')
    assert "LLM02_INSECURE_OUTPUT_HANDLING" not in _ids(findings)


def test_llm02_eval_substring_identifier_suppressed(tmp_path):
    findings = _llm(tmp_path, "vilt.py", '''
        model = ViltForImageAndTextRetrieval(config)
    ''')
    assert "LLM02_INSECURE_OUTPUT_HANDLING" not in _ids(findings)


def test_llm02_bare_eval_still_reported(tmp_path):
    """Control: a real dynamic-evaluation call keeps its finding."""
    findings = _llm(tmp_path, "cfg.py", '''
        conv_layers = eval(fs_config.extractor_conv_feature_layers)
    ''')
    assert "LLM02_INSECURE_OUTPUT_HANDLING" in _ids(findings)


def test_llm02_child_process_exec_still_reported(tmp_path):
    """Control: ``.exec(`` is NOT gated -- child_process exec executes."""
    findings = _llm(tmp_path, "cp.js", '''
        const cp = require("child_process");
        const out = cp.exec(cmd);
    ''')
    assert "LLM02_INSECURE_OUTPUT_HANDLING" in _ids(findings)


# ---------------------------------------------------------------------------
# A2 -- model theft requires a transfer, not a local save
# ---------------------------------------------------------------------------
def test_llm10_local_save_pretrained_suppressed(tmp_path):
    findings = _llm(tmp_path, "save.py", '''
        def dump(model, tmpdir):
            model.save_pretrained(tmpdir)
    ''')
    assert "LLM10_MODEL_THEFT" not in _ids(findings)


def test_llm10_method_definition_suppressed(tmp_path):
    findings = _llm(tmp_path, "defs.py", '''
        class M:
            def save_pretrained(self, save_directory, push_to_hub: bool = False):
                pass
    ''')
    assert "LLM10_MODEL_THEFT" not in _ids(findings)


def test_llm10_save_pretrained_with_exfil_still_reported(tmp_path):
    """Control: the same call beside push_to_hub=True is theft."""
    findings = _llm(tmp_path, "hub.py", '''
        trainer.save_pretrained(output_dir, push_to_hub=True)
    ''')
    assert "LLM10_MODEL_THEFT" in _ids(findings)


def test_llm10_state_dict_sink_still_reported(tmp_path):
    """Control: the other LLM10 sinks are untouched by the save gate."""
    findings = _llm(tmp_path, "sd.py", '''
        torch.save(model.state_dict(), path)
    ''')
    assert "LLM10_MODEL_THEFT" in _ids(findings)


# ---------------------------------------------------------------------------
# A3 -- returning NLP vocabulary is not credential disclosure
# ---------------------------------------------------------------------------
def test_llm06_return_nlp_vocab_suppressed(tmp_path):
    findings = _llm(tmp_path, "tok.py", '''
        def peek(tokenizer):
            return tokenizer
        def special(self):
            return self._all_special_tokens
    ''')
    assert "LLM06_SENSITIVE_INFORMATION_DISCLOSURE" not in _ids(findings)


def test_llm06_return_credential_token_still_reported(tmp_path):
    """Control: wokelo's real credential return keeps its finding."""
    findings = _llm(tmp_path, "wokelo.py", '''
        def session_token():
            return token_info.get("access_token")
    ''')
    assert "LLM06_SENSITIVE_INFORMATION_DISCLOSURE" in _ids(findings)


def test_llm06_return_api_key_pattern_still_reported(tmp_path):
    """Control: ``return.*api_key`` is a separate exact pattern, ungated."""
    findings = _llm(tmp_path, "apikey.py", '''
        def key():
            return os.environ.get("OPENAI_API_KEY")
    ''')
    assert "LLM06_SENSITIVE_INFORMATION_DISCLOSURE" in _ids(findings)


# ---------------------------------------------------------------------------
# A4 -- the credential-named identifier must NAME a credential, and the
# value must BE secret material
# ---------------------------------------------------------------------------
def test_source_reference_values_suppressed(tmp_path):
    """Every class of the measured 42-row family, one example each."""
    findings = _sec(tmp_path, "ref_values.py", '''
        return_token_type_ids = "token_type_ids"
        target_tokenizer: "PreTrainedTokenizerBase"
        _bos_token_tensor: "torch.Tensor | None"
        tile_global_token = "TILE_GLOBAL"
        bos_token = "__start__"
        IMAGE_TOKEN = "]<]image[>["
        image_break_token = "[IMG_BREAK]"
        SPECIAL_TOKENS_PATTERN = "cls_double_sep"
        TMP_TOKENIZER_DIR = "/tmp/tokenizers"
        has_max_new_tokens = "max_new_tokens"
    ''')
    assert "SOURCE_HARDCODED_CREDENTIAL" not in _ids(findings)


def test_source_real_tokens_still_reported(tmp_path):
    """Control: the corpus/e2e secret fixtures keep their findings."""
    findings = _sec(tmp_path, "real_secrets.py", '''
        GITHUB_TOKEN = "ghp_0123456789abcdefghij0123456789abcd"
        OPENAI_API_KEY = "sk-proj-0123456789abcdefghij0123456789abcd"
        JWT_SIGNING_SECRET = "a-signing-key-of-sufficient-length-0123456789"
        API_KEY = "sk-live-hardcoded-secret-0123456789"
    ''')
    assert "SOURCE_HARDCODED_CREDENTIAL" in _ids(findings)


# ---------------------------------------------------------------------------
# A5 -- deployment environment is operator input, not network input
# ---------------------------------------------------------------------------
def test_env_values_do_not_taint(tmp_path):
    findings = _taint(tmp_path, "conf.py", '''
        import os, subprocess
        def run():
            subprocess.run(os.environ["BUILD_CMD"], shell=True)
    ''')
    assert "TAINT_COMMAND_INJECTION" not in _ids(findings)


def test_argv_still_taints(tmp_path):
    """Control: a direct attacker-reachable process surface keeps tainting."""
    findings = _taint(tmp_path, "cli.py", '''
        import subprocess, sys
        def run():
            subprocess.run(sys.argv[1], shell=True)
    ''')
    assert "TAINT_COMMAND_INJECTION" in _ids(findings)


# ---------------------------------------------------------------------------
# A6 -- "pip install" in an instruction sentence is prose
# ---------------------------------------------------------------------------
def test_llm05_instructional_pip_prose_suppressed(tmp_path):
    findings = _llm(tmp_path, "doc.py", '''
        raise RuntimeError("Install the required tokenizer pieces with pip install sentencepiece and retry.")
    ''')
    assert "LLM05_SUPPLY_CHAIN_VULNERABILITY" not in _ids(findings)


def test_llm05_command_at_string_start_still_reported(tmp_path):
    """Control: the command *is* the string value, 0 words precede it."""
    findings = _llm(tmp_path, "resolver.py", '''
        INSTALL_RESOLVER = "pip install -r requirements.txt"
    ''')
    assert "LLM05_SUPPLY_CHAIN_VULNERABILITY" in _ids(findings)


def test_llm05_ci_yaml_command_still_reported(tmp_path):
    findings = _llm(tmp_path, "ci.yml", '''
        steps:
          - run: uv pip install -U -e .
    ''')
    assert "LLM05_SUPPLY_CHAIN_VULNERABILITY" in _ids(findings)


def test_llm05_two_word_instruction_keeps(tmp_path):
    """Control: the threshold is >=3 words; a 2-word lead keeps."""
    findings = _llm(tmp_path, "hint.py", '''
        hint = "Please run `pip install llama-index` to continue."
    ''')
    assert "LLM05_SUPPLY_CHAIN_VULNERABILITY" in _ids(findings)


def test_llm05_langchain_import_keeps(tmp_path):
    """Control: a non-pip LLM05 pattern is untouched by the prose gate."""
    findings = _llm(tmp_path, "chain.py", '''
        from langchain.llms import FakeListLLM
    ''')
    assert "LLM05_SUPPLY_CHAIN_VULNERABILITY" in _ids(findings)


# ---------------------------------------------------------------------------
# A7 -- identity evidence must be evidence; the AI gate binds to the SAME
# indicator it escalates
# ---------------------------------------------------------------------------
def test_identity_remediation_prose_is_not_iam_evidence():
    from analysis.identity_access_risk_engine import enrich_identity_access_risk

    findings = [{
        "remediation": [
            "Require every authenticated principal to pass negative authorization tests.",
            "Tenant and owner match the authenticated principal before release.",
        ],
        "snippet": "cross-tenant reference: *",
    }]
    summary = enrich_identity_access_risk(findings)
    names = {i["indicator"] for i in summary["global_indicators"]}
    assert "PUBLIC_ROLE_TRUST" not in names
    assert "AZURE_OWNER_ROLE" not in names


def test_identity_wildcard_principal_and_owner_role_still_reported():
    """Control: real IAM/AML evidence shapes keep their indicators."""
    from analysis.identity_access_risk_engine import enrich_identity_access_risk

    findings = [{
        "snippet": '{"Principal": "*", "roleDefinitionName": "Owner", "trusted_entities": ["*"]}',
    }]
    summary = enrich_identity_access_risk(findings)
    names = {i["indicator"] for i in summary["global_indicators"]}
    assert "PUBLIC_ROLE_TRUST" in names
    assert "AZURE_OWNER_ROLE" in names


def test_ai_gate_priority_follows_confirmed_indicator():
    """216 unconfirmed criticals + one confirmed HIGH must not reach P0."""
    from analysis.release_readiness_engine import derive_release_readiness

    indicators = (
        [{"indicator": "UNSAFE_CODE_INTERPRETER_TOOL", "risk_level": "CRITICAL",
          "confirmed_executive_risk": False}] * 216
        + [{"indicator": "NO_CONTENT_FILTERING", "risk_level": "HIGH",
            "confirmed_executive_risk": True}]
    )
    payload = {"ai_model_risk_summary": {
        "critical_ai_model_risk_indicators": 216,
        "high_ai_model_risk_indicators": 1,
        "confirmed_executive_risk_indicators": 1,
        "global_indicators": indicators,
    }}
    gates = {g["gate_id"]: g for g in derive_release_readiness(payload)["all_gates"]}
    assert "CRITICAL_AI_MODEL_RISK" not in gates
    assert gates.get("HIGH_AI_MODEL_RISK", {}).get("priority") == "P1"


def test_ai_gate_confirmed_critical_still_p0_with_bound_evidence():
    """Control: transformers' 6 confirmed CRITICAL rows keep P0 -- and the
    evidence now cites the confirmed count, not the 222-row volume."""
    from analysis.release_readiness_engine import derive_release_readiness

    indicators = [
        {"indicator": "TRUST_REMOTE_CODE_ENABLED", "risk_level": "CRITICAL",
         "confirmed_executive_risk": True}
    ] * 6
    payload = {"ai_model_risk_summary": {
        "critical_ai_model_risk_indicators": 222,
        "high_ai_model_risk_indicators": 0,
        "confirmed_executive_risk_indicators": 6,
        "global_indicators": indicators,
    }}
    gates = {g["gate_id"]: g for g in derive_release_readiness(payload)["all_gates"]}
    gate = gates.get("CRITICAL_AI_MODEL_RISK")
    assert gate and gate["priority"] == "P0"
    assert gate["evidence"].get("confirmed_critical_ai_model_risk_indicators") == 6


# ---------------------------------------------------------------------------
# A8 -- setup.py is a manifest: parse it statically, never execute it
# ---------------------------------------------------------------------------
def test_setup_py_install_requires_parsed(tmp_path):
    from scanner.manifests import parse_setup_py

    path = _write(tmp_path, "setup.py", '''
        from setuptools import setup
        _deps = ["numpy>=1.17", "tokenizers", "packaging==24.0"]
        deps = {k: v for k, v in ((x.split(">")[0], x) for x in _deps)}
        install_requires = [deps["numpy"], deps["tokenizers"], deps["packaging"]]
        setup(install_requires=list(install_requires))
    ''')
    rows = parse_setup_py(str(path))
    got = {r["name"]: r["version"] for r in rows}
    assert set(got) == {"numpy", "tokenizers", "packaging"}
    assert got["packaging"] == "24.0"   # exact pin resolves
    assert got["numpy"] == "unknown"    # ranges never guess


def test_setup_py_unparseable_returns_empty(tmp_path):
    from scanner.manifests import parse_setup_py

    path = _write(tmp_path, "setup.py", "def (\n")
    assert parse_setup_py(str(path)) == []


# ---------------------------------------------------------------------------
# A9 -- SSRF: the source must be request state and the taint must sit in
# the URL the server actually fetches; httpx is a sink like requests
# ---------------------------------------------------------------------------
def test_ssrf_urllib_module_is_not_a_source(tmp_path):
    """``urllib.request.urlopen`` sourced from its own module import."""
    findings = _taint(tmp_path, "add_dates.py", '''
        import urllib.request
        def fetch(url):
            with urllib.request.urlopen(url, timeout=10) as response:
                return response.read()
    ''')
    assert "TAINT_SSRF_EXPANDED" not in _ids(findings)
    assert "TAINT_SSRF" not in _ids(findings)


def test_ssrf_payload_kwarg_is_not_the_url(tmp_path):
    """``json=params`` / ``headers=`` carry the payload, not the target."""
    findings = _taint(tmp_path, "payman.py", '''
        import requests
        BASE = "https://api.example"
        def send(params, headers):
            return requests.post(f"{BASE}/augies", json=params, headers=headers)
    ''')
    assert "TAINT_SSRF" not in _ids(findings)
    assert "TAINT_SSRF_EXPANDED" not in _ids(findings)


def test_ssrf_env_token_header_not_reported(tmp_path):
    """The 4x transformer rows: a Circle-Token read from the environment."""
    findings = _taint(tmp_path, "circle.py", '''
        import os, requests
        def fetch(url):
            return requests.get(url, headers={"Circle-Token": os.environ.get("CIRCLE_TOKEN", "")})
    ''')
    assert "TAINT_SSRF" not in _ids(findings)


def test_ssrf_httpx_url_taint_reported(tmp_path):
    """Control/FN fill: httpx was absent from every sink list."""
    findings = _taint(tmp_path, "hx.py", '''
        from flask import request
        import httpx
        def go():
            return httpx.get(request.args["url"])
    ''')
    assert "TAINT_SSRF" in _ids(findings)


def test_ssrf_alias_from_request_args_still_reported(tmp_path):
    """Control: the cross-line alias flow keeps both engine paths."""
    findings = _taint(tmp_path, "proxy.py", '''
        from flask import request
        import requests
        def proxy():
            target = request.args["url"]
            return requests.get(target)
    ''')
    assert "TAINT_SSRF" in _ids(findings)
    assert "TAINT_SSRF_EXPANDED" in _ids(findings)


def test_ssrf_same_line_url_source_still_reported(tmp_path):
    """Control: the source sitting in the URL argument itself."""
    findings = _taint(tmp_path, "direct.py", '''
        from flask import request
        import requests
        def go():
            return requests.get(request.args["url"])
    ''')
    assert "TAINT_SSRF" in _ids(findings)
    assert "TAINT_SSRF_EXPANDED" in _ids(findings)


# ---------------------------------------------------------------------------
# A9d -- the six urllib-object rows that survived the A9 gates end-to-end
# (the rule compiles with re.IGNORECASE, so ``Request\.`` matched lowercase
# ``urllib.request.``/local ``request.`` and bypassed the A9a lookbehind)
# ---------------------------------------------------------------------------
def test_ssrf_local_request_object_variable_suppressed(tmp_path):
    """transformers utils/add_dates.py:80 -- ``request`` is a local
    ``Request(url, method="HEAD")`` object; ``request.add_header`` is a
    method call on it, not a web surface."""
    findings = _taint(tmp_path, "add_dates_local.py", '''
        from urllib.request import Request, urlopen
        def head(file_path):
            url = f"{GITHUB_RAW_URL}/{file_path}"
            request = Request(url, method="HEAD")
            request.add_header("User-Agent", "script")
            with urlopen(request, timeout=10) as response:
                return response.status == 200
    ''')
    assert "TAINT_SSRF_EXPANDED" not in _ids(findings)
    assert "TAINT_SSRF" not in _ids(findings)


def test_ssrf_urllib_request_alias_chain_suppressed(tmp_path):
    """transformers utils/get_ci_error_statistics.py:120 and
    utils/update_pr_ci_dashboard_recap.py:73 -- the ``request`` name is a
    local ``urllib.request.Request(...)`` alias and the sink fetches a
    server-derived URL, never user input."""
    findings = _taint(tmp_path, "ci_stats.py", '''
        import urllib.request
        def fetch(token, artifact_url):
            request = urllib.request.Request(artifact_url, headers={"t": token}, method="GET")
            opener = urllib.request.build_opener(object)
            with opener.open(request, timeout=30) as result:
                download_url = result.headers["Location"]
            with urllib.request.urlopen(download_url, timeout=60) as response:
                return response.read()
    ''')
    assert "TAINT_SSRF_EXPANDED" not in _ids(findings)
    assert "TAINT_SSRF" not in _ids(findings)


def test_ssrf_urlerror_substring_is_not_a_source(tmp_path):
    """transformers utils/github_utils.py:221 -- ``r\.URL`` matched the
    literal substring inside ``urllib.error.URLError``."""
    findings = _taint(tmp_path, "gh_utils.py", '''
        import urllib.request, urllib.error
        def _request(url, headers, method="GET", data=None):
            """Network failures raise (urllib.error.URLError) for the caller."""
            request = urllib.request.Request(url, data=data, headers=headers, method=method)
            try:
                with urllib.request.urlopen(request, timeout=30) as response:
                    return response.status
            except urllib.error.HTTPError as error:
                return error.code
            except urllib.error.URLError(reason=error) from error:
                raise
    ''')
    assert "TAINT_SSRF_EXPANDED" not in _ids(findings)
    assert "TAINT_SSRF" not in _ids(findings)


def test_ssrf_urlopen_response_variable_suppressed(tmp_path):
    """transformers examples/.../transformers_serve_cb_eval_job.py:29 --
    ``req`` is the RESPONSE object of a hardcoded localhost health probe;
    ``req.status`` is not a request surface."""
    findings = _taint(tmp_path, "serve_cb.py", '''
        import urllib.request
        def wait_for_server_up(port=8000):
            req = urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=2)
            if req.status == 200:
                print("up")
    ''')
    assert "TAINT_SSRF_EXPANDED" not in _ids(findings)
    assert "TAINT_SSRF" not in _ids(findings)


def test_ssrf_request_surface_alias_still_reported(tmp_path):
    """Control: the surface-bounded Python pattern keeps the framework
    alias flow (``request.args``), including the qualified-import form."""
    findings = _taint(tmp_path, "proxy_qual.py", '''
        import flask, urllib.request
        def proxy():
            target = flask.request.args.get("url")
            urllib.request.urlopen(target)
    ''')
    assert "TAINT_SSRF_EXPANDED" in _ids(findings)


def test_ssrf_fastapi_query_params_still_reported(tmp_path):
    """Control: Starlette/FastAPI ``request.query_params`` is in the
    surface list and httpx is a sink. The enterprise text rule carries this
    shape (``query_params`` was never an AST TAINT_SOURCES entry -- unchanged
    pre-existing scope)."""
    findings = _taint(tmp_path, "fastapi_proxy.py", '''
        import httpx
        from fastapi import Request
        async def proxy(request: Request):
            async with httpx.get(request.query_params["u"]) as resp:
                return resp
    ''')
    assert "TAINT_SSRF_EXPANDED" in _ids(findings)


def test_ssrf_go_rurl_still_reported(tmp_path):
    """Control: the ``r.URL`` left boundary cannot lose a standalone Go
    ``r`` (always non-word delimited) -- ``http.Get`` still fires."""
    findings = _taint(tmp_path, "handler.go", '''
        package main
        import "net/http"
        func handler(w http.ResponseWriter, r *http.Request) {
            u := r.URL.Query().Get("u")
            resp, _ := http.Get(u)
        }
    ''')
    assert "TAINT_SSRF_EXPANDED" in _ids(findings)


def test_ssrf_js_generic_req_surface_unchanged(tmp_path):
    """Control: non-Python languages keep the generic ``req.`` pattern."""
    findings = _taint(tmp_path, "src/routes/proxy_q.js", '''
        app.get("/proxy", async (req, res) => {
            const r = await fetch(req.query.url);
        });
    ''')
    assert "TAINT_SSRF_EXPANDED" in _ids(findings)


# ---------------------------------------------------------------------------
# A9e -- nested-sanitizer attribution: the payload encoder sits INSIDE the
# f-string, so the old outermost-call check saw a JoinedStr, marked the URL
# unsanitised, and the taint rode request_json() into urlopen()
# ---------------------------------------------------------------------------
def test_ssrf_urlencode_payload_laundered_cross_function_suppressed(tmp_path):
    """transformers utils/update_pr_ci_dashboard_recap.py:73: the chain
    ``query -> urlencode -> url -> Request -> urlopen`` fired SSRF against
    the hardcoded GRAFANA_QUERY_URL constant with the taint confined to the
    percent-encoded query payload -- payload, never destination."""
    findings = _taint(tmp_path, "recap.py", '''
        import urllib.request, urllib.parse
        GRAFANA_QUERY_URL = "https://ci.example/api/v1/query"
        def request_json(url):
            headers = {"Accept": "application/json"}
            request = urllib.request.Request(url, headers=headers, method="GET")
            with urllib.request.urlopen(request, timeout=30) as response:
                return response.read()
        def query_prometheus(query):
            url = f"{GRAFANA_QUERY_URL}?{urllib.parse.urlencode({'query': query})}"
            return request_json(url)
    ''')
    assert "TAINT_SSRF" not in _ids(findings)
    assert "TAINT_SSRF_EXPANDED" not in _ids(findings)


def test_ssrf_cross_function_destination_taint_still_reported(tmp_path):
    """Control: the identical cross-function shape WITHOUT the payload
    encoder -- the destination itself is attacker-controlled -- must fire.
    Also the A9f seeding fix: ``request.args["url"]``'s recorded source label
    ends in a subscript, so ``_network_source`` must cut the head at ``[``,
    or the canonical Flask destination shape never crosses the call boundary
    even though ``_match_source`` accepts ``startswith(src + "[")``."""
    findings = _taint(tmp_path, "fetcher.py", '''
        import urllib.request
        def request_json(url):
            request = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(request, timeout=30) as response:
                return response.read()
        def proxy(request):
            target = request.args["url"]
            return request_json(target)
    ''')
    assert "TAINT_SSRF" in _ids(findings)


def test_ssrf_partial_urlencode_does_not_approve_raw_contributor(tmp_path):
    """Control: one raw contributor vetoes the class for the whole value --
    ``f"{urlencode(a)} {b}"`` is not a purified destination."""
    findings = _taint(tmp_path, "mixed_payload.py", '''
        import urllib.parse, requests
        from flask import request
        def go():
            q = request.args["q"]
            raw = request.args["url"]
            return requests.get(f"{urllib.parse.urlencode({'q': q})} {raw}")
    ''')
    assert "TAINT_SSRF_EXPANDED" in _ids(findings)


# ---------------------------------------------------------------------------
# A10 -- a bare DB-API method name needs a DB-shaped receiver
# ---------------------------------------------------------------------------
def test_sql_function_executor_receiver_suppressed(tmp_path):
    """babyagi's ``g.functionz.executor.execute(function, **params)``."""
    findings = _taint(tmp_path, "agent.py", '''
        from flask import request
        def run(g):
            g.functionz.executor.execute(request.args["fn"])
    ''')
    assert "TAINT_SQL_INJECTION" not in _ids(findings)


def test_sql_dbapi_receiver_still_reported(tmp_path):
    """Control: the existing must-keep ``c.execute`` TP shape."""
    findings = _taint(tmp_path, "q.py", '''
        from flask import request
        def query(c):
            c.execute(request.args["q"])
    ''')
    assert "TAINT_SQL_INJECTION" in _ids(findings)


def test_sql_chained_receiver_still_reported(tmp_path):
    """Control: a call-chained receiver cannot be proven non-DB, so it keeps."""
    findings = _taint(tmp_path, "chain.py", '''
        from flask import request
        def query(get_db):
            get_db().execute(request.args["q"])
    ''')
    assert "TAINT_SQL_INJECTION" in _ids(findings)


def test_sql_session_receiver_still_reported(tmp_path):
    findings = _taint(tmp_path, "sess.py", '''
        from flask import request
        def query(session):
            session.execute(request.args["q"])
    ''')
    assert "TAINT_SQL_INJECTION" in _ids(findings)


# ---------------------------------------------------------------------------
# A11 -- GraphQL context and identifier boundaries
# ---------------------------------------------------------------------------
def test_graphql_schema_word_is_not_context(tmp_path):
    findings = _taint(tmp_path, "user_db.py", '''
        # schema module for the metadata store
        def reflect(record_id, user_db):
            user_db.metadata.reflect(user_db.engine)
    ''')
    assert "TAINT_GRAPHQL_RESOLVER_BOLA" not in _ids(findings)


def test_graphql_bola_identifier_boundaries_suppressed(tmp_path):
    """Real resolver context, but ``record_id:``/``user_db.`` are substrings."""
    findings = _taint(tmp_path, "resolver_user_db.py", '''
        def resolver(record_id: int, user_db):
            return user_db.find_one(record_id)
    ''')
    assert "TAINT_GRAPHQL_RESOLVER_BOLA" not in _ids(findings)


def test_graphql_bola_real_resolver_still_reported(tmp_path):
    """Control: a genuine resolver argument-to-database flow."""
    findings = _taint(tmp_path, "resolver.py", '''
        def resolver(id: int, db):
            return db.find_one(id)
    ''')
    assert "TAINT_GRAPHQL_RESOLVER_BOLA" in _ids(findings)


# ---------------------------------------------------------------------------
# A12 -- browser bundles are not server-side request forgery
# ---------------------------------------------------------------------------
def test_ssrf_static_bundle_is_client_side(tmp_path):
    findings = _taint(
        tmp_path,
        "dashboard/static/js/function_details.js",
        '''
            function run(getApiRoute, params) {
                return fetch(getApiRoute("executeFunction"), {method: "POST", body: JSON.stringify(params)});
            }
        ''',
    )
    assert "TAINT_SSRF_EXPANDED" not in _ids(findings)


def test_ssrf_server_route_fetch_still_reported(tmp_path):
    """Control: server-side Node keeps its finding."""
    findings = _taint(tmp_path, "src/routes/proxy.js", '''
        const handler = async (req, res) => {
            const target = req.query.url;
            return fetch(target);
        };
    ''')
    assert "TAINT_SSRF_EXPANDED" in _ids(findings)


# ---------------------------------------------------------------------------
# B1 -- one frame-taller-than-row table cell must not cost the whole PDF
#
# Open-Assistant (2026-10-16): the SBOM dependency table's Fixed In cell is
# ", ".join of every fixed version; `next` carries 60+ of them, a 656pt row
# in a 1.47cm column against the 665pt content frame.  Table.split()
# returns [] when the row-wise split cannot advance past a row taller than
# the frame, doctemplate turns that into reportlab's LayoutError, and the
# run ships NO Security_Report.pdf (the executive generator is nested in
# the same try, so it never runs either) -- pages 1-123 had rendered.
# splitInRow=1 is a fallback that only runs when the row-wise split
# already failed, i.e. exactly in the old LayoutError case.
# ---------------------------------------------------------------------------
def test_pdf_every_splitbyrow_table_declares_splitinrow():
    """Source pin: all 11 splitByRow=1 sites carry splitInRow=1."""
    import re as _re

    src = (pathlib.Path(__file__).resolve().parents[1]
           / "reporting" / "pdf_report.py").read_text(encoding="utf-8-sig")
    row_wise = _re.findall(r"splitByRow=1(?=[,)\r\n])", src)
    in_row = _re.findall(r"splitInRow=1(?=[,)\r\n])", src)
    assert len(row_wise) == 11, f"splitByRow sites drifted: {len(row_wise)}"
    assert len(in_row) == len(row_wise)


def test_pdf_giant_cell_row_splits_instead_of_dropping_report():
    """Functional: the Open-Assistant killer shape (header + frame-taller
    row first) returns [] without splitInRow -- the LayoutError path -- and
    splits in two with it.  Frame dims are the real 'content' frame of the
    'SBOM' page template (481.23 x 665.48pt)."""
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.platypus import Paragraph, Table

    cm = 28.3464566929
    cw = [w * cm for w in
          (3.10, 1.42, 0.95, 2.99, 1.71, 1.04, 1.46, 1.56, 1.70, 1.47)]
    st = ParagraphStyle("td", fontSize=8, leading=9.6)
    header = ["Package", "Ver", "Type", "CVE / Advisory", "CVSS",
              "EPSS", "Severity", "Age", "Reachable", "Fixed In"]
    # A cell whose wrap height exceeds the 665pt frame (narrow column,
    # no spaces to wrap on -- splitLongWords splits it per character).
    giant = [Paragraph("x" * 400, st) for _ in range(10)]
    small = ["--"] * 10
    rows = [header, giant, small, small]

    old = Table(rows, colWidths=cw, repeatRows=1, splitByRow=1, splitInRow=0)
    assert old.split(481.23, 665.48) == []  # the pre-B1 report-killing path

    fixed = Table(rows, colWidths=cw, repeatRows=1, splitByRow=1, splitInRow=1)
    assert len(fixed.split(481.23, 665.48)) >= 2

    # No behaviour change for tables that fit: still one piece.
    fitting = Table([header, small], colWidths=cw, repeatRows=1,
                    splitByRow=1, splitInRow=1)
    assert len(fitting.split(481.23, 665.48)) == 1


# ---------------------------------------------------------------------------
# B2 -- GraphQL introspection's boolean must be an enablement assignment
#
# peft (2026-10-16): the enterprise rule's sink was the bare token ``true``
# (case-insensitive), so any ``= True`` in the window of an ``introspection``
# mention fired -- generate_method_capabilities.py is a *static
# introspection* toolkit (``INTROSPECTION = "introspection"`` enum) whose
# neighbour was ``@dataclass(frozen=True)`` -> "GraphQL Introspection
# Enabled", High.  sast.py's static GRAPHQL_INTROSPECTION_ENABLED has always
# required the anchored shape (``introspection\s*:\s*true``); the boolean
# sink now does too.  The presence sinks (GraphQLPlayground / ApolloServer /
# GraphQLServer) are untouched.
# ---------------------------------------------------------------------------
def test_graphql_introspection_frozen_true_suppressed(tmp_path):
    findings = _taint(tmp_path, "generate_method_capabilities.py", '''
        INTROSPECTION = "introspection"

        @dataclass(frozen=True)
        class Finding:
            value: str
            source: str
    ''')
    assert "TAINT_GRAPHQL_INTROSPECTION_ENABLED" not in _ids(findings)


def test_graphql_introspection_enablement_bool_still_reported(tmp_path):
    """Control: the real enablement shapes keep firing."""
    findings = _taint(tmp_path, "server.js", '''
        const typeDefs = `type Query { ping: String }`;
        const server = new ApolloServer({ typeDefs, resolvers, introspection: true });
    ''')
    assert "TAINT_GRAPHQL_INTROSPECTION_ENABLED" in _ids(findings)


def test_graphql_introspection_python_config_bool_still_reported(tmp_path):
    """Control: ``= True`` behind an enablement noun in Python config."""
    findings = _taint(tmp_path, "app_config.py", '''
        app.config["GRAPHIQL"] = True
        schema = build_schema(type_defs)
    ''')
    assert "TAINT_GRAPHQL_INTROSPECTION_ENABLED" in _ids(findings)


# ---------------------------------------------------------------------------
# B3 -- a dotted ``.compile`` is not code injection
#
# peft (2026-10-16): ``model = torch.compile(model, dynamic=True)`` carried
# request-shaped taint and reported TAINT_CODE_INJECTION.  Every dotted
# compile host compiles something other than attacker source text: re.* a
# regex, torch.* a graph, py_compile files, XPath/Pattern/WebAssembly
# likewise.  The builtin ``compile(source, ...)`` -- the only compile that
# turns attacker text into bytecode -- is receiver-less and keeps firing.
# Receiver-form gate mirrors A1's eval treatment.
# ---------------------------------------------------------------------------
def test_taint_torch_compile_is_not_code_injection(tmp_path):
    findings = _taint(tmp_path, "train.py", '''
        model = request.args["model"]
        model = torch.compile(model, dynamic=True)
    ''')
    assert "TAINT_CODE_INJECTION" not in _ids(findings)


def test_taint_bare_compile_of_request_still_reported(tmp_path):
    """Control: the builtin compiles attacker text into bytecode."""
    findings = _taint(tmp_path, "runner.py", '''
        code = request.args["code"]
        compiled = compile(code, "<user>", "exec")
    ''')
    assert "TAINT_CODE_INJECTION" in _ids(findings)


def test_taint_re_compile_is_not_code_injection(tmp_path):
    findings = _taint(tmp_path, "parse.py", '''
        pattern = request.args["pattern"]
        rx = re.compile(pattern)
    ''')
    assert "TAINT_CODE_INJECTION" not in _ids(findings)


# ---------------------------------------------------------------------------
# B4 -- a bracketed integer array is not credential material
#
# peft (2026-10-16): adapter_config.json's ``token_indices: [128000, 128001]``
# (tokenizer vocabulary positions) reported CONFIG_CONTEXTUAL_CREDENTIAL:
# the KEY's "token" noun and a length >= 8 were enough, and
# _looks_like_secret_value never asked what the value WAS.  Structured
# numeric arrays are data; arrays carrying strings/objects are untouched.
# ---------------------------------------------------------------------------
def test_config_integer_array_is_not_a_credential(tmp_path):
    findings = _sec(tmp_path, "adapter_config.json", '''
        {
          "peft_type": "TRAINABLE_TOKENS",
          "token_indices": [128000, 128001],
          "task_type": "CAUSAL_LM"
        }
    ''')
    assert "CONFIG_CONTEXTUAL_CREDENTIAL" not in _ids(findings)


def test_config_token_key_with_string_value_still_reported(tmp_path):
    """Control: same key, a string that could be token material keeps."""
    findings = _sec(tmp_path, "adapter_config.json", '''
        {
          "token_indices": "128000128001deadbeef"
        }
    ''')
    assert "CONFIG_CONTEXTUAL_CREDENTIAL" in _ids(findings)


# ---------------------------------------------------------------------------
# B5 -- session.exec is DB query execution, not Python code execution
#
# Open-Assistant (2026-10-16): 18 rows of TAINT_CODE_INJECTION on
# ``message = (await self.session.exec(query)).one()`` -- SQLModel's
# Session.exec runs a SELECT built through the query-builder API.  The bare
# ``exec`` sink key matched any dotted receiver, the same receiver-form
# defect family as A10 (SQL ``execute``), B3 (``torch.compile``) and A1
# (eval).  Python's builtin ``exec(...)`` is receiver-less and keeps firing.
# ---------------------------------------------------------------------------
def test_taint_session_exec_is_not_code_injection(tmp_path):
    findings = _taint(tmp_path, "chat_repository.py", """
        async def get_messages(self, session, user_id: int):
            query = sqlmodel.select(ChatMessage).where(ChatMessage.user_id == user_id)
            message = (await session.exec(query)).one()
            return message
    """)
    assert "TAINT_CODE_INJECTION" not in _ids(findings)


def test_taint_self_session_exec_is_not_code_injection(tmp_path):
    findings = _taint(tmp_path, "repository.py", """
        class Repo:
            async def run(self, user_id: int):
                query = select(models.Row).where(models.Row.uid == user_id)
                return (await self.session.exec(query)).all()
    """)
    assert "TAINT_CODE_INJECTION" not in _ids(findings)


def test_taint_bare_exec_of_request_still_reported(tmp_path):
    """Control: the builtin executes attacker statements."""
    findings = _taint(tmp_path, "runner.py", """
        code = request.args["code"]
        exec(code)
    """)
    assert "TAINT_CODE_INJECTION" in _ids(findings)


# ---------------------------------------------------------------------------
# B6 -- LLM02's exec evidence must not count a DB session query
#
# Same OA lines fired LLM02_INSECURE_OUTPUT_HANDLING because LLM_EXEC_ANY_RE
# treats any "exec(" as dynamic execution.  child_process's cp.exec(cmd) and
# the Python builtin stay (the A1-era comment names them); only the
# session receiver -- query execution, not eval of LLM output -- is excluded.
# ---------------------------------------------------------------------------
def test_llm02_session_exec_suppressed(tmp_path):
    findings = _llm(tmp_path, "chat_repository.py", """
        message = (await self.session.exec(query)).one()
        return message
    """)
    assert "LLM02_INSECURE_OUTPUT_HANDLING" not in _ids(findings)


def test_llm02_child_process_exec_still_reported_control(tmp_path):
    """Control: Node's child_process.exec really executes a shell command."""
    findings = _llm(tmp_path, "handler.js", """
        const cp = require("child_process");
        cp.exec(userInput, callback);
    """)
    assert "LLM02_INSECURE_OUTPUT_HANDLING" in _ids(findings)


# ---------------------------------------------------------------------------
# B7 -- a credential noun must not match as the prefix of a longer word
#
# Open-Assistant: ``tokenizer_type: "SentencePieceTokenizer"`` (pretokenize
# config) reported CONFIG_CONTEXTUAL_CREDENTIAL because "token" matched
# inside "tokenizer"; and ``if args.tokenizer_type == "FalconTokenizer"``
# (x5) reported HARDCODED_CREDENTIAL_COMPARISON because the comparison
# pattern let the noun ride an arbitrary [\w]* suffix.  The same defect in
# the comparison pattern was masking a genuine detection failure: nouns
# behind ``_`` (``access_token``, ``user_password``) never matched because
# ``\b`` cannot fire between two word characters.  Both are fixed together:
# the suffix must now start with ``_``/``-``/digit, and the prefix boundary
# is "not alphanumeric" instead of ``\b``.
# ---------------------------------------------------------------------------
def test_config_tokenizer_type_is_not_a_credential(tmp_path):
    findings = _sec(tmp_path, "pretokenize.yaml", """
        model:
          tokenizer_type: "SentencePieceTokenizer"
    """)
    assert "CONFIG_CONTEXTUAL_CREDENTIAL" not in _ids(findings)


def test_config_access_token_value_still_reported(tmp_path):
    """Control: a token-named key with material keeps firing."""
    findings = _sec(tmp_path, "service.yaml", """
        auth:
          access_token: Abcdefghijklmnop123456
    """)
    assert "CONFIG_CONTEXTUAL_CREDENTIAL" in _ids(findings)


def test_sast_tokenizer_type_comparison_suppressed(tmp_path):
    findings = _sast(tmp_path, "tokenizer.py", """
        def build(args):
            if args.tokenizer_type == "FalconTokenizer":
                return FalconTokenizer()
    """)
    assert "HARDCODED_CREDENTIAL_COMPARISON" not in _ids(findings)


def test_sast_password_comparison_still_reported(tmp_path):
    """Control: the canonical auth-bypass shape keeps its Critical."""
    findings = _sast(tmp_path, "auth.py", """
        def check(user):
            if user.password == "hunter2secret":
                return True
    """)
    assert "HARDCODED_CREDENTIAL_COMPARISON" in _ids(findings)


def test_sast_access_token_comparison_now_reported(tmp_path):
    r"""FN fix control: ``access_token == "literal"`` is the canonical
    credential-comparison shape and could never match behind ``\b``."""
    findings = _sast(tmp_path, "auth.py", """
        def check(session):
            if session.access_token == "tok_live_9f3c1d7a":
                return True
    """)
    assert "HARDCODED_CREDENTIAL_COMPARISON" in _ids(findings)


def test_sast_user_password_comparison_now_reported(tmp_path):
    """FN fix control: ``user_password == "literal"`` likewise."""
    findings = _sast(tmp_path, "auth.py", """
        def check(user):
            if user_password == "hunter2secret":
                return True
    """)
    assert "HARDCODED_CREDENTIAL_COMPARISON" in _ids(findings)


# ---------------------------------------------------------------------------
# B8 -- template/interpolation references are not secret material
#
# Open-Assistant: 11 of 17 CONFIG_CONTEXTUAL rows were reference-shaped
# values the value gates never questioned -- Jinja2 ``{{ postgres_password }}``
# (ansible x7), a secrets-manager PATH carrying ``${...}`` interpolations
# (CF manifests x3), and a GitHub Actions ``${{secrets.X}}`` with a trailing
# line-continuation backslash (workflow x1).  Interpolation means the
# deployed value is assembled at template time; literal material never
# contains ``${...}`` or is itself a pure template expression.  Hardcoded
# literals (``POSTGRES_PASSWORD: postgres``) keep firing.
# ---------------------------------------------------------------------------
def test_config_jinja_reference_suppressed(tmp_path):
    findings = _sec(tmp_path, "deploy-to-node.yaml", """
        environment:
          POSTGRES_PASSWORD: "{{ postgres_password }}"
          OFFICIAL_WEB_API_KEY: "{{ web_api_key }}"
    """)
    assert "CONFIG_CONTEXTUAL_CREDENTIAL" not in _ids(findings)


def test_config_secrets_path_with_interpolation_suppressed(tmp_path):
    findings = _sec(tmp_path, "manifest.yml", """
        env:
          EMAIL_SERVER_PASSWORD: /copilot/${COPILOT_APPLICATION_NAME}/secrets/EMAIL_SERVER_PASSWORD
          NEXTAUTH_SECRET: /copilot/${COPILOT_APPLICATION_NAME}/secrets/NEXTAUTH_SECRET
    """)
    assert "CONFIG_CONTEXTUAL_CREDENTIAL" not in _ids(findings)


def test_config_gh_expression_with_continuation_suppressed(tmp_path):
    findings = _sec(tmp_path, "deploy-to-node.yaml", """
        run: |
          postgres_password=${{secrets.POSTGRES_PASSWORD}} \
          createdb oasst
    """)
    assert "CONFIG_CONTEXTUAL_CREDENTIAL" not in _ids(findings)


def test_config_hardcoded_compose_password_still_reported(tmp_path):
    """Control: the genuine hardcoded default credential keeps firing."""
    findings = _sec(tmp_path, "docker-compose.yaml", """
        services:
          db:
            environment:
              POSTGRES_PASSWORD: postgres
    """)
    assert "CONFIG_CONTEXTUAL_CREDENTIAL" in _ids(findings)


# ---------------------------------------------------------------------------
# C1 -- EVAL_CALL must not fire inside JSON data files
#
# llama_index (2026-10-16): 2 EVAL_CALL rows matched ``eval(`` inside the
# ``"content"`` string of a Discord chat-log JSON dump (line 74901 of each
# file) -- a user quoting a Python traceback.  JSON is a data format: it is
# never executed as code, and nearly every character of a JSON file sits
# inside a string value, so string-context helpers for code languages cannot
# apply.  Code-execution rules are gated to executable languages already
# (PYTHON_EXEC_CALL: {python}); EVAL_CALL, which spans JS/PHP/Python eval,
# had no gate.  Secrets/config rules must keep firing on JSON -- only
# code-injection classification is gated.
# ---------------------------------------------------------------------------
def test_eval_call_json_chat_log_suppressed(tmp_path):
    findings = _sast(tmp_path, "help_channel_dump.json", """
        {
          "content": "Traceback: File \\"x.py\\", line 2, in <module> eval(payload)",
          "author": {"name": "user"}
        }
    """)
    assert "EVAL_CALL" not in _ids(findings)


def test_eval_call_json_config_snippet_suppressed(tmp_path):
    findings = _sast(tmp_path, "config.json", """
        {"example": "call eval(user_input) to evaluate"}
    """)
    assert "EVAL_CALL" not in _ids(findings)


def test_eval_call_js_bare_still_reported_control(tmp_path):
    """Control: bare eval in real executable code keeps its Critical."""
    findings = _sast(tmp_path, "server.js", """
        function run(input) {
            return eval(input);
        }
    """)
    assert "EVAL_CALL" in _ids(findings)


def test_secret_engine_json_config_still_reported_control(tmp_path):
    """Control: the JSON gate is sast code-injection-only; the secret engine
    keeps classifying credentials in JSON config."""
    findings = _sec(tmp_path, "settings.json", """
        {"db_password": "SuperSecretPw123!"}
    """)
    assert "CONFIG_CONTEXTUAL_CREDENTIAL" in _ids(findings)


def test_sast_json_command_injection_still_reported_control(tmp_path):
    """Control: within sast, non-code_injection rules keep firing on JSON --
    only the code-execution classification requires executable context."""
    findings = _sast(tmp_path, "snippet.json", """
        {"code": "os.system(cmd)"}
    """)
    assert "OS_SYSTEM" in _ids(findings)


# ---------------------------------------------------------------------------
# C2 -- LLM02's fixed-argv exemption must survive a line break
#
# llama_index (2026-10-16): scripts/convert-examples.py:58 fired LLM02 on
# ``repo_root = subprocess.run(`` followed by ``    ["git", "rev-parse",
# "--show-toplevel"],`` -- a fixed argv list that no model output can steer.
# The exemption regex required the bracket on the same line as the call, so
# the common multi-line formatting escaped it.
# ---------------------------------------------------------------------------
def test_llm02_multiline_fixed_argv_suppressed(tmp_path):
    findings = _llm(tmp_path, "convert_examples.py", """
        def changed(root):
            repo_root = subprocess.run(
                ["git", "rev-parse", "--show-toplevel"],
                capture_output=True,
                text=True,
            )
            return repo_root.stdout
    """)
    assert "LLM02_INSECURE_OUTPUT_HANDLING" not in _ids(findings)


def test_llm02_dynamic_argv_still_reported_control(tmp_path):
    """Control: a run whose command comes from a variable keeps the finding
    (no fixed bracket literal on the call or the next line)."""
    findings = _llm(tmp_path, "handler.py", """
        def run(cmd):
            subprocess.run(cmd, shell=True)
    """)
    assert "LLM02_INSECURE_OUTPUT_HANDLING" in _ids(findings)


# ---------------------------------------------------------------------------
# C3 -- query-builder provenance must survive Name-receiver chaining
#
# llama_index (2026-10-16): 3 TAINT_SQL_INJECTION rows on
# llama-index-core/.../storage/chat_store/sql.py -- ``query =
# select(table).where(...)`` (a parameterized SQLAlchemy builder product,
# recorded) followed by ``query = query.limit(limit)`` /
# ``query = query.where(table.c.status == status.value)``.  The chain
# receiver is a local Name, not the sqlalchemy module alias, so
# _is_query_builder_rhs returned False and POPPED the proven record; the
# sink then saw a tainted ``query`` with no provenance and fired.  A chain
# whose receiver is already a recorded builder product in the same function
# (earlier line) extends that provenance -- the same proof the sink-side
# Name check already trusts.
# ---------------------------------------------------------------------------
def test_taint_sqlalchemy_builder_chain_preserved(tmp_path):
    findings = _taint(tmp_path, "chat_store.py", """
        from sqlalchemy import select

        async def get(key, limit, session_factory, table):
            query = select(table).where(table.c.key == key)
            query = query.limit(limit)
            async with session_factory() as session:
                await session.execute(query)
    """)
    assert "TAINT_SQL_INJECTION" not in _ids(findings)


def test_taint_sqlalchemy_builder_where_chain_preserved(tmp_path):
    findings = _taint(tmp_path, "chat_store.py", """
        from sqlalchemy import select

        async def get(key, status, session_factory, table):
            query = select(table).where(table.c.key == key)
            query = query.where(table.c.status == status)
            async with session_factory() as session:
                await session.execute(query)
    """)
    assert "TAINT_SQL_INJECTION" not in _ids(findings)


def test_taint_builder_chain_reassigned_from_source_still_reported_control(tmp_path):
    """Control: an untainted-builder chain that is later overwritten by raw
    request text must still fire -- the record dies on the reassignment."""
    findings = _taint(tmp_path, "endpoint.py", """
        from sqlalchemy import select

        def run(request, table):
            query = select(table).where(table.c.id == 1)
            query = request.args["q"]
            session.execute(query)
    """)
    assert "TAINT_SQL_INJECTION" in _ids(findings)


# ---------------------------------------------------------------------------
# D1 -- LLM02's fixed-argv exemption must cover subprocess.Popen /
#       check_output / call AND the matched line sitting inside the call's
#       argument list
#
# diffusers (2026-10-17): src/diffusers/commands/env.py:124 fired LLM02 on
# ``stdout=subprocess.PIPE,`` inside ``sp = subprocess.Popen(["nvidia-smi",
# ...], stdout=PIPE, stderr=PIPE)``.  The rule pattern ``subprocess\.``
# matches every line carrying the module name, LLM_EXEC_ANY_RE sees the same
# bare ``subprocess.`` (so A1's dynamic-eval gate keeps the row), and C2's
# exemption only consulted the MATCHED line for the literal ``subprocess.run``
# spelling.  Fixed literal argv + captured output: no model-derived value can
# steer which program runs, and nothing executes the captured output.
# ---------------------------------------------------------------------------
def test_llm02_popen_fixed_argv_in_arglist_suppressed(tmp_path):
    """The real env.py shape: call opener, literal argv, then stdout=PIPE
    lines -- all three matching lines must be exempt."""
    findings = _llm(tmp_path, "env.py", """
        def gpu_info():
            sp = subprocess.Popen(
                ["nvidia-smi", "--query-gpu=gpu_name", "--format=csv,noheader"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            out, _ = sp.communicate()
            return out.decode("utf-8")
    """)
    assert "LLM02_INSECURE_OUTPUT_HANDLING" not in _ids(findings)


def test_llm02_inline_fixed_argv_other_call_suppressed(tmp_path):
    """Same-line literal argv on check_output (previously only run() was
    exempt)."""
    findings = _llm(tmp_path, "env2.py", """
        def gpu_info():
            out = subprocess.check_output(["nvidia-smi", "-L"], text=True)
            return out
    """)
    assert "LLM02_INSECURE_OUTPUT_HANDLING" not in _ids(findings)


def test_llm02_popen_dynamic_argv_still_reported_control(tmp_path):
    """Control: Popen whose argv comes from a variable keeps the finding --
    the exemption is the literal list, not the call name."""
    findings = _llm(tmp_path, "handler.py", """
        def spawn(cmd):
            sp = subprocess.Popen(cmd, stdout=subprocess.PIPE)
            return sp
    """)
    assert "LLM02_INSECURE_OUTPUT_HANDLING" in _ids(findings)


def test_llm02_earlier_fixed_argv_does_not_exempt_later_dynamic_call_control(tmp_path):
    """Control: the backward window inspects only the NEAREST preceding
    subprocess call, so an earlier fixed-argv run cannot bless a later
    dynamic Popen in the same function."""
    findings = _llm(tmp_path, "mixed.py", """
        def probe(cmd):
            subprocess.run(["ls"], check=True)
            sp = subprocess.Popen(cmd, stdout=subprocess.PIPE)
            return sp
    """)
    assert "LLM02_INSECURE_OUTPUT_HANDLING" in _ids(findings)


def test_llm02_shell_string_argv_still_reported_control(tmp_path):
    """Control: shell=True with a string argv is a real sink and keeps."""
    findings = _llm(tmp_path, "shellstr.py", """
        def run(cmd):
            subprocess.run(cmd, shell=True)
    """)
    assert "LLM02_INSECURE_OUTPUT_HANDLING" in _ids(findings)


# ---------------------------------------------------------------------------
# D2 -- PROMPT_TEMPLATE_SECRET_EXPOSURE: the ``template.*token`` window must
#       see a CREDENTIAL token, not the tokenization vocabulary
#
# diffusers (2026-10-17): 3 Low rows, all from ``template.*token``:
#   * apply_chat_template(messages, tokenize=False, ...) x2 -- the HF
#     chat-template API + its tokenize= keyword (function name, no secret);
#   * _PROMPT_TEMPLATE_ENCODE_NUM_SUFFIX_TOKENS = 5 -- a token COUNT
#     constant matched inside the identifier.
# The rule claims prompt-template SECRET exposure (Critical before
# normalisation); none of the three embeds credential material.  Same
# vocabulary boundary B7a applied to the secrets layer: token must not be
# followed by a letter.  ``template.*api_key/secret/password`` untouched.
# ---------------------------------------------------------------------------
def test_prompt_template_chat_template_tokenize_suppressed(tmp_path):
    findings = _llm(tmp_path, "chat.py", """
        class P:
            def enc(self, messages):
                return self.processor.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
    """)
    assert "PROMPT_TEMPLATE_SECRET_EXPOSURE" not in _ids(findings)


def test_prompt_template_token_count_constant_suppressed(tmp_path):
    findings = _llm(tmp_path, "count.py", """
        _PROMPT_TEMPLATE_ENCODE_NUM_SUFFIX_TOKENS = 5
    """)
    assert "PROMPT_TEMPLATE_SECRET_EXPOSURE" not in _ids(findings)


def test_prompt_template_real_token_literal_still_reported_control(tmp_path):
    """Control: a template that actually embeds a token value keeps -- the
    token is followed by ``}``/punctuation, not a letter."""
    findings = _llm(tmp_path, "keep_token.py", """
        prompt_template = "Hello, your access token: {token}"
    """)
    assert "PROMPT_TEMPLATE_SECRET_EXPOSURE" in _ids(findings)


def test_prompt_template_password_pattern_unaffected_control(tmp_path):
    """Control: the other template.* patterns are untouched by D2."""
    findings = _llm(tmp_path, "keep_password.py", """
        system_template = f"login with password {pw}"
    """)
    assert "PROMPT_TEMPLATE_SECRET_EXPOSURE" in _ids(findings)
