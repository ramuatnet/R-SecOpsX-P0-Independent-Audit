# -*- coding: utf-8 -*-
r"""semantic-kernel-main + autogen-main validation (2026-10-15): the FP families
found on the two large corpora, plus the AgentGPT families as stability.

The consultant validation traced ~92% of semantic-kernel's 1961 code findings
and ~87% of autogen's 412 to permissive gates that no small corpus exposed:

  1. DOTNET_HARDCODED_CREDENTIAL matched ANY C# string literal of 8+ chars
     (``var model = "meta-llama-3-8b-instruct"``) -- 1526 rows, no gate.
  2. GENERIC placeholder family missed test/your/overwrite/sk-/REPLACE_WITH/
     camelCase stems and hyphen decorations (``api_key = "test-key"``).
  3. CONFIG structural keys matched credential nouns on ANCESTOR segments
     (``...tokens[0].logprob``, ``inputs.fallback-token.description``), kept
     YAML inline comments in values, and missed bare ``${VAR}`` env refs
     behind comments.
  4. GENERIC_HIGH_ENTROPY fired on any 24+ char identifier regardless of key.
  5. OAUTH/SOURCE accepted dotted config refs, constructor-call RHS, bare
     identifiers (code), SecretStr type annotations and OTel attribute names.
  6. JWT_SIGNING_SECRET's ``\s*`` crossed newlines: ``if not jwt_secret:``
     swallowed the next line's token as "the secret".
  7. GITHUB_TOKEN matched redaction masks (``ghp_XXXX...``).
  8. CLOUD_METADATA_TOKEN_USE punished SSRF-defense test fixtures.
  9. WORKFLOW_APPROVAL_BYPASS fired on test mocks, secure defaults
     (``auto_approve: bool = False``) and identifier passthroughs.
 10. TAINT_SQL_INJECTION missed DB-API parameterized sinks that do not import
     sqlalchemy (psycopg ``sql.SQL(...)`` + 2-arg execute, executemany binds,
     ``to_execute()`` command objects).
 11. TAINT_NOSQL_INJECTION fired on ``{"$in": values}`` data operands.
 12. LLM rules fired on comments, docstrings, await-loops, help text,
     argv-list subprocess calls and ORM ``session.exec(select(...))``.
 13. Licence category froze pre-policy (``Permissive`` on copyleft rows).
 14. SBOM ignored pyproject.toml / uv.lock / NuGet manifests entirely.
 15. Docker findings carried a doubled project prefix in their path.

Every test states both sides of the kill-only-on-proof contract: the false
shape must be gone, and a real secret at the same location must survive.
"""
from __future__ import annotations

import json
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


def _sec(tmp_path, name: str, source: str) -> list[dict]:
    from scanner.secret_intelligence import scan_file

    return scan_file(str(_write(tmp_path, name, source)))


def _sast(tmp_path, name: str, source: str) -> list[dict]:
    from scanner.sast import scan_file

    return scan_file(str(_write(tmp_path, name, source)))


def _taint(tmp_path, name: str, source: str) -> list[dict]:
    from scanner.taint_engine import analyze_file

    return analyze_file(str(_write(tmp_path, name, source)))


def _ids(findings: list[dict]) -> set[str]:
    return {str(f.get("rule_id") or f.get("id")) for f in findings}


# ---------------------------------------------------------------------------
# 1 -- DOTNET: the declaration's IDENTIFIER must name a credential
# ---------------------------------------------------------------------------
def test_dotnet_model_and_prompt_literals_are_not_credentials(tmp_path):
    """The exact ungated shapes that produced 1327 SK + 199 autogen rows."""
    findings = _sast(tmp_path, "models.cs", '''
        var model = "meta-llama-3-8b-instruct";
        string prompt = "Hello, world!";
        var deployName = "Mistral-small";
        private const string CollectionId = "fake-collection-id";
        var endpointUrl = "https://contoso.openai.azure.com/";
    ''')
    assert "DOTNET_HARDCODED_CREDENTIAL" not in _ids(findings)


def test_dotnet_credential_identifier_still_reported(tmp_path):
    """Control: credential-named declarations keep their finding."""
    findings = _sast(tmp_path, "creds.cs", '''
        string password = "Sup3rSecretValue!42";
        var apiKey = "live-Ab3DeF5HiJ7KlM9";
        const string clientSecret = "oauth-Client-Secret-99x";
    ''')
    assert "DOTNET_HARDCODED_CREDENTIAL" in _ids(findings)


def test_dotnet_name_values_are_not_credentials(tmp_path):
    """The C# twins of the OTel constants: dotted attribute names and
    SCREAMING_SNAKE env-var NAMES at credential-named declarations are
    references, not material (ModelDiagnostics.cs / utils.py)."""
    findings = _sast(tmp_path, "telemetry.cs", '''
        public const string MaxToken = "gen_ai.request.max_tokens";
        public const string InputTokens = "gen_ai.usage.input_tokens";
        string apiKeyName = "AZURE_COGNITIVE_SEARCH_ADMIN_KEY";
    ''')
    assert "DOTNET_HARDCODED_CREDENTIAL" not in _ids(findings)


def test_generic_env_var_name_value_suppressed(tmp_path):
    """``ENV_VAR_API_KEY = "AZURE_COGNITIVE_SEARCH_ADMIN_KEY"`` -- the value
    names an environment variable; a NAME is not material."""
    findings = _sast(tmp_path, "env_names.py", '''
        ENV_VAR_API_KEY = "AZURE_COGNITIVE_SEARCH_ADMIN_KEY"
    ''')
    assert "GENERIC_API_KEY_PASSWORD" not in _ids(findings)


def test_single_token_caps_secret_still_reported(tmp_path):
    """Control: caps WITHOUT word breaks is material-shaped, not a name."""
    findings = _sast(tmp_path, "caps.py", '''
        api_key = "SUP3RSECRET123"
    ''')
    assert "GENERIC_API_KEY_PASSWORD" in _ids(findings)


# ---------------------------------------------------------------------------
# 2 -- GENERIC placeholder family: stems, decorations, sk-, camelCase
# ---------------------------------------------------------------------------
def test_placeholder_stems_and_decorations_suppressed(tmp_path):
    findings = _sast(tmp_path, "fixtures.py", '''
        api_key = "fake-api-key"
        api_key = "test-key"
        api_key = "test_api_key"
        api_key = "your-api-key"
        api_key = "overwrite-api-key"
        api_key = "sk-password"
        api_key = "unittest_token"
    ''')
    assert "GENERIC_API_KEY_PASSWORD" not in _ids(findings)


def test_camelcase_test_placeholder_suppressed(tmp_path):
    """CopilotStudioTests.cs shape: ``= "testAppClientSecret"``."""
    findings = _sast(tmp_path, "copilot.cs", '''
        string appClientSecret = "testAppClientSecret";
        string mockToken = "MockApiKey123456";
    ''')
    assert "GENERIC_API_KEY_PASSWORD" not in _ids(findings)


def test_real_literals_at_same_keys_still_reported(tmp_path):
    """Control: the AgentGPT gate-repro sentinels must survive the extension."""
    findings = _sast(tmp_path, "real_keys.py", '''
        api_key = "realvalue123456"
        some_key = "some_key_prod_9x2"
        api_key = "Abcdefghijklmnop123456"
    ''')
    assert "GENERIC_API_KEY_PASSWORD" in _ids(findings)


def test_replace_with_sentinel_suppressed_in_config(tmp_path):
    """autogen ships ``REPLACE_WITH_YOUR_API_KEY`` in every sample yaml."""
    findings = _sec(tmp_path, "model_config.yaml", '''
        openai_config:
          api_key: REPLACE_WITH_YOUR_API_KEY
          api_key2: your-api-key
    ''')
    assert "CONFIG_CONTEXTUAL_CREDENTIAL" not in _ids(findings)


# ---------------------------------------------------------------------------
# 3 -- CONFIG structural keys: leaf matching, comments, env defaults
# ---------------------------------------------------------------------------
def test_composite_documentation_keys_suppressed(tmp_path):
    """``tokens[0].logprob`` (HF fixture) and ``*-token.description``
    (action docs) fire only because an ANCESTOR says token/secret."""
    findings = _sec(tmp_path, "fixture.json", json.dumps({
        "outputs": {"token": {"description": "The output token description here"}},
        "inputs": {"fallback-token": {"description": "Docs text for the fallback token"}},
    }, indent=2))
    assert "CONFIG_CONTEXTUAL_CREDENTIAL" not in _ids(findings)


def test_yaml_inline_comment_is_not_secret_material(tmp_path):
    """``tokens_per_minute: auto # set to null ...`` -- the note made every
    short value an 8+ character "secret"."""
    findings = _sec(tmp_path, "autogen.yaml", '''
        tokens_per_minute: auto # set to null to disable rate limiting
    ''')
    assert "CONFIG_CONTEXTUAL_CREDENTIAL" not in _ids(findings)


def test_env_reference_with_trailing_comment_suppressed(tmp_path):
    """``api_key: ${GRAPHRAG_API_KEY} # set this in the generated .env``."""
    findings = _sec(tmp_path, "settings.yaml", '''
        graphrag:
          api_key: ${GRAPHRAG_API_KEY} # set this in the generated .env file
    ''')
    assert "CONFIG_CONTEXTUAL_CREDENTIAL" not in _ids(findings)


def test_credential_leaf_with_real_value_still_reported(tmp_path):
    """Control: nested configs whose LEAF names the credential keep firing --
    the ancestor-scoping trade-off must not kill the real shape."""
    findings = _sec(tmp_path, "app_settings.yaml", '''
        openai:
          api_key: Abcdefghijklmnop123456
    ''')
    assert "CONFIG_CONTEXTUAL_CREDENTIAL" in _ids(findings)


def test_credential_leaf_with_comment_still_reported(tmp_path):
    """Control: comments attach prose, not value material -- the literal
    before the comment still reports."""
    findings = _sec(tmp_path, "prod.yaml", '''
        service:
          api_key: Abcdefghijklmnop123456 # production credential
    ''')
    assert "CONFIG_CONTEXTUAL_CREDENTIAL" in _ids(findings)


def test_composite_key_leaf_matching_helpers():
    """White-box: the leaf rules for the exact SK structural keys."""
    from scanner.secret_intelligence import _key_names_credential

    assert not _key_names_credential(
        "[0].details.tokens[0].logprob")
    assert not _key_names_credential(
        "paths./secrets/{secret-name}.get.parameters.*.description")
    assert not _key_names_credential(
        "inputs.fallback-token.description")
    assert not _key_names_credential(
        "jobs.build-and-test-docker.steps.run.docker run --rm -v $(pwd)")
    # credential-named leaves keep matching (flat or composite)
    assert _key_names_credential("api_key")
    assert _key_names_credential("openai.api_key")
    assert _key_names_credential("azure.credentials.client_secret")


# ---------------------------------------------------------------------------
# 4 -- Entropy: every charset class requires a credential-bearing key
# ---------------------------------------------------------------------------
def test_entropy_requires_credential_key_context(tmp_path):
    findings = _sec(tmp_path, "identifier.py", '''
        component = "aB3xY9kQ2mN7pR5sT8vW1zC6dL4fG0h"
    ''')
    assert "GENERIC_HIGH_ENTROPY_SECRET" not in _ids(findings)


def test_entropy_at_credential_key_still_reported(tmp_path):
    """Control: the same value at ``api_key`` keeps its finding."""
    findings = _sec(tmp_path, "entropy_key.py", '''
        api_key = "aB3xY9kQ2mN7pR5sT8vW1zC6dL4fG0h"
    ''')
    assert "GENERIC_HIGH_ENTROPY_SECRET" in _ids(findings)


# ---------------------------------------------------------------------------
# 5 -- Reference guards: dotted chains, calls, code identifiers, SecretStr
# ---------------------------------------------------------------------------
def test_config_object_references_suppressed(tmp_path):
    findings = _sec(tmp_path, "wiring.py", '''
        client_secret = booking_sample_settings.client_secret
        client_secret = app_client_secret
        client_secret = weaviate_auth.AuthApiKey(api_key=api_key)
        client_secret: SecretStr
    ''')
    assert "OAUTH_CLIENT_SECRET" not in _ids(findings)


def test_telemetry_attribute_names_are_not_credentials(tmp_path):
    """OTel constants: ``MAX_TOKENS = "gen_ai.request.max_tokens"``."""
    findings = _sec(tmp_path, "telemetry.py", '''
        MAX_TOKENS = "gen_ai.request.max_tokens"
        SPAN_NAME = "gen_ai.content_generation"
    ''')
    assert "SOURCE_HARDCODED_CREDENTIAL" not in _ids(findings)


def test_source_env_var_name_value_suppressed(tmp_path):
    """The SOURCE engine must agree with the sast GENERIC gate on SK
    utils.py:39 -- ``ENV_VAR_API_KEY = "AZURE_COGNITIVE_SEARCH_ADMIN_KEY"``
    names a variable. (Cross-engine duplicate collapsing hid this copy while
    the GENERIC twin fired, so both gates are needed.)"""
    findings = _sec(tmp_path, "utils.py", '''
        ENV_VAR_API_KEY = "AZURE_COGNITIVE_SEARCH_ADMIN_KEY"
    ''')
    assert "SOURCE_HARDCODED_CREDENTIAL" not in _ids(findings)


def test_quoted_real_secret_at_credential_key_still_reported(tmp_path):
    """Control: quoted literals at credential keys are unaffected by every
    reference guard."""
    findings = _sec(tmp_path, "real_oauth.py", '''
        client_secret = "abcdefghijklmnop123456"
    ''')
    assert "OAUTH_CLIENT_SECRET" in _ids(findings)


# ---------------------------------------------------------------------------
# 6 -- JWT: a line-final colon is a guard, not an assignment
# ---------------------------------------------------------------------------
def test_jwt_presence_guard_is_not_a_hardcoded_secret(tmp_path):
    findings = _sec(tmp_path, "wsauth.py", '''
        def check(config):
            if not config.jwt_secret:
                raise RuntimeError("jwt secret missing")
    ''')
    assert "JWT_SIGNING_SECRET" not in _ids(findings)


def test_jwt_same_line_literal_still_reported(tmp_path):
    findings = _sec(tmp_path, "jwt_cfg.yml", '''
        jwt_secret: "abcdefghijklmnop123456"
    ''')
    assert "JWT_SIGNING_SECRET" in _ids(findings)


# ---------------------------------------------------------------------------
# 7 -- GitHub token redaction masks
# ---------------------------------------------------------------------------
def test_github_token_redaction_mask_suppressed(tmp_path):
    findings = _sec(tmp_path, ".github/workflows/ci.yml", '''
        steps:
          - uses: actions/checkout@v4
            with:
              token: ghp_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
    ''')
    assert "GITHUB_TOKEN" not in _ids(findings)


def test_real_github_token_still_reported(tmp_path):
    findings = _sec(tmp_path, ".github/workflows/release.yml", '''
        steps:
          - uses: actions/checkout@v4
            with:
              token: ghp_Ab3DeF5HiJ7KlM9NoP0QrS5TuV8Wx
    ''')
    assert "GITHUB_TOKEN" in _ids(findings)


# ---------------------------------------------------------------------------
# 8 -- Cloud metadata in SSRF-defense tests
# ---------------------------------------------------------------------------
def test_metadata_ip_in_test_fixture_suppressed(tmp_path):
    """The 10 SK rows were dns-pinning tests that VERIFY the block."""
    findings = _sec(tmp_path, "tests/test_server_url_validator.py", '''
        def test_metadata_blocked():
            resp = requests.get("http://169.254.169.254/latest/meta-data/")
            assert resp.blocked
    ''')
    assert "CLOUD_METADATA_TOKEN_USE" not in _ids(findings)


def test_metadata_ip_in_production_code_still_reported(tmp_path):
    findings = _sec(tmp_path, "app/metadata.py", '''
        def fetch_metadata():
            return requests.get("http://169.254.169.254/latest/meta-data/")
    ''')
    assert "CLOUD_METADATA_TOKEN_USE" in _ids(findings)


# ---------------------------------------------------------------------------
# 9 -- Workflow approval bypass: tests, secure defaults, passthroughs
# ---------------------------------------------------------------------------
def test_workflow_bypass_test_mocks_suppressed(tmp_path):
    findings = _sast(tmp_path, "tests/test_sampling_approval.py", '''
        response = ApprovalResponse(approved=True)
    ''')
    assert "WORKFLOW_APPROVAL_BYPASS" not in _ids(findings)


def test_workflow_bypass_secure_default_suppressed(tmp_path):
    findings = _sast(tmp_path, "app/sampling.py", '''
        sampling_auto_approve: bool = False
    ''')
    assert "WORKFLOW_APPROVAL_BYPASS" not in _ids(findings)


def test_workflow_bypass_identifier_passthrough_suppressed(tmp_path):
    findings = _sast(tmp_path, "app/wiring.py", '''
        self.sampling_auto_approve = sampling_auto_approve
    ''')
    assert "WORKFLOW_APPROVAL_BYPASS" not in _ids(findings)


def test_workflow_bypass_disabled_approval_still_reported(tmp_path):
    """Control: ``approval_required = false`` IS the bypass."""
    findings = _sast(tmp_path, "app/handlers.py", '''
        approval_required = false
    ''')
    assert "WORKFLOW_APPROVAL_BYPASS" in _ids(findings)


def test_workflow_bypass_enabled_value_still_reported(tmp_path):
    """Control: ``auto_approve = True`` enables the bypass."""
    findings = _sast(tmp_path, "app/enable.py", '''
        auto_approve = True
    ''')
    assert "WORKFLOW_APPROVAL_BYPASS" in _ids(findings)


# ---------------------------------------------------------------------------
# 10 -- SQL: DB-API parameterized sinks (psycopg, binds, to_execute)
# ---------------------------------------------------------------------------
_PSQL_TWO_ARG = '''
    from psycopg import sql

    async def fetch(cursor, table_name: str, user_id: str):
        query = sql.SQL("SELECT * FROM {} WHERE id = %s").format(
            sql.Identifier(table_name)
        )
        cursor.execute(query, (user_id,))
'''

_PSQL_BUILDER_ONE_ARG = '''
    from psycopg import sql

    async def fetch(cursor, table_name: str, user_id: str):
        query = sql.SQL("SELECT * FROM {} WHERE id = %s").format(
            sql.Identifier(table_name)
        )
        cursor.execute(query)
'''


def test_psycopg_two_arg_execute_is_parameterized(tmp_path):
    findings = _taint(tmp_path, "postgres.py", _PSQL_TWO_ARG)
    assert "TAINT_SQL_INJECTION" not in _ids(findings)


def test_psycopg_builder_product_is_parameterized(tmp_path):
    findings = _taint(tmp_path, "postgres_one.py", _PSQL_BUILDER_ONE_ARG)
    assert "TAINT_SQL_INJECTION" not in _ids(findings)


def test_executemany_with_binds_is_parameterized(tmp_path):
    findings = _taint(tmp_path, "oracle.py", '''
        async def bulk(cursor, binds):
            cursor.executemany("INSERT INTO t VALUES (%s, %s)", binds)
    ''')
    assert "TAINT_SQL_INJECTION" not in _ids(findings)


def test_command_object_to_execute_is_parameterized(tmp_path):
    findings = _taint(tmp_path, "sqlserver.py", '''
        async def run(cursor, cmd, user_id: str):
            cursor.execute(*cmd.to_execute())
    ''')
    assert "TAINT_SQL_INJECTION" not in _ids(findings)


def test_fstring_execute_still_reported(tmp_path):
    """Control: 1-arg string-built SQL remains the injectable shape."""
    findings = _taint(tmp_path, "crud_fstring.py", '''
        from fastapi import APIRouter

        router = APIRouter()

        @router.get("/q")
        async def q(db, user_id: str):
            query = f"SELECT * FROM users WHERE id = '{user_id}'"
            return db.execute(query).scalar()
    ''')
    assert "TAINT_SQL_INJECTION" in _ids(findings)


# ---------------------------------------------------------------------------
# 11 -- NoSQL: $in list operands are data, not operator positions
# ---------------------------------------------------------------------------
def test_nosql_in_data_operand_suppressed(tmp_path):
    findings = _taint(tmp_path, "nosql_safe.py", '''
        async def get_items(db, params: dict):
            result = await db.find({"_id": {"$in": params["ids"]}}).to_list(length=None)
            return result
    ''')
    assert "TAINT_NOSQL_INJECTION" not in _ids(findings)


def test_nosql_operator_position_still_reported(tmp_path):
    """Control: ``{"$gt": <taint>}`` smuggles an operator object."""
    findings = _taint(tmp_path, "nosql_bad.py", '''
        async def get_items(db, params: dict):
            result = await db.find({"age": {"$gt": params["min_age"]}}).to_list(length=None)
            return result
    ''')
    assert "TAINT_NOSQL_INJECTION" in _ids(findings)


# ---------------------------------------------------------------------------
# 12 -- LLM engine: comments, docstrings, await loops, help text, argv
# ---------------------------------------------------------------------------
def _llm(tmp_path, name: str, source: str) -> list[dict]:
    from scanner.llm_security import scan_llm_file

    text = textwrap.dedent(source)
    path = _write(tmp_path, name, text)
    return scan_llm_file(str(path), text)


def test_llm_comment_and_docstring_lines_suppressed(tmp_path):
    findings = _llm(tmp_path, "helpers.py", '''
        # NOTE: FunctionTool has been removed; exec() is no longer called.
        """
        Apply the -qqq flag to pip install commands to reduce noise.
        """
        import os
    ''')
    assert "LLM02_INSECURE_OUTPUT_HANDLING" not in _ids(findings)
    assert "LLM05_SUPPLY_CHAIN_VULNERABILITY" not in _ids(findings)


def test_llm_await_loop_is_not_cpu_spin(tmp_path):
    findings = _llm(tmp_path, "pump.py", '''
        import asyncio

        async def pump():
            while True:
                await asyncio.sleep(1)
    ''')
    assert "LLM04_MODEL_DENIAL_OF_SERVICE" not in _ids(findings)


def test_llm_tight_loop_still_reported(tmp_path):
    """Control: ``while True: pass`` is the CPU spin the rule means."""
    findings = _llm(tmp_path, "spin.py", '''
        def spin():
            while True:
                pass
    ''')
    assert "LLM04_MODEL_DENIAL_OF_SERVICE" in _ids(findings)


def test_llm_env_var_help_text_suppressed(tmp_path):
    findings = _llm(tmp_path, "help.py", '''
        def main():
            print("Error: OPENAI_API_KEY environment variable is not set!")
    ''')
    assert "LLM06_SENSITIVE_INFORMATION_DISCLOSURE" not in _ids(findings)


def test_llm_argv_subprocess_and_orm_exec_suppressed(tmp_path):
    findings = _llm(tmp_path, "tools.py", '''
        import subprocess

        def rev(branch):
            subprocess.run(["git", "rev-parse", branch])

        def get(session, model_class, item_id):
            session.exec(select(model_class).where(model_class.id == item_id))
    ''')
    assert "LLM02_INSECURE_OUTPUT_HANDLING" not in _ids(findings)


def test_llm_os_system_still_reported(tmp_path):
    """Control: os.system with dynamic text remains reportable."""
    findings = _llm(tmp_path, "legacy.py", '''
        import os

        def run(path):
            os.system("ls " + path)
    ''')
    assert "LLM02_INSECURE_OUTPUT_HANDLING" in _ids(findings)


# ---------------------------------------------------------------------------
# 13 -- Licence category reconciliation
# ---------------------------------------------------------------------------
def test_license_category_reconciled_after_policy():
    from analysis.license_policy_engine import reconcile_license_category

    out = reconcile_license_category([
        {"name": "lightningcss", "license_issue": "COPYLEFT_OR_RECIPROCAL_LICENSE",
         "license_category": "Permissive"},
        {"name": "requests", "license_issue": "PERMISSIVE_LICENSE",
         "license_category": "Permissive"},
        {"name": "mystery", "license_category": "Unknown"},
    ])
    assert out[0]["license_category"] == "Copyleft / Reciprocal"
    assert out[1]["license_category"] == "Permissive"
    assert out[2]["license_category"] == "Unknown"


# ---------------------------------------------------------------------------
# 14 -- SBOM parsers: pyproject / uv.lock / NuGet
# ---------------------------------------------------------------------------
def test_pyproject_parser_pep621_and_groups(tmp_path):
    from scanner.manifests.pyproject_toml import parse_pyproject_toml

    path = _write(tmp_path, "pyproject.toml", '''
        [project]
        name = "demo"
        dependencies = ["requests>=2.0,<3.0", "flask==3.0.1"]

        [project.optional-dependencies]
        dev = ["pytest==8.3.3"]

        [dependency-groups]
        lint = ["ruff==0.6.2"]
    ''')
    rows = {r["name"]: r for r in parse_pyproject_toml(str(path))}
    assert rows["requests"]["version"] == "unknown"  # range, not a pin
    assert rows["requests"]["direct"] is True
    assert rows["flask"]["version"] == "3.0.1"
    assert rows["pytest"]["version"] == "8.3.3"
    assert rows["ruff"]["direct"] is False  # dev group


def test_uv_lock_parser_skips_editable_workspace(tmp_path):
    from scanner.manifests.uv_lock import parse_uv_lock

    path = _write(tmp_path, "uv.lock", '''
        [[package]]
        name = "autogen"
        version = "0.4.0"
        source = { editable = "." }

        [[package]]
        name = "requests"
        version = "2.32.3"
        source = "registry+https://pypi.org/simple"
    ''')
    rows = parse_uv_lock(str(path))
    assert [r["name"] for r in rows] == ["requests"]
    assert rows[0]["version"] == "2.32.3"


def test_nuget_csproj_and_props_parsers(tmp_path):
    from scanner.manifests.nuget_packages import (
        parse_nuget_csproj, parse_nuget_packages_props,
    )

    csproj = _write(tmp_path, "Demo.csproj", '''
        <Project Sdk="Microsoft.NET.Sdk">
          <ItemGroup>
            <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
            <PackageReference Include="Moq"><Version>4.20.70</Version></PackageReference>
            <PackageReference Include="xunit" />
          </ItemGroup>
        </Project>
    ''')
    rows = {r["name"]: r for r in parse_nuget_csproj(str(csproj))}
    assert rows["Newtonsoft.Json"]["version"] == "13.0.3"
    assert rows["Moq"]["version"] == "4.20.70"
    assert rows["xunit"]["version"] == "unknown"  # central management
    assert all(r["direct"] for r in rows.values())

    props = _write(tmp_path, "Directory.Packages.props", '''
        <Project>
          <ItemGroup>
            <PackageVersion Include="Azure.AI.OpenAI" Version="1.0.0-beta.12" />
            <PackageVersion Include="Moq" Version="[4.20.70]" />
          </ItemGroup>
        </Project>
    ''')
    prow = {r["name"]: r for r in parse_nuget_packages_props(str(props))}
    assert prow["Azure.AI.OpenAI"]["version"] == "1.0.0-beta.12"
    assert prow["Moq"]["version"] == "4.20.70"  # bracket-exact
    assert prow["Moq"]["direct"] is False


def test_nuget_lock_parser(tmp_path):
    from scanner.manifests.nuget_packages import parse_nuget_lock

    path = _write(tmp_path, "packages.lock.json", json.dumps({
        "version": 1,
        "dependencies": {
            ".NETCoreApp,Version=v8.0": {
                "Newtonsoft.Json": {
                    "type": "Direct",
                    "requested": "[13.0.3, )",
                    "resolved": "13.0.3",
                },
                "System.Text.Json": {
                    "type": "Transitive",
                    "resolved": "8.0.5",
                },
            }
        },
    }))
    rows = {r["name"]: r for r in parse_nuget_lock(str(path))}
    assert rows["Newtonsoft.Json"]["version"] == "13.0.3"
    assert rows["Newtonsoft.Json"]["direct"] is True
    assert rows["System.Text.Json"]["direct"] is False


# ---------------------------------------------------------------------------
# 15 -- Docker paths are target-relative
# ---------------------------------------------------------------------------
def test_docker_findings_use_target_relative_paths(tmp_path):
    from scanner.iac_docker import scan_docker

    _write(tmp_path, ".devcontainer/Dockerfile", "FROM ubuntu:latest\nUSER app\n")
    findings = scan_docker(str(tmp_path))
    files = {f.get("file", "") for f in findings}
    assert ".devcontainer/Dockerfile" in files
    # The old prefix bug prepended the target dir name to every path.
    assert not any(f.startswith(tmp_path.name + "/") for f in files)
