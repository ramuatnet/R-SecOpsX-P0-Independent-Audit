# -*- coding: utf-8 -*-
"""AgentGPT-main validation (2026-10-15): the five false-positive families.

A consultant review of the AgentGPT-main report (122 findings) traced ~16 of
the 50 code findings to rules that punish the SECURE or CORRECT shape:

  A. TAINT_SQL_INJECTION x8 -- ``query = select(M).filter(M.col == taint)``
     then ``session.execute(query)``: SQLAlchemy generates a parameterized
     statement, so taint rides in BOUND PARAMETERS, never in SQL structure.
  B. CONFIG_CONTEXTUAL_CREDENTIAL x2 -- ``token: ${{ secrets.X }}`` in GitHub
     Actions: a secret REFERENCE is the secure pattern, not a leaked value.
  C. CONFIG_CONTEXTUAL_CREDENTIAL x1 -- ``aws-secretsmanager-caching =
     "^1.1.1.5"``: a dependency line whose NAME contains "secret", whose
     VALUE is a version range.
  D. OAUTH_CLIENT_SECRET x2 -- ``sid_client_secret: Optional[str] = None``
     (a type declaration) and ``clientSecret: serverEnv.GOOGLE_CLIENT_SECRET
     ?? ""`` (config-object wiring).
  E. GENERIC_API_KEY_PASSWORD x3 -- ``helicone_api_key = "some_key"`` in test
     fixtures: placeholder stems, not credential material.

Each test states both sides of the kill-only-on-proof contract: the false
shape must be gone, and a real literal at the same location must survive.
The licence case adds ODC-By-1.0, the one UNCLASSIFIED_LICENSE row on that
scan (language-subtag-registry), to the shared catalogue.
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


def _lines(findings: list[dict], rule_id: str) -> set[int]:
    return {
        int(f.get("line") or 0)
        for f in findings
        if str(f.get("rule_id") or f.get("id")) == rule_id
    }


# ---------------------------------------------------------------------------
# A -- SQLAlchemy query builders are parameterized by construction
# ---------------------------------------------------------------------------
_BUILDER_SOURCE = '''
    from sqlalchemy import select
    from fastapi import APIRouter
    from app.db.model import OauthCredentials

    router = APIRouter()

    @router.post("/callback")
    async def oauth_callback(session, code: str, state: str):
        query = select(OauthCredentials).filter(OauthCredentials.state == state)
        return session.execute(query).scalar()

    @router.post("/verify")
    async def verify(session, token: str):
        stmt = select(OauthCredentials).where(OauthCredentials.session_token == token)
        return session.execute(stmt).scalar()
'''


def test_sqlalchemy_builder_queries_are_not_sql_injection(tmp_path):
    """Family A: both AgentGPT CRUD shapes (filter/where on a select()
    builder feeding session.execute) must not be reported."""
    findings = _taint(tmp_path, "crud_oauth.py", _BUILDER_SOURCE)
    assert "TAINT_SQL_INJECTION" not in _ids(findings)


def test_module_aliased_builder_is_not_sql_injection(tmp_path):
    """``sa.select(...)`` -- the alias resolves through the sqlalchemy
    import, so the same kill applies."""
    findings = _taint(tmp_path, "crud_sa.py", '''
        from sqlalchemy import select as sa_select
        import sqlalchemy as sa
        from fastapi import APIRouter

        router = APIRouter()

        @router.get("/rows")
        async def rows(db, state: str):
            stmt = sa.select(Users).where(Users.state == state)
            return db.execute(stmt).scalar()
    ''')
    assert "TAINT_SQL_INJECTION" not in _ids(findings)


def test_dynamic_text_query_still_reported(tmp_path):
    """Control: ``text(f"...{taint}")`` inside a builder is exactly the
    injectable shape; the kill must withhold."""
    findings = _taint(tmp_path, "crud_bad.py", '''
        from sqlalchemy import select, text
        from fastapi import APIRouter

        router = APIRouter()

        @router.get("/users")
        async def users(session, user_id: str):
            query = select(text(f"SELECT * FROM users WHERE id = '{user_id}'"))
            return session.execute(query).scalar()
    ''')
    assert "TAINT_SQL_INJECTION" in _ids(findings)


def test_raw_fstring_execute_still_reported(tmp_path):
    """Control: a non-builder assignment feeding execute() is untouched."""
    findings = _taint(tmp_path, "crud_fstring.py", '''
        from fastapi import APIRouter

        router = APIRouter()

        @router.get("/q")
        async def q(db, user_id: str):
            query = f"SELECT * FROM users WHERE id = '{user_id}'"
            return db.execute(query).scalar()
    ''')
    assert "TAINT_SQL_INJECTION" in _ids(findings)


def test_builder_kill_requires_sqlalchemy_import(tmp_path):
    """Control: without a sqlalchemy import the builder shape proves
    nothing -- the finding must survive."""
    findings = _taint(tmp_path, "crud_nosqla.py", '''
        from fastapi import APIRouter

        router = APIRouter()

        @router.get("/rows")
        async def rows(db, state: str):
            query = select(Users).filter(Users.state == state)
            return db.execute(query).scalar()
    ''')
    assert "TAINT_SQL_INJECTION" in _ids(findings)


def test_reassignment_invalidates_builder_kill(tmp_path):
    """Control: ``query = request.args["q"]`` after a builder assignment
    drops the record; the later execute() must be reported."""
    findings = _taint(tmp_path, "crud_reassign.py", '''
        from sqlalchemy import select
        from fastapi import APIRouter

        router = APIRouter()

        @router.get("/q")
        async def q(db, state: str):
            query = select(Users).filter(Users.state == state)
            query = request.args["q"]
            return db.execute(query).scalar()
    ''')
    assert "TAINT_SQL_INJECTION" in _ids(findings)


# ---------------------------------------------------------------------------
# B -- GitHub Actions secret EXPRESSIONS are references, not values
# ---------------------------------------------------------------------------
def test_github_actions_secret_expression_not_reported(tmp_path):
    """Family B: the exact sponsors.yml lines from the scan."""
    findings = _sec(tmp_path, ".github/workflows/sponsors.yml", '''
        name: sponsors
        steps:
          - name: Generate Sponsors
            uses: JamesIves/github-sponsors-readme-action@v1.2.2
            with:
              token: ${{ secrets.SPONSOR_WORKFLOW_PAT }}
              file: 'README.md'
          - name: Create Pull Request
            uses: peter-evans/create-pull-request@v5.0.1
            with:
              token: ${{ secrets.SPONSOR_WORKFLOW_PAT }}
    ''')
    ids = _ids(findings)
    assert "CONFIG_CONTEXTUAL_CREDENTIAL" not in ids
    assert "GITHUB_TOKEN" not in ids


def test_literal_workflow_token_still_reported(tmp_path):
    """Control: a real literal token in a workflow keeps its finding
    (known-signature layer passes regardless of the context layer)."""
    findings = _sec(tmp_path, ".github/workflows/ci.yml", '''
        jobs:
          build:
            steps:
              - run: echo hi
                env:
                  jwt_secret: "abcdefghijklmnop123456"
    ''')
    assert "JWT_SIGNING_SECRET" in _ids(findings)


# ---------------------------------------------------------------------------
# C -- a dependency line whose value is a version range
# ---------------------------------------------------------------------------
def test_manifest_version_range_not_reported(tmp_path):
    """Family C: ``aws-secretsmanager-caching = "^1.1.1.5"`` -- the key
    contains "secret", the value is a semver range."""
    findings = _sec(tmp_path, "pyproject.toml", '''
        [tool.poetry.dependencies]
        python = "^3.9"
        aws-secretsmanager-caching = "^1.1.1.5"
        lanarky = "^0.7.15"
    ''')
    assert "CONFIG_CONTEXTUAL_CREDENTIAL" not in _ids(findings)


def test_literal_manifest_secret_still_reported(tmp_path):
    """Control: a literal credential in the same manifest still fires."""
    findings = _sec(tmp_path, "secrets.toml", '''
        [service]
        api_key = "Abcdefghijklmnop123456"
    ''')
    assert _ids(findings), "literal manifest credential disappeared"


# ---------------------------------------------------------------------------
# D -- OAuth secret DECLARATIONS and config-object references
# ---------------------------------------------------------------------------
def test_pydantic_secret_field_declaration_not_reported(tmp_path):
    """Family D1: ``sid_client_secret: Optional[str] = None`` is a type
    declaration with an empty default."""
    findings = _sec(tmp_path, "reworkd_platform/settings.py", '''
        from pydantic import BaseModel
        from typing import Optional

        class Settings(BaseModel):
            sid_client_secret: Optional[str] = None
            github_client_secret: Optional[str] = None
    ''')
    assert "OAUTH_CLIENT_SECRET" not in _ids(findings)


def test_config_object_reference_not_reported(tmp_path):
    """Family D2: NextAuth wiring reads the value from serverEnv --
    a reference, not a literal."""
    findings = _sec(tmp_path, "next/src/server/auth.ts", '''
        import { serverEnv } from "../server/env";

        export const authOptions = {
          providers: [
            GitHubProvider({
              clientId: serverEnv.GITHUB_CLIENT_ID ?? "",
              clientSecret: serverEnv.GOOGLE_CLIENT_SECRET ?? "",
            }),
          ],
        };
    ''')
    assert "OAUTH_CLIENT_SECRET" not in _ids(findings)


def test_literal_client_secret_still_reported(tmp_path):
    """Control: a quoted literal at the same direct-assignment key keeps
    the Critical finding (the shape the two AgentGPT FPs shared)."""
    findings = _sec(tmp_path, "oauth_config.py", '''
        client_secret = "abcdef123456"
    ''')
    assert "OAUTH_CLIENT_SECRET" in _ids(findings)


def test_bare_literal_client_secret_still_reported(tmp_path):
    """Control: YAML-style unquoted literals remain reportable."""
    findings = _sec(tmp_path, "application.yml", '''
        spring:
          security:
            oauth:
              client_secret: zxcvbnm123456789
    ''')
    assert "OAUTH_CLIENT_SECRET" in _ids(findings)


# ---------------------------------------------------------------------------
# E -- placeholder credential VALUES in generic key rules
# ---------------------------------------------------------------------------
def test_placeholder_generic_key_values_not_reported(tmp_path):
    """Family E: ``some_key`` / ``custom_key`` test-fixture stand-ins
    (bare-key shape -- the one the real scan matched)."""
    findings = _sast(tmp_path, "tests/agent/test_model_factory.py", '''
        def make_openai():
            helicone_api_key = "some_key"
            custom_key = "custom_key"
            return helicone_api_key, custom_key
    ''')
    assert _ids(findings) == set() or "GENERIC_API_KEY_PASSWORD" not in _ids(
        findings), sorted(_ids(findings))


def test_real_generic_key_value_still_reported(tmp_path):
    """Control: non-placeholder literals at the same key names fire."""
    findings = _sast(tmp_path, "app_config.py", '''
        api_key = "realvalue123456"
        password = "hunter2hunter2"
    ''')
    assert "GENERIC_API_KEY_PASSWORD" in _ids(findings)


def test_placeholder_stems_are_value_scoped_not_prefix_lenient(tmp_path):
    """The placeholder family matches whole values only: a decorated stem
    that could hold material stays reportable."""
    findings = _sast(tmp_path, "prod_config.py", '''
        api_key = "some_key_prod_9x2"
    ''')
    assert "GENERIC_API_KEY_PASSWORD" in _ids(findings)


# ---------------------------------------------------------------------------
# Licence catalogue -- the one UNCLASSIFIED row from the same scan
# ---------------------------------------------------------------------------
def _row(name: str, license_value: str) -> dict:
    return {
        "name": name,
        "version": "0.1.0",
        "license": license_value,
        "license_declared": license_value,
        "license_resolution_status": "RESOLVED_FROM_CANONICAL_REPORT",
    }


def test_odc_by_is_permissive_with_notice():
    """language-subtag-registry declares ODC-By-1.0 (a CC-BY-family data
    licence): permissive, attribution retained -> LOW / ALLOW / NOTICE."""
    from analysis.license_policy_engine import enrich_license_policy
    from core.license_catalog import requires_notice

    item = enrich_license_policy(
        [_row("language-subtag-registry", "ODC-By-1.0")]
    )[0]
    assert item["license_risk"] == "LOW", item["license_risk"]
    assert item["license_issue"] == "PERMISSIVE_LICENSE", item["license_issue"]
    assert item["license_policy_decision"] == "ALLOW", (
        item["license_policy_decision"])
    assert requires_notice("ODC-By-1.0") is True
