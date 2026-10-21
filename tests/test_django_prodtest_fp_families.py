# -*- coding: utf-8 -*-
r"""django/django (main) prodtest validation (2026-10-21): defect families
found while cross-checking the Lacework/CNAP django pair against the V11
scan of ``prodtest\django``.

  D1  the pyproject parser leaked PEP 508 environment markers into the
      version field: ``tzdata; sys_platform == 'win32'`` produced
      ``tzdata@'win32'`` because ``_EXACT_PIN`` matched the *marker's*
      ``==``.  The advisory query then carries a garbage version.
  D2  ``_find_line`` could not locate PEP 621 array entries of the form
      ``"asgiref>=3.12.1",`` (specifier directly after the name), so
      provenance fell back to ``pyproject.toml:1``.
  D3  HARDCODED_CREDENTIAL_COMPARISON fired on IANA HTTP method literals
      compared against credential-noun variables
      (django ``csrf.py:345`` ``if token_source != "POST":``) -- a method
      name can never be secret material, so the rule's claim ("the secret
      is committed to source") is false by construction.

Controls keep every genuine shape firing: exact pins before markers,
range deps as ``unknown``, and the canonical credential comparison.
"""
import textwrap

import pytest


def _write(tmp_path, name: str, source: str):
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(source), encoding="utf-8")
    return path


def _sast(tmp_path, name: str, source: str) -> list[dict]:
    from scanner.sast import scan_file

    return scan_file(str(_write(tmp_path, name, source)))


def _ids(findings: list[dict]) -> set[str]:
    return {str(f.get("rule_id") or f.get("id")) for f in findings}


# ---------------------------------------------------------------------------
# D1 -- pyproject environment marker is not a version pin
# ---------------------------------------------------------------------------
def test_pyproject_marker_double_equals_is_not_a_version(tmp_path):
    r"""``tzdata; sys_platform == 'win32'`` must not resolve to 'win32'."""
    from scanner.manifests.pyproject_toml import parse_pyproject_toml

    path = _write(tmp_path, "pyproject.toml", '''
        [project]
        name = "demo"
        dependencies = [
            "asgiref>=3.12.1",
            "sqlparse>=0.5.0",
            "tzdata; sys_platform == 'win32'",
        ]
    ''')
    rows = {r["name"]: r for r in parse_pyproject_toml(str(path))}
    assert rows["tzdata"]["version"] == "unknown"
    # name must not absorb the marker either
    assert set(rows) == {"asgiref", "sqlparse", "tzdata"}


def test_pyproject_exact_pin_before_marker_still_parsed(tmp_path):
    from scanner.manifests.pyproject_toml import parse_pyproject_toml

    path = _write(tmp_path, "pyproject.toml", '''
        [project]
        name = "demo"
        dependencies = ["pkg==1.2.3; python_version >= '3.9'"]
    ''')
    rows = {r["name"]: r for r in parse_pyproject_toml(str(path))}
    assert rows["pkg"]["version"] == "1.2.3"


def test_pyproject_range_deps_remain_unknown(tmp_path):
    from scanner.manifests.pyproject_toml import parse_pyproject_toml

    path = _write(tmp_path, "pyproject.toml", '''
        [project]
        name = "demo"
        dependencies = ["requests>=2.0,<3.0", "flask==3.0.1"]
    ''')
    rows = {r["name"]: r for r in parse_pyproject_toml(str(path))}
    assert rows["requests"]["version"] == "unknown"
    assert rows["flask"]["version"] == "3.0.1"


# ---------------------------------------------------------------------------
# D2 -- array-entry provenance line
# ---------------------------------------------------------------------------
def test_pyproject_array_entry_line_located(tmp_path):
    r"""``"asgiref>=3.12.1",`` must resolve to its real line, not 1."""
    from scanner.manifests.pyproject_toml import parse_pyproject_toml

    path = _write(tmp_path, "pyproject.toml", '''
        [project]
        name = "demo"
        dynamic = ["version"]
        dependencies = [
            "asgiref>=3.12.1",
            "sqlparse>=0.5.0",
        ]
    ''')
    rows = {r["name"]: r for r in parse_pyproject_toml(str(path))}
    assert rows["asgiref"]["manifest_line"] == 6
    assert rows["sqlparse"]["manifest_line"] == 7


def test_pyproject_optional_key_line_still_located(tmp_path):
    r"""django's real shape: optional-dependencies group key ``bcrypt =
    ["bcrypt>=4.1.1"]`` locates via the ``=`` arm, not the specifier arm."""
    from scanner.manifests.pyproject_toml import parse_pyproject_toml

    path = _write(tmp_path, "pyproject.toml", '''
        [project]
        name = "demo"

        [project.optional-dependencies]
        bcrypt = ["bcrypt>=4.1.1"]
    ''')
    rows = {r["name"]: r for r in parse_pyproject_toml(str(path))}
    assert rows["bcrypt"]["manifest_line"] == 6


# ---------------------------------------------------------------------------
# D3 -- HTTP method literals are not secret material
# ---------------------------------------------------------------------------
def test_sast_http_method_verb_comparison_suppressed(tmp_path):
    r"""django csrf.py:345 shape: ``if token_source != "POST":``."""
    findings = _sast(tmp_path, "csrf.py", '''
        def _check_source(request):
            token_source = resolve_source(request)
            if token_source != "POST":
                return False
            return True
    ''')
    assert "HARDCODED_CREDENTIAL_COMPARISON" not in _ids(findings)


def test_sast_lowercase_http_verb_comparison_suppressed(tmp_path):
    findings = _sast(tmp_path, "router.py", '''
        def allow(token_method):
            if token_method == "get":
                return True
            return False
    ''')
    assert "HARDCODED_CREDENTIAL_COMPARISON" not in _ids(findings)


def test_sast_credential_comparison_still_reported(tmp_path):
    """Control: the canonical auth-bypass shape keeps its finding."""
    findings = _sast(tmp_path, "auth.py", '''
        def check(user):
            if user.password == "hunter2secret":
                return True
            return False
    ''')
    assert "HARDCODED_CREDENTIAL_COMPARISON" in _ids(findings)
