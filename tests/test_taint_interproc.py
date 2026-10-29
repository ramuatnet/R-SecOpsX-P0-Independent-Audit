"""T-2.1+T-2.2: interprocedural taint post-pass.

The measured misses this pass exists for are both route -> dao/model
boundaries (dvpwa student dao, VAmPI user model): the worker pool sees one
file at a time, so the callee's SQL sink stays dark while H1 reports the
build site.  These tests pin the closure, the H1 ownership drop, the
kill-switch, recursion termination, and the filter_trace ledger.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import filter_trace


# --- fixture: dvpwa shape (async handler -> named-tuple dao) ---------------
DAOPKG = (
    "class Student:\n"
    "    @staticmethod\n"
    "    def create(conn, name):\n"
    "        q = (\"INSERT INTO students (name) \"\n"
    "             \"VALUES ('%(name)s')\" % {'name': name})\n"
    "        cur = conn.cursor()\n"
    "        cur.execute(q)\n"
    "        label = (\"SELECT name FROM t WHERE id = '%s'\"\n"
    "                 % {'id': conn.id})\n"
    "        return label\n"
)

VIEWST = (
    "from aiohttp import web\n"
    "from pkg.dao.student import Student\n"
    "\n"
    "async def create_student(request):\n"
    "    data = await request.post()\n"
    "    await Student.create(None, data['name'])\n"
    "    return web.Response()\n"
)

VIEWS_UNTAINTED = (
    "from aiohttp import web\n"
    "from pkg.dao.student import Student\n"
    "\n"
    "async def create_student(request):\n"
    "    await Student.create(None, 'literal')\n"
    "    return web.Response()\n"
)


def _write(tmp_path: Path, rel: str, text: str) -> None:
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


def _daopkg_tree(tmp_path: Path, views_src: str) -> Path:
    root = tmp_path / "src"
    _write(root, "pkg/__init__.py", "")
    _write(root, "pkg/dao/__init__.py", "")
    _write(root, "pkg/dao/student.py", DAOPKG)
    _write(root, "web/views.py", views_src)
    # `web` package marker so views.py is a project module, not a script.
    _write(root, "web/__init__.py", "")
    return root


def _marker_rows(findings):
    return [f for f in findings
            if isinstance(f, dict)
            and any("__param__:" in str(e)
                    for e in (f.get("taint_chain") or ())
                    if isinstance(e, str))]


def _h1_rows(findings, filename_suffix):
    return [f for f in findings
            if isinstance(f, dict)
            and f.get("rule_id") == "PY_SQL_INTERPOLATED_QUERY"
            and str(f.get("file", "")).replace("\\", "/").endswith(
                filename_suffix)]


def test_dvpwa_shape_sink_receives_flow_and_h1_defers(tmp_path):
    """request.post() -> Student.create(name) -> cur.execute(q):
    the SQL sink fires with a marker chain, the H1 build-site row at the
    tainted interpolation is dropped, and the control H1 (untainted
    interpolation in the same file) survives."""
    from scanner.sast import scan_directory

    root = _daopkg_tree(tmp_path, VIEWST)
    findings = scan_directory(str(root), workers=1)

    tainted = [f for f in findings
               if isinstance(f, dict)
               and f.get("rule_id") == "TAINT_SQL_INJECTION"
               and str(f.get("file", "")).replace("\\", "/").endswith(
                   "pkg/dao/student.py")]
    assert tainted, [f.get("rule_id") for f in findings
                     if isinstance(f, dict)]
    chain = tainted[0].get("taint_chain") or []
    chain_text = " | ".join(str(e) for e in chain)
    assert "request.post()" in chain_text, chain_text
    assert "__param__:pkg.dao.student#Student.create.name" in chain_text

    build_site_h1 = _h1_rows(findings, "pkg/dao/student.py")
    # The tainted build site (q = ...INSERT...) must be gone: only the
    # control interpolation remains as an H1 row.
    assert len(build_site_h1) == 1, [
        (h.get("line"), h.get("evidence")) for h in build_site_h1]
    assert build_site_h1[0].get("function") == "create"


def test_untainted_caller_keeps_h1_and_adds_no_marker(tmp_path):
    """A literal argument is not a flow: no marker row, no H1 drop."""
    from scanner.sast import scan_directory

    root = _daopkg_tree(tmp_path, VIEWS_UNTAINTED)
    findings = scan_directory(str(root), workers=1)

    assert not _marker_rows(findings)
    h1 = _h1_rows(findings, "pkg/dao/student.py")
    assert h1, "worker H1 at the build site must remain when nothing is tainted"


OPENAPI_SPEC = (
    "openapi: 3.0.0\n"
    "info:\n"
    "  title: t\n"
    "  version: '1'\n"
    "paths:\n"
    "  /users/v1/{username}:\n"
    "    get:\n"
    "      operationId: api_views.users.get_by_username\n"
    "      parameters:\n"
    "        - name: username\n"
    "          in: path\n"
    "          required: true\n"
    "          schema:\n"
    "            type: string\n"
    "      responses:\n"
    "        '200':\n"
    "          description: ok\n"
)

VAMPI_USERS = (
    "from models.user_model import User\n"
    "\n"
    "def get_by_username(username):\n"
    "    if User.get_user(username):\n"
    "        return 'found'\n"
    "    return 'missing'\n"
)

VAMPI_MODEL = (
    "class User:\n"
    "    @staticmethod\n"
    "    def get_user(username):\n"
    "        if username == 'vuln':\n"
    "            user_query = (\n"
    "                f\"SELECT * FROM users WHERE username = '{username}'\"\n"
    "            )\n"
    "            query = db.session.execute(text(user_query))\n"
    "            return query\n"
    "        label = (\"SELECT name FROM t WHERE id = '%s'\"\n"
    "                 % {'id': 'static'})\n"
    "        return label\n"
)


def _vampi_tree(tmp_path: Path) -> Path:
    root = tmp_path / "src"
    _write(root, "openapi_specs/openapi3.yml", OPENAPI_SPEC)
    _write(root, "api_views/__init__.py", "")
    _write(root, "api_views/users.py", VAMPI_USERS)
    _write(root, "models/__init__.py", "")
    _write(root, "models/user_model.py", VAMPI_MODEL)
    return root


def test_openapi_route_param_reaches_model_sink(tmp_path):
    """connexion operationId + path template: username is attacker input,
    so the model's db.session.execute(text(user_query)) fires and its H1
    build site is dropped while the control H1 survives."""
    from scanner.sast import scan_directory

    root = _vampi_tree(tmp_path)
    findings = scan_directory(str(root), workers=1)

    tainted = [f for f in findings
               if isinstance(f, dict)
               and f.get("rule_id") == "TAINT_SQL_INJECTION"
               and str(f.get("file", "")).replace("\\", "/").endswith(
                   "models/user_model.py")]
    assert tainted, [f.get("rule_id") for f in findings
                     if isinstance(f, dict)]
    chain_text = " | ".join(str(e) for e in (tainted[0].get("taint_chain") or []))
    assert "route parameter username" in chain_text, chain_text
    assert "__param__:models.user_model#User.get_user.username" in chain_text

    h1 = _h1_rows(findings, "models/user_model.py")
    assert len(h1) == 1, [(h.get("line"), h.get("function")) for h in h1]
    assert h1[0].get("function") == "get_user"


def test_kill_switch_disables_post_pass(tmp_path, monkeypatch):
    """RSX_Taint_INTERPROC=0: the worker's findings stand alone -- no
    marker rows, and the H1 build site stays (it is the worker's row)."""
    from scanner.sast import scan_directory

    monkeypatch.setenv("RSX_Taint_INTERPROC", "0")
    root = _daopkg_tree(tmp_path, VIEWST)
    findings = scan_directory(str(root), workers=1)
    assert not _marker_rows(findings)
    assert _h1_rows(findings, "pkg/dao/student.py")


MUT_A = (
    "from flask import request\n"
    "from mod_b import helper_b\n"
    "import subprocess\n"
    "\n"
    "def entry():\n"
    "    data = request.args.get('q')\n"
    "    helper_b(data)\n"
    "\n"
    "def helper_a(y):\n"
    "    subprocess.check_output('ls ' + y, shell=True)\n"
)

MUT_B = (
    "from mod_a import helper_a\n"
    "\n"
    "def helper_b(x):\n"
    "    helper_a(x)\n"
)


def test_mutual_recursion_terminates_and_reaches_sink(tmp_path):
    """a -> b -> a: the worklist must reach a fixed point (no hang) and
    the shell sink in the second hop still gets a marker chain."""
    from scanner.sast import scan_directory

    root = tmp_path / "src"
    _write(root, "mod_a.py", MUT_A)
    _write(root, "mod_b.py", MUT_B)
    findings = scan_directory(str(root), workers=1)

    tainted = [f for f in findings
               if isinstance(f, dict)
               and str(f.get("rule_id", "")).startswith("TAINT_")
               and str(f.get("file", "")).replace("\\", "/").endswith(
                   "mod_a.py")]
    assert tainted, [f.get("rule_id") for f in findings
                     if isinstance(f, dict)]
    chain_text = " | ".join(str(e) for e in (tainted[0].get("taint_chain") or []))
    assert "__param__:mod_a#helper_a.y" in chain_text, chain_text
    assert "request.args.get()" in chain_text or "request.args" in chain_text


def test_h1_drop_is_recorded_in_filter_trace(tmp_path):
    """The H1 drop must never be silent: the ledger carries a
    interproc_taint_ownership row for the dropped finding."""
    from scanner.sast import scan_directory

    ledger = filter_trace.begin_scan()
    root = _daopkg_tree(tmp_path, VIEWST)
    scan_directory(str(root), workers=1)

    owners = [r for r in ledger.entries
              if str(r.get("pass", "")) == "interproc_taint_ownership"]
    assert owners, [r.get("pass") for r in ledger.entries]
    assert any("tainted flows stay at the sink" in str(r.get("reason", ""))
               for r in owners)
