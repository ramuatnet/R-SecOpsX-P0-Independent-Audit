"""Phase B — SAST coverage rules that closed genuine blind spots versus Lacework.

Each rule was designed against real source from the comparison targets and is
RED before implementation:

  B1  NODE_SQL_TEMPLATE_INTERPOLATION — juice-shop routes/login.ts:34 builds a
      SQL query inside a JS template literal via ${req.body...}; no JS/TS SQLi
      rule existed, so all 6 of Lacework's SQLi lines were missed.
  B2  EXPRESS_CSRF_MISSING — server.ts:130 creates a bare express() app with 59
      state-changing routes and no CSRF middleware ("missing control").
  B3  NODE_JWT_DECODE_NO_VERIFY — routes/authenticatedUsers.ts imports decode
      from jsonwebtoken and reads a token payload without ever verifying it.
  B4  JAVA_XPATH_INJECTION — BenchmarkJava xpathi tests build an XPath query by
      concatenating a tainted variable (0/15 detected before this rule).
"""

from __future__ import annotations

from pathlib import Path

from scanner import sast


def _rules(findings):
    return {f.get("rule_id") for f in findings}


# ---------------------------------------------------------------------------
# B1 — JS/TS SQL injection via template-literal interpolation
# ---------------------------------------------------------------------------

_LOGIN_TS = (
    "import models from '../models'\n"
    "export default function login () {\n"
    "  return (req: any, res: any) => {\n"
    "    models.sequelize.query("
    "`SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND deletedAt IS NULL`, "
    "{ model: UserModel, plain: true })\n"
    "      .then((user: any) => res.json(user))\n"
    "  }\n"
    "}\n"
)


def test_js_template_literal_sql_interpolation_flagged(tmp_path):
    p = tmp_path / "login.ts"
    p.write_text(_LOGIN_TS, encoding="utf-8")
    assert "NODE_SQL_TEMPLATE_INTERPOLATION" in _rules(sast.scan_file(str(p)))


def test_js_parameterized_query_not_flagged(tmp_path):
    # A parameterized query (?: placeholder) is the SAFE pattern and must not
    # be reported even though it calls .query().
    p = tmp_path / "safe.ts"
    p.write_text(
        "db.query('SELECT * FROM Users WHERE email = ?', [req.body.email])\n",
        encoding="utf-8",
    )
    assert "NODE_SQL_TEMPLATE_INTERPOLATION" not in _rules(sast.scan_file(str(p)))


def test_js_knex_raw_interpolation_flagged(tmp_path):
    p = tmp_path / "repo.ts"
    p.write_text(
        "knex.raw(`SELECT * FROM users WHERE id = ${req.params.id}`)\n",
        encoding="utf-8",
    )
    assert "NODE_SQL_TEMPLATE_INTERPOLATION" in _rules(sast.scan_file(str(p)))


# ---------------------------------------------------------------------------
# B2 — Express CSRF missing-control
# ---------------------------------------------------------------------------

_SERVER_TS = (
    "import express from 'express'\n"
    "import * as models from './models'\n"
    "const app = express()\n"
    "app.post('/api/Login', login())\n"
    "app.put('/api/Basket/:id', updateBasket())\n"
    "app.delete('/api/BasketItem/:id', deleteItem())\n"
)


def test_express_bare_app_without_csrf_flagged(tmp_path):
    p = tmp_path / "server.ts"
    p.write_text(_SERVER_TS, encoding="utf-8")
    assert "EXPRESS_CSRF_MISSING" in _rules(sast.scan_file(str(p)))


def test_express_with_csurf_middleware_not_flagged(tmp_path):
    p = tmp_path / "server.ts"
    p.write_text(
        "import express from 'express'\n"
        "import csurf from 'csurf'\n"
        "const app = express()\n"
        "app.use(csurf({ cookie: true }))\n"
        "app.post('/api/Login', login())\n",
        encoding="utf-8",
    )
    assert "EXPRESS_CSRF_MISSING" not in _rules(sast.scan_file(str(p)))


def test_express_app_without_routes_not_flagged(tmp_path):
    # Bare express() with no state-changing route is not a CSRF finding.
    p = tmp_path / "mini.ts"
    p.write_text("import express from 'express'\nconst app = express()\n", encoding="utf-8")
    assert "EXPRESS_CSRF_MISSING" not in _rules(sast.scan_file(str(p)))


# ---------------------------------------------------------------------------
# B3 — JWT decoded without verification
# ---------------------------------------------------------------------------

_AUTH_USERS_TS = (
    "import { decode } from 'jsonwebtoken'\n"
    "export function listUsers (userToken: string) {\n"
    "  const parsedToken = decode(userToken, { json: true })\n"
    "  return parsedToken\n"
    "}\n"
)


def test_jwt_decode_without_verify_flagged(tmp_path):
    p = tmp_path / "authenticatedUsers.ts"
    p.write_text(_AUTH_USERS_TS, encoding="utf-8")
    assert "NODE_JWT_DECODE_NO_VERIFY" in _rules(sast.scan_file(str(p)))


def test_jwt_decode_with_verify_not_flagged(tmp_path):
    # verify.ts decodes then verifies — the secure pattern.
    p = tmp_path / "verify.ts"
    p.write_text(
        "import jwt from 'jsonwebtoken'\n"
        "const decoded = jwt.decode(token)\n"
        "jwt.verify(token, publicKey, (err, result) => {})\n",
        encoding="utf-8",
    )
    assert "NODE_JWT_DECODE_NO_VERIFY" not in _rules(sast.scan_file(str(p)))


def test_plain_decode_without_jsonwebtoken_not_flagged(tmp_path):
    # A decode() in a file that never touches jsonwebtoken is not a JWT finding.
    p = tmp_path / "util.ts"
    p.write_text("const data = decode(buffer)\n", encoding="utf-8")
    assert "NODE_JWT_DECODE_NO_VERIFY" not in _rules(sast.scan_file(str(p)))


# ---------------------------------------------------------------------------
# B4 — Java XPath injection
# ---------------------------------------------------------------------------

_XPATH_JAVA = (
    "package org.owasp.benchmark.testcode;\n"
    "public class BenchmarkTest00116 extends HttpServlet {\n"
    "  protected void doPost(HttpServletRequest request, HttpServletResponse response) {\n"
    "    String bar = request.getParameter(\"id\");\n"
    "    javax.xml.xpath.XPathFactory xpf = javax.xml.xpath.XPathFactory.newInstance();\n"
    "    javax.xml.xpath.XPath xp = xpf.newXPath();\n"
    "    String expression = \"/Employees/Employee[@emplid='\" + bar + \"']\";\n"
    "    xp.evaluate(expression, xmlDocument);\n"
    "  }\n"
    "}\n"
)


def test_java_xpath_concat_flagged(tmp_path):
    p = tmp_path / "BenchmarkTest00116.java"
    p.write_text(_XPATH_JAVA, encoding="utf-8")
    assert "JAVA_XPATH_INJECTION" in _rules(sast.scan_file(str(p)))


def test_java_constant_xpath_not_flagged(tmp_path):
    # A constant XPath expression (no concatenation) is safe.
    p = tmp_path / "Safe.java"
    p.write_text(
        "public class Safe {\n"
        "  void go(javax.xml.xpath.XPath xp) throws Exception {\n"
        "    String expression = \"/Employees/Employee[@emplid='123']\";\n"
        "    xp.evaluate(expression, doc);\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    assert "JAVA_XPATH_INJECTION" not in _rules(sast.scan_file(str(p)))


def test_java_url_path_concat_without_xpath_not_flagged(tmp_path):
    # A URL path built by concatenation in a non-XPath file must not be a
    # false XPath finding (the guard requires XPath context).
    p = tmp_path / "Client.java"
    p.write_text(
        "public class Client {\n"
        "  String url = \"https://api.example.com/users/\" + userId;\n"
        "}\n",
        encoding="utf-8",
    )
    assert "JAVA_XPATH_INJECTION" not in _rules(sast.scan_file(str(p)))
