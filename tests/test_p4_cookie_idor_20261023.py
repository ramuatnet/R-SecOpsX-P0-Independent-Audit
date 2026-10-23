# -*- coding: utf-8 -*-
r"""P4 leftovers (2026-10-23): cookie-flag arms the audit found missing, and
the IDOR intermediate-variable recall sub-shape that empirically stays dark.

Red-first: the six positive tests below were observed failing (rule id
absent / no finding) before the change. Every positive has a negative twin
whose mitigation is structural, so the gate proves precision rather than
asserting it.

  G1 Go cookies       GO_COOKIE_MISSING_SECURE / GO_COOKIE_MISSING_HTTPONLY:
                      http.SetCookie whose Cookie literal lacks Secure:true /
                      HttpOnly:true. Mirrors the Express gate (missing-option
                      on a known call), not a blanket SetCookie report.
  G2 .NET cookies     DOTNET_COOKIE_MISSING_SECURE / DOTNET_COOKIE_MISSING_HTTPONLY:
                      Response.Cookies.Append/Add whose CookieOptions lack
                      Secure=true / HttpOnly=true.
  G3 IDOR intermediate
                      The G23 gate required the request expression inside the
                      400-char call window, so
                          oid = request.GET["id"]
                          Invoice.objects.get(pk=oid)
                      (and the JS const id = req.params.id; findByPk(id)
                      equivalent) was invisible. The fix keeps the direct
                      shape and adds one honest hop: some identifier inside
                      the fetch call is ASSIGNED from a request expression in
                      the same handler body. A fetch whose argument never
                      receives request data (constant, config, whitelisted)
                      stays dark, and the ownership gate is unchanged.

Flask CSRF-absence remains a documented non-ship: a POST handler without a
token check cannot be distinguished statically from an API authenticating by
header token, so any absence rule would manufacture FPs on correct code.
"""
import textwrap


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


def _rule_at(findings: list[dict], rule_id: str, line) -> bool:
    return any(
        (str(f.get("rule_id") or f.get("id")) == rule_id)
        and (line is None or f.get("line") == line)
        for f in findings)


# ---------------------------------------------------------------------------
# G1 -- Go cookie flags
# ---------------------------------------------------------------------------

def test_go_cookie_insecure_flags_fire(tmp_path):
    findings = _sast(tmp_path, "cookies.go", """\
        package main

        import ("net/http")

        func handler(w http.ResponseWriter, r *http.Request) {
            v := r.URL.Query().Get("sid")
            http.SetCookie(w, &http.Cookie{Name: "sid", Value: v, Path: "/"})
        }
        """)
    assert _rule_at(findings, "GO_COOKIE_MISSING_SECURE", 7), \
        sorted(_ids(findings))
    assert _rule_at(findings, "GO_COOKIE_MISSING_HTTPONLY", 7), \
        sorted(_ids(findings))


def test_go_cookie_secure_flags_stay_dark(tmp_path):
    findings = _sast(tmp_path, "cookies.go", """\
        package main

        import ("net/http")

        func handler(w http.ResponseWriter, r *http.Request) {
            v := r.URL.Query().Get("sid")
            http.SetCookie(w, &http.Cookie{
                Name: "sid", Value: v, Path: "/",
                Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
            })
        }
        """)
    assert "GO_COOKIE_MISSING_SECURE" not in _ids(findings)
    assert "GO_COOKIE_MISSING_HTTPONLY" not in _ids(findings)


# ---------------------------------------------------------------------------
# G2 -- .NET cookie flags
# ---------------------------------------------------------------------------

def test_dotnet_cookie_insecure_flags_fire(tmp_path):
    findings = _sast(tmp_path, "Cookies.cs", """\
        using Microsoft.AspNetCore.Http;

        public class CookiesController
        {
            public void Issue(HttpResponse response, string sid)
            {
                response.Cookies.Append("sid", sid, new CookieOptions { Path = "/" });
            }
        }
        """)
    assert _rule_at(findings, "DOTNET_COOKIE_MISSING_SECURE", 7), \
        sorted(_ids(findings))
    assert _rule_at(findings, "DOTNET_COOKIE_MISSING_HTTPONLY", 7), \
        sorted(_ids(findings))


def test_dotnet_cookie_secure_flags_stay_dark(tmp_path):
    findings = _sast(tmp_path, "Cookies.cs", """\
        using Microsoft.AspNetCore.Http;

        public class CookiesController
        {
            public void Issue(HttpResponse response, string sid)
            {
                response.Cookies.Append("sid", sid, new CookieOptions {
                    Path = "/", Secure = true, HttpOnly = true,
                    SameSite = SameSiteMode.Lax });
            }
        }
        """)
    assert "DOTNET_COOKIE_MISSING_SECURE" not in _ids(findings)
    assert "DOTNET_COOKIE_MISSING_HTTPONLY" not in _ids(findings)


# ---------------------------------------------------------------------------
# G3 -- IDOR intermediate-variable recall
# ---------------------------------------------------------------------------

def test_py_idor_intermediate_request_id_fires(tmp_path):
    findings = _sast(tmp_path, "views.py", """\
        from django.http import HttpResponse

        from .models import Invoice


        def invoice_detail(request):
            oid = request.GET["id"]
            invoice = Invoice.objects.get(pk=oid)
            return HttpResponse(invoice.body)
        """)
    assert _rule_at(findings, "PY_IDOR_OBJECT_FETCH", 8), \
        sorted(_ids(findings))


def test_js_idor_intermediate_request_id_fires(tmp_path):
    findings = _sast(tmp_path, "routes.js", """\
        const express = require("express");
        const router = express.Router();

        router.get("/invoice", async (req, res) => {
          const id = req.params.id;
          const invoice = await Invoice.findByPk(id);
          res.json(invoice);
        });
        """)
    assert _rule_at(findings, "NODE_IDOR_OBJECT_FETCH", 6), \
        sorted(_ids(findings))


def test_py_idor_intermediate_owned_fetch_stays_dark(tmp_path):
    findings = _sast(tmp_path, "views.py", """\
        from django.http import HttpResponse

        from .models import Invoice


        def invoice_detail(request):
            oid = request.GET["id"]
            invoice = Invoice.objects.get(pk=oid, owner=request.user)
            return HttpResponse(invoice.body)
        """)
    assert "PY_IDOR_OBJECT_FETCH" not in _ids(findings)


def test_py_idor_constant_id_stays_dark(tmp_path):
    findings = _sast(tmp_path, "views.py", """\
        from django.http import HttpResponse

        from .models import Invoice

        WELCOME_ID = 1


        def welcome_invoice(request):
            oid = WELCOME_ID
            invoice = Invoice.objects.get(pk=oid)
            return HttpResponse(invoice.body)
        """)
    assert "PY_IDOR_OBJECT_FETCH" not in _ids(findings)


def test_js_idor_intermediate_owned_fetch_stays_dark(tmp_path):
    findings = _sast(tmp_path, "routes.js", """\
        const express = require("express");
        const router = express.Router();

        router.get("/invoice", async (req, res) => {
          const id = req.params.id;
          const invoice = await Invoice.findByPk(id, { where: { userId: req.user.id } });
          res.json(invoice);
        });
        """)
    assert "NODE_IDOR_OBJECT_FETCH" not in _ids(findings)
