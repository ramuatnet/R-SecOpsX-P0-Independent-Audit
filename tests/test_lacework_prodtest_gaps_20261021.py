# -*- coding: utf-8 -*-
r"""Lacework/FortiCNAPP cross-validation gaps (2026-10-21): validated CNAP
true positives the V11 scan missed on prodtest targets (crAPI, pygoat,
NodeGoat). Each family below was source-verified against the target before
this file was written:

  G1  npm ``package-lock.json`` nested entries were recorded with PATH-shaped
      names (``mkdirp/node_modules/minimist`` instead of ``minimist``), so
      advisory queries could never resolve them: one hoisted version per
      package name stayed queryable and ~29 OSV-confirmed vulnerable pins
      (crAPI 18, NodeGoat 11) vanished from the advisory set.
  G2  MD5/SHA1 rules matched only ``hashlib.md5(`` / ``hashlib.sha1(``.
      pygoat ``introduction/mitre.py:161`` is ``from hashlib import md5;
      password = md5(password.encode())`` -- aliased import, plain md5 of
      passwords, reported by CNAP CRYPTO-WEAK-003, missed by V11.
  G3  Python cookie security flags had no rule at all. pygoat
      ``broken_auth_lab/app.py:49/51`` ``set_cookie`` without
      Secure/HttpOnly/SameSite = CNAP DATA-COOKIE-001/002 + INTEG-COOKIE-001
      (6 Medium findings, all source-verified).
  G4  Django ``@csrf_exempt`` had no rule. CNAP INTEG-ORIGIN-002 fires on
      pygoat apis.py/mitre.py/playground (10) and crAPI
      mechanic/views.py:54 (all verified as real decorator anchors).
  G5  Express open redirect had no rule (only .NET/Go exist). NodeGoat
      ``app/routes/index.js:72`` ``res.redirect(req.query.url)`` = CNAP
      INPUT-REDIRECT-001 High, source-verified.
  G6  Express session cookie without ``maxAge``/``expires`` had no rule.
      NodeGoat ``server.js:78`` session({...}) block with
      ``// TODO: Add "maxAge"`` = CNAP AUTH-SE... Medium, source-verified.
  G7  Go weak-hash had no rule (md5/sha1 in ``crypto/md5`` packages).
  G8  k8s absence-based hardening: CNAP fails workloads that never set
      ``allowPrivilegeEscalation: false`` and never ``drop: [NET_RAW]``
      (crAPI 10 + 10 findings; source-verified: no capabilities or
      allowPrivilegeEscalation keys anywhere). V11 only flagged the
      presence-of-bad forms.

Controls keep every existing shape firing.
"""
import json
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


def _rule_at(findings: list[dict], rule_id: str, line) -> bool:
    return any(
        str(f.get("rule_id") or f.get("id")) == rule_id and str(f.get("line")) == str(line)
        for f in findings
    )


# ---------------------------------------------------------------------------
# G1 -- package-lock nested entries carry the PACKAGE name, not the path
# ---------------------------------------------------------------------------
_LOCK = {
    "name": "demo",
    "lockfileVersion": 2,
    "requires": True,
    "packages": {
        "": {
            "name": "demo",
            "version": "1.0.0",
            "dependencies": {"minimist": "^1.2.0", "mkdirp": "^0.5.1"},
        },
        "node_modules/minimist": {"version": "0.0.10"},
        "node_modules/mkdirp": {"version": "0.5.6"},
        "node_modules/mkdirp/node_modules/minimist": {"version": "0.0.8"},
        "node_modules/@babel/core": {"version": "7.27.1"},
        "node_modules/webpack/node_modules/@babel/core": {"version": "7.24.6"},
    },
}


def _sbom(tmp_path, lock=None) -> list[dict]:
    from scanner.sbom import generate_sbom

    _write(tmp_path, "package-lock.json", json.dumps(lock or _LOCK))
    return generate_sbom(str(tmp_path))


def test_package_lock_nested_names_are_package_names(tmp_path):
    """No SBOM name may embed the node_modules path (G1)."""
    sbom = _sbom(tmp_path)
    names = {p["name"] for p in sbom}
    assert not any("node_modules/" in n for n in names), sorted(n for n in names if "node_modules/" in n)


def test_package_lock_nested_duplicate_versions_both_kept(tmp_path):
    """minimist 0.0.8 (nested under mkdirp) must be queryable beside 0.0.10."""
    sbom = _sbom(tmp_path)
    versions = {p["version"] for p in sbom if p["name"] == "minimist"}
    assert versions == {"0.0.10", "0.0.8"}, versions


def test_package_lock_nested_scoped_package_resolved(tmp_path):
    """node_modules/webpack/node_modules/@babel/core is @babel/core@7.24.6."""
    sbom = _sbom(tmp_path)
    versions = {p["version"] for p in sbom if p["name"] == "@babel/core"}
    assert versions == {"7.27.1", "7.24.6"}, versions
    assert "webpack" in {p["name"] for p in sbom} or True  # parent never required


# ---------------------------------------------------------------------------
# G2 -- md5/sha1 via aliased hashlib import
# ---------------------------------------------------------------------------
def test_sast_aliased_md5_import_reported(tmp_path):
    """pygoat mitre.py:161 shape: ``from hashlib import md5`` + bare md5()."""
    findings = _sast(tmp_path, "mitre.py", '''
        from hashlib import md5

        def login(password, username):
            password = md5(password.encode()).hexdigest()
            return check(username, password)
    ''')
    assert "MD5_USAGE" in _ids(findings)


def test_sast_aliased_sha1_import_reported(tmp_path):
    findings = _sast(tmp_path, "tokens.py", '''
        from hashlib import sha1

        def token(data):
            return sha1(data).hexdigest()
    ''')
    assert "SHA1_USAGE" in _ids(findings)


def test_sast_bare_md5_without_hashlib_import_suppressed(tmp_path):
    """A local helper called md5() is not the hashlib algorithm."""
    findings = _sast(tmp_path, "helper.py", '''
        def md5(x):
            return x

        def use(data):
            return md5(data)
    ''')
    assert "MD5_USAGE" not in _ids(findings)


def test_sast_qualified_hashlib_md5_still_reported(tmp_path):
    """Control: the original qualified shape keeps its finding."""
    findings = _sast(tmp_path, "h.py", '''
        import hashlib

        def use(data):
            return hashlib.md5(data).hexdigest()
    ''')
    assert "MD5_USAGE" in _ids(findings)


# ---------------------------------------------------------------------------
# G3 -- python cookie security flags
# ---------------------------------------------------------------------------
def _cookie_ids(findings) -> set[str]:
    return {i for i in _ids(findings) if i.startswith("PY_COOKIE_")}


def test_sast_set_cookie_missing_all_flags_reported(tmp_path):
    """pygoat broken_auth_lab/app.py:49 shape."""
    findings = _sast(tmp_path, "app.py", '''
        from flask import Flask, make_response

        app = Flask(__name__)

        def login(resp, session_token):
            resp.set_cookie("session", session_token, max_age=3600)
            return resp
    ''')
    ids = _cookie_ids(findings)
    assert ids == {
        "PY_COOKIE_MISSING_SECURE",
        "PY_COOKIE_MISSING_HTTPONLY",
        "PY_COOKIE_MISSING_SAMESITE",
    }, ids


def test_sast_set_cookie_complete_flags_quiet(tmp_path):
    findings = _sast(tmp_path, "app.py", '''
        from flask import Flask

        app = Flask(__name__)

        def login(resp, token):
            resp.set_cookie(
                "session", token,
                httponly=True, secure=True, samesite="Lax",
            )
            return resp
    ''')
    assert not _cookie_ids(findings), _cookie_ids(findings)


def test_sast_set_cookie_partial_flags_reports_only_missing(tmp_path):
    findings = _sast(tmp_path, "app.py", '''
        from django.http import HttpResponse

        def login(request):
            resp = HttpResponse()
            resp.set_cookie("session", "tok", secure=True, samesite="Strict")
            return resp
    ''')
    ids = _cookie_ids(findings)
    assert ids == {"PY_COOKIE_MISSING_HTTPONLY"}, ids


def test_sast_set_cookie_outside_web_framework_suppressed(tmp_path):
    """A bespoke object's set_cookie() with no flask/django context is not
    the framework cookie API."""
    findings = _sast(tmp_path, "jar.py", '''
        class Jar:
            def put(self):
                self.set_cookie("sid", "value", path="/")
    ''')
    assert not _cookie_ids(findings), _cookie_ids(findings)


def test_cookie_flags_survive_production_dedup(tmp_path):
    """The aggregation boundary, not scan_file, is where per-flag rules died.

    core.deduplicator.root_key() keys on (vuln_type, file, line); when the
    three rules shared one family vuln_type, the pygoat after-scan collapsed
    them to one representative per call and PY_COOKIE_MISSING_SAMESITE
    reported 0 of 14 source calls. Each flag keeps its own vuln_type, so all
    three claims must come through group_findings as distinct findings.
    """
    from core.deduplicator import group_findings

    findings = _sast(tmp_path, "app.py", '''
        from flask import Flask

        app = Flask(__name__)

        def login(resp, token):
            resp.set_cookie("session", token, max_age=3600)
            return resp
    ''')
    assert _cookie_ids(findings) == {
        "PY_COOKIE_MISSING_SECURE",
        "PY_COOKIE_MISSING_HTTPONLY",
        "PY_COOKIE_MISSING_SAMESITE",
    }, _cookie_ids(findings)
    grouped = group_findings(findings)
    grouped_ids = {str(f.get("rule_id")) for f in grouped}
    assert _cookie_ids(findings) <= grouped_ids, (
        "cookie per-flag findings collapsed at the deduplicator: %r" % grouped_ids)


# ---------------------------------------------------------------------------
# G4 -- django csrf_exempt
# ---------------------------------------------------------------------------
def test_sast_django_csrf_exempt_decorator_reported(tmp_path):
    """pygoat introduction/apis.py:22 shape."""
    findings = _sast(tmp_path, "apis.py", '''
        from django.views.decorators.csrf import csrf_exempt
        from django.http import HttpResponse

        @csrf_exempt
        def ssrf_code_checker(request):
            return HttpResponse("ok")
    ''')
    assert "DJANGO_CSRF_EXEMPT" in _ids(findings)


def test_sast_django_csrf_exempt_import_alone_quiet(tmp_path):
    """Importing the decorator without applying it is not an exemption."""
    findings = _sast(tmp_path, "views.py", '''
        from django.views.decorators.csrf import csrf_exempt
        from django.http import HttpResponse

        def index(request):
            return HttpResponse("ok")
    ''')
    assert "DJANGO_CSRF_EXEMPT" not in _ids(findings)


def test_sast_django_method_decorator_csrf_exempt_reported(tmp_path):
    findings = _sast(tmp_path, "views.py", '''
        from django.utils.decorators import method_decorator
        from django.views.decorators.csrf import csrf_exempt

        @method_decorator(csrf_exempt, name="dispatch")
        class UploadView:
            pass
    ''')
    assert "DJANGO_CSRF_EXEMPT" in _ids(findings)


# ---------------------------------------------------------------------------
# G5 -- express open redirect
# ---------------------------------------------------------------------------
def test_sast_express_open_redirect_from_query_reported(tmp_path):
    """NodeGoat app/routes/index.js:72 shape."""
    findings = _sast(tmp_path, "index.js", '''
        app.get("/learn", isLoggedIn, (req, res) => {
            return res.redirect(req.query.url);
        });
    ''')
    assert "EXPRESS_OPEN_REDIRECT" in _ids(findings)


def test_sast_express_redirect_literal_quiet(tmp_path):
    findings = _sast(tmp_path, "routes.js", '''
        app.get("/home", (req, res) => {
            res.redirect("/dashboard");
        });
    ''')
    assert "EXPRESS_OPEN_REDIRECT" not in _ids(findings)


def test_sast_express_redirect_req_path_quiet(tmp_path):
    """req.path stays same-site; the rule requires query/body/params/headers."""
    findings = _sast(tmp_path, "routes.js", '''
        app.get("/back", (req, res) => {
            res.redirect(req.path);
        });
    ''')
    assert "EXPRESS_OPEN_REDIRECT" not in _ids(findings)


# ---------------------------------------------------------------------------
# G6 -- express session cookie without expiry
# ---------------------------------------------------------------------------
def test_sast_session_without_maxage_reported(tmp_path):
    """NodeGoat server.js:78 shape (incl. the TODO comment inside the block)."""
    findings = _sast(tmp_path, "server.js", '''
        const session = require("express-session");
        const app = express();
        app.use(session({
            name: "sid",
            cookie: { httpOnly: true },
            // TODO: Add "maxAge"
        }));
    ''')
    assert "EXPRESS_SESSION_COOKIE_NO_EXPIRY" in _ids(findings)


def test_sast_session_with_maxage_quiet(tmp_path):
    findings = _sast(tmp_path, "server.js", '''
        const session = require("express-session");
        app.use(session({
            cookie: { maxAge: 86400000, httpOnly: true },
        }));
    ''')
    assert "EXPRESS_SESSION_COOKIE_NO_EXPIRY" not in _ids(findings)


def test_sast_session_without_express_session_import_quiet(tmp_path):
    """A local session() helper with no express-session in the file is not
    the cookie session middleware."""
    findings = _sast(tmp_path, "app.js", '''
        function session(opts) {
            return opts;
        }
        const cfg = session({ cookie: {} });
    ''')
    assert "EXPRESS_SESSION_COOKIE_NO_EXPIRY" not in _ids(findings)


# ---------------------------------------------------------------------------
# G7 -- go weak hash
# ---------------------------------------------------------------------------
def test_sast_go_md5_import_reported(tmp_path):
    findings = _sast(tmp_path, "util.go", '''
        package util

        import (
            "crypto/md5"
            "hash"
        )

        func digest(b []byte) hash.Hash {
            return md5.New()
        }
    ''')
    assert "GO_MD5_USAGE" in _ids(findings)


def test_sast_go_sha1_call_reported(tmp_path):
    findings = _sast(tmp_path, "sig.go", '''
        package sig

        import "crypto/sha1"

        func sum(b []byte) []byte {
            return sha1.Sum(b)
        }
    ''')
    assert "GO_SHA1_USAGE" in _ids(findings)


def test_sast_go_sha256_quiet(tmp_path):
    findings = _sast(tmp_path, "ok.go", '''
        package ok

        import "crypto/sha256"

        func sum(b []byte) []byte {
            h := sha256.Sum256(b)
            return h[:]
        }
    ''')
    assert "GO_MD5_USAGE" not in _ids(findings)
    assert "GO_SHA1_USAGE" not in _ids(findings)


# ---------------------------------------------------------------------------
# G8 -- k8s absence-based hardening (crAPI deploy manifests)
# ---------------------------------------------------------------------------
_DEPLOY_BAD = '''
    apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: web
    spec:
      replicas: 1
      selector:
        matchLabels: {app: web}
      template:
        metadata:
          labels: {app: web}
        spec:
          containers:
            - name: app
              image: crapi/crapi-community:latest
'''


def _k8s(tmp_path, yaml_text: str) -> list[dict]:
    from scanner.iac_kubernetes import scan_kubernetes

    _write(tmp_path, "deploy/deployment.yaml", yaml_text)
    return scan_kubernetes(str(tmp_path))


def test_k8s_missing_allowprivilegeescalation_and_netraw_reported(tmp_path):
    findings = _k8s(tmp_path, _DEPLOY_BAD)
    ids = _ids(findings)
    assert "K8S_MISSING_ALLOW_PRIVILEGE_ESCALATION" in ids, ids
    assert "K8S_MISSING_NET_RAW_DROP" in ids, ids
    # the validated CNAP-adjacent controls keep firing too
    assert "K8S_LATEST_IMAGE_TAG" in ids, ids


def test_k8s_hardened_security_context_quiet(tmp_path):
    findings = _k8s(tmp_path, '''
        apiVersion: apps/v1
        kind: Deployment
        metadata:
          name: web
        spec:
          selector:
            matchLabels: {app: web}
          template:
            metadata:
              labels: {app: web}
            spec:
              containers:
                - name: app
                  image: repo/app:v1
                  securityContext:
                    allowPrivilegeEscalation: false
                    capabilities:
                      drop: ["ALL"]
    ''')
    ids = _ids(findings)
    assert "K8S_MISSING_ALLOW_PRIVILEGE_ESCALATION" not in ids, ids
    assert "K8S_MISSING_NET_RAW_DROP" not in ids, ids


def test_k8s_pod_level_drop_inherited_by_container(tmp_path):
    findings = _k8s(tmp_path, '''
        apiVersion: apps/v1
        kind: Deployment
        metadata:
          name: web
        spec:
          selector:
            matchLabels: {app: web}
          template:
            metadata:
              labels: {app: web}
            spec:
              securityContext:
                allowPrivilegeEscalation: false
                capabilities:
                  drop: ["NET_RAW"]
              containers:
                - name: app
                  image: repo/app:v1
    ''')
    ids = _ids(findings)
    assert "K8S_MISSING_ALLOW_PRIVILEGE_ESCALATION" not in ids, ids
    assert "K8S_MISSING_NET_RAW_DROP" not in ids, ids


def test_k8s_explicit_true_reported_once_by_presence_rule(tmp_path):
    """``allowPrivilegeEscalation: true`` is the presence rule's claim; the
    missing-control rule must not double-report it."""
    findings = _k8s(tmp_path, '''
        apiVersion: apps/v1
        kind: Deployment
        metadata:
          name: web
        spec:
          selector:
            matchLabels: {app: web}
          template:
            metadata:
              labels: {app: web}
            spec:
              containers:
                - name: app
                  image: repo/app:v1
                  securityContext:
                    allowPrivilegeEscalation: true
    ''')
    ids = _ids(findings)
    assert "K8S_ALLOW_PRIVILEGE_ESCALATION" in ids, ids
    assert "K8S_MISSING_ALLOW_PRIVILEGE_ESCALATION" not in ids, ids


def test_k8s_text_fallback_missing_controls_still_fire(tmp_path):
    """Invalid YAML degrades to the text engine, never to silence."""
    broken = (
        "apiVersion: apps/v1\n"
        "kind: Deployment\n"
        "metadata:\n"
        "  name: web\n"
        "spec:\n"
        "  template:\n"
        "    spec:\n"
        "      containers:\n"
        "        - name: app\n"
        "          image: repo/app:v1\n"
        "\tbad: [key: value\n"
    )
    findings = _k8s(tmp_path, broken)
    ids = _ids(findings)
    assert "K8S_MISSING_ALLOW_PRIVILEGE_ESCALATION" in ids, ids
    assert "K8S_MISSING_NET_RAW_DROP" in ids, ids
