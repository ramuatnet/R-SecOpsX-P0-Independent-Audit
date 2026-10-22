# -*- coding: utf-8 -*-
r"""TLS-bypass and SSRF arm coverage (2026-10-22, test-only).

Two families shipped rules with NO positive test of their own, so a
regression in the pattern (or in a shared gate such as the SSRF
client-side/config-endpoint filters) would have been invisible:

  TLS (``vuln == "tls_bypass"``, 7 rules in ``scanner/sast.py``)
      PY_TLS_CERT_VALIDATION_DISABLED, JAVA_TLS_TRUST_BYPASS,
      JAVA_TRUSTMANAGER_EMPTY_METHOD, DOTNET_CERT_VALIDATION_BYPASS,
      DOTNET_HTTPCLIENT_CERT_CALLBACK_TRUE, GO_TLS_INSECURE_SKIP_VERIFY,
      PHP_CURL_SSL_VERIFY_DISABLED.

  SSRF (the language arms; ``TAINT_SSRF`` already has its own suite)
      NODE_SSRF_DYNAMIC_URL, GO_SSRF_HTTP_GET, PHP_SSRF_CURL_FILEGET.

Every test is hermetic: one snippet in a ``tmp_path`` file, scanned the
same way the pipeline does (``scanner.sast.scan_file``). Each POSITIVE
asserts the rule fires on the offending line; each NEGATIVE is the
literal-safe / fail-closed counterpart of the same call shape and must
stay dark, so precision is proven rather than asserted. The negation is
never a blanket "no finding in the file": it is the same sink with a
literal or a validating argument.

This file required no scanner change — every rule fired on its own
positive on the first run. It exists so that fact stays true.
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


def _rule_at(findings: list[dict], rule_id: str, line) -> bool:
    return any(
        str(f.get("rule_id") or f.get("id")) == rule_id
        and str(f.get("line")) == str(line)
        for f in findings
    )


# ---------------------------------------------------------------------------
# Python TLS
# ---------------------------------------------------------------------------

def test_py_tls_verify_false_fires(tmp_path):
    rows = _sast(tmp_path, "tls_req.py", """\
        import requests
        requests.get("https://internal.example/api", verify=False)
    """)
    assert _rule_at(rows, "PY_TLS_CERT_VALIDATION_DISABLED", 2), _ids(rows)


def test_py_tls_unverified_context_fires(tmp_path):
    rows = _sast(tmp_path, "tls_ctx.py", """\
        import ssl
        ctx = ssl._create_unverified_context()
        ctx.check_hostname = False
    """)
    assert _rule_at(rows, "PY_TLS_CERT_VALIDATION_DISABLED", 2), _ids(rows)
    assert _rule_at(rows, "PY_TLS_CERT_VALIDATION_DISABLED", 3), _ids(rows)


def test_py_tls_verify_true_stays_dark(tmp_path):
    rows = _sast(tmp_path, "tls_ok.py", """\
        import requests
        requests.get("https://internal.example/api", verify=True)
    """)
    assert "PY_TLS_CERT_VALIDATION_DISABLED" not in _ids(rows), _ids(rows)


# ---------------------------------------------------------------------------
# Java TLS: permissive HostnameVerifier / empty TrustManager
# ---------------------------------------------------------------------------

_JAVA_PERMISSIVE_HOSTNAME = """\
    import javax.net.ssl.*;
    public class Permissive {
        HostnameVerifier allHosts = new HostnameVerifier() {
            public boolean verify(String hostname, SSLSession session) {
                return true;
            }
        };
    }
"""

_JAVA_EMPTY_TRUST = """\
    import java.security.cert.X509Certificate;
    public class EmptyTrust {
        public void checkServerTrusted(X509Certificate[] chain, String authType) {
        }
    }
"""

_JAVA_FAIL_CLOSED = """\
    import javax.net.ssl.*;
    public class FailClosed {
        void call(SSLSocketFactory factory) throws Exception {
            SSLContext ctx = SSLContext.getInstance("TLS");
            // Platform trust store, default hostname verification.
            ctx.init(null, null, null);
            factory.createSocket().startHandshake();
        }
        public void checkServerTrusted(java.security.cert.X509Certificate[] chain,
                String authType) throws java.security.cert.CertificateException {
            if (chain == null || chain.length == 0) {
                throw new java.security.cert.CertificateException("empty chain");
            }
        }
    }
"""


def test_java_tls_permissive_hostname_verifier_fires(tmp_path):
    rows = _sast(tmp_path, "Permissive.java", _JAVA_PERMISSIVE_HOSTNAME)
    # The rule anchors on the permissive declaration and on the
    # verify(..) { return true; } body; both are the same defect.
    assert _rule_at(rows, "JAVA_TLS_TRUST_BYPASS", 3), _ids(rows)
    assert _rule_at(rows, "JAVA_TLS_TRUST_BYPASS", 4), _ids(rows)


def test_java_tls_empty_trustmanager_fires(tmp_path):
    rows = _sast(tmp_path, "EmptyTrust.java", _JAVA_EMPTY_TRUST)
    assert _rule_at(rows, "JAVA_TRUSTMANAGER_EMPTY_METHOD", 3), _ids(rows)


def test_java_tls_fail_closed_trustmanager_stays_dark(tmp_path):
    rows = _sast(tmp_path, "FailClosed.java", _JAVA_FAIL_CLOSED)
    assert "JAVA_TLS_TRUST_BYPASS" not in _ids(rows), _ids(rows)
    assert "JAVA_TRUSTMANAGER_EMPTY_METHOD" not in _ids(rows), _ids(rows)


# ---------------------------------------------------------------------------
# .NET TLS: accept-any callback vs real validation
# ---------------------------------------------------------------------------

def test_dotnet_cert_callback_returning_true_fires(tmp_path):
    rows = _sast(tmp_path, "Permissive.cs", """\
        using System.Net.Http;
        class C {
            void M(HttpClientHandler handler) {
                handler.ServerCertificateCustomValidationCallback = (m, c, ch, e) => true;
            }
        }
    """)
    assert _rule_at(rows, "DOTNET_CERT_VALIDATION_BYPASS", 4), _ids(rows)


def test_dotnet_dangerous_validator_fires(tmp_path):
    rows = _sast(tmp_path, "Dangerous.cs", """\
        using System.Net.Http;
        class C {
            void M(HttpClientHandler handler) {
                handler.ServerCertificateCustomValidationCallback =
                    HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
            }
        }
    """)
    assert _rule_at(rows, "DOTNET_HTTPCLIENT_CERT_CALLBACK_TRUE", 5), _ids(rows)


def test_dotnet_real_validation_callback_stays_dark(tmp_path):
    rows = _sast(tmp_path, "Strict.cs", """\
        using System.Net.Http;
        class C {
            void M(HttpClientHandler handler) {
                handler.ServerCertificateCustomValidationCallback =
                    (m, c, ch, e) => e == SslPolicyErrors.None;
            }
        }
    """)
    assert "DOTNET_CERT_VALIDATION_BYPASS" not in _ids(rows), _ids(rows)
    assert "DOTNET_HTTPCLIENT_CERT_CALLBACK_TRUE" not in _ids(rows), _ids(rows)


# ---------------------------------------------------------------------------
# Go TLS
# ---------------------------------------------------------------------------

def test_go_tls_insecure_skip_verify_fires(tmp_path):
    rows = _sast(tmp_path, "tls.go", """\
        package main
        import "crypto/tls"
        func client() *tls.Config {
            return &tls.Config{InsecureSkipVerify: true}
        }
    """)
    assert _rule_at(rows, "GO_TLS_INSECURE_SKIP_VERIFY", 4), _ids(rows)


def test_go_tls_verified_config_stays_dark(tmp_path):
    rows = _sast(tmp_path, "tls_ok.go", """\
        package main
        import "crypto/tls"
        func client() *tls.Config {
            return &tls.Config{InsecureSkipVerify: false, MinVersion: tls.VersionTLS12}
        }
    """)
    assert "GO_TLS_INSECURE_SKIP_VERIFY" not in _ids(rows), _ids(rows)


# ---------------------------------------------------------------------------
# PHP TLS
# ---------------------------------------------------------------------------

def test_php_curl_ssl_verify_disabled_fires(tmp_path):
    rows = _sast(tmp_path, "tls.php", """\
        <?php
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
    """)
    assert _rule_at(rows, "PHP_CURL_SSL_VERIFY_DISABLED", 3), _ids(rows)
    assert _rule_at(rows, "PHP_CURL_SSL_VERIFY_DISABLED", 4), _ids(rows)


def test_php_curl_ssl_verify_enabled_stays_dark(tmp_path):
    rows = _sast(tmp_path, "tls_ok.php", """\
        <?php
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
    """)
    assert "PHP_CURL_SSL_VERIFY_DISABLED" not in _ids(rows), _ids(rows)


# ---------------------------------------------------------------------------
# SSRF: Node
# ---------------------------------------------------------------------------

def test_node_ssrf_fetch_from_request_fires(tmp_path):
    rows = _sast(tmp_path, "ssrf.js", """\
        const express = require('express');
        const app = express();
        app.get('/proxy', async (req, res) => {
            const upstream = await fetch(req.query.url);
            res.send(await upstream.text());
        });
    """)
    assert _rule_at(rows, "NODE_SSRF_DYNAMIC_URL", 4), _ids(rows)


def test_node_ssrf_axios_from_body_fires(tmp_path):
    rows = _sast(tmp_path, "ssrf2.ts", """\
        export async function proxy(req: any) {
            return axios.get(req.body.target);
        }
    """)
    assert _rule_at(rows, "NODE_SSRF_DYNAMIC_URL", 2), _ids(rows)


def test_node_ssrf_literal_url_stays_dark(tmp_path):
    rows = _sast(tmp_path, "ssrf_ok.js", """\
        async function health() {
            return fetch("https://api.example.com/status");
        }
    """)
    assert "NODE_SSRF_DYNAMIC_URL" not in _ids(rows), _ids(rows)


# ---------------------------------------------------------------------------
# SSRF: Go
# ---------------------------------------------------------------------------

def test_go_ssrf_form_value_fires(tmp_path):
    rows = _sast(tmp_path, "ssrf.go", """\
        package main
        import "net/http"
        func proxy(w http.ResponseWriter, r *http.Request) {
            resp, err := http.Get(r.FormValue("url"))
            _ = resp
            _ = err
        }
    """)
    assert _rule_at(rows, "GO_SSRF_HTTP_GET", 4), _ids(rows)


def test_go_ssrf_new_request_query_fires(tmp_path):
    rows = _sast(tmp_path, "ssrf2.go", """\
        package main
        import "net/http"
        func proxy(r *http.Request) {
            req, err := http.NewRequest("GET", r.URL.Query().Get("u"), nil)
            _ = req
            _ = err
        }
    """)
    assert _rule_at(rows, "GO_SSRF_HTTP_GET", 4), _ids(rows)


def test_go_ssrf_literal_url_stays_dark(tmp_path):
    rows = _sast(tmp_path, "ssrf_ok.go", """\
        package main
        import "net/http"
        func health() {
            resp, err := http.Get("https://api.example.com/status")
            _ = resp
            _ = err
        }
    """)
    assert "GO_SSRF_HTTP_GET" not in _ids(rows), _ids(rows)


# ---------------------------------------------------------------------------
# SSRF: PHP
# ---------------------------------------------------------------------------

def test_php_ssrf_curl_url_from_get_fires(tmp_path):
    rows = _sast(tmp_path, "ssrf.php", """\
        <?php
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $_GET['url']);
        curl_exec($ch);
    """)
    assert _rule_at(rows, "PHP_SSRF_CURL_FILEGET", 3), _ids(rows)


def test_php_ssrf_file_get_contents_from_post_fires(tmp_path):
    rows = _sast(tmp_path, "ssrf2.php", """\
        <?php
        $body = file_get_contents($_POST['target']);
        echo $body;
    """)
    assert _rule_at(rows, "PHP_SSRF_CURL_FILEGET", 2), _ids(rows)


def test_php_ssrf_literal_url_stays_dark(tmp_path):
    rows = _sast(tmp_path, "ssrf_ok.php", """\
        <?php
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, "https://api.example.com/status");
        $body = file_get_contents("https://api.example.com/health");
    """)
    assert "PHP_SSRF_CURL_FILEGET" not in _ids(rows), _ids(rows)
