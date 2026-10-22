# -*- coding: utf-8 -*-
r"""Coverage-audit gap fixes (2026-10-22): detection families the audit
verified were absent. Red-first: every positive test below was observed
failing (rule id absent from scan output) before the rule was implemented.
Each family lists a negative control that must stay dark so precision is
provable, not asserted.

Families and the honest sub-shape shipped:

  F1 JS/TS XSS      NODE_DOM_XSS (innerHTML/outerHTML/insertAdjacentHTML/
                     document.write fed a request/DOM source, literals and
                     escaped values dark), EXPRESS_REFLECTED_XSS
                     (res.send/end/write reflecting req.query|params|body).
  F2 C/C++ memory    CPP_UNSAFE_STRING_FUNCTION (strcpy/strcat/gets/sprintf/
                     vsprintf), CPP_FORMAT_STRING (printf-family with a
                     non-literal format arg), CPP_USE_AFTER_FREE (free(p)
                     then p->/p[ before any reassignment).
  F3 REST IDOR       NODE_IDOR_OBJECT_FETCH / PY_IDOR_OBJECT_FETCH: ORM
                     fetch by a request-supplied id inside a handler with NO
                     ownership predicate in the same function.
  F4 Session/cookie  FLASK_SESSION_FIXATION (login_user without session
                     rotation), DJANGO_SESSION_COOKIE_INSECURE (explicit
                     SESSION_COOKIE_SECURE/HTTPONLY=False), 
                     EXPRESS_COOKIE_MISSING_SECURE (res.cookie without
                     secure:true).
  F5 Fill-ins        PY_XML_ENTITIES (lxml parse, entities on by default),
                     PHP_XXE_LIBXML, PY_REDOS_NESTED_QUANTIFIER,
                     PHP_REDOS_NESTED_QUANTIFIER, PY_LOG_INJECTION,
                     PHP_LOG_INJECTION, HOST_HEADER_INJECTION (php/python),
                     NODE_WEBSOCKET_SINK, PY_TAR_EXTRACTALL (tar slip;
                     zipfile.extractall already covered by GENERIC_ZIPSLIP).

Documented-as-limitation families (no dishonest rule shipped): HTTP
request smuggling (no provable app-level static shape), DNS rebinding
(runtime-only), Flask/CSRF absence rules (FP-prone, Express already covered).
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
# F1 -- JS/TS XSS (DOM sinks + Express reflected)
# ---------------------------------------------------------------------------

def test_node_dom_xss_innerhtml_from_request(tmp_path):
    rows = _sast(tmp_path, "dom.js",
                 "function render(v){ el.innerHTML = req.query.x; }\n")
    assert _rule_at(rows, "NODE_DOM_XSS", 1), _ids(rows)


def test_node_dom_xss_outerhtml_insertadjacent_documentwrite(tmp_path):
    rows = _sast(tmp_path, "dom2.js",
                 "a.outerHTML = location.hash;\n"
                 "d.insertAdjacentHTML('beforeend', req.body.html);\n"
                 "document.write(req.params.q);\n")
    assert _rule_at(rows, "NODE_DOM_XSS", 1), _ids(rows)
    assert _rule_at(rows, "NODE_DOM_XSS", 2), _ids(rows)
    assert _rule_at(rows, "NODE_DOM_XSS", 3), _ids(rows)


def test_node_dom_xss_one_hop_variable(tmp_path):
    rows = _sast(tmp_path, "dom3.js",
                 "const h = req.query.html;\n"
                 "el.innerHTML = h;\n")
    assert _rule_at(rows, "NODE_DOM_XSS", 2), _ids(rows)


def test_node_dom_xss_literal_stays_dark(tmp_path):
    rows = _sast(tmp_path, "lit.js",
                 "el.innerHTML = '<b>static</b>';\n")
    assert "NODE_DOM_XSS" not in _ids(rows), _ids(rows)


def test_node_dom_xss_escaped_stays_dark(tmp_path):
    rows = _sast(tmp_path, "esc.js",
                 "el.innerHTML = DOMPurify.sanitize(req.query.x);\n"
                 "el2.innerHTML = escapeHtml(req.body.y);\n")
    assert "NODE_DOM_XSS" not in _ids(rows), _ids(rows)


def test_express_reflected_xss_positive(tmp_path):
    rows = _sast(tmp_path, "refl.js",
                 "app.get('/x', (req, res) => {\n"
                 "  res.send('<h1>' + req.query.name + '</h1>');\n"
                 "});\n")
    assert _rule_at(rows, "EXPRESS_REFLECTED_XSS", 2), _ids(rows)


def test_express_reflected_xss_literal_stays_dark(tmp_path):
    rows = _sast(tmp_path, "refl2.js",
                 "app.get('/x', (req, res) => res.send('<h1>static</h1>'));\n")
    assert "EXPRESS_REFLECTED_XSS" not in _ids(rows), _ids(rows)


def test_express_reflected_xss_escaped_stays_dark(tmp_path):
    rows = _sast(tmp_path, "refl3.js",
                 "res.send(escapeHtml(req.query.name));\n")
    assert "EXPRESS_REFLECTED_XSS" not in _ids(rows), _ids(rows)


# ---------------------------------------------------------------------------
# F2 -- C/C++ memory safety
# ---------------------------------------------------------------------------

def test_cpp_unsafe_string_functions_positive(tmp_path):
    rows = _sast(tmp_path, "u.c",
                 "strcpy(dst, src);\n"
                 "strcat(dst, src);\n"
                 "gets(buf);\n"
                 "vsprintf(dst, fmt, ap);\n")
    for ln in (1, 2, 3, 4):
        assert _rule_at(rows, "CPP_UNSAFE_STRING_FUNCTION", ln), (_ids(rows), ln)


def test_cpp_unsafe_string_bounded_variants_stay_dark(tmp_path):
    rows = _sast(tmp_path, "safe.c",
                 "strncpy(dst, src, n);\n"
                 "strncat(dst, src, n);\n"
                 "snprintf(dst, n, \"%s\", src);\n")
    assert "CPP_UNSAFE_STRING_FUNCTION" not in _ids(rows), _ids(rows)


def test_cpp_format_string_variable_format_positive(tmp_path):
    rows = _sast(tmp_path, "fmt.c",
                 "printf(buf);\n"
                 "fprintf(fp, fmt);\n")
    assert _rule_at(rows, "CPP_FORMAT_STRING", 1), _ids(rows)
    assert _rule_at(rows, "CPP_FORMAT_STRING", 2), _ids(rows)


def test_cpp_format_string_literal_format_stays_dark(tmp_path):
    rows = _sast(tmp_path, "fmt2.c",
                 "printf(\"%s\", buf);\n"
                 "fprintf(fp, \"%d\\n\", n);\n")
    assert "CPP_FORMAT_STRING" not in _ids(rows), _ids(rows)


def test_cpp_use_after_free_positive(tmp_path):
    rows = _sast(tmp_path, "uaf.c",
                 "free(p);\n"
                 "p->next = NULL;\n")
    assert _rule_at(rows, "CPP_USE_AFTER_FREE", 1), _ids(rows)


def test_cpp_use_after_free_null_then_dark(tmp_path):
    rows = _sast(tmp_path, "uaf2.c",
                 "free(p);\n"
                 "p = NULL;\n")
    assert "CPP_USE_AFTER_FREE" not in _ids(rows), _ids(rows)


def test_cpp_use_after_free_no_deref_stays_dark(tmp_path):
    rows = _sast(tmp_path, "uaf3.c",
                 "free(p);\n"
                 "count -= 1;\n")
    assert "CPP_USE_AFTER_FREE" not in _ids(rows), _ids(rows)


# ---------------------------------------------------------------------------
# F3 -- REST IDOR as a finding (ownership-gated)
# ---------------------------------------------------------------------------

def test_node_idor_object_fetch_positive(tmp_path):
    rows = _sast(tmp_path, "idor.js",
                 "router.get('/order/:id', async (req, res) => {\n"
                 "  const o = await Order.findByPk(req.params.id);\n"
                 "  res.json(o);\n"
                 "});\n")
    assert _rule_at(rows, "NODE_IDOR_OBJECT_FETCH", 2), _ids(rows)


def test_node_idor_ownership_checked_stays_dark(tmp_path):
    rows = _sast(tmp_path, "idor2.js",
                 "router.get('/order/:id', async (req, res) => {\n"
                 "  const o = await Order.findByPk(req.params.id);\n"
                 "  if (o.userId !== req.user.id) return res.sendStatus(403);\n"
                 "  res.json(o);\n"
                 "});\n")
    assert "NODE_IDOR_OBJECT_FETCH" not in _ids(rows), _ids(rows)


def test_node_idor_non_request_id_stays_dark(tmp_path):
    rows = _sast(tmp_path, "idor3.js",
                 "const o = await Order.findByPk(knownId);\n")
    assert "NODE_IDOR_OBJECT_FETCH" not in _ids(rows), _ids(rows)


def test_py_idor_object_fetch_positive(tmp_path):
    rows = _sast(tmp_path, "idor.py",
                 "def order(request, pk):\n"
                 "    o = Order.objects.get(pk=request.GET['id'])\n"
                 "    return JsonResponse(o)\n")
    assert _rule_at(rows, "PY_IDOR_OBJECT_FETCH", 2), _ids(rows)


def test_py_idor_ownership_checked_stays_dark(tmp_path):
    rows = _sast(tmp_path, "idor2.py",
                 "def order(request):\n"
                 "    o = Order.objects.get(pk=request.GET['id'])\n"
                 "    if o.user != request.user:\n"
                 "        raise PermissionDenied\n"
                 "    return JsonResponse(o)\n")
    assert "PY_IDOR_OBJECT_FETCH" not in _ids(rows), _ids(rows)


def test_py_idor_non_request_id_stays_dark(tmp_path):
    rows = _sast(tmp_path, "idor3.py",
                 "def order(request):\n"
                 "    o = Order.objects.get(pk=123)\n"
                 "    return JsonResponse(o)\n")
    assert "PY_IDOR_OBJECT_FETCH" not in _ids(rows), _ids(rows)


# ---------------------------------------------------------------------------
# F4 -- Session fixation + cookie flags
# ---------------------------------------------------------------------------

def test_flask_session_fixation_positive(tmp_path):
    rows = _sast(tmp_path, "fix.py",
                 "from flask_login import login_user\n"
                 "def do_login(user):\n"
                 "    login_user(user)\n")
    assert _rule_at(rows, "FLASK_SESSION_FIXATION", 3), _ids(rows)


def test_flask_session_fixation_rotated_stays_dark(tmp_path):
    rows = _sast(tmp_path, "fix2.py",
                 "from flask_login import login_user\n"
                 "def do_login(user):\n"
                 "    session.clear()\n"
                 "    login_user(user)\n")
    assert "FLASK_SESSION_FIXATION" not in _ids(rows), _ids(rows)


def test_django_session_cookie_insecure_positive(tmp_path):
    rows = _sast(tmp_path, "settings.py",
                 "SESSION_COOKIE_SECURE = False\n"
                 "SESSION_COOKIE_HTTPONLY = False\n")
    assert _rule_at(rows, "DJANGO_SESSION_COOKIE_INSECURE", 1), _ids(rows)
    assert _rule_at(rows, "DJANGO_SESSION_COOKIE_INSECURE", 2), _ids(rows)


def test_django_session_cookie_secure_stays_dark(tmp_path):
    rows = _sast(tmp_path, "settings2.py",
                 "SESSION_COOKIE_SECURE = True\n"
                 "SESSION_COOKIE_HTTPONLY = True\n")
    assert "DJANGO_SESSION_COOKIE_INSECURE" not in _ids(rows), _ids(rows)


def test_express_cookie_missing_secure_positive(tmp_path):
    rows = _sast(tmp_path, "ck.js",
                 "res.cookie('sid', val);\n")
    assert _rule_at(rows, "EXPRESS_COOKIE_MISSING_SECURE", 1), _ids(rows)


def test_express_cookie_secure_stays_dark(tmp_path):
    rows = _sast(tmp_path, "ck2.js",
                 "res.cookie('sid', val, { secure: true });\n")
    assert "EXPRESS_COOKIE_MISSING_SECURE" not in _ids(rows), _ids(rows)


# ---------------------------------------------------------------------------
# F5 -- single-arm fill-ins
# ---------------------------------------------------------------------------

def test_py_lxml_xxe_positive(tmp_path):
    rows = _sast(tmp_path, "xxe.py",
                 "from lxml import etree\n"
                 "root = etree.fromstring(untrusted)\n")
    assert _rule_at(rows, "PY_XML_ENTITIES", 2), _ids(rows)


def test_py_stdlib_etree_not_xxe_stays_dark(tmp_path):
    # xml.etree does not resolve external entities by default -> not XXE.
    rows = _sast(tmp_path, "xxe2.py",
                 "from xml.etree import ElementTree as ET\n"
                 "root = ET.fromstring(untrusted)\n")
    assert "PY_XML_ENTITIES" not in _ids(rows), _ids(rows)


def test_py_lxml_xxe_hardened_stays_dark(tmp_path):
    rows = _sast(tmp_path, "xxe3.py",
                 "from lxml import etree\n"
                 "parser = etree.XMLParser(resolve_entities=False)\n"
                 "root = etree.fromstring(untrusted, parser)\n")
    assert "PY_XML_ENTITIES" not in _ids(rows), _ids(rows)


def test_php_xxe_libxml_positive(tmp_path):
    rows = _sast(tmp_path, "xxe.php",
                 "<?php\n"
                 "$x = simplexml_load_string($_POST['xml']);\n")
    assert _rule_at(rows, "PHP_XXE_LIBXML", 2), _ids(rows)


def test_php_xxe_libxml_literal_stays_dark(tmp_path):
    rows = _sast(tmp_path, "xxe2.php",
                 "<?php\n"
                 "$x = simplexml_load_string($trusted);\n")
    assert "PHP_XXE_LIBXML" not in _ids(rows), _ids(rows)


def test_py_redos_nested_quantifier_positive(tmp_path):
    rows = _sast(tmp_path, "redos.py",
                 "import re\n"
                 "re.compile(r'(a+)+$')\n")
    assert _rule_at(rows, "PY_REDOS_NESTED_QUANTIFIER", 2), _ids(rows)


def test_py_redos_safe_pattern_stays_dark(tmp_path):
    rows = _sast(tmp_path, "redos2.py",
                 "import re\n"
                 "re.compile(r'^[a-z]+$/i')\n")
    assert "PY_REDOS_NESTED_QUANTIFIER" not in _ids(rows), _ids(rows)


def test_php_redos_nested_quantifier_positive(tmp_path):
    rows = _sast(tmp_path, "redos.php",
                 "<?php\n"
                 "preg_match('/(a+)+$/', $input);\n")
    assert _rule_at(rows, "PHP_REDOS_NESTED_QUANTIFIER", 2), _ids(rows)


def test_php_redos_safe_pattern_stays_dark(tmp_path):
    rows = _sast(tmp_path, "redos2.php",
                 "<?php\n"
                 "preg_match('/^[a-z]+$/', $input);\n")
    assert "PHP_REDOS_NESTED_QUANTIFIER" not in _ids(rows), _ids(rows)


def test_py_log_injection_positive(tmp_path):
    rows = _sast(tmp_path, "log.py",
                 "import logging\n"
                 "logging.info(request.args.get('name'))\n")
    assert _rule_at(rows, "PY_LOG_INJECTION", 2), _ids(rows)


def test_py_log_injection_literal_stays_dark(tmp_path):
    rows = _sast(tmp_path, "log2.py",
                 "import logging\n"
                 "logging.info('user logged in')\n")
    assert "PY_LOG_INJECTION" not in _ids(rows), _ids(rows)


def test_php_log_injection_positive(tmp_path):
    rows = _sast(tmp_path, "log.php",
                 "<?php\n"
                 "error_log($_GET['name']);\n")
    assert _rule_at(rows, "PHP_LOG_INJECTION", 2), _ids(rows)


def test_php_log_injection_literal_stays_dark(tmp_path):
    rows = _sast(tmp_path, "log2.php",
                 "<?php\n"
                 "error_log('done');\n")
    assert "PHP_LOG_INJECTION" not in _ids(rows), _ids(rows)


def test_host_header_injection_php_positive(tmp_path):
    # The host reference sits on its own line (no ``//`` before it) because the
    # PHP comment detector reads ``//`` inside a URL string as a line comment.
    rows = _sast(tmp_path, "host.php",
                 "<?php\n"
                 "$host = $_SERVER['HTTP_HOST'];\n"
                 "$url = 'http://' . $host . '/reset?t=' . $tok;\n"
                 "mail($to, 'Reset', $url);\n")
    assert _rule_at(rows, "HOST_HEADER_INJECTION", 2), _ids(rows)


def test_host_header_php_display_only_stays_dark(tmp_path):
    rows = _sast(tmp_path, "host2.php",
                 "<?php\n"
                 "echo 'Welcome from ' . $_SERVER['HTTP_HOST'];\n")
    assert "HOST_HEADER_INJECTION" not in _ids(rows), _ids(rows)


def test_websocket_message_to_eval_positive(tmp_path):
    rows = _sast(tmp_path, "ws.js",
                 "socket.on('message', (m) => { eval(m); });\n")
    assert _rule_at(rows, "NODE_WEBSOCKET_SINK", 1), _ids(rows)


def test_websocket_message_to_console_stays_dark(tmp_path):
    rows = _sast(tmp_path, "ws2.js",
                 "socket.on('message', (m) => { console.log(m); });\n")
    assert "NODE_WEBSOCKET_SINK" not in _ids(rows), _ids(rows)


def test_tar_extractall_positive(tmp_path):
    rows = _sast(tmp_path, "tar.py",
                 "import tarfile\n"
                 "tarfile.open('a.tgz').extractall('/tmp')\n")
    assert _rule_at(rows, "PY_TAR_EXTRACTALL", 2), _ids(rows)


def test_zip_extractall_is_already_covered(tmp_path):
    # zipfile.extractall is handled by the pre-existing GENERIC_ZIPSLIP rule;
    # this guards against a duplicate claim and documents the split.
    rows = _sast(tmp_path, "zip.py",
                 "import zipfile\n"
                 "zipfile.ZipFile('a.zip').extractall('/tmp')\n")
    assert "GENERIC_ZIPSLIP" in _ids(rows), _ids(rows)
    assert "PY_TAR_EXTRACTALL" not in _ids(rows), _ids(rows)
