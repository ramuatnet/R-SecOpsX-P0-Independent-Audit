"""PHP code-execution / webshell rule pack (additive, evidence-scoped).

Why this exists
---------------
A measured probe of the live engine (2026-10-27) on 22 PHP webshell shapes
found 13 undetected: every *code-execution* family rather than the classic
command-execution family. The legacy tables capture

    system() / shell_exec() / passthru() / popen() / proc_open() / exec()
    include()/require() with a request variable
    eval()                        (EVAL_CALL, language-agnostic)
    unserialize()                 (PHP_UNSERIALIZE)

but there was NO rule for

    assert() with request data                  (eval-equivalent pre-PHP8)
    call_user_func / call_user_func_array / array_map / usort / ... with a
        request-derived callable                (arbitrary function invocation)
    variable functions  $_GET['f'](...)  /  $fn = $_POST['f']; $fn();
    create_function()                            (removed in PHP 8, still in
                                                  legacy code)
    preg_replace() with the /e modifier          (code execution, removed 7.0)
    file_put_contents / fwrite webshell drops
    move_uploaded_file() with the client filename (CWE-434)
    extract($_GET) variable injection

Every rule here requires a request superglobal in the SAME statement as the
sink, so benign calls (`shell_exec("ls")`, `call_user_func("handler")`,
`file_put_contents("cache.json", ...)`) stay dark. Nothing in this module
modifies an existing rule, id, severity or CWE mapping.

Registration is the CALLER's decision: ``as_sast_rules()`` returns rule dicts
in the legacy schema; register them before the rule table is compiled (see
docs/php_webshell_rules.md for the one-block wiring diff). The pack can be
disabled with ``RSECOPSX_PHP_WEBSHELL_RULES=0`` once registered.

Provenance: original work for this repository, derived from the PHP language
reference (eval/assert/callable semantics) and CWE-95 / CWE-434 / CWE-621.
No third-party rule text is copied. Patterns are ReDoS-audited at import.
"""
from __future__ import annotations

import os
import re

PACK_SCHEMA = "RSECOPSX-PHP-WEBSHELL-1"
PACK_VERSION = "1.0"
DISABLE_ENV = "RSECOPSX_PHP_WEBSHELL_RULES"

_F = re.IGNORECASE | re.MULTILINE

# Request-derived data, in the shapes PHP actually exposes it.
_REQ = r"\$_(?:GET|POST|REQUEST|COOKIE)"

# Each rule: id,title,vuln,sev,langs,cwe,owasp,pat + positive/negative
# snippets used by the quality gate in tests/test_php_webshell_rules.py.
RULES = [
    {
        "id": "PHP_ASSERT_REQUEST_CODE_EXEC",
        "title": "PHP assert() with Request-Derived Code",
        "vuln": "code_injection", "sev": "Critical", "langs": ["php"],
        "cwe": "CWE-95", "owasp": "A03:2021 - Injection",
        # assert("...$_POST...") evaluated strings before PHP 8; assert($x)
        # with a request variable is an eval-equivalent in legacy code.
        "pat": r"\bassert\s*\([^;]{0,200}?" + _REQ + r"[^;]{0,120}\)",
        "positive": [
            'assert($_REQUEST[0]);',
            "assert(\"{$_POST['c']}\");",
            'assert($_GET["c"] == "x");',
        ],
        "negative": [
            'assert(is_array($data));',
            'assert($user !== null);',
        ],
    },
    {
        "id": "PHP_DYNAMIC_CALLABLE_REQUEST",
        "title": "PHP Request-Controlled Callable Invocation",
        "vuln": "code_injection", "sev": "Critical", "langs": ["php"],
        "cwe": "CWE-95", "owasp": "A03:2021 - Injection",
        # call_user_func($_POST['f']) -> attacker names the function;
        # array_map / usort / preg_replace_callback take the callable first.
        "pat": (r"\b(?:call_user_func(?:_array)?|array_map|array_filter|"
                r"array_walk(?:_recursive)?|usort|uasort|uksort|"
                r"preg_replace_callback|forward_static_call(?:_array)?)"
                r"\s*\([^;]{0,120}?" + _REQ + r"[^;]{0,80}\)"),
        "positive": [
            'call_user_func($_POST["f"]);',
            'call_user_func_array($_GET["f"], array());',
            'array_map($_GET["f"], array(1));',
            'usort($a, $_GET["f"]);',
        ],
        "negative": [
            'call_user_func("my_function");',
            'usort($rows, "strcmp");',
            'array_map(fn($x) => $x + 1, $nums);',
        ],
    },
    {
        "id": "PHP_CREATE_FUNCTION_REQUEST",
        "title": "PHP create_function() with Request-Derived Body",
        "vuln": "code_injection", "sev": "Critical", "langs": ["php"],
        "cwe": "CWE-95", "owasp": "A03:2021 - Injection",
        "pat": r"\bcreate_function\s*\([^;]{0,160}?" + _REQ + r"[^;]{0,80}\)",
        "positive": [
            '$f = create_function("", $_GET["c"]); $f();',
        ],
        "negative": [
            '$f = create_function("$a", "return $a + 1;");',
        ],
    },
    {
        "id": "PHP_VARIABLE_FUNCTION_REQUEST",
        "title": "PHP Variable Function Call from Request Data",
        "vuln": "code_injection", "sev": "Critical", "langs": ["php"],
        "cwe": "CWE-95", "owasp": "A03:2021 - Injection",
        # $_GET['f'](...) and $fn = $_POST['f']; $fn(...);
        "pat": (r"(?:\$_(?:GET|POST|REQUEST|COOKIE)\s*\[[^\]]{1,60}\]\s*\("
                r"|\$([A-Za-z_]\w{0,40})\s*=\s*" + _REQ + r"[^;\n]{0,80};"
                r"[\s\S]{0,300}?\$\1\s*\()"),
        "positive": [
            '$_GET["f"]($_GET["a"]);',
            '$fn = $_POST["f"];\n$fn();',
        ],
        "negative": [
            '$fn = "strlen"; $fn("abc");',
            '$out = $_GET["value"]; echo $out;',
        ],
    },
    {
        "id": "PHP_PREG_REPLACE_EVAL_MODIFIER",
        "title": "PHP preg_replace() /e Modifier Code Execution",
        "vuln": "code_injection", "sev": "Critical", "langs": ["php"],
        "cwe": "CWE-95", "owasp": "A03:2021 - Injection",
        # only the e modifier is code execution; the same call without /e is
        # a plain regex (PHP_REDOS_* territory, not this rule). The pattern
        # sits inside a PHP string, so the regex delimiter is the character
        # AFTER the quote: "/.../e", '#...#e', '~...~e' are all legal.
        "pat": (r"\bpreg_replace\s*\(\s*(['\"])(.)"
                r"(?:(?!(?:\1|\2)).){0,160}\2[a-zA-Z]{0,7}e[a-zA-Z]{0,7}\1"),
        "positive": [
            'preg_replace("/.*/e", $_POST["c"], "x");',
            'preg_replace("#x#e", "phpinfo()", $s);',
        ],
        "negative": [
            'preg_replace("/a/", "b", $s);',
            'preg_replace("#x#i", "b", $s);',
        ],
    },
    {
        "id": "PHP_WEBSHELL_DROPPER_REQUEST",
        "title": "PHP Webshell Drop from Request Data",
        "vuln": "unrestricted_upload", "sev": "Critical", "langs": ["php"],
        "cwe": "CWE-434", "owasp": "A04:2021 - Insecure Design",
        # writing request data to a file = the drop half of a webshell.
        "pat": (r"\b(?:file_put_contents|fwrite|fputs)\s*\([^;]{0,200}?"
                + _REQ + r"|" + _REQ + r"[^;]{0,120}?"
                r"\b(?:file_put_contents|fwrite|fputs)\s*\("),
        "positive": [
            'file_put_contents("shell.php", $_POST["c"]);',
            '$h = fopen("x.php","w"); fwrite($h, $_POST["c"]);',
        ],
        "negative": [
            'file_put_contents("cache.json", json_encode($data));',
            'fwrite($log, $line);',
        ],
    },
    {
        "id": "PHP_UPLOAD_CLIENT_FILENAME",
        "title": "PHP Upload Written Under Client-Supplied Filename",
        "vuln": "unrestricted_upload", "sev": "High", "langs": ["php"],
        "cwe": "CWE-434", "owasp": "A04:2021 - Insecure Design",
        # The DESTINATION must be the client-supplied filename; using tmp_name
        # as the source is the normal, safe half of the same call.
        "pat": (r"\bmove_uploaded_file\s*\([^;]{0,200}?"
                r"\$_FILES\s*\[[^\]]{1,60}\]\s*\[\s*['\"]name['\"]\s*\]"),
        "positive": [
            'move_uploaded_file($_FILES["f"]["tmp_name"], "up/".$_FILES["f"]["name"]);',
        ],
        "negative": [
            'move_uploaded_file($_FILES["f"]["tmp_name"], "up/" . $safe_name);',
        ],
    },
    {
        "id": "PHP_UPLOAD_INDIRECT_CLIENT_FILENAME",
        "title": "PHP Upload Destination Built from Client Filename",
        "vuln": "unrestricted_upload", "sev": "High", "langs": ["php"],
        "cwe": "CWE-434", "owasp": "A04:2021 - Insecure Design",
        # DVWA's canonical shape: the destination variable is built from
        # $_FILES[...]['name'] a few lines above the move. Bounded window,
        # back-reference to the SAME variable.
        "pat": (r"\$([A-Za-z_]\w{0,40})\s*\.?=\s*[^;\n]{0,160}?"
                r"\$_FILES\s*\[[^\]]{1,60}\]\s*\[\s*['\"]name['\"]\s*\]"
                r"[^;\n]{0,60};[\s\S]{0,700}?"
                r"move_uploaded_file\s*\([^;]{0,200}?\$\1\s*\)"),
        "positive": [
            '$target_path .= basename( $_FILES[ "uploaded" ][ "name" ] );\n'
            'move_uploaded_file( $_FILES[ "uploaded" ][ "tmp_name" ], $target_path );',
        ],
        "negative": [
            '$dest = "uploads/" . $safe_name;\n'
            'move_uploaded_file($tmp, $dest);',
        ],
    },
    {
        "id": "PHP_EXTRACT_REQUEST_SCOPE_INJECTION",
        "title": "PHP extract() / parse_str() Request Variable Injection",
        "vuln": "variable_injection", "sev": "High", "langs": ["php"],
        "cwe": "CWE-621", "owasp": "A04:2021 - Insecure Design",
        "pat": r"\b(?:extract|parse_str)\s*\(\s*" + _REQ,
        "positive": [
            'extract($_GET);',
            'parse_str($_POST["args"], $out);',
        ],
        "negative": [
            'extract($row, EXTR_SKIP);',
            'parse_str("a=1&b=2", $out);',
        ],
    },
]


def redos_safe(rule: dict) -> bool:
    """Reject nested/unbounded repetition shapes before a rule ships."""
    p = rule["pat"]
    if re.search(r"\)\s*[+*]\s*[+*]", p):
        return False
    if re.search(r"\(\.\*[+*]\)\s*\{", p):
        return False
    # a quantified group that itself contains a quantified class
    if re.search(r"\([^()]*\[[^\]]*\][+*][^()]*\)[+*]", p):
        return False
    return True


def enabled() -> bool:
    return os.environ.get(DISABLE_ENV, "1") != "0"


# Sink categories for the pack's findings (T-0.6: moved out of sast's
# _PHP_SINK_CATEGORY so the pack is self-contained -- rules and their sink
# taxonomy travel together, and the env switch removes both). EVIDEX
# deletes a regex finding with no recorded sink category at report intake,
# so these must be registered with the rules.
SINK_CATEGORIES = {
    "PHP_ASSERT_REQUEST_CODE_EXEC": "code",
    "PHP_DYNAMIC_CALLABLE_REQUEST": "code",
    "PHP_CREATE_FUNCTION_REQUEST": "code",
    "PHP_VARIABLE_FUNCTION_REQUEST": "code",
    "PHP_PREG_REPLACE_EVAL_MODIFIER": "code",
    "PHP_WEBSHELL_DROPPER_REQUEST": "file",
    "PHP_UPLOAD_CLIENT_FILENAME": "file",
    "PHP_UPLOAD_INDIRECT_CLIENT_FILENAME": "file",
}


def as_sast_rules() -> list[dict]:
    """Rule dicts in the legacy ENTERPRISE_RULES schema (only these keys)."""
    if not enabled():
        return []
    return [
        {
            "id": r["id"],
            "title": r["title"],
            "vuln": r["vuln"],
            "sev": r["sev"],
            "langs": list(r["langs"]),
            "cwe": r["cwe"],
            "owasp": r["owasp"],
            "pat": r["pat"],
        }
        for r in RULES
    ]


def pack_summary() -> list[dict]:
    return [
        {"id": r["id"], "title": r["title"], "cwe": r["cwe"],
         "sev": r["sev"], "enabled": enabled(), "redos_safe": redos_safe(r)}
        for r in RULES
    ]


for _r in RULES:
    assert redos_safe(_r), "ReDoS-unsafe pattern in %s" % _r["id"]
