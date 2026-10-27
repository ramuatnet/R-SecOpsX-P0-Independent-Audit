# PHP webshell / code-execution rule pack

Status: **measured, committed, NOT yet registered** — registration is a
6-line additive block in `scanner/sast.py` shown at the bottom of this file.
Until that block lands, the pack has no effect on scans.

## Why the pack exists

A probe of the live engine (2026-10-27) ran 22 PHP webshell shapes through
the real `scanner.sast.scan_file()` + `scanner.taint_engine.scan_file()`
paths. The legacy tables already cover **command execution**, **file
inclusion**, **eval** and **deserialization**:

| Shape | Legacy detection | Verdict |
|---|---|---|
| `system($_GET['cmd'])` | `PHP_COMMAND_INJECTION` + `TAINT_PHP_COMMAND_INJECTION` | detected |
| `shell_exec($_POST['x'])` | same | detected |
| `passthru` / `popen` / `proc_open` / `exec` | same | detected |
| `include($_REQUEST['p'])` | `PHP_LFI_RFI_INCLUDE`, `PHP_PATH_USER_INPUT_VAR` | detected |
| `eval($_POST['c'])`, `eval(base64_decode(...))`, `eval(file_get_contents("php://input"))` | `EVAL_CALL` | detected |
| `unserialize($_POST['d'])` | `PHP_UNSERIALIZE` | detected |
| `preg_replace("/.*/e", ...)` | `PHP_XSS_TAINTED_ECHO` only — **not** as code execution | partial |

These were **not detected at all** (13 of 22 shapes):

    assert($_REQUEST[0])                       eval-equivalent before PHP 8
    assert("{$_POST['c']}")                    same
    call_user_func($_POST['f'])                attacker names the function
    call_user_func_array($_GET['f'], [])       same
    array_map / usort / preg_replace_callback  request-controlled callable
    create_function("", $_GET['c'])            removed in PHP 8, still in legacy
                                               code and still an eval
    $_GET['f']($_GET['a'])                     variable function
    $fn = $_POST['f']; $fn();                  same, one assignment away
    preg_replace("#x#e", ...)                  /e modifier = code execution
    file_put_contents("shell.php", $_POST[])   webshell drop
    fwrite($h, $_POST['c'])                    webshell drop
    move_uploaded_file($tmp, ...$_FILES[...]['name'])   CWE-434
    extract($_GET) / parse_str($_POST['args']) variable injection

Also measured: the canonical **DVWA upload family** (`low.php`, `medium.php`,
`high.php`) produced **zero** findings from both engines — `PHP_*` has no
upload rule and `TAINT_MULTIPART_TRAVERSAL` does not fire on the PHP
`$_FILES` → destination-variable shape.

## What the pack adds

`scanner/php_webshell_rules.py`, 9 rules, all `langs == ["php"]`, each one
requiring a request superglobal (`$_GET|$_POST|$_REQUEST|$_COOKIE`,
`$_FILES` for uploads) in the same statement as the sink:

| Rule id | CWE | Claim |
|---|---|---|
| `PHP_ASSERT_REQUEST_CODE_EXEC` | CWE-95 | `assert()` receiving request-derived code |
| `PHP_DYNAMIC_CALLABLE_REQUEST` | CWE-95 | `call_user_func*`, `array_map`, `usort`, `preg_replace_callback` … with a request callable |
| `PHP_CREATE_FUNCTION_REQUEST` | CWE-95 | `create_function()` body from request |
| `PHP_VARIABLE_FUNCTION_REQUEST` | CWE-95 | `$_GET['f'](...)` and one-assignment `$fn()` |
| `PHP_PREG_REPLACE_EVAL_MODIFIER` | CWE-95 | `/e` (or `#…#e`, `~…~e`) modifier |
| `PHP_WEBSHELL_DROPPER_REQUEST` | CWE-434 | request data written to a file |
| `PHP_UPLOAD_CLIENT_FILENAME` | CWE-434 | upload written under the client filename (same call) |
| `PHP_UPLOAD_INDIRECT_CLIENT_FILENAME` | CWE-434 | destination variable built from the client filename (bounded 700-char window, back-reference to the same variable) |
| `PHP_EXTRACT_REQUEST_SCOPE_INJECTION` | CWE-621 | `extract()` / `parse_str()` with request data |

Provenance: original work for this repository, derived from the PHP language
reference and CWE-95 / CWE-434 / CWE-621. No third-party rule text is used.
Every pattern is ReDoS-audited at import (`redos_safe()`), and a unit test
fails if a pattern acquires a nested/unbounded quantifier.

## Measured quality

| Gate | Result |
|---|---|
| webshell shapes covered | **16/16** (14 previously-missed + the DVWA indirect upload) |
| benign controls dark | **15/15** (`eval("1+1")`, `call_user_func("f")`, `preg_replace("/a/","b")`, `fwrite($log,$line)`, generated upload names, …) |
| real PHP code on host | 493 files → **3 hits**, all `DVWA/vulnerabilities/upload/source/{low,medium,high}.php` |
| DVWA verdicts | `low`/`medium` → real claim stands; `high` → extension + `getimagesize()` validation ⇒ `NEEDS_REVIEW` via `accuracy.validators.upload_check`; `impossible` → no hit (random filename) |
| perf | 20 000-line PHP file: 1.2 s total engine time (pack overhead not separable, same order as legacy) |

The only hits in 493 unrelated PHP files being the three intentional DVWA
upload sources is the precision evidence; there is no large real-world PHP
codebase on this host, so this is a bounded measurement, not a claim-level
precision percentage.

## Interaction with the accuracy layer

`accuracy.validators.upload_check` now also accepts `unrestricted_upload`
findings (rule id contains `UPLOAD`) and recognises PHP hardening
(`getimagesize`, `mime_content_type`, `pathinfo`, `_ext` comparisons,
`in_array(... ext ...)`). A validated upload is **downgraded to
NEEDS_REVIEW**, never deleted; the verdict and reason are kept in the audit
output.

## Registration diff (requires approval — touches `scanner/sast.py`)

Insert immediately after the Big4 block (line 648,
`# ---- end Big4 enterprise gap patch ----`) and before
`COMPILED_ENTERPRISE_RULES = [`:

```python
# ---- PHP webshell / code-execution pack (G-PHP-WS) ----
# Additive: new ids only, no existing rule touched. Every pattern requires a
# request superglobal in the same statement as the sink. Rollback is one
# environment variable: RSECOPSX_PHP_WEBSHELL_RULES=0.
from scanner.php_webshell_rules import as_sast_rules as _php_ws_rules
for _r in _php_ws_rules():
    if _r["id"] not in _existing_rule_ids:
        ENTERPRISE_RULES.append(_r)
        _existing_rule_ids.add(_r["id"])
# ---- end PHP webshell pack ----
```

Rollback without a code change: `RSECOPSX_PHP_WEBSHELL_RULES=0` makes
`as_sast_rules()` return `[]`, so registration adds nothing.

## Known limits

- Indirect webshell drops (`$body = $_POST['c']; file_put_contents($f, $body)`)
  are not modelled; only request data inside the sink call is matched.
- Request-controlled **paths** remain traversal territory (`PHP_PATH_*`), not
  this pack.
- `preg_replace /e` is code execution only up to PHP 7.0; the rule keeps its
  critical severity because such code is legacy and still exploitable when
  deployed on an old runtime.
- After registration the pack must pass the UFIB corpus guard: the
  `code_injection` contract covers 5 of the 9 rules by `vuln_type`; the
  `unrestricted_upload` / `variable_injection` ids resolve to the manual-review
  default until a contract is added (no silent confirmation either way).
