"""Quality gate for scanner/php_webshell_rules.py.

Measured facts pinned here (2026-10-27):
  - 14 PHP code-execution / webshell shapes that the legacy tables missed
    (assert, dynamic callables, variable functions, create_function,
    preg_replace /e, webshell drops, client-filename uploads, extract).
  - 14 benign controls that must stay dark, including the DVWA "safe" upload
    shape (destination from a generated name) and constant-argument calls.
  - 3 real DVWA upload sources are the only hits across 493 PHP files on the
    host -- no false positives in unrelated PHP code.

These tests never touch the live rule tables: they register the pack into a
private copy of the compiled rule list.
"""
from __future__ import annotations

import os
import re
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner import sast  # noqa: E402
from scanner.php_webshell_rules import (  # noqa: E402
    DISABLE_ENV,
    RULES,
    as_sast_rules,
    enabled,
    pack_summary,
    redos_safe,
)

F = re.I | re.M

MALICIOUS = {
    "assert_request": '<?php assert($_REQUEST[0]); ?>',
    "assert_string": "<?php assert(\"{$_POST['c']}\"); ?>",
    "call_user_func": '<?php call_user_func($_POST["f"]); ?>',
    "call_user_func_array": '<?php call_user_func_array($_GET["f"], array()); ?>',
    "array_map_cb": '<?php array_map($_GET["f"], array(1)); ?>',
    "usort_cb": '<?php usort($a, $_GET["f"]); ?>',
    "var_function_direct": '<?php $_GET["f"]($_GET["a"]); ?>',
    "var_function_assigned": '<?php\n$fn = $_POST["f"];\n$fn();\n?>',
    "create_function": '<?php $f = create_function("", $_GET["c"]); $f(); ?>',
    "preg_replace_e": '<?php echo preg_replace("/.*/e", $_POST["c"], "x"); ?>',
    "preg_replace_e_hash": "<?php preg_replace('#x#e', 'phpinfo()', $s); ?>",
    "file_put_contents": '<?php file_put_contents("shell.php", $_POST["c"]); ?>',
    "fwrite_drop": '<?php $h = fopen("x.php","w"); fwrite($h, $_POST["c"]); ?>',
    "move_uploaded": ('<?php move_uploaded_file($_FILES["f"]["tmp_name"], '
                      '"up/".$_FILES["f"]["name"]); ?>'),
    "extract_get": '<?php extract($_GET); ?>',
    "dvwa_low_upload": (
        '<?php\n'
        '$target_path  = DVWA_WEB_PAGE_TO_ROOT . "hackable/uploads/";\n'
        '$target_path .= basename( $_FILES[ "uploaded" ][ "name" ] );\n'
        'move_uploaded_file( $_FILES[ "uploaded" ][ "tmp_name" ], $target_path );\n'),
}

BENIGN = {
    "eval_const": '<?php eval("1+1;"); ?>',
    "assert_type": "<?php assert(is_array($data)); ?>",
    "assert_null": "<?php assert($user !== null); ?>",
    "call_user_func_const": '<?php call_user_func("my_function"); ?>',
    "usort_strcmp": '<?php usort($rows, "strcmp"); ?>',
    "array_map_arrow": "<?php array_map(fn($x) => $x + 1, $nums); ?>",
    "file_put_cache": '<?php file_put_contents("cache.json", json_encode($data)); ?>',
    "fwrite_log": "<?php fwrite($log, $line); ?>",
    "preg_plain": '<?php $x = preg_replace("/a/", "b", $s); ?>',
    "preg_i_modifier": "<?php $x = preg_replace('#a#i', 'b', $s); ?>",
    "include_const": '<?php include __DIR__ . "/views/home.php"; ?>',
    "exec_const": '<?php $out = shell_exec("ls -la"); ?>',
    "extract_skip": "<?php extract($row, EXTR_SKIP); ?>",
    "var_from_request_echo": '<?php $out = $_GET["value"]; echo $out; ?>',
    "upload_safe_name": ('<?php $dest = "uploads/" . $generated_name;\n'
                         'move_uploaded_file($tmp, $dest); ?>'),
}


def _compiled_pack():
    return [(r["id"], re.compile(r["pat"], F)) for r in RULES]


def _pack_hits(code):
    return sorted({rid for rid, pat in _compiled_pack() if pat.search(code)})


def test_pack_ids_unique_and_collision_free():
    ids = [r["id"] for r in RULES]
    assert len(ids) == len(set(ids))
    legacy = {r.get("id") for r in sast.ENTERPRISE_RULES}
    assert not (set(ids) & legacy), "pack id collides with a legacy rule id"


def test_pack_patterns_are_redos_safe():
    for r in RULES:
        assert redos_safe(r), "ReDoS-unsafe pattern: %s" % r["id"]


@pytest.mark.parametrize("rule", RULES, ids=[r["id"] for r in RULES])
def test_rule_snippets(rule):
    pat = re.compile(rule["pat"], F)
    for snippet in rule["positive"]:
        assert pat.search(snippet), "%s missed positive %r" % (rule["id"], snippet)
    for snippet in rule["negative"]:
        assert not pat.search(snippet), "%s hit negative %r" % (rule["id"], snippet)


def test_every_legacy_missed_shape_is_covered():
    """The measurement that motivated the pack: all code-exec families fire."""
    missed = [k for k, v in MALICIOUS.items() if not _pack_hits(v)]
    assert missed == [], "uncovered webshell shapes: %s" % missed


def test_benign_controls_stay_dark():
    fps = {k: _pack_hits(v) for k, v in BENIGN.items() if _pack_hits(v)}
    assert fps == {}, "pack fired on benign code: %s" % fps


def test_dvwa_upload_family_classification():
    """low/medium are the vulnerable shapes, high is mitigated (the accuracy
    layer downgrades it to NEEDS_REVIEW), impossible generates its own name."""
    low = MALICIOUS["dvwa_low_upload"]
    assert "PHP_UPLOAD_INDIRECT_CLIENT_FILENAME" in _pack_hits(low)
    assert _pack_hits(BENIGN["upload_safe_name"]) == []

    from accuracy import validators as V
    finding = {"rule_id": "PHP_UPLOAD_INDIRECT_CLIENT_FILENAME",
               "vuln_type": "unrestricted_upload"}
    # No validation in low/medium -> the real claim stands.
    assert V.upload_check(finding, low) is None
    # Extension + image validation -> downgrade, never suppression.
    high = ('<?php\n$target_path .= basename( $_FILES[ "uploaded" ][ "name" ] );\n'
            '$uploaded_ext = substr($uploaded_name, strrpos($uploaded_name, ".") + 1);\n'
            'if (strtolower($uploaded_ext) == "jpg" && getimagesize($uploaded_tmp)) {\n'
            '  move_uploaded_file($uploaded_tmp, $target_path);\n}')
    r = V.upload_check(finding, high)
    assert r and r[0] == "NEEDS_REVIEW"


def test_pack_schema_is_sast_compatible():
    for r in as_sast_rules():
        assert set(r) == {"id", "title", "vuln", "sev", "langs", "cwe",
                          "owasp", "pat"}
        assert r["langs"] == ["php"]


def test_disable_switch(monkeypatch):
    assert enabled() is True
    assert len(as_sast_rules()) == len(RULES)
    monkeypatch.setenv(DISABLE_ENV, "0")
    assert enabled() is False
    assert as_sast_rules() == []


def test_pack_summary_reports_redos_state():
    summary = pack_summary()
    assert len(summary) == len(RULES)
    assert all(s["redos_safe"] for s in summary)
