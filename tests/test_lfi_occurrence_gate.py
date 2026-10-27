"""Pins for main._prune_unsupported_occurrences' path_traversal gate.

THE GAP THIS MEASURES (2026-10-27)
A request-controlled PHP include was dropped from the report:

    $p = $_GET['page'];
    include($p);

The scanner raises PHP_PATH_USER_INPUT_VAR (CWE-22, sink_category "file") and
records ``taint_path = "$p -> include"``. The gate accepted only
file|path|filename|dest|target|name as evidence, and the PHP chain names
neither the parameter nor the superglobal -- it starts at the tainted variable.
So the finding reached the report payload and was pruned there.

WHAT THE FIX ACCEPTS
A filesystem sink call whose argument is a *variable* (a dollar sign followed
by an identifier), on an occurrence whose taint path contains "->". A literal
call -- include of 'config.php', open of 'data.csv', fs.readFile of a quoted
path -- has no taint path and is still dropped by the pre-existing branches.

KNOWN LIMIT
The gate cannot tell a session-sourced dynamic include from a request-sourced
one: both arrive as "$p -> include". That is a limit of the recorded evidence,
not of this predicate, and it is why the condition is written against the
sink shape rather than pretending to see a source name the chain does not
carry.
"""
from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


@pytest.fixture(scope="module")
def main_module():
    return importlib.import_module("main")


def _occ(snippet, taint, detection="Enterprise SAST Pattern"):
    return {"file": "app/index.php", "line": 3, "snippet": snippet,
            "taint_path": taint, "detection": detection,
            "severity": "High", "cwe": "CWE-22"}


def _prune(main_module, vuln_type, occurrence):
    payload = {"findings": [{"vuln_type": vuln_type, "instances": 1,
                             "occurrences": [dict(occurrence)]}]}
    removed = main_module._prune_unsupported_occurrences(payload)
    return removed, payload["findings"][0]["occurrences"]


# (id, snippet, taint, kept, why)
CASES = [
    ("include-variable-page", "include($p);", "$p -> include", True,
     "request-controlled include; the parameter is named 'page', not a path word"),
    ("require-variable-tpl", "require($tpl);", "$tpl -> require", True,
     "same shape through require"),
    ("include-variable-short-name", "include($f);", "$f -> include", True,
     "even a 'file'-named parameter used to drop: the PHP chain never names it"),
    ("file-get-contents-variable", "$b = file_get_contents($tpl);",
     "$tpl -> file_get_contents", True,
     "already kept: the sink name itself contains 'file'"),
    ("include-literal-no-taint", "include('config.php');", "", False,
     "literal include is static; must stay pruned"),
    ("include-literal-stray-taint", "include('config.php');", "$x -> include", False,
     "a literal argument is not made dynamic by someone else's taint"),
    ("js-readfile-literal", "fs.readFile('/etc/passwd', cb)", "", False,
     "pre-existing literal branch"),
    ("python-open-request", "open(p)", "request.GET.get('path') -> p -> open", True,
     "pre-existing supported shape, must not regress"),
    ("python-open-literal", "open('data.csv')", "", False,
     "literal open is static; must stay pruned"),
    ("include-no-arrow", "include($p);", "$p include", False,
     "no '->' means no taint chain was recorded"),
]


@pytest.mark.parametrize("case_id,snippet,taint,kept,why", CASES,
                         ids=[c[0] for c in CASES])
def test_path_traversal_gate(main_module, case_id, snippet, taint, kept, why):
    removed, remaining = _prune(main_module, "path_traversal", _occ(snippet, taint))
    assert (removed == 0) is kept, f"{case_id}: {why} (removed={removed})"
    assert bool(remaining) is kept, f"{case_id}: occurrences after gate: {remaining}"
    assert why  # keeps the parametrisation readable in failures


def test_non_path_finding_unaffected(main_module):
    removed, remaining = _prune(main_module, "code_injection", _occ("eval(code)", ""))
    assert removed == 0
    assert remaining, "code_injection must not be pruned by the path gate"


def test_engine_taint_chain_survives_the_gate(main_module, tmp_path):
    """The integration row: use the chain the PHP engine really records.

    This is the assertion the first version of the fix would have failed --
    it keyed on a request superglobal in taint_path, but the engine records
    "$p -> include", with no superglobal anywhere in the occurrence.
    """
    from scanner.sast import scan_file

    fixture = tmp_path / "lfi.php"
    fixture.write_text("<?php\n$p = $_GET['page'];\ninclude($p);\n",
                       encoding="utf-8")
    rows = [f for f in scan_file(str(fixture))
            if str(f.get("rule_id")) == "PHP_PATH_USER_INPUT_VAR"]
    assert rows, "PHP_PATH_USER_INPUT_VAR did not fire on a request-controlled include"

    row = rows[0]
    assert row.get("taint_path") == "$p -> include", row.get("taint_path")
    assert row.get("sink_category") == "file", row.get("sink_category")

    occurrence = {
        "file": str(fixture),
        "line": row.get("line"),
        "snippet": row.get("snippet"),
        "taint_path": row.get("taint_path"),
        "detection": row.get("detection"),
        "severity": row.get("severity"),
        "cwe": row.get("cwe"),
    }
    removed, remaining = _prune(main_module, str(row.get("vuln_type")), occurrence)
    assert removed == 0, f"engine occurrence was pruned: {occurrence}"
    assert remaining, "occurrence list emptied by the gate"
