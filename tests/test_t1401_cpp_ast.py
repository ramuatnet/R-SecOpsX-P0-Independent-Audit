"""T-14.1a — C/C++ real AST (task.md section 14, language coverage).

The C/C++ window rules guess from line shapes; several of those guesses
are structurally disprovable by the syntax tree the phase-32 layer already
parses:

* ``CPP_UNSAFE_STRING_FUNCTION`` fires on FUNCTION DECLARATIONS
  (``char *strcpy(char*, const char*);``) and on NAME MENTIONS INSIDE
  STRING LITERALS (``char *msg = "call strcpy(dst, src) later";``) —
  measured, both are not calls;
* ``CPP_FORMAT_STRING``'s text gate lets ``void printf(void);`` through
  (``void`` reads as an identifier-format argument);
* ``CPP_SYSTEM_VARIABLE`` / ``CPP_SQLITE3_EXEC_VARIABLE`` /
  ``CPP_USE_AFTER_FREE`` get the same callee-position proof for free.

Kill-on-proof: only the proven non-call shapes (declarator of a
function_declarator, macro definition name, string/comment content) are
killed; a real ``call_expression`` callee and every unrecognised shape
keeps. Grammar absent or unparseable file never reaches the predicate —
``apply_ast_validation`` returns the findings untouched first (escape
pinned here for this family).

Wiring note (pre-existing phase-32 architecture): the AST pass runs in
``scan_directory`` (per-file) and the taint-interproc path — ``scan_file``
never calls it, for ANY validated id. These tests therefore drive
``apply_ast_validation`` directly, the same way test_phase32 does.
"""
from __future__ import annotations

import importlib.util
import pathlib
import textwrap

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]

from scanner import tree_sitter_support as ts  # noqa: E402
from scanner.ast_validators import (  # noqa: E402
    VALIDATED_RULE_IDS,
    apply_ast_validation,
)

TS_INSTALLED = importlib.util.find_spec("tree_sitter") is not None
needs_cpp = pytest.mark.skipif(
    not TS_INSTALLED or not ts.grammar_available("cpp"),
    reason="cpp grammar unavailable")

#: The five C/C++ window-rule ids this batch joins the closed set.
FAMILY_IDS = frozenset({
    "CPP_UNSAFE_STRING_FUNCTION",
    "CPP_SYSTEM_VARIABLE",
    "CPP_SQLITE3_EXEC_VARIABLE",
    "CPP_FORMAT_STRING",
    "CPP_USE_AFTER_FREE",
})

#: Engine source needles (mutation anchors for the dispatch table).
ENGINE_SRC = (REPO / "scanner" / "ast_validators.py").read_text(
    encoding="utf-8")


def _scan(tmp_path: pathlib.Path, name: str, source: str):
    from scanner.sast import scan_file
    path = tmp_path / name
    path.write_text(textwrap.dedent(source), encoding="utf-8")
    rows = scan_file(str(path))
    return [r for r in rows
            if str(r.get("rule_id") or "").startswith("CPP_")], path


def _ids(rows) -> set:
    return {str(r.get("rule_id")) for r in rows}


def _apply(rows, path: pathlib.Path) -> set:
    return _ids(apply_ast_validation(rows, str(path)))


# ---------------------------------------------------------------- disclosure


def test_disclosure_needles():
    for needle in (
        "T-14.1a",
        "C/C++ real AST",
        "Kill-on-proof",
        "function_declarator",
        "preproc_function_def",
        "string_content",
        "_cpp_call_shape",
        "_CPP_CALL_RULES",
        "grammar absent",
    ):
        assert needle in ENGINE_SRC, "disclosure missing: %r" % needle


def test_family_ids_joined_the_closed_set():
    # Baseline (same commit as the product change, ground rules): the
    # five ids are members of the closed validator set.  The exact-set
    # pin in test_phase32_tree_sitter.py is updated in the same commit.
    missing = FAMILY_IDS - set(VALIDATED_RULE_IDS)
    assert not missing, missing


def test_call_rule_dispatch_table_pinned():
    # The dispatch table must name each family id with the SAME function
    # alternation the sast pattern uses (a dropped id = silent keep).
    import scanner.ast_validators as av
    table = av._CPP_CALL_RULES
    assert set(table) == set(FAMILY_IDS), sorted(table)
    assert set(table["CPP_UNSAFE_STRING_FUNCTION"]) == {
        "strcpy", "strcat", "gets", "sprintf", "vsprintf"}
    assert set(table["CPP_FORMAT_STRING"]) == {
        "printf", "fprintf", "sprintf", "snprintf",
        "vprintf", "vfprintf", "vsprintf", "vsnprintf"}
    assert table["CPP_SYSTEM_VARIABLE"] == ("system", "_system")
    assert table["CPP_SQLITE3_EXEC_VARIABLE"] == ("sqlite3_exec",)
    assert table["CPP_USE_AFTER_FREE"] == ("free",)


# ------------------------------------------------------------------- kills


@needs_cpp
def test_declaration_prototype_fires_then_is_killed(tmp_path):
    # MEASURED RED: the prototype fires through scan_file today and
    # survives apply_ast_validation (id not in the closed set).
    rows, path = _scan(tmp_path, "decl.c",
                       "char *strcpy(char *d, const char *s);\n")
    assert "CPP_UNSAFE_STRING_FUNCTION" in _ids(rows), _ids(rows)
    assert "CPP_UNSAFE_STRING_FUNCTION" not in _apply(rows, path), (
        "declaration is not a call")


@needs_cpp
def test_string_literal_mention_fires_then_is_killed(tmp_path):
    # MEASURED RED: string CONTENT is not comment-masked, so the mention
    # fires; the tree proves it sits in string_content, not a call.
    rows, path = _scan(tmp_path, "strmention.c",
                       'char *msg = "call strcpy(dst, src) later";\n')
    assert "CPP_UNSAFE_STRING_FUNCTION" in _ids(rows), _ids(rows)
    assert "CPP_UNSAFE_STRING_FUNCTION" not in _apply(rows, path), (
        "string-literal mention is not a call")


@needs_cpp
def test_printf_void_declaration_killed(tmp_path):
    # MEASURED RED: the text gate reads `void` as an identifier format
    # argument, so the declaration fires; callee-position kills it.
    rows, path = _scan(tmp_path, "printfdecl.c", "void printf(void);\n")
    assert "CPP_FORMAT_STRING" in _ids(rows), _ids(rows)
    assert "CPP_FORMAT_STRING" not in _apply(rows, path), (
        "declaration is not a call")


@needs_cpp
def test_macro_definition_killed_real_macro_call_kept(tmp_path):
    # The #define is a definition, not a use; the call inside a
    # function body is a call_expression and must stay.
    rows, path = _scan(tmp_path, "macro.c",
                       "#define gets(x) do {} while (0)\n"
                       "void f(void) { gets(buf); }\n")
    assert "CPP_UNSAFE_STRING_FUNCTION" in _ids(rows), _ids(rows)
    kept = apply_ast_validation(rows, str(path))
    kept_lines = {(r.get("rule_id"), r.get("line")) for r in kept}
    assert ("CPP_UNSAFE_STRING_FUNCTION", 1) not in kept_lines, kept_lines
    assert ("CPP_UNSAFE_STRING_FUNCTION", 2) in kept_lines, kept_lines


# ------------------------------------------------------------------- keeps


@needs_cpp
def test_real_calls_survive_the_ast_pass(tmp_path):
    # NOTE: CPP_SYSTEM_VARIABLE matches `std::system` / `_system` only
    # (deliberate C++-style rule, langs=[cpp]) -- bare `system(cmd)` in
    # a .c file never fires; the honest gap is disclosed in the batch
    # commit, not papered over here.  Hence .cpp + std::system.
    rows, path = _scan(tmp_path, "calls.cpp",
                       "void f(void) {\n"
                       "    strcpy(dst, src);\n"
                       "    printf(buf);\n"
                       "    int r = std::system(cmd);\n"
                       "    sqlite3_exec(db, sql, 0, 0, 0);\n"
                       "    free(p);\n"
                       "    p->next = NULL;\n"
                       "}\n")
    assert _ids(rows) >= {
        "CPP_UNSAFE_STRING_FUNCTION", "CPP_FORMAT_STRING",
        "CPP_SYSTEM_VARIABLE", "CPP_SQLITE3_EXEC_VARIABLE",
        "CPP_USE_AFTER_FREE",
    }, _ids(rows)
    assert _apply(rows, path) == _ids(rows), (
        _ids(rows), _apply(rows, path))


@needs_cpp
def test_qualified_std_system_call_kept(tmp_path):
    rows, path = _scan(tmp_path, "sys.cpp",
                       "void f(void) { int r = std::system(cmd); }\n")
    assert "CPP_SYSTEM_VARIABLE" in _ids(rows), _ids(rows)
    assert _apply(rows, path) == _ids(rows), _ids(rows)


def test_grammar_absent_keeps_every_family_finding(tmp_path, monkeypatch):
    # Escape pin at this family's layer: no parse -> findings object is
    # returned untouched (identity), exactly as the phase-32 contract.
    rows, path = _scan(tmp_path, "esc.c",
                       "char *strcpy(char *d, const char *s);\n")
    assert rows, "engine must have produced candidates first"
    monkeypatch.setattr("scanner.ast_validators.ts.parse",
                        lambda lang, src: None)
    result = apply_ast_validation(rows, str(path))
    assert result is rows  # identical list, not merely equal


def test_unrecognised_shape_keeps(tmp_path):
    # Kill-on-proof: an occurrence that is neither a proven non-call nor
    # resolvable keeps (conservative).  `system` as a bare identifier
    # in a condition with no call_expression above it.
    rows, path = _scan(tmp_path, "unknown.c",
                       "void f(void) { if (system) { } }\n")
    if "CPP_SYSTEM_VARIABLE" not in _ids(rows):
        pytest.skip("engine pattern does not match this shape")
    assert _apply(rows, path) == _ids(rows), _ids(rows)
