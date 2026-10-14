"""Phase 3.2 — tree-sitter AST validation layer behind the window rules.

Pins three things:

* HONESTY — the modules import with none of the optional wheels installed,
  an absent grammar leaves every finding byte-identical, the env kill-switch
  disables the pass, validator doubt (exception, unresolvable variable, no
  enclosing function, unknown extension, missing file) always keeps the
  finding, and the validated rule set stays closed.
* DECISIONS — every KILL / RE-ANCHOR / KEEP from the module docstring,
  executed against the real golden-corpus fixtures (the exact files whose
  false positives motivated each validator), so the measurement and the
  test can never drift apart.
* WIRING — ``sast.scan_directory`` calls the pass, and the end-to-end
  scan of a corpus fixture loses the false positive while keeping every
  true positive.

Grammar-dependent tests skip themselves on boxes without the optional
wheels (CI stays green stdlib-only); the honesty tests run everywhere.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

from scanner import ast_validators
from scanner import tree_sitter_support as ts
from scanner.ast_validators import VALIDATED_RULE_IDS, apply_ast_validation

SAST_CORPUS = Path("tests/vuln-test-corpus/sast")

TS_INSTALLED = importlib.util.find_spec("tree_sitter") is not None
needs_ts = pytest.mark.skipif(
    not TS_INSTALLED, reason="optional tree-sitter wheels not installed")
needs_go = pytest.mark.skipif(
    not TS_INSTALLED or not ts.grammar_available("go"),
    reason="go grammar unavailable")
needs_php = pytest.mark.skipif(
    not TS_INSTALLED or not ts.grammar_available("php"),
    reason="php grammar unavailable")
needs_csharp = pytest.mark.skipif(
    not TS_INSTALLED or not ts.grammar_available("csharp"),
    reason="csharp grammar unavailable")


def _finding(rule_id: str, file: Path, line: int, snippet: str,
             language: str = "go") -> dict:
    """Engine-shaped finding (sast._make_finding / taint emission)."""
    path = str(file)
    return {
        "rule_id": rule_id,
        "title": rule_id,
        "vuln_type": "x",
        "severity": "High",
        "language": language,
        "file": path,
        "line": line,
        "snippet": snippet,
        "evidence": f"{path}:{line}: {snippet}",
        "group_key": f"{rule_id}|{path}|{line}|{snippet[:120]}",
    }


def _lines(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8-sig").splitlines()


# ---------------------------------------------------------------------------
# Honesty contracts — these run on every box, with or without the wheels
# ---------------------------------------------------------------------------

class TestHonestyContracts:
    def test_modules_import_without_optional_wheels(self):
        # The import itself is the assertion: both modules must be
        # loadable with tree_sitter absent (stdlib-only CLI invariant).
        assert hasattr(ts, "status") and hasattr(ts, "parse")
        assert hasattr(ast_validators, "apply_ast_validation")

    def test_status_disclosure_shape(self):
        status = ts.status()
        assert set(status) == {"available", "grammars", "errors"}
        assert set(status["grammars"]) == set(ts._LANGUAGE_SPECS)
        assert all(isinstance(v, bool) for v in status["grammars"].values())
        assert status["available"] == any(status["grammars"].values())

    def test_parse_returns_none_for_unknown_language(self):
        assert ts.parse("klingon", "x = 1") is None

    def test_parse_returns_none_when_parser_absent(self, monkeypatch):
        monkeypatch.setattr(ts, "_parser_for", lambda key: None)
        assert ts.parse("go", "package main") is None

    def test_apply_is_noop_without_validated_candidates(self, tmp_path):
        target = tmp_path / "a.go"
        target.write_text("package main\n", encoding="utf-8")
        findings = [_finding("SOME_OTHER_RULE", target, 1, "package main")]
        result = apply_ast_validation(findings, str(target))
        assert result is findings  # identical list, not merely equal

    def test_validated_rule_set_is_closed(self):
        # Scope creep guard: the pass may touch exactly these nine rules.
        # (V1.12a added TAINT_MULTIPART_TRAVERSAL as a guard-dominance
        # KILL-only validator — it can never make the rule fire.)
        assert VALIDATED_RULE_IDS == {
            "PHP_HARDCODED_CREDENTIAL",
            "PHP_INCLUDE_CONCAT_PATH",
            "TAINT_PHP_COMMAND_INJECTION",
            "TAINT_MULTIPART_TRAVERSAL",
            "GO_PATH_CONCAT",
            "GO_SQL_CONCAT_INTERMEDIATE",
            "DOTNET_SQL_INTERPOLATED",
            "DOTNET_PROCESS_START_INFO",
            "DOTNET_PATH_COMBINE_TRAVERSAL",
        }

    def test_env_kill_switch_disables_the_pass(self, tmp_path, monkeypatch):
        monkeypatch.setenv("RSX_AST_VALIDATION", "0")
        target = tmp_path / "a.go"
        target.write_text(
            'package main\nvar p = "/var/www/" + name\n', encoding="utf-8")
        findings = [_finding("GO_PATH_CONCAT", target, 2, 'p := "/var/www/" + name')]
        assert apply_ast_validation(findings, str(target)) is findings

    def test_unknown_extension_unchanged(self, tmp_path):
        target = tmp_path / "a.py"
        target.write_text("x = 1\n", encoding="utf-8")
        findings = [_finding("GO_PATH_CONCAT", target, 1, 'p := "/var/www/" + n')]
        assert apply_ast_validation(findings, str(target)) is findings

    def test_missing_file_unchanged(self, tmp_path):
        ghost = tmp_path / "ghost.go"  # never written
        findings = [_finding("GO_PATH_CONCAT", ghost, 1, 'p := "/x/" + n')]
        assert apply_ast_validation(findings, str(ghost)) is findings

    def test_validator_exception_keeps_the_finding(self, tmp_path, monkeypatch):
        target = tmp_path / "a.go"
        target.write_text("package main\n", encoding="utf-8")
        findings = [_finding("GO_PATH_CONCAT", target, 1, 'p := "/x/" + n')]
        monkeypatch.setattr(
            ast_validators, "_validate",
            lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
        assert apply_ast_validation(findings, str(target)) == findings

    def test_malformed_line_keeps_the_finding(self, tmp_path):
        target = tmp_path / "a.go"
        target.write_text("package main\n", encoding="utf-8")
        bad = _finding("GO_PATH_CONCAT", target, "not-a-line", "p := /x/ + n")
        # int("not-a-line") raises inside the validator — caught -> keep.
        assert apply_ast_validation([bad], str(target)) == [bad]

    def test_unclosed_brace_file_still_safe(self, tmp_path):
        # tree-sitter is error-tolerant: a syntactically broken file must
        # neither crash nor lose findings.
        target = tmp_path / "broken.go"
        target.write_text(
            'package main\nfunc f() {\n\tp := "/var/www/" + name\n',
            encoding="utf-8")
        finding = _finding(
            "GO_PATH_CONCAT", target, 3, 'p := "/var/www/" + name')
        result = apply_ast_validation([finding], str(target))
        assert result  # kept (no guard to prove) — never dropped by a crash


# ---------------------------------------------------------------------------
# Grammar plumbing — skipped when the optional wheels are absent
# ---------------------------------------------------------------------------

class TestGrammarPlumbing:
    @needs_ts
    @pytest.mark.parametrize("lang_key,sample", [
        ("javascript", "function f() { const x = 1; }\n"),
        ("typescript", "function f(): void { const x = 1; }\n"),
        ("tsx", "const a = <div>x</div>;\n"),
        ("go", "package main\nfunc f() {}\n"),
        ("csharp", "class C { void M() {} }\n"),
        ("php", "<?php function f() { $x = 1; }\n"),
    ])
    def test_every_grammar_parses(self, lang_key, sample):
        tree = ts.parse(lang_key, sample)
        assert tree is not None
        assert tree.root_node.type

    @needs_go
    def test_enclosing_function_and_rows(self):
        source = (
            "package main\n"
            "func a() {\n"
            "\tx := 1\n"
            "}\n"
            "func b() {\n"
            "\ty := 2\n"
            "}\n"
            "var top = 3\n"
        )
        tree = ts.parse("go", source)
        names = {}

        def func_name(node):
            ident = node.child_by_field_name("name")
            return ts.node_text(ident) if ident is not None else "?"

        for row in (3, 6, 8):
            func = ts.find_enclosing_function(tree, "go", row)
            names[row] = func_name(func) if func is not None else None
        assert names == {3: "a", 6: "b", 8: None}  # top-level -> None

    @needs_ts
    def test_bom_is_stripped_before_parsing(self):
        tree = ts.parse("go", "﻿package main\nfunc f() {}\n")
        assert tree is not None
        assert ts.node_row(tree.root_node) == 1

    @needs_ts
    def test_walk_is_iterative_and_complete(self):
        tree = ts.parse("go", "package main\nfunc f() { g(1) }\n")
        types = [n.type for n in ts.walk(tree.root_node)]
        assert "function_declaration" in types
        assert "call_expression" in types


# ---------------------------------------------------------------------------
# Validator decisions on the golden-corpus fixtures
# ---------------------------------------------------------------------------

class TestPhpCredentialNameCheck:
    @needs_php
    def test_kills_host_and_sql_keeps_password(self):
        """vulnerable.php: `$host = "localhost"` and the SQL builder string
        were both reported as credentials; only `$pass` is one."""
        target = SAST_CORPUS / "php" / "vulnerable.php"
        lines = _lines(target)
        findings = [
            _finding("PHP_HARDCODED_CREDENTIAL", target, 3, lines[2].strip(),
                     "php"),
            _finding("PHP_HARDCODED_CREDENTIAL", target, 5, lines[4].strip(),
                     "php"),
            _finding("PHP_HARDCODED_CREDENTIAL", target, 15, lines[14].strip(),
                     "php"),
        ]
        result = apply_ast_validation(findings, str(target))
        assert [f["line"] for f in result] == [5]

    @needs_php
    def test_credential_shaped_names_survive(self, tmp_path):
        target = tmp_path / "creds.php"
        target.write_text(
            "<?php\n"
            "$db_password = 'hunter2';\n"
            "$api_key = 'AKIAEXAMPLEKEYS';\n"
            "$title = 'A very long page title';\n", encoding="utf-8")
        lines = _lines(target)
        findings = [
            _finding("PHP_HARDCODED_CREDENTIAL", target, i + 1, lines[i], "php")
            for i in (1, 2, 3)
        ]
        result = apply_ast_validation(findings, str(target))
        assert sorted(f["line"] for f in result) == [2, 3]


class TestGuardDominance:
    @needs_go
    def test_go_path_concat_guarded_kills_unguarded_keeps(self):
        safe = SAST_CORPUS / "go" / "safe.go"
        vuln = SAST_CORPUS / "go" / "vulnerable.go"
        safe_finding = _finding(
            "GO_PATH_CONCAT", safe, 68,
            _lines(safe)[67].strip(), "go")
        vuln_finding = _finding(
            "GO_PATH_CONCAT", vuln, 60,
            _lines(vuln)[59].strip(), "go")
        assert apply_ast_validation([safe_finding], str(safe)) == []
        assert apply_ast_validation([vuln_finding], str(vuln)) == [vuln_finding]

    @needs_php
    def test_php_include_guarded_kills_unguarded_keeps(self):
        safe = SAST_CORPUS / "php" / "safe.php"
        vuln = SAST_CORPUS / "php" / "vulnerable.php"
        safe_finding = _finding(
            "PHP_INCLUDE_CONCAT_PATH", safe, 41,
            _lines(safe)[40].strip(), "php")
        vuln_finding = _finding(
            "PHP_INCLUDE_CONCAT_PATH", vuln, 27,
            _lines(vuln)[26].strip(), "php")
        assert apply_ast_validation([safe_finding], str(safe)) == []
        assert apply_ast_validation([vuln_finding], str(vuln)) == [vuln_finding]


class TestGoSqlSinkAnchor:
    @needs_go
    def test_reanchors_assignment_to_sink_line(self):
        """vulnerable.go: the window rule fires on `q := "SELECT..." + input`;
        the corpus labels the sink `db.Query(q)` one line below."""
        target = SAST_CORPUS / "go" / "vulnerable.go"
        lines = _lines(target)
        finding = _finding(
            "GO_SQL_CONCAT_INTERMEDIATE", target, 34, lines[33].strip(), "go")
        result = apply_ast_validation([finding], str(target))
        assert len(result) == 1
        moved = result[0]
        assert moved["line"] == 35
        assert "db.Query(q)" in moved["snippet"]
        assert moved["evidence"].endswith(f":35: {moved['snippet']}")
        assert f"|35|" in moved["group_key"]

    @needs_go
    def test_snippet_without_assignment_unchanged(self):
        target = SAST_CORPUS / "go" / "vulnerable.go"
        finding = _finding(
            "GO_SQL_CONCAT_INTERMEDIATE", target, 35, "rows, err := db.Query(q)",
            "go")
        result = apply_ast_validation([finding], str(target))
        assert result[0]["line"] == 35  # not an assignment snippet -> keep


class TestDotnetSql:
    @needs_csharp
    def test_parameterised_query_sink_is_killed(self):
        """SafeController L28: `.ExecuteReader()` on a command built from a
        PLAIN string literal (+ AddWithValue) is not an injection."""
        target = SAST_CORPUS / "dotnet" / "SafeController.cs"
        finding = _finding(
            "DOTNET_SQL_INTERPOLATED", target, 28,
            _lines(target)[27].strip(), "csharp")
        result = apply_ast_validation([finding], str(target))
        assert result == []

    @needs_csharp
    def test_interpolated_sink_kept_constructor_duplicate_killed(self):
        """VulnerableController: L21 (ExecuteReader on the interpolated
        command) is the canonical anchor; L20 (the constructor with the
        same command) is the duplicate the window rule also produced."""
        target = SAST_CORPUS / "dotnet" / "VulnerableController.cs"
        lines = _lines(target)
        ctor = _finding(
            "DOTNET_SQL_INTERPOLATED", target, 20, lines[19].strip(), "csharp")
        sink = _finding(
            "DOTNET_SQL_INTERPOLATED", target, 21, lines[20].strip(), "csharp")
        result = apply_ast_validation([ctor, sink], str(target))
        assert [f["line"] for f in result] == [21]


class TestDotnetProcess:
    @needs_csharp
    def test_noshell_whitelisted_start_is_killed(self):
        """SafeController L56: FileName is whitelist-guarded (parts[0] via
        allowed.Contains + BadRequest return); UseShellExecute=false."""
        target = SAST_CORPUS / "dotnet" / "SafeController.cs"
        finding = _finding(
            "DOTNET_PROCESS_START_INFO", target, 56,
            _lines(target)[55].strip(), "csharp")
        result = apply_ast_validation([finding], str(target))
        assert result == []

    @needs_csharp
    def test_shell_start_reanchors_to_unsafe_argument(self):
        """VulnerableController L44 `proc.Start()` is the wrong anchor: the
        finding is the `Arguments = "/c " + cmd` statement at L38."""
        target = SAST_CORPUS / "dotnet" / "VulnerableController.cs"
        finding = _finding(
            "DOTNET_PROCESS_START_INFO", target, 44,
            _lines(target)[43].strip(), "csharp")
        result = apply_ast_validation([finding], str(target))
        assert len(result) == 1
        moved = result[0]
        assert moved["line"] == 38
        assert 'Arguments = "/c " + cmd' in moved["snippet"]
        assert moved["evidence"].endswith(f":38: {moved['snippet']}")


class TestDotnetPathCombine:
    @needs_csharp
    def test_guarded_filename_killed(self):
        """SafeController L69: Path.Combine with a filename validated by
        `Contains("..") || IsPathRooted` + BadRequest return at L66-67."""
        target = SAST_CORPUS / "dotnet" / "SafeController.cs"
        finding = _finding(
            "DOTNET_PATH_COMBINE_TRAVERSAL", target, 69,
            _lines(target)[68].strip(), "csharp")
        result = apply_ast_validation([finding], str(target))
        assert result == []

    @needs_csharp
    def test_unguarded_filename_kept(self):
        """VulnerableController L54: identical shape, no guard — the true
        positive must survive the same validator."""
        target = SAST_CORPUS / "dotnet" / "VulnerableController.cs"
        finding = _finding(
            "DOTNET_PATH_COMBINE_TRAVERSAL", target, 54,
            _lines(target)[53].strip(), "csharp")
        result = apply_ast_validation([finding], str(target))
        assert [f["line"] for f in result] == [54]


class TestPhpShellSanitizers:
    @needs_php
    def test_fully_escapeshell_wrapped_killed(self):
        """safe.php L33: `$safeCmd` is escapeshellcmd-derived and the
        remaining segment sits inside escapeshellarg(...)."""
        target = SAST_CORPUS / "php" / "safe.php"
        finding = _finding(
            "TAINT_PHP_COMMAND_INJECTION", target, 33,
            _lines(target)[32].strip(), "php")
        result = apply_ast_validation([finding], str(target))
        assert result == []

    @needs_php
    def test_unwrapped_operand_keeps_the_finding(self):
        """vulnerable.php L23: system("echo " . $cmd) with $cmd straight
        from $_GET — one unwrapped operand keeps the finding alive.
        (Top-level code: no enclosing function -> conservative keep.)"""
        target = SAST_CORPUS / "php" / "vulnerable.php"
        finding = _finding(
            "TAINT_PHP_COMMAND_INJECTION", target, 23,
            _lines(target)[22].strip(), "php")
        result = apply_ast_validation([finding], str(target))
        assert [f["line"] for f in result] == [23]


class TestClosedSetAndDeterminism:
    @needs_php
    def test_other_rules_pass_through_untouched(self):
        target = SAST_CORPUS / "php" / "vulnerable.php"
        lines = _lines(target)
        untouched = _finding(
            "TAINT_MULTIPART_TRAVERSAL", target, 27, lines[26].strip(), "php")
        killed = _finding(
            "PHP_HARDCODED_CREDENTIAL", target, 3, lines[2].strip(), "php")
        result = apply_ast_validation([untouched, killed], str(target))
        assert result == [untouched]

    @needs_csharp
    def test_deterministic_across_runs(self):
        target = SAST_CORPUS / "dotnet" / "VulnerableController.cs"
        lines = _lines(target)

        def build():
            return [
                _finding("DOTNET_PROCESS_START_INFO", target, 44,
                         lines[43].strip(), "csharp"),
                _finding("DOTNET_SQL_INTERPOLATED", target, 20,
                         lines[19].strip(), "csharp"),
                _finding("DOTNET_SQL_INTERPOLATED", target, 21,
                         lines[20].strip(), "csharp"),
            ]

        first = apply_ast_validation(build(), str(target))
        second = apply_ast_validation(build(), str(target))
        assert first == second


# ---------------------------------------------------------------------------
# Wiring — scan_directory must run the pass (works without the wheels too)
# ---------------------------------------------------------------------------

class TestWiring:
    def test_scan_directory_invokes_the_pass(self, tmp_path, monkeypatch):
        target = tmp_path / "proj"
        target.mkdir()
        (target / "main.go").write_text(
            'package main\nimport "fmt"\nfunc main() { fmt.Println("hi") }\n',
            encoding="utf-8")
        calls = []
        monkeypatch.setattr(
            ast_validators, "apply_ast_validation",
            lambda findings, filepath: (calls.append(filepath), findings)[1])
        from scanner.sast import scan_directory
        scan_directory(str(target), workers=1)
        assert any(str(c).endswith("main.go") for c in calls)

    @needs_go
    def test_end_to_end_corpus_fixture_loses_only_the_fp(self, tmp_path):
        """Full pipeline (regex + taint + gate + AST) over safe.go: the
        GO_PATH_CONCAT false positive disappears; vulnerable.go's true
        positive at L60 survives the same validators."""
        import shutil

        from scanner.sast import scan_directory

        safe_dir = tmp_path / "safe"
        safe_dir.mkdir()
        shutil.copy(SAST_CORPUS / "go" / "safe.go", safe_dir / "safe.go")
        safe_findings = scan_directory(str(safe_dir), workers=1)
        assert [f for f in safe_findings
                if f.get("rule_id") == "GO_PATH_CONCAT"] == []

        vuln_dir = tmp_path / "vuln"
        vuln_dir.mkdir()
        shutil.copy(SAST_CORPUS / "go" / "vulnerable.go",
                    vuln_dir / "vulnerable.go")
        vuln_findings = scan_directory(str(vuln_dir), workers=1)
        path_hits = [f for f in vuln_findings
                     if f.get("rule_id") == "GO_PATH_CONCAT"]
        assert [f["line"] for f in path_hits] == [60]  # TP held
        sql_hits = [f for f in vuln_findings
                    if f.get("rule_id") == "GO_SQL_CONCAT_INTERMEDIATE"]
        assert [f["line"] for f in sql_hits] == [35]  # re-anchored to the sink
