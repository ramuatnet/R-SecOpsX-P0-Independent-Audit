# -*- coding: utf-8 -*-
r"""T-14.1b -- long-tail language coverage (task.md section 14, item 1
remainder: Kotlin, Scala, Swift, Dart, Elixir, Lua, R, Perl).

Measured red ground (2026-11-02, before this batch):

* ``.swift`` / ``.dart`` / ``.ex`` / ``.exs`` / ``.lua`` / ``.r`` /
  ``.pl`` / ``.pm`` were absent from ``SCANNABLE_EXT`` -- a directory
  scan never saw those files at all (``.kt`` / ``.scala`` were already
  scannable);
* zero dedicated rules existed for any of the eight languages: the
  probe shapes (``Runtime.getRuntime().exec(cmd)``,
  ``Process.run(cmd, [])``, ``System.cmd("sh", ...)``,
  ``os.execute(cmd)``, ``system(param("cmd"))``,
  ``NSKeyedUnarchiver.unarchiveObject``, ``String.to_atom(s)``)
  fired nothing dedicated -- only generic cross-language rules
  (``MD5_USAGE`` / ``SHA1_USAGE`` / ``EVAL_CALL``) matched where the
  shape happened to be one of theirs;
* ``.ex`` / ``.pl`` also lacked a ``LANG_BY_EXT`` mapping, so even the
  bare-extension fallback language (``"ex"``, ``"pl"``) would never
  satisfy an ``langs: ['elixir']`` / ``['perl']`` gate.

Bars (G7 honesty standard): injection rules require a dynamic shape
(non-literal argument, string concat/interpolation, or -- for Perl --
a ``param(...)`` call in the same statement as the sink); literal-only
calls stay dark.  Every language gets comment masking so a mention in
``//`` / ``#`` / ``--`` commentary never fires.
"""
from __future__ import annotations

import pathlib
import textwrap

REPO = pathlib.Path(__file__).resolve().parents[1]

#: Extensions this batch adds to the walk gate + language map.
NEW_EXTS = {
    ".swift": "swift",
    ".dart": "dart",
    ".ex": "elixir",
    ".exs": "elixir",
    ".lua": "lua",
    ".r": "r",
    ".pl": "perl",
    ".pm": "perl",
}

#: The 14 rule ids this batch adds to rules/enterprise_v1.yaml.
NEW_RULE_IDS = frozenset({
    "KOTLIN_CMD_INJECTION",
    "KOTLIN_INSECURE_DESER",
    "SCALA_CMD_INJECTION",
    "SCALA_INSECURE_DESER",
    "SWIFT_MD5_SHA1_USAGE",
    "SWIFT_INSECURE_DESER",
    "DART_CMD_INJECTION",
    "ELIXIR_CMD_INJECTION",
    "ELIXIR_ATOM_UNBOUNDED",
    "LUA_CMD_INJECTION",
    "LUA_CODE_INJECTION",
    "R_CMD_INJECTION",
    "PERL_CMD_INJECTION",
    "PERL_CODE_INJECTION",
})

SAST_SRC = (REPO / "scanner" / "sast.py").read_text(encoding="utf-8")
FILE_INDEX_SRC = (REPO / "core" / "file_index.py").read_text(encoding="utf-8")


def _write(tmp_path: pathlib.Path, name: str, source: str) -> pathlib.Path:
    path = tmp_path / name
    path.write_text(textwrap.dedent(source), encoding="utf-8")
    return path


def _sast(tmp_path: pathlib.Path, name: str, source: str) -> list[dict]:
    from scanner.sast import scan_file

    return scan_file(str(_write(tmp_path, name, source)))


def _ids(findings: list[dict]) -> set[str]:
    return {str(f.get("rule_id") or f.get("id")) for f in findings}


# ---------------------------------------------------------------- disclosure


def test_disclosure_needles():
    for needle in ("T-14.1b", "long-tail"):
        assert needle in SAST_SRC, "sast disclosure missing: %r" % needle
        assert needle in FILE_INDEX_SRC, (
            "file_index disclosure missing: %r" % needle)


# -------------------------------------------------------------------- wiring


def test_new_extensions_are_scannable():
    from scanner.sast import SCANNABLE_EXT

    scannable = {str(e).lower() for e in SCANNABLE_EXT}
    missing = {e for e in NEW_EXTS if e not in scannable}
    assert not missing, missing


def test_new_extensions_map_to_languages():
    from core.file_index import LANG_BY_EXT

    for ext, lang in NEW_EXTS.items():
        assert LANG_BY_EXT.get(ext) == lang, (ext, LANG_BY_EXT.get(ext))


def test_language_gates_not_orphaned():
    # Every LANG_BY_EXT key must be walk-scannable (the G7/.sol shape);
    # the batch adds both halves together.
    from analysis.validation.brain import _chk_L1_language_gates_not_orphaned

    evidence = _chk_L1_language_gates_not_orphaned()
    assert "all reachable" in evidence, evidence


def test_comment_prefixes_wired():
    from scanner.sast import _BLOCK_COMMENT_DELIMS, _LINE_COMMENT_PREFIXES

    for lang in ("swift", "dart", "elixir", "lua", "r", "perl"):
        assert lang in _LINE_COMMENT_PREFIXES, lang
    for lang in ("swift", "dart"):
        assert lang in _BLOCK_COMMENT_DELIMS, lang


def test_should_scan_accepts_new_extensions(tmp_path):
    from scanner.sast import _should_scan

    for ext in NEW_EXTS:
        path = tmp_path / ("sample%s" % ext)
        path.write_text("x = 1\n", encoding="utf-8")
        assert _should_scan(path), ext


# -------------------------------------------------------------------- rules


def test_new_rule_ids_registered_with_langs():
    from scanner.sast import ENTERPRISE_RULES

    by_id = {r["id"]: r for r in ENTERPRISE_RULES}
    missing = NEW_RULE_IDS - set(by_id)
    assert not missing, missing
    # langs gates must name exactly the language family that fires them.
    expect_langs = {
        "KOTLIN_CMD_INJECTION": ["kotlin"],
        "KOTLIN_INSECURE_DESER": ["kotlin"],
        "SCALA_CMD_INJECTION": ["scala"],
        "SCALA_INSECURE_DESER": ["scala"],
        "SWIFT_MD5_SHA1_USAGE": ["swift"],
        "SWIFT_INSECURE_DESER": ["swift"],
        "DART_CMD_INJECTION": ["dart"],
        "ELIXIR_CMD_INJECTION": ["elixir"],
        "ELIXIR_ATOM_UNBOUNDED": ["elixir"],
        "LUA_CMD_INJECTION": ["lua"],
        "LUA_CODE_INJECTION": ["lua"],
        "R_CMD_INJECTION": ["r"],
        "PERL_CMD_INJECTION": ["perl"],
        "PERL_CODE_INJECTION": ["perl"],
    }
    for rid, langs in expect_langs.items():
        assert by_id[rid]["langs"] == langs, (rid, by_id[rid]["langs"])


def test_new_ids_resolve_to_real_categories():
    from analysis.ufib_contracts import CONTRACTS, resolve_category

    for rid in sorted(NEW_RULE_IDS):
        cat = resolve_category({"rule_id": rid, "vuln_type": ""})
        assert cat in CONTRACTS, (rid, cat)


def test_new_contract_refs_are_contract_keys():
    from analysis.ufib_contracts import CONTRACTS
    from core import rule_loader

    refs = rule_loader.load_contract_refs()
    for rid in sorted(NEW_RULE_IDS):
        if rid in refs:
            assert refs[rid] in CONTRACTS, (rid, refs[rid])


# ------------------------------------------------------------------- kotlin


def test_kotlin_dynamic_exec_fires(tmp_path):
    findings = _sast(tmp_path, "Run.kt", """\
        fun run(cmd: String) {
            Runtime.getRuntime().exec(cmd)
        }
        """)
    assert "KOTLIN_CMD_INJECTION" in _ids(findings), sorted(_ids(findings))


def test_kotlin_literal_exec_stays_dark(tmp_path):
    findings = _sast(tmp_path, "Ok.kt", """\
        fun ls() {
            Runtime.getRuntime().exec("ls -la")
        }
        """)
    assert "KOTLIN_CMD_INJECTION" not in _ids(findings), sorted(_ids(findings))


def test_kotlin_objectinputstream_fires(tmp_path):
    findings = _sast(tmp_path, "De.kt", """\
        fun load(input: InputStream): Any {
            return ObjectInputStream(input).readObject()
        }
        """)
    assert "KOTLIN_INSECURE_DESER" in _ids(findings), sorted(_ids(findings))


def test_kotlin_comment_mention_stays_dark(tmp_path):
    findings = _sast(tmp_path, "Note.kt", """\
        // Runtime.getRuntime().exec(cmd) is dangerous
        fun ok() = 1
        """)
    assert "KOTLIN_CMD_INJECTION" not in _ids(findings), sorted(_ids(findings))


# -------------------------------------------------------------------- scala


def test_scala_dynamic_exec_fires(tmp_path):
    findings = _sast(tmp_path, "Run.scala", """\
        object Run {
          def exec(cmd: String) = Runtime.getRuntime.exec(cmd + " 2>&1")
        }
        """)
    assert "SCALA_CMD_INJECTION" in _ids(findings), sorted(_ids(findings))


def test_scala_literal_exec_stays_dark(tmp_path):
    findings = _sast(tmp_path, "Ok.scala", """\
        object Ok {
          def ls() = Runtime.getRuntime.exec("ls")
        }
        """)
    assert "SCALA_CMD_INJECTION" not in _ids(findings), sorted(_ids(findings))


def test_scala_objectinputstream_fires(tmp_path):
    findings = _sast(tmp_path, "De.scala", """\
        object De {
          def load(in: java.io.InputStream) =
            new java.io.ObjectInputStream(in).readObject()
        }
        """)
    assert "SCALA_INSECURE_DESER" in _ids(findings), sorted(_ids(findings))


# -------------------------------------------------------------------- swift


def test_swift_insecure_md5_fires(tmp_path):
    findings = _sast(tmp_path, "Hash.swift", """\
        func h(_ data: Data) -> Data {
            return Insecure.MD5.hash(data: data)
        }
        """)
    assert "SWIFT_MD5_SHA1_USAGE" in _ids(findings), sorted(_ids(findings))


def test_swift_modern_sha256_stays_dark(tmp_path):
    findings = _sast(tmp_path, "Ok.swift", """\
        import CryptoKit
        func h(_ data: Data) -> Data {
            return SHA256.hash(data: data)
        }
        """)
    assert "SWIFT_MD5_SHA1_USAGE" not in _ids(findings), sorted(_ids(findings))


def test_swift_nskeyedunarchiver_fires(tmp_path):
    findings = _sast(tmp_path, "De.swift", """\
        func u(_ d: Data) -> Any? {
            return try NSKeyedUnarchiver.unarchiveTopLevelObjectWithData(d)
        }
        """)
    assert "SWIFT_INSECURE_DESER" in _ids(findings), sorted(_ids(findings))


def test_swift_comment_mention_stays_dark(tmp_path):
    findings = _sast(tmp_path, "Note.swift", """\
        // Insecure.MD5.hash(data:) is weak
        func ok() -> Int { 1 }
        """)
    assert "SWIFT_MD5_SHA1_USAGE" not in _ids(findings), sorted(_ids(findings))


# -------------------------------------------------------------------- dart


def test_dart_dynamic_process_run_fires(tmp_path):
    findings = _sast(tmp_path, "run.dart", """\
        Future<void> run(String cmd) async {
          final r = await Process.run(cmd, []);
        }
        """)
    assert "DART_CMD_INJECTION" in _ids(findings), sorted(_ids(findings))


def test_dart_literal_process_run_stays_dark(tmp_path):
    findings = _sast(tmp_path, "ok.dart", """\
        Future<void> ls() async {
          final r = await Process.run('ls', []);
        }
        """)
    assert "DART_CMD_INJECTION" not in _ids(findings), sorted(_ids(findings))


# ------------------------------------------------------------------ elixir


def test_elixir_dynamic_system_cmd_fires(tmp_path):
    findings = _sast(tmp_path, "run.ex", """\
        defmodule A do
          def run(cmd), do: System.cmd(cmd, [])
        end
        """)
    assert "ELIXIR_CMD_INJECTION" in _ids(findings), sorted(_ids(findings))


def test_elixir_interp_system_cmd_fires(tmp_path):
    findings = _sast(tmp_path, "run2.ex", """\
        defmodule A do
          def run(dir), do: System.cmd("sh", ["-c", "ls #{dir}"])
        end
        """)
    assert "ELIXIR_CMD_INJECTION" in _ids(findings), sorted(_ids(findings))


def test_elixir_literal_system_cmd_stays_dark(tmp_path):
    findings = _sast(tmp_path, "ok.ex", """\
        defmodule A do
          def ls, do: System.cmd("ls", [])
        end
        """)
    assert "ELIXIR_CMD_INJECTION" not in _ids(findings), sorted(_ids(findings))


def test_elixir_dynamic_to_atom_fires(tmp_path):
    findings = _sast(tmp_path, "atom.ex", """\
        defmodule A do
          def a(s), do: String.to_atom(s)
        end
        """)
    assert "ELIXIR_ATOM_UNBOUNDED" in _ids(findings), sorted(_ids(findings))


def test_elixir_literal_and_existing_atom_stay_dark(tmp_path):
    findings = _sast(tmp_path, "ok_atom.ex", """\
        defmodule A do
          def a, do: String.to_atom("literal")
          def b(s), do: String.to_existing_atom(s)
        end
        """)
    assert "ELIXIR_ATOM_UNBOUNDED" not in _ids(findings), sorted(_ids(findings))


# --------------------------------------------------------------------- lua


def test_lua_dynamic_os_execute_fires(tmp_path):
    findings = _sast(tmp_path, "run.lua", """\
        function run(cmd)
          os.execute(cmd)
        end
        """)
    assert "LUA_CMD_INJECTION" in _ids(findings), sorted(_ids(findings))


def test_lua_concat_os_execute_fires(tmp_path):
    findings = _sast(tmp_path, "run2.lua", """\
        function run(dir)
          os.execute("ls " .. dir)
        end
        """)
    assert "LUA_CMD_INJECTION" in _ids(findings), sorted(_ids(findings))


def test_lua_literal_os_execute_stays_dark(tmp_path):
    findings = _sast(tmp_path, "ok.lua", """\
        function ls()
          os.execute("ls -la")
        end
        """)
    assert "LUA_CMD_INJECTION" not in _ids(findings), sorted(_ids(findings))


def test_lua_dynamic_loadstring_fires(tmp_path):
    findings = _sast(tmp_path, "load.lua", """\
        function run(src)
          loadstring(src)
        end
        """)
    assert "LUA_CODE_INJECTION" in _ids(findings), sorted(_ids(findings))


def test_lua_literal_load_stays_dark(tmp_path):
    findings = _sast(tmp_path, "ok_load.lua", """\
        local f = load("return 1")
        """)
    assert "LUA_CODE_INJECTION" not in _ids(findings), sorted(_ids(findings))


def test_lua_comment_mention_stays_dark(tmp_path):
    findings = _sast(tmp_path, "note.lua", """\
        -- os.execute(cmd) would be dangerous
        function ok() return 1 end
        """)
    assert "LUA_CMD_INJECTION" not in _ids(findings), sorted(_ids(findings))


# ----------------------------------------------------------------------- r


def test_r_dynamic_system_fires(tmp_path):
    findings = _sast(tmp_path, "run.R", """\
        run <- function(cmd) {
          system(cmd)
        }
        """)
    assert "R_CMD_INJECTION" in _ids(findings), sorted(_ids(findings))


def test_r_literal_system_stays_dark(tmp_path):
    findings = _sast(tmp_path, "ok.R", """\
        ls <- function() {
          system("ls -la")
        }
        """)
    assert "R_CMD_INJECTION" not in _ids(findings), sorted(_ids(findings))


def test_r_comment_mention_stays_dark(tmp_path):
    findings = _sast(tmp_path, "note.R", """\
        # system(cmd) is dangerous
        ok <- function() 1
        """)
    assert "R_CMD_INJECTION" not in _ids(findings), sorted(_ids(findings))


# -------------------------------------------------------------------- perl


def test_perl_param_system_fires(tmp_path):
    findings = _sast(tmp_path, "run.pl", """\
        sub run {
          system(param("cmd"));
        }
        """)
    assert "PERL_CMD_INJECTION" in _ids(findings), sorted(_ids(findings))


def test_perl_param_open_fires(tmp_path):
    # Direct call-arg provenance: param(...) feeds the sink inline. (A
    # red-run premise of backticks + param on one line was wrong and fixed
    # at the TEST layer: Perl backtick provenance always lands in a
    # variable first, so it is not inline-provable -- disclosed.)
    findings = _sast(tmp_path, "run2.pl", """\
        sub run {
          open(my $fh, param("file"));
        }
        """)
    assert "PERL_CMD_INJECTION" in _ids(findings), sorted(_ids(findings))


def test_perl_literal_system_stays_dark(tmp_path):
    findings = _sast(tmp_path, "ok.pl", """\
        sub ls {
          system("ls -la");
        }
        """)
    assert "PERL_CMD_INJECTION" not in _ids(findings), sorted(_ids(findings))


def test_perl_dynamic_eval_fires(tmp_path):
    findings = _sast(tmp_path, "eval.pl", """\
        sub check {
          eval $rule;
        }
        """)
    assert "PERL_CODE_INJECTION" in _ids(findings), sorted(_ids(findings))


def test_perl_eval_block_stays_dark(tmp_path):
    findings = _sast(tmp_path, "ok_eval.pl", """\
        sub safe {
          eval { $x = 1; };
        }
        """)
    assert "PERL_CODE_INJECTION" not in _ids(findings), sorted(_ids(findings))


def test_perl_comment_mention_stays_dark(tmp_path):
    findings = _sast(tmp_path, "note.pl", """\
        # system(param("cmd")) would be dangerous
        sub ok { 1 }
        """)
    assert "PERL_CMD_INJECTION" not in _ids(findings), sorted(_ids(findings))
