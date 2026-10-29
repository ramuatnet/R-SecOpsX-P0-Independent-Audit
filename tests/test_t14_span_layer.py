"""T-1.4: AST + span layer (SpanTable + symbol table, Phase-0 fallback).

task.md section 3, T-1.4:

    `tree-sitter` grammars: python, java, js, ts, go, php, csharp, rust,
    ruby, c, cpp. Produce SpanTable + symbol table; fall back to Phase-0
    spans where no grammar.

The contract asserted here:

  * the native core carries eleven compiled-in tree-sitter grammars and
    emits a grammar-backed SpanTable (`spans`) + symbol table (`symbols`)
    with 1-based lines, enclosing-type attribution, and the BOM stripped;
  * a language with NO grammar (yaml, swift, ...) falls back to Phase-0
    LINE spans with `grammar=false` and the fallback DISCLOSED (never a
    silent empty table that reads as "no code here");
  * `scanner/span_layer.py` is the Python facade: grammar tables come from
    the native core only, and when the extension is absent it degrades to
    Phase-0 (`native_core_absent`) -- never raises;
  * `enclosing_symbol` resolves the innermost definition around a line
    (method beats its class) and returns None for top-level / no-symbol;
  * the layer's ONE product consumer (fix_validation `code_context`) is
    ADDITIVE and parity-excluded -- it never mutates finding rows, so the
    T-1.5 parity gate (all fields except engine/evidence/group_key) and the
    replay gate (byte-identical evidence) stay green.
"""
from __future__ import annotations

import json
import pathlib
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))


def _load_core():
    from scanner import rust_engine
    try:
        return rust_engine.load_extension()
    except Exception as exc:  # pragma: no cover - depends on the build
        pytest.skip(f"native core not built: {exc}")


PY_SRC = """class Foo:
    def bar(self, x):
        return x

def top(a):
    import os
    return a
"""

JAVA_SRC = """public class Svc {
  public int compute(int n) { return n; }
}
"""

RUST_SRC = """struct Rect { w: i32 }
impl Rect {
    fn area(&self) -> i32 { self.w }
}
fn helper() {}
"""

YAML_SRC = "a: 1\nb: [2, 3]\n"


# ---------------------------------------------------------------------------
# 1. Native core: grammar-backed SpanTable + symbol table
# ---------------------------------------------------------------------------
def test_core_span_languages_lists_eleven_task_languages():
    core = _load_core()
    langs = set(core.span_languages())
    assert langs == {"python", "java", "javascript", "typescript", "tsx",
                     "go", "php", "csharp", "rust", "ruby", "c", "cpp"}


def test_core_span_table_python_symbols_and_enclosing():
    core = _load_core()
    t = json.loads(core.span_table(PY_SRC, "python"))
    assert t["schema"] == "rsecopsx.span_table/v1"
    assert t["grammar"] is True and t["fallback"] is None
    assert t["language"] == "python"
    assert t["spans"], "grammar path must emit spans"
    syms = {s["name"]: s for s in t["symbols"]}
    assert syms["Foo"]["kind"] == "class" and syms["Foo"]["enclosing"] is None
    assert syms["bar"]["kind"] == "function"
    assert syms["bar"]["enclosing"] == "Foo"
    assert syms["top"]["enclosing"] is None
    assert syms["os"]["kind"] == "import"
    # 1-based lines.
    assert syms["Foo"]["start_line"] == 1
    assert syms["bar"]["start_line"] == 2


def test_core_span_table_java_method_name_not_return_type():
    # "public int compute(...)": the name heuristic must pick `compute`
    # (last name-bearing node before the params), not `int`/the class.
    core = _load_core()
    t = json.loads(core.span_table(JAVA_SRC, "java"))
    syms = {s["name"]: s for s in t["symbols"]}
    assert "compute" in syms
    assert syms["compute"]["kind"] == "method"
    assert syms["compute"]["enclosing"] == "Svc"


def test_core_span_table_rust_impl_enclosing_and_fn():
    core = _load_core()
    t = json.loads(core.span_table(RUST_SRC, "rust"))
    syms = t["symbols"]
    # `struct Rect` AND `impl Rect` are both real definitions -> two symbols
    # named Rect (kinds struct + impl); a name-keyed dict would lose one.
    kinds: dict[str, set[str]] = {}
    for s in syms:
        kinds.setdefault(s["kind"], set()).add(s["name"])
    assert "Rect" in kinds.get("struct", set())
    assert "Rect" in kinds.get("impl", set())
    area = next(s for s in syms if s["name"] == "area")
    assert area["kind"] == "function"
    assert area["enclosing"] == "Rect"   # method body sits inside the impl
    helper = next(s for s in syms if s["name"] == "helper")
    assert helper["enclosing"] is None


def test_core_span_table_strips_bom():
    core = _load_core()
    t = json.loads(core.span_table("﻿def f():\n    pass\n", "python"))
    assert t["grammar"] is True
    names = [s["name"] for s in t["symbols"]]
    assert "f" in names
    # The BOM must not shift line 1 (it never occupies a line).
    f = next(s for s in t["symbols"] if s["name"] == "f")
    assert f["start_line"] == 1


def test_core_span_table_crlf_lines_are_1_based():
    core = _load_core()
    t = json.loads(core.span_table("a = 1\r\ndef f():\r\n    pass\r\n", "python"))
    syms = {s["name"]: s for s in t["symbols"]}
    assert syms["f"]["start_line"] == 2


# ---------------------------------------------------------------------------
# 2. Phase-0 fallback where NO grammar exists (disclosed, never silent)
# ---------------------------------------------------------------------------
def test_core_falls_back_to_phase0_when_no_grammar():
    core = _load_core()
    t = json.loads(core.span_table(YAML_SRC, "yaml"))
    assert t["grammar"] is False
    assert t["fallback"] == "no_grammar"
    assert t["symbols"] == []
    assert len(t["spans"]) == 2          # two lines
    assert all(s["kind"] == "line" for s in t["spans"])
    assert t["spans"][0]["start_line"] == 1 and t["spans"][1]["start_line"] == 2
    # byte spans cover each line's content.
    assert t["spans"][0]["start_byte"] == 0


def test_core_falls_back_for_unmapped_language():
    core = _load_core()
    t = json.loads(core.span_table("let x = 1;\n", "swift"))
    assert t["grammar"] is False and t["fallback"] == "no_grammar"
    assert t["language"] == "swift"
    assert len(t["spans"]) == 1


def test_core_phase0_last_line_without_newline():
    core = _load_core()
    t = json.loads(core.span_table("only-line-no-newline", "generic"))
    assert t["grammar"] is False
    assert len(t["spans"]) == 1
    assert t["spans"][0]["end_byte"] == len("only-line-no-newline")


# ---------------------------------------------------------------------------
# 3. span_layer facade: delegation, fallback, enclosing_symbol
# ---------------------------------------------------------------------------
def test_span_layer_delegates_to_native_core():
    from scanner import span_layer
    t = span_layer.span_table(PY_SRC, "python")
    assert t["grammar"] is True and t["schema"] == span_layer.SCHEMA
    assert {s["name"] for s in t["symbols"]} >= {"Foo", "bar"}


def test_span_layer_phase0_when_native_absent(monkeypatch):
    from scanner import span_layer

    def _raise():
        raise ImportError("simulated missing native core")

    monkeypatch.setattr(span_layer, "_native_core", _raise)
    t = span_layer.span_table("a: 1\nb: 2\n", "yaml")
    assert t["grammar"] is False
    assert t["fallback"] == "native_core_absent"
    assert len(t["spans"]) == 2
    assert t["symbols"] == []


def test_span_layer_never_raises_for_unknown_language():
    from scanner import span_layer
    t = span_layer.span_table("whatever", "klingon")
    assert t["grammar"] is False
    assert t["symbols"] == []
    assert t["spans"]  # still line-addressable


def test_enclosing_symbol_innermost_method_beats_class():
    from scanner import span_layer
    src = ("class C:\n"
           "    def m(self):\n"
           "        x = 1\n"      # line 3: inside m, inside C
           "y = 2\n")            # line 4: top-level
    inner = span_layer.enclosing_symbol(src, "python", 3)
    assert inner is not None
    assert inner["name"] == "m"          # innermost, not C
    assert inner["enclosing"] == "C"
    assert span_layer.enclosing_symbol(src, "python", 4) is None   # top-level
    assert span_layer.enclosing_symbol(src, "python", 99) is None  # out of range
    assert span_layer.enclosing_symbol(src, "python", 0) is None   # invalid


def test_enclosing_symbol_none_when_no_grammar():
    from scanner import span_layer
    # yaml has no grammar -> no symbols -> None (honest, not an error).
    assert span_layer.enclosing_symbol("a: 1\n", "yaml", 1) is None


def test_infer_language_mapping():
    from scanner import span_layer
    assert span_layer.infer_language("a/b/c.py") == "python"
    assert span_layer.infer_language("x.ts") == "typescript"
    assert span_layer.infer_language("x.tsx") == "tsx"
    assert span_layer.infer_language("x.rs") == "rust"
    assert span_layer.infer_language("x.rb") == "ruby"
    assert span_layer.infer_language("x.c") == "c"
    assert span_layer.infer_language("x.cpp") == "cpp"
    assert span_layer.infer_language("x.cs") == "csharp"
    assert span_layer.infer_language("x.unknownext") == "unknown"


def test_enclosing_symbol_for_file_reads_source(tmp_path):
    from scanner import span_layer
    f = tmp_path / "mod.py"
    f.write_text("def fn():\n    return 1\n", encoding="utf-8")
    sym = span_layer.enclosing_symbol_for_file(f, 2)
    assert sym is not None and sym["name"] == "fn"
    # Unreadable file -> None, never an exception.
    assert span_layer.enclosing_symbol_for_file(tmp_path / "missing.py", 1) is None


def test_span_layer_status_discloses_native_and_grammars():
    from scanner import span_layer
    st = span_layer.status()
    assert st["schema"] == span_layer.SCHEMA
    if st["native"]:
        # All ELEVEN task.md languages have a compiled-in grammar, plus
        # tsx as an intentional bonus (the Python layer treats it too).
        task = {"python", "java", "javascript", "typescript", "go", "php",
                "csharp", "rust", "ruby", "c", "cpp"}
        assert task <= set(st["grammar_languages"])
        assert "tsx" in st["grammar_languages"]
        assert st["error"] is None
    else:  # pragma: no cover - offline box
        assert st["grammar_languages"] == [] and st["error"]


# ---------------------------------------------------------------------------
# 4. Product consumer: fix_validation code_context is additive + parity-safe
# ---------------------------------------------------------------------------
def test_fix_validation_code_context_is_additive(tmp_path):
    from analysis.repro import fix_validation as fv
    tgt = tmp_path / "target"
    tgt.mkdir()
    (tgt / "app.py").write_text(
        "class Handler:\n    def serve(self):\n        q = 1\n", encoding="utf-8")
    finding = {"rule_id": "T14_DEMO", "file": "app.py", "line": 3,
               "language": "python"}
    ctx = fv._code_context(tgt, finding)
    assert ctx is not None
    assert ctx["line"] == 3 and ctx["language"] == "python"
    sym = ctx["enclosing_symbol"]
    assert sym is not None and sym["name"] == "serve"
    assert sym["enclosing"] == "Handler"


def test_fix_validation_code_context_defensive(tmp_path):
    from analysis.repro import fix_validation as fv
    tgt = tmp_path / "empty_target"
    tgt.mkdir()
    # Missing source file -> enclosing_symbol None, context still a dict.
    finding = {"file": "nope.py", "line": 1, "language": "python"}
    ctx = fv._code_context(tgt, finding)
    assert ctx is None or ctx["enclosing_symbol"] is None
    # No file at all -> None.
    assert fv._code_context(tgt, {"line": 1}) is None


def test_code_context_is_top_level_additive_key():
    # Parity guard: the consumer adds a TOP-LEVEL `code_context` key and
    # never injects span data into finding_ref (which mirrors a finding row).
    import inspect
    from analysis.repro import fix_validation as fv
    src = inspect.getsource(fv.validate_fix)
    assert 'report["code_context"]' in src
    # finding_ref is a fixed identity dict; code_context is assigned to the
    # report separately, so finding_ref stays byte-stable for parity.
    assert '"enclosing_symbol"' not in src.split("finding_ref")[0]
    ctx = fv._code_context(pathlib.Path("/nonexistent"), {"line": 1})
    assert ctx is None  # no file -> graceful None, not a crash


# ---------------------------------------------------------------------------
# 5. The layer is genuinely backed by the native core (not decorative)
# ---------------------------------------------------------------------------
def test_native_core_exposes_span_api():
    core = _load_core()
    assert hasattr(core, "span_table") and hasattr(core, "span_languages")
    assert core.SPAN_TABLE_SCHEMA == "rsecopsx.span_table/v1"


def test_span_table_and_findings_are_separate_structures():
    # span_table returns ONLY schema/language/grammar/fallback/spans/symbols;
    # it never carries finding fields -- so it cannot leak into a finding row.
    core = _load_core()
    t = json.loads(core.span_table(PY_SRC, "python"))
    assert set(t) == {"schema", "language", "grammar", "fallback",
                      "spans", "symbols"}
    for s in t["spans"]:
        assert set(s) == {"start_byte", "end_byte", "start_line",
                          "end_line", "start_col", "end_col", "kind"}
