"""T-1.4 — the SpanTable + symbol-table facade (Python side).

WHAT THIS IS
------------
A thin, stdlib-only facade over the native core's AST + span layer
(``rsecopsx_core.span_table``): grammar-backed spans and symbols for the
eleven task.md languages, with a self-sufficient Phase-0 fallback when the
native extension is absent (an offline box that only ever ran ``--engine
py`` still gets line-addressable spans, disclosed, never a silent empty
table).

HONESTY CONTRACTS
-----------------
* ``span_table()`` NEVER raises for an unknown language or a missing
  extension -- that IS the fallback path (``grammar: false`` + ``fallback``
  reason). Callers keep their behavior either way.
* Grammar-backed tables come from the native core only (one grammar
  implementation, 11 languages, compiled in). This module does not re-implement
  a parser; the Phase-0 branch is pure line splitting, matching the regex
  engine's granularity.
* Symbol extraction's name heuristic lives in the Rust core; this facade
  only consumes the produced table.
* Nothing here touches finding rows -- the T-1.5 parity gate compares every
  field except ``engine``/``evidence``/``group_key``, so spans travel beside
  findings, never inside them.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

SCHEMA = "rsecopsx.span_table/v1"

#: Node kinds that form a body a source line can sit inside.
_CONTAINER_KINDS = frozenset({
    "function", "method", "class", "struct", "interface", "impl", "enum",
})

#: Common extension -> grammar language key (for ``enclosing_symbol_for_file``).
_EXT_LANG = {
    ".py": "python", ".pyw": "python",
    ".java": "java",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript",
    ".ts": "typescript", ".mts": "typescript",
    ".tsx": "tsx",
    ".go": "go",
    ".php": "php",
    ".cs": "csharp",
    ".rs": "rust",
    ".rb": "ruby",
    ".c": "c",
    ".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp", ".hpp": "cpp", ".hh": "cpp",
}


def _native_core() -> Any:
    """Load the native extension; raises ImportError when unavailable."""
    from scanner import rust_engine
    return rust_engine.load_extension()


def _phase0_table(source: str, language: str, reason: str) -> dict:
    """Line-granularity Phase-0 spans (mirrors the Rust fallback)."""
    text = source[1:] if source.startswith("﻿") else source
    spans: list[dict] = []
    line = 1
    line_start = 0
    data = text.encode("utf-8", "replace")
    for i, b in enumerate(data):
        if b == 0x0A:  # \n
            end = i
            if end > line_start and data[end - 1] == 0x0D:  # CRLF
                end -= 1
            spans.append({
                "start_byte": line_start, "end_byte": end,
                "start_line": line, "end_line": line,
                "start_col": 0, "end_col": end - line_start,
                "kind": "line",
            })
            line += 1
            line_start = i + 1
    if line_start < len(data) or not data:
        spans.append({
            "start_byte": line_start, "end_byte": len(data),
            "start_line": line, "end_line": line,
            "start_col": 0, "end_col": len(data) - line_start,
            "kind": "line",
        })
    return {
        "schema": SCHEMA, "language": language,
        "grammar": False, "fallback": reason,
        "spans": spans, "symbols": [],
    }


def span_table(source: str, language: str) -> dict:
    """Span + symbol table for one source buffer.

    Grammar-backed via the native core; Phase-0 line spans otherwise. Never
    raises for a missing extension or an unknown language.
    """
    try:
        core = _native_core()
        return json.loads(core.span_table(source, language))
    except Exception:  # noqa: BLE001 - the fallback IS the contract
        return _phase0_table(source, language, "native_core_absent")


def enclosing_symbol(source: str, language: str, line: int) -> Optional[dict]:
    """Innermost function/method/type containing the 1-based ``line``.

    ``None`` when the line sits outside every definition (top-level code) or
    the table has no grammar (no symbols) -- callers then treat it as
    "no enclosing symbol", never as an error.
    """
    if line is None or line <= 0:
        return None
    table = span_table(source, language)
    best: Optional[dict] = None
    for sym in table.get("symbols", ()):
        if sym.get("kind") not in _CONTAINER_KINDS:
            continue
        start = int(sym.get("start_line") or 0)
        end = int(sym.get("end_line") or 0)
        if start <= line <= end:
            # Largest start_line = innermost (a method starts after its class).
            if best is None or start >= int(best.get("start_line") or 0):
                best = sym
    return best


def infer_language(path: str | Path) -> str:
    """Grammar language key for a file path (``"unknown"`` when unmapped)."""
    return _EXT_LANG.get(Path(path).suffix.lower(), "unknown")


def enclosing_symbol_for_file(path: str | Path, line: int,
                              language: Optional[str] = None) -> Optional[dict]:
    """Convenience consumer: read ``path`` and resolve the enclosing symbol.

    The file is read defensively; an unreadable file or unknown language
    degrades to ``None`` (Phase-0 / no symbols), never an exception.
    """
    p = Path(path)
    lang = language or infer_language(p)
    try:
        source = p.read_text(encoding="utf-8", errors="replace")
    except Exception:  # noqa: BLE001 - unreadable file -> no context
        return None
    return enclosing_symbol(source, lang, line)


def status() -> dict:
    """Disclosed capability state (native availability + grammar set)."""
    try:
        core = _native_core()
        return {
            "schema": SCHEMA,
            "native": True,
            "grammar_languages": list(core.span_languages()),
            "error": None,
        }
    except Exception as exc:  # noqa: BLE001 - disclosure, not a failure
        return {
            "schema": SCHEMA,
            "native": False,
            "grammar_languages": [],
            "error": f"{type(exc).__name__}: {exc}",
        }
