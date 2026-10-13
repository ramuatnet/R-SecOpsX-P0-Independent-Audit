"""Phase 3.2 — lazy-optional tree-sitter bootstrap for the SAST pipeline.

WHAT THIS IS
------------
An OPTIONAL accelerator: real syntax trees for JavaScript/TypeScript/Go/
C#/PHP, used by ``scanner/ast_validators.py`` to replace line-window
guesses with structural facts. The repo stays a stdlib-only CLI at import
time — ``tree_sitter`` and the grammar wheels are imported lazily on first
use, one grammar at a time, and every failure degrades to the existing
regex/heuristic path with the failure DISCLOSED in :func:`status`.

HONESTY CONTRACTS
-----------------
* No module-level tree-sitter import: ``import scanner.tree_sitter_support``
  must succeed on a box with none of the packages installed.
* ``parse()`` returns ``None`` when the grammar is absent or parsing fails —
  callers keep their current behavior (never a silent "no findings").
* The BOM is stripped before parsing (Windows-authored files carry
  ``\\ufeff``; tree-sitter would count it as a column-0 token). Row/line
  numbering is unaffected because the BOM never occupies a line.
* Grammar versions are pinned by whatever wheel is installed; nothing here
  hardcodes node-type names — those live in the validators, which are
  covered by tests that skip themselves when the grammars are absent.

Node-type facts used by the validators (verified against grammar 0.23–0.25
releases, see tests/test_phase32_tree_sitter.py):
* C#: ``variable_declarator`` (identifier ``=`` value),
  ``object_creation_expression`` (``argument_list``, ``initializer`` →
  ``initializer_expression`` of ``assignment_expression`` children),
  ``interpolated_string_expression``, ``invocation_expression`` →
  ``member_access_expression``, ``if_statement`` (condition/consequence).
* Go: ``short_var_declaration``, ``call_expression`` (function is a
  ``selector_expression`` with a ``field_identifier``), ``if_statement``
  (condition/consequence).
* PHP: ``function_call_expression`` (function/arguments),
  ``assignment_expression`` (left/right), ``if_statement``
  (condition/statements).
"""
from __future__ import annotations

import importlib
from typing import Any, Iterator

# lang_key -> (module, factory attribute). php/typescript ship multiple
# grammars; the plain-source variants are the ones we need.
_LANGUAGE_SPECS: dict[str, tuple[str, str]] = {
    "javascript": ("tree_sitter_javascript", "language"),
    "typescript": ("tree_sitter_typescript", "language_typescript"),
    "tsx": ("tree_sitter_typescript", "language_tsx"),
    "go": ("tree_sitter_go", "language"),
    "csharp": ("tree_sitter_c_sharp", "language"),
    "php": ("tree_sitter_php", "language_php"),
}

#: Function-like node types per language, used to attribute a finding to
#: the function that contains it.
FUNCTION_TYPES: dict[str, frozenset[str]] = {
    "go": frozenset({"function_declaration", "method_declaration", "func_literal"}),
    "csharp": frozenset({"method_declaration", "constructor_declaration",
                         "local_function_statement"}),
    "php": frozenset({"function_definition", "method_declaration",
                      "arrow_function"}),
    "javascript": frozenset({"function_declaration", "function_expression",
                             "generator_function_declaration",
                             "method_definition", "arrow_function"}),
    "typescript": frozenset({"function_declaration", "function_expression",
                             "generator_function_declaration",
                             "method_definition", "arrow_function"}),
    "tsx": frozenset({"function_declaration", "function_expression",
                      "generator_function_declaration", "method_definition",
                      "arrow_function"}),
}

_PARSERS: dict[str, Any] = {}
_LOAD_ERRORS: dict[str, str] = {}


def _parser_for(lang_key: str) -> Any:
    """Load and cache the parser for one grammar; never raises."""
    parser = _PARSERS.get(lang_key)
    if parser is not None:
        return parser
    if lang_key in _LOAD_ERRORS:
        return None
    spec = _LANGUAGE_SPECS.get(lang_key)
    if spec is None:
        _LOAD_ERRORS[lang_key] = "unknown language key"
        return None
    module_name, factory = spec
    try:
        from tree_sitter import Language, Parser  # lazy: optional dependency

        module = importlib.import_module(module_name)
        language = Language(getattr(module, factory)())
        parser = Parser(language)
        _PARSERS[lang_key] = parser
        return parser
    except Exception as exc:  # pragma: no cover - depends on the box
        _LOAD_ERRORS[lang_key] = f"{type(exc).__name__}: {exc}"
        return None


def grammar_available(lang_key: str) -> bool:
    return _parser_for(lang_key) is not None


def available() -> bool:
    """True when at least one grammar can be loaded on this box."""
    return any(grammar_available(key) for key in _LANGUAGE_SPECS)


def status() -> dict:
    """Disclosed capability state — surfaced in the scan payload."""
    grammars = {key: grammar_available(key) for key in _LANGUAGE_SPECS}
    return {
        "available": any(grammars.values()),
        "grammars": grammars,
        "errors": dict(_LOAD_ERRORS),
    }


def parse(lang_key: str, source: str) -> Any:
    """Parse source into a tree; ``None`` means "no AST available"."""
    parser = _parser_for(lang_key)
    if parser is None:
        return None
    try:
        text = source[1:] if source.startswith("\ufeff") else source
        return parser.parse(text.encode("utf-8"))
    except Exception:  # pragma: no cover - defensive
        return None


def node_text(node: Any) -> str:
    try:
        return (node.text or b"").decode("utf-8", "replace")
    except Exception:  # pragma: no cover - defensive
        return ""


def walk(node: Any) -> Iterator[Any]:
    """Iterative pre-order walk (deep trees must not hit recursion limits)."""
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        stack.extend(reversed(current.children))


def node_row(node: Any) -> int:
    """1-based source line of a node's first token."""
    return node.start_point[0] + 1


def find_enclosing_function(tree: Any, lang_key: str, row: int):
    """Innermost function-like node containing the 1-based ``row``.

    Conservative: returns ``None`` when the row sits outside every
    function (top-level code) — validators then keep the finding.
    """
    types = FUNCTION_TYPES.get(lang_key, frozenset())
    best = None
    best_start = -1
    for node in walk(tree.root_node):
        if node.type not in types:
            continue
        start = node.start_point[0]
        end = node.end_point[0]
        if start <= row - 1 <= end and start >= best_start:
            best = node
            best_start = start
    return best


def first_of_type(node: Any, type_name: str) -> Any:
    for candidate in walk(node):
        if candidate.type == type_name:
            return candidate
    return None


def nodes_of_type(node: Any, type_name: str) -> list[Any]:
    return [candidate for candidate in walk(node) if candidate.type == type_name]
