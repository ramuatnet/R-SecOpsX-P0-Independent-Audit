//! T-1.4 — AST + span layer.
//!
//! Produces a **SpanTable** (byte/line/column spans of the syntax tree)
//! and a **symbol table** (named definitions with their enclosing type)
//! for the eleven task.md languages, backed by tree-sitter grammars that
//! are compiled INTO this cdylib — so the native core carries its AST
//! capability with no runtime wheel dependency (offline invariant).
//!
//! Where a language has no grammar (yaml, json, shell, generic text, ...)
//! the table **falls back to Phase-0 spans**: one span per source line at
//! the same granularity the regex engine matches on, with an empty symbol
//! table and the fallback DISCLOSED in the envelope (never a silent empty
//! table that looks like "no code here").
//!
//! Honesty contracts:
//! * Row/line numbering is 1-based (matches `tree_sitter_support.node_row`).
//! * The BOM is stripped before parsing (Windows-authored files carry
//!   `﻿`; tree-sitter would count it as a column-0 token); line
//!   numbering is unaffected because the BOM never occupies a line.
//! * Symbol extraction is a disclosed HEURISTIC (name-bearing node
//!   selection, see `extract_name`): functions take the last name-bearing
//!   node before their parameter list, types take the first. Anonymous /
//!   unnameable definitions emit no symbol but still emit their span.
//! * This layer never touches finding rows — the T-1.5 parity gate
//!   compares every field except `engine`/`evidence`/`group_key`, so spans
//!   travel beside findings, never inside them.

use serde::Serialize;
use tree_sitter::{Node, Parser};

/// Envelope schema for a single file's span + symbol table.
pub const SPAN_TABLE_SCHEMA: &str = "rsecopsx.span_table/v1";

/// The eleven task.md languages with a compiled-in grammar.
pub const GRAMMAR_LANGUAGES: &[&str] = &[
    "python", "java", "javascript", "typescript", "tsx", "go", "php",
    "csharp", "rust", "ruby", "c", "cpp",
];

#[derive(Clone, Copy, PartialEq, Eq)]
enum Lang {
    Python,
    Java,
    Javascript,
    Typescript,
    Tsx,
    Go,
    Php,
    Csharp,
    Rust,
    Ruby,
    C,
    Cpp,
}

impl Lang {
    /// Resolve a language key (with common aliases) to a grammar-backed
    /// language, or `None` when there is no grammar (Phase-0 fallback).
    fn from_key(key: &str) -> Option<Lang> {
        let k = key.trim().to_ascii_lowercase();
        Some(match k.as_str() {
            "python" | "py" | "python3" => Lang::Python,
            "java" => Lang::Java,
            "javascript" | "js" | "jsx" | "node" => Lang::Javascript,
            "typescript" | "ts" => Lang::Typescript,
            "tsx" => Lang::Tsx,
            "go" | "golang" => Lang::Go,
            "php" => Lang::Php,
            "csharp" | "c#" | "cs" => Lang::Csharp,
            "rust" | "rs" => Lang::Rust,
            "ruby" | "rb" => Lang::Ruby,
            "c" => Lang::C,
            "cpp" | "c++" | "cxx" => Lang::Cpp,
            _ => return None,
        })
    }

    fn key(self) -> &'static str {
        match self {
            Lang::Python => "python",
            Lang::Java => "java",
            Lang::Javascript => "javascript",
            Lang::Typescript => "typescript",
            Lang::Tsx => "tsx",
            Lang::Go => "go",
            Lang::Php => "php",
            Lang::Csharp => "csharp",
            Lang::Rust => "rust",
            Lang::Ruby => "ruby",
            Lang::C => "c",
            Lang::Cpp => "cpp",
        }
    }

    fn to_tree_sitter(self) -> tree_sitter::Language {
        match self {
            Lang::Python => tree_sitter_python::LANGUAGE.into(),
            Lang::Java => tree_sitter_java::LANGUAGE.into(),
            Lang::Javascript => tree_sitter_javascript::LANGUAGE.into(),
            Lang::Typescript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
            Lang::Tsx => tree_sitter_typescript::LANGUAGE_TSX.into(),
            Lang::Go => tree_sitter_go::LANGUAGE.into(),
            Lang::Php => tree_sitter_php::LANGUAGE_PHP.into(),
            Lang::Csharp => tree_sitter_c_sharp::LANGUAGE.into(),
            Lang::Rust => tree_sitter_rust::LANGUAGE.into(),
            Lang::Ruby => tree_sitter_ruby::LANGUAGE.into(),
            Lang::C => tree_sitter_c::LANGUAGE.into(),
            Lang::Cpp => tree_sitter_cpp::LANGUAGE.into(),
        }
    }
}

/// Classification of a named definition.
#[derive(Clone, Copy, PartialEq, Eq)]
enum SymKind {
    Function,
    Method,
    Class,
    Struct,
    Interface,
    Impl,
    Enum,
    Import,
}

impl SymKind {
    fn as_str(self) -> &'static str {
        match self {
            SymKind::Function => "function",
            SymKind::Method => "method",
            SymKind::Class => "class",
            SymKind::Struct => "struct",
            SymKind::Interface => "interface",
            SymKind::Impl => "impl",
            SymKind::Enum => "enum",
            SymKind::Import => "import",
        }
    }

    /// Types nest: an inner definition's `enclosing` is the nearest type.
    fn is_type(self) -> bool {
        matches!(
            self,
            SymKind::Class | SymKind::Struct | SymKind::Interface | SymKind::Impl | SymKind::Enum
        )
    }

    /// Functions/methods resolve their name as "last before the params".
    fn is_fn(self) -> bool {
        matches!(self, SymKind::Function | SymKind::Method)
    }
}

/// Per-language map: syntax-node type -> symbol kind. Node types verified
/// against the compiled grammar 0.23 set (see tests/test_t14_span_layer.py).
fn def_map(lang: Lang) -> &'static [(&'static str, SymKind)] {
    use SymKind::*;
    match lang {
        Lang::Python => &[
            ("function_definition", Function),
            ("class_definition", Class),
            ("import_statement", Import),
            ("import_from_statement", Import),
        ],
        Lang::Java => &[
            ("method_declaration", Method),
            ("constructor_declaration", Method),
            ("class_declaration", Class),
            ("interface_declaration", Interface),
            ("enum_declaration", Enum),
            ("import_declaration", Import),
        ],
        Lang::Javascript => &[
            ("function_declaration", Function),
            ("generator_function_declaration", Function),
            ("function_expression", Function),
            ("arrow_function", Function),
            ("method_definition", Method),
            ("class_declaration", Class),
            ("class", Class),
            ("import_statement", Import),
        ],
        Lang::Typescript => &[
            ("function_declaration", Function),
            ("generator_function_declaration", Function),
            ("function_expression", Function),
            ("arrow_function", Function),
            ("method_definition", Method),
            ("class_declaration", Class),
            ("class", Class),
            ("interface_declaration", Interface),
            ("enum_declaration", Enum),
            ("import_statement", Import),
        ],
        Lang::Tsx => &[
            ("function_declaration", Function),
            ("generator_function_declaration", Function),
            ("function_expression", Function),
            ("arrow_function", Function),
            ("method_definition", Method),
            ("class_declaration", Class),
            ("class", Class),
            ("interface_declaration", Interface),
            ("enum_declaration", Enum),
            ("import_statement", Import),
        ],
        Lang::Go => &[
            ("function_declaration", Function),
            ("method_declaration", Method),
            // type_spec covers struct/interface/alias; classified struct as
            // a disclosed approximation (the span, not the kind, is load-bearing).
            ("type_spec", Struct),
            ("import_declaration", Import),
        ],
        Lang::Php => &[
            ("function_definition", Function),
            ("method_declaration", Method),
            ("class_declaration", Class),
            ("interface_declaration", Interface),
            ("trait_declaration", Class),
            ("namespace_use_declaration", Import),
        ],
        Lang::Csharp => &[
            ("method_declaration", Method),
            ("constructor_declaration", Method),
            ("class_declaration", Class),
            ("interface_declaration", Interface),
            ("struct_declaration", Struct),
            ("enum_declaration", Enum),
            ("using_directive", Import),
        ],
        Lang::Rust => &[
            ("function_item", Function),
            ("impl_item", Impl),
            ("struct_item", Struct),
            ("enum_item", Enum),
            ("trait_item", Interface),
            ("mod_item", Class),
            ("use_declaration", Import),
        ],
        Lang::Ruby => &[
            ("method", Function),
            ("singleton_method", Function),
            ("class", Class),
            ("module", Class),
        ],
        Lang::C => &[
            ("function_definition", Function),
            ("struct_specifier", Struct),
            ("enum_specifier", Enum),
            ("preproc_include", Import),
        ],
        Lang::Cpp => &[
            ("function_definition", Function),
            ("struct_specifier", Struct),
            ("class_specifier", Class),
            ("enum_specifier", Enum),
            ("namespace_definition", Class),
            ("preproc_include", Import),
        ],
    }
}

fn def_kind(node_type: &str, lang: Lang) -> Option<SymKind> {
    def_map(lang)
        .iter()
        .find(|(t, _)| *t == node_type)
        .map(|(_, k)| *k)
}

#[derive(Serialize)]
pub struct Span {
    #[serde(rename = "start_byte")]
    pub start_byte: usize,
    #[serde(rename = "end_byte")]
    pub end_byte: usize,
    #[serde(rename = "start_line")]
    pub start_line: usize,
    #[serde(rename = "end_line")]
    pub end_line: usize,
    #[serde(rename = "start_col")]
    pub start_col: usize,
    #[serde(rename = "end_col")]
    pub end_col: usize,
    pub kind: String,
}

#[derive(Serialize)]
pub struct Symbol {
    pub name: String,
    pub kind: String,
    #[serde(rename = "start_line")]
    pub start_line: usize,
    #[serde(rename = "end_line")]
    pub end_line: usize,
    /// Nearest enclosing type (class/struct/interface/impl/enum) name, or
    /// `None` for top-level definitions.
    pub enclosing: Option<String>,
}

#[derive(Serialize)]
pub struct SpanTable {
    pub schema: &'static str,
    /// Normalized language key (raw input when there is no grammar).
    pub language: String,
    /// True when a tree-sitter grammar produced the table.
    pub grammar: bool,
    /// `null` on the grammar path; otherwise the disclosed fallback reason.
    pub fallback: Option<String>,
    pub spans: Vec<Span>,
    pub symbols: Vec<Symbol>,
}

/// Build the span + symbol table for one source buffer.
///
/// Grammar-backed for the eleven task.md languages; Phase-0 line spans for
/// everything else (disclosed via `fallback`).
pub fn span_table(source: &str, language: &str) -> SpanTable {
    match Lang::from_key(language) {
        Some(lang) => grammar_table(source, lang),
        None => phase0_table(source, language, "no_grammar"),
    }
}

/// The grammar-backed path: parse and collect named-node spans + symbols.
fn grammar_table(source: &str, lang: Lang) -> SpanTable {
    // Strip the BOM before parsing (tree-sitter would count it as a token).
    let text = source.strip_prefix('\u{feff}').unwrap_or(source);
    let bytes = text.as_bytes();

    let mut parser = Parser::new();
    if parser.set_language(&lang.to_tree_sitter()).is_err() {
        // Grammar present in Cargo but unloadable at runtime -> disclose.
        return phase0_table(source, lang.key(), "grammar_unsupported");
    }
    let tree = match parser.parse(bytes, None) {
        Some(t) => t,
        // Defensive: tree-sitter returns a tree even for error-recovered
        // input; only a genuine None (OOM / unsupported) lands here.
        None => return phase0_table(source, lang.key(), "parse_error"),
    };

    let root = tree.root_node();
    let (spans, symbols) = collect(&root, lang, bytes);

    SpanTable {
        schema: SPAN_TABLE_SCHEMA,
        language: lang.key().to_string(),
        grammar: true,
        fallback: None,
        spans,
        symbols,
    }
}

/// Phase-0 fallback: one span per source line, no symbols, reason disclosed.
///
/// This is the same granularity the regex engine matches on, so a file with
/// no grammar still yields usable line-addressable spans instead of nothing.
fn phase0_table(source: &str, language: &str, reason: &str) -> SpanTable {
    let text = source.strip_prefix('\u{feff}').unwrap_or(source);
    let mut spans = Vec::new();
    let mut line = 1usize;
    let mut line_start = 0usize;
    let bytes = text.as_bytes();
    for (i, b) in bytes.iter().enumerate() {
        if *b == b'\n' {
            let mut end = i;
            // CRLF: the span excludes the carriage return.
            if end > line_start && bytes[end - 1] == b'\r' {
                end -= 1;
            }
            spans.push(Span {
                start_byte: line_start,
                end_byte: end,
                start_line: line,
                end_line: line,
                start_col: 0,
                end_col: end - line_start,
                kind: "line".to_string(),
            });
            line += 1;
            line_start = i + 1;
        }
    }
    // Trailing line without a newline.
    if line_start <= bytes.len() && (line_start < bytes.len() || bytes.is_empty()) {
        let end = bytes.len();
        if end > line_start || bytes.is_empty() {
            spans.push(Span {
                start_byte: line_start,
                end_byte: end,
                start_line: line,
                end_line: line,
                start_col: 0,
                end_col: end - line_start,
                kind: "line".to_string(),
            });
        }
    }

    SpanTable {
        schema: SPAN_TABLE_SCHEMA,
        language: language.to_string(),
        grammar: false,
        fallback: Some(reason.to_string()),
        spans,
        symbols: Vec::new(),
    }
}

/// Pre-order walk collecting named-node spans and named definitions, with
/// the nearest enclosing type tracked on an explicit stack (deep trees must
/// not hit recursion limits).
fn collect(root: &Node, lang: Lang, src: &[u8]) -> (Vec<Span>, Vec<Symbol>) {
    let mut spans: Vec<Span> = Vec::new();
    let mut symbols: Vec<Symbol> = Vec::new();
    // (node, enclosing type name for its descendants)
    let mut stack: Vec<(Node, Option<String>)> = vec![(*root, None)];

    while let Some((node, enclosing)) = stack.pop() {
        if node.is_named() {
            let sp = node.start_position();
            let ep = node.end_position();
            spans.push(Span {
                start_byte: node.start_byte(),
                end_byte: node.end_byte(),
                start_line: sp.row + 1,
                end_line: ep.row + 1,
                start_col: sp.column,
                end_col: ep.column,
                kind: node.kind().to_string(),
            });
        }

        let mut child_enclosing = enclosing.clone();
        if let Some((kind, name)) = extract_symbol(&node, lang, src) {
            symbols.push(Symbol {
                name: name.clone(),
                kind: kind.as_str().to_string(),
                start_line: node.start_position().row + 1,
                end_line: node.end_position().row + 1,
                enclosing: enclosing.clone(),
            });
            if kind.is_type() {
                child_enclosing = Some(name);
            }
        }

        // Push children reversed so they pop in source order.
        for i in (0..node.child_count()).rev() {
            if let Some(child) = node.child(i) {
                stack.push((child, child_enclosing.clone()));
            }
        }
    }

    (spans, symbols)
}

/// Name + kind for a definition node, `None` when it is not a definition
/// or has no extractable name (anonymous).
fn extract_symbol(node: &Node, lang: Lang, src: &[u8]) -> Option<(SymKind, String)> {
    let kind = def_kind(node.kind(), lang)?;
    let name = extract_name(node, kind, src)?;
    Some((kind, name))
}

/// Disclosed heuristic for the declared name.
///
/// Functions/methods: the LAST name-bearing node before the first parameter
/// node (so `public MyType foo(...)` yields `foo`, not `MyType`); when there
/// is no parameter node (e.g. a Ruby `def foo` with no args) the FIRST
/// name-bearing node (the body's identifiers are never scanned).
/// Types/imports: the FIRST name-bearing node.
fn extract_name(node: &Node, kind: SymKind, src: &[u8]) -> Option<String> {
    let named = named_descendants(*node);
    if kind.is_fn() {
        let param_idx = named.iter().position(|n| is_param_type(n.kind()));
        if let Some(idx) = param_idx {
            named[..idx]
                .iter()
                .rev()
                .find_map(|n| name_text(n, src))
                .map(|s| s.to_string())
        } else {
            named.iter().find_map(|n| name_text(n, src)).map(|s| s.to_string())
        }
    } else {
        named.iter().find_map(|n| name_text(n, src)).map(|s| s.to_string())
    }
}

/// Named descendants of `root` in pre-order (iterative, no recursion).
fn named_descendants<'a>(root: Node<'a>) -> Vec<Node<'a>> {
    let mut out = Vec::new();
    let mut stack = vec![root];
    while let Some(n) = stack.pop() {
        if n.is_named() {
            out.push(n);
        }
        for i in (0..n.child_count()).rev() {
            if let Some(c) = n.child(i) {
                stack.push(c);
            }
        }
    }
    out
}

/// Node types that open a parameter list ("parameters", "formal_parameters",
/// "parameter_list", "method_parameters", ...).
fn is_param_type(kind: &str) -> bool {
    kind.contains("param")
}

/// The node's text when it can carry a declared name.
fn name_text<'a>(n: &Node, src: &'a [u8]) -> Option<&'a str> {
    if !is_name_type(n.kind()) {
        return None;
    }
    n.utf8_text(src).ok()
}

/// Name-bearing node types: any `*_identifier`, plus `name`, `constant`
/// (Ruby class names, Go type names) and `word`.
fn is_name_type(kind: &str) -> bool {
    kind == "name" || kind == "constant" || kind == "word" || kind.contains("identifier")
}
