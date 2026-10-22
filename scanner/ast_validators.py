"""Phase 3.2 — AST-validated precision layer for the window/regex SAST rules.

WHAT THIS DOES
--------------
``apply_ast_validation(findings, filepath)`` is a per-file post-pass wired
in ``scanner/sast.py::scan_directory`` AFTER the regex and taint engines
have both contributed findings (so it can reason across engines' output
for one file). For a closed set of rule ids it uses a real syntax tree
(``scanner/tree_sitter_support``) to make one of three decisions per
candidate:

* KILL — the structural facts disprove the line-shape guess;
* RE-ANCHOR — the finding is real but the window rule pointed at the wrong
  statement (the assignment instead of the sink, or the start call instead
  of the unsafe argument); the line/snippet/evidence move together;
* KEEP — everything else, including every case the validator cannot prove.

Each decision is a NEGATIVE decision about one candidate — nothing here
invents findings, and every kill path has an explicit escape: no grammar,
unparseable file, unresolvable variable, no enclosing function → KEEP.

THE RULES AND WHY (each pinned by tests/test_phase32_tree_sitter.py,
measured on tests/vuln-test-corpus/sast)
-----------------------------------------
* ``PHP_HARDCODED_CREDENTIAL`` (regex ``$var = "8+ chars"``) fired on ANY
  long string assignment: ``$host = "localhost"`` and the SQL builder
  ``$sql = "SELECT ..."`` were both "credentials". Now the variable name
  must be credential-shaped (pass/pwd/secret/token/key/auth/...).
* ``DOTNET_SQL_INTERPOLATED`` fires on ``.ExecuteReader()`` regardless of
  how the command text was built — a PARAMETERISED query
  (``new SqlCommand("... @pName", conn)``) still matched. The tree proves
  the constructor's first argument is a plain string literal → kill; and
  when both the constructor branch and the sink branch fire for the same
  command, the constructor branch is the duplicate → kill (the sink is the
  canonical anchor).
* ``DOTNET_PROCESS_START_INFO`` fires on ANY ``.Start()``. Facts that
  disprove it: ``UseShellExecute = false`` with a non-shell FileName
  (arguments never reach a shell), or a FileName variable guarded by a
  whitelist check with an early exit. When the finding is real, the
  ``.Start()`` line is the wrong anchor — the unsafe argument assignment
  (``Arguments = "/c " + cmd``) is the finding, so it is re-anchored there.
* ``GO_PATH_CONCAT`` / ``PHP_INCLUDE_CONCAT_PATH`` fire on the
  concatenation line with no idea whether the variable was validated. A
  guard-dominance check (an ``if`` mentioning the variable with a
  traversal check — ``..`` / IsPathRooted / HasPrefix / strpos — whose
  block exits early, preceding the sink) kills the safe cases.
* ``GO_SQL_CONCAT_INTERMEDIATE`` fires on the ASSIGNMENT of the query
  variable; the corpus labels the SINK (``db.Query(q)``). Re-anchors to
  the first SQL-sink call consuming the variable — converting a
  false-positive-at-the-wrong-line into the true positive at the sink.
* ``TAINT_PHP_COMMAND_INJECTION`` (taint window rule) fires on
  ``shell_exec($a . " " . $b)`` even when every variable operand is
  ``escapeshellarg``/``escapeshellcmd``-derived — the sanitized case is
  killed only when EVERY variable operand is wrapped or defined from a
  wrapped expression (one unwrapped operand keeps the finding).
* ``DOTNET_PATH_COMBINE_TRAVERSAL`` fires on any ``Path.Combine`` whose
  arguments mention file/path/name-shaped text. Killed only when EVERY
  non-literal argument is guarded by a traversal/whitelist check with an
  early exit (``filename.Contains("..") || Path.IsPathRooted(filename)`` +
  ``return BadRequest(...)``); one unguarded operand keeps the finding.
* Golden-corpus closure 2026-10-22: ten more ids join the closed set, all
  kill-on-proof reusing the machinery above.
  ``JAVA_PATH_TRAVERSAL_FILE`` / ``JAVA_TAINT_COMMAND_INJECTION`` /
  ``JAVA_TAINT_PATH_TRAVERSAL`` — Java ``matches()``-whitelist and
  ``..``-traversal guards with an early exit, proven over every variable
  in the finding's ``taint_chain`` (or the snippet when no chain exists).
  ``PHP_PATH_USER_INPUT_VAR`` — the same guard machinery as
  ``PHP_INCLUDE_CONCAT_PATH`` (``strpos(..) !== false`` + ``die``).
  ``TAINT_COMMAND_INJECTION`` (Python) — whitelist guard
  (``parts[0] not in allowed`` + early return) over the chain.
  ``TAINT_XSS`` (Python) — a PURE string-literal template passed to
  Flask's ``render_template_string`` is auto-escaped, so taint reaching
  only template *variables* is safe; an f-string/concatenated/tainted
  template is SSTI and a ``|safe``/``autoescape false`` template turns
  the data back into markup — every one of those keeps.
  ``RUST_COMMAND_EXEC`` / ``RUST_PATH_FORMAT`` /
  ``CPP_PATH_SNPRINTF_INTERP`` — whitelist/traversal guard over the
  snippet's identifiers; additionally the C++/Rust
  ``if (bad) { /* reject */ } else { USE }`` shape kills only when the
  rejection branch is comment-only (a branch that executes anything
  non-exiting is not proof of rejection and keeps the finding; exit-based
  rejection stays on the classic path above).
  ``CPP_HARDCODED_CREDENTIAL`` — the same credential-name gate as the
  PHP rule (``const char* sql = "SELECT ..."`` is a query, not a secret).
  python/rust/cpp grammars are LOCAL-only wheels under the same honesty
  contract: absent → ``parse()`` is None → every finding keeps, and each
  grammar-dependent test skips itself.

NOT HERE (deliberately):
* ``TAINT_MULTIPART_TRAVERSAL`` gets a guard-dominance KILL only: the src
  subject (``source_expr``, e.g. ``fileName``) must be validated by a
  preceding guard with an early exit (the same machinery as the traversal
  rules above, including the Java ``if (safe) { use } else { return; }``
  shape). The data-flow "provably constant" kill happens earlier, inside
  ``taint_engine`` (``scanner/multipart_flow.py``); this module only adds
  the guarded-tainted case. Nothing here can make the rule fire.
* No JavaScript/TypeScript rule fires a corpus false positive today; the
  grammars parse (covered by tests) so the capability is real, but no
  validator is claimed for languages with nothing to fix.

WIRING: ``RSX_AST_VALIDATION=0`` disables the pass entirely (A/B escape
hatch); absent tree-sitter keeps every finding exactly as the engines
produced it, and ``tree_sitter_support.status()`` discloses why.
"""
from __future__ import annotations

import os
import re
from pathlib import Path

from scanner import tree_sitter_support as ts

#: Rules this layer is allowed to touch. Anything else passes through.
VALIDATED_RULE_IDS = frozenset({
    "PHP_HARDCODED_CREDENTIAL",
    "PHP_INCLUDE_CONCAT_PATH",
    "TAINT_PHP_COMMAND_INJECTION",
    "GO_PATH_CONCAT",
    "GO_SQL_CONCAT_INTERMEDIATE",
    "DOTNET_SQL_INTERPOLATED",
    "DOTNET_PROCESS_START_INFO",
    "DOTNET_PATH_COMBINE_TRAVERSAL",
    "TAINT_MULTIPART_TRAVERSAL",
    # Golden-corpus closure 2026-10-22 (kill-on-proof; see header).
    "JAVA_PATH_TRAVERSAL_FILE",
    "JAVA_TAINT_COMMAND_INJECTION",
    "JAVA_TAINT_PATH_TRAVERSAL",
    "PHP_PATH_USER_INPUT_VAR",
    "TAINT_COMMAND_INJECTION",
    "TAINT_XSS",
    "RUST_COMMAND_EXEC",
    "RUST_PATH_FORMAT",
    "CPP_HARDCODED_CREDENTIAL",
    "CPP_PATH_SNPRINTF_INTERP",
})

_EXT_TO_LANG = {
    ".go": "go",
    ".cs": "csharp",
    ".php": "php",
    ".java": "java",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "tsx",
    # LOCAL-only wheels (2026-10-22): absent grammar = parse() None = keep.
    ".py": "python",
    ".rs": "rust",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".c": "cpp",
}

#: Variable names that make a string assignment credential-shaped.
_CRED_NAME_RE = re.compile(
    r"(?i)(pass|pwd|secret|token|api_?key|auth|credential|db_?pass"
    r"|private_?key|access_?key|client_?secret)")

#: Tokens that make a guard a PATH-VALIDATION check.
_TRAVERSAL_TOKENS = (
    '".."', "'..'", "IsPathRooted", "HasPrefix", "strpos",
    "str_contains", "GetFullPath", "Path.Clean", "contains(",
)

#: Tokens that make a guard a WHITELIST check. ``matches(`` is Java's
#: canonical validation idiom (``if (input.matches("[a-z0-9]+"))``).
_WHITELIST_TOKENS = (
    "in_array", ".contains(", "allowed", "whitelist", "matches(",
)

#: Executables that interpret their arguments through a shell grammar.
_SHELL_BINARIES = frozenset({
    "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh", "pwsh.exe",
    "sh", "bash", "zsh", "fish", "csh", "ksh", "dash",
})

_GO_SQL_SINKS = frozenset({
    "Query", "QueryRow", "QueryContext", "QueryRowContext",
    "Exec", "ExecContext",
})

_PHP_CMD_SINKS = frozenset({
    "shell_exec", "exec", "system", "passthru", "popen", "proc_open",
})

_ESCAPERS = ("escapeshellarg", "escapeshellcmd")


class _FileContext:
    def __init__(self, tree, lang_key: str, source: str, filepath: str):
        self.tree = tree
        self.lang = lang_key
        self.source = source
        self.lines = source.splitlines()
        self.filepath = filepath

    def line_text(self, row: int) -> str:
        if 1 <= row <= len(self.lines):
            return self.lines[row - 1].strip()
        return ""


def apply_ast_validation(findings: list[dict], filepath: str) -> list[dict]:
    """Validate/repair window-rule candidates for one file. Never raises."""
    if not findings:
        return findings
    if os.environ.get("RSX_AST_VALIDATION", "1").strip().lower() in {
        "0", "false", "off", "no",
    }:
        return findings
    candidates = [
        f for f in findings
        if str(f.get("rule_id") or "") in VALIDATED_RULE_IDS
    ]
    if not candidates:
        return findings
    lang_key = _EXT_TO_LANG.get(Path(filepath).suffix.lower())
    if lang_key is None:
        return findings
    try:
        source = Path(filepath).read_text(
            encoding="utf-8-sig", errors="replace")
    except OSError:
        return findings
    tree = ts.parse(lang_key, source)
    if tree is None:
        return findings
    ctx = _FileContext(tree, lang_key, source, filepath)

    kept: list[dict] = []
    for finding in findings:
        rule_id = str(finding.get("rule_id") or "")
        if rule_id not in VALIDATED_RULE_IDS:
            kept.append(finding)
            continue
        try:
            verdict = _validate(finding, rule_id, ctx)
        except Exception:
            # A validator bug must never eat a finding: unknown → keep.
            kept.append(finding)
            continue
        if verdict == "kill":
            continue
        if isinstance(verdict, tuple) and verdict[0] == "reanchor":
            _reanchor(finding, verdict[1], ctx)
        kept.append(finding)
    return kept


def _reanchor(finding: dict, new_row: int, ctx: _FileContext) -> None:
    """Move a finding to a new line, keeping every line-derived field in sync."""
    if new_row == finding.get("line"):
        return
    snippet = ctx.line_text(new_row) or finding.get("snippet", "")
    finding["line"] = new_row
    finding["snippet"] = snippet
    if "evidence" in finding:
        finding["evidence"] = f"{ctx.filepath}:{new_row}: {snippet}"
    old_key = str(finding.get("group_key") or "")
    if old_key.count("|") >= 3:  # sast shape carries the snippet too
        finding["group_key"] = (
            f"{finding.get('rule_id')}|{ctx.filepath}|{new_row}|{snippet[:120]}")
    else:
        finding["group_key"] = (
            f"{finding.get('rule_id')}|{ctx.filepath}|{new_row}")


def _validate(finding: dict, rule_id: str, ctx: _FileContext):
    if rule_id == "PHP_HARDCODED_CREDENTIAL":
        return _php_credential(finding, ctx)
    if rule_id == "PHP_INCLUDE_CONCAT_PATH":
        return _traversal_concat(finding, ctx, _php_concat_var)
    if rule_id == "GO_PATH_CONCAT":
        return _traversal_concat(finding, ctx, _go_concat_var)
    if rule_id == "GO_SQL_CONCAT_INTERMEDIATE":
        return _go_sql_sink_anchor(finding, ctx)
    if rule_id == "TAINT_PHP_COMMAND_INJECTION":
        return _php_shell_sanitized(finding, ctx)
    if rule_id == "TAINT_MULTIPART_TRAVERSAL":
        return _multipart_guard_kill(finding, ctx)
    if rule_id == "DOTNET_SQL_INTERPOLATED":
        return _dotnet_sql(finding, ctx)
    if rule_id == "DOTNET_PROCESS_START_INFO":
        return _dotnet_process(finding, ctx)
    if rule_id == "DOTNET_PATH_COMBINE_TRAVERSAL":
        return _dotnet_path_combine(finding, ctx)
    if rule_id in _TAINT_CHAIN_GUARD_RULES:
        return _taint_guard_kill(finding, ctx)
    if rule_id in _SNIPPET_GUARD_RULES:
        return _snippet_guard_kill(finding, ctx)
    if rule_id == "PHP_PATH_USER_INPUT_VAR":
        return _traversal_concat(finding, ctx, _php_concat_var)
    if rule_id == "CPP_HARDCODED_CREDENTIAL":
        return _cpp_credential(finding, ctx)
    if rule_id == "TAINT_XSS":
        return _python_render_literal_kill(finding, ctx)
    return "keep"


# ---------------------------------------------------------------------------
# PHP hard-coded credentials: the variable name must be credential-shaped
# ---------------------------------------------------------------------------

def _php_credential(finding: dict, ctx: _FileContext):
    snippet = str(finding.get("snippet") or "").strip()
    match = re.match(r"\$(\w+)\s*=", snippet)
    if match and not _CRED_NAME_RE.search(match.group(1)):
        return "kill"
    return "keep"


# ---------------------------------------------------------------------------
# Guard dominance for path-concat rules (Go/PHP)
# ---------------------------------------------------------------------------

def _go_concat_var(snippet: str) -> str | None:
    match = re.search(r"\+\s*([A-Za-z_]\w*)\s*$", snippet)
    return match.group(1) if match else None


def _php_concat_var(snippet: str) -> str | None:
    matches = re.findall(r"\.\s*(\$\w+)\s*\)?\s*;?\s*$", snippet)
    return matches[-1] if matches else None


def _traversal_concat(finding: dict, ctx: _FileContext, var_extractor):
    var = var_extractor(str(finding.get("snippet") or ""))
    if not var:
        return "keep"
    return _guarded_var_kill(finding, ctx, var)


def _scope(ctx: _FileContext, row: int):
    """Reasoning scope for a finding's row: the enclosing function, or —
    for top-level code (idiomatic PHP scripts, module scope) — the file
    root. An early-exit guard earlier in the file still governs the
    statements after it, so guard/sanitizer semantics are unchanged."""
    func = ts.find_enclosing_function(ctx.tree, ctx.lang, row)
    return func if func is not None else ctx.tree.root_node


def _guarded_var_kill(finding: dict, ctx: _FileContext, var: str):
    """Kill when a preceding guard validates ``var`` and exits early.

    Conservative on every axis: the ``if`` must mention the variable, carry
    a validation-family token in its condition, exit early in its block,
    and precede the finding's line within the reasoning scope.

    Two exit shapes are recognised. The classic one exits in the
    consequence (``if (bad) return;`` — findings after the guard are
    protected). The Java-safe idiom exits in the ALTERNATIVE
    (``if (safe) { use } else { return; }``) — that shape only kills a
    finding that sits INSIDE the consequence, i.e. inside the region the
    guard proved safe; a finding after the whole statement would sit on
    the bad-check path instead and is kept.

    A third shape needs no exit at all: the C++/Rust
    ``if (bad) { /* reject */ } else { USE }`` idiom. The alternative
    executes only when the condition is false, so a finding INSIDE it is
    killed when the rejection branch is comment/whitespace-only and the
    condition carries traversal-family vocabulary (``find("..")``,
    ``contains("..")``): the author's empty branch is the bad-path
    sink-hole. Whitelist-family conditions are deliberately excluded from
    this shape — in an empty-then branch they read inverted
    (``if (allowed(x)) {} else { use(x); }``) — and a rejection branch
    that executes anything non-exiting is not proof of rejection.
    """
    _EXIT_RE = r"\breturn\b|\bthrow\b|die\s*\(|exit\s*\("
    row = int(finding.get("line") or 0)
    scope = _scope(ctx, row)
    if_types = ts.if_node_types(ctx.lang)
    for node in ts.walk(scope):
        if node.type not in if_types or ts.node_row(node) >= row:
            continue
        condition = node.child_by_field_name("condition")
        # Body field differs per grammar: C#/Go/Java use `consequence`,
        # PHP uses `body` (compound_statement) for braced blocks and
        # `statements` for the single-statement form.
        consequence = (
            node.child_by_field_name("consequence")
            or node.child_by_field_name("body")
            or node.child_by_field_name("statements")
        )
        if condition is None or consequence is None:
            continue
        cond_text = ts.node_text(condition)
        if var.startswith("$"):
            # PHP: exact ``$name`` substring (a ``\b`` before ``$`` never
            # matches — ``$`` is not a word character).
            hit = var in cond_text
        else:
            hit = re.search(rf"\b{re.escape(var)}\b", cond_text) is not None
        if not hit:
            continue
        cond_lower = cond_text.lower()
        family_hit = (
            any(token in cond_text for token in _TRAVERSAL_TOKENS)
            or any(token in cond_lower for token in _WHITELIST_TOKENS)
        )
        if not family_hit:
            continue
        cons_text = ts.node_text(consequence)
        if re.search(_EXIT_RE, cons_text):
            return "kill"
        # Java/C# safe idiom: exit lives in the else branch.
        alternative = node.child_by_field_name("alternative")
        if alternative is None:
            for child in node.children:
                if child.type in ("else_clause", "else"):
                    alternative = child
                    break
        if alternative is None:
            continue
        if (ts.node_start_row(consequence) <= row
                <= ts.node_end_row(consequence)):
            if re.search(_EXIT_RE, ts.node_text(alternative)):
                return "kill"
            continue        # inside the proven-safe branch, no exit after
        # C++/Rust reject-comment idiom (see docstring, shape three).
        if (ts.node_start_row(alternative) <= row
                <= ts.node_end_row(alternative)
                and _branch_is_comment_only(consequence)
                and any(token in cond_text for token in _TRAVERSAL_TOKENS)):
            return "kill"
    return "keep"


def _branch_is_comment_only(node) -> bool:
    """True when a branch body performs no executable statement."""
    substantive = [child for child in node.children
                   if child.type not in ("{", "}", "(", ")")
                   and "comment" not in child.type]
    return not substantive


def _multipart_guard_kill(finding: dict, ctx: _FileContext):
    """Guard-dominance kill for the multipart window rule.

    The src subject (``source_expr``, e.g. ``fileName``) must be validated
    by a preceding guard with an early exit before — or around — the
    finding's line. This only removes findings; it can never make the rule
    fire (the data-flow constant kill happens earlier in ``taint_engine``).
    """
    m = re.search(r"[A-Za-z_$][\w$]*", str(finding.get("source_expr") or ""))
    if not m:
        return "keep"
    return _guarded_var_kill(finding, ctx, m.group(0))


# ---------------------------------------------------------------------------
# Chain/snippet guard kills (2026-10-22 golden-corpus closure)
# ---------------------------------------------------------------------------

#: Taint-engine rules whose findings carry a ``taint_chain``; a guard that
#: constrains ANY variable on the flow path proves the sink value validated.
_TAINT_CHAIN_GUARD_RULES = frozenset({
    "JAVA_PATH_TRAVERSAL_FILE",
    "JAVA_TAINT_COMMAND_INJECTION",
    "JAVA_TAINT_PATH_TRAVERSAL",
    "TAINT_COMMAND_INJECTION",
})

#: Window rules with no chain state; the subject is every identifier in the
#: snippet (each candidate still needs family token + early exit to kill).
_SNIPPET_GUARD_RULES = frozenset({
    "RUST_COMMAND_EXEC",
    "RUST_PATH_FORMAT",
    "CPP_PATH_SNPRINTF_INTERP",
})


def _chain_idents(chain) -> list[str]:
    """First identifier of each chain element (``cmd``, ``parts[0]``,
    ``request.args.get('cmd', '')`` → request, ...)."""
    out = []
    for element in chain or []:
        match = re.search(r"[A-Za-z_]\w*", str(element))
        if match:
            out.append(match.group(0))
    return out


def _snippet_idents(snippet: str) -> list[str]:
    return [m.group(0) for m in re.finditer(r"[A-Za-z_]\w*", snippet or "")]


def _taint_guard_kill(finding: dict, ctx: _FileContext):
    """Kill when a guard constrains any variable on the taint path.

    The chain is the flow the engine proved (source → ... → sink); a
    whitelist/traversal guard with an early exit over any chain member
    constrains the value reaching the sink. Without a chain the snippet's
    identifiers are the fallback (window-style rows enriched with flow).
    """
    chain = finding.get("taint_chain")
    idents = _chain_idents(chain) if chain else _snippet_idents(
        str(finding.get("snippet") or ""))
    for var in dict.fromkeys(idents):
        if _guarded_var_kill(finding, ctx, var) == "kill":
            return "kill"
    return "keep"


def _snippet_guard_kill(finding: dict, ctx: _FileContext):
    """Guard kill driven by the snippet's identifiers (no chain state).

    Kill-on-proof only: every candidate still needs the full triple —
    variable mention, validation-family token, early exit — before the
    finding's line inside the reasoning scope.
    """
    for var in dict.fromkeys(_snippet_idents(str(finding.get("snippet") or ""))):
        if _guarded_var_kill(finding, ctx, var) == "kill":
            return "kill"
    return "keep"


# ---------------------------------------------------------------------------
# C++ hard-coded credentials: same credential-name gate as the PHP rule
# ---------------------------------------------------------------------------

_CPP_CRED_ASSIGN = re.compile(
    r"(?:const\s+)?char\s*\*?\s*(\w+)(?:\s*\[\s*\])?\s*=")


def _cpp_credential(finding: dict, ctx: _FileContext):
    """``const char* sql = "SELECT ..."`` is a query, not a credential.

    The rule matches ANY ``const char* name = "8+ chars"``; the variable
    name must be credential-shaped, exactly like the PHP rule's gate.
    An array declaration the extractor cannot read keeps (conservative).
    """
    snippet = str(finding.get("snippet") or "").strip()
    match = _CPP_CRED_ASSIGN.search(snippet)
    if match and not _CRED_NAME_RE.search(match.group(1)):
        return "kill"
    return "keep"


# ---------------------------------------------------------------------------
# Python render_template_string: literal template ⇒ auto-escaped data
# ---------------------------------------------------------------------------

#: A PURE string literal (no f-prefix — interpolation is not a literal).
_LITERAL_TEMPLATE = re.compile(
    r"""^([rub]{0,2}"(?:[^"\\]|\\.)*"|[rub]{0,2}'(?:[^'\\]|\\.)*')"""
    r"""\s*(?:,|\))""")

#: Constructs that turn escaped data back into markup.
_XSS_UNSAFE_TOKENS = ("|safe", "autoescape false", "autoescape=False")


def _python_render_literal_kill(finding: dict, ctx: _FileContext):
    """Kill a TAINT_XSS row whose template is a pure string literal.

    Flask enables autoescape for template strings (``select_autoescape``
    with ``default_for_string``), so taint that reaches only template
    *variables* renders escaped. The proof dies the moment interpolation
    enters the template: an f-string/concatenated/tainted template is
    SSTI, and a ``|safe`` filter or ``autoescape false`` block hands the
    data back to the browser as markup. Non-Flask renderers never carry
    ``render_template_string`` in the snippet, so the check is inert there.
    """
    snippet = str(finding.get("snippet") or "")
    if "render_template_string" not in snippet:
        return "keep"
    call = snippet[snippet.index("render_template_string"):]
    args = call[call.index("(") + 1:].lstrip() if "(" in call else ""
    match = _LITERAL_TEMPLATE.match(args)
    if not match:
        return "keep"          # f-string / concatenation / tainted template
    template = match.group(1)
    if any(token in template for token in _XSS_UNSAFE_TOKENS):
        return "keep"
    return "kill"


# ---------------------------------------------------------------------------
# Go SQL concatenation: anchor at the sink, not at the assignment
# ---------------------------------------------------------------------------

def _go_sql_sink_anchor(finding: dict, ctx: _FileContext):
    snippet = str(finding.get("snippet") or "")
    match = re.match(r"([A-Za-z_]\w*)\s*:?=", snippet)
    if not match:
        return "keep"
    var = match.group(1)
    row = int(finding.get("line") or 0)
    func = ts.find_enclosing_function(ctx.tree, ctx.lang, row)
    if func is None:
        return "keep"
    for node in ts.walk(func):
        if node.type != "call_expression" or ts.node_row(node) <= row:
            continue
        callee = node.child_by_field_name("function")
        if callee is None or callee.type != "selector_expression":
            continue
        name_node = callee.child_by_field_name("field")
        name = ts.node_text(name_node) if name_node is not None else ""
        if name not in _GO_SQL_SINKS:
            continue
        args = node.child_by_field_name("arguments")
        if args is None or not re.search(
            rf"\b{re.escape(var)}\b", ts.node_text(args)
        ):
            continue
        return ("reanchor", ts.node_row(node))
    return "keep"


# ---------------------------------------------------------------------------
# PHP shell sinks: every variable operand must be escapeshell*-derived
# ---------------------------------------------------------------------------

def _php_shell_sanitized(finding: dict, ctx: _FileContext):
    row = int(finding.get("line") or 0)
    scope = _scope(ctx, row)
    sink = None
    for node in ts.nodes_of_type(scope, "function_call_expression"):
        if ts.node_row(node) != row:
            continue
        name_node = node.child_by_field_name("function")
        name = ts.node_text(name_node) if name_node is not None else ""
        if name in _PHP_CMD_SINKS:
            sink = node
            break
    if sink is None:
        return "keep"
    args = sink.child_by_field_name("arguments")
    if args is None:
        return "keep"

    variables = _php_variables(args)
    if not variables:
        return "keep"
    for ident, var in variables:
        if _has_escaper_ancestor(ident):
            continue  # used inside escapeshellarg(...)/escapeshellcmd(...)
        if _defined_from_escaper(scope, var):
            continue  # bound from an escapeshell*-wrapped expression
        return "keep"  # one unwrapped operand keeps the finding alive
    return "kill"


def _php_variables(args_node) -> list[tuple[object, str]]:
    out: list[tuple[object, str]] = []
    for node in ts.walk(args_node):
        # tree-sitter-php names a `$var` expression ``variable_name`` (with
        # a `$` token and a ``name`` child) — not ``variable``.
        if node.type != "variable_name":
            continue
        name = ts.node_text(node)
        if re.fullmatch(r"\$\w+", name):
            out.append((node, name))
    return out


def _has_escaper_ancestor(node) -> bool:
    parent = node.parent
    while parent is not None:
        if parent.type == "function_call_expression":
            name_node = parent.child_by_field_name("function")
            name = ts.node_text(name_node) if name_node is not None else ""
            if name in _ESCAPERS:
                return True
        parent = parent.parent
    return False


def _defined_from_escaper(func, var: str) -> bool:
    for node in ts.nodes_of_type(func, "assignment_expression"):
        left = node.child_by_field_name("left")
        if left is None or ts.node_text(left) != var:
            continue
        right = node.child_by_field_name("right")
        if right is not None:
            right_text = ts.node_text(right)
            if any(escaper + "(" in right_text for escaper in _ESCAPERS):
                return True
    return False


# ---------------------------------------------------------------------------
# .NET SqlCommand: parameterised queries are not findings, and the sink is
# the canonical anchor
# ---------------------------------------------------------------------------

def _dotnet_sql(finding: dict, ctx: _FileContext):
    snippet = str(finding.get("snippet") or "")
    row = int(finding.get("line") or 0)
    func = ts.find_enclosing_function(ctx.tree, ctx.lang, row)
    if func is None:
        return "keep"

    sink_branch = (
        "ExecuteReader" in snippet or "ExecuteScalar" in snippet
    )
    if sink_branch:
        match = re.search(r"(\w+)\.Execute(?:Reader|Scalar)", snippet)
        if not match:
            return "keep"
        creation = _find_object_creation(func, match.group(1), "SqlCommand")
        if creation is None:
            return "keep"  # construction not resolvable → keep
        args = _argument_list(creation)
        if args is None:
            return "keep"
        first_arg = _first_argument(args)
        if first_arg is not None and first_arg.type in {
            "string_literal", "verbatim_string_literal",
        }:
            # Plain/parameterised query text: no interpolation, no concat.
            return "kill"
        return "keep"

    # Constructor branch (``SqlCommand($"...")``): the sink-branch finding
    # for the same command is the canonical anchor — this is the duplicate.
    for node in ts.nodes_of_type(func, "invocation_expression"):
        text = ts.node_text(node)
        if ".ExecuteReader" in text or ".ExecuteScalar" in text:
            return "kill"
    return "keep"


def _find_object_creation(func, var: str, type_name: str):
    """The ``new <type_name>(...)`` assigned to ``var`` inside ``func``."""
    for node in ts.nodes_of_type(func, "variable_declarator"):
        name_node = node.child_by_field_name("name")
        if name_node is None or ts.node_text(name_node) != var:
            continue
        value = node.child_by_field_name("value")
        if value is None:
            # The C# grammar gives declarators a `name` field but no named
            # `value` field — the initialiser rides as a plain child after
            # the `=` token.
            for child in node.children:
                if child.type == "object_creation_expression":
                    value = child
                    break
        if value is None or value.type != "object_creation_expression":
            continue
        type_node = value.child_by_field_name("type")
        if type_node is not None and ts.node_text(type_node) == type_name:
            return value
    return None


def _argument_list(node):
    """``argument_list`` child of a call/creation — a plain child, not a
    field, on the C# grammar."""
    args = node.child_by_field_name("argument_list")
    if args is not None:
        return args
    for child in node.children:
        if child.type == "argument_list":
            return child
    return None


def _first_argument(args_node):
    for child in args_node.children:
        if child.type == "argument":
            # `argument` is a wrapper; its first named child is the actual
            # expression (string_literal, interpolated_string_expression, ...).
            named = [c for c in child.children if c.is_named]
            return named[0] if named else child
    return None


# ---------------------------------------------------------------------------
# .NET ProcessStartInfo: shell semantics decide, and the unsafe argument is
# the anchor — not the Start() call
# ---------------------------------------------------------------------------

def _dotnet_process(finding: dict, ctx: _FileContext):
    snippet = str(finding.get("snippet") or "")
    row = int(finding.get("line") or 0)
    func = ts.find_enclosing_function(ctx.tree, ctx.lang, row)
    if func is None:
        return "keep"
    creation = _find_any_creation(func, "ProcessStartInfo")
    if creation is None:
        return "keep"
    fields = _initializer_fields(creation)
    if not fields:
        return "keep"

    use_shell = fields.get("UseShellExecute")
    no_shell = (
        use_shell is not None
        and ts.node_text(use_shell[1]).strip() == "false"
    )
    file_name = fields.get("FileName")
    if no_shell and file_name is not None:
        name_text = ts.node_text(file_name[1]).strip().strip('"')
        if file_name[1].type in {"string_literal", "verbatim_string_literal"}:
            if name_text.lower() not in _SHELL_BINARIES:
                # Arguments never reach a shell grammar, and the executable
                # is not a shell: no command injection through Arguments.
                return "kill"
        else:
            # Variable FileName: kill only when a whitelist guard with an
            # early exit dominates the finding (e.g. allowed.Contains(x)).
            base = re.match(r"([A-Za-z_]\w*)", name_text)
            if base and _guarded_var_kill(finding, ctx, base.group(1)) == "kill":
                return "kill"

    # The finding is real: anchor where the unsafe value enters, not at Start.
    for key in ("Arguments", "FileName"):
        entry = fields.get(key)
        if entry is None:
            continue
        value_text = ts.node_text(entry[1]).strip()
        if entry[1].type not in {"string_literal", "verbatim_string_literal"}:
            return ("reanchor", entry[0])
        # A shell executable with a literal argument string still matters
        # only when the literal is not the whole story; keep as-is.
        _ = value_text
    return "keep"


def _find_any_creation(func, type_name: str):
    for node in ts.nodes_of_type(func, "object_creation_expression"):
        type_node = node.child_by_field_name("type")
        if type_node is not None and ts.node_text(type_node) == type_name:
            return node
        # Fully-qualified creation: type node may be a qualified_name.
        if type_name in ts.node_text(node):
            return node
    return None


def _initializer_fields(creation) -> dict[str, tuple[int, object]]:
    """``{Field: (row, value_node)}`` from a C# object initializer."""
    initializer = creation.child_by_field_name("initializer")
    if initializer is None:
        return {}
    out: dict[str, tuple[int, object]] = {}
    for child in ts.walk(initializer):
        if child.type != "assignment_expression":
            continue
        left = child.child_by_field_name("left")
        right = child.child_by_field_name("right")
        if left is None or right is None:
            # Fall back to positional children: [left, =, right].
            operands = [c for c in child.children if c.type != "="]
            if len(operands) >= 2:
                left, right = operands[0], operands[-1]
        if left is None or right is None:
            continue
        out.setdefault(ts.node_text(left).strip(), (ts.node_row(child), right))
    return out


# ---------------------------------------------------------------------------
# .NET Path.Combine: every non-literal argument must be guarded
# ---------------------------------------------------------------------------


def _dotnet_path_combine(finding: dict, ctx: _FileContext):
    """Kill when EVERY non-literal argument of the Combine call is guarded
    by a traversal/whitelist check with an early exit (the fixture's
    ``filename.Contains("..") || Path.IsPathRooted(filename)`` + BadRequest
    pattern). One unguarded operand keeps the finding."""
    snippet = str(finding.get("snippet") or "")
    call_at = snippet.find("Path.Combine")
    if call_at == -1:
        return "keep"
    open_paren = snippet.find("(", call_at)
    close_paren = snippet.find(")", open_paren)
    args = snippet[open_paren + 1: close_paren if close_paren != -1 else None]
    # String literals are values, not operands: strip them so only real
    # variable references remain (@"C:\\Uploads" must not look like one).
    args = re.sub(r'@?"[^"]*"', " ", args)
    names = re.findall(r"[A-Za-z_]\w*", args)
    if not names:
        return "keep"
    for name in names:
        if _guarded_var_kill(finding, ctx, name) != "kill":
            return "keep"
    return "kill"
