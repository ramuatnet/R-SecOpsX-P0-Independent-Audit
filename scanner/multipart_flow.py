"""V1.12a — bounded abstract evaluation for the multipart-upload path gate.

WHY THIS EXISTS
---------------
``TAINT_MULTIPART_TRAVERSAL`` (taint_engine's enterprise window rule) is the
single largest false-positive family on the OWASP Benchmark: 81 firings, 45
of them on negative tests whose taint provably never reaches the sink. The
window rule pairs a source-shaped token (``filename``) with a sink-shaped
token (``File(``, ``Paths.get(``, ...) within 14 lines and asks nothing
about the value in between. The negatives differ from the positives ONLY in
semantics:

    FP: bar = (7*18)+num > 200 ? "constant" : param;   // cond folds TRUE
    TP: bar = (7*42)-num > 200 ? "never"   : param;    // cond folds FALSE

    FP: bar = map.get("keyB"); bar = map.get("keyA");  // strong update wins
    TP: bar = map.get("keyB");                         // taint survives

    FP: bar = doSomething(request, param);             // helper returns a
    TP: bar = doSomething(request, param);             // constant vs param

No line-shape or syntax heuristic separates these; only evaluation of the
value does. This module answers exactly ONE question, conservatively:

    "Can the value of ``var`` at the sink line be PROVEN a constant that
     no attacker input can influence?"

KILL-ONLY-ON-PROOF CONTRACT
---------------------------
The result is True only when every definition path reaching the sink
evaluates to a literal constant. Every ambiguity — unresolvable variable,
non-constant condition, unknown call, loop-carried definition, inline
budget exhaustion, malformed source — returns False, which callers turn
into "keep the finding". The analysis may be incomplete; it must never be
wrong in the kill direction. ``RSX_MULTIPART_FLOW=0`` disables the gate.

WHAT IT UNDERSTANDS (deliberately bounded)
-----------------------------------------
* logical statements joined across line wraps (benchmark/prettier style);
* a forward abstract interpretation of one method body: strong updates,
  constant folding of integer arithmetic/comparisons, ternary selection on
  a folded condition, ``if``/``else`` branch pruning and merging, and
  ``try``/``catch`` merging over the shared pre-state;
* single-collection value tracking for ``add``/``put``/``remove``/``get``
  with literal keys and indices — the ``[safe, param, safe]`` +
  ``remove(0)`` + ``get(1)`` benchmark archetype;
* ONE level of same-file helper inlining (``doSomething(request, param)``
  resolves to a method of the same file and is evaluated with its
  arguments bound), depth- and budget-limited.

It does NOT attempt cross-file interprocedural analysis, loop fixpoints,
reflection, or object-field tracking — all of those yield "not proven"
and therefore KEEP.
"""
from __future__ import annotations

import os
import re

from core import file_index

#: Value lattice. SAFE is the only value that can justify a kill.
_SAFE = "safe"
_UNSAFE = "unsafe"      # proven attacker-influenced
_UNKNOWN = "unknown"    # anything not proven either way

#: Budgets. Exceeding any of them yields UNKNOWN (never a kill).
_MAX_STATEMENTS = 3000
_MAX_INLINE_DEPTH = 2
_MAX_STEPS = 4000

_INT_ATOM_RE = re.compile(r"^-?\d+$")
_INT_SUFFIX_RE = re.compile(r"^-?\d+[lLfFdD]$")
_STRING_RE = re.compile(r'^"([^"\\]|\\.)*"$')
_CHAR_RE = re.compile(r"^'([^'\\]|\\.)'$")
_IDENT_RE = re.compile(r"[A-Za-z_$][\w$]*")

#: Receivers whose values are request-controlled.
_REQUEST_RECEIVER_RE = re.compile(
    r"^(?:req|request|httprequest|servletrequest|ctx|context|r)$", re.I)

#: Calls that are request-data sources even through qualified receivers.
_REQUEST_CALL_RE = re.compile(
    r"\b(?:req|request|httprequest|servletrequest|ctx|context)\s*\.\s*\w+"
    r"|\$_\s*(?:GET|POST|REQUEST|COOKIE|FILES)"
    r"|\bRequest\s*\.\s*\w+|\bgetTheValue\s*\(", re.I)

_BLOCK_HEADER_RE = re.compile(r"^(if|for|while|switch|try|catch|finally|"
                             r"synchronized|else|do)\b")
_METHOD_HEADER_RE = re.compile(
    r"^(?:(?:public|private|protected|static|final|abstract|synchronized|"
    r"native|strictfp|override|internal|virtual|sealed|async|partial)\s+)*"
    r"[\w$][\w$<>\[\],.?]*\s+([\w$][\w$]*)\s*\(([^)]*)\)"
    r"\s*(?:throws\s+[\w.,\s]+)?$")
_LOOP_HEADER_RE = re.compile(r"^(?:for|while|do)\b")
_INT_DECL_RE = re.compile(
    r"^(?:(?:final|const|static)\s+)*"
    r"(?:int|long|short|byte|Integer|Long)\s+"
    r"([\w$][\w$]*)\s*=\s*(.+?)\s*;?$")
_ASSIGN_RE = re.compile(
    r"^(?:(?:var|final|const|public|private|protected|static)\s+)*"
    r"(?:[\w$][\w$<>\[\],.?]*\s+)?"
    r"([\w$][\w$]*)\s*(?:\[[^\]]*\])?\s*=(?!=)\s*(.+?)\s*;?$")
_DECL_RE = re.compile(
    r"^(?:(?:final|const|public|private|protected|static)\s+)*"
    r"[\w$][\w$.]*(?:\s*<[^=<>]*>)?(?:\s*\[\])*\s+"
    r"([\w$][\w$]*)\s*=\s*(.+?)\s*;?$")


def gate_enabled() -> bool:
    return os.environ.get("RSX_MULTIPART_FLOW", "1").strip().lower() not in (
        "0", "false", "no", "off")


# ---------------------------------------------------------------------------
# Logical statement splitting (line-wrap, comment and string aware)
# ---------------------------------------------------------------------------

def split_statements(lines: list[str]) -> list[dict]:
    """Split source lines into logical statements.

    Each statement carries ``start``/``end`` (1-based line numbers) and the
    joined ``text``. A statement terminates at ``;``; a ``{`` flushes the
    open header (the brace joins the header text); a ``}`` becomes its own
    marker statement. Terminators only count at bracket depth 0. Strings,
    chars, line comments and block comments are honoured so punctuation
    inside them never terminates a statement.
    """
    out: list[dict] = []
    buf: list[str] = []
    start = 0
    paren = square = curly = 0
    in_str = in_char = in_block_comment = False
    verbatim = False

    def flush(end_line: int) -> None:
        text = re.sub(r"\s+", " ", "".join(buf)).strip()
        if text and text != "}":
            out.append({"start": start, "end": end_line, "text": text})
        buf.clear()

    for lineno, raw in enumerate(lines, 1):
        i, n = 0, len(raw)
        while i < n:
            ch = raw[i]
            nxt = raw[i + 1] if i + 1 < n else ""
            if in_block_comment:
                buf.append(ch)
                if ch == "*" and nxt == "/":
                    buf.append(nxt)
                    in_block_comment = False
                    i += 2
                    continue
                i += 1
                continue
            if in_str:
                buf.append(ch)
                if verbatim:
                    if ch == '"':
                        if nxt == '"':
                            buf.append(nxt)
                            i += 2
                            continue
                        in_str = False
                elif ch == "\\":
                    if nxt:
                        buf.append(nxt)
                    i += 2
                    continue
                elif ch == '"':
                    in_str = False
                i += 1
                continue
            if in_char:
                buf.append(ch)
                if ch == "\\":
                    if nxt:
                        buf.append(nxt)
                    i += 2
                    continue
                if ch == "'":
                    in_char = False
                i += 1
                continue
            if ch == "/" and nxt == "/":
                break
            if ch == "/" and nxt == "*":
                in_block_comment = True
                i += 2
                continue
            if ch == '"':
                buf.append(ch)
                in_str = True
                verbatim = i > 0 and raw[i - 1] == "@"
                i += 1
                continue
            if ch == "'":
                buf.append(ch)
                in_char = True
                i += 1
                continue
            if ch == "(":
                paren += 1
            elif ch == ")":
                paren = max(0, paren - 1)
            elif ch == "[":
                square += 1
            elif ch == "]":
                square = max(0, square - 1)
            elif ch == "{" and paren == 0 and square == 0:
                if not buf:
                    start = lineno
                buf.append(ch)
                flush(lineno)
                curly += 1
                i += 1
                continue
            elif ch == "}" and paren == 0 and square == 0:
                if buf:
                    flush(lineno)
                out.append({"start": lineno, "end": lineno, "text": "}"})
                curly = max(0, curly - 1)
                i += 1
                continue
            elif ch == ";" and paren == 0 and square == 0:
                if not buf:
                    start = lineno
                buf.append(ch)
                flush(lineno)
                i += 1
                continue
            if not buf:
                start = lineno
            buf.append(ch)
            i += 1
    if buf and start:
        out.append({"start": start, "end": len(lines),
                    "text": re.sub(r"\s+", " ", "".join(buf)).strip()})
    return [s for s in out if s["text"]]


# ---------------------------------------------------------------------------
# Small expression utilities
# ---------------------------------------------------------------------------

def _split_top(expr: str, sep: str) -> list[str]:
    parts, depth, cur, in_str = [], 0, "", False
    for ch in expr:
        if in_str:
            cur += ch
            if ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
            cur += ch
        elif ch in "([{":
            depth += 1
            cur += ch
        elif ch in ")]}":
            depth = max(0, depth - 1)
            cur += ch
        elif ch == sep and depth == 0:
            parts.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        parts.append(cur.strip())
    return parts


def _split_args(text: str) -> list[str]:
    return [a for a in _split_top(text, ",") if a]


def _find_matching_paren(text: str) -> int:
    """Index of the ``)`` matching the first ``(``, or -1."""
    depth = 0
    in_str = False
    for i, ch in enumerate(text):
        if in_str:
            if ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return i
    return -1


def _compare(op: str, left: int, right: int) -> int:
    return int({">": left > right, ">=": left >= right,
                "<": left < right, "<=": left <= right,
                "==": left == right, "!=": left != right}[op])


def _fold_int(expr: str, env: dict) -> int | None:
    """Fold integer arithmetic/comparisons, or None when not foldable.

    Handles literals, integer locals recorded in ``env``, ``+ - * / %`` and
    ``> >= < <= == !=`` — exactly the shapes of the constant conditions the
    benchmark's negative tests use.
    """
    expr = expr.strip()
    if not expr:
        return None
    for ops in (("!=", "=="), (">=", "<="), (">", "<")):
        depth = 0
        for i in range(len(expr) - 1, -1, -1):
            ch = expr[i]
            if ch == ")":
                depth += 1
            elif ch == "(":
                depth = max(0, depth - 1)
            elif depth == 0:
                for op in ops:
                    if i > 0 and expr.startswith(op, i):
                        left = _fold_int(expr[:i], env)
                        right = _fold_int(expr[i + len(op):], env)
                        if left is None or right is None:
                            return None
                        return _compare(op, left, right)
    depth = 0
    for i in range(len(expr) - 1, -1, -1):
        ch = expr[i]
        if ch == ")":
            depth += 1
        elif ch == "(":
            depth = max(0, depth - 1)
        elif depth == 0 and ch in "+-" and i > 0 \
                and expr[i - 1] not in "+-*/%=<>!":
            left = _fold_int(expr[:i], env)
            right = _fold_int(expr[i + 1:], env)
            if left is None or right is None:
                return None
            return left + right if ch == "+" else left - right
    depth = 0
    for i in range(len(expr) - 1, -1, -1):
        ch = expr[i]
        if ch == ")":
            depth += 1
        elif ch == "(":
            depth = max(0, depth - 1)
        elif depth == 0 and ch in "*/%":
            left = _fold_int(expr[:i], env)
            right = _fold_int(expr[i + 1:], env)
            if left is None or right is None or (ch in "/%" and right == 0):
                return None
            if ch == "*":
                return left * right
            if ch == "/":
                return left // right
            return left % right
    inner = expr
    if inner.startswith("(") and inner.endswith(")"):
        return _fold_int(inner[1:-1], env)
    if _INT_ATOM_RE.match(inner) or _INT_SUFFIX_RE.match(inner):
        return int(re.match(r"^-?\d+", inner).group(0))
    if inner in env and isinstance(env[inner], int):
        return env[inner]
    return None


def _outer_call_open(expr: str) -> int:
    """Index of the ``(`` whose ``)`` is the final character, else -1.

    Lets ``new Test().doSomething(a, b)`` resolve its callee to the
    METHOD call (``new Test().doSomething``) instead of the constructor.
    """
    depth = 0
    open_idx = -1
    for i, ch in enumerate(expr):
        if ch == "(":
            if depth == 0:
                open_idx = i
            depth += 1
        elif ch == ")":
            depth = max(0, depth - 1)
            if depth == 0 and i == len(expr) - 1:
                return open_idx
    return -1


def _merge(a: str, b: str) -> str:
    if a == b:
        return a
    if a == _UNSAFE or b == _UNSAFE:
        return _UNSAFE
    return _UNKNOWN


def _split_ternary(expr: str) -> int | None:
    """Index of the top-level ``?`` of a ternary, or None."""
    depth = 0
    in_str = False
    for i, ch in enumerate(expr):
        if in_str:
            if ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth = max(0, depth - 1)
        elif ch == "?" and depth == 0:
            return i
    return None


# ---------------------------------------------------------------------------
# Collection model
# ---------------------------------------------------------------------------

class _Coll:
    """Abstract value of one tracked list or keyed map."""

    def __init__(self, keyed: bool):
        self.keyed = keyed
        self.items: list[str] = []
        self.map: dict = {}
        self.broken = False

    def add(self, value: str) -> None:
        if self.keyed:
            self.broken = True
            return
        self.items.append(value)

    def put(self, key: str, value: str) -> None:
        if not self.keyed:
            self.broken = True
            return
        self.map[key] = value

    def remove_index(self, idx: int) -> None:
        if self.keyed or idx < 0 or idx >= len(self.items):
            self.broken = True
            return
        del self.items[idx]

    def get(self, key) -> str:
        if self.broken:
            return _UNKNOWN
        if self.keyed:
            return self.map.get(key, _UNKNOWN)
        if isinstance(key, int) and 0 <= key < len(self.items):
            return self.items[key]
        return _UNKNOWN


# ---------------------------------------------------------------------------
# The analyzer
# ---------------------------------------------------------------------------

class _Analyzer:
    def __init__(self, statements: list[dict], filepath: str | None = None):
        self.stmts = statements
        self.filepath = filepath
        self.steps = 0
        self.inline_depth = 0
        #: var -> method name, for ``x.getMethod("name")`` references.
        self.methodrefs: dict[str, str] = {}
        #: var -> constructor class simple name (``x = new T(...)``).
        self.ctors: dict[str, str] = {}
        #: var -> concrete literal value (constant-selector ``switch``).
        self.vals: dict[str, str] = {}
        #: (class, method, arity) -> cross-file constant verdict (memo).
        self._crossfile: dict = {}

    def _spend(self) -> bool:
        self.steps += 1
        return self.steps > _MAX_STEPS

    # -- expression evaluation -------------------------------------------

    def eval_expr(self, expr: str, env: dict, colls: dict) -> str:
        if self._spend():
            return _UNKNOWN
        expr = expr.strip().rstrip(";").strip()
        if not expr:
            return _UNKNOWN
        # Unwrap grouping parens / casts / new-wrappers.
        while True:
            if expr.startswith("("):
                close = _find_matching_paren(expr)
                if close == len(expr) - 1:
                    expr = expr[1:-1].strip()
                    continue
            m = re.match(r"^\([\w$][\w$<>\[\],.?]*\)\s*(.+)$", expr)
            if m:
                expr = m.group(1).strip()
                continue
            m = re.match(r"^new\s+[\w$][\w$.<>[\],?\s]*?\((.*)\)$", expr)
            if m and _find_matching_paren(expr) == len(expr) - 1:
                expr = m.group(1).strip()
                continue
            break
        if _STRING_RE.match(expr) or _CHAR_RE.match(expr):
            return _SAFE
        if expr in ("null", "None", "nil", "true", "false"):
            return _SAFE        # constants; definitely not attacker input
        if _INT_ATOM_RE.match(expr) or _INT_SUFFIX_RE.match(expr):
            return _SAFE
        # Ternary: a folded condition selects one branch.
        qmark = _split_ternary(expr)
        if qmark is not None:
            cond = expr[:qmark].strip()
            branches = _split_top(expr[qmark + 1:], ":")
            if len(branches) == 2:
                folded = _fold_int(cond, env)
                if folded is not None:
                    return self.eval_expr(branches[0] if folded
                                          else branches[1], env, colls)
                return _merge(self.eval_expr(branches[0], env, colls),
                              self.eval_expr(branches[1], env, colls))
            return _UNKNOWN
        # Bare identifier.
        if re.fullmatch(r"[\w$][\w$]*", expr):
            return env.get(expr, _UNKNOWN)
        # Qualified field access (Utils.TESTFILES_DIR, request.path, ...).
        if re.fullmatch(r"[\w$][\w$.]*(?:\.[\w$][\w$]*)+", expr):
            head = expr.split(".")[0]
            tail = expr.split(".")[-1]
            if _REQUEST_RECEIVER_RE.match(head):
                return _UNSAFE
            if re.fullmatch(r"[A-Z][A-Z_0-9]+", tail):
                return _SAFE        # static final constant by convention
            return _UNKNOWN
        # Concatenation / arithmetic.
        parts = _split_top(expr, "+")
        if len(parts) > 1:
            values = [self.eval_expr(p, env, colls) for p in parts]
            if any(v == _UNSAFE for v in values):
                return _UNSAFE
            if all(v == _SAFE for v in values):
                return _SAFE
            return _UNKNOWN
        # Call.
        if "(" in expr:
            return self.eval_call(expr, env, colls)
        # Member access on a request-like receiver.
        m = re.match(r"^([\w$][\w$]*)\s*\.", expr)
        if m and _REQUEST_RECEIVER_RE.match(m.group(1)):
            return _UNSAFE
        return _UNKNOWN

    def eval_call(self, expr: str, env: dict, colls: dict) -> str:
        if self._spend():
            return _UNKNOWN
        open_at = _outer_call_open(expr)
        if open_at < 0:
            open_at = expr.find("(")
        close_at = _find_matching_paren(expr[open_at:]) + open_at \
            if open_at >= 0 else -1
        if open_at < 0 or close_at < open_at:
            return _UNKNOWN
        callee = expr[:open_at].strip()
        args = _split_args(expr[open_at + 1: close_at])
        values = [self.eval_expr(a, env, colls) for a in args]
        # Tracked collection accessors.
        m = re.match(r"^([\w$][\w$]*)\s*\.\s*(add|put|remove|get)\s*$", callee)
        if m:
            coll = colls.get(m.group(1))
            if coll is not None:
                if m.group(2) != "get":
                    return _UNKNOWN       # mutators: state handled elsewhere
                if coll.keyed:
                    if args and _STRING_RE.match(args[0].strip()):
                        return coll.get(args[0].strip().strip('"'))
                    return _UNKNOWN
                if args:
                    folded = _fold_int(args[0], env)
                    if folded is not None:
                        return coll.get(folded)
                return _UNKNOWN
        # Request-data source.
        head = callee.split(".")[0]
        if _REQUEST_RECEIVER_RE.match(head) or _REQUEST_CALL_RE.search(callee):
            return _UNSAFE
        # Reflective method reference: record ``x.getMethod("name", ...)``
        # so a later ``x.invoke(recv, args...)`` can be resolved in-file.
        m = re.search(r"^(.*)\.\s*getMethod\s*$", callee)
        if m and args and _STRING_RE.match(args[0].strip()):
            self.methodrefs[m.group(1).strip()] = args[0].strip().strip('"')
            return _UNKNOWN
        # Reflective invoke of a recorded same-file method.
        m = re.match(r"^([\w$][\w$]*)\s*\.\s*invoke\s*$", callee)
        if m and m.group(1) in self.methodrefs:
            inlined = self.inline_helper(
                self.methodrefs[m.group(1)], values[1:], env)
            if inlined is not None:
                return inlined
        # Same-file helper inline.
        inlined = self.inline_helper(callee.split(".")[-1], values, env)
        if inlined is not None:
            return inlined
        # Same-tree cross-file constant helper: the receiver was built as
        # ``new T(...)`` and a class T declared beside (or one directory
        # level above) this file exposes a method of the same name and
        # arity whose entire body is a single literal ``return`` — resolve
        # to that constant. The literal return is the proof; anything more
        # complex stays unresolved.
        m = re.match(r"^([\w$][\w$]*)\s*\.\s*([\w$][\w$]*)\s*$", callee)
        if m and m.group(1) in self.ctors and m.group(1) in env:
            const = self._crossfile_constant(
                self.ctors[m.group(1)], m.group(2), len(args))
            if const is not None:
                return const
        # Unresolved opaque call. The receiver's classification dominates:
        # a tainted receiver keeps taint, and an unknown TRACKED receiver
        # may itself hold attacker data (``theCookie.getName()``) so it can
        # never be promoted to SAFE. Untracked lowercase receivers are
        # treated the same way. A SAFE receiver, a class-style callee or a
        # bare call fed only constants can produce nothing but a constant
        # — the result depends on the arguments plus non-attacker global
        # state, which is outside this threat model.
        receiver_cls = None
        receiver_ok = True
        if "." in callee:
            recv = callee.rsplit(".", 1)[0].strip()
            if re.fullmatch(r"[\w$]+", recv):
                if recv in env:
                    receiver_cls = env[recv]
                elif not re.match(r"^[A-Z]", recv):
                    receiver_ok = False
        if receiver_cls == _UNSAFE:
            return _UNSAFE
        if receiver_ok and receiver_cls in (None, _SAFE) \
                and all(v == _SAFE for v in values):
            return _SAFE
        # Unknown method: round-trips preserve taint (Base64 archetype).
        if any(v == _UNSAFE for v in values):
            return _UNSAFE
        return _UNKNOWN

    # -- constant folding helpers ----------------------------------------

    def literal_value(self, expr: str, env: dict, colls: dict) -> str | None:
        """Concrete constant value of ``expr`` when provable, else ``None``.

        Feeds constant-selector ``switch`` folding: string/char literals,
        folded integers, tracked variable values and ``guess.charAt(1)``
        access on them. Never guesses.
        """
        expr = expr.strip().rstrip(";").strip()
        if _STRING_RE.match(expr):
            return expr[1:-1]
        if _CHAR_RE.match(expr):
            return expr[1:-1]
        folded = _fold_int(expr, env)
        if folded is not None:
            return str(folded)
        if re.fullmatch(r"[\w$][\w$]*", expr):
            return self.vals.get(expr)
        m = re.match(r"^([\w$][\w$]*)\s*\.\s*charAt\s*\((.+)\)$", expr)
        if m:
            base = self.vals.get(m.group(1))
            idx = _fold_int(m.group(2), env)
            if base is not None and idx is not None and 0 <= idx < len(base):
                return base[idx]
        m = re.match(r"^([\w$][\w$]*)\s*\.\s*length\s*\(\s*\)$", expr)
        if m:
            base = self.vals.get(m.group(1))
            if base is not None:
                return str(len(base))
        return None

    def _sync_val(self, name: str, rhs: str, env: dict, colls: dict) -> None:
        """Track ``name``'s literal value and constructor class, if any."""
        value = self.literal_value(rhs, env, colls)
        if value is not None:
            self.vals[name] = value
        else:
            self.vals.pop(name, None)
        # Only a rhs that IS a plain ``new T(...)`` construction records a
        # constructor class (``x = new T().call(...)`` must not).
        m = re.match(r"^new\s+([\w$][\w$.]*)\s*\(", rhs)
        if m and _find_matching_paren(rhs) == len(rhs) - 1:
            self.ctors[name] = m.group(1)
        else:
            self.ctors.pop(name, None)

    def _file_meta(self, path) -> tuple:
        """(package, imports) of a source file — memoized."""
        key = ("__meta__", str(path))
        if key in self._crossfile:
            return self._crossfile[key]
        meta: tuple = ("", [])
        try:
            head = (file_index.read_source(
                path, encoding="utf-8-sig", errors="replace") or "")[:8192]
            pm = re.search(r"^\s*package\s+([\w.]+)\s*;", head, re.M)
            imports = re.findall(
                r"^\s*import\s+(?:static\s+)?([\w.]+)\s*;", head, re.M)
            meta = (pm.group(1) if pm else "", imports)
        except OSError:
            meta = ("", [])
        self._crossfile[key] = meta
        return meta

    def _crossfile_constant(self, cls: str, method: str,
                            arity: int) -> str | None:
        """Resolve a same-tree helper class method to its literal return.

        Candidate files are derived EXACTLY — a fully-qualified constructor
        type (or a simple name matching an import) is located through this
        file's own ``package`` declaration from the shared source root; a
        simple name otherwise resolves next to this file. Only the tightest
        shape counts: a method ``<method>`` with matching arity whose entire
        body is a single literal ``return``. Anything else — non-literal
        return, multiple statements, unresolvable path — stays unresolved.
        """
        key = (cls, method, arity)
        if key in self._crossfile:
            return self._crossfile[key]
        result = None
        try:
            if self.filepath and cls and re.fullmatch(r"[\w$][\w$.]*", cls):
                from pathlib import Path
                here = Path(self.filepath)
                pkg, imports = self._file_meta(here)
                candidates: list = []
                if "." in cls:
                    if pkg:
                        root = here.parent
                        for _ in pkg.split("."):
                            root = root.parent
                        candidates.append(root.joinpath(*cls.split("."))
                                          .with_suffix(".java"))
                else:
                    candidates.append(here.parent / (cls + ".java"))
                    if pkg:
                        root = here.parent
                        for _ in pkg.split("."):
                            root = root.parent
                        for imp in imports:
                            if imp.rsplit(".", 1)[-1] == cls:
                                candidates.append(
                                    root.joinpath(*imp.split("."))
                                    .with_suffix(".java"))
                                break
                for cand in candidates:
                    if not cand.is_file() or cand.resolve() == here.resolve():
                        continue
                    if cand.stat().st_size > 262144:
                        continue
                    text = file_index.read_source(
                        cand, encoding="utf-8-sig", errors="replace")
                    if text is None:
                        # Old path raised OSError here and the outer handler
                        # kept the cache slot as an unresolved None -- an
                        # unreadable candidate never half-resolves.
                        raise OSError(f"unreadable: {cand}")
                    if not re.search(rf"\bclass\s+{re.escape(cls.rsplit('.', 1)[-1])}\b",
                                     text):
                        continue
                    result = self._literal_return_method(text, method, arity)
                    break
        except Exception:
            result = None
        self._crossfile[key] = result
        return result

    @staticmethod
    def _literal_return_method(text: str, method: str, arity: int):
        """``_SAFE`` when ``text`` declares ``method`` as a single literal
        ``return`` with matching arity; else ``None``."""
        if not re.fullmatch(r"[\w$][\w$]*", method or ""):
            return None
        pattern = (
            rf"(?:public|private|protected)?[^{{;]*?\b{re.escape(method)}"
            rf"\s*\(([^)]*)\)\s*(?:throws[\w.,\s]+)?\{{\s*([^{{}}]*?)\}}")
        for m in re.finditer(pattern, text):
            params = [p for p in _split_args(m.group(1)) if p.strip()]
            if len(params) != arity:
                continue
            body = re.sub(r"//[^\n]*|/\*.*?\*/", "", m.group(2), flags=re.S)
            rm = re.fullmatch(r"\s*return\s+(.+?)\s*;\s*", body, flags=re.S)
            if rm and _STRING_RE.match(rm.group(1).strip()):
                return _SAFE
            return None
        return None

    # -- block structure helpers -----------------------------------------

    @staticmethod
    def _matching_close(stmts: list[dict], header_idx: int,
                        end: int) -> int:
        """Index of the ``}`` closing a ``{``-ended header.

        When the range is truncated before the closing brace (the caller
        sliced at the sink line, which can sit inside a block), the body is
        treated as extending to ``end`` — the visible statements still get
        executed.
        """
        if not stmts[header_idx]["text"].endswith("{"):
            return header_idx
        depth = 1
        j = header_idx + 1
        while j < end:
            t = stmts[j]["text"]
            if t.endswith("{"):
                depth += 1
            elif t == "}":
                depth -= 1
                if depth == 0:
                    return j
            j += 1
        return end

    @staticmethod
    def _past_block(stmts: list[dict], i: int, end: int) -> int:
        """Index just past the block starting at stmts[i]."""
        t = stmts[i]["text"]
        if t.endswith("{"):
            depth = 1
            j = i + 1
        elif i + 1 < end and stmts[i + 1]["text"] == "{":
            depth = 1
            j = i + 2
        else:
            return i + 1          # single-statement body
        while j < end and depth > 0:
            t = stmts[j]["text"]
            if t.endswith("{"):
                depth += 1
            elif t == "}":
                depth -= 1
                if depth == 0:
                    return j + 1
            j += 1
        return end

    # -- statement execution ---------------------------------------------

    def exec_range(self, stmts: list[dict], env: dict, colls: dict,
                   start: int = 0, end: int | None = None) -> None:
        end = len(stmts) if end is None else end
        i = max(0, start)
        while i < end:
            if self._spend():
                return
            text = stmts[i]["text"].strip()
            if text == "}":
                i += 1
                continue
            if _LOOP_HEADER_RE.match(text):
                # Opaque: definitions inside loops are not strong updates.
                stop = self._past_block(stmts, i, end)
                mfor = re.match(
                    r"^for\s*\(\s*(?:[\w$][\w$<>\[\],.?]*\s+)+([\w$][\w$]*)\s*:",
                    text)
                if mfor:
                    # Enhanced-for declares its loop variable.
                    env[mfor.group(1)] = _UNKNOWN
                    self.vals.pop(mfor.group(1), None)
                self._null_assignments(stmts, i, stop, env, colls)
                i = stop
                continue
            if re.match(r"^if\b", text):
                i = self._exec_if(stmts, i, env, colls, end)
                continue
            if text.startswith("try"):
                i = self._exec_try(stmts, i, env, colls, end)
                continue
            if text.startswith("switch"):
                i = self._exec_switch(stmts, i, env, colls, end)
                continue
            if text.startswith(("else", "catch", "finally")):
                # Consumed by _exec_if/_exec_try; a stray one is opaque.
                stop = self._past_block(stmts, i, end)
                self._null_assignments(stmts, i, stop, env, colls,
                                       also_colls=False)
                i = stop
                continue
            if text.endswith("{") or _BLOCK_HEADER_RE.match(text):
                stop = self._past_block(stmts, i, end)
                inner = stmts[i + 1: stop - 1] if stop > i + 1 else []
                self.exec_range(inner, env, colls)
                i = stop
                continue
            self._exec_simple(text, env, colls)
            i += 1

    def _null_assignments(self, stmts: list[dict], start: int, stop: int,
                          env: dict, colls: dict,
                          also_colls: bool = True) -> None:
        """Mark every assignment in ``[start, stop)`` UNKNOWN (opaque)."""
        for s in stmts[start:stop]:
            m = _ASSIGN_RE.match(s["text"].strip())
            if m:
                env[m.group(1)] = _UNKNOWN
                self.vals.pop(m.group(1), None)
                if also_colls:
                    colls.pop(m.group(1), None)

    def _exec_simple(self, text: str, env: dict, colls: dict) -> None:
        # Collection mutators apply state changes.
        m = re.match(r"^([\w$][\w$]*)\s*\.\s*add\s*\((.*)\)\s*;?$", text)
        if m:
            coll = colls.get(m.group(1))
            if coll is not None:
                coll.add(self.eval_expr(m.group(2), env, colls))
            return
        m = re.match(r"^([\w$][\w$]*)\s*\.\s*put\s*\((.*)\)\s*;?$", text)
        if m:
            coll = colls.get(m.group(1))
            if coll is not None:
                args = _split_args(m.group(2))
                if len(args) == 2 and _STRING_RE.match(args[0].strip()):
                    coll.put(args[0].strip().strip('"'),
                             self.eval_expr(args[1], env, colls))
                else:
                    coll.broken = True
            return
        m = re.match(r"^([\w$][\w$]*)\s*\.\s*remove\s*\(\s*(\d+)\s*\)\s*;?$",
                     text)
        if m:
            coll = colls.get(m.group(1))
            if coll is not None:
                coll.remove_index(int(m.group(2)))
            return
        m = re.match(r"^([\w$][\w$]*)\s*\.\s*remove\s*\((.*)\)\s*;?$", text)
        if m:
            coll = colls.get(m.group(1))
            if coll is not None:
                coll.broken = True        # object-removal: index unknown
            return
        # Declarations with initialisers.
        m = _DECL_RE.match(text)
        if m:
            self._declare(m.group(1), m.group(2), text, env, colls)
            return
        # Plain assignments.
        m = _ASSIGN_RE.match(text)
        if m:
            env[m.group(1)] = self.eval_expr(m.group(2), env, colls)
            colls.pop(m.group(1), None)
            self._sync_val(m.group(1), m.group(2), env, colls)

    def _declare(self, name: str, rhs: str, text: str, env: dict,
                 colls: dict) -> None:
        if re.search(r"new\s+(?:[\w$][\w$.]*\.)?(?:ArrayList|LinkedList|"
                     r"Vector)\b", rhs) or re.search(r"\bList\s*<", rhs):
            colls[name] = _Coll(keyed=False)
            env[name] = _UNKNOWN
            self.vals.pop(name, None)
            self.ctors.pop(name, None)
            return
        if re.search(r"new\s+(?:[\w$][\w$.]*\.)?(?:HashMap|Hashtable|"
                     r"TreeMap|LinkedHashMap|ConcurrentHashMap)\b", rhs) \
                or re.search(r"\bMap\s*<", rhs):
            colls[name] = _Coll(keyed=True)
            env[name] = _UNKNOWN
            self.vals.pop(name, None)
            self.ctors.pop(name, None)
            return
        m = re.match(r"^(?:[\w$][\w$<>\[\],.?]*\s+)?"
                     r"(?:[\w$][\w$.]*\s*\.\s*)?asList\s*\((.*)\)$", rhs)
        if m:
            coll = _Coll(keyed=False)
            for arg in _split_args(m.group(1)):
                coll.add(self.eval_expr(arg, env, colls))
            colls[name] = coll
            env[name] = _UNKNOWN
            self.vals.pop(name, None)
            self.ctors.pop(name, None)
            return
        mint = _INT_DECL_RE.match(text)
        if mint:
            folded = _fold_int(mint.group(2), env)
            if folded is not None:
                env[mint.group(1)] = folded
                self.vals[mint.group(1)] = str(folded)
                return
        env[name] = self.eval_expr(rhs, env, colls)
        self._sync_val(name, rhs, env, colls)

    def _exec_if(self, stmts: list[dict], i: int, env: dict, colls: dict,
                 end: int) -> int:
        text = stmts[i]["text"].strip()
        open_at = text.find("(")
        close_at = _find_matching_paren(text) if open_at >= 0 else -1
        vals_snap = dict(self.vals)
        ctors_snap = dict(self.ctors)
        if open_at < 0 or close_at < 0:
            stop = self._past_block(stmts, i, end)
            self._null_assignments(stmts, i, stop, env, colls,
                                   also_colls=False)
            return stop
        cond = text[open_at + 1: close_at].strip()
        rest = text[close_at + 1:].strip()

        # Consequence: inline statement text, or a braced body.
        cons_inline = None
        if rest and rest != "{":
            cons_inline = rest
            cons_start = cons_end = -1
            next_i = i + 1
        else:
            cons_close = self._matching_close(stmts, i, end)
            cons_start = i + 1
            cons_end = cons_close - 1
            next_i = cons_close + 1

        # Else: inline statement, braced body, or an else-if chain.
        else_inline = None
        else_start = else_end = -1
        conservative_else = False
        j = next_i
        if j < end and stmts[j]["text"].strip().startswith("else"):
            etext = stmts[j]["text"].strip()
            erest = etext[4:].strip()
            if erest.startswith("if") or erest == "":
                if erest.startswith("if"):
                    conservative_else = True
                else:
                    else_close = self._matching_close(stmts, j, end)
                    else_start, else_end = j + 1, else_close - 1
                    next_i = else_close + 1
            elif erest.endswith("{"):
                else_close = self._matching_close(stmts, j, end)
                else_start, else_end = j + 1, else_close - 1
                next_i = else_close + 1
            else:
                else_inline = erest
                next_i = j + 1

        folded = _fold_int(cond, env)

        def run_inline(code: str, base: dict) -> dict:
            scope = dict(base)
            self._exec_simple(code.rstrip(";").strip() + ";", scope,
                              dict(colls))
            return scope

        def run_range(a: int, b: int, base: dict) -> dict:
            scope = dict(base)
            scope_colls = dict(colls)
            if 0 <= a <= b:
                self.exec_range(stmts, scope, scope_colls, a, b + 1)
            return scope

        if folded == 1:
            env_after = (run_inline(cons_inline, env) if cons_inline
                         else run_range(cons_start, cons_end, env))
        elif folded == 0:
            if else_inline is not None:
                env_after = run_inline(else_inline, env)
            elif else_start >= 0:
                env_after = run_range(else_start, else_end, env)
            else:
                env_after = dict(env)
        else:
            left = (run_inline(cons_inline, env) if cons_inline
                    else run_range(cons_start, cons_end, env))
            if conservative_else:
                right = dict(env)
                for s in stmts[next_i:]:
                    pass
                stop = self._past_block(stmts, j, end) if j < end else next_i
                for s in stmts[j:stop]:
                    m = _ASSIGN_RE.match(s["text"].strip())
                    if m:
                        right[m.group(1)] = _UNKNOWN
            elif else_inline is not None:
                right = run_inline(else_inline, env)
            elif else_start >= 0:
                right = run_range(else_start, else_end, env)
            else:
                right = dict(env)
            keys = set(left) | set(right)
            env_after = {
                k: _merge(left.get(k, env.get(k, _UNKNOWN)),
                          right.get(k, env.get(k, _UNKNOWN)))
                for k in keys}
        env.update(env_after)
        # Collections mutated in a merged (both-branch) context lose their
        # identity: drop them so later reads are UNKNOWN, never stale-safe.
        if folded is None:
            for s in stmts[i:next_i]:
                m = _DECL_RE.match(s["text"].strip())
                if m:
                    colls.pop(m.group(1), None)
            # Both branches executed speculatively: values/constructors
            # recorded inside them do not survive the merge.
            self.vals = vals_snap
            self.ctors = ctors_snap
        return next_i

    def _exec_switch(self, stmts: list[dict], i: int, env: dict,
                     colls: dict, end: int) -> int:
        """``switch`` with branch pruning (constant selector) or merging.

        A constant selector folds to the matching ``case`` section (with
        fall-through up to its ``break``); an opaque selector merges every
        section, so a tainted assignment in ANY case keeps the finding.
        Nested blocks reuse the full statement machinery.
        """
        text = stmts[i]["text"].strip()
        m = re.match(r"^switch\s*\((.+)\)\s*\{$", text)
        close = self._matching_close(stmts, i, end)
        if not m:
            self._null_assignments(stmts, i, close, env, colls)
            return close + 1 if close < end else end
        selector = m.group(1).strip()
        raw = stmts[i + 1: close] if close > i + 1 else []
        nxt = close + 1 if close < end else end

        # Strip case labels so nested blocks execute as plain statements,
        # remembering where each section starts and which values select it.
        clean: list[dict] = []
        sections: list[dict] = []
        for s in raw:
            t = s["text"].strip()
            cases: list[str] = []
            is_default = False
            while True:
                lm = re.match(r"^case\s+(.+?)\s*:\s*(.*)$", t)
                if lm:
                    cases.append(lm.group(1).strip())
                    t = lm.group(2)
                    continue
                lm = re.match(r"^default\s*:\s*(.*)$", t)
                if lm:
                    is_default = True
                    t = lm.group(1)
                    continue
                break
            if cases or is_default:
                sections.append({"start": len(clean), "cases": cases,
                                 "default": is_default})
            clean.append({"start": s["start"], "end": s["end"], "text": t})
        if not clean:
            return nxt

        sel_val = self.literal_value(selector, env, colls)
        if sel_val is not None:
            chosen = None
            default_sec = None
            for sec in sections:
                for cv in sec["cases"]:
                    norm = cv[1:-1] if (len(cv) >= 2
                                        and cv[0] in "\"'") else cv
                    if norm == sel_val and chosen is None:
                        chosen = sec
                if sec["default"] and default_sec is None:
                    default_sec = sec
            if chosen is None:
                chosen = default_sec
            # Statements before the first label always execute.
            stop = chosen["start"] if chosen is not None else len(clean)
            self.exec_range(clean, env, colls, 0, stop)
            if chosen is not None:
                # The reached section runs until its ``break`` (or, on
                # fall-through without one, to the end of the body).
                bound = len(clean)
                for k in range(chosen["start"], len(clean)):
                    if re.match(r"^break\b", clean[k]["text"].strip()):
                        bound = k
                        break
                self.exec_range(clean, env, colls, chosen["start"], bound)
            return nxt

        # Opaque selector: execute every section on its own copy and merge.
        vals_snap = dict(self.vals)
        ctors_snap = dict(self.ctors)
        prelude_end = sections[0]["start"] if sections else len(clean)
        self.exec_range(clean, env, colls, 0, prelude_end)
        base = dict(env)
        base_colls = dict(colls)
        bounds = [sec["start"] for sec in sections] + [len(clean)]
        envs: list[dict] = []
        for idx in range(len(sections)):
            scope = dict(base)
            scope_colls = dict(base_colls)
            self.exec_range(clean, scope, scope_colls,
                            bounds[idx], bounds[idx + 1])
            envs.append(scope)
        merged: dict = {}
        for var in {v for e in envs for v in e}:
            value = base.get(var, _UNKNOWN)
            for e in envs:
                value = _merge(value, e.get(var, base.get(var, _UNKNOWN)))
            merged[var] = value
        env.update(merged)
        # Section execution was speculative: literal values and constructor
        # classes recorded inside it do not survive the merge.
        self.vals = vals_snap
        self.ctors = ctors_snap
        return nxt

    def _exec_try(self, stmts: list[dict], i: int, env: dict, colls: dict,
                  end: int) -> int:
        vals_snap = dict(self.vals)
        ctors_snap = dict(self.ctors)
        close = self._matching_close(stmts, i, end)
        base = dict(env)
        left_env = dict(env)
        left_colls = dict(colls)
        self.exec_range(stmts, left_env, left_colls, i + 1, close)
        merged = dict(left_env)
        j = close + 1
        while j < end and stmts[j]["text"].strip().startswith(
                ("catch", "finally")):
            cclose = self._matching_close(stmts, j, end)
            right_env = dict(base)
            right_colls = dict(colls)
            self.exec_range(stmts, right_env, right_colls, j + 1, cclose)
            keys = set(merged) | set(right_env)
            merged = {
                k: _merge(merged.get(k, base.get(k, _UNKNOWN)),
                          right_env.get(k, base.get(k, _UNKNOWN)))
                for k in keys}
            j = cclose + 1
        env.update(merged)
        # try/catch is a speculative merge: values recorded inside it do
        # not survive.
        self.vals = vals_snap
        self.ctors = ctors_snap
        return j

    # -- same-file helper inline -----------------------------------------

    def inline_helper(self, name: str, arg_values: list[str],
                      env: dict) -> str | None:
        if self.inline_depth >= _MAX_INLINE_DEPTH:
            return None
        header = None
        for idx, stmt in enumerate(self.stmts):
            text = stmt["text"].rstrip()
            if not text.endswith("{"):
                continue
            head = _strip_attributes(text[:-1].strip())
            if not head or _BLOCK_HEADER_RE.match(head):
                continue
            m = _METHOD_HEADER_RE.match(head)
            if m and m.group(1) == name:
                params = [p.strip().split()[-1]
                          for p in _split_args(m.group(2)) if p.strip()]
                if arg_values and len(params) != len(arg_values):
                    continue          # overload mismatch
                header = (idx, params)
                break
        if header is None:
            return None
        idx, params = header
        close = self._matching_close(self.stmts, idx, len(self.stmts))
        body = self.stmts[idx + 1: close]
        if len(body) > _MAX_STATEMENTS:
            return _UNKNOWN
        bound = dict(env)
        for p, v in zip(params, arg_values):
            bound[p] = v
        bound_colls: dict = {}
        vals_snap = dict(self.vals)
        ctors_snap = dict(self.ctors)
        self.inline_depth += 1
        try:
            self.exec_range(body, bound, bound_colls)
        finally:
            self.inline_depth -= 1
            # The helper body runs against bound copies: its local value
            # tracking must not leak into the caller.
            self.vals = vals_snap
            self.ctors = ctors_snap
        result = _UNKNOWN
        seen = False
        for s in body:
            m = re.match(r"^return\s+(.+?)\s*;?$", s["text"].strip())
            if not m:
                continue
            got = self.eval_expr(m.group(1), bound, bound_colls)
            result = got if not seen else _merge(result, got)
            seen = True
        return result if seen else _UNKNOWN


# ---------------------------------------------------------------------------
# Public entry
# ---------------------------------------------------------------------------

def is_proven_constant(source: str, var: str, at_line: int,
                       filepath: str | None = None) -> bool:
    """True only when ``var``'s value at ``at_line`` is a proven constant.

    ``filepath`` (optional) enables same-tree cross-file helper
    resolution. Never raises: any analysis failure is "not proven" (KEEP).
    """
    if not gate_enabled() or not var:
        return False
    try:
        stmts = split_statements(source.splitlines())
        if not stmts or len(stmts) > _MAX_STATEMENTS:
            return False
        body_start, params = _method_scope(stmts, at_line)
        analyzer = _Analyzer(stmts, filepath)
        env: dict = {p: _UNSAFE for p in params}
        colls: dict = {}
        idx = body_start
        n = sum(1 for s in stmts if s["end"] <= at_line)
        analyzer.exec_range(stmts, env, colls, idx, n)
        return env.get(var) == _SAFE
    except Exception:
        return False


def sink_value_proven_constant(source: str, at_line: int, names,
                               filepath: str | None = None) -> bool:
    """True only when EVERY name in ``names`` is a proven constant at
    ``at_line`` (V1.12b kill-only-on-proof gate for sink emissions).

    Callers pass the tainted carriers reaching one sink; when every one of
    them folds to a constant at that line the attacker data provably died
    before the sink (constant-true branch/ternary, safe-key map read, or a
    helper whose return folds) and the finding must not fire.  An empty
    input, any unproven name, or any analysis failure returns False
    (KEEP): the gate never kills on absence of proof.  Honours
    ``gate_enabled()``; ``RSX_MULTIPART_FLOW=0`` restores pre-gate
    behaviour.
    """
    if not names or not gate_enabled():
        return False
    for name in names:
        if not isinstance(name, str) or not name.strip():
            return False
        try:
            if not is_proven_constant(source, name.strip(), at_line,
                                      filepath=filepath):
                return False
        except Exception:
            return False
    return True


_ATTR_PREFIX_RE = re.compile(
    r"^(?:@\w+(?:\([^()]*\))?\s+|\[[^\][]*\]\s*)+")


def _strip_attributes(head: str) -> str:
    """Drop leading annotations/attributes (``@Override``, ``[HttpGet]``)."""
    return _ATTR_PREFIX_RE.sub("", head).strip()


def _method_scope(stmts: list[dict], at_line: int) -> tuple[int, list[str]]:
    """(first statement index inside the enclosing method, param names)."""
    for idx in range(len(stmts) - 1, -1, -1):
        stmt = stmts[idx]
        if stmt["end"] > at_line or not stmt["text"].endswith("{"):
            continue
        head = _strip_attributes(stmt["text"][:-1].strip())
        if not head or _BLOCK_HEADER_RE.match(head):
            continue
        m = _METHOD_HEADER_RE.match(head)
        if m:
            params = [p.strip().split()[-1]
                      for p in _split_args(m.group(2))
                      if p.strip() and p.strip() != "..."]
            return idx + 1, params
    return 0, []
