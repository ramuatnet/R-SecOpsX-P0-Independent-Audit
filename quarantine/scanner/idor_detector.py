"""
scanner/idor_detector.py
========================
Behaviour-based IDOR detector using AST taint analysis.

Three conditions must ALL hold before a finding is raised:
  1. A user-controlled identifier reaches a data-access sink.
  2. The flow is not suppressed by a real ownership / authorization check.
  3. (Route-based path) the route has a variable segment <param> that feeds a sink.

Detection strategy
------------------
* Uses a lightweight single-function taint propagation (no cross-function).
* Suppresses findings when ownership patterns are present in the same scope.
* Complements (does NOT replace) the taint_engine.py general analysis.

Auth suppression patterns (cause the finding to be dropped)
-----------------------------------------------------------
  Sufficient (suppress IDOR):
    current_user.id  == var  /  var == current_user.id   (ownership compare)
    is_authorized(   / check_access(  / has_permission(
    if var not in allowed_ids / whitelist / allowed
    AND owner_id=?  / AND user_id=current_user   in a DB query string

  Insufficient (IDOR still flagged):
    current_user.is_authenticated              (authn ≠ authz)
    int(var) / str(var)                        (type-cast ≠ authz)
    current_user.email == var                  (wrong attribute)
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Taint sources — expressions whose return value is user-controlled
# ---------------------------------------------------------------------------
_TAINT_SOURCE_RE = re.compile(
    r"""
    request\.(?:args|GET|POST|form|params|data|values|files|view_args)
        \.get\s*\(
    | request\.(?:args|GET|POST|form)\s*\[
    | request\.(?:json|data|get_json)\b
    """,
    re.VERBOSE | re.IGNORECASE,
)

# Function/attribute names that indicate the function argument receives a
# user-controlled value (used for route-variable path params).
_ROUTE_SOURCES: frozenset[str] = frozenset({
    "user_id", "uid", "account_id", "item_id", "order_id",
    "record_id", "doc_id", "pk", "obj_id", "id", "file_id",
})

# ---------------------------------------------------------------------------
# Data-access sinks that constitute an IDOR when reached by tainted data
# ---------------------------------------------------------------------------
# Part 4: HTTP sinks are SSRF territory — NEVER IDOR.
# Removing: requests.get, requests.post, fetch_by_id (fetch = HTTP verb ambiguity),
#           repository.fetch (use repository.find/get instead)
_IDOR_SINKS: frozenset[str] = frozenset({
    # Generic DB helpers
    "db.get", "db.find", "db.query",
    # SQLAlchemy
    "session.get", "session.query",
    # Django ORM
    "objects.get", "objects.filter", "objects.exclude",
    "get_object_or_404",
    # Mongo / generic ORMs
    "collection.find_one", "collection.find",
    "Model.get", "Model.find",
    # Generic by-ID helpers
    "find_by_id", "get_by_id",
    "findById", "findOne",
    # File system
    "open",
    # Raw SQL
    "execute", "cursor.execute",
    # Repository / DAO patterns
    # repository.fetch / repo.fetch = DAO pattern (receiver makes it safe)
    "repository.find", "repository.get", "repository.fetch",
    "repo.get", "repo.find", "repo.fetch",
    "User.find_by_id", "User.objects.get",
})

# Part 3+4: Sink → category mapping for conflict resolution
_SINK_CATEGORY: dict[str, str] = {
    # database
    "db.get":           "database", "db.find":           "database",
    "db.query":         "database", "session.get":        "database",
    "session.query":    "database", "objects.get":        "database",
    "objects.filter":   "database", "objects.exclude":    "database",
    "get_object_or_404":"database", "collection.find_one":"database",
    "collection.find":  "database", "Model.get":          "database",
    "Model.find":       "database", "find_by_id":         "database",
    "get_by_id":        "database", "findById":           "database",
    "findOne":          "database", "execute":            "database",
    "cursor.execute":   "database", "repository.find":    "database", "repository.get":   "database",
    "repository.fetch":   "database",
    "repo.get":           "database", "repo.find":        "database",
    "repo.fetch":         "database", "User.find_by_id":    "database",
    "User.objects.get": "database",
    # file
    "open":             "file",
    # http — these must NEVER appear in _IDOR_SINKS but kept here for reference
    "requests.get":     "http",     "requests.post":      "http",
    "requests.put":     "http",     "requests.delete":    "http",
    "urllib.request.urlopen": "http",
    "http.client.HTTPConnection": "http",
    "fetch":            "http",     "axios":              "http",
}

# Part 6: HTTP sink names — if a call resolves to one of these it is SSRF not IDOR
_HTTP_SINKS: frozenset[str] = frozenset({
    "requests.get", "requests.post", "requests.put", "requests.delete",
    "requests.request", "requests.patch",
    "urllib.request.urlopen", "urllib.urlopen",
    "http.client.HTTPConnection", "http.client.HTTPSConnection",
    "httpx.get", "httpx.post",
    "fetch", "axios", "axios.get", "axios.post",
    "aiohttp.ClientSession.get", "aiohttp.ClientSession.post",
})


def _classify_sink(call_str: str) -> str:
    """Return sink_category for a call string."""
    # Direct lookup
    cat = _SINK_CATEGORY.get(call_str)
    if cat:
        return cat
    # Suffix match for chained calls
    for key, cat in _SINK_CATEGORY.items():
        if call_str.endswith("." + key.split(".")[-1]):
            return cat
    return "unknown"

# ---------------------------------------------------------------------------
# Auth / ownership suppression patterns
# These make a finding safe — IDOR is NOT raised when they appear in scope.
# ---------------------------------------------------------------------------

# Pattern: current_user.id compared to the tainted variable
_OWNERSHIP_CMP_RE = re.compile(
    r"current_user\.id\s*(?:==|!=|is)\s*\w+"
    r"|"
    r"\w+\s*(?:==|!=|is)\s*current_user\.id",
    re.IGNORECASE,
)

# Authorization function calls
_AUTH_FUNC_RE = re.compile(
    r"\b(?:is_authorized|check_access|has_permission|require_permission"
    r"|authorize|can_access|check_permission)\s*\(",
    re.IGNORECASE,
)

# Allowlist / denylist membership check on the tainted variable
_ALLOWLIST_RE = re.compile(
    r"\bnot\s+in\s+\w*(?:allowed|whitelist|permit|safe)\w*"
    r"|\bnot\s+in\s+\w*_ids\b",
    re.IGNORECASE,
)

# SQL query string contains owner-filter (inline, not parameterised check)
_OWNER_FILTER_SQL_RE = re.compile(
    r"AND\s+(?:owner_id|user_id|account_id)\s*[=!]",
    re.IGNORECASE,
)

# Auth decorators on the function (Flask-Login, custom)
_AUTH_DECORATOR_RE = re.compile(
    r"\blogin_required\b|\bjwt_required\b|\btoken_required\b"
    r"|\brequire_auth\b|\bpermission_required\b",
    re.IGNORECASE,
)

# ── Patterns that look like auth but are NOT sufficient ──────────────────────
# is_authenticated is authn, not authz — still an IDOR
# Type-casting (int(), str()) is sanitisation, not authorisation
# Comparing wrong attribute (current_user.email != user_id) is not ownership
_INSUFFICIENT_AUTH_RE = re.compile(
    r"current_user\.is_authenticated"
    r"|"
    r"\bint\s*\(\s*\w+\s*\)"
    r"|"
    r"current_user\.(?!id\b)\w+\s*==",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Route variable regex (matches ast.unparse output, no @ prefix)
# ---------------------------------------------------------------------------
_ROUTE_VAR_RE = re.compile(r"route\s*\(.*<[^>]+>", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------
@dataclass
class IDORFinding:
    file:       str
    line:       int
    snippet:    str
    taint_path: str
    confidence: str   # "High" | "Medium"
    note:          str   = ""
    suppressed:    bool  = False   # True = would have fired but auth was found
    vuln_type:     str   = "api_idor"
    detection:     str   = "Taint Flow Analysis"
    sink_category: str   = "unknown"   # Part 3: database | file | http | internal_api | unknown


# ---------------------------------------------------------------------------
# Single-function taint tracker
# ---------------------------------------------------------------------------
class _FunctionAnalyser(ast.NodeVisitor):
    """
    Lightweight per-function taint propagation.

    Tracks variables that hold user-controlled values and checks whether
    they reach an IDOR sink without a real ownership/authorization check
    in the same function scope.
    """

    def __init__(self, source_lines: list[str], filepath: str):
        self._lines     = source_lines
        self._filepath  = filepath
        self._tainted:  dict[str, str] = {}   # varname -> taint_path string
        self._findings: list[IDORFinding]  = []

    # ── Public entry ─────────────────────────────────────────────────────────

    def analyse_function(self, func_node: ast.FunctionDef | ast.AsyncFunctionDef,
                         route_vars: list[str] | None = None) -> list[IDORFinding]:
        """Analyse one function; route_vars are the <param> names from the route."""
        self._tainted = {}
        self._findings = []
        self._route_vars = set(route_vars or [])

        # Seed taint from route parameters that match known ID-param names
        for arg in func_node.args.args:
            if arg.arg in _ROUTE_SOURCES or arg.arg in self._route_vars:
                self._tainted[arg.arg] = arg.arg   # initial path = the param name

        # Walk the function body
        for stmt in func_node.body:
            self._visit_stmt(stmt)

        # Return only un-suppressed findings
        return [f for f in self._findings if not f.suppressed]

    # ── Statement visitor ────────────────────────────────────────────────────

    def _visit_stmt(self, node: ast.stmt) -> None:
        """Dispatch a single statement for taint propagation."""
        if isinstance(node, ast.Assign):
            self._handle_assign(node)
        elif isinstance(node, (ast.Expr, ast.Return)):
            self._handle_expr(node)
        elif isinstance(node, ast.If):
            self._handle_if(node)
        elif isinstance(node, (ast.For, ast.While, ast.With)):
            for child in ast.walk(node):
                if child is not node and isinstance(child, ast.stmt):
                    self._visit_stmt(child)
        # Other stmt types: not interesting for IDOR

    def _handle_assign(self, node: ast.Assign) -> None:
        """Propagate taint through assignments and detect source calls."""
        rhs_taint = self._taint_of_expr(node.value)
        for target in node.targets:
            if isinstance(target, ast.Name):
                if rhs_taint:
                    # Propagate: lhs is now tainted
                    self._tainted[target.id] = rhs_taint + " -> " + target.id
                else:
                    # Assignment may clear taint (but only at this scope level)
                    self._tainted.pop(target.id, None)
        # Also check if the RHS itself is a sink call reaching tainted data
        if isinstance(node.value, ast.Call):
            self._check_sink_call(node.value)

    def _handle_expr(self, node: ast.Expr | ast.Return) -> None:
        """Check expression / return statement for sink calls."""
        value = node.value if isinstance(node, ast.Return) else node.value
        if value is None:
            return
        for call in _calls_in(value):
            self._check_sink_call(call)

    def _handle_if(self, node: ast.If) -> None:
        """
        Handle if-statements.
        An 'if … return Forbidden' guard only suppresses IDOR for the ELSE
        branch. We conservatively flag if ANY code path reaches the sink
        without authorisation (E1 mixed-safe-unsafe case).
        We simply visit both branches without modelling branch-level taint
        splitting — this catches E1 correctly.
        """
        # Visit test expression for sink calls (rare, but possible)
        for call in _calls_in(node.test):
            self._check_sink_call(call)
        # Visit both branches
        for stmt in node.body + node.orelse:
            self._visit_stmt(stmt)

    # ── Taint helper ─────────────────────────────────────────────────────────

    def _taint_of_expr(self, node: ast.expr) -> str:
        """
        Return a taint-path string if the expression is tainted, else ''.

        Handles:
          - Direct Name references
          - Source calls: request.args.get('user_id')
          - Propagation through function calls: int(uid), transform(uid)
          - f-strings containing tainted values
          - BinOp / JoinedStr with tainted sub-expressions
        """
        if isinstance(node, ast.Name):
            return self._tainted.get(node.id, "")

        if isinstance(node, ast.Call):
            # Is this a taint source?
            call_str = _unparse_call(node)
            for src in TAINT_SOURCES_STR:
                if call_str.startswith(src):
                    # Extract the argument string for the path label
                    arg_label = _first_str_arg(node) or call_str
                    return arg_label

            # Propagation through arbitrary function call:
            # if any argument is tainted, the result is tainted
            # (conservative — models int(uid), transform(uid), fetch(uid) etc.)
            for arg in node.args:
                tp = self._taint_of_expr(arg)
                if tp:
                    return tp + " -> [call]"
            return ""

        if isinstance(node, (ast.JoinedStr, ast.BinOp)):
            # f-string or concatenation: tainted if any part is tainted
            for child in ast.walk(node):
                if isinstance(child, ast.Name):
                    tp = self._tainted.get(child.id, "")
                    if tp:
                        return tp + " -> [fstring]"
            return ""

        if isinstance(node, ast.Attribute):
            # request.args, current_user.id — check if the object is tainted
            tp = self._taint_of_expr(node.value)
            return (tp + "." + node.attr) if tp else ""

        if isinstance(node, ast.Subscript):
            tp = self._taint_of_expr(node.value)
            return tp if tp else ""

        return ""

    # ── Sink checker ─────────────────────────────────────────────────────────

    def _check_sink_call(self, call_node: ast.Call) -> None:
        """
        If call_node is an IDOR sink AND any argument is tainted AND no
        ownership/auth check suppresses the finding → record an IDORFinding.
        """
        call_str = _unparse_call(call_node)

        # Issue 1 FIX: reject HTTP sinks BEFORE any sink matching.
        # Partial name overlaps (e.g. repository.fetch, fetch_by_id) must
        # not sneak through — check the raw call string first.
        if _is_http_sink(call_str):
            return

        sink_name = _match_sink(call_str)
        if not sink_name:
            return

        # Check if any argument carries taint
        tainted_path = ""
        for arg in call_node.args + [kw.value for kw in call_node.keywords]:
            tp = self._taint_of_expr(arg)
            if tp:
                tainted_path = tp
                break
        if not tainted_path:
            return   # sink reached, but no tainted input

        lineno  = getattr(call_node, "lineno", 0)
        snippet = self._lines[lineno-1].strip() if lineno <= len(self._lines) else call_str

        # Build full taint path label
        full_path = tainted_path + " -> " + call_str

        sink_cat = _classify_sink(call_str)
        self._findings.append(IDORFinding(
            file=self._filepath,
            line=lineno,
            snippet=snippet,
            taint_path=full_path,
            confidence="High",
            note="User-controlled identifier reaches data-access sink without authorization validation.",
            sink_category=sink_cat,
        ))


# ---------------------------------------------------------------------------
# Auth suppression pass — applied to the entire function body text
# ---------------------------------------------------------------------------

# Regex to count data-access sink calls in function source
_SINK_CALL_RE = re.compile(
    r"(?:db|session|objects|collection|cursor|repo(?:sitory)?)"
    r"\.(?:get|find|filter|query|execute|fetch)\s*\("
    r"|find_by_id\s*\(|findById\s*\(|get_object_or_404\s*\(|open\s*\(",
    re.IGNORECASE,
)


def _suppressed_by_auth(func_src: str,
                        func_node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """
    Return True ONLY if ALL tainted-data paths through the function are
    protected by a real ownership / authorization check.

    Key insight for E1 (mixed safe+unsafe):
      If there are multiple sink calls in the function and only ONE of them
      is inside an ownership-protected if-block, the function is NOT fully
      suppressed — the unguarded sink path is still an IDOR.

    Patterns that ARE sufficient (when they cover ALL sink calls):
      • current_user.id == var  — direct ownership comparison
      • is_authorized(…) / check_access(…) / has_permission(…)
      • if var not in allowed_ids / whitelist
      • SQL: AND owner_id=? inline guard

    Patterns that are NOT sufficient:
      • current_user.is_authenticated  (authn ≠ authz)
      • int(user_id) / str(user_id)   (type-cast)
      • current_user.email == var     (wrong attribute)
    """
    has_ownership = bool(_OWNERSHIP_CMP_RE.search(func_src))
    has_auth_func = bool(_AUTH_FUNC_RE.search(func_src))
    has_allowlist = bool(_ALLOWLIST_RE.search(func_src))
    has_owner_sql = bool(_OWNER_FILTER_SQL_RE.search(func_src))

    if not (has_ownership or has_auth_func or has_allowlist or has_owner_sql):
        return False  # no auth at all

    # Count how many distinct sink calls are present
    sink_calls = _SINK_CALL_RE.findall(func_src)
    if len(sink_calls) <= 1:
        # Single sink — the auth check covers it
        return True

    # Multiple sinks: ownership comparison only suppresses if it guards ALL paths.
    # A simple heuristic: if there are N sink calls and the function has an
    # unconditional (not-inside-if) sink call after the auth check, it's NOT safe.
    # We detect this by checking if the auth expression appears on a line where
    # the NEXT non-empty line is NOT a return/raise (i.e. execution continues).
    if has_auth_func or has_allowlist or has_owner_sql:
        # These are typically guard-clause patterns (return Forbidden immediately)
        # so they suppress even with multiple sinks.
        return True

    if has_ownership:
        # Ownership check inside an if-block: only safe when it wraps ALL sinks.
        # Heuristic: count sink calls inside vs outside if-blocks.
        # If any sink call line is at base indentation (not inside an if),
        # the function has an unguarded path.
        lines = func_src.split("\n")
        base_indent = len(lines[0]) - len(lines[0].lstrip()) if lines else 0
        unguarded_sinks = 0
        in_if = False
        if_indent = 999
        for line in lines:
            stripped = line.lstrip()
            indent = len(line) - len(stripped)
            if stripped.startswith("if ") and indent <= base_indent + 4:
                in_if = True
                if_indent = indent
            elif in_if and indent <= if_indent:
                in_if = False   # exited the if block
            if not in_if and _SINK_CALL_RE.search(stripped):
                unguarded_sinks += 1
        return unguarded_sinks == 0  # safe only if no unguarded sinks

    return False


# ---------------------------------------------------------------------------
# Route decorator scanner
# ---------------------------------------------------------------------------

def _get_route_vars(func_node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    """Return <param> names from Flask/FastAPI route decorators, e.g. [user_id]."""
    route_vars: list[str] = []
    for deco in func_node.decorator_list:
        try:
            deco_str = ast.unparse(deco)
        except Exception:
            continue
        if _ROUTE_VAR_RE.search(deco_str):
            route_vars += re.findall(r"<(?:[^:>]+:)?([^>]+)>", deco_str)
    return route_vars


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

TAINT_SOURCES_STR: list[str] = [
    "request.args.get",  "request.GET.get",   "request.POST.get",
    "request.form.get",  "request.params.get","request.data.get",
    "request.values.get","request.args[",     "request.GET[",
    "request.form[",     "request.get_json",  "request.json",
]


def _analyse_python(filepath: str) -> list[dict]:
    """
    Run IDOR taint analysis on a Python source file.

    Returns a list of finding dicts compatible with the rest of the pipeline
    (same keys as findings from sast.py / taint_engine.py).
    """
    try:
        source = Path(filepath).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []

    lines    = source.splitlines()
    findings = []

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        # Extract source text for this function for the suppression regex checks
        func_start = node.lineno - 1
        func_end   = getattr(node, "end_lineno", func_start + 30)
        func_src   = "\n".join(lines[func_start:func_end])

        # Collect route path variables (<user_id> etc.)
        route_vars = _get_route_vars(node)

        # Analyse taint flow inside this function
        analyser = _FunctionAnalyser(lines, filepath)
        raw = analyser.analyse_function(node, route_vars)
        if not raw:
            continue

        # Suppression check — applied once per function
        if _suppressed_by_auth(func_src, node):
            continue   # all findings in this function are suppressed

        # Emit findings
        for f in raw:
            findings.append(_make_finding_dict(f, filepath))

    return findings


_IDOR_FALLBACK_MAPPING = {
    "title": "Insecure Direct Object Reference (IDOR)",
    "severity": "High",
    "priority": "P2",
    "cwe": "CWE-639",
    "cwe_desc": "Authorization Bypass Through User-Controlled Key",
    "owasp": "A01:2021 - Broken Access Control",
    "owasp_id": "A01",
    "mitre": "T1190",
    "mitre_desc": "Exploit Public-Facing Application",
    "pci_dss": "Req 7.1 - Limit access to system components",
    "nist": "AC-3 Access Enforcement",
    "iso27001": "A.9.4.1 Information Access Restriction",
    "soc2": "CC6.3 Access to Information Assets",
    "exploitability": "High",
    "business_impact": (
        "Attacker accesses any user's data by changing a predictable ID "
        "in the URL. Sequential enumeration exposes all records."
    ),
    "remediation": [
        "Implement server-side authorization on every object access.",
        "Use UUIDs instead of sequential IDs.",
        "Verify authenticated user owns the requested resource.",
    ],
}


def _get_idor_mapping() -> dict:
    """Load central api_idor mapping with a safe compatibility fallback."""
    try:
        from core.mapper import get_mapping
        mapped = get_mapping("api_idor")
        if isinstance(mapped, dict) and mapped:
            merged = dict(_IDOR_FALLBACK_MAPPING)
            merged.update(mapped)
            return merged
    except Exception:
        pass

    return dict(_IDOR_FALLBACK_MAPPING)


def _base_idor_finding(
    filepath: str,
    line: int,
    snippet: str,
    language: str,
) -> dict:
    """Build a pipeline-compatible IDOR finding from central mapping data."""
    m = _get_idor_mapping()

    return {
        "rule_id": "API_IDOR",
        "vuln_type": "api_idor",
        "title": m.get("title", "Insecure Direct Object Reference (IDOR)"),
        "severity": m.get("severity", "High"),
        "priority": m.get("priority", "P2"),
        "confidence": "Medium",
        "language": language,
        "file": str(filepath),
        "line": int(line),
        "snippet": snippet,
        "cwe": m.get("cwe", "CWE-639"),
        "cwe_desc": m.get(
            "cwe_desc",
            "Authorization Bypass Through User-Controlled Key",
        ),
        "owasp": m.get(
            "owasp",
            "A01:2021 - Broken Access Control",
        ),
        "owasp_id": m.get("owasp_id", "A01"),
        "mitre": m.get("mitre", "T1190"),
        "mitre_desc": m.get(
            "mitre_desc",
            "Exploit Public-Facing Application",
        ),
        "pci_dss": m.get(
            "pci_dss",
            "Req 7.1 - Limit access to system components",
        ),
        "nist": m.get("nist", "AC-3 Access Enforcement"),
        "iso27001": m.get(
            "iso27001",
            "A.9.4.1 Information Access Restriction",
        ),
        "soc2": m.get(
            "soc2",
            "CC6.3 Access to Information Assets",
        ),
        "exploitability": m.get("exploitability", "High"),
        "business_impact": m.get("business_impact", ""),
        "remediation": list(m.get("remediation") or []),
    }


def _make_finding_dict(f: IDORFinding, filepath: str) -> dict:
    """Convert IDORFinding to a pipeline-compatible dict."""
    base = _base_idor_finding(
        filepath=filepath,
        line=f.line,
        snippet=f.snippet,
        language="python",
    )

    tp_parts = f.taint_path.rsplit(" -> ", 1)
    norm_sink = (
        tp_parts[-1].split("(")[0].strip()
        if tp_parts
        else "unknown"
    )

    base.update({
        "taint_path": f.taint_path,
        "taint_chain": f.taint_path.split(" -> "),
        "detection": "TAINT-VALIDATED",
        "confidence": f.confidence,
        "note": f.note,
        "sink_category": f.sink_category,
        "group_key": f"api_idor|{norm_sink}",
    })

    return base


def _unparse_call(node: ast.Call) -> str:
    """Best-effort string representation of a Call node's function part."""
    try:
        return ast.unparse(node.func)
    except Exception:
        return ""


def _first_str_arg(node: ast.Call) -> str:
    """Return the first string-literal argument of a call, if any."""
    for arg in node.args:
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            return f"request.args.get('{arg.value}')"
    return ""


def _is_http_sink(call_str: str) -> bool:
    """
    Issue 1: Return True if the call is an HTTP client call.
    Checked BEFORE _match_sink to prevent partial-name overlaps like
    'repository.fetch' or 'fetch_by_id' slipping through.
    """
    # Check against the explicit HTTP sink set
    if call_str in _HTTP_SINKS:
        return True
    # Check common HTTP prefixes/substrings that indicate outbound HTTP
    # DAO objects with .fetch are NOT HTTP (e.g. repository.fetch, repo.fetch)
    _DAO_PREFIXES = ("repository.", "repo.", "store.", "dao.", "model.", "db.")
    if any(call_str.startswith(p) for p in _DAO_PREFIXES):
        return False   # DAO method — not HTTP regardless of verb name
    _HTTP_INDICATORS = (
        "requests.", "urllib.", "httpx.", "aiohttp.",
        "http.client.", "httplib.", "urlopen",
        "axios", "fetch(",
    )
    return any(ind in call_str for ind in _HTTP_INDICATORS)


def _match_sink(call_str: str) -> str:
    """Return the matched sink name if call_str matches an IDOR sink, else ''."""
    for sink in _IDOR_SINKS:
        if call_str == sink or call_str.endswith("." + sink.split(".")[-1]):
            return sink
        # Handle method calls: objects.get, User.find_by_id etc.
        if sink in call_str:
            return sink
    return ""


def _calls_in(node: ast.expr) -> list[ast.Call]:
    """Collect all Call nodes inside an expression (non-recursive top-level)."""
    calls = []
    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            calls.append(child)
    return calls


# ===========================================================================
# Multi-language IDOR detection (Node.js, Java, Go)
# Uses a line-window contextual approach:
#   1. Find a user-input source line
#   2. Extract the variable name captured
#   3. Scan a forward window for a data-access sink using that variable
#   4. Check whether any auth suppression appears in the same window
# ===========================================================================

import re as _re

# ---------------------------------------------------------------------------
# Language-specific source patterns (return the tainted variable name)
# ---------------------------------------------------------------------------
_JS_SOURCES = _re.compile(
    r'(?:const|let|var)\s+(\w+)\s*=\s*'
    r'req\.(?:query|params|body)(?:\.\w+|\[[\'"]\w+[\'"]\])',
    _re.IGNORECASE,
)
_JS_SOURCES_INLINE = _re.compile(        # req.query.id used inline (no assignment)
    r'req\.(?:query|params|body)\.(\w+)',
    _re.IGNORECASE,
)

_JAVA_SOURCES = _re.compile(
    r'(?:String|Long|Integer|int|long)\s+(\w+)\s*=\s*'
    r'(?:request\.getParameter|pathVariable|@PathVariable[^)]*|req\.getParameter)\s*\(',
    _re.IGNORECASE,
)
_JAVA_PATH_VAR = _re.compile(           # @PathVariable annotation on parameter
    r'@PathVariable(?:\(["\']?\w*["\']?\))?\s+\w+\s+(\w+)',
    _re.IGNORECASE,
)

_GO_SOURCES = _re.compile(
    r'(\w+)\s*:?=\s*'
    r'(?:r\.URL\.Query\(\)\.Get|r\.FormValue|c\.Param|ctx\.Query|'
    r'r\.PathValue|chi\.URLParam|mux\.Vars\(r\))\s*\(',
    _re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Language-specific sink patterns
# ---------------------------------------------------------------------------
_JS_SINKS = _re.compile(
    r'(?:db|repository|repo|collection|model|User|Account|Item)'
    r'\.(?:findById|findOne|find|get|fetch|findByPk|findAll)\s*\('
    r'|\.exec\s*\(|\.query\s*\('
    r'|fs\.(?:readFile|readFileSync|createReadStream)\s*\(',
    _re.IGNORECASE,
)

_JAVA_SINKS = _re.compile(
    r'(?:repository|repo|service|dao|em|entityManager)'
    r'\.(?:findById|find|get|getOne|load|createQuery|createNativeQuery)\s*\('
    r'|jdbcTemplate\.(?:query|queryForObject|execute)\s*\('
    r'|Files\.(?:readAllBytes|newInputStream)\s*\(',
    _re.IGNORECASE,
)

_GO_SINKS = _re.compile(
    r'(?:db|repo|store|col)\.'
    r'(?:Query|QueryRow|Exec|FindById|FindOne|Get|Find|First)\s*\('
    r'|os\.(?:Open|ReadFile)\s*\('
    r'|ioutil\.ReadFile\s*\(',
    _re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Language-specific auth suppression patterns
# ---------------------------------------------------------------------------
_JS_AUTH = _re.compile(
    r'\bif\s*\(!?\s*(?:req\.user|user|auth|session|token|isAdmin|isAuthorized)\b'
    r'|\bverify(?:Token|Auth|Permission|Owner)\s*\('
    r'|\bcheckOwner\s*\(|\bauthorize\s*\(|\bhasPermission\s*\('
    r'|\breq\.user\.id\s*[!=]=\s*\w+'
    r'|\w+\s*[!=]=\s*req\.user\.id',
    _re.IGNORECASE,
)

_JAVA_AUTH = _re.compile(
    r'@PreAuthorize|@Secured|@RolesAllowed|@WithMockUser'
    r'|\bSecurityContextHolder\b'
    r'|\bAuthentication\b'
    r'|\b(?:authorize|canAccess|checkAccess|hasAccess|isAuthorized)\s*\('
    r'|\bgetCurrentUser\(\)\.getId\(\)\s*[!=]='
    r'|\bid\s*[!=]=\s*currentUser',
    _re.IGNORECASE,
)

# For Java, @PreAuthorize / @Secured often appears on a PREVIOUS line.
# Extend the window backward by scanning the preceding lines too.
_JAVA_WINDOW_BACK = 8

_GO_AUTH = _re.compile(
    r'\bgetUserFromContext\b|\bctx\.Value\b'
    r'|\buserID\s*!=\s*\w+'
    r'|\b(?:authorize|authorizeUser|checkPermission|canAccess|hasAccess|isAuthorized)\s*\('
    r'|\bif\s+\w+\.UserID\s*!=',
    _re.IGNORECASE,
)

# window of lines to look ahead for sink + auth
_WINDOW = 12


def _window_idor(lines: list[str], source_re, sink_re, auth_re,
                 filepath: str, lang: str) -> list[dict]:
    """
    Contextual line-window IDOR detector for JS/Java/Go.

    For each line that matches a source pattern:
      - Extract the tainted variable name
      - Look forward WINDOW lines for a sink that uses the variable
      - Suppress if auth pattern appears anywhere in the window
    """
    findings = []
    n = len(lines)

    for i, line in enumerate(lines):
        # Skip comments
        stripped = line.strip()
        if stripped.startswith(('//', '#', '*', '/*')):
            continue

        m = source_re.search(line)
        if not m:
            continue

        var_name = m.group(1) if m.lastindex and m.lastindex >= 1 else ""
        window_end = min(i + _WINDOW, n)
        window_lines = lines[i:window_end]
        window_src = "\n".join(window_lines)

        # Auth check anywhere in the window → suppress
        if auth_re.search(window_src):
            continue

        # Must find the variable reaching a sink within the window
        sink_found = False
        sink_line = i
        for j, wl in enumerate(window_lines):
            if sink_re.search(wl):
                # Require the tainted identifier on the actual sink line.
                if not var_name:
                    sink_found = True
                    sink_line = i + j
                    break

                if _re.search(
                    rf"\b{_re.escape(var_name)}\b",
                    wl,
                    _re.IGNORECASE,
                ):
                    sink_found = True
                    sink_line = i + j
                    break

        if not sink_found:
            continue

        lineno  = sink_line + 1
        snippet = lines[sink_line].strip()
        source_snippet = lines[i].strip()
        taint_path = f"{source_snippet} → {snippet}"

        base = _base_idor_finding(
            filepath=filepath,
            line=lineno,
            snippet=snippet,
            language=lang,
        )
        base.update({
            "taint_path": taint_path,
            "detection": "Taint Flow Analysis",
            "confidence": "Medium",
            "note": (
                "User-controlled identifier from request reaches "
                f"data-access sink without authorization check ({lang})."
            ),
            "group_key": f"api_idor|{taint_path[:60]}",
        })
        findings.append(base)

    return findings


def _analyse_js(filepath: str, lines: list[str]) -> list[dict]:
    """IDOR detection for Node.js / JavaScript."""
    results = []

    results.extend(
        _window_idor(
            lines,
            _JS_SOURCES,
            _JS_SINKS,
            _JS_AUTH,
            filepath,
            "javascript",
        )
    )

    results.extend(
        _window_idor(
            lines,
            _JS_SOURCES_INLINE,
            _JS_SINKS,
            _JS_AUTH,
            filepath,
            "javascript",
        )
    )

    seen = set()
    deduped = []

    for finding in results:
        key = (
            finding.get("line"),
            finding.get("taint_path"),
            finding.get("group_key"),
        )

        if key in seen:
            continue

        seen.add(key)
        deduped.append(finding)

    return deduped


def _analyse_java(filepath: str, lines: list[str]) -> list[dict]:
    """IDOR detection for Java — checks backward window for security annotations."""
    # Build an augmented line list: prepend preceding N lines so @PreAuthorize
    # on a previous line is visible in the window
    def _with_back_context(line_idx: int, back: int = _JAVA_WINDOW_BACK) -> str:
        start = max(0, line_idx - back)
        return "\n".join(lines[start:line_idx + _WINDOW])

    # Run standard window analysis
    results = _window_idor(lines, _JAVA_SOURCES, _JAVA_SINKS, _JAVA_AUTH, filepath, "java")
    results += _window_idor(lines, _JAVA_PATH_VAR, _JAVA_SINKS, _JAVA_AUTH, filepath, "java")

    # Post-filter: remove any finding where a security annotation appears in
    # the backward context of the source line
    filtered = []
    for r in results:
        src_line = r["line"] - 1
        back_ctx = _with_back_context(src_line)
        if not _JAVA_AUTH.search(back_ctx):
            filtered.append(r)
    results = filtered
    # Deduplicate by line
    seen = set()
    deduped = []
    for r in results:
        if r["line"] not in seen:
            seen.add(r["line"])
            deduped.append(r)
    return deduped


def _analyse_go(filepath: str, lines: list[str]) -> list[dict]:
    """IDOR detection for Go."""
    return _window_idor(lines, _GO_SOURCES, _GO_SINKS, _GO_AUTH, filepath, "go")

# ---------------------------------------------------------------------------
# Public language dispatcher
# ---------------------------------------------------------------------------

def analyse_file(filepath: str) -> list[dict]:
    """Dispatch IDOR analysis based on file extension."""
    ext = filepath.rsplit(".", 1)[-1].lower() if "." in filepath else ""

    if ext == "py":
        return _analyse_python(filepath)

    try:
        source = Path(filepath).read_text(
            encoding="utf-8",
            errors="replace",
        )
        lines = source.splitlines()
    except OSError:
        return []

    if ext in ("js", "ts", "mjs", "cjs"):
        return _analyse_js(filepath, lines)

    if ext == "java":
        return _analyse_java(filepath, lines)

    if ext == "go":
        return _analyse_go(filepath, lines)

    return []

